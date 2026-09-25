/**
 * Nextcloud instance — health, version drift, app updates and `occ`
 * maintenance for a self-hosted {@link https://nextcloud.com | Nextcloud}.
 *
 * Eight methods over two transports.
 *
 * Over HTTP, needing no credential beyond an optional read-only token:
 *
 * - `sync` reads `status.php` (installed, maintenance, needsDbUpgrade,
 *   version) and, when a serverinfo token is configured, the serverinfo API
 *   (storage, users, database size, PHP, active users).
 * - `drift` compares the running version against Nextcloud's published stable
 *   releases and reports the patch target and the next major separately.
 *
 * Over `occ` and `docker exec`, run either locally or on a host over SSH:
 *
 * - `setupchecks` — the admin overview's warnings, as data. Read-only.
 * - `apps` — installed apps and the ones with updates available, and with a
 *   `targetVersion`, which store apps have no release for that version.
 *   Read-only.
 * - `maintenance` — turn maintenance mode on or off.
 * - `dbRepair` — add missing indices, columns and primary keys.
 * - `updateApps` — update apps from the app store.
 * - `backup` — dump the database and archive the web-root directories an
 *   upgrade changes, onto the machine swamp runs on, then read both back.
 *
 * Together they cover a major upgrade except the image bump itself, which
 * belongs to whatever deploys the container: `drift` names the target, `apps`
 * with that target shows what the upgrade would disable, `backup` makes the
 * rollback point, and after the deploy `sync`, `dbRepair` and `setupchecks`
 * confirm it took.
 *
 * ## Why `backup` verifies by reading back
 *
 * A dump cut short by a dropped connection is still valid SQL up to the cut,
 * and a truncated archive still lists its first entries, so an exit status of
 * 0 and a non-empty file prove little. `backup` reads both files back from
 * disk: the dump must end with `-- Dump completed` and create as many tables
 * as the database had, and the archive must reach its end-of-archive marker
 * with every header checksum and the gzip CRC intact. A backup that fails any
 * check is renamed with a `.FAILED` suffix, so it cannot be mistaken for a
 * rollback point. The database password is read from an environment variable
 * inside the database container and handed to the client as `MYSQL_PWD`, so
 * it never appears in a command line, which on a shared host any local user
 * can read with `ps`.
 *
 * **Every method that changes state is a dry run unless `apply: true`.** A dry
 * run reports what would change and changes nothing; the apply path re-reads
 * the state afterwards and fails if the change did not take.
 *
 * ## Why `status.php` cannot be probed by IP address
 *
 * Nextcloud 34 enforces `trusted_domains` on `status.php`. Asked by an address
 * that is not trusted it answers HTTP 400 with
 * `{"error":"Trusted domain error.","code":15}`. A test against `127.0.0.1`
 * will not catch this, because localhost is trusted implicitly.
 *
 * The obvious workaround is to probe the IP and send the real name as a `Host`
 * header. That does not work from here: Deno's `fetch` drops a caller-supplied
 * `Host` header without a warning. Measured 2026-09-24, the same request that
 * `curl -H Host:` answers 200 answered 400/code 15 from Deno. So `baseUrl`
 * must be a name the instance trusts, and `sync` names the cause when it is not
 * rather than reporting a bare 400.
 *
 * ## Why drift reports two targets
 *
 * Nextcloud cannot skip a major version: 32 → 34 is refused, and the upgrade
 * must go 32 → 33 → 34. So "the newest release" is not a target you can deploy
 * unless it happens to be one major ahead. `drift` reports:
 *
 * - `patchTarget`, the newest stable release on the running major. Always a
 *   legal, low-risk move.
 * - `nextMajor`, the newest stable release on the *next* major. The only legal
 *   major hop.
 * - `latestVersion`, the newest stable overall, and `majorsBehind`.
 *
 * Releases come from GitHub, where Nextcloud flags betas and RCs
 * `prerelease: true`. The tag spellings are not consistent (`v35.0.0rc2` and
 * `v35.0.0RC2` both exist) so prereleases are excluded both by that flag and
 * by refusing any tag with a suffix.
 *
 * `updates.nextcloud.com` is deliberately not the source. For a version string
 * it cannot parse it answers HTTP 200 with an empty body, and for a version
 * with nothing to offer it answers the same way. A check that cannot tell
 * "current" from "I did not understand the question" is not one to alert on.
 *
 * ## Why `occ setupchecks` exiting 1 is not a failure
 *
 * `occ setupchecks` exits 1 whenever any check has a warning. It is reporting
 * findings, not failing. The model accepts exit 1 when the output is the JSON
 * report it asked for, and fails on anything else.
 *
 * ## Failure is never folded into "healthy" or "current"
 *
 * An unreachable instance is recorded as `healthy: false`, because a down
 * instance is a result. Every other failure throws: an exhausted GitHub rate
 * limit, a registry answering neither 200 nor 404, an `occ` command that exits
 * non-zero, and output that does not parse. Reporting "current" or "no
 * updates" because the question could not be answered is the failure mode this
 * model exists to prevent.
 *
 * @module
 */
import { createHash } from "node:crypto";
import { z } from "npm:zod@4";

const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const APP_ID_PATTERN = /^[a-z0-9_]+$/;
const ENV_NAME_PATTERN = /^[A-Z_][A-Z0-9_]*$/;
const WEBROOT_PATH_PATTERN = /^[A-Za-z0-9_][A-Za-z0-9_.-]*$/;

const GlobalArgsSchema = z.object({
  baseUrl: z.string().url().describe(
    "Base URL of the instance, e.g. https://cloud.example.com. Must be a name " +
      "in the instance's `trusted_domains`: Nextcloud 34 answers HTTP 400 to " +
      "`status.php` requested by any other name, and a Host header override " +
      "does not survive Deno's fetch. Used by `sync` and `drift`.",
  ),
  // `.meta({ sensitive: true })` sits on the declaration line rather than
  // after the multi-line describe(): the push-time safety analyzer reads the
  // field's declaration LINE.
  serverinfoToken: z.string().meta({ sensitive: true }).optional().describe(
    "Optional serverinfo token, sent as the `NC-Token` header. Set it on the " +
      'instance by piping `{"apps":{"serverinfo":{"token":"..."}}}` into ' +
      "`occ config:import` on stdin, which keeps it out of the command line " +
      "that `occ config:app:set --value` would put it in. It grants read " +
      "access to the monitoring endpoint only, not an account, so it is the " +
      "least-privileged way to read storage and user statistics. Without it " +
      "`sync` reads `status.php` alone. Supply it from a vault.",
  ),
  sshHost: z.string().optional().describe(
    "Host to run `occ` on over SSH. Omit to run `docker exec` locally, on the " +
      "machine swamp runs on.",
  ),
  sshUser: z.string().optional().describe(
    "SSH user. Omit to use the SSH client's own configuration for the host.",
  ),
  strictHostKeyChecking: z.enum(["yes", "accept-new", "no"]).default("yes")
    .describe(
      "SSH StrictHostKeyChecking. `yes` refuses an unknown host key, which is " +
        "right for a scheduled job that has nobody to ask.",
    ),
  knownHostsFile: z.string().optional().describe(
    "Optional UserKnownHostsFile for SSH.",
  ),
  dockerBin: z.string().default("docker").describe(
    "Docker CLI on the target. Give a full path where docker is not on the " +
      "non-interactive PATH, e.g. /usr/local/bin/docker on Synology DSM.",
  ),
  container: z.string().regex(NAME_PATTERN).default("nextcloud").describe(
    "Name of the Nextcloud application container.",
  ),
  occUser: z.string().regex(NAME_PATTERN).default("www-data").describe(
    "User `occ` runs as inside the container. Must own config.php, or occ " +
      "refuses to start.",
  ),
  githubRepo: z.string().default("nextcloud/server").describe(
    "GitHub `owner/repo` whose releases define what is current.",
  ),
  githubToken: z.string().meta({ sensitive: true }).optional().describe(
    "Optional GitHub token, only to raise the API rate limit. Needs no scopes " +
      "for a public repo. Unauthenticated GitHub allows 60 requests an hour " +
      "per IP, shared with everything else on that address.",
  ),
  imageRepository: z.string().default("nextcloud").describe(
    "Image the deployment pulls. Reported in `drift` so a bump can be " +
      "applied verbatim.",
  ),
  imageVariant: z.string().default("apache").describe(
    "Tag suffix the deployment uses, e.g. `apache` for `34.0.4-apache` or " +
      "`fpm`. Empty for a bare version tag.",
  ),
  verifyRegistry: z.string().default("registry-1.docker.io").describe(
    "Registry that image existence is checked against. Must answer the " +
      "Docker Registry HTTP API V2 manifest endpoint.",
  ),
  verifyRepository: z.string().default("library/nextcloud").describe(
    "Repository path within `verifyRegistry`. Docker Hub official images live " +
      "under `library/`.",
  ),
  appStoreUrl: z.string().url().default("https://apps.nextcloud.com").describe(
    "Nextcloud app store, used by `apps` with a `targetVersion` to check " +
      "which installed store apps have a release for that version.",
  ),
  timeoutMs: z.number().int().positive().default(10_000).describe(
    "Abort each HTTP call after this long.",
  ),
  occTimeoutMs: z.number().int().positive().default(120_000).describe(
    "Abort a read-only `occ` command after this long. Commands that change " +
      "state get ten times this, because an app update or an index build on a " +
      "large table can legitimately take minutes.",
  ),
});

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

/* ------------------------------------------------------------------ *
 * Resource schemas
 * ------------------------------------------------------------------ */

const InstanceSchema = z.object({
  url: z.string().describe("Base URL this reading came from."),
  reachable: z.boolean().describe(
    "True when status.php answered with a parseable status document.",
  ),
  healthy: z.boolean().describe(
    "Installed, not in maintenance mode, and not waiting on a database " +
      "upgrade. The single field to alert on.",
  ),
  httpStatus: z.number().describe(
    "HTTP status of status.php, 0 on a transport error.",
  ),
  latencyMs: z.number().describe("Round-trip time of the status.php probe."),
  installed: z.boolean().nullable().describe("From status.php."),
  maintenance: z.boolean().nullable().describe("From status.php."),
  needsDbUpgrade: z.boolean().nullable().describe(
    "From status.php. True after an image bump whose `occ upgrade` has not " +
      "run, which leaves the instance serving an upgrade page.",
  ),
  version: z.string().nullable().describe(
    "Four-part internal version, e.g. 34.0.4.1.",
  ),
  versionString: z.string().nullable().describe(
    "Release version, e.g. 34.0.4. This is what `drift` compares.",
  ),
  extendedSupport: z.boolean().nullable().describe("From status.php."),
  serverinfo: z.object({
    freeSpaceBytes: z.number().nullable(),
    numUsers: z.number().nullable(),
    numFiles: z.number().nullable(),
    numShares: z.number().nullable(),
    activeUsers5m: z.number().nullable(),
    activeUsers1h: z.number().nullable(),
    activeUsers24h: z.number().nullable(),
    phpVersion: z.string().nullable(),
    databaseType: z.string().nullable(),
    databaseVersion: z.string().nullable(),
    databaseSizeBytes: z.number().nullable(),
  }).nullable().describe(
    "From the serverinfo API. Null when no token is configured, or when the " +
      "call failed -- see `serverinfoError`.",
  ),
  serverinfoError: z.string().nullable().describe(
    "Why serverinfo is null despite a configured token.",
  ),
  detail: z.string().describe(
    "Transport error, a diagnosis, or a truncated response body.",
  ),
  checkedAt: z.iso.datetime().describe("When the probe ran."),
});

const DriftSchema = z.object({
  runningVersion: z.string().describe("The version compared."),
  runningVersionSource: z.enum(["status.php", "argument"]).describe(
    "Where the running version came from.",
  ),
  status: z.enum(["current", "behind-patch", "behind-major", "ahead"])
    .describe(
      "`behind-patch` means a newer release exists on the running major. " +
        "`behind-major` means the running major is fully patched and a newer " +
        "major exists. A deployment behind on both reads `behind-patch`, " +
        "because the patch is the move to make first.",
    ),
  behind: z.boolean().describe(
    "True for either `behind-*` status. The single field to alert on.",
  ),
  patchTarget: z.string().nullable().describe(
    "Newest stable release on the running major, when newer than running.",
  ),
  missedPatches: z.array(z.string()).describe(
    "Stable releases on the running major newer than running, newest first.",
  ),
  nextMajor: z.string().nullable().describe(
    "Newest stable release on the next major. Nextcloud cannot skip a " +
      "major, so this is the only legal major upgrade target.",
  ),
  latestVersion: z.string().describe("Newest stable release overall."),
  majorsBehind: z.number().int().describe(
    "Major versions between running and `latestVersion`. Each one is a " +
      "separate upgrade.",
  ),
  patchImage: z.string().nullable().describe(
    "Fully qualified image for `patchTarget`.",
  ),
  patchImageAvailable: z.boolean().nullable().describe(
    "Whether `patchImage` resolves in the registry. Null when not checked.",
  ),
  nextMajorImage: z.string().nullable().describe(
    "Fully qualified image for `nextMajor`.",
  ),
  nextMajorImageAvailable: z.boolean().nullable().describe(
    "Whether `nextMajorImage` resolves in the registry. Null when not checked.",
  ),
  releaseUrl: z.string().describe(
    "Release notes for the recommended target, or the releases index.",
  ),
  truncated: z.boolean().describe(
    "True when the release page filled up before reaching the running " +
      "version, so `missedPatches` may be incomplete. It cannot make a " +
      "too-new target be offered.",
  ),
  checkedAt: z.iso.datetime().describe("When the check ran."),
});

const SetupCheckSchema = z.object({
  category: z.string(),
  check: z.string().describe(
    "Check class, e.g. OCA\\Settings\\SetupChecks\\X.",
  ),
  name: z.string(),
  severity: z.string().describe("success, info, warning or error."),
  description: z.string().nullable(),
  linkToDoc: z.string().nullable(),
});

const SetupChecksSchema = z.object({
  total: z.number().int(),
  counts: z.record(z.string(), z.number().int()).describe(
    "Checks per severity.",
  ),
  errors: z.number().int(),
  warnings: z.number().int(),
  problems: z.array(SetupCheckSchema).describe(
    "Every check with severity warning or error.",
  ),
  checks: z.array(SetupCheckSchema).describe("Every check, as reported."),
  checkedAt: z.iso.datetime(),
});

const AppUpdateSchema = z.object({
  app: z.string(),
  currentVersion: z.string().nullable(),
  availableVersion: z.string(),
});

const AppCompatibilitySchema = z.object({
  app: z.string(),
  installedVersion: z.string(),
  compatible: z.boolean().describe(
    "The app store lists at least one stable release for the target version.",
  ),
  installedReleaseCompatible: z.boolean().describe(
    "The installed release itself is listed for the target version. When " +
      "false but `compatible` is true, the upgrade has to update the app too.",
  ),
  newestCompatibleVersion: z.string().nullable(),
});

const AppsSchema = z.object({
  enabled: z.record(z.string(), z.string()).describe("App id → version."),
  disabled: z.record(z.string(), z.string()).describe("App id → version."),
  enabledCount: z.number().int(),
  disabledCount: z.number().int(),
  updates: z.array(AppUpdateSchema).describe(
    "Apps with a newer store release, as `occ app:update --showonly` reports.",
  ),
  hasUpdates: z.boolean().describe("The single field to alert on."),
  targetVersion: z.string().nullable().describe(
    "The Nextcloud version compatibility was checked against. Null when no " +
      "targetVersion was given.",
  ),
  compatibility: z.array(AppCompatibilitySchema).nullable().describe(
    "One entry per enabled app that is not shipped with the server. Shipped " +
      "apps upgrade with the server and are not listed. Null when no " +
      "targetVersion was given.",
  ),
  incompatible: z.array(z.string()).nullable().describe(
    "Enabled store apps with no stable release for targetVersion. Non-empty " +
      "means the upgrade would disable them. The field to gate an upgrade on.",
  ),
  checkedAt: z.iso.datetime(),
});

const MaintenanceSchema = z.object({
  requested: z.enum(["on", "off"]),
  enabledBefore: z.boolean(),
  enabledAfter: z.boolean(),
  changed: z.boolean(),
  applied: z.boolean().describe("False for a dry run."),
  checkedAt: z.iso.datetime(),
});

const DbRepairStepSchema = z.object({
  command: z.string(),
  pendingItems: z.array(z.string()).describe(
    "What the dry run said it would add, one entry per missing index, " +
      "column or primary key.",
  ),
  remainingItems: z.number().int().nullable().describe(
    "Items a second dry run still reports after applying. Null for a dry run.",
  ),
  sql: z.array(z.string()).describe(
    "Every statement the dry run proposed, uncapped.",
  ),
});

const DbRepairSchema = z.object({
  applied: z.boolean(),
  pending: z.number().int().describe(
    "Missing indices, columns and primary keys found before any change. The " +
      "field to alert on.",
  ),
  steps: z.array(DbRepairStepSchema),
  checkedAt: z.iso.datetime(),
});

const AppUpdateRunSchema = z.object({
  applied: z.boolean(),
  requested: z.array(z.string()).describe(
    "App ids asked for. Empty means every app with an update.",
  ),
  planned: z.array(AppUpdateSchema),
  updated: z.array(z.string()).describe(
    "Apps no longer reporting an update after applying.",
  ),
  stillPending: z.array(z.string()).describe(
    "Planned apps that still report an update after applying. Non-empty " +
      "fails the method.",
  ),
  checkedAt: z.iso.datetime(),
});

const BackupFileSchema = z.object({
  name: z.string().describe("File name within the backup directory."),
  bytes: z.number().int(),
  sha256: z.string(),
});

const BackupSchema = z.object({
  applied: z.boolean().describe("False for a dry run, which writes nothing."),
  verified: z.boolean().describe(
    "Every check below passed. Only a verified backup is a rollback point. " +
      "The field to gate an upgrade on.",
  ),
  directory: z.string().nullable().describe(
    "Where the backup was written, on the machine swamp runs on. A backup " +
      "that fails verification is renamed with a `.FAILED` suffix.",
  ),
  nextcloudVersion: z.string().describe(
    "Version running when the backup was taken, from `occ status`. A " +
      "restore must run this version's image.",
  ),
  database: z.object({
    container: z.string(),
    name: z.string(),
    liveTables: z.number().int().describe(
      "Tables in the database, counted before the dump.",
    ),
    dumpedTables: z.number().int().nullable().describe(
      "CREATE TABLE statements in the dump. Null for a dry run.",
    ),
    dumpComplete: z.boolean().nullable().describe(
      "The dump ends with mysqldump's `-- Dump completed` line, so it was " +
        "not cut short. Null for a dry run.",
    ),
  }),
  archive: z.object({
    paths: z.array(z.string()).describe(
      "Directories under the web root that were archived.",
    ),
    sourceKiB: z.record(z.string(), z.number().int()).describe(
      "Size of each path on the instance, from `du -sk`.",
    ),
    entries: z.number().int().nullable().describe(
      "Entries read back from the written archive. Null for a dry run.",
    ),
    hasConfigPhp: z.boolean().nullable().describe(
      "The archive contains config/config.php. Null for a dry run or when " +
        "`config` was not archived.",
    ),
  }),
  files: z.array(BackupFileSchema),
  problems: z.array(z.string()).describe(
    "Every verification that failed. Non-empty fails the method.",
  ),
  checkedAt: z.iso.datetime(),
});

/* ------------------------------------------------------------------ *
 * Context
 * ------------------------------------------------------------------ */

type Logger = {
  info: (message: string, props?: Record<string, unknown>) => void;
  warn: (message: string, props?: Record<string, unknown>) => void;
};

type Context = {
  globalArgs: GlobalArgs;
  signal?: AbortSignal;
  logger: Logger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
};

/* ------------------------------------------------------------------ *
 * Version handling
 * ------------------------------------------------------------------ */

/** A parsed stable Nextcloud version. */
export type ParsedVersion = { major: number; minor: number; patch: number };

/**
 * Parse a stable release version.
 *
 * Accepts `34.0.4`, `v34.0.4` and the four-part internal `34.0.4.1` (the
 * fourth part is a build counter that never distinguishes releases). Rejects
 * anything with a suffix: Nextcloud's prerelease tags are not consistently
 * spelled (`rc1`, `RC2`, `beta3`), so a suffix of any kind means "not a
 * stable release" rather than something to parse.
 *
 * @param raw Version or tag.
 * @returns The parsed version, or null if it is not a stable version.
 */
export function parseVersion(raw: string): ParsedVersion | null {
  const m = raw.trim().match(/^v?(\d+)\.(\d+)\.(\d+)(?:\.\d+)?$/i);
  if (!m) return null;
  return {
    major: parseInt(m[1], 10),
    minor: parseInt(m[2], 10),
    patch: parseInt(m[3], 10),
  };
}

/**
 * Compare two versions numerically.
 *
 * @returns Negative if a < b, positive if a > b, zero if equal.
 */
export function compareVersions(a: ParsedVersion, b: ParsedVersion): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
}

/** Render a parsed version as `major.minor.patch`. */
export function formatVersion(v: ParsedVersion): string {
  return `${v.major}.${v.minor}.${v.patch}`;
}

/** One upstream release. */
export type ReleaseInfo = { tag: string; prerelease: boolean; htmlUrl: string };

/** The result of comparing a running version against upstream releases. */
export type DriftResult = {
  status: "current" | "behind-patch" | "behind-major" | "ahead";
  behind: boolean;
  patchTarget: string | null;
  missedPatches: string[];
  nextMajor: string | null;
  latestVersion: string;
  majorsBehind: number;
  truncated: boolean;
};

/**
 * Compare a running version against the stable releases.
 *
 * @param runningVersion Version deployed.
 * @param releases Recent releases, newest first, as GitHub returns them.
 * @param pageWasFull Whether the page was full, so older releases exist that
 *   were not examined.
 */
export function computeDrift(
  runningVersion: string,
  releases: ReleaseInfo[],
  pageWasFull: boolean,
): DriftResult {
  const running = parseVersion(runningVersion);
  if (!running) {
    throw new Error(
      `running version ${JSON.stringify(runningVersion)} is not a ` +
        `recognisable stable version; refusing to report drift rather than guess`,
    );
  }

  const stable = releases
    .filter((r) => !r.prerelease)
    .map((r) => parseVersion(r.tag))
    .filter((v): v is ParsedVersion => v !== null)
    .sort((a, b) => compareVersions(b, a));

  if (stable.length === 0) {
    throw new Error(
      "no stable releases found on the page examined; cannot determine what " +
        "is current",
    );
  }

  const latest = stable[0];
  const newestOnMajor = (major: number) =>
    stable.find((v) => v.major === major) ?? null;

  const missedPatches = stable
    .filter((v) => v.major === running.major && compareVersions(v, running) > 0)
    .map(formatVersion);
  const sameMajor = newestOnMajor(running.major);
  const patchTarget = sameMajor && compareVersions(sameMajor, running) > 0
    ? formatVersion(sameMajor)
    : null;
  const next = newestOnMajor(running.major + 1);
  const nextMajor = next ? formatVersion(next) : null;

  let status: DriftResult["status"];
  if (patchTarget) status = "behind-patch";
  else if (compareVersions(latest, running) > 0) status = "behind-major";
  else if (compareVersions(latest, running) < 0) status = "ahead";
  else status = "current";

  // A full page whose oldest release is still newer than what is running
  // means the gap continues past what was examined.
  const oldest = releases.length > 0
    ? parseVersion(releases[releases.length - 1].tag)
    : null;
  const truncated = pageWasFull && oldest !== null &&
    compareVersions(oldest, running) > 0;

  return {
    status,
    behind: status === "behind-patch" || status === "behind-major",
    patchTarget,
    missedPatches,
    nextMajor,
    latestVersion: formatVersion(latest),
    majorsBehind: Math.max(0, latest.major - running.major),
    truncated,
  };
}

/** Build a fully qualified image reference for a version. */
export function imageTag(version: string, variant: string): string {
  return variant ? `${version}-${variant}` : version;
}

/* ------------------------------------------------------------------ *
 * HTTP helpers
 * ------------------------------------------------------------------ */

async function readErrorBody(res: Response): Promise<string> {
  try {
    return (await res.text()).slice(0, 300);
  } catch {
    return "<unreadable body>";
  }
}

/**
 * Combine the caller's cancellation signal with a per-call timeout, so a
 * cancelled workflow stops these requests too.
 */
function callSignal(timeoutMs: number, outer?: AbortSignal): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);
  return outer ? AbortSignal.any([outer, timeout]) : timeout;
}

/** The fields of status.php this model uses. */
export type StatusDocument = {
  installed: boolean;
  maintenance: boolean;
  needsDbUpgrade: boolean;
  version: string;
  versionstring: string;
  extendedSupport: boolean;
};

/**
 * Validate a status.php body.
 *
 * @returns The document, or null if the body is not a Nextcloud status.
 */
export function parseStatusDocument(body: unknown): StatusDocument | null {
  if (!body || typeof body !== "object") return null;
  const b = body as Record<string, unknown>;
  if (
    typeof b.installed !== "boolean" || typeof b.maintenance !== "boolean" ||
    typeof b.needsDbUpgrade !== "boolean" || typeof b.version !== "string" ||
    typeof b.versionstring !== "string"
  ) {
    return null;
  }
  return {
    installed: b.installed,
    maintenance: b.maintenance,
    needsDbUpgrade: b.needsDbUpgrade,
    version: b.version,
    versionstring: b.versionstring,
    extendedSupport: b.extendedSupport === true,
  };
}

/**
 * Explain a non-status response in terms of its likely cause.
 *
 * The trusted-domain refusal is the one worth naming: it is HTTP 400 with a
 * JSON body, so it looks like a broken instance when it is a misconfigured
 * `baseUrl`.
 */
export function diagnoseStatusBody(httpStatus: number, body: string): string {
  if (/"code"\s*:\s*15\b/.test(body) || /Trusted domain error/i.test(body)) {
    return "Nextcloud refused the request with a trusted-domain error " +
      "(code 15). baseUrl must use a name listed in the instance's " +
      "trusted_domains; Nextcloud 34 enforces it on status.php, and probing " +
      "by IP address fails this way.";
  }
  return `HTTP ${httpStatus}: ${body.slice(0, 300)}`;
}

function num(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v))) {
    return Number(v);
  }
  return null;
}

function str(v: unknown): string | null {
  return typeof v === "string" && v !== "" ? v : null;
}

/** Extract the fields this model records from a serverinfo OCS response. */
export function parseServerinfo(body: unknown) {
  const data = (body as { ocs?: { data?: Record<string, unknown> } })?.ocs
    ?.data;
  if (!data || typeof data !== "object") {
    throw new Error("serverinfo response has no ocs.data");
  }
  const nc = (data.nextcloud ?? {}) as Record<string, Record<string, unknown>>;
  const server = (data.server ?? {}) as Record<string, Record<string, unknown>>;
  const active = (data.activeUsers ?? {}) as Record<string, unknown>;
  return {
    freeSpaceBytes: num(nc.system?.freespace),
    numUsers: num(nc.storage?.num_users),
    numFiles: num(nc.storage?.num_files),
    numShares: num(nc.shares?.num_shares),
    activeUsers5m: num(active.last5minutes),
    activeUsers1h: num(active.last1hour),
    activeUsers24h: num(active.last24hours),
    phpVersion: str(server.php?.version),
    databaseType: str(server.database?.type),
    databaseVersion: str(server.database?.version),
    databaseSizeBytes: num(server.database?.size),
  };
}

/* ------------------------------------------------------------------ *
 * Registry existence check
 * ------------------------------------------------------------------ */

/** Parse the realm and service out of a `WWW-Authenticate: Bearer` header. */
export function parseAuthChallenge(
  header: string,
): { realm: string; service: string | null } | null {
  if (!/^\s*Bearer\s/i.test(header)) return null;
  const realm = header.match(/realm="([^"]+)"/i)?.[1];
  if (!realm) return null;
  const service = header.match(/service="([^"]+)"/i)?.[1] ?? null;
  return { realm, service };
}

/**
 * Whether a tag resolves to a manifest in the registry.
 *
 * Anything but 200 or 404 throws. A 429 must never read as "absent": that
 * would suppress every update while the check looked healthy.
 */
export async function imageTagExists(
  registry: string,
  repository: string,
  tag: string,
  timeoutMs: number,
  signal?: AbortSignal,
): Promise<boolean> {
  const manifestUrl = `https://${registry}/v2/${repository}/manifests/${
    encodeURIComponent(tag)
  }`;
  const accept = [
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
  ].join(", ");

  const probe = await fetch(manifestUrl, {
    method: "HEAD",
    signal: callSignal(timeoutMs, signal),
    headers: { Accept: accept },
  });
  await probe.body?.cancel();
  if (probe.status === 200) return true;
  if (probe.status === 404) return false;
  if (probe.status !== 401) {
    throw new Error(
      `registry ${registry} answered HTTP ${probe.status} for ` +
        `${repository}:${tag}; treating as indeterminate rather than absent`,
    );
  }

  const challenge = parseAuthChallenge(
    probe.headers.get("www-authenticate") ?? "",
  );
  if (!challenge) {
    throw new Error(
      `registry ${registry} demanded authentication for ${repository} but ` +
        `sent no parseable Bearer challenge`,
    );
  }
  const tokenUrl = new URL(challenge.realm);
  tokenUrl.searchParams.set("scope", `repository:${repository}:pull`);
  if (challenge.service) {
    tokenUrl.searchParams.set("service", challenge.service);
  }

  const tokenRes = await fetch(tokenUrl, {
    signal: callSignal(timeoutMs, signal),
  });
  if (!tokenRes.ok) {
    throw new Error(
      `${challenge.realm} refused an anonymous pull token for ${repository}: ` +
        `HTTP ${tokenRes.status}: ${await readErrorBody(tokenRes)}`,
    );
  }
  const tokenBody = await tokenRes.json() as {
    token?: string;
    access_token?: string;
  };
  const token = tokenBody.token ?? tokenBody.access_token;
  if (!token) throw new Error(`${challenge.realm} returned no token`);

  const res = await fetch(manifestUrl, {
    method: "HEAD",
    signal: callSignal(timeoutMs, signal),
    headers: { Accept: accept, Authorization: `Bearer ${token}` },
  });
  await res.body?.cancel();
  if (res.status === 404) return false;
  if (res.ok) return true;
  throw new Error(
    `registry ${registry} answered HTTP ${res.status} for ${repository}:${tag} ` +
      `after authenticating; treating as indeterminate rather than absent`,
  );
}

/* ------------------------------------------------------------------ *
 * occ transport
 * ------------------------------------------------------------------ */

/** Quote one argument for a POSIX shell. */
export function shellQuote(arg: string): string {
  if (/^[A-Za-z0-9_./:=@%+-]+$/.test(arg)) return arg;
  return `'${arg.replaceAll("'", `'"'"'`)}'`;
}

type TransportArgs = Pick<
  GlobalArgs,
  | "sshHost"
  | "sshUser"
  | "strictHostKeyChecking"
  | "knownHostsFile"
  | "dockerBin"
>;

/**
 * Build the argv that runs `occ` with the given arguments.
 *
 * Locally the argv is executed directly, with no shell. Over SSH the remote
 * side always runs a shell, so the docker command is quoted into one string
 * first; app ids and container names are also validated against a strict
 * pattern before they get here, so the quoting is a second line rather than
 * the only one.
 */
export function occArgv(
  g: TransportArgs & Pick<GlobalArgs, "container" | "occUser">,
  occArgs: string[],
): { cmd: string; args: string[] } {
  return dockerExecArgv(g, g.container, g.occUser, [
    "php",
    "occ",
    "--no-interaction",
    "--no-ansi",
    ...occArgs,
  ]);
}

/**
 * Build the argv that runs a command in a container with `docker exec`,
 * locally or over SSH. `user` null runs as the container's default user.
 */
export function dockerExecArgv(
  g: TransportArgs,
  container: string,
  user: string | null,
  command: string[],
): { cmd: string; args: string[] } {
  const docker = [
    "exec",
    ...(user ? ["-u", user] : []),
    container,
    ...command,
  ];
  if (!g.sshHost) return { cmd: g.dockerBin, args: docker };

  const ssh = [
    "-o",
    "BatchMode=yes",
    "-o",
    `StrictHostKeyChecking=${g.strictHostKeyChecking}`,
    "-o",
    "ConnectTimeout=10",
  ];
  if (g.knownHostsFile) {
    ssh.push("-o", `UserKnownHostsFile=${g.knownHostsFile}`);
  }
  ssh.push(
    g.sshUser ? `${g.sshUser}@${g.sshHost}` : g.sshHost,
    [g.dockerBin, ...docker].map(shellQuote).join(" "),
  );
  return { cmd: "ssh", args: ssh };
}

/** The outcome of one occ invocation. */
export type OccResult = { code: number; stdout: string; stderr: string };

/** Runs occ; replaceable in tests. */
export type OccRunner = (
  occArgs: string[],
  timeoutMs: number,
  signal?: AbortSignal,
) => Promise<OccResult>;

function processRunner(g: GlobalArgs): OccRunner {
  return async (occArgs, timeoutMs, signal) => {
    const { cmd, args } = occArgv(g, occArgs);
    // stdin is null so ssh cannot swallow anything, and a non-TTY stdin can
    // never leave the command waiting on a prompt.
    const proc = new Deno.Command(cmd, {
      args,
      stdin: "null",
      stdout: "piped",
      stderr: "piped",
      signal: callSignal(timeoutMs, signal),
    });
    const out = await proc.output();
    return {
      code: out.code,
      stdout: new TextDecoder().decode(out.stdout),
      stderr: new TextDecoder().decode(out.stderr),
    };
  };
}

async function occ(
  run: OccRunner,
  occArgs: string[],
  timeoutMs: number,
  signal: AbortSignal | undefined,
  okCodes: number[] = [0],
): Promise<string> {
  const r = await run(occArgs, timeoutMs, signal);
  if (!okCodes.includes(r.code)) {
    throw new Error(
      `occ ${occArgs.join(" ")} exited ${r.code}: ` +
        `${(r.stderr.trim() || r.stdout.trim()).slice(-400)}`,
    );
  }
  return r.stdout;
}

/* ------------------------------------------------------------------ *
 * occ output parsing
 * ------------------------------------------------------------------ */

/** Flatten `occ setupchecks --output=json` into a list. */
export function parseSetupChecks(stdout: string) {
  let doc: unknown;
  try {
    doc = JSON.parse(stdout);
  } catch {
    throw new Error(
      `occ setupchecks did not return JSON: ${stdout.slice(0, 300)}`,
    );
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    throw new Error("occ setupchecks returned JSON of an unexpected shape");
  }
  const checks: z.infer<typeof SetupCheckSchema>[] = [];
  for (const [category, group] of Object.entries(doc)) {
    if (!group || typeof group !== "object") continue;
    for (const [check, raw] of Object.entries(group as object)) {
      const c = raw as Record<string, unknown>;
      checks.push({
        category,
        check,
        name: str(c.name) ?? check,
        severity: str(c.severity) ?? "unknown",
        description: str(c.description),
        linkToDoc: str(c.linkToDoc),
      });
    }
  }
  if (checks.length === 0) {
    throw new Error(
      "occ setupchecks returned no checks at all; refusing to report a clean " +
        "result that was never measured",
    );
  }
  return checks;
}

/**
 * Parse `occ app:list --output=json`.
 *
 * @param allowEmpty Accept an empty enabled list. Only right when the listing
 *   is filtered, as `--shipped=false` is: an instance may have no store apps,
 *   but it always has shipped ones.
 */
export function parseAppList(stdout: string, allowEmpty = false): {
  enabled: Record<string, string>;
  disabled: Record<string, string>;
} {
  let doc: { enabled?: unknown; disabled?: unknown };
  try {
    doc = JSON.parse(stdout);
  } catch {
    throw new Error(
      `occ app:list did not return JSON: ${stdout.slice(0, 300)}`,
    );
  }
  const asMap = (v: unknown): Record<string, string> => {
    // An empty PHP associative array serialises as [], not {}.
    if (Array.isArray(v) && v.length === 0) return {};
    if (!v || typeof v !== "object" || Array.isArray(v)) {
      throw new Error("occ app:list returned JSON of an unexpected shape");
    }
    return Object.fromEntries(
      Object.entries(v).map(([k, ver]) => [k, String(ver)]),
    );
  };
  const enabled = asMap(doc.enabled);
  if (!allowEmpty && Object.keys(enabled).length === 0) {
    throw new Error(
      "occ app:list reported no enabled apps; a working instance always has " +
        "some, so this output is not trusted",
    );
  }
  return { enabled, disabled: asMap(doc.disabled ?? {}) };
}

/**
 * Parse `occ app:update --showonly`.
 *
 * The command has no JSON output. It prints one `<app> new version available:
 * <version>` line per update, or a single "All apps are up-to-date" line.
 * Any other non-empty line throws: output this parser does not understand
 * must not be reported as "no updates".
 */
export function parseAppUpdates(
  stdout: string,
): { app: string; availableVersion: string }[] {
  const updates: { app: string; availableVersion: string }[] = [];
  const unknown: string[] = [];
  for (const line of stdout.split("\n").map((l) => l.trim())) {
    if (line === "") continue;
    if (/^All apps are up-to-date/i.test(line)) continue;
    const m = line.match(/^([a-z0-9_]+) new version available: (\S+)/);
    if (m) updates.push({ app: m[1], availableVersion: m[2] });
    else unknown.push(line);
  }
  if (unknown.length > 0) {
    throw new Error(
      `occ app:update --showonly printed lines this parser does not ` +
        `recognise; refusing to report the update list: ` +
        unknown.slice(0, 5).join(" | "),
    );
  }
  return updates;
}

/** Parse `occ maintenance:mode` with no flag. */
export function parseMaintenanceMode(stdout: string): boolean {
  if (/currently enabled/i.test(stdout)) return true;
  if (/currently disabled/i.test(stdout)) return false;
  throw new Error(
    `occ maintenance:mode printed an unrecognised state: ${
      stdout.trim().slice(0, 200)
    }`,
  );
}

/**
 * Parse a `db:add-missing-*` dry run.
 *
 * Each of the three commands prints one "Adding ..." line per missing item,
 * dry run or not, and with `--dry-run` also prints the SQL it would run. The
 * progress lines are the count; the SQL is the detail.
 *
 * Both are read so that each checks the other. Counting only SQL would read a
 * change in SQL formatting as "nothing pending", and this path cannot be
 * exercised against a healthy instance, so such a change would go unnoticed.
 * Progress lines with no SQL, or SQL with no progress lines, throw.
 */
export function parseRepairDryRun(
  command: string,
  stdout: string,
): { items: string[]; sql: string[] } {
  const lines = stdout.split("\n").map((l) => l.trim());
  const items = lines.filter((l) =>
    /^Adding (additional|primary key)\b/i.test(l)
  );
  const sql = lines.filter((l) =>
    /^(CREATE|ALTER|DROP|UPDATE|INSERT)\s/i.test(l)
  );
  if ((items.length > 0) !== (sql.length > 0)) {
    throw new Error(
      `${command} --dry-run reported ${items.length} missing item(s) and ` +
        `${sql.length} SQL statement(s); expected both or neither, so the ` +
        `output format has changed and the result is not trusted`,
    );
  }
  return { items, sql };
}

/* ------------------------------------------------------------------ *
 * App store compatibility
 * ------------------------------------------------------------------ */

/**
 * Parse the app store's `/api/v1/platform/<version>/apps.json` into app id →
 * stable release versions. The endpoint lists only releases whose platform
 * range includes that version, so presence is compatibility. Nightly releases
 * are dropped.
 */
export function parseStoreApps(body: unknown): Map<string, string[]> {
  if (!Array.isArray(body)) {
    throw new Error("app store response is not a list of apps");
  }
  const out = new Map<string, string[]>();
  for (const a of body as Array<Record<string, unknown>>) {
    if (typeof a?.id !== "string" || !Array.isArray(a.releases)) continue;
    const versions = (a.releases as Array<Record<string, unknown>>)
      .filter((r) => typeof r?.version === "string" && r.isNightly !== true)
      .map((r) => r.version as string);
    if (versions.length > 0) out.set(a.id, versions);
  }
  return out;
}

/** Newest of a list of app versions; unparseable ones only as a fallback. */
function newestVersion(versions: string[]): string | null {
  const parsed = versions
    .map((v) => ({ v, p: parseVersion(v) }))
    .filter((x): x is { v: string; p: ParsedVersion } => x.p !== null)
    .sort((a, b) => compareVersions(b.p, a.p));
  return parsed[0]?.v ?? versions[0] ?? null;
}

/**
 * Compare installed store apps against what the app store lists for a
 * target version.
 */
export function computeCompatibility(
  installed: Record<string, string>,
  store: Map<string, string[]>,
): z.infer<typeof AppCompatibilitySchema>[] {
  return Object.entries(installed)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([app, installedVersion]) => {
      const versions = store.get(app) ?? [];
      return {
        app,
        installedVersion,
        compatible: versions.length > 0,
        installedReleaseCompatible: versions.includes(installedVersion),
        newestCompatibleVersion: newestVersion(versions),
      };
    });
}

/* ------------------------------------------------------------------ *
 * Backup verification
 * ------------------------------------------------------------------ */

/**
 * Read a SQL dump as a stream and report how many tables it creates and
 * whether it ends with mysqldump's completion line. A dump cut short by a
 * dropped connection or a full disk is still valid SQL up to the cut, so
 * the missing last line is the only sign.
 */
export async function inspectDump(
  stream: ReadableStream<Uint8Array>,
): Promise<{ createTables: number; complete: boolean }> {
  let createTables = 0;
  let last = "";
  let pending = "";
  const take = (line: string) => {
    if (/^CREATE TABLE /.test(line)) createTables++;
    if (line.trim() !== "") last = line;
  };
  for await (
    const chunk of stream.pipeThrough(new TextDecoderStream())
  ) {
    const lines = (pending + chunk).split("\n");
    pending = lines.pop() ?? "";
    lines.forEach(take);
  }
  take(pending);
  return { createTables, complete: /^-- Dump completed/.test(last) };
}

/** Reads exact byte counts from a stream. */
class ByteReader {
  #buf = new Uint8Array(0);
  #off = 0;
  constructor(private reader: ReadableStreamDefaultReader<Uint8Array>) {}

  async #fill(): Promise<boolean> {
    const { value, done } = await this.reader.read();
    if (done) return false;
    const rest = this.#buf.subarray(this.#off);
    const next = new Uint8Array(rest.length + value.length);
    next.set(rest);
    next.set(value, rest.length);
    this.#buf = next;
    this.#off = 0;
    return true;
  }

  async read(n: number): Promise<Uint8Array | null> {
    while (this.#buf.length - this.#off < n) {
      if (!(await this.#fill())) return null;
    }
    const out = this.#buf.slice(this.#off, this.#off + n);
    this.#off += n;
    return out;
  }

  async skip(n: number): Promise<boolean> {
    while (n > 0) {
      const avail = this.#buf.length - this.#off;
      if (avail === 0) {
        if (!(await this.#fill())) return false;
        continue;
      }
      const k = Math.min(avail, n);
      this.#off += k;
      n -= k;
    }
    return true;
  }

  async drain(): Promise<void> {
    while (await this.#fill()) this.#off = this.#buf.length;
  }

  /** Release the underlying stream, and with it the file, after an error. */
  async cancel(): Promise<void> {
    await this.reader.cancel().catch(() => {});
  }
}

function tarString(block: Uint8Array, start: number, len: number): string {
  const field = block.subarray(start, start + len);
  const end = field.indexOf(0);
  return new TextDecoder().decode(end === -1 ? field : field.subarray(0, end));
}

function tarNumber(block: Uint8Array, start: number, len: number): number {
  // GNU tar writes sizes over 8 GiB in base-256, flagged by the high bit.
  if (block[start] & 0x80) {
    let n = block[start] & 0x7f;
    for (let i = start + 1; i < start + len; i++) n = n * 256 + block[i];
    return n;
  }
  const s = tarString(block, start, len).trim();
  return s === "" ? 0 : parseInt(s, 8);
}

/**
 * List the entries of a gzip-compressed tar archive, verifying it on the way.
 *
 * Every header checksum is checked, the archive must reach its end-of-archive
 * marker, and the gzip stream is read to the end so its CRC is checked too.
 * Any of those failing throws: an archive that cannot be read back in full is
 * not a backup. Reading it in-process means verification does not depend on
 * which `tar` the machine swamp runs on has.
 */
export async function listTarGz(
  stream: ReadableStream<Uint8Array>,
): Promise<string[]> {
  const reader = new ByteReader(
    stream.pipeThrough(
      // lib.dom types the writable side as BufferSource; it takes bytes.
      new DecompressionStream("gzip") as unknown as TransformStream<
        Uint8Array,
        Uint8Array
      >,
    ).getReader(),
  );
  try {
    return await readTarEntries(reader);
  } catch (err) {
    await reader.cancel();
    throw err;
  }
}

async function readTarEntries(reader: ByteReader): Promise<string[]> {
  const names: string[] = [];
  let longName: string | null = null;
  for (;;) {
    const header = await reader.read(512);
    if (!header) {
      throw new Error("archive ends before its end-of-archive marker");
    }
    if (header.every((b) => b === 0)) break;

    const stored = tarNumber(header, 148, 8);
    let sum = 0;
    for (let i = 0; i < 512; i++) {
      sum += i >= 148 && i < 156 ? 32 : header[i];
    }
    if (sum !== stored) {
      throw new Error(
        `tar header checksum mismatch after ${names.length} entries`,
      );
    }

    const type = String.fromCharCode(header[156] || 48);
    const size = tarNumber(header, 124, 12);
    const padded = Math.ceil(size / 512) * 512;

    if (type === "L" || type === "x") {
      const data = await reader.read(padded);
      if (!data) throw new Error("archive truncated inside an extended header");
      const text = new TextDecoder().decode(data.subarray(0, size));
      if (type === "L") longName = text.replace(/\0.*$/s, "");
      else {
        const path = text.match(/^\d+ path=(.*)$/m)?.[1];
        if (path) longName = path;
      }
      continue;
    }

    let name = tarString(header, 0, 100);
    if (tarString(header, 257, 5) === "ustar") {
      const prefix = tarString(header, 345, 155);
      if (prefix) name = `${prefix}/${name}`;
    }
    if (longName !== null) {
      name = longName;
      longName = null;
    }
    if (type !== "g") names.push(name);
    if (!(await reader.skip(padded))) {
      throw new Error(`archive truncated inside ${name}`);
    }
  }
  // Read to the end so the gzip trailer's CRC and length are checked.
  await reader.drain();
  return names;
}

/** SHA-256 of a stream, as lowercase hex. */
export async function sha256Hex(
  stream: ReadableStream<Uint8Array>,
): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of stream) hash.update(chunk);
  return hash.digest("hex");
}

/** A command run in a container, optionally with stdout sent to a file. */
export type ExecSpec = {
  container: string;
  user: string | null;
  command: string[];
  /** Stream stdout into this new file (mode 600) instead of returning it. */
  stdoutFile?: string;
};

/** Runs a command in a container; replaceable in tests. */
export type ExecRunner = (
  spec: ExecSpec,
  timeoutMs: number,
  signal?: AbortSignal,
) => Promise<OccResult>;

function processExecRunner(g: GlobalArgs): ExecRunner {
  return async (spec, timeoutMs, signal) => {
    const { cmd, args } = dockerExecArgv(
      g,
      spec.container,
      spec.user,
      spec.command,
    );
    // Open the destination before starting anything remote, so a file that
    // cannot be created never leaves a dump running with nobody reading it.
    const file = spec.stdoutFile
      ? await Deno.open(spec.stdoutFile, {
        write: true,
        createNew: true,
        mode: 0o600,
      })
      : null;
    let proc: Deno.ChildProcess;
    try {
      proc = new Deno.Command(cmd, {
        args,
        stdin: "null",
        stdout: "piped",
        stderr: "piped",
        signal: callSignal(timeoutMs, signal),
      }).spawn();
    } catch (err) {
      file?.close();
      throw err;
    }
    const stderr = new Response(proc.stderr).text();
    let stdout = "";
    if (file) {
      // pipeTo closes the file when the stream ends or errors.
      await proc.stdout.pipeTo(file.writable);
    } else {
      stdout = await new Response(proc.stdout).text();
    }
    const status = await proc.status;
    return { code: status.code, stdout, stderr: await stderr };
  };
}

/* ------------------------------------------------------------------ *
 * Method implementations
 * ------------------------------------------------------------------ */

const DB_REPAIR_COMMANDS = [
  "db:add-missing-indices",
  "db:add-missing-columns",
  "db:add-missing-primary-keys",
];

async function readAppUpdates(
  run: OccRunner,
  g: GlobalArgs,
  signal: AbortSignal | undefined,
  enabled: Record<string, string>,
) {
  const out = await occ(
    run,
    ["app:update", "--showonly", "--no-warnings"],
    g.occTimeoutMs,
    signal,
  );
  return parseAppUpdates(out).map((u) => ({
    app: u.app,
    currentVersion: enabled[u.app] ?? null,
    availableVersion: u.availableVersion,
  }));
}

/** Test seam: the occ and exec runners, when not the real process. */
type Deps = { run?: OccRunner; exec?: ExecRunner };

function runnerFor(context: Context & Deps): OccRunner {
  return context.run ?? processRunner(context.globalArgs);
}

function execFor(context: Context & Deps): ExecRunner {
  return context.exec ?? processExecRunner(context.globalArgs);
}

/** Database connection details for `backup`, validated before use. */
export type DbTarget = { user: string; name: string; passwordEnv: string };

/**
 * Shell prelude for a command in the database container. The password is
 * passed to the client as MYSQL_PWD, taken from an environment variable the
 * container already has, so only the variable's NAME ever appears in a
 * command line. On a shared host every local user can read command lines
 * with `ps`; a process environment is readable only by its owner.
 */
function dbPrelude(db: DbTarget, clients: [string, string]): string {
  const [a, b] = clients;
  return `c=$(command -v ${a} || command -v ${b}) || ` +
    `{ echo "neither ${a} nor ${b} is in the database container" >&2; exit 127; }; ` +
    `[ -n "$${db.passwordEnv}" ] || ` +
    `{ echo "${db.passwordEnv} is not set in the database container" >&2; exit 64; }; ` +
    `MYSQL_PWD="$${db.passwordEnv}" exec "$c" -u ${db.user}`;
}

/** Script that prints the number of tables in the database. */
export function tableCountScript(db: DbTarget): string {
  return `${dbPrelude(db, ["mariadb", "mysql"])} -N -B -e ` +
    `"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = '${db.name}'"`;
}

/**
 * Script that writes a consistent dump of the database to stdout.
 * `--single-transaction` gives a consistent InnoDB snapshot without locking
 * the tables, so the instance can stay up while it runs.
 */
export function dumpScript(db: DbTarget): string {
  return `${dbPrelude(db, ["mariadb-dump", "mysqldump"])} ` +
    `--single-transaction --quick --routines --triggers --events ` +
    `--hex-blob --default-character-set=utf8mb4 ${db.name}`;
}

/** Parse `du -sk` output into path → KiB. */
export function parseDu(stdout: string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const line of stdout.split("\n")) {
    const m = line.trim().match(/^(\d+)\s+(.+)$/);
    if (m) out[m[2]] = parseInt(m[1], 10);
  }
  return out;
}

/** `20260925T151500Z`: sortable, and legal in a file name everywhere. */
export function backupStamp(d: Date): string {
  return d.toISOString().replace(/\.\d+Z$/, "Z").replace(/[-:]/g, "");
}

/**
 * Pre-flight for the methods that change state: prove `occ` answers in the
 * configured container and reports an installed instance, before anything is
 * changed.
 *
 * A check receives the instance's RAW global arguments, before the schema
 * applies its defaults, so they are parsed here first. Reading them as the
 * parsed type would see `container` and `dockerBin` as undefined on any
 * instance that relies on the defaults.
 */
export async function checkOccReachable(
  rawGlobalArgs: unknown,
  run?: OccRunner,
): Promise<{ pass: boolean; errors?: string[] }> {
  const parsed = GlobalArgsSchema.safeParse(rawGlobalArgs);
  if (!parsed.success) {
    return {
      pass: false,
      errors: [`global arguments do not validate: ${parsed.error.message}`],
    };
  }
  const g = parsed.data;
  try {
    const r = await (run ?? processRunner(g))(
      ["status", "--output=json"],
      g.occTimeoutMs,
    );
    if (r.code !== 0) {
      return {
        pass: false,
        errors: [
          `occ status exited ${r.code} in container ${g.container} on ` +
          `${g.sshHost ?? "local docker"}: ${
            (r.stderr.trim() || r.stdout.trim()).slice(-300)
          }`,
        ],
      };
    }
    const status = parseStatusDocument(JSON.parse(r.stdout));
    if (!status?.installed) {
      return {
        pass: false,
        errors: [`occ status does not report an installed Nextcloud`],
      };
    }
    return { pass: true };
  } catch (err) {
    return {
      pass: false,
      errors: [
        `could not run occ status: ${
          err instanceof Error ? err.message : String(err)
        }`,
      ],
    };
  }
}

/* ------------------------------------------------------------------ *
 * Model
 * ------------------------------------------------------------------ */

/**
 * Model type `@sntxrr/nextcloud/instance`.
 *
 * @example
 * ```bash
 * swamp model create @sntxrr/nextcloud/instance cloud \
 *   --global-arg baseUrl=https://cloud.example.com \
 *   --global-arg sshHost=nas.example.com \
 *   --global-arg container=nextcloud
 * swamp model @sntxrr/nextcloud/instance method run sync cloud
 * swamp model @sntxrr/nextcloud/instance method run drift cloud
 * swamp model @sntxrr/nextcloud/instance method run setupchecks cloud
 * swamp model @sntxrr/nextcloud/instance method run apps cloud
 * swamp model @sntxrr/nextcloud/instance method run dbRepair cloud
 * swamp model @sntxrr/nextcloud/instance method run dbRepair cloud \
 *   --arg apply=true
 * swamp model @sntxrr/nextcloud/instance method run apps cloud \
 *   --arg targetVersion=35.0.1
 * swamp model @sntxrr/nextcloud/instance method run backup cloud \
 *   --arg destDir=/srv/backups --arg dbContainer=nextcloud-db --arg apply=true
 * ```
 */
export const model = {
  type: "@sntxrr/nextcloud/instance",
  description:
    "Health, version drift, setup checks, app updates and compatibility, verified backups and occ maintenance for a self-hosted Nextcloud. Methods that change state are dry runs unless apply=true.",
  version: "2026.09.25.1",
  globalArguments: GlobalArgsSchema,
  upgrades: [
    {
      toVersion: "2026.09.25.1",
      description:
        "Add appStoreUrl (defaults to https://apps.nextcloud.com); existing arguments are unchanged",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],

  resources: {
    instance: {
      description: "status.php and, with a token, serverinfo statistics.",
      schema: InstanceSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    drift: {
      description:
        "Running version against stable releases: patch target, next major, and image availability.",
      schema: DriftSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    setupchecks: {
      description: "The admin overview's setup checks, as data.",
      schema: SetupChecksSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    apps: {
      description: "Installed apps and available app updates.",
      schema: AppsSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    maintenance: {
      description: "Maintenance mode before and after a change.",
      schema: MaintenanceSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    dbRepair: {
      description:
        "Missing indices, columns and primary keys, and their repair.",
      schema: DbRepairSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    appUpdate: {
      description: "An app update run: what was planned and what took.",
      schema: AppUpdateRunSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
    backup: {
      description:
        "A database dump and web-root archive: where it is and how it was verified.",
      schema: BackupSchema,
      lifetime: "infinite" as const,
      garbageCollection: 30,
    },
  },

  checks: {
    "occ-reachable": {
      description:
        "Before a method that can change state, prove occ answers in the configured container and reports an installed Nextcloud.",
      labels: ["live"],
      appliesTo: ["maintenance", "dbRepair", "updateApps", "backup"],
      execute: (context: { globalArgs: unknown }) =>
        checkOccReachable(context.globalArgs),
    },
  },

  methods: {
    sync: {
      description:
        "Read status.php, and serverinfo when a token is configured. An unreachable instance is recorded as unhealthy, not raised. Read-only.",
      arguments: z.object({}),
      execute: async (_args: Record<never, never>, context: Context) => {
        const { globalArgs: g, logger } = context;
        logger.info("Reading status.php from {url}{si}", {
          url: g.baseUrl,
          si: g.serverinfoToken ? " with serverinfo" : "",
        });
        const base = g.baseUrl.replace(/\/+$/, "");

        let httpStatus = 0;
        let detail = "";
        let status: StatusDocument | null = null;
        const started = performance.now();
        try {
          const res = await fetch(`${base}/status.php`, {
            signal: callSignal(g.timeoutMs, context.signal),
          });
          httpStatus = res.status;
          const text = await res.text();
          let parsed: unknown = null;
          try {
            parsed = JSON.parse(text);
          } catch {
            // Not JSON: a proxy error page, a login redirect target, etc.
          }
          status = res.ok ? parseStatusDocument(parsed) : null;
          detail = status ? "" : diagnoseStatusBody(httpStatus, text);
        } catch (err) {
          // A refused connection is a health result, not a model error.
          detail = err instanceof Error ? err.message : String(err);
        }
        const latencyMs = Math.round(performance.now() - started);
        const reachable = status !== null;
        const healthy = reachable && status!.installed &&
          !status!.maintenance && !status!.needsDbUpgrade;

        let serverinfo: ReturnType<typeof parseServerinfo> | null = null;
        let serverinfoError: string | null = null;
        if (g.serverinfoToken && reachable) {
          try {
            const res = await fetch(
              `${base}/ocs/v2.php/apps/serverinfo/api/v1/info?format=json`,
              {
                signal: callSignal(g.timeoutMs, context.signal),
                headers: {
                  "NC-Token": g.serverinfoToken,
                  "OCS-APIRequest": "true",
                  Accept: "application/json",
                },
              },
            );
            if (res.ok) serverinfo = parseServerinfo(await res.json());
            else {
              serverinfoError = `HTTP ${res.status}: ${await readErrorBody(
                res,
              )}`;
            }
          } catch (err) {
            serverinfoError = err instanceof Error ? err.message : String(err);
          }
          if (serverinfoError) {
            logger.warn("serverinfo unavailable: {error}", {
              error: serverinfoError,
            });
          }
        }

        if (healthy) {
          logger.info("Nextcloud {version} at {url} is healthy ({ms}ms)", {
            version: status!.versionstring,
            url: base,
            ms: latencyMs,
          });
        } else {
          logger.warn(
            "Nextcloud at {url} is not healthy: installed={i} maintenance={m} needsDbUpgrade={u} {detail}",
            {
              url: base,
              i: status?.installed ?? "?",
              m: status?.maintenance ?? "?",
              u: status?.needsDbUpgrade ?? "?",
              detail,
            },
          );
        }

        const handle = await context.writeResource(
          "instance",
          "instance-current",
          {
            url: base,
            reachable,
            healthy,
            httpStatus,
            latencyMs,
            installed: status?.installed ?? null,
            maintenance: status?.maintenance ?? null,
            needsDbUpgrade: status?.needsDbUpgrade ?? null,
            version: status?.version ?? null,
            versionString: status?.versionstring ?? null,
            extendedSupport: status?.extendedSupport ?? null,
            serverinfo,
            serverinfoError,
            detail,
            checkedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    drift: {
      description:
        "Compare the running version against stable releases, reporting the patch target and the next major separately (Nextcloud cannot skip a major), and confirm each target image exists. Read-only.",
      arguments: z.object({
        runningVersion: z.string().optional().describe(
          "Version to compare. Omit to read it from status.php. Supply it " +
            "when the pinned image tag is the better source, e.g. after a " +
            "bump whose `occ upgrade` has not run yet.",
        ),
        pageSize: z.number().int().min(1).max(100).default(100).describe(
          "Recent releases to examine. Nextcloud ships three supported majors " +
            "with release candidates for each, so a page covers a few months.",
        ),
        verifyImage: z.boolean().default(true).describe(
          "Confirm each offered target tag exists in the registry.",
        ),
      }),
      execute: async (
        args: {
          runningVersion?: string;
          pageSize: number;
          verifyImage: boolean;
        },
        context: Context,
      ) => {
        const { globalArgs: g, logger } = context;
        logger.info("Checking Nextcloud drift against {repo} releases", {
          repo: g.githubRepo,
        });

        let running = args.runningVersion?.trim();
        let runningVersionSource: "status.php" | "argument" = "argument";
        if (!running) {
          runningVersionSource = "status.php";
          const base = g.baseUrl.replace(/\/+$/, "");
          const res = await fetch(`${base}/status.php`, {
            signal: callSignal(g.timeoutMs, context.signal),
          });
          const text = await res.text();
          let parsed: unknown = null;
          try {
            parsed = JSON.parse(text);
          } catch {
            // Handled below.
          }
          const status = res.ok ? parseStatusDocument(parsed) : null;
          if (!status) {
            throw new Error(
              `cannot read the running version from status.php: ${
                diagnoseStatusBody(res.status, text)
              }`,
            );
          }
          running = status.versionstring;
        }

        const headers: Record<string, string> = {
          Accept: "application/vnd.github+json",
          "X-GitHub-Api-Version": "2022-11-28",
        };
        if (g.githubToken) headers.Authorization = `Bearer ${g.githubToken}`;
        const relRes = await fetch(
          `https://api.github.com/repos/${g.githubRepo}/releases?per_page=${args.pageSize}`,
          { headers, signal: callSignal(g.timeoutMs, context.signal) },
        );
        if (!relRes.ok) {
          const hint = relRes.status === 403 && !g.githubToken
            ? " (unauthenticated GitHub allows 60 requests/hour per IP; set " +
              "globalArgs.githubToken)"
            : "";
          throw new Error(
            `GitHub releases for ${g.githubRepo} returned HTTP ` +
              `${relRes.status}${hint}: ${await readErrorBody(relRes)}`,
          );
        }
        const raw = await relRes.json() as Array<
          { tag_name?: string; prerelease?: boolean; html_url?: string }
        >;
        const releases: ReleaseInfo[] = raw
          .filter((r) => typeof r.tag_name === "string")
          .map((r) => ({
            tag: r.tag_name as string,
            prerelease: Boolean(r.prerelease),
            htmlUrl: r.html_url ?? "",
          }));

        const drift = computeDrift(
          running,
          releases,
          raw.length >= args.pageSize,
        );

        const imageFor = (v: string | null) =>
          v ? `${g.imageRepository}:${imageTag(v, g.imageVariant)}` : null;
        const check = async (v: string | null) =>
          v && args.verifyImage
            ? await imageTagExists(
              g.verifyRegistry,
              g.verifyRepository,
              imageTag(v, g.imageVariant),
              g.timeoutMs,
              context.signal,
            )
            : null;

        const patchImage = imageFor(drift.patchTarget);
        const patchImageAvailable = await check(drift.patchTarget);
        const nextMajorImage = imageFor(drift.nextMajor);
        const nextMajorImageAvailable = await check(drift.nextMajor);
        for (
          const [image, ok] of [
            [patchImage, patchImageAvailable],
            [nextMajorImage, nextMajorImageAvailable],
          ] as const
        ) {
          if (image && ok === false) {
            logger.warn(
              "{image} is released but not in the registry yet; a deploy would fail at pull",
              { image },
            );
          }
        }

        const recommended = drift.patchTarget ?? drift.nextMajor;
        const releaseUrl =
          releases.find((r) =>
            recommended && parseVersion(r.tag) &&
            formatVersion(parseVersion(r.tag)!) === recommended
          )?.htmlUrl ?? `https://github.com/${g.githubRepo}/releases`;

        if (drift.truncated) {
          logger.warn(
            "the release page filled before reaching {running}; missedPatches may be incomplete",
            { running },
          );
        }
        logger.info(
          "Nextcloud running={running} status={status} patch={patch} nextMajor={next} latest={latest}",
          {
            running,
            status: drift.status,
            patch: drift.patchTarget ?? "-",
            next: drift.nextMajor ?? "-",
            latest: drift.latestVersion,
          },
        );

        const handle = await context.writeResource("drift", "drift-current", {
          runningVersion: running,
          runningVersionSource,
          ...drift,
          patchImage,
          patchImageAvailable,
          nextMajorImage,
          nextMajorImageAvailable,
          releaseUrl,
          checkedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    setupchecks: {
      description:
        "Run occ setupchecks and record every check, with warnings and errors pulled out. Read-only.",
      arguments: z.object({}),
      execute: async (
        _args: Record<never, never>,
        context: Context & Deps,
      ) => {
        const { globalArgs: g, logger } = context;
        logger.info("Running occ setupchecks in {container} on {host}", {
          container: g.container,
          host: g.sshHost ?? "local docker",
        });
        // Exit 1 means "some check warned", and still prints the report.
        const out = await occ(
          runnerFor(context),
          ["setupchecks", "--output=json"],
          g.occTimeoutMs,
          context.signal,
          [0, 1],
        );
        const checks = parseSetupChecks(out);
        const counts: Record<string, number> = {};
        for (const c of checks) {
          counts[c.severity] = (counts[c.severity] ?? 0) + 1;
        }
        const problems = checks.filter((c) =>
          c.severity === "warning" || c.severity === "error"
        );
        for (const p of problems) {
          logger.warn("setup check {severity}: {name} -- {description}", {
            severity: p.severity,
            name: p.name,
            description: p.description ?? "",
          });
        }
        const handle = await context.writeResource(
          "setupchecks",
          "setupchecks-current",
          {
            total: checks.length,
            counts,
            errors: counts.error ?? 0,
            warnings: counts.warning ?? 0,
            problems,
            checks,
            checkedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    apps: {
      description:
        "List installed apps and the ones with an app store update available. With targetVersion, also check every enabled store app has a stable release for that Nextcloud version. Read-only.",
      arguments: z.object({
        targetVersion: z.string().optional().describe(
          "A Nextcloud version to check app compatibility against, usually " +
            "`drift`'s `nextMajor`. Give a real release: the app store " +
            "answers for any version string, and one that does not exist " +
            "still matches apps with an open-ended range.",
        ),
      }),
      execute: async (
        args: { targetVersion?: string },
        context: Context & Deps,
      ) => {
        const { globalArgs: g, logger } = context;
        logger.info("Listing apps and app updates in {container} on {host}", {
          container: g.container,
          host: g.sshHost ?? "local docker",
        });
        const run = runnerFor(context);
        const { enabled, disabled } = parseAppList(
          await occ(
            run,
            ["app:list", "--output=json"],
            g.occTimeoutMs,
            context.signal,
          ),
        );
        const updates = await readAppUpdates(run, g, context.signal, enabled);
        logger.info("{enabled} apps enabled, {n} with updates: {apps}", {
          enabled: Object.keys(enabled).length,
          n: updates.length,
          apps: updates.map((u) => `${u.app} ${u.availableVersion}`).join(
            ", ",
          ) || "none",
        });

        let targetVersion: string | null = null;
        let compatibility: z.infer<typeof AppCompatibilitySchema>[] | null =
          null;
        let incompatible: string[] | null = null;
        if (args.targetVersion !== undefined) {
          const target = parseVersion(args.targetVersion);
          if (!target) {
            throw new Error(
              `targetVersion ${
                JSON.stringify(args.targetVersion)
              } is not a stable Nextcloud version`,
            );
          }
          targetVersion = formatVersion(target);
          // Shipped apps upgrade with the server; only store apps can block.
          const store = parseAppList(
            await occ(
              run,
              ["app:list", "--shipped=false", "--output=json"],
              g.occTimeoutMs,
              context.signal,
            ),
            true,
          ).enabled;
          const url = `${
            g.appStoreUrl.replace(/\/+$/, "")
          }/api/v1/platform/${targetVersion}/apps.json`;
          // The listing is several MB; allow it more than a status probe.
          const res = await fetch(url, {
            signal: callSignal(g.timeoutMs * 6, context.signal),
          });
          if (!res.ok) {
            throw new Error(
              `app store answered HTTP ${res.status} for ${targetVersion}: ` +
                `${await readErrorBody(res)}`,
            );
          }
          compatibility = computeCompatibility(
            store,
            parseStoreApps(await res.json()),
          );
          incompatible = compatibility.filter((c) => !c.compatible).map((c) =>
            c.app
          );
          for (const c of compatibility.filter((c) => !c.compatible)) {
            logger.warn(
              "{app} {installed} has no release for Nextcloud {target}; the upgrade would disable it",
              {
                app: c.app,
                installed: c.installedVersion,
                target: targetVersion,
              },
            );
          }
          logger.info(
            "{n} store apps checked against Nextcloud {target}: {bad} incompatible",
            {
              n: compatibility.length,
              target: targetVersion,
              bad: incompatible.length,
            },
          );
        }

        const handle = await context.writeResource("apps", "apps-current", {
          enabled,
          disabled,
          enabledCount: Object.keys(enabled).length,
          disabledCount: Object.keys(disabled).length,
          updates,
          hasUpdates: updates.length > 0,
          targetVersion,
          compatibility,
          incompatible,
          checkedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },

    maintenance: {
      description:
        "Turn maintenance mode on or off. Dry run unless apply=true; the apply path re-reads the mode and fails if it did not change.",
      arguments: z.object({
        mode: z.enum(["on", "off"]).describe("The state to put it in."),
        apply: z.boolean().default(false).describe(
          "Actually change the mode. Without it, report only.",
        ),
      }),
      execute: async (
        args: { mode: "on" | "off"; apply: boolean },
        context: Context & Deps,
      ) => {
        const { globalArgs: g, logger } = context;
        logger.info("Maintenance mode {mode} requested ({kind}) on {host}", {
          mode: args.mode,
          kind: args.apply ? "apply" : "dry run",
          host: g.sshHost ?? "local docker",
        });
        const run = runnerFor(context);
        const read = async () =>
          parseMaintenanceMode(
            await occ(
              run,
              ["maintenance:mode"],
              g.occTimeoutMs,
              context.signal,
            ),
          );

        const want = args.mode === "on";
        const before = await read();
        let after = before;
        if (before === want) {
          logger.info("maintenance mode is already {mode}; nothing to do", {
            mode: args.mode,
          });
        } else if (!args.apply) {
          logger.info(
            "Dry run. Would turn maintenance mode {mode}. Pass apply=true to act.",
            { mode: args.mode },
          );
        } else {
          await occ(
            run,
            ["maintenance:mode", want ? "--on" : "--off"],
            g.occTimeoutMs,
            context.signal,
          );
          after = await read();
          if (after !== want) {
            throw new Error(
              `maintenance:mode --${args.mode} exited 0 but the mode still ` +
                `reads ${after ? "on" : "off"}`,
            );
          }
          logger.info("maintenance mode turned {mode}", { mode: args.mode });
        }

        const handle = await context.writeResource(
          "maintenance",
          "maintenance-current",
          {
            requested: args.mode,
            enabledBefore: before,
            enabledAfter: after,
            changed: before !== after,
            applied: args.apply && before !== want,
            checkedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },

    dbRepair: {
      description:
        "Find missing database indices, columns and primary keys, the repairs the admin overview asks for after an upgrade. Dry run unless apply=true; the apply path re-runs the dry run and fails if anything is still pending.",
      arguments: z.object({
        apply: z.boolean().default(false).describe(
          "Run the repairs. Adding an index to a large table can take " +
            "minutes and locks it on some databases, so schedule accordingly.",
        ),
      }),
      execute: async (args: { apply: boolean }, context: Context & Deps) => {
        const { globalArgs: g, logger } = context;
        logger.info(
          "Checking missing indices, columns and primary keys ({kind}) on {host}",
          {
            kind: args.apply ? "apply" : "dry run",
            host: g.sshHost ?? "local docker",
          },
        );
        const run = runnerFor(context);
        const dryRun = async (command: string) =>
          parseRepairDryRun(
            command,
            await occ(
              run,
              [command, "--dry-run"],
              g.occTimeoutMs,
              context.signal,
            ),
          );

        const steps: z.infer<typeof DbRepairStepSchema>[] = [];
        for (const command of DB_REPAIR_COMMANDS) {
          const { items, sql } = await dryRun(command);
          let remaining: number | null = null;
          if (args.apply && items.length > 0) {
            await occ(run, [command], g.occTimeoutMs * 10, context.signal);
            remaining = (await dryRun(command)).items.length;
          } else if (args.apply) {
            remaining = 0;
          }
          steps.push({
            command,
            pendingItems: items,
            remainingItems: remaining,
            sql,
          });
        }
        const pending = steps.reduce((n, s) => n + s.pendingItems.length, 0);

        const handle = await context.writeResource(
          "dbRepair",
          "dbRepair-current",
          {
            applied: args.apply,
            pending,
            steps,
            checkedAt: new Date().toISOString(),
          },
        );

        const stuck = steps.filter((s) => (s.remainingItems ?? 0) > 0);
        if (stuck.length > 0) {
          throw new Error(
            `repairs ran but still pending: ${
              stuck.map((s) => `${s.command} (${s.remainingItems})`).join(
                ", ",
              )
            }`,
          );
        }
        logger.info(
          args.apply
            ? "database repaired: {n} items added"
            : "Dry run. {n} items missing. Pass apply=true to add them.",
          { n: pending },
        );
        return { dataHandles: [handle] };
      },
    },

    updateApps: {
      description:
        "Update apps from the app store, either the named ones or every app with an update. Dry run unless apply=true; the apply path re-reads the update list and fails if a planned app still reports one.",
      arguments: z.object({
        apps: z.array(z.string().regex(APP_ID_PATTERN)).default([]).describe(
          "App ids to update. Empty means every app with an update.",
        ),
        apply: z.boolean().default(false).describe(
          "Run the updates. Without it, report the plan only.",
        ),
      }),
      execute: async (
        args: { apps: string[]; apply: boolean },
        context: Context & Deps,
      ) => {
        const { globalArgs: g, logger } = context;
        logger.info("Planning app updates for {apps} ({kind}) on {host}", {
          apps: args.apps.join(", ") || "every app with an update",
          kind: args.apply ? "apply" : "dry run",
          host: g.sshHost ?? "local docker",
        });
        const run = runnerFor(context);
        const list = async () =>
          parseAppList(
            await occ(
              run,
              ["app:list", "--output=json"],
              g.occTimeoutMs,
              context.signal,
            ),
          ).enabled;

        const available = await readAppUpdates(
          run,
          g,
          context.signal,
          await list(),
        );
        const planned = args.apps.length === 0
          ? available
          : available.filter((u) => args.apps.includes(u.app));
        const notOffered = args.apps.filter((a) =>
          !available.some((u) => u.app === a)
        );
        if (notOffered.length > 0) {
          logger.warn("no update available for: {apps}", {
            apps: notOffered.join(", "),
          });
        }

        let updated: string[] = [];
        let stillPending: string[] = [];
        if (args.apply && planned.length > 0) {
          for (const u of planned) {
            await occ(
              run,
              ["app:update", u.app],
              g.occTimeoutMs * 10,
              context.signal,
            );
          }
          const after = await readAppUpdates(
            run,
            g,
            context.signal,
            await list(),
          );
          stillPending = planned.filter((u) =>
            after.some((a) => a.app === u.app)
          ).map((u) => u.app);
          updated = planned.map((u) => u.app).filter((a) =>
            !stillPending.includes(a)
          );
        } else if (!args.apply) {
          logger.info(
            "Dry run. Would update {n} apps: {apps}. Pass apply=true to act.",
            {
              n: planned.length,
              apps: planned.map((u) => `${u.app} ${u.availableVersion}`)
                .join(", ") || "none",
            },
          );
        }

        const handle = await context.writeResource(
          "appUpdate",
          "appUpdate-current",
          {
            applied: args.apply,
            requested: args.apps,
            planned,
            updated,
            stillPending,
            checkedAt: new Date().toISOString(),
          },
        );
        if (stillPending.length > 0) {
          throw new Error(
            `app:update exited 0 but these still report an update: ${
              stillPending.join(", ")
            }`,
          );
        }
        return { dataHandles: [handle] };
      },
    },

    backup: {
      description:
        "Dump the MySQL/MariaDB database and archive web-root directories (config and custom_apps by default) into a new directory on the machine swamp runs on, then read both back to verify them. Dry run unless apply=true. The rollback point for an upgrade.",
      arguments: z.object({
        destDir: z.string().regex(/^\//).describe(
          "Existing absolute directory, on the machine swamp runs on, to " +
            "create the backup directory in. It is not created: a typo " +
            "should fail, not scatter a tree.",
        ),
        label: z.string().regex(NAME_PATTERN).default("nextcloud").describe(
          "Prefix of the backup directory, which is <label>-<UTC timestamp>.",
        ),
        dbContainer: z.string().regex(NAME_PATTERN).describe(
          "Name of the MySQL/MariaDB container.",
        ),
        dbName: z.string().regex(NAME_PATTERN).default("nextcloud"),
        dbUser: z.string().regex(NAME_PATTERN).default("root").describe(
          "Database user to dump as. root sees routines and events; the " +
            "application user may not.",
        ),
        dbPasswordEnv: z.string().regex(ENV_NAME_PATTERN).default(
          "MARIADB_ROOT_PASSWORD",
        ).describe(
          "Environment variable, inside the database container, that holds " +
            "dbUser's password. The mariadb image sets MARIADB_ROOT_PASSWORD, " +
            "the mysql image MYSQL_ROOT_PASSWORD. The value never leaves the " +
            "container and never appears in a command line.",
        ),
        webRoot: z.string().regex(/^\/[A-Za-z0-9_./-]*$/).default(
          "/var/www/html",
        ).describe("The web root inside the application container."),
        paths: z.array(z.string().regex(WEBROOT_PATH_PATTERN)).min(1).default([
          "config",
          "custom_apps",
          "themes",
        ]).describe(
          "Directories directly under webRoot to archive. The defaults are " +
            "what an upgrade changes: config.php and the store apps it " +
            "updates. User files in `data` are not touched by an upgrade and " +
            "can be large; add `data` to include them.",
        ),
        apply: z.boolean().default(false).describe(
          "Write the backup. Without it, measure what would be backed up " +
            "and write nothing.",
        ),
      }),
      execute: async (
        args: {
          destDir: string;
          label: string;
          dbContainer: string;
          dbName: string;
          dbUser: string;
          dbPasswordEnv: string;
          webRoot: string;
          paths: string[];
          apply: boolean;
        },
        context: Context & Deps,
      ) => {
        const { globalArgs: g, logger } = context;
        const run = runnerFor(context);
        const exec = execFor(context);
        const db: DbTarget = {
          user: args.dbUser,
          name: args.dbName,
          passwordEnv: args.dbPasswordEnv,
        };
        const longTimeout = g.occTimeoutMs * 10;
        // du over a large `data` path can outlast a read-only occ timeout.
        const execOk = async (spec: ExecSpec, what: string) => {
          const r = await exec(spec, longTimeout, context.signal);
          if (r.code !== 0) {
            throw new Error(
              `${what} exited ${r.code}: ${
                (r.stderr.trim() || r.stdout.trim()).slice(-400)
              }`,
            );
          }
          return r.stdout;
        };

        const status = parseStatusDocument(
          JSON.parse(
            await occ(
              run,
              ["status", "--output=json"],
              g.occTimeoutMs,
              context.signal,
            ),
          ),
        );
        if (!status?.installed) {
          throw new Error("occ status does not report an installed Nextcloud");
        }

        const liveTablesRaw = (await execOk(
          {
            container: args.dbContainer,
            user: null,
            command: ["sh", "-c", tableCountScript(db)],
          },
          "counting tables",
        )).trim();
        const liveTables = /^\d+$/.test(liveTablesRaw)
          ? parseInt(liveTablesRaw, 10)
          : NaN;
        if (!(liveTables > 0)) {
          throw new Error(
            `database ${args.dbName} reports ${
              JSON.stringify(liveTablesRaw.slice(0, 100))
            } tables; refusing to back up what looks like the wrong database`,
          );
        }

        const sourceKiB = parseDu(
          await execOk(
            {
              container: g.container,
              user: g.occUser,
              command: [
                "sh",
                "-c",
                `cd ${shellQuote(args.webRoot)} && du -sk -- ${
                  args.paths.map(shellQuote).join(" ")
                }`,
              ],
            },
            "measuring paths",
          ),
        );
        const missing = args.paths.filter((p) => !(p in sourceKiB));
        if (missing.length > 0) {
          throw new Error(
            `not found under ${args.webRoot}: ${missing.join(", ")}`,
          );
        }

        const summary = {
          nextcloudVersion: status.versionstring,
          database: {
            container: args.dbContainer,
            name: args.dbName,
            liveTables,
          },
          sourceKiB,
        };

        if (!args.apply) {
          logger.info(
            "Dry run. Would back up Nextcloud {version}: database {db} ({tables} tables) and {paths} ({kib} KiB) into {dest}. Pass apply=true to write it.",
            {
              version: status.versionstring,
              db: args.dbName,
              tables: liveTables,
              paths: args.paths.join(", "),
              kib: Object.values(sourceKiB).reduce((a, b) => a + b, 0),
              dest: args.destDir,
            },
          );
          const handle = await context.writeResource(
            "backup",
            "backup-current",
            {
              applied: false,
              verified: false,
              directory: null,
              nextcloudVersion: summary.nextcloudVersion,
              database: {
                ...summary.database,
                dumpedTables: null,
                dumpComplete: null,
              },
              archive: {
                paths: args.paths,
                sourceKiB,
                entries: null,
                hasConfigPhp: null,
              },
              files: [],
              problems: [],
              checkedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        }

        const dest = await Deno.stat(args.destDir).catch(() => null);
        if (!dest?.isDirectory) {
          throw new Error(
            `destDir ${args.destDir} is not an existing directory`,
          );
        }
        const dir = `${args.destDir.replace(/\/+$/, "")}/${args.label}-${
          backupStamp(new Date())
        }`;
        await Deno.mkdir(dir, { mode: 0o700 });
        await Deno.chmod(dir, 0o700);
        logger.info("Backing up Nextcloud {version} into {dir}", {
          version: status.versionstring,
          dir,
        });

        const problems: string[] = [];
        const dumpName = `${args.dbName}.sql`;
        const archiveName = "files.tar.gz";

        // A failure here is recorded, not thrown, so the directory is still
        // renamed .FAILED below and cannot be mistaken for a good backup.
        const capture = async (spec: ExecSpec, what: string) => {
          try {
            const r = await exec(spec, longTimeout, context.signal);
            if (r.code !== 0) {
              problems.push(
                `${what} exited ${r.code}: ${r.stderr.trim().slice(-300)}`,
              );
            }
          } catch (err) {
            problems.push(
              `${what} failed: ${
                err instanceof Error ? err.message : String(err)
              }`,
            );
          }
        };
        await capture({
          container: args.dbContainer,
          user: null,
          command: ["sh", "-c", dumpScript(db)],
          stdoutFile: `${dir}/${dumpName}`,
        }, "database dump");
        await capture({
          container: g.container,
          user: g.occUser,
          command: [
            "tar",
            "-czf",
            "-",
            "-C",
            args.webRoot,
            "--",
            ...args.paths,
          ],
          stdoutFile: `${dir}/${archiveName}`,
        }, "tar");

        const openRead = async (name: string) =>
          (await Deno.open(`${dir}/${name}`, { read: true })).readable;

        let dumpedTables: number | null = null;
        let dumpComplete: boolean | null = null;
        try {
          const d = await inspectDump(await openRead(dumpName));
          dumpedTables = d.createTables;
          dumpComplete = d.complete;
          if (!d.complete) {
            problems.push(
              "the dump does not end with `-- Dump completed`; it was cut short",
            );
          }
          if (d.createTables !== liveTables) {
            problems.push(
              `the dump creates ${d.createTables} tables; the database has ${liveTables}`,
            );
          }
        } catch (err) {
          problems.push(
            `could not read the dump back: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        }

        let entries: number | null = null;
        let hasConfigPhp: boolean | null = null;
        try {
          const names = await listTarGz(await openRead(archiveName));
          entries = names.length;
          if (entries === 0) problems.push("the archive has no entries");
          if (args.paths.includes("config")) {
            hasConfigPhp = names.includes("config/config.php");
            if (!hasConfigPhp) {
              problems.push("the archive has no config/config.php");
            }
          }
        } catch (err) {
          problems.push(
            `could not read the archive back: ${
              err instanceof Error ? err.message : String(err)
            }`,
          );
        }

        const files: z.infer<typeof BackupFileSchema>[] = [];
        for (const name of [dumpName, archiveName]) {
          const stat = await Deno.stat(`${dir}/${name}`).catch(() => null);
          if (!stat) {
            problems.push(`${name} was not written`);
            continue;
          }
          files.push({
            name,
            bytes: stat.size,
            sha256: await sha256Hex(await openRead(name)),
          });
        }
        await Deno.writeTextFile(
          `${dir}/SHA256SUMS`,
          files.map((f) => `${f.sha256}  ${f.name}\n`).join(""),
          { mode: 0o600, createNew: true },
        );

        const verified = problems.length === 0;
        const finalDir = verified ? dir : `${dir}.FAILED`;
        const record = {
          applied: true,
          verified,
          directory: finalDir,
          nextcloudVersion: summary.nextcloudVersion,
          database: { ...summary.database, dumpedTables, dumpComplete },
          archive: { paths: args.paths, sourceKiB, entries, hasConfigPhp },
          files,
          problems,
          checkedAt: new Date().toISOString(),
        };
        // The directory describes itself: a restore should not depend on
        // swamp's datastore being reachable.
        await Deno.writeTextFile(
          `${dir}/BACKUP.json`,
          JSON.stringify(record, null, 2) + "\n",
          { mode: 0o600, createNew: true },
        );
        if (!verified) await Deno.rename(dir, finalDir);

        const handle = await context.writeResource(
          "backup",
          "backup-current",
          record,
        );
        if (!verified) {
          throw new Error(
            `backup failed verification and was renamed ${finalDir}: ${
              problems.join("; ")
            }`,
          );
        }
        logger.info(
          "Backup verified: {tables} tables, {entries} archive entries, {dir}",
          { tables: dumpedTables, entries, dir },
        );
        return { dataHandles: [handle] };
      },
    },
  },
};
