/**
 * Nextcloud instance — health, version drift, app updates and `occ`
 * maintenance for a self-hosted {@link https://nextcloud.com | Nextcloud}.
 *
 * Seven methods over two transports.
 *
 * Over HTTP, needing no credential beyond an optional read-only token:
 *
 * - `sync` reads `status.php` (installed, maintenance, needsDbUpgrade,
 *   version) and, when a serverinfo token is configured, the serverinfo API
 *   (storage, users, database size, PHP, active users).
 * - `drift` compares the running version against Nextcloud's published stable
 *   releases and reports the patch target and the next major separately.
 *
 * Over `occ`, run with `docker exec` either locally or on a host over SSH:
 *
 * - `setupchecks` — the admin overview's warnings, as data. Read-only.
 * - `apps` — installed apps and the ones with updates available. Read-only.
 * - `maintenance` — turn maintenance mode on or off.
 * - `dbRepair` — add missing indices, columns and primary keys.
 * - `updateApps` — update apps from the app store.
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
import { z } from "npm:zod@4";

const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const APP_ID_PATTERN = /^[a-z0-9_]+$/;

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
    "Optional serverinfo token, sent as the `NC-Token` header. Set on the " +
      "instance with `occ config:app:set serverinfo token --value <token>`. It " +
      "grants read access to the monitoring endpoint only, not an account, so " +
      "it is the least-privileged way to read storage and user statistics. " +
      "Without it `sync` reads `status.php` alone. Supply it from a vault.",
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

const AppsSchema = z.object({
  enabled: z.record(z.string(), z.string()).describe("App id → version."),
  disabled: z.record(z.string(), z.string()).describe("App id → version."),
  enabledCount: z.number().int(),
  disabledCount: z.number().int(),
  updates: z.array(AppUpdateSchema).describe(
    "Apps with a newer store release, as `occ app:update --showonly` reports.",
  ),
  hasUpdates: z.boolean().describe("The single field to alert on."),
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
  g: Pick<
    GlobalArgs,
    | "sshHost"
    | "sshUser"
    | "strictHostKeyChecking"
    | "knownHostsFile"
    | "dockerBin"
    | "container"
    | "occUser"
  >,
  occArgs: string[],
): { cmd: string; args: string[] } {
  const docker = [
    "exec",
    "-u",
    g.occUser,
    g.container,
    "php",
    "occ",
    "--no-interaction",
    "--no-ansi",
    ...occArgs,
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

/** Parse `occ app:list --output=json`. */
export function parseAppList(stdout: string): {
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
  if (Object.keys(enabled).length === 0) {
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

/** Test seam: the occ runner, when not the real process. */
type Deps = { run?: OccRunner };

function runnerFor(context: Context & Deps): OccRunner {
  return context.run ?? processRunner(context.globalArgs);
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
 * ```
 */
export const model = {
  type: "@sntxrr/nextcloud/instance",
  description:
    "Health, version drift, setup checks, app updates and occ maintenance for a self-hosted Nextcloud. Methods that change state are dry runs unless apply=true.",
  version: "2026.09.24.1",
  globalArguments: GlobalArgsSchema,

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
  },

  checks: {
    "occ-reachable": {
      description:
        "Before a method that can change state, prove occ answers in the configured container and reports an installed Nextcloud.",
      labels: ["live"],
      appliesTo: ["maintenance", "dbRepair", "updateApps"],
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
        "List installed apps and the ones with an app store update available. Read-only.",
      arguments: z.object({}),
      execute: async (
        _args: Record<never, never>,
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
        const handle = await context.writeResource("apps", "apps-current", {
          enabled,
          disabled,
          enabledCount: Object.keys(enabled).length,
          disabledCount: Object.keys(disabled).length,
          updates,
          hasUpdates: updates.length > 0,
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
  },
};
