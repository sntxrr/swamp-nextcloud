import {
  assert,
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1";
import {
  checkOccReachable,
  computeDrift,
  diagnoseStatusBody,
  imageTag,
  model,
  occArgv,
  type OccResult,
  parseAppList,
  parseAppUpdates,
  parseMaintenanceMode,
  parseRepairDryRun,
  parseServerinfo,
  parseSetupChecks,
  parseStatusDocument,
  parseVersion,
  type ReleaseInfo,
  shellQuote,
} from "./nextcloud_instance.ts";

/* ------------------------------------------------------------------ *
 * Versions and drift
 * ------------------------------------------------------------------ */

Deno.test("parseVersion accepts release tags and the four-part internal version", () => {
  const expected = { major: 34, minor: 0, patch: 4 };
  assertEquals(parseVersion("v34.0.4"), expected);
  assertEquals(parseVersion("34.0.4"), expected);
  assertEquals(parseVersion("34.0.4.1"), expected);
});

Deno.test("parseVersion rejects every prerelease spelling Nextcloud has used", () => {
  // Both `rc2` and `RC2` exist as tags for 35.0.0. A suffix of any kind means
  // "not stable", never something to parse around.
  for (
    const tag of ["v35.0.0rc2", "v35.0.0RC2", "v35.0.0beta4", "v35.0.1rc1"]
  ) {
    assertEquals(parseVersion(tag), null, tag);
  }
});

// The release feed as it stood on 2026-09-24, newest first.
const RELEASES: ReleaseInfo[] = [
  ["v35.0.1", false],
  ["v35.0.1rc1", true],
  ["v35.0.0", false],
  ["v35.0.0rc4", true],
  ["v34.0.4", false],
  ["v33.0.9", false],
  ["v32.0.15", false],
  ["v35.0.0RC2", true],
  ["v34.0.3", false],
  ["v33.0.8", false],
  ["v32.0.14", false],
  ["v34.0.2", false],
  ["v33.0.7", false],
].map(([tag, prerelease]) => ({
  tag: tag as string,
  prerelease: prerelease as boolean,
  htmlUrl: `https://example.test/${tag}`,
}));

Deno.test("fully patched on the previous major reads behind-major", () => {
  const d = computeDrift("34.0.4", RELEASES, false);
  assertEquals(d.status, "behind-major");
  assertEquals(d.behind, true);
  assertEquals(d.patchTarget, null);
  assertEquals(d.nextMajor, "35.0.1");
  assertEquals(d.latestVersion, "35.0.1");
  assertEquals(d.majorsBehind, 1);
});

Deno.test("a missing patch is the target before any major", () => {
  const d = computeDrift("34.0.2", RELEASES, false);
  assertEquals(d.status, "behind-patch");
  assertEquals(d.patchTarget, "34.0.4");
  assertEquals(d.missedPatches, ["34.0.4", "34.0.3"]);
  assertEquals(d.nextMajor, "35.0.1");
});

Deno.test("two majors behind offers the next major, never the latest", () => {
  // Nextcloud refuses to skip a major; 33 -> 35 is not a legal upgrade.
  const d = computeDrift("33.0.9", RELEASES, false);
  assertEquals(d.status, "behind-major");
  assertEquals(d.nextMajor, "34.0.4");
  assertEquals(d.latestVersion, "35.0.1");
  assertEquals(d.majorsBehind, 2);
});

Deno.test("prereleases are never offered", () => {
  const d = computeDrift("35.0.0", RELEASES, false);
  // 35.0.1rc1 must not appear; 35.0.1 final is the patch.
  assertEquals(d.patchTarget, "35.0.1");
  assertEquals(d.missedPatches, ["35.0.1"]);
});

Deno.test("current and ahead", () => {
  assertEquals(computeDrift("35.0.1", RELEASES, false).status, "current");
  const ahead = computeDrift("36.0.0", RELEASES, false);
  assertEquals(ahead.status, "ahead");
  assertEquals(ahead.behind, false);
});

Deno.test("a full page ending above the running version is truncated", () => {
  assertEquals(computeDrift("30.0.0", RELEASES, true).truncated, true);
  assertEquals(computeDrift("30.0.0", RELEASES, false).truncated, false);
  assertEquals(computeDrift("34.0.4", RELEASES, true).truncated, false);
});

Deno.test("an unparseable running version throws instead of reading current", () => {
  assertThrows(() => computeDrift("", RELEASES, false), Error, "refusing");
  assertThrows(() => computeDrift("35.0.0rc1", RELEASES, false), Error);
});

Deno.test("a page with no stable release throws", () => {
  assertThrows(
    () =>
      computeDrift("34.0.4", [{
        tag: "v35.0.0rc1",
        prerelease: true,
        htmlUrl: "",
      }], false),
    Error,
    "no stable releases",
  );
});

Deno.test("imageTag appends the variant only when there is one", () => {
  assertEquals(imageTag("34.0.4", "apache"), "34.0.4-apache");
  assertEquals(imageTag("34.0.4", ""), "34.0.4");
});

/* ------------------------------------------------------------------ *
 * status.php and serverinfo
 * ------------------------------------------------------------------ */

const STATUS = {
  installed: true,
  maintenance: false,
  needsDbUpgrade: false,
  version: "34.0.4.1",
  versionstring: "34.0.4",
  edition: "",
  productname: "Nextcloud",
  extendedSupport: false,
};

Deno.test("parseStatusDocument accepts a real status.php body", () => {
  assertEquals(parseStatusDocument(STATUS)?.versionstring, "34.0.4");
});

Deno.test("parseStatusDocument rejects the trusted-domain error body", () => {
  assertEquals(
    parseStatusDocument({ error: "Trusted domain error.", code: 15 }),
    null,
  );
});

Deno.test("diagnoseStatusBody names the trusted-domain cause", () => {
  const msg = diagnoseStatusBody(
    400,
    '{"error": "Trusted domain error.", "code": 15}',
  );
  assert(msg.includes("trusted_domains"), msg);
  assertEquals(diagnoseStatusBody(502, "Bad Gateway"), "HTTP 502: Bad Gateway");
});

Deno.test("parseServerinfo reads the documented OCS paths", () => {
  const info = parseServerinfo({
    ocs: {
      data: {
        nextcloud: {
          system: { freespace: 1000 },
          storage: { num_users: 3, num_files: "42" },
          shares: { num_shares: 5 },
        },
        server: {
          php: { version: "8.3.10" },
          database: { type: "pgsql", version: "16.4", size: 123 },
        },
        activeUsers: { last5minutes: 1, last1hour: 2, last24hours: 3 },
      },
    },
  });
  assertEquals(info.numFiles, 42);
  assertEquals(info.databaseType, "pgsql");
  assertEquals(info.activeUsers24h, 3);
  assertThrows(() => parseServerinfo({}), Error, "ocs.data");
});

/* ------------------------------------------------------------------ *
 * occ transport
 * ------------------------------------------------------------------ */

const TRANSPORT = {
  sshHost: undefined as string | undefined,
  sshUser: undefined as string | undefined,
  strictHostKeyChecking: "yes" as const,
  knownHostsFile: undefined as string | undefined,
  dockerBin: "docker",
  container: "nextcloud",
  occUser: "www-data",
};

Deno.test("occArgv runs docker directly when there is no sshHost", () => {
  const { cmd, args } = occArgv(TRANSPORT, ["status"]);
  assertEquals(cmd, "docker");
  assertEquals(args, [
    "exec",
    "-u",
    "www-data",
    "nextcloud",
    "php",
    "occ",
    "--no-interaction",
    "--no-ansi",
    "status",
  ]);
});

Deno.test("occArgv over ssh uses BatchMode and one quoted remote command", () => {
  const { cmd, args } = occArgv(
    { ...TRANSPORT, sshHost: "nas.example.com", sshUser: "ops" },
    ["setupchecks", "--output=json"],
  );
  assertEquals(cmd, "ssh");
  assert(args.includes("BatchMode=yes"));
  assert(args.includes("StrictHostKeyChecking=yes"));
  assertEquals(args.at(-2), "ops@nas.example.com");
  assertEquals(
    args.at(-1),
    "docker exec -u www-data nextcloud php occ --no-interaction --no-ansi setupchecks --output=json",
  );
});

Deno.test("shellQuote neutralises shell metacharacters", () => {
  assertEquals(shellQuote("plain-arg"), "plain-arg");
  assertEquals(shellQuote("a b"), "'a b'");
  assertEquals(shellQuote("x'; rm -rf /"), `'x'"'"'; rm -rf /'`);
});

/* ------------------------------------------------------------------ *
 * occ output parsing
 * ------------------------------------------------------------------ */

const SETUPCHECKS = JSON.stringify({
  system: {
    "OCA\\LogReader\\SetupChecks\\LogErrors": {
      name: "Errors in the log",
      severity: "warning",
      description: "2 errors in the logs",
      descriptionParameters: null,
      linkToDoc: null,
    },
    "OCA\\Settings\\SetupChecks\\CronErrors": {
      name: "Cron errors",
      severity: "success",
      description: null,
      descriptionParameters: null,
      linkToDoc: null,
    },
  },
});

Deno.test("parseSetupChecks flattens categories", () => {
  const checks = parseSetupChecks(SETUPCHECKS);
  assertEquals(checks.length, 2);
  assertEquals(checks[0].category, "system");
  assertEquals(checks[0].severity, "warning");
});

Deno.test("parseSetupChecks refuses non-JSON and an empty report", () => {
  assertThrows(() => parseSetupChecks("Nextcloud is not installed"), Error);
  assertThrows(() => parseSetupChecks("{}"), Error, "never measured");
});

Deno.test("parseAppList handles PHP's empty-array serialisation", () => {
  const r = parseAppList('{"enabled":{"dav":"1.40.0"},"disabled":[]}');
  assertEquals(r.enabled, { dav: "1.40.0" });
  assertEquals(r.disabled, {});
  assertThrows(() => parseAppList('{"enabled":[],"disabled":[]}'), Error);
});

Deno.test("parseAppUpdates reads the format core/Command/App/Update.php prints", () => {
  assertEquals(
    parseAppUpdates(
      "calendar new version available: 6.6.2\n" +
        "user_oidc new version available: 8.12.0 (current version: 8.11.0)\n",
    ),
    [
      { app: "calendar", availableVersion: "6.6.2" },
      { app: "user_oidc", availableVersion: "8.12.0" },
    ],
  );
  assertEquals(
    parseAppUpdates("All apps are up-to-date or no updates could be found\n"),
    [],
  );
});

Deno.test("parseAppUpdates refuses output it does not recognise", () => {
  // e.g. an app store outage printing an error instead of the list.
  assertThrows(
    () => parseAppUpdates("Could not connect to appstore\n"),
    Error,
    "does not recognise",
  );
});

Deno.test("parseMaintenanceMode reads both states and refuses others", () => {
  assertEquals(
    parseMaintenanceMode("Maintenance mode is currently enabled"),
    true,
  );
  assertEquals(
    parseMaintenanceMode("Maintenance mode is currently disabled"),
    false,
  );
  assertThrows(() => parseMaintenanceMode(""), Error);
});

const PENDING_INDEX =
  "Adding additional fs_size index to the filecache table, this can take some time...\n" +
  "CREATE INDEX fs_size ON oc_filecache (size);\n" +
  "filecache table updated successfully.\n";

Deno.test("parseRepairDryRun counts items and keeps the SQL", () => {
  const r = parseRepairDryRun("db:add-missing-indices", PENDING_INDEX);
  assertEquals(r.items.length, 1);
  assertEquals(r.sql, ["CREATE INDEX fs_size ON oc_filecache (size);"]);
  assertEquals(parseRepairDryRun("x", ""), { items: [], sql: [] });
  assertEquals(
    parseRepairDryRun(
      "db:add-missing-primary-keys",
      "Adding primary key to the oc_x table, this can take some time...\n" +
        "ALTER TABLE oc_x ADD PRIMARY KEY (id);\n",
    ).items.length,
    1,
  );
});

Deno.test("parseRepairDryRun throws when progress and SQL disagree", () => {
  // Either direction means the output format moved under the parser. Counting
  // only one of them would read that as "nothing pending".
  assertThrows(
    () =>
      parseRepairDryRun(
        "db:add-missing-indices",
        "Adding additional fs_size index to the filecache table...\n",
      ),
    Error,
    "not trusted",
  );
  assertThrows(
    () =>
      parseRepairDryRun("db:add-missing-indices", "CREATE INDEX a ON b (c);"),
    Error,
    "not trusted",
  );
});

/* ------------------------------------------------------------------ *
 * Methods, against a scripted occ
 * ------------------------------------------------------------------ */

type Script = Record<string, OccResult | OccResult[]>;

function harness(script: Script) {
  const calls: string[] = [];
  const written: Record<string, Record<string, unknown>> = {};
  const counters: Record<string, number> = {};
  const ok = (stdout: string, code = 0): OccResult => ({
    code,
    stdout,
    stderr: "",
  });
  const context = {
    globalArgs: {
      ...TRANSPORT,
      baseUrl: "https://cloud.example.com",
      githubRepo: "nextcloud/server",
      imageRepository: "nextcloud",
      imageVariant: "apache",
      verifyRegistry: "registry-1.docker.io",
      verifyRepository: "library/nextcloud",
      timeoutMs: 1000,
      occTimeoutMs: 1000,
    },
    logger: { info: () => {}, warn: () => {} },
    writeResource: (
      spec: string,
      _name: string,
      data: Record<string, unknown>,
    ) => {
      written[spec] = data;
      return Promise.resolve({ name: spec });
    },
    run: (occArgs: string[]) => {
      const key = occArgs.join(" ");
      calls.push(key);
      const entry = script[key];
      if (!entry) return Promise.resolve(ok(`unscripted: ${key}`, 99));
      if (Array.isArray(entry)) {
        const i = counters[key] ?? 0;
        counters[key] = i + 1;
        return Promise.resolve(entry[Math.min(i, entry.length - 1)]);
      }
      return Promise.resolve(entry);
    },
  };
  return { context, calls, written, ok };
}

const ok = (stdout: string, code = 0): OccResult => ({
  code,
  stdout,
  stderr: "",
});
const APPLIST = ok(
  '{"enabled":{"calendar":"6.6.1","dav":"1.40.0"},"disabled":[]}',
);
const SHOWONLY = "app:update --showonly --no-warnings";

// deno-lint-ignore no-explicit-any
const run = (method: string, args: Record<string, unknown>, context: any) =>
  // deno-lint-ignore no-explicit-any
  (model.methods as any)[method].execute(args, context);

Deno.test("setupchecks accepts exit 1, which occ uses to mean 'a check warned'", async () => {
  const h = harness({ "setupchecks --output=json": ok(SETUPCHECKS, 1) });
  await run("setupchecks", {}, h.context);
  assertEquals(h.written.setupchecks.warnings, 1);
  assertEquals(h.written.setupchecks.total, 2);
});

Deno.test("setupchecks fails on any other exit code", async () => {
  const h = harness({ "setupchecks --output=json": ok("boom", 2) });
  await assertRejects(
    () => run("setupchecks", {}, h.context),
    Error,
    "exited 2",
  );
});

Deno.test("apps records updates with the current version", async () => {
  const h = harness({
    "app:list --output=json": APPLIST,
    [SHOWONLY]: ok("calendar new version available: 6.6.2\n"),
  });
  await run("apps", {}, h.context);
  assertEquals(h.written.apps.hasUpdates, true);
  assertEquals(h.written.apps.updates, [
    { app: "calendar", currentVersion: "6.6.1", availableVersion: "6.6.2" },
  ]);
});

Deno.test("maintenance dry run changes nothing", async () => {
  const h = harness({
    "maintenance:mode": ok("Maintenance mode is currently disabled"),
  });
  await run("maintenance", { mode: "on", apply: false }, h.context);
  assertEquals(h.calls, ["maintenance:mode"]);
  assertEquals(h.written.maintenance.applied, false);
  assertEquals(h.written.maintenance.changed, false);
});

Deno.test("maintenance apply verifies the new state", async () => {
  const h = harness({
    "maintenance:mode": [
      ok("Maintenance mode is currently disabled"),
      ok("Maintenance mode is currently enabled"),
    ],
    "maintenance:mode --on": ok("Maintenance mode enabled"),
  });
  await run("maintenance", { mode: "on", apply: true }, h.context);
  assertEquals(h.written.maintenance.enabledAfter, true);
  assertEquals(h.written.maintenance.applied, true);
});

Deno.test("maintenance apply fails when the mode did not change", async () => {
  const h = harness({
    "maintenance:mode": ok("Maintenance mode is currently disabled"),
    "maintenance:mode --on": ok("Maintenance mode enabled"),
  });
  await assertRejects(
    () => run("maintenance", { mode: "on", apply: true }, h.context),
    Error,
    "still reads off",
  );
});

const CLEAN_DB = {
  "db:add-missing-indices --dry-run": ok(""),
  "db:add-missing-columns --dry-run": ok(""),
  "db:add-missing-primary-keys --dry-run": ok(""),
};

Deno.test("dbRepair dry run runs only --dry-run commands", async () => {
  const h = harness({
    ...CLEAN_DB,
    "db:add-missing-indices --dry-run": ok(PENDING_INDEX),
  });
  await run("dbRepair", { apply: false }, h.context);
  assert(h.calls.every((c) => c.endsWith("--dry-run")), h.calls.join());
  assertEquals(h.written.dbRepair.pending, 1);
});

Deno.test("dbRepair apply re-runs the dry run and fails if still pending", async () => {
  const h = harness({
    ...CLEAN_DB,
    "db:add-missing-indices --dry-run": ok(PENDING_INDEX),
    "db:add-missing-indices": ok("done"),
  });
  await assertRejects(
    () => run("dbRepair", { apply: true }, h.context),
    Error,
    "still pending",
  );
  // The record is written before the throw, so the evidence survives.
  assertEquals(h.written.dbRepair.applied, true);
});

Deno.test("dbRepair apply succeeds when the second dry run is clean", async () => {
  const h = harness({
    ...CLEAN_DB,
    "db:add-missing-indices --dry-run": [
      ok(PENDING_INDEX),
      ok(""),
    ],
    "db:add-missing-indices": ok("done"),
  });
  await run("dbRepair", { apply: true }, h.context);
  // deno-lint-ignore no-explicit-any
  const steps = h.written.dbRepair.steps as any[];
  assertEquals(steps[0].remainingItems, 0);
  assert(
    !h.calls.includes("db:add-missing-columns"),
    "clean steps must not run",
  );
});

Deno.test("updateApps dry run plans without updating", async () => {
  const h = harness({
    "app:list --output=json": APPLIST,
    [SHOWONLY]: ok("calendar new version available: 6.6.2\n"),
  });
  await run("updateApps", { apps: [], apply: false }, h.context);
  assert(!h.calls.some((c) => c.startsWith("app:update calendar")));
  // deno-lint-ignore no-explicit-any
  assertEquals((h.written.appUpdate.planned as any[]).length, 1);
});

Deno.test("updateApps apply verifies each app no longer reports an update", async () => {
  const h = harness({
    "app:list --output=json": APPLIST,
    [SHOWONLY]: [
      ok("calendar new version available: 6.6.2\n"),
      ok("All apps are up-to-date or no updates could be found\n"),
    ],
    "app:update calendar": ok("calendar updated"),
  });
  await run("updateApps", { apps: [], apply: true }, h.context);
  assertEquals(h.written.appUpdate.updated, ["calendar"]);
  assertEquals(h.written.appUpdate.stillPending, []);
});

Deno.test("updateApps apply fails when an update did not take", async () => {
  const h = harness({
    "app:list --output=json": APPLIST,
    [SHOWONLY]: ok("calendar new version available: 6.6.2\n"),
    "app:update calendar": ok("calendar updated"),
  });
  await assertRejects(
    () => run("updateApps", { apps: ["calendar"], apply: true }, h.context),
    Error,
    "still report an update",
  );
});

Deno.test("updateApps rejects an app id that could inject into the remote shell", () => {
  const schema = model.methods.updateApps.arguments;
  assertEquals(schema.safeParse({ apps: ["calendar; reboot"] }).success, false);
  assertEquals(schema.safeParse({ apps: ["user_oidc"] }).success, true);
});

/* ------------------------------------------------------------------ *
 * HTTP methods, against a stubbed fetch
 * ------------------------------------------------------------------ */

type Route = (url: string, init?: RequestInit) => Response | Promise<Response>;

async function withFetch(route: Route, fn: () => Promise<void>) {
  const real = globalThis.fetch;
  globalThis.fetch =
    ((input: string | URL | Request, init?: RequestInit) =>
      Promise.resolve(
        route(input instanceof Request ? input.url : String(input), init),
      )) as typeof fetch;
  try {
    await fn();
  } finally {
    globalThis.fetch = real;
  }
}

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

const GH_RELEASES = RELEASES.map((r) => ({
  tag_name: r.tag,
  prerelease: r.prerelease,
  html_url: r.htmlUrl,
}));

Deno.test("sync records a healthy instance", async () => {
  const h = harness({});
  await withFetch(() => json(STATUS), async () => {
    await run("sync", {}, h.context);
  });
  assertEquals(h.written.instance.healthy, true);
  assertEquals(h.written.instance.versionString, "34.0.4");
  assertEquals(h.written.instance.serverinfo, null);
});

Deno.test("sync records maintenance mode as unhealthy, not as an error", async () => {
  const h = harness({});
  await withFetch(() => json({ ...STATUS, maintenance: true }), async () => {
    await run("sync", {}, h.context);
  });
  assertEquals(h.written.instance.reachable, true);
  assertEquals(h.written.instance.healthy, false);
});

Deno.test("sync names the trusted-domain cause", async () => {
  const h = harness({});
  await withFetch(
    () => json({ error: "Trusted domain error.", code: 15 }, 400),
    async () => {
      await run("sync", {}, h.context);
    },
  );
  assertEquals(h.written.instance.reachable, false);
  assert(String(h.written.instance.detail).includes("trusted_domains"));
});

Deno.test("sync records a refused connection as unhealthy", async () => {
  const h = harness({});
  await withFetch(() => {
    throw new TypeError("connection refused");
  }, async () => {
    await run("sync", {}, h.context);
  });
  assertEquals(h.written.instance.healthy, false);
  assertEquals(h.written.instance.httpStatus, 0);
});

Deno.test("sync sends the serverinfo token as NC-Token", async () => {
  const h = harness({});
  h.context.globalArgs = {
    ...h.context.globalArgs,
    serverinfoToken: "t0k",
  } as typeof h.context.globalArgs;
  let sent: string | null = null;
  await withFetch((url, init) => {
    if (url.includes("serverinfo")) {
      sent = new Headers(init?.headers).get("NC-Token");
      return json({
        ocs: { data: { nextcloud: { storage: { num_users: 2 } } } },
      });
    }
    return json(STATUS);
  }, async () => {
    await run("sync", {}, h.context);
  });
  assertEquals(sent, "t0k");
  // deno-lint-ignore no-explicit-any
  assertEquals((h.written.instance.serverinfo as any).numUsers, 2);
});

Deno.test("drift reads the version from status.php and checks the image", async () => {
  const h = harness({});
  const heads: string[] = [];
  await withFetch((url, init) => {
    if (url.endsWith("/status.php")) return json(STATUS);
    if (url.includes("api.github.com")) return json(GH_RELEASES);
    if (init?.method === "HEAD") {
      heads.push(url);
      return new Response(null, { status: 200 });
    }
    return new Response("unexpected", { status: 500 });
  }, async () => {
    await run("drift", { pageSize: 100, verifyImage: true }, h.context);
  });
  assertEquals(h.written.drift.runningVersionSource, "status.php");
  assertEquals(h.written.drift.status, "behind-major");
  assertEquals(h.written.drift.nextMajorImage, "nextcloud:35.0.1-apache");
  assertEquals(h.written.drift.nextMajorImageAvailable, true);
  assertEquals(heads.length, 1);
  assert(heads[0].endsWith("/library/nextcloud/manifests/35.0.1-apache"));
});

Deno.test("drift raises a GitHub rate limit instead of reading current", async () => {
  const h = harness({});
  await withFetch((url) => {
    if (url.includes("api.github.com")) {
      return new Response("rate limited", { status: 403 });
    }
    return json(STATUS);
  }, async () => {
    await assertRejects(
      () => run("drift", { pageSize: 100, verifyImage: true }, h.context),
      Error,
      "60 requests/hour",
    );
  });
  assertEquals(h.written.drift, undefined);
});

Deno.test("drift raises a registry 429 instead of reading the image as absent", async () => {
  const h = harness({});
  await withFetch((url, init) => {
    if (url.includes("api.github.com")) return json(GH_RELEASES);
    if (init?.method === "HEAD") return new Response(null, { status: 429 });
    return json(STATUS);
  }, async () => {
    await assertRejects(
      () => run("drift", { pageSize: 100, verifyImage: true }, h.context),
      Error,
      "indeterminate",
    );
  });
});

/* ------------------------------------------------------------------ *
 * Pre-flight
 * ------------------------------------------------------------------ */

Deno.test("occ-reachable applies defaults to the raw global arguments", async () => {
  let argv: string[] = [];
  // Only baseUrl is set: container, occUser and dockerBin come from defaults.
  const result = await checkOccReachable(
    { baseUrl: "https://cloud.example.com" },
    (occArgs) => {
      argv = occArgs;
      return Promise.resolve({
        code: 0,
        stdout: JSON.stringify(STATUS),
        stderr: "",
      });
    },
  );
  assertEquals(result, { pass: true });
  assertEquals(argv, ["status", "--output=json"]);
});

Deno.test("occ-reachable fails on a non-zero exit and names the container", async () => {
  const result = await checkOccReachable(
    { baseUrl: "https://cloud.example.com", container: "wrong" },
    () =>
      Promise.resolve({
        code: 1,
        stdout: "",
        stderr: "No such container: wrong",
      }),
  );
  assertEquals(result.pass, false);
  assert(result.errors?.[0].includes("container wrong"));
});

Deno.test("occ-reachable fails when Nextcloud is not installed", async () => {
  const result = await checkOccReachable(
    { baseUrl: "https://cloud.example.com" },
    () =>
      Promise.resolve({
        code: 0,
        stdout: JSON.stringify({ ...STATUS, installed: false }),
        stderr: "",
      }),
  );
  assertEquals(result.pass, false);
});
