# @sntxrr/nextcloud

Health, version drift, setup checks, app updates and `occ` maintenance for a
self-hosted [Nextcloud](https://nextcloud.com).

One model type, `@sntxrr/nextcloud/instance`, with seven methods over two
transports.

| Method        | Transport | Changes state                   | Resource      |
| ------------- | --------- | ------------------------------- | ------------- |
| `sync`        | HTTP      | no                              | `instance`    |
| `drift`       | HTTP      | no                              | `drift`       |
| `setupchecks` | occ       | no                              | `setupchecks` |
| `apps`        | occ       | no                              | `apps`        |
| `maintenance` | occ       | **dry run unless `apply=true`** | `maintenance` |
| `dbRepair`    | occ       | **dry run unless `apply=true`** | `dbRepair`    |
| `updateApps`  | occ       | **dry run unless `apply=true`** | `appUpdate`   |

Every apply path re-reads the state after acting and **fails if the change did
not take**. For example, `dbRepair` runs a second `--dry-run` and requires it to
come back empty. An `occ` command exiting 0 does not count as proof.

## Setup

```bash
swamp model create @sntxrr/nextcloud/instance cloud \
  --global-arg baseUrl=https://cloud.example.com \
  --global-arg sshHost=nas.example.com \
  --global-arg dockerBin=/usr/local/bin/docker \
  --global-arg container=nextcloud
```

| Global argument                       | Default                                      | Notes                                                                                            |
| ------------------------------------- | -------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `baseUrl`                             | —                                            | **Must be a name in `trusted_domains`.** See below.                                              |
| `serverinfoToken`                     | —                                            | Optional, sensitive. Enables storage and user statistics in `sync`.                              |
| `sshHost` / `sshUser`                 | —                                            | Where `occ` runs. Omit `sshHost` to run `docker exec` locally.                                   |
| `strictHostKeyChecking`               | `yes`                                        | Refuses an unknown host key; a scheduled job has nobody to ask.                                  |
| `dockerBin`                           | `docker`                                     | Full path where docker is not on a non-interactive PATH (Synology DSM: `/usr/local/bin/docker`). |
| `container` / `occUser`               | `nextcloud` / `www-data`                     | occ must run as the owner of `config.php`.                                                       |
| `imageRepository` / `imageVariant`    | `nextcloud` / `apache`                       | Builds the tag to offer, e.g. `nextcloud:34.0.4-apache`.                                         |
| `verifyRegistry` / `verifyRepository` | `registry-1.docker.io` / `library/nextcloud` | Where image existence is checked.                                                                |
| `githubToken`                         | —                                            | Optional, sensitive. Only raises the GitHub rate limit.                                          |

### The serverinfo token

`sync` can read storage, user and database statistics from the serverinfo API.
It authenticates with a **serverinfo token**, not an account. The token grants
access to that one monitoring endpoint and nothing else:

```bash
occ config:app:set serverinfo token --value "$(openssl rand -hex 32)"
```

Store it in a vault and reference it from the model. Without a token, `sync`
reads `status.php` only.

## Three behaviours worth knowing

### `baseUrl` cannot be an IP address

Nextcloud 34 enforces `trusted_domains` on `status.php`. Asked by an untrusted
name it answers:

```
HTTP 400  {"error": "Trusted domain error.", "code": 15}
```

A test against `127.0.0.1` will not catch this, because localhost is trusted
implicitly. The usual workaround is to probe the IP and send the real name in a
`Host` header, but that does not work here: **Deno's `fetch` drops a
caller-supplied `Host` header without warning**. The same request that
`curl -H 'Host: …'` answers 200 gets the 400 from Deno. When this happens,
`sync` records the trusted-domain cause in `detail` instead of a bare HTTP 400.

### `drift` reports two targets, because Nextcloud cannot skip a major

Upgrading 32 → 34 is refused; it has to go 32 → 33 → 34. So the newest release
is only a legal target when it is exactly one major ahead. `drift` reports:

```
runningVersion   33.0.9
status           behind-major
patchTarget      null          (33 is fully patched)
nextMajor        34.0.4        (the only legal major hop)
latestVersion    35.0.1
majorsBehind     2
```

A deployment behind on both its patch and its major reads `behind-patch`,
because the patch is the move to make first.

Releases come from GitHub. Nextcloud's prerelease tags are spelled
inconsistently (`v35.0.0rc2` and `v35.0.0RC2` both exist), so the model does not
try to parse suffixes. Any tag with a suffix is excluded, and so is any tag
flagged `prerelease`.

`updates.nextcloud.com` is **not** used. It answers an empty HTTP 200 both when
it has nothing to offer and when it could not parse the query. A check that
cannot tell "current" apart from "did not understand the question" should not
drive an alert.

Each offered target's image is checked with a registry manifest `HEAD`. A 429 or
any other response that is not 200 or 404 is raised, never read as "absent".

### `occ setupchecks` exits 1 when anything warns

The exit code reports findings, not a failure. The model accepts exit 1 when the
output is the JSON report it asked for, and fails on anything else.

## Failure is never folded into "fine"

An unreachable instance is recorded as `healthy: false`, because that is a
result. Everything else throws: a GitHub rate limit, a registry that answers
neither 200 nor 404, an `occ` command that exits non-zero, and output that does
not parse. Two examples of the last case:

- `app:update --showonly` has no JSON mode. A line the parser does not
  recognise, such as an app store error, makes the method throw. It never
  becomes "no updates".
- `setupchecks` with zero checks in its report throws. It never becomes "clean".

## Resources

| Resource      | Alert on                                     |
| ------------- | -------------------------------------------- |
| `instance`    | `healthy`                                    |
| `drift`       | `behind`                                     |
| `setupchecks` | `errors`, `warnings` (details in `problems`) |
| `apps`        | `hasUpdates`                                 |

Each resource has a fixed name (`instance-current`, `drift-current`, and so on),
so workflow expressions can use `data.latest('<model>', '<name>')` without
building names from configuration.

## License

MIT, see [LICENSE.md](LICENSE.md).
