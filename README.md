# swamp-nextcloud

A [swamp](https://swamp-club.com) extension for [Nextcloud](https://nextcloud.com).

| Extension | Type | What it does |
| --- | --- | --- |
| [`@sntxrr/nextcloud`](extensions/models/README.md) | model | Health, version drift, setup checks, app updates and app compatibility with the next major, plus verified backups and `occ` maintenance (maintenance mode, database repair, app updates) that are dry runs unless `apply=true` |

See [the extension README](extensions/models/README.md) for methods,
configuration, and the behaviours worth knowing before relying on it.

## Why this exists

Nextcloud's admin overview shows what needs attention: pending app updates,
missing database indices after an upgrade, a newer release, log errors. It shows
them only to someone who logs in and looks, and a container healthcheck stays
green through all of them. This extension puts the same information on a
schedule and turns each item into one field to alert on.

## Development

```bash
~/.swamp/deno/deno test --allow-read --allow-write extensions/models/nextcloud_instance_test.ts
swamp extension fmt extensions/models/manifest.yaml
swamp extension quality extensions/models/manifest.yaml
```

## License

MIT, see [LICENSE.md](extensions/models/LICENSE.md).
