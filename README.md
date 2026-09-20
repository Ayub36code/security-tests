# targets/

One JSON file per site you audit. Copy `example-target.json` and edit.

Key fields:

| Field | Meaning |
|---|---|
| `name` | Short label; used for report folder names |
| `url` / `host` | Target |
| `scan_options` | Ports, crawl depth, threads, time-based SQLi, TLS verify |
| `auth.cookies` | `{ "sessionid": "..." }` — grab from your browser DevTools |
| `auth.headers` | `{ "X-API-Key": "..." }` |
| `auth.bearer_token` | Raw JWT or opaque token |
| `admin_paths` | Extra paths merged with the built-in admin wordlist |

**Never commit real tokens.** The `data/registry.json` is gitignored for the same reason.