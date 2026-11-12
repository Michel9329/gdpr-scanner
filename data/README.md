# Data files

Three hand-written lists drive detection:

| File | What it holds |
|---|---|
| `tracker-hosts.ts` | Hostname substring to tracker (entity, name, category). Unknown hosts are never flagged. |
| `cmp-signatures.ts` | How to recognise a consent platform: network hosts, JS globals, cookie names, DOM selectors. |
| `cookie-patterns.ts` | Cookie name prefixes and exact names of common analytics and marketing cookies. |

## Provenance

All three were written by hand for this project from publicly known vendor hostnames and vendor
documentation. They are not copied or derived from any third-party list. The lists are short on
purpose and will miss trackers. Adding an entry is a one-line change per host.

## Extending them from external sources

If you want broader coverage, check each source's license before copying data into your own repo.
Several well-known lists are non-commercial or share-alike, which may not fit your use:

| List | License (verified) | Source |
|---|---|---|
| DuckDuckGo Tracker Radar | CC BY-NC-SA 4.0 (non-commercial, share-alike) | [README, Licensing section](https://github.com/duckduckgo/tracker-radar/blob/main/README.md), [LICENSE](https://github.com/duckduckgo/tracker-radar/blob/main/LICENSE) |
| Disconnect tracking protection lists | CC BY-NC-SA 4.0 (non-commercial, share-alike) | [README](https://github.com/disconnectme/disconnect-tracking-protection/blob/master/README.md), [LICENSE](https://github.com/disconnectme/disconnect-tracking-protection/blob/master/LICENSE) |
| EasyPrivacy (EasyList repository) | Dual license: GPL-3.0-or-later or CC BY-SA 3.0, at your option | [easylist.to licence page](https://easylist.to/pages/licence.html) |
| WhoTracks.me | Data: CC BY 4.0. Code: MIT | [README, License section](https://github.com/ghostery/whotracks.me/blob/master/README.md), [LICENSE.md](https://github.com/ghostery/whotracks.me/blob/master/LICENSE.md) |
| Open Cookie Database | Apache-2.0 | [LICENSE](https://github.com/jkwakman/Open-Cookie-Database/blob/master/LICENSE), [GitHub license API](https://api.github.com/repos/jkwakman/Open-Cookie-Database/license) |

Checked against each project's own page or LICENSE file in November 2026. Licenses can change, so
confirm on the project page again before relying on this table. Note that some of these licenses
(Tracker Radar, Disconnect) forbid commercial use unless you obtain a separate license from the owner.

A workable pattern is to load a large list at runtime from KV or R2
instead of bundling it in the repo.
