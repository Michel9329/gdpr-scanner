# Data files

Three hand-written lists drive detection:

| File | What it holds |
|---|---|
| `tracker-hosts.ts` | Host to tracker (name, category, and whether it is exempt). An entry matches the host or a subdomain, optionally with a path. Unknown hosts are never flagged, and the functional hosts listed at the end (CDNs, payments, reCAPTCHA and others) are never reported as trackers. |
| `cmp-signatures.ts` | How to recognise a consent platform: network hosts, JS globals, cookie names (a name or the start of one), DOM selectors (matched only inside an `id` or `class` attribute of the markup). One signal is enough. |
| `cookie-patterns.ts` | Exact names and name patterns of analytics and marketing cookies set on the visited site's own domain. |

## Provenance

All three were written by hand for this project from publicly known vendor hostnames and vendor
documentation. They are not copied or derived from any third-party list. The lists are short on
purpose and will miss trackers. Adding an entry is a one-line change per host.

## How entries match

A request belongs to a vendor when its host is the vendor's host or a subdomain of it. Apart from the
keyword entries described below, the lists never look for a vendor name anywhere in the URL:
`cheap.io` is not `heap.io`, and a script called `customer-segment.common.js` is not Segment. The
entry forms are in `src/hosts.ts`:

| Entry | Matches |
|---|---|
| `vendor.com` | `vendor.com` and its subdomains |
| `vendor.com/path` | the same hosts, and a request path under `/path` |
| `label.vendor.*` | the host `label.vendor.` followed by a country or generic ending of two or three letters, optionally a dot and two more (`adservice.google.it`, `adservice.google.co.uk`); not a subdomain of it and not a longer tail such as `adservice.google.evil.example` |
| `keyword: true` | a word looked for in the host and path, for self-hosted tools such as Matomo. Keyword entries are tried after every host rule, so a word in the path of a known vendor's URL does not hide the vendor |

In `cmp-signatures.ts`, a `hosts` entry with a dot is a host rule and counts on any request; an entry
without a dot (`optanon`) is a word looked for in the host and path, and counts only on requests that
load code (`script`, `xhr`, `fetch`), never on an image or a stylesheet.

### Cookie names

An entry in `cookie-patterns.ts` has a `match` that is either the exact cookie name (a string) or a
regular expression the whole name must match, anchored with `^` and `$`. There is no prefix form: a
prefix such as `_ga` also names a site's own `_gallery_seen` or `_gate`, and `mp_` names `mp_lang`.
Each expression states the shape the vendor documents, for example `_ga_` plus the container id or
`mp_<project token>_mixpanel`. No two entries match the same name, so their order does not matter.

Cookies set on the vendor's own domain (Facebook's `fr`, Google's `NID`) are left out on purpose: the
scan reads the cookies of the page it loaded, so a cookie with one of those names on the visited
site is something else.

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
