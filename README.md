# gdpr-scanner

[![test](https://github.com/Michel9329/gdpr-scanner/actions/workflows/test.yml/badge.svg)](https://github.com/Michel9329/gdpr-scanner/actions/workflows/test.yml)

A Cloudflare Worker that opens a website in a headless browser and reports what loads before the
visitor has consented to anything. Built with Claude Code, designed and reviewed by Michel Dimitri.

It exists because the manual version of this check (open DevTools, clear cookies, read the network
tab) is slow and easy to get wrong across many sites. It was built for the privacy check of the free
site audit at [sharkcodestudio.com](https://sharkcodestudio.com/en/strumenti/audit), where an earlier
version runs in production.

**This is not legal advice.** The output is a technical observation about one page load. It does not
decide whether a site complies with the GDPR, the ePrivacy rules or any national law. Have a qualified
person review anything that matters.

## What it detects

- **Trackers before consent:** analytics, advertising, social pixels, session replay and A/B testing
  that load or set cookies before the visitor has chosen.
- **Google Fonts** loaded from the Google CDN.
- **Google Consent Mode**, v1 or v2, read from the signals the page actually sends.
- **The consent platform:** a CMP from the list, an IAB TCF API or a home-made banner.
- **The cookie banner:** whether its first level offers accept, reject, close, settings and a link to
  the policy.
- **Pre-ticked consent checkboxes** in visible forms.
- **Privacy and cookie policy links**, with words in twelve languages.
- **The content of the privacy notice:** whether it mentions the elements GDPR articles 12 and 13 ask
  for, in Italian, English and Spanish notices.
- **Scroll and reject:** whether tracker cookies appear after scrolling or after clicking reject, and
  whether the choice is remembered.

When the evidence is not certain the scanner reports nothing, because a wrong accusation is worse than
a miss. The exact rule behind each line is in [docs/detection.md](docs/detection.md).

## What it does not detect

- Trackers missing from the lists in `data/`. Unknown hosts are not flagged by design.
- Cookies a vendor sets on its own domain (third-party cookies). The scan reads the cookies of the
  page it loaded; those vendors are found from the network requests instead.
- Anything behind a login, on other pages, or triggered by interaction beyond scroll and reject.
- Whether a cookieless analytics tool is really anonymised. Matomo and Plausible are treated as exempt.
- A home-made banner is reported as "custom"; its behaviour is only partly checked.
- Server-side tracking, fingerprinting, and the legal quality of the policy text.
- A page that fails to load returns `scanned: false` and no verdict, not a guess.

## How it works

1. `POST /scan` with a URL. Only the address of a public website is accepted: `http` or `https`, the
   default port, a host name. IP addresses, `localhost`, internal names, credentials in the URL and
   other ports are refused with `400 bad-url`.
2. The Worker launches Chromium through Cloudflare Browser Run (formerly Browser Rendering), driven
   with `@cloudflare/puppeteer`. It records every network request and cookie before any interaction
   and inspects the page for banners and globals. The page's requests are checked before they leave
   and its responses for the address they came from; what this does not cover is listed under
   [Security](#security).
3. It scrolls, and if the banner has a reject control it clicks it and watches again.
4. The policy page is fetched with a normal `fetch` (no browser time), one redirect at a time, each
   hop checked before it is requested.
5. A strict rule set turns the raw observation into findings and a verdict
   (`compliant`, `partial`, `non-compliant`). "Compliant" only means nothing non-essential started.

The browser session is cut at 45 seconds. Results are cached per URL for 6 hours in KV, and a daily
cap on browser sessions (also in KV) protects the browser-time budget; both need the `SCAN_KV`
binding. See [Time, cap and cache](#time-cap-and-cache).

## Run it locally

You need [Bun](https://bun.sh) for the tests and Node 22 or newer for Wrangler.

```
bun install
cp .dev.vars.example .dev.vars     # then set SCANNER_SECRET (at least 32 characters)
bunx wrangler dev                  # http://localhost:8787, with a local browser and a local KV
```

Wrangler runs the browser binding with a Chromium on your machine, so no Cloudflare account is needed
to try a scan. The placeholder KV id in `wrangler.toml` is fine for local runs.

```
curl -X POST http://localhost:8787/scan \
  -H "Authorization: Bearer $SCANNER_SECRET" \
  -H "content-type: application/json" \
  -d '{"url":"https://www.wikipedia.org"}'
```

Run locally, the browser is on your own network. See [Security](#security) before pointing it at
URLs you did not choose.

## Tests

```
bun test
bun run typecheck
```

`bun run typecheck` runs two checks. `tsc --noEmit` covers the Worker code, the data lists and the
tests, with the Workers types and Bun's types. `tsc --noEmit -p tsconfig.worker.json` checks the
Worker code and the data lists again with the Workers types only, so a Bun global used by mistake in
`src/` does not pass.

The suite needs no network and no browser. It covers:

- detection and verdict logic on fixed observations (`test/scanner.test.ts`);
- vendor matching, with the look-alike URLs that must not be flagged, such as `cheap.io` for Heap or
  a path ending in `customer-segment.common.js` for Segment (`test/matching.test.ts`);
- how each control of a banner is read, against a small stand-in for the DOM (`test/ux.test.ts`);
- which addresses are accepted, for the target and for each request of the page: private ranges,
  every IPv4 encoding, IPv6 forms that carry a private IPv4 address, `localhost.` with the root dot,
  private and special-use names, ports, credentials, redirects of the page itself
  (`test/net-guard.test.ts`);
- the request handler with the browser step replaced: cache key, daily cap, error codes, debug
  gating (`test/handler.test.ts`);
- the fetch of the policy page with `fetch` replaced: redirects to private hosts, loops, non-text
  answers, a body that never ends, the language of the notice, hostile markup and hostile `<html>`
  tags read in linear time
  (`test/policy-check.test.ts`);
- what the browser hands back, checked again on hostile shapes; the scan deadline and the launch
  retry, with a fake browser binding (`test/scanner-guard.test.ts`);
- the browser session of `scan()` on a fake browser and page that record what the scanner asks and
  fire the events a page fires (`test/scan-session.test.ts`): after a response from a private
  address the page is closed, later requests are aborted and the scan ends with `private-address`;
  a redirect of the page to a refused address gives `blocked-redirect`; requests to blocked hosts
  are aborted; service workers are bypassed and downloads denied; new page targets and popups are
  closed; dialogs are dismissed (`beforeunload` accepted); everything the page returns passes
  through the re-validation; the reads go to the isolated world and fall back to the main world
  when it is missing; the launch retry respects the time left and skips a 429 for the daily time.

### Checked in a real browser

The tests above drive the session code with a fake page, not with Chromium. For version 0.2 the
session also ran in a local Chromium under `wrangler dev`, with fixture pages served as HTML by
postman-echo.com:

- whole scans of live sites;
- the banner and checkbox logic on fixture pages;
- a public name that resolves to `127.0.0.1` (`localtest.me`), loaded directly, through an HTTP
  redirect and through a meta refresh: `private-address` each time, with the first request reaching
  the local server and nothing after it;
- a script redirect to `127.0.0.1` and to `example.com:8443`, and an HTTP redirect to port 8443:
  `blocked-redirect`, and nothing reached the local server;
- `alert`, `confirm` and `prompt` at load: dismissed, and the scan finished;
- an endless loop in a script: `scan-timeout` at 45 seconds;
- a page script that breaks `querySelectorAll`: the links were still read;
- a popup opened at load: its first request reached the local server, nothing after it.

Never run in a real browser, though some of these run on the fake page: the denial of a real
download; the fallback to the main world when the isolated world is missing; the `beforeunload`
dialog; the deadline passing during the browser launch; the launch retry; the 5-second limit on
closing the browser; the status and type read after a load timeout; the reload step of the reject
test. A popup opened by the reject click sent no request, but it is not known whether it opened at
all. Nothing has been verified on Cloudflare's own browser.

## Deploy to Cloudflare

Requires a Cloudflare account and Wrangler.

Install with `bun install` first. Before the first deploy, `wrangler secret put` asks whether to create the Worker: answer yes, the deploy fills it in.

```
bunx wrangler kv namespace create SCAN_KV     # required: cache and daily cap
# paste the id in wrangler.toml, replacing <your-kv-namespace-id>
bunx wrangler secret put SCANNER_SECRET       # required: bearer token for /scan, at least 32 characters (openssl rand -hex 32)
bunx wrangler deploy
```

Browser Run has limits on both Workers plans; the figures that matter for the daily cap are under
[The daily cap](#the-daily-cap). Check Cloudflare's pages for your plan before you deploy.

### Configuration

| Name | Kind | Purpose |
|---|---|---|
| `SCANNER_SECRET` | secret | Required, at least 32 characters. `/scan` needs `Authorization: Bearer <secret>`. If it is not set or is shorter than 32 characters, `/scan` answers 503 and never opens a browser; a wrong or missing token gets 401. |
| `SCAN_KV` | KV binding | Required. Cache and daily counter. If it is not bound, `/scan` answers 503, because without it there would be no daily cap. |
| `SCANNER_UA_SUFFIX` | var | Appended to the User-Agent, for example `my-scanner/1.0 (+https://example.com/about)`. Default `gdpr-scanner/0.2`. The rest of the User-Agent is the browser's own, with `HeadlessChrome/` written as `Chrome/`. |
| `DAILY_CAP` | var | Max browser sessions per UTC day, a positive integer. Default 20. |
| `DEBUG` | var | `1` lets a request send `x-debug: 1` to get raw details. Off by default. |

Send `x-fresh: 1` to skip the cache.

## Time, cap and cache

### Time to answer

One request answers within about 58 seconds in the worst case: the browser session, launch included,
is cut at 45 seconds, closing the browser can take up to 5 seconds more, and the fetch of the policy
page has 8 seconds. KV reads and writes come on top. Set your client's timeout above that, for
example at 70 seconds.

### The daily cap

`DAILY_CAP` (default 20) limits browser sessions per UTC day. It counts sessions, not seconds. The
slot is taken before the browser starts, so a page that fails or times out uses one like any other.
If the counter cannot be read or written, the scan does not run (`budget-unavailable`).

A session lasts at most the 45-second deadline plus up to 5 seconds to close the browser: 50
seconds, so 1,000 seconds a day with the default cap. A browser that does not close in those 5
seconds keeps using time until 60 seconds without activity (see below), so in the worst case one
session uses about 110 seconds, and 20 of them about 2,200. The live sites scanned for version 0.2,
on a local Chromium, took 8 to 12 seconds each; at 12 seconds a scan, 20 scans use 240 seconds; at
25, 500. Set the cap from your plan.

Cloudflare's figures, from the Browser Run [limits](https://developers.cloudflare.com/browser-run/limits/)
and [pricing](https://developers.cloudflare.com/browser-run/pricing/) pages in November 2026:

- Workers Free: 10 minutes (600 seconds) of browser time a day, 3 concurrent browsers, 1 new
  browser every 20 seconds. Past the daily time, Cloudflare refuses new browsers until the next UTC
  day and scans end with `scan-failed`.
- Workers Paid: no daily limit; 10 hours a month included, then 0.09 USD for each further hour;
  3 new browsers a second.
- On both, a browser that is not closed keeps using time until 60 seconds of inactivity. The
  scanner closes its browser on every exit, waiting up to 5 seconds for it.

The counter is in KV, which by Cloudflare's own
[description](https://developers.cloudflare.com/kv/concepts/how-kv-works/) is not for
read-then-write: requests that arrive together, or in different locations within about a minute, can
each read the same count. In a test with the browser step and KV replaced, 20 requests sent together
with `DAILY_CAP=3` all reached the browser step and moved the counter by 1. On Workers Free, Cloudflare's own
limits bound such a burst: one new browser every 20 seconds, three at a time. The launches it refuses
end with `scan-failed`.

### The cache

A result with a verdict is cached in KV for 6 hours under the normalized URL that was asked for:
scheme, host in lower case without the root dot, path and query, without the fragment. The key is a
SHA-256 hash of that URL. Another page of the same site, or the same page with another query string,
is scanned on its own: each query-string variant of a page (`?x=1`, `?x=2`) takes its own slot of the
daily cap and its own cache entry. Results without a verdict are not cached. Send `x-fresh: 1` to
skip the cache: a fresh result with a verdict replaces the cached one, and a fresh scan that ends
without a verdict leaves the cached entry as it was.

## Security

The endpoint is closed by default. Set `SCANNER_SECRET` (at least 32 characters, generate it with `openssl rand -hex 32`) and bind `SCAN_KV` before deploying
(or use `.dev.vars` for local runs), otherwise every `/scan` request gets a 503 and no browser is launched. This protects you from paying
Browser Run minutes for strangers. Treat the secret like a password and rotate it if it leaks. The token is compared in constant time.

The daily cap counts browser sessions, and the slot is taken before the browser starts: see
[The daily cap](#the-daily-cap), including what happens with requests that arrive together.

**The scanner only talks to public websites.** One rule set (`src/net-guard.ts`) decides which
addresses it may reach, and each step applies it:

- **The target** must be `http` or `https` on the default port, with a public host name and no
  credentials. IP addresses, `localhost` with or without the root dot, single-label names, and names
  under `.localhost`, `.local`, `.internal`, `.home.arpa`, `.test`, `.invalid`, `.example`, `.onion`,
  `.lan`, `.home`, `.corp`, `.intranet`, `.localdomain`, `.private` or `.svc` get `400 bad-url`.
- **Navigations of the page itself**, its redirects included (HTTP, meta refresh or script), must meet
  the same rule. Otherwise the navigation is aborted and the scan ends with `blocked-redirect`.
- **Every other request of the page** is aborted when its URL does not parse, uses a scheme other
  than `http`, `https`, `data`, `blob` or `about`, carries credentials, or names a host the rule
  refuses. Requests to other ports and to public IP addresses go through; the next check covers them.
- **The address each response came from** is checked, in IPv4 and in IPv6, including the IPv6 forms
  that carry an IPv4 address. One response from a private or reserved address closes the page at
  once, every later request is aborted, and the scan ends with `private-address` without reporting
  anything of the page.
- **The policy page** is fetched by the Worker, not by the browser. A Worker's `fetch` does not tell
  which address it reached, so only names are checked there: each redirect is checked before it is
  requested, with at most 3 redirects, 600 KB and 8 seconds.

Inside the browser, dialogs (`alert`, `confirm`, `prompt`) are dismissed, other pages the scanned page
opens are closed as soon as the browser reports them, the page's own requests bypass service workers,
and downloads are denied where the platform allows it. The markup, the links and the banner are read
in an isolated world, where the page's scripts cannot redefine the built-in functions used to read
them (if that world is missing, the page's main world is used). Everything the browser hands back is
checked again in the Worker: types, string lengths, list sizes.

What remains:

- For a public name that resolves to a private address, requests are sent before the address is
  known: it is read from the answer, and several requests can leave before the first answer comes
  back. When an answer comes from a private address the page is closed and nothing of it is read or
  reported. When the private address never answers over HTTP (a closed port, a service that is not a
  web server), there is no answer to read, and every request to it is sent.
- A popup the page opens is closed as soon as the browser reports it, but its first request has
  already left, and that request is checked neither by name nor by address.
- Dedicated, shared and service workers make their own requests. Those requests are not checked by
  name or by address and are not counted, so the requests of a tracker that runs inside a worker, for
  example through Partytown, are not seen. Cookies set on the visited site are still read, whatever
  set them.
- WebSocket and WebRTC connections are not intercepted.
- The page's own variables (`dataLayer`, the globals of consent platforms) exist only in its main
  world, where its scripts control every built-in function. They are read there, and what comes back
  is bounded only once it reaches the Worker.
- The scanned page runs its own JavaScript, as it would for any visitor.

The scanner is not a firewall. On Cloudflare the browser runs in Cloudflare's network, outside yours.
Under `wrangler dev` it runs on your machine and reaches what your machine reaches: there, scan only
sites you trust.

Report a vulnerability privately: see [SECURITY.md](SECURITY.md).

## Example

```
curl -X POST https://<your-worker>.workers.dev/scan \
  -H "Authorization: Bearer $SCANNER_SECRET" \
  -H "content-type: application/json" \
  -d '{"url":"https://example.com"}'
```

example.com itself is too small to judge: the scanner answers `"scanned": false` with `"error": "empty-or-blocked"` for pages with almost no links or content. Try a real site. Only `POST /scan` is routed; a `GET` returns 404.

Response for a page with a Google Analytics cookie, Google Fonts from the CDN and an Iubenda banner
(generated by running `buildResult` on a fixture, not from a live site):

```json
{
  "scanned": true,
  "verdict": "non-compliant",
  "score": 43,
  "findings": [
    {
      "id": "trackers-before-consent",
      "severity": "critical",
      "data": { "vendors": "Google Analytics", "count": 1, "hasCmp": 1 }
    },
    { "id": "google-fonts-cdn", "severity": "moderate" }
  ],
  "summary": {
    "trackers": ["Google Analytics"],
    "tagManager": false,
    "cmp": "Iubenda",
    "consentMode": null,
    "googleFonts": true,
    "privacyPolicy": true,
    "cookiePolicy": true
  },
  "finalUrl": "https://example.com/"
}
```

Finding ids are stable keys (`no-cmp`, `no-privacy-policy`, `banner-no-reject`,
`trackers-after-reject` and so on). Turning them into text for your users is up to the caller.

### When there is no verdict

A page that was not read comes back with HTTP 200, `"scanned": false`, `"verdict": null` and one of
these codes in `error`:

| `error` | Meaning |
|---|---|
| `empty-or-blocked` | The page answered, but with a status of 400 or higher (a 403 bot challenge, a 404, a 503), with a main document that is not HTML (`text/html` or `application/xhtml+xml`; an unknown type is judged), or with almost no navigation: fewer than 3 links, and either under 2,500 characters of markup (whitespace not counted) or no non-essential tracker or tracker cookie seen. A JavaScript challenge or an empty application shell is in this case. |
| `navigation-failed` | The page could not be loaded: a DNS, connection or TLS error, or any other load error that is not a timeout. |
| `navigation-timeout` | Nothing usable had loaded when the time for loading ran out. |
| `blocked-redirect` | The site sent the browser to an address the scanner does not load: another port, an IP address, a private or internal name, credentials in the URL, or a scheme other than `http` and `https`. |
| `private-address` | The page, or something it loaded, was served from a non-public address. |
| `scan-timeout` | The browser session reached its 45-second deadline, for example on a page with an endless script. |
| `daily-budget` | The daily cap was reached. |
| `budget-unavailable` | The daily counter could not be read or written, so the scan did not run. |
| `scan-failed` | Unexpected error in the browser session, including Cloudflare refusing to start a browser. The detail is in the Worker log. |

A page with fewer than 3 links, at least 2,500 characters of markup and a non-essential tracker or
tracker cookie seen is judged: the tracker is evidence on its own. It is judged without the two
findings about missing policy links (`no-privacy-policy`, `no-cookie-policy`), because a page with no
navigation cannot be judged on its links. Its other findings stand.

Requests the Worker refuses outright use HTTP status codes: `400` (`bad-json`, `bad-url`), `401`
(`unauthorized`), `404` (`not-found`), `503` (`not-configured`).

### For callers

`finalUrl`, the `sample` in the data of a `preticked-consent` finding and, in debug output, the
banner labels, the cookie names, the policy URL and the exception text can carry text chosen by the
scanned page. Escape them before you display them.

## Known limits

- Detection works from hand-written pattern lists: the lists in `data/` (see `data/README.md`) and
  the banner labels in `src/ux.ts`. What is not in them is not seen, and the two directions differ. A
  banner label the patterns do not know means doubt, so that banner gets no `banner-no-reject`. A
  tracker host or cookie name that is not listed is not counted, so a site that uses only unlisted
  trackers gets a clean report.
- Languages differ by check. Banner labels: Italian, English, Spanish, French, German. Policy links:
  the languages listed in [docs/detection.md](docs/detection.md#policy-links). Notice text: Italian, English,
  Spanish. Pre-ticked checkboxes: Italian, Spanish and English words.
- A banner is looked for among visible elements that are fixed or sticky, or sit close inside one,
  whose `id` or `class` contains `cookie`, `consent`, `gdpr`, `iubenda` or `cc-window`, and whose text
  matches a short list of words about cookies and consent. A banner built otherwise is not seen and
  gets no banner finding.
- Criteo is matched by its hosts and by one first-party cookie, `cto_bundle`, the only name found
  documented. A Criteo cookie with another name is not counted.
- A consent platform is also recognised from its cookie names, and those are matched by prefix
  (`_iub_cs` for `_iub_cs-<site id>`). A site's own cookie that starts like one of them, for example
  `CookieConsentShown` or `usercentrics_lang`, credits a platform that is not there: the summary
  names it, trackers seen only in the requests are reported as `trackers-maybe-ungated` (moderate)
  instead of critical, and `no-cmp` is not raised. Evidence from a cookie name alone never raises a
  finding: for `banner-no-reject`, a platform counts only when its host, a global or its markup was
  found, or an IAB TCF API runs.
- Trackers that run inside a worker (for example through Partytown) are not seen in the requests;
  see [Security](#security).
- Consent Mode is read in part from the `gcd` parameter, whose format Google does not document and
  can change. A value of another shape is ignored whole and the other signals decide; a letter
  outside the documented table sets nothing, while the other letters of the same value still count.
- The scroll and reject phases run only while the time budget allows; on a slow page they can be
  skipped, and then they report nothing.
- A scan loads the page like a visitor would. You are responsible for which sites you scan.
- The notice check reads one link: the last one with a strong notice phrase on the scanned page's
  own host, or else the last one found. On a site that links several notices (one per service, or
  a general one and a specific one), the last of them is read, whether or not it is the notice for
  the scanned page. A site whose only privacy link is a single word inside a longer text gets no
  notice check.
- A page with no `lang` attribute is judged with the policy-link words of every listed language. A
  page in a language that is not listed and does not declare it (Czech without `lang`, for example)
  can get `no-privacy-policy` although it links its notice.
- The cookie policy word is "cookie" in most languages, so a link that only talks about cookies to
  eat (a recipe) counts as a cookie policy link and clears `no-cookie-policy`.
- Sites on a non-default port are not scanned.

## License

MIT. See `LICENSE`.

---

More tools from the same system: [github.com/Michel9329](https://github.com/Michel9329).
