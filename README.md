# gdpr-scanner

[![test](https://github.com/Michel9329/gdpr-scanner/actions/workflows/test.yml/badge.svg)](https://github.com/Michel9329/gdpr-scanner/actions/workflows/test.yml)

A Cloudflare Worker that opens a website in a headless browser and reports what loads before the
visitor has consented to anything. Built with Claude Code, designed and reviewed by Michel Dimitri.

It exists because the manual version of this check (open DevTools, clear cookies, read the network
tab) is slow and easy to get wrong across many sites.

**This is not legal advice.** The output is a technical observation about one page load. It does not
decide whether a site complies with the GDPR, the ePrivacy rules or any national law. Have a qualified
person review anything that matters.

## What it detects

- Non-essential trackers (analytics, advertising, social pixels, session replay, A/B testing) that
  load or set cookies before consent. Matching is by hostname and cookie name from a short list.
- Google Fonts loaded from the Google CDN.
- Google Consent Mode (v1 or v2 signals).
- A known consent management platform (CMP), or a custom banner.
- Whether the banner has an accept control, a reject control, a close button and a link to the policy.
- Pre-ticked consent checkboxes.
- Presence of a privacy policy and a cookie policy link, and whether the privacy policy text mentions
  the elements GDPR articles 12 and 13 ask for. This is a plain text fetch, so it can fail on policies
  rendered by JavaScript.
- Whether scrolling starts new trackers, and whether trackers still run after clicking reject.

## What it does not detect

- Trackers missing from the lists in `data/`. Unknown hosts are not flagged by design.
- Anything behind a login, on other pages, or triggered by interaction beyond scroll and reject.
- Whether a cookieless analytics tool is really anonymised. Matomo and Plausible are treated as exempt.
- A home-made banner is reported as "custom"; its behaviour is only partly checked.
- Server-side tracking, fingerprinting, and the legal quality of the policy text.
- A page that fails to load returns `scanned: false` and no verdict, not a guess.

## How it works

1. `POST /scan` with a URL. Private hosts and IP literals are rejected (SSRF guard).
2. The Worker launches Chromium through Cloudflare Browser Rendering (`@cloudflare/puppeteer`),
   records every network request and cookie before any interaction, and inspects the page for
   banners and globals.
3. It scrolls, and if the banner has a reject control it clicks it and watches again.
4. The policy page is fetched with a normal `fetch` (no browser time).
5. A strict rule set turns the raw observation into findings and a verdict
   (`compliant`, `partial`, `non-compliant`). "Compliant" only means nothing non-essential started.

Results are cached per domain for 6 hours in KV, with a daily scan counter (both need the `SCAN_KV` binding) to protect the free
browser-time budget.

## Install and test

You need [Bun](https://bun.sh) for the tests and Node 22 or newer for Wrangler.

```
bun install
bun test        # 80 tests, no network or browser needed
```

The tests run the detection and verdict logic on fixed fixtures. The browser step in `src/scanner.ts`
is not covered by them and needs a real Browser Rendering binding.

## Deploy to Cloudflare

Requires a Cloudflare account and Wrangler.

Install with `bun install` first. Before the first deploy, `wrangler secret put` asks whether to create the Worker: answer yes, the deploy fills it in.

```
bunx wrangler kv namespace create SCAN_KV     # required: cache and daily cap
# paste the id in wrangler.toml, replacing <your-kv-namespace-id>
bunx wrangler secret put SCANNER_SECRET       # required: bearer token for /scan, at least 32 characters (openssl rand -hex 32)
bunx wrangler deploy
```

Browser Rendering plans: Cloudflare's [limits page](https://developers.cloudflare.com/browser-rendering/platform/limits/)
lists limits for both Workers Free and Workers Paid. At the time of writing (November 2026) Free allows
10 browser minutes per day, 3 concurrent browsers and 1 new browser every 20 seconds. Paid has no daily
browser-time limit, 200 concurrent browsers and 3 launches per second, billed per Cloudflare's pricing.
The page does not say which plan is required for the Workers binding, so check it before you deploy.
A scan takes roughly 18 to 28 seconds in the author's runs, which is why the default daily cap is 25.

### Configuration

| Name | Kind | Purpose |
|---|---|---|
| `SCANNER_SECRET` | secret | Required, at least 32 characters. `/scan` needs `Authorization: Bearer <secret>`. If it is not set or is shorter than 32 characters, `/scan` answers 503 and never opens a browser; a wrong or missing token gets 401. |
| `SCAN_KV` | KV binding | Required. Cache and daily counter. If it is not bound, `/scan` answers 503, because without it there would be no daily cap. |
| `SCANNER_UA_SUFFIX` | var | Appended to the User-Agent, for example `my-scanner/1.0 (+https://example.com/about)`. Default `gdpr-scanner/0.1`. |
| `DAILY_CAP` | var | Max scans per UTC day. Default 25. |
| `DEBUG` | var | `1` lets a request send `x-debug: 1` to get raw details. Off by default. |

Send `x-fresh: 1` to skip the cache.

### Security

The endpoint is closed by default. Set `SCANNER_SECRET` (at least 32 characters, generate it with `openssl rand -hex 32`) and bind `SCAN_KV` before deploying
(or use `.dev.vars` for local runs), otherwise every `/scan` request gets a 503 and no browser is launched. This protects you from paying
Browser Rendering minutes for strangers. Treat the secret like a password and rotate it if it leaks. The token is compared in constant time.

The daily cap is approximate: KV is not atomic, so several scans started at the same moment can all read the same
counter and slip past the cap by a few. It protects your budget, it is not an exact quota.

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

## Known limits

- Some detection patterns look for Italian words on purpose (policy page names, banner buttons such as "Rifiuta" and "Accetta"). Sites in other languages may need more patterns.
- A scan loads the page like a visitor would. You are responsible for which sites you scan.
- Detection quality depends on the hand-written lists in `data/`; see `data/README.md`.

## License

MIT. See `LICENSE`.

---

More tools from the same system: [github.com/Michel9329](https://github.com/Michel9329).
