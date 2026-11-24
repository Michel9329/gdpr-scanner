# Changelog

## 0.2.1 (24 November 2026)

- **0.2.0 did not work on Cloudflare: every scan ended with `private-address`.** Browser Run reaches
  the web through a forward proxy and reports it (`[::1]:9001`) as the address of every response, and
  the address check took that for the site. An address whose port differs from the URL's is now taken
  for a proxy and not judged. The check still runs where the browser connects directly, as under
  `wrangler dev`; on Cloudflare it has nothing to read, and the README says so.
- First checks on Cloudflare's own browser: whole scans of live sites, dialogs, a redirect to another
  port, an endless script.
- The Meta tracker is reported as `Meta (Pixel/SDK)`, a name that reads the same in every language.

## 0.2.0 (24 November 2026)

### Security and robustness

- One rule set (`src/net-guard.ts`) decides which addresses the scanner may reach, for the target,
  for the browser's requests and for the policy page. It replaces three copies of the same function.
- `localhost.` and other names written with the root dot were accepted. They are refused now,
  together with single-label names, names under private and special-use suffixes (`.lan`, `.corp`,
  `.svc`, `.test`, `.example` and the others listed in the README), credentials in the URL and
  non-default ports.
- A navigation of the page itself to an address the scanner would not accept as a target (an HTTP
  redirect, a meta refresh or a script) is aborted, and the scan ends with `blocked-redirect`. Other
  requests of the page are aborted when their URL does not parse, uses a scheme other than `http`,
  `https`, `data`, `blob` or `about`, carries credentials, or names a refused host. Before, only the
  host name was checked, and a URL that did not parse went through.
- A public name that resolves to a private address was scanned. The address each response came from
  is now checked, and such a scan ends with `private-address`. IPv6 is parsed in full (compressed,
  uncompressed, dotted tail, brackets, zone id). The IPv4 rules apply to the forms that carry an IPv4
  address: IPv4-mapped (`::ffff:0:0/96`), IPv4-translated (`::ffff:0:0:0/96`), IPv4-compatible
  (`::/96`), NAT64 (`64:ff9b::/96` and the local-use `64:ff9b:1::/48`) and 6to4 (`2002::/16`). The
  ranges that are never a website are refused: Teredo, documentation, ORCHID, discard-only, segment
  routing identifiers, unique local, link-local, site-local and multicast. Text that contains a colon
  but does not parse as IPv6 counts as private. After one such response the page is closed at once
  and every later request is aborted.
- The browser session has a deadline of 45 seconds from the launch; past it the browser is closed and
  the scan ends with `scan-timeout`. Dialogs are dismissed. Before, an `alert()` or an endless script
  held the browser until the protocol timeout of 180 seconds.
- Popups and other pages opened by the scanned page are closed when the browser reports them, the
  page's requests bypass service workers, and downloads are denied where the platform allows it.
  What these do not cover is listed in the README.
- Sizes of everything kept from the scanned page are bounded (markup, links, requests, cookies,
  `dataLayer`), and the banner patterns are bounded so hostile markup cannot stall them.
- The markup, the links and the banner are read in an isolated world, where the page's scripts cannot
  redefine the built-in functions used to read them, and the markup is cut to size inside the page.
  Everything the browser hands back is checked again in the Worker: types, string lengths, list sizes.
  A banner field that comes back missing or malformed takes the value that raises no finding.
- The text of the policy page is extracted in one linear pass. The old regular expressions took tens
  of seconds on hostile markup such as 600 KB of `<script`, and the fetch timeout could not stop them.
  A pattern that stripped trailing dots from host names was quadratic too and is gone.
- The daily cap counted only successful scans, so pages that never load could use browser time without
  limit. It now counts browser sessions and the slot is taken before the browser starts.
- The launch is retried once after a short wait on a 429 for too many new browsers, only while enough
  of the deadline is left. A 429 for the daily browser time is not retried.
- The policy page is fetched one redirect at a time, each hop checked before it is requested, and the
  body is read up to a fixed size instead of whole.
- The cache key was the host, so the scan of one page, or of wherever that page redirected, answered
  for the whole site for 6 hours. The key is now the full URL.

### Changed for callers

- `error` is one of a fixed set of codes (see the README) and never carries exception text. The detail
  goes to the Worker log, and to the caller only in debug mode.
- New codes: `blocked-redirect`, `scan-timeout`, `budget-unavailable`, `scan-failed`.
  `redirect-to-private` is gone: a redirect to a refused name or address ends with `blocked-redirect`,
  and a page served from a private address with `private-address`.
- `empty-or-blocked` now also covers an error status (such as a 403 bot challenge) and a document that
  is not HTML. `navigation-failed` covers any load error that is not a timeout.
- Names under `.test`, `.invalid`, `.example`, `.onion`, `.lan`, `.home`, `.corp`, `.intranet`,
  `.localdomain`, `.private` and `.svc` get `400 bad-url`.
- The default daily cap went from 25 to 20 browser sessions.
- Results are cached per URL instead of per host, so each query-string variant of a page takes its own
  slot of the daily cap and its own cache entry. Entries written by 0.1 are not read any more.
- The User-Agent is the browser's own, with `HeadlessChrome/` written as `Chrome/`, followed by
  `SCANNER_UA_SUFFIX`. It was a fixed `Chrome/124.0` string.
- One request answers within about 58 seconds in the worst case (45 seconds of browser session, up to
  5 to close the browser, 8 for the policy page). Set client timeouts above that.
- The notice check judges only a notice whose text reads as Italian, English or Spanish; others get no
  finding. The page's `<html lang>` can refuse a notice but never vouch for it, and a match on an
  article number ("art. 6") is not taken as a sign that the text was read. The patterns accept more
  wordings in all three languages, such as "controller", "lawful basis", "Responsable" and
  "Legitimación".
- Responses carry `cache-control: no-store`.

### Detection accuracy

Wrong accusations removed:

- Vendors are matched by host (the host or a subdomain), not by a name found anywhere in the URL.
  `cheap.io` was read as Heap and a script named `customer-segment.common.js` as Segment. The same
  applies to consent platforms and Google Fonts. The one-host-per-country rule (`adservice.google.*`)
  now needs a country or generic ending, so `adservice.google.evil.example` is no longer Google Ads.
- Cookie names are matched exactly or against the shape the vendor documents, never as a prefix. A
  site's own `_gallery_seen` or `_gate` was read as Google Analytics, `mp_lang` as Mixpanel and
  `cto_cart` as Criteo. The `_ga` prefix also answered for `_gac_`, so a Google Ads cookie was reported
  as Google Analytics. Criteo is now matched on `cto_bundle` only.
- Cookie names that only exist on the vendor's own domain (`fr`, `NID`, `IDE`, `MUID`, `bcookie` and
  others) are no longer judged: on the visited site they are a different cookie.
- `banner-no-reject` reported a missing reject on banners whose reject used words the patterns did not
  know: "Non accettare", "Refuse all", "I do not agree", "No, thanks", "Necessary only", "Solo cookie
  tecnici", "Tout refuser", "No aceptar", "Don't allow" and others. Reject labels are now tested before
  accept labels, more wordings are known, and French and German labels are read. "Accept selected"
  and "Consenti la selezione", which act as a reject when the choices are unticked, are no longer read
  as accept. The finding now also needs every visible control to be recognised (one unknown label
  means doubt) and something to refuse: trackers or tracker cookies seen, a listed consent platform
  found by its host, a global or its markup, an IAB TCF API, or a settings control on the banner. A
  platform credited only from a cookie name (a site's own `CookieConsentShown` read as Cookiebot) is
  still named in the summary and can still lower a severity, but does not count here. A notice banner with only "Ho capito" on a site
  where nothing non-essential was seen is no longer accused.
- A link in the banner that leads to another page was read as the reject control when its text named
  one ("Come rifiutare i cookie" pointing to the cookie policy), and the reject test pressed it: the
  page navigated away, the banner counted as gone, and the reload could report
  `banner-reappears-after-reject`, or `trackers-after-reject` if a cookie appeared meanwhile. Such a
  link is never a reject or an accept control now, and is never pressed.
- A page with an error status (a 403 bot challenge, a 404, a 503) or a main document that is not HTML
  got a verdict, usually `no-privacy-policy`. It now gets none. Neither does a page with fewer than 3
  links, such as a JavaScript challenge or an empty application shell with kilobytes of script, unless
  a non-essential tracker or tracker cookie was seen; such a page is then judged without the
  missing-policy findings.
- Privacy links in French, Polish, Swedish, Danish, Norwegian and Finnish were not recognised, and
  those sites were reported as having no privacy policy. On a page that declares a
  language the link words do not cover, missing policy links are not reported.
- Portuguese notices were judged with the Italian, English and Spanish patterns, because "privacidad"
  is the start of "privacidade". The notice check now judges only Italian, English and Spanish notices,
  and only on a scanned page that declares one of those languages or none.
- The notice check read the first link on the site's host with any privacy word, and menus come
  before footers: a blog post about privacy or a product sheet ("Scheda informativa") was read and
  judged on the six elements. It now reads only a link with a strong phrase ("privacy policy",
  "informativa privacy", "Datenschutzerklärung" and the like, or a whole link text such as "Privacy"),
  the last one on the site's host.
- `no-consent-mode` was raised for a non-empty `dataLayer` alone. It now needs a request to a Google
  tag host.
- On pages with more links than the scanner stores, policy links are kept first. Large home pages were
  reported as having no privacy policy because the footer link was cut off.

Wrong clearances removed:

- `gcd` on a Google hit counted as Consent Mode v2, and lowered trackers seen in the requests from
  critical to moderate. Google tags send `gcd` on every hit, with or without Consent Mode. It now
  counts only when one of its four signals is set; a value of unknown shape decides nothing. A `gcs`
  parameter counted on its own, even empty. An empty `gcs`, or one on a hit whose `gcd` shows all four
  signals as not set, now proves nothing.
- A real tracker whose URL contained "matomo" (`cdn.segment.com/.../matomo/2.0/matomo.js`) was
  classified as Matomo and exempted. Host rules now come before the Matomo keyword.
- A consent platform was credited from its name anywhere in a request URL, such as "optanon" in the
  name of an image. Host signatures now match the host, and the word only counts on script, xhr and
  fetch requests.

Banner observation:

- The banner observation in debug output has two new fields: `settings` (a control that opens the
  preferences) and `unknown` (visible controls the patterns did not recognise).
- The reject test clicks a reject label with no accept word in it when there is one. A reject label
  that also reads as accept ("Accetta solo i necessari") is pressed only when the banner has another,
  plain accept control, so a lone accept button misread as reject ("OK, no problem, accept") is not
  pressed. Next to a plain accept control such a label is still pressed, even when it is in fact an
  accept. A link that leads to another page is never pressed.

### Tests

- New suites for the address rules, vendor matching with look-alikes, the request handler and the
  policy fetch with their I/O replaced, the values the browser hands back, the scan deadline and the
  launch retry. `bun run typecheck` checks the tests too.
- The browser session of `scan()` runs in the suite on a fake browser and page, passed in through
  `scan()`'s options: the address check, the request guard, service workers, downloads, popups,
  dialogs, the re-validation, the isolated world and the launch retry each have a test that fails
  when its line is removed.

## 0.1.0 (12 November 2026)

First public release.
