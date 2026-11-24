# How each check decides

The exact rule behind each line of [What it detects](../README.md#what-it-detects). When the evidence is not certain the scanner
reports nothing: it judges other people's sites, so a wrong accusation is worse than a miss.

## Trackers before consent

Non-essential trackers (analytics, advertising, social pixels, session replay, A/B testing) that load or set cookies before consent. A request counts for a vendor when its host is the vendor's host or a subdomain of it; the keyword entry for self-hosted Matomo is tried only after every host rule. A cookie counts when its name is one of the exact names or documented name shapes in the list: `_ga` and `_ga_<container id>` count, a site's own `_gallery_seen` does not. Both lists are short and hand-written; see `data/README.md`.

A tracker cookie seen before consent is reported as `trackers-before-consent` (critical). A tracker seen only in the network requests is reported the same way when the page has neither a consent platform nor Consent Mode, and as `trackers-maybe-ungated` (moderate) when it has either, because from outside the scanner cannot tell whether the tracker waits for consent. Google Tag Manager is reported in the summary (`tagManager`), not as a tracker.

## Google Fonts

Google Fonts loaded from the Google CDN.

## Google Consent Mode, v1 or v2

It counts as present when a request's `gcd` has at least one of its four signals set by a default or an update, when a request carries a non-empty `gcs` and its own `gcd` does not show all four signals as not set, when `dataLayer` holds a `consent` command (`default` or `update`), or when Google's internal consent state has entries.

`gcd` alone proves nothing: Google tags send it on every hit, with or without Consent Mode ([Google](https://developers.google.com/tag-platform/security/concepts/consent-mode), [Simo Ahava](https://simoahava.com/analytics/consent-mode-v2-google-tags/)), and a signal written as `l` was not set. A `gcd` without the documented shape (four signal letters between digits; a fifth segment does not fit) is ignored whole, and the other signals decide. In a `gcd` that has the shape, a letter outside the documented table sets nothing and the other three letters still count.

Consent Mode is v2 when `ad_user_data` or `ad_personalization` is set. When it is present, trackers seen only in the requests drop from critical to `trackers-maybe-ungated` (moderate) and `no-consent-mode` is not raised; tracker cookies stay critical, and `no-cmp` is still raised when no consent platform is found. `no-consent-mode` (minor) needs a request to a Google tag host: a `dataLayer` alone is not a Google tag.

## Consent platform

A consent management platform (CMP) from the list, an IAB TCF API, or a home-made banner (reported as `custom`, recognised by an `id` or `class` attribute that names a cookie, consent or GDPR banner).

A listed platform is found by its host, a JavaScript global, its banner markup, or a cookie name. A cookie name alone is weak evidence (see [Known limits](../README.md#known-limits)): it names the platform in the summary and can lower a severity, but it never raises a finding.

## Cookie banner

What the banner offers at the first level: accept, reject, close (X), a settings control and a link to the policy (`banner-no-policy-link`, minor, when there is none). Button labels are read in Italian, English, Spanish, French and German, and a reject label is tested before an accept label, so "Non accettare" and "Accept only essential cookies" count as reject.

`banner-no-reject` (serious) is raised only when all of these hold: there is an accept control; there is no reject and no close control; every visible control was recognised; and there is something to refuse, meaning non-essential trackers or tracker cookies were seen, a listed consent platform found by its host, a global or its markup (not by a cookie name alone) or an IAB TCF API runs, or the banner has a settings control. A settings control ("Manage preferences") is recognised but is not a reject.

Only a real control can be a choice: a link that leads to another page (any `href` but empty, `#...` or `javascript:`) is never a reject or an accept control and is never clicked, whatever its text says ("Come rifiutare i cookie").

A control the patterns do not recognise means doubt and no finding: a label in another language, an icon button with no label (unless its class or id says close), "Allow selection" or "Accept selected", an accept word next to a negation in a language the lists do not cover ("Niet accepteren"), a link to another page whose text names a choice, a link on the same site with unknown text. A link to another page whose text names no choice is not counted at all when it has no text, when its text only informs (a policy, "more information"), or when it goes to another site.

A notice banner with only "OK" on a site where nothing non-essential was seen gets no `banner-no-reject` (it still gets `banner-no-policy-link` when it has no link to the policy).

## Pre-ticked consent checkboxes

Pre-ticked consent checkboxes in visible forms, when the text next to them is about consent, privacy, marketing or a newsletter.

## Policy links

Presence of a privacy policy and a cookie policy link, from the URLs and texts of the page's links, with words in Italian, English, Spanish, Portuguese, French, German, Dutch, Polish, Swedish, Danish, Norwegian and Finnish. On a page whose `<html lang>` names another language, a missing link is not reported. A page with fewer than 3 links gets no verdict, unless a non-essential tracker or tracker cookie was seen: then it is judged without the two missing-link findings (see [When there is no verdict](../README.md#when-there-is-no-verdict)). `no-cookie-policy` is raised only when trackers or tracker cookies were seen.

## Privacy notice content

Whether the notice mentions the elements GDPR articles 12 and 13 ask for (`privacy-policy-incomplete`, moderate, when at least three of six are missing; with five or six missing the page is taken for something other than a notice).

The page read is chosen among links with a strong phrase in their URL or text ("privacy policy", "informativa privacy", "política de privacidad", "Datenschutzerklärung" and their equivalents) or whose whole text is a word such as "Privacy", "Informativa" or "Datenschutz" (unless its URL points to a cookie page); a single word inside a longer text ("Consulenza GDPR", "Confidentiality agreement") counts for presence only. The last such link on the scanned page's host is read, or else the last one found: menus come before footers.

This is a plain text fetch, so it can fail on policies rendered by JavaScript. Only a notice whose text reads as Italian, English or Spanish is judged: common words of that language must make up a real share of its words, and its `<html lang>` can refuse it but never vouch for it. A notice in another language, or one whose language cannot be told, gets no finding, and so does a notice found on a scanned page whose `<html lang>` names another language.

## Scroll and reject

These two phases run when the time budget allows. The page is scrolled to the bottom, and tracker cookies that appear give `scroll-activates-trackers` (serious).

If the banner has a recognised reject control, the scanner clicks it, preferring a reject label with no accept word in it. A reject label that also reads as accept is clicked only when the banner has another, plain accept control. Only when the banner is gone after the click: tracker cookies that appear give `trackers-after-reject` (critical), and after one reload, the banner coming back with its choices gives `banner-reappears-after-reject` (moderate). These phases judge new cookies only, never network requests.
