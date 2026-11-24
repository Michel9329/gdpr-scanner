// GDPR detection logic over the raw observations (RawScan). No verdict here: only "what is there".
import type { RawScan } from './types';
import { CMP_SIGNATURES } from '../data/cmp-signatures';
import { classifyTrackerUrl, type TrackerHost } from '../data/tracker-hosts';
import { classifyCookieName } from '../data/cookie-patterns';
import { hostMatches, requestParts } from './hosts';

// --- Privacy / cookie policy (link scan, multilingual) ---
// The words below are data: they are matched, in lower case, against the link URL and link text of
// the scanned page. Where a URL slug drops the accents, the slug form is listed too. A language is
// "covered" only when it has words for both links; on a page whose <html lang> names a language
// that is not covered, a missing link is not reported (the link may be there, in words not listed).
//   privacy  words that make a link count as a privacy link (presence only)
//   notice   phrases strong enough to pick the link whose page is read as the privacy notice;
//            matched with "-" and "_" read as spaces, so "privacy-policy" is "privacy policy"
//   text     whole link texts that are also strong ("Privacy", "Informativa" alone in a footer)
//   cookie   words that make a link count as a cookie policy link; a word that is also ordinary
//            vocabulary ("kakor" are cakes, "ciasteczka" biscuits) is listed only inside a phrase
const POLICY_WORDS: Record<string, { privacy: string[]; notice: string[]; text: string[]; cookie: string[] }> = {
  it: {
    privacy: ['privacy', 'informativa', 'trattamento dei dati'],
    notice: ['privacy policy', 'informativa privacy', 'informativa sulla privacy', 'informativa sul trattamento', 'trattamento dei dati', 'protezione dei dati'],
    text: ['privacy', 'informativa'],
    cookie: ['cookie'],
  },
  en: { privacy: ['privacy'], notice: ['privacy policy', 'privacypolicy', 'privacy notice', 'privacy statement'], text: ['privacy'], cookie: ['cookie'] },
  es: {
    privacy: ['privacidad'],
    notice: ['política de privacidad', 'politica de privacidad', 'aviso de privacidad', 'protección de datos', 'proteccion de datos'],
    text: ['privacidad'],
    cookie: ['cookie'],
  },
  pt: { privacy: ['privacidade'], notice: ['política de privacidade', 'politica de privacidade', 'aviso de privacidade'], text: ['privacidade'], cookie: ['cookie'] },
  fr: {
    privacy: ['confidentialit', 'données personnelles', 'donnees-personnelles'],
    notice: ['politique de confidentialit', 'données personnelles', 'donnees personnelles', 'protection des données', 'protection des donnees'],
    text: ['confidentialité'],
    cookie: ['cookie'],
  },
  de: { privacy: ['datenschutz'], notice: ['datenschutzerkl', 'datenschutzhinweis', 'datenschutzrichtlinie'], text: ['datenschutz'], cookie: ['cookie'] },
  nl: { privacy: ['privacy'], notice: ['privacyverklaring', 'privacybeleid', 'privacy policy', 'privacy statement'], text: ['privacy'], cookie: ['cookie'] },
  pl: {
    privacy: ['prywatno'],
    notice: ['polityka prywatności', 'polityka prywatnosci'],
    text: [],
    cookie: ['cookie', 'polityka ciasteczek', 'polityka-ciasteczek'],
  },
  sv: {
    privacy: ['integritet'],
    notice: ['integritetspolicy'],
    text: [],
    cookie: ['cookie', 'kakpolicy', 'om kakor', 'om-kakor', 'användning av kakor', 'anvandning-av-kakor'],
  },
  da: { privacy: ['privatliv'], notice: ['privatlivspolitik', 'persondatapolitik'], text: [], cookie: ['cookie'] },
  nb: { privacy: ['personvern'], notice: ['personvernerklæring', 'personvernerklaering', 'personvernerklaring'], text: ['personvern'], cookie: ['cookie', 'informasjonskaps'] },
  fi: { privacy: ['tietosuoja'], notice: ['tietosuojaseloste', 'tietosuojakäytäntö', 'tietosuojakaytanto'], text: [], cookie: ['cookie', 'eväste', 'evaste'] },
};
// Norwegian is tagged "no", "nb" (Bokmål) or "nn" (Nynorsk): the same words serve all three.
const LANG_ALIASES: Record<string, string> = { no: 'nb', nn: 'nb' };

const uniq = (a: string[]) => [...new Set(a)];
/** Words that mark a link as a privacy notice. "gdpr" is used in link text across languages. */
const PRIVACY_HINTS = uniq([...Object.values(POLICY_WORDS).flatMap((w) => w.privacy), 'gdpr']);
/** Words that mark a link as a cookie policy. */
const COOKIE_HINTS = uniq(Object.values(POLICY_WORDS).flatMap((w) => w.cookie));
/** Words that mark a link as a privacy or cookie policy link. The scanner uses the same list to
 *  keep those links when a page has more links than it stores. */
export const POLICY_LINK_HINTS = uniq([...PRIVACY_HINTS, ...COOKIE_HINTS]);

/** Phrases strong enough to choose the privacy notice to read, and whole link texts that are. */
const NOTICE_PHRASES = uniq(Object.values(POLICY_WORDS).flatMap((w) => w.notice));
const NOTICE_TEXTS = new Set(Object.values(POLICY_WORDS).flatMap((w) => w.text));

const isPrivacyLink = (hay: string) => PRIVACY_HINTS.some((h) => hay.includes(h));
const isCookieLink = (hay: string) => COOKIE_HINTS.some((h) => hay.includes(h));
const linkHay = (l: { href: string; text: string }) => `${l.href} ${l.text}`.toLowerCase();

/** A link strong enough to be read as the privacy notice: a notice phrase in its URL or text, or a
 *  whole link text such as "Privacy" when its URL does not point to a cookie page. Single words
 *  inside a longer text ("Consulenza GDPR", "La nuova privacy di WhatsApp") only count for presence. */
function isNoticeLink(l: { href: string; text: string }): boolean {
  const hay = linkHay(l).replace(/[-_]+/g, ' ');
  if (NOTICE_PHRASES.some((p) => hay.includes(p))) return true;
  const text = String(l.text || '').trim().toLowerCase();
  return NOTICE_TEXTS.has(text) && !/cookie/i.test(String(l.href || ''));
}

/**
 * Primary language subtag of the first <html> tag's lang attribute, lower case ("de" for "de-AT"),
 * '' when absent. Linear on any input: the tag is found with a fixed pattern, at most its first
 * 1,000 characters are read, and the attribute pattern has no two overlapping repeats.
 */
export function pageLanguage(html: string): string {
  const s = String(html || '');
  const start = /<html(?=[\s>/])/i.exec(s);
  if (!start) return '';
  let tag = s.slice(start.index, start.index + 1000);
  const end = tag.indexOf('>');
  if (end !== -1) tag = tag.slice(0, end);
  const m = /\s(?:xml:)?lang\s*=\s*(?:["']\s*)?([a-z]{2,3})(?![a-z])/i.exec(tag);
  return m ? m[1].toLowerCase() : '';
}

/** False when <html lang> names a language the policy-link words do not cover. An absent lang
 *  attribute is judged with the words of every language. */
export function policyLanguageCovered(html: string): boolean {
  const lang = pageLanguage(html);
  return !lang || (LANG_ALIASES[lang] ?? lang) in POLICY_WORDS;
}

export interface PolicyDetection {
  hasPrivacy: boolean;
  hasCookie: boolean;
}

export function detectPolicies(scan: RawScan): PolicyDetection {
  let hasPrivacy = false;
  let hasCookie = false;
  for (const l of scan.links) {
    const hay = linkHay(l);
    if (!hasPrivacy && isPrivacyLink(hay)) hasPrivacy = true;
    if (!hasCookie && isCookieLink(hay)) hasCookie = true;
  }
  return { hasPrivacy, hasCookie };
}

/** URL of the privacy notice page (for the Arts. 12-13 content check). Only links strong enough to
 *  be the notice count (isNoticeLink). Among them the last one on the scanned page's host wins,
 *  else the last one at all: menus come before footers, and the notice is linked from the footer.
 *  mailto:, tel: and other non-http links are discarded. */
export function findPrivacyPolicyUrl(scan: RawScan): string | null {
  let sameHost: string | null = null;
  let any: string | null = null;
  let baseHost = '';
  try {
    baseHost = new URL(scan.finalUrl || scan.requestedUrl).hostname.toLowerCase();
  } catch {
    /* noop */
  }
  for (const l of scan.links) {
    if (!isNoticeLink(l)) continue;
    let u: URL;
    try {
      u = new URL(l.href);
    } catch {
      continue;
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
    any = u.toString();
    if (baseHost && u.hostname.toLowerCase() === baseHost) sameHost = u.toString();
  }
  return sameHost || any;
}

// --- CMP / cookie banner ---

/** How far into an id/class attribute value the banner patterns look. The bound keeps the regexes
 *  linear on hostile markup (a page made of unterminated attributes). */
const ATTR_SCAN = 300;

/** Request types that can carry a consent platform's code. A word in the path of an image or a
 *  stylesheet ("optanon-screenshot.png") says nothing about which platform runs on the page. */
const CODE_REQUEST_TYPES = new Set(['script', 'xhr', 'fetch']);

/** How a consent platform was found. A cookie name alone is weak evidence: cookie names are matched
 *  by prefix, so a site's own "CookieConsentShown" looks like Cookiebot's "CookieConsent". It may
 *  lower a severity (trackers seen only in the requests, no-cmp) but never raise a finding. */
export type CmpEvidence = 'host' | 'global' | 'selector' | 'tcf' | 'cookie' | 'custom';

export interface CmpDetection {
  id: string | null;
  name: string | null;
  evidence: CmpEvidence | null;
}

export function detectCmp(scan: RawScan): CmpDetection {
  const requests = scan.network.map((r) => ({ ...requestParts(r.url), code: CODE_REQUEST_TYPES.has(r.type) }));
  const cookieNames = scan.cookies.map((c) => c.name);
  const html = scan.html.toLowerCase();
  let byCookieOnly: { id: string; name: string } | null = null;
  for (const cmp of CMP_SIGNATURES) {
    // A host entry matches the host or a subdomain, on any request. An entry without a dot is a
    // word looked for in the host and path, and only on requests that load code.
    const byHost = cmp.hosts.some((h) =>
      requests.some((q) => (h.includes('.') ? hostMatches(q.host, h) : q.code && !!q.host && (q.host + q.path).includes(h))),
    );
    const byGlobal = cmp.globals.some((g) => scan.globals.cmpGlobals.includes(g));
    const bySelector = cmp.selectors.some((s) => {
      // Match ONLY inside a real id/class attribute (NOT in links/text): avoids "onetrust" in a blog post.
      const token = s.replace(/^[#.]/, '').toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      return new RegExp(`(?:id|class)\\s*=\\s*["'][^"']{0,${ATTR_SCAN}}${token}`).test(html);
    });
    const evidence: CmpEvidence | null = byHost ? 'host' : byGlobal ? 'global' : bySelector ? 'selector' : null;
    if (evidence) return { id: cmp.id, name: cmp.name, evidence };
    if (!byCookieOnly && cmp.cookies.some((ck) => cookieNames.some((n) => n === ck || n.startsWith(ck)))) {
      byCookieOnly = { id: cmp.id, name: cmp.name };
    }
  }
  // IAB TCF: an active window.__tcfapi means a CMP compliant with the Transparency & Consent Framework
  // is running, even if it is not one of the known CMPs by name. Strong signal that a consent dialog is present.
  if (scan.globals.hasTcfApi) {
    return { id: 'tcf', name: 'IAB TCF', evidence: 'tcf' };
  }
  // A listed platform seen only through a cookie name: named in the summary, weak evidence.
  if (byCookieOnly) return { ...byCookieOnly, evidence: 'cookie' };
  // Fallback: a home-made banner, recognized by an id/class attribute that names a cookie or consent
  // banner. A link or a text that only talks about cookies does not count.
  if (CUSTOM_BANNER_RE.test(scan.html)) {
    return { id: 'custom', name: CUSTOM_CMP, evidence: 'custom' };
  }
  return { id: null, name: null, evidence: null };
}

/** Sentinel for "custom banner detected" (localized downstream: Personalizzato/Custom/Personalizado). */
export const CUSTOM_CMP = '__custom__';
// Match ONLY inside a real id/class attribute (no href/text): avoids false positives on links such as
// "/cookie-consent-guide" or text that TALKS about cookies. A hidden leftover can still match.
const CUSTOM_BANNER_RE = new RegExp(
  `(?:id|class)\\s*=\\s*["'][^"']{0,${ATTR_SCAN}}` +
    '(?:cookie[-_]?(?:banner|consent|notice|bar|popup|law|modal|widget|disclaimer|prefs|preferences)|consent[-_]?(?:banner|manager|popup|bar)|gdpr[-_]?(?:banner|consent|cookie)|cookieconsent)',
  'i',
);

// --- Google Consent Mode (v1/v2) ---
const GOOGLE_TAG_HOSTS = ['googletagmanager.com', 'google-analytics.com', 'googleadservices.com', 'googlesyndication.com', 'doubleclick.net'];

export interface ConsentModeDetection {
  /** A request went to a Google tag host. */
  hasGoogleTag: boolean;
  present: boolean;
  version: 'v1' | 'v2' | null;
}

/**
 * The `gcd` parameter of a Google hit. Google tags send it to Google services whether or not the
 * site activated Consent Mode, so its presence alone proves nothing.
 *   https://developers.google.com/tag-platform/security/concepts/consent-mode
 *   https://simoahava.com/analytics/consent-mode-v2-google-tags/
 * Format, as documented by the second source: digits, then four signal letters separated by digits
 * (ad_storage, analytics_storage, ad_user_data, ad_personalization), then a closing digit, e.g.
 * "11p1p1p1p5". The digits are not documented, so any digits are accepted. Letters: "l" = the
 * signal was not set with Consent Mode; p q t r m n u v = set by a default and/or an update.
 * Google does not document this format and it can change: a value of any other shape, or a letter
 * outside that table, decides nothing, and the other evidence (gcs, a consent command) decides.
 * A value with a fifth letter segment does not have the documented shape and is ignored whole.
 *
 * `gcs` (ad_storage and analytics_storage, e.g. "G100") is read on the same hit: on a hit whose
 * gcd parses with all four signals "l", gcs proves nothing (the signals were not set); an empty gcs
 * proves nothing; otherwise, on a hit with no gcd or an unparseable one, a gcs value counts.
 */
const GCD_RE = /^\d+([a-zA-Z])\d+([a-zA-Z])\d+([a-zA-Z])\d+([a-zA-Z])\d*$/;
const GCD_SET = new Set(['p', 'q', 't', 'r', 'm', 'n', 'u', 'v']);

interface HitConsent {
  /** Consent Mode is shown by this hit. */
  present: boolean;
  /** ad_user_data or ad_personalization was set on this hit. */
  v2: boolean;
}

/** What one request URL says about Consent Mode, from its gcd and gcs parameters. */
function hitConsent(url: string): HitConsent {
  const gcdRaw = /[?&]gcd=([^&#]*)/.exec(url)?.[1];
  const m = gcdRaw ? GCD_RE.exec(gcdRaw) : null;
  const letters = m ? m.slice(1, 5) : null;
  const set = letters ? letters.map((c) => GCD_SET.has(c)) : [false, false, false, false];
  const allNotSet = !!letters && letters.every((c) => c === 'l');
  const gcs = !!/[?&]gcs=[^&#]/.exec(url) && !allNotSet;
  return { present: set.some(Boolean) || gcs, v2: set[2] || set[3] };
}

export function detectConsentMode(scan: RawScan): ConsentModeDetection {
  const urls = scan.network.map((r) => r.url);
  // A dataLayer alone is not a Google tag: other tools (and sites) push to window.dataLayer too.
  const hasGoogleTag = urls.some((u) => {
    const { host } = requestParts(u);
    return GOOGLE_TAG_HOSTS.some((d) => hostMatches(host, d));
  });

  const gtde = scan.globals.googleTagDataEntries;
  const hasIcs = !!gtde && typeof gtde === 'object' && Object.keys(gtde as object).length > 0;
  const dlStr = safeStringify(scan.globals.dataLayer);
  // Serialized gtag tuple: ["consent","default"/"update",...] (stricter than "consent" and default scattered apart,
  // avoids the false positive of {consent:'default'} -> "consent":"default").
  const dlConsent = /"consent"\s*,\s*"(?:default|update)"/.test(dlStr);
  const hits = urls.map(hitConsent);
  const netConsent = hits.some((h) => h.present);
  // ad_user_data and ad_personalization (the two signals added by v2) are the 3rd and 4th letters.
  const gcdV2 = hits.some((h) => h.v2);

  const present = hasIcs || dlConsent || netConsent;
  const v2 =
    gcdV2 ||
    /ad_user_data|ad_personalization/.test(dlStr) ||
    (hasIcs && /ad_user_data|ad_personalization/.test(safeStringify(gtde)));
  const version: 'v1' | 'v2' | null = present ? (v2 ? 'v2' : 'v1') : null;
  return { hasGoogleTag, present, version };
}

// --- Google Fonts from the CDN (known GDPR issue) ---
export function detectGoogleFonts(scan: RawScan): { found: boolean } {
  const found = scan.network.some((r) => {
    const { host } = requestParts(r.url);
    return hostMatches(host, 'fonts.googleapis.com') || hostMatches(host, 'fonts.gstatic.com');
  });
  return { found };
}

// --- Non-essential trackers (from network requests) ---
export interface TrackerDetection {
  trackers: TrackerHost[]; // unique by name
  hasTagManager: boolean;
}

export function detectTrackers(scan: RawScan): TrackerDetection {
  const seen = new Set<string>();
  const trackers: TrackerHost[] = [];
  let hasTagManager = false;
  for (const r of scan.network) {
    const t = classifyTrackerUrl(r.url);
    if (!t) continue;
    if (t.category === 'tag-manager') {
      hasTagManager = true;
      continue; // the tag manager itself is not a violation: what counts are the trackers it orchestrates
    }
    if (t.exempt) continue; // cookieless-capable analytics (Matomo, Plausible): conservative, we do not accuse
    if (seen.has(t.name)) continue;
    seen.add(t.name);
    trackers.push(t);
  }
  return { trackers, hasTagManager };
}

// --- Non-essential cookies (by name, secondary signal) ---
/** Unique vendors of the non-essential cookies in a list (the page's cookies, or a phase diff). */
export function cookieVendors(cookies: { name: string }[]): string[] {
  const vendors = new Set<string>();
  for (const c of cookies || []) {
    const p = classifyCookieName(c.name);
    if (p) vendors.add(p.name);
  }
  return [...vendors];
}

function safeStringify(v: unknown): string {
  try {
    return JSON.stringify(v) ?? '';
  } catch {
    return '';
  }
}
