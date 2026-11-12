// GDPR detection logic over the raw observations (RawScan). No verdict here: only "what is there".
import type { RawScan, DetectedItem } from './types';
import { CMP_SIGNATURES } from '../data/cmp-signatures';
import { classifyTrackerHost, type TrackerHost } from '../data/tracker-hosts';
import { classifyCookieName } from '../data/cookie-patterns';

// --- Privacy / cookie policy (link scan, multilingual) ---
// The Italian/Spanish/German words below are data: they are matched against the scanned sites' link text and URLs.
const PRIVACY_HINTS = ['privacy', 'informativa', 'privacidad', 'datenschutz', 'gdpr', 'trattamento dei dati'];
const COOKIE_HINTS = ['cookie', 'cookies'];

export interface PolicyDetection {
  hasPrivacy: boolean;
  hasCookie: boolean;
  detected: DetectedItem[];
}

export function detectPolicies(scan: RawScan): PolicyDetection {
  let hasPrivacy = false;
  let hasCookie = false;
  for (const l of scan.links) {
    const hay = `${l.href} ${l.text}`.toLowerCase();
    if (!hasPrivacy && PRIVACY_HINTS.some((h) => hay.includes(h))) hasPrivacy = true;
    // "cookie" alone in the link text, or /cookie in the URL
    if (!hasCookie && COOKIE_HINTS.some((h) => hay.includes(h)) && /cookie/.test(hay)) hasCookie = true;
  }
  const detected: DetectedItem[] = [];
  if (hasPrivacy) detected.push({ kind: 'policy', name: 'Privacy policy', detail: 'present' });
  if (hasCookie) detected.push({ kind: 'policy', name: 'Cookie policy', detail: 'present' });
  return { hasPrivacy, hasCookie, detected };
}

/** URL of the privacy notice page (for the Arts. 12-13 content check).
 *  Prefers a link on the same host as the scanned page; discards mailto/tel/anchors. */
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
    const hay = `${l.href} ${l.text}`.toLowerCase();
    // Only an explicit "privacy/informativa" (Italian: privacy notice) link: a cookie policy alone is not enough for Arts. 12-13.
    // The words in this regex are data matched against scanned sites.
    if (!/privacy|informativa|privacidad|trattamento dei dati/.test(hay)) continue;
    let u: URL;
    try {
      u = new URL(l.href);
    } catch {
      continue;
    }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;
    if (!any) any = u.toString();
    if (baseHost && u.hostname.toLowerCase() === baseHost) {
      sameHost = u.toString();
      break;
    }
  }
  return sameHost || any;
}

// --- CMP / cookie banner ---
export interface CmpDetection {
  id: string | null;
  name: string | null;
  detected: DetectedItem | null;
}

export function detectCmp(scan: RawScan): CmpDetection {
  const netHosts = scan.network.map((r) => r.url.toLowerCase());
  const cookieNames = scan.cookies.map((c) => c.name);
  const html = scan.html.toLowerCase();
  for (const cmp of CMP_SIGNATURES) {
    const byHost = cmp.hosts.some((h) => netHosts.some((u) => u.includes(h)));
    const byGlobal = cmp.globals.some((g) => scan.globals.cmpGlobals.includes(g));
    const byCookie = cmp.cookies.some((ck) => cookieNames.some((n) => n === ck || n.startsWith(ck)));
    const bySelector = cmp.selectors.some((s) => {
      // Match ONLY inside a real id/class attribute (NOT in links/text): avoids "onetrust" in a blog post.
      const token = s.replace(/^[#.]/, '').toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      return new RegExp(`(?:id|class)\\s*=\\s*["'][^"']*${token}`).test(html);
    });
    if (byHost || byGlobal || byCookie || bySelector) {
      return { id: cmp.id, name: cmp.name, detected: { kind: 'cmp', name: cmp.name, detail: 'detected' } };
    }
  }
  // IAB TCF: an active window.__tcfapi means a CMP compliant with the Transparency & Consent Framework
  // is running, even if it is not one of the known CMPs by name. Strong signal that a consent dialog is present.
  if (scan.globals.hasTcfApi) {
    return { id: 'tcf', name: 'IAB TCF', detected: { kind: 'cmp', name: 'Cookie banner (IAB TCF)', detail: 'detected' } };
  }
  // Fallback: CUSTOM/self-hosted cookie banner (not a known third-party CMP). Pattern on id/class
  // in the markup. Conservative: does NOT match plain "cookie policy" links. E.g. a site with
  // id="site-cookie-banner" is a custom GDPR banner and must be recognised as present.
  if (CUSTOM_BANNER_RE.test(scan.html)) {
    return { id: 'custom', name: CUSTOM_CMP, detected: { kind: 'cmp', name: 'Cookie banner', detail: 'custom' } };
  }
  return { id: null, name: null, detected: null };
}

/** Sentinel for "custom banner detected" (localized downstream: Personalizzato/Custom/Personalizado). */
export const CUSTOM_CMP = '__custom__';
// Match ONLY inside a real id/class attribute (no href/text): avoids false positives on links such as
// "/cookie-consent-guide" or text that TALKS about cookies. A hidden leftover can still match (rare).
const CUSTOM_BANNER_RE =
  /(?:id|class)\s*=\s*["'][^"']*(?:cookie[-_]?(?:banner|consent|notice|bar|popup|law|modal|widget|disclaimer|prefs|preferences)|consent[-_]?(?:banner|manager|popup|bar)|gdpr[-_]?(?:banner|consent|cookie)|cookieconsent)/i;

// --- Google Consent Mode (v1/v2) ---
export interface ConsentModeDetection {
  hasGoogleTag: boolean;
  present: boolean;
  version: 'v1' | 'v2' | null;
  detected: DetectedItem | null;
}

export function detectConsentMode(scan: RawScan): ConsentModeDetection {
  const netStr = scan.network.map((r) => r.url).join(' ');
  const hasGoogleTag =
    /googletagmanager\.com|google-analytics\.com|gtag\/js|googleads/.test(netStr) ||
    (Array.isArray(scan.globals.dataLayer) && scan.globals.dataLayer.length > 0);

  const gtde = scan.globals.googleTagDataEntries;
  const hasIcs = !!gtde && typeof gtde === 'object' && Object.keys(gtde as object).length > 0;
  const dlStr = safeStringify(scan.globals.dataLayer);
  // Serialized gtag tuple: ["consent","default"/"update",...] (stricter than "consent" and default scattered apart,
  // avoids the false positive of {consent:'default'} -> "consent":"default").
  const dlConsent = /"consent"\s*,\s*"(?:default|update)"/.test(dlStr);
  const netGcs = /[?&]gcs=/.test(netStr);
  const netGcd = /[?&]gcd=/.test(netStr);

  const present = hasIcs || dlConsent || netGcs || netGcd;
  const v2 =
    netGcd ||
    /ad_user_data|ad_personalization/.test(dlStr) ||
    (hasIcs && /ad_user_data|ad_personalization/.test(safeStringify(gtde)));
  const version: 'v1' | 'v2' | null = present ? (v2 ? 'v2' : 'v1') : null;

  let detected: DetectedItem | null = null;
  if (present) {
    detected = { kind: 'consent-mode', name: 'Google Consent Mode', detail: version === 'v2' ? 'v2' : 'v1' };
  }
  return { hasGoogleTag, present, version, detected };
}

// --- Google Fonts from the CDN (known GDPR issue) ---
export function detectGoogleFonts(scan: RawScan): { found: boolean; detected: DetectedItem | null } {
  const found = scan.network.some((r) => /fonts\.googleapis\.com|fonts\.gstatic\.com/.test(r.url));
  return {
    found,
    detected: found ? { kind: 'google-fonts', name: 'Google Fonts (CDN)', detail: 'loaded from Google' } : null,
  };
}

// --- Non-essential trackers (from network hosts) ---
export interface TrackerDetection {
  trackers: TrackerHost[]; // unique by name
  hasTagManager: boolean;
  detected: DetectedItem[];
}

export function detectTrackers(scan: RawScan): TrackerDetection {
  const seen = new Set<string>();
  const trackers: TrackerHost[] = [];
  let hasTagManager = false;
  for (const r of scan.network) {
    const t = classifyTrackerHost(r.url);
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
  const detected: DetectedItem[] = trackers.map((t) => ({
    kind: 'tracker' as const,
    name: t.name,
    detail: t.category,
  }));
  if (hasTagManager) detected.push({ kind: 'tag-manager', name: 'Google Tag Manager', detail: 'present' });
  return { trackers, hasTagManager, detected };
}

// --- Non-essential cookies (by name, secondary signal) ---
// Returns only the unique vendors (raw cookie names are not needed downstream: the verdict uses vendors).
export function classifyCookies(scan: RawScan): { vendors: string[] } {
  const vendors = new Set<string>();
  for (const c of scan.cookies) {
    const p = classifyCookieName(c.name);
    if (p) vendors.add(p.name);
  }
  return { vendors: [...vendors] };
}

function safeStringify(v: unknown): string {
  try {
    return JSON.stringify(v) ?? '';
  } catch {
    return '';
  }
}
