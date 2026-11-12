// Shared types for gdpr-scanner.

export type Severity = 'critical' | 'serious' | 'moderate' | 'minor';

/** Raw observations collected by the headless browser (no judgment here). */
export interface RawScan {
  requestedUrl: string;
  finalUrl: string;
  status: number;
  reachable: boolean;
  /** HTML after load (PRE-consent state: we do not click any banner). */
  html: string;
  links: { href: string; text: string }[];
  /** All network requests fired at load. */
  network: { url: string; type: string }[];
  /** Cookies present after load (pre-consent). */
  cookies: { name: string; domain: string }[];
  globals: {
    /** window.dataLayer (gtag/GTM) if present. */
    dataLayer: unknown[];
    /** window.google_tag_data.ics.entries (Consent Mode, internal API). */
    googleTagDataEntries: unknown;
    /** window.__tcfapi exists (IAB TCF). */
    hasTcfApi: boolean;
    /** which known CMP globals are present (e.g. "_iub", "Cookiebot"). */
    cmpGlobals: string[];
  };
  /** UX observation of the cookie banner VISIBLE at the first level.
   *  Optional: absent on old scans in the KV cache and in older test fixtures. */
  banner?: BannerObs | null;
  /** Consent checkboxes ALREADY ticked in visible forms (EDPB 05/2020: pre-ticked = invalid consent). */
  preticked?: { count: number; sample: string };
  /** Tier B (2026-07-05): stateful observations (scroll test + reject test). Optional: absent on
   *  old scans in the cache and when the time budget does not allow it. */
  phase2?: Phase2Obs;
  error?: string;
}

/** Tier B observations. Evidence = ONLY new cookies (diff), never judgments here. */
export interface Phase2Obs {
  /** After scrolling to the bottom of the page: cookies that appeared compared to before the scroll. */
  scroll: { newCookies: { name: string; domain: string }[] };
  /** After clicking the banner's reject control (only if it existed). */
  reject?: {
    clicked: boolean;
    /** the banner disappeared after the click (false = a panel may have opened: ambiguous state, do not judge) */
    bannerGone: boolean;
    /** cookies that appeared AFTER the rejection */
    newCookies: { name: string; domain: string }[];
    /** the verification reload was performed */
    reloaded: boolean;
    /** on reload the banner with the consent controls reappeared (choice not remembered) */
    bannerReappeared: boolean;
  };
}

/** What the cookie banner offers at the FIRST level (without opening panels). Observations only, no judgment. */
export interface BannerObs {
  found: boolean;
  /** accept control present */
  accept: boolean;
  /** reject / "continue without accepting" control present at the same level */
  reject: boolean;
  /** close (X) button present */
  close: boolean;
  /** link to the notice (privacy/cookie policy) inside the banner */
  policyLink: boolean;
}

/** Result of the minimum-content check of the privacy notice (server-side fetch, not browser). */
export interface PolicyContentCheck {
  /** true only if the notice page was actually downloaded and read (conservative). */
  checked: boolean;
  /** mandatory Arts. 12-13 GDPR elements NOT found in the text (stable keys, localized downstream). */
  missing: string[];
  url?: string;
}

/** GDPR finding: stable id (to be localized by the caller) + severity + data to interpolate. */
export interface PrivacyFinding {
  id: string;
  severity: Severity;
  data?: Record<string, string | number>;
}

/** Detected item, shown in the "what we found" list. */
export interface DetectedItem {
  kind: 'tracker' | 'cmp' | 'consent-mode' | 'google-fonts' | 'policy' | 'tag-manager';
  name: string;
  detail?: string;
}

export type Verdict = 'compliant' | 'partial' | 'non-compliant';

/** Summary of what was detected (for the "what we found" list in a UI or email). */
export interface PrivacySummary {
  trackers: string[]; // non-essential vendor names found (e.g. "Google Analytics", "Meta Pixel")
  tagManager: boolean;
  cmp: string | null; // name of the detected CMP, or null
  consentMode: 'v1' | 'v2' | null;
  googleFonts: boolean;
  privacyPolicy: boolean;
  cookiePolicy: boolean;
}

/** Final result returned by the Worker. */
export interface PrivacyResult {
  scanned: boolean; // false if we could not load the page (conservative: no verdict)
  verdict: Verdict | null;
  /** 0-100 internal value for color/ordering; does NOT enter any audit grade average. */
  score: number;
  findings: PrivacyFinding[];
  summary: PrivacySummary;
  finalUrl: string;
  error?: string;
}
