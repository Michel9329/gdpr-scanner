// Combines the detections into a weighted GDPR verdict. Conservative: when in doubt, it does not accuse.
import type { RawScan, PrivacyResult, PrivacyFinding, PrivacySummary, Severity, PolicyContentCheck, ScanErrorCode } from './types';
import {
  detectPolicies,
  detectCmp,
  detectConsentMode,
  detectGoogleFonts,
  detectTrackers,
  cookieVendors,
  pageLanguage,
  policyLanguageCovered,
} from './detect';

const WEIGHT: Record<Severity, number> = { critical: 45, serious: 25, moderate: 12, minor: 5 };

/** Media types of a page that can be judged. Anything else (a PDF, an image, JSON) is not a site page. */
const HTML_TYPES = ['text/html', 'application/xhtml+xml'];

/** Fewer links than this and the page has no navigation to judge policy links on. */
const MIN_LINKS = 3;

/** Languages the privacy-notice content check can read (src/policy-check.ts). */
const NOTICE_LANGS = ['it', 'en', 'es'];

/** "Not evaluable" result: no verdict, no findings, an empty summary. */
export function notScannedResult(finalUrl: string, error: ScanErrorCode): PrivacyResult {
  return { scanned: false, verdict: null, score: 0, findings: [], summary: emptySummary(), finalUrl, error };
}

/** Why the page cannot be judged, or null when it can. */
function notEvaluable(scan: RawScan): ScanErrorCode | null {
  if (!scan.reachable) return scan.error || 'navigation-failed';
  // An error status (403 challenge, 404, 503 maintenance) is not the site's page.
  if (scan.status >= 400) return 'empty-or-blocked';
  // A document that is not HTML (a PDF, an image, a text file) is not a site page. '' = unknown.
  if (scan.contentType && !HTML_TYPES.includes(scan.contentType)) return 'empty-or-blocked';
  // Almost no content: a bot challenge, an interstitial or an empty page. (A longer page with few
  // links is decided in buildResult, once it is known whether trackers were seen.)
  const htmlLen = scan.html.replace(/\s+/g, '').length;
  if (scan.links.length < MIN_LINKS && htmlLen < 2500) return 'empty-or-blocked';
  return null;
}

export function buildResult(scan: RawScan, policyCheck?: PolicyContentCheck): PrivacyResult {
  // Never issue a verdict from a page we did not really read (avoids false "no-privacy-policy" or
  // false "compliant" from an error or empty page).
  const notJudged = notEvaluable(scan);
  if (notJudged) return notScannedResult(scan.finalUrl || scan.requestedUrl, notJudged);

  const pol = detectPolicies(scan);
  const cmp = detectCmp(scan);
  const cm = detectConsentMode(scan);
  const gf = detectGoogleFonts(scan);
  const tr = detectTrackers(scan);

  // STRICT model: "compliant" ONLY if NO tracking tool fires
  // pre-consent. If anything fires -> at least "partial, check the blocking". No blind trust in the
  // self-declared consent state: from outside we cannot confirm that it is really blocked.
  const cookieVendorNames = cookieVendors(scan.cookies);
  const networkVendors = tr.trackers.map((t) => t.name);
  const hasConsentMgmt = !!cmp.id || cm.present;
  // CERTAIN (non-compliant): non-essential cookie pre-consent, OR network trackers with no consent management at all.
  const certainVendors = dedupe([...cookieVendorNames, ...(hasConsentMgmt ? [] : networkVendors)]);
  // AMBIGUOUS (partial): network trackers pre-consent WITH a consent system present, but no proof
  // of cookies. They may be gated/cookieless, but we cannot confirm it from outside -> "check the blocking".
  const ambiguousVendors = hasConsentMgmt
    ? dedupe(networkVendors.filter((v) => !cookieVendorNames.includes(v)))
    : [];
  const allVendors = dedupe([...certainVendors, ...ambiguousVendors]);
  const hasCertain = certainVendors.length > 0;
  const hasAmbiguous = ambiguousVendors.length > 0;
  // A consent platform known to run: a listed vendor found by its host, a global or its markup, or an
  // IAB TCF API. Not a home-made banner, and not a cookie name alone: cookie names are matched by
  // prefix, so that evidence may lower a severity (above) but never raise a finding (below).
  const knownCmp = cmp.evidence === 'host' || cmp.evidence === 'global' || cmp.evidence === 'selector' || cmp.evidence === 'tcf';

  // A page with almost no navigation was probably not really read: a JavaScript challenge or an
  // empty application shell can carry kilobytes of script and still say nothing about the site. It
  // gets no verdict, unless a non-essential tracker or tracker cookie was seen: that is evidence on
  // its own, and the page is judged without the findings that need links to look at.
  const fewLinks = scan.links.length < MIN_LINKS;
  if (fewLinks && networkVendors.length === 0 && cookieVendorNames.length === 0) {
    return notScannedResult(scan.finalUrl || scan.requestedUrl, 'empty-or-blocked');
  }

  // The policy-link findings need navigation to look at, in words the lists know.
  const policyLinksJudgeable = !fewLinks && policyLanguageCovered(scan.html);

  const findings: PrivacyFinding[] = [];

  // Non-essential cookies/trackers pre-consent, no doubt = strong violation.
  if (hasCertain) {
    findings.push({
      id: 'trackers-before-consent',
      severity: 'critical',
      data: { vendors: certainVendors.join(', '), count: certainVendors.length, hasCmp: cmp.id ? 1 : 0 },
    });
  }
  // Tools that fire pre-consent but may be blocked -> to verify (partial, not compliant).
  if (hasAmbiguous) {
    findings.push({
      id: 'trackers-maybe-ungated',
      severity: 'moderate',
      data: { vendors: ambiguousVendors.join(', '), count: ambiguousVendors.length },
    });
  }

  // Tools present but no consent dialog detected.
  if ((hasCertain || hasAmbiguous) && !cmp.id) {
    findings.push({ id: 'no-cmp', severity: 'serious' });
  }

  // Privacy policy missing.
  if (policyLinksJudgeable && !pol.hasPrivacy) {
    findings.push({ id: 'no-privacy-policy', severity: 'serious' });
  }

  // Cookie policy missing, but only if the site uses cookies/trackers (otherwise it is not needed).
  if (policyLinksJudgeable && !pol.hasCookie && (hasCertain || hasAmbiguous)) {
    findings.push({ id: 'no-cookie-policy', severity: 'moderate' });
  }

  // Google Fonts loaded from the CDN.
  if (gf.found) {
    findings.push({ id: 'google-fonts-cdn', severity: 'moderate' });
  }

  // Google tags present but Consent Mode missing.
  if (cm.hasGoogleTag && !cm.present) {
    findings.push({ id: 'no-consent-mode', severity: 'minor' });
  }

  // --- Tier A checks: banner UX, pre-ticked checkboxes, content of the privacy notice ---

  // Banner with "Accept" but with NO reject or X at the first level (Italian DPA guidelines 231/2021
  // s.7.1-7.2: continuing without consent must be as easy as consenting). Conservative on both sides:
  // - every visible control was recognized (unknown === 0): one label the patterns do not know could
  //   be the reject control, so it means doubt and no finding. A settings control is recognized, and
  //   does not count as a reject at the first level;
  // - there is something to refuse: non-essential trackers or cookies were seen, or a known consent
  //   platform runs, or the banner itself has a settings control (preferences exist, so there are
  //   choices to refuse). A notice banner with only "OK" on a site that sets nothing has nothing to reject.
  const b = scan.banner;
  const somethingToRefuse = hasCertain || hasAmbiguous || knownCmp || !!b?.settings;
  if (b?.found && b.accept && !b.reject && !b.close && b.unknown === 0 && somethingToRefuse) {
    findings.push({ id: 'banner-no-reject', severity: 'serious' });
  }
  // Banner without a link to the notice (guidelines 231/2021 s.7.2: the banner points to the full notice).
  if (b?.found && !b.policyLink) {
    findings.push({ id: 'banner-no-policy-link', severity: 'minor' });
  }
  // Pre-ticked consent checkboxes (EDPB 05/2020 + CJEU Planet49: pre-ticked = invalid consent).
  if (scan.preticked && scan.preticked.count > 0) {
    findings.push({
      id: 'preticked-consent',
      severity: 'serious',
      data: { count: scan.preticked.count, sample: scan.preticked.sample },
    });
  }
  // Poor privacy notice: >=3 of the 6 mandatory Arts. 12-13 GDPR elements are missing. Only if the
  // page was actually downloaded and read (checked); high threshold = conservative about wording.
  // Second guard on the language (the content check has its own): the notice patterns know only
  // Italian, English and Spanish, so a site that declares another language is not judged on them.
  const lang = pageLanguage(scan.html);
  if (policyCheck?.checked && policyCheck.missing.length >= 3 && (!lang || NOTICE_LANGS.includes(lang))) {
    findings.push({
      id: 'privacy-policy-incomplete',
      severity: 'moderate',
      data: { missing: policyCheck.missing.join(','), count: policyCheck.missing.length },
    });
  }

  // --- Tier B stateful: evidence = ONLY new non-essential cookies (certain) ---
  const p2 = scan.phase2;
  if (p2) {
    // Scrolling makes tracking cookies appear = the site treats scrolling as consent
    // (forbidden: Italian DPA guidelines 231/2021 + EDPB Guidelines 05/2020, example 16).
    const scrollVendors = cookieVendors(p2.scroll.newCookies);
    if (scrollVendors.length > 0) {
      findings.push({
        id: 'scroll-activates-trackers',
        severity: 'serious',
        data: { vendors: scrollVendors.join(', '), count: scrollVendors.length },
      });
    }
    // Post-reject judgments ONLY if the click was clean (banner gone: ambiguous click = no accusations).
    if (p2.reject?.clicked && p2.reject.bannerGone) {
      // Tracking cookies AFTER an explicit rejection = the most serious violation of all.
      const rejVendors = cookieVendors(p2.reject.newCookies);
      if (rejVendors.length > 0) {
        findings.push({
          id: 'trackers-after-reject',
          severity: 'critical',
          data: { vendors: rejVendors.join(', '), count: rejVendors.length },
        });
      }
      // The banner reappears on reload = the choice is not recorded (guidelines 231/2021 s.7.1: kept
      // for at least 6 months and banner not shown again).
      if (p2.reject.reloaded && p2.reject.bannerReappeared) {
        findings.push({ id: 'banner-reappears-after-reject', severity: 'moderate' });
      }
    }
  }

  // Internal 0-100 score (for color/ordering, does NOT enter any audit average).
  const penalty = findings.reduce((s, f) => s + WEIGHT[f.severity], 0);
  const score = Math.max(0, Math.min(100, 100 - penalty));

  // Verdict: one critical = non-compliant; serious/moderate = partial; only minor or nothing = compliant.
  const hasCritical = findings.some((f) => f.severity === 'critical');
  const hasSeriousOrModerate = findings.some((f) => f.severity === 'serious' || f.severity === 'moderate');
  const verdict = hasCritical ? 'non-compliant' : hasSeriousOrModerate ? 'partial' : 'compliant';

  return {
    scanned: true,
    verdict,
    score,
    findings,
    summary: {
      trackers: allVendors,
      tagManager: tr.hasTagManager,
      cmp: cmp.name,
      consentMode: cm.version,
      googleFonts: gf.found,
      privacyPolicy: pol.hasPrivacy,
      cookiePolicy: pol.hasCookie,
    },
    finalUrl: scan.finalUrl || scan.requestedUrl,
  };
}

function dedupe(arr: string[]): string[] {
  return [...new Set(arr.filter(Boolean))];
}

function emptySummary(): PrivacySummary {
  return {
    trackers: [],
    tagManager: false,
    cmp: null,
    consentMode: null,
    googleFonts: false,
    privacyPolicy: false,
    cookiePolicy: false,
  };
}
