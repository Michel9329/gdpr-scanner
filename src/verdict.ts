// Combines the detections into a weighted GDPR verdict. Conservative: when in doubt, it does not accuse.
import type { RawScan, PrivacyResult, PrivacyFinding, Severity, PolicyContentCheck } from './types';
import {
  detectPolicies,
  detectCmp,
  detectConsentMode,
  detectGoogleFonts,
  detectTrackers,
  classifyCookies,
} from './detect';
import { classifyCookieName } from '../data/cookie-patterns';

const WEIGHT: Record<Severity, number> = { critical: 45, serious: 25, moderate: 12, minor: 5 };

export function buildResult(scan: RawScan, policyCheck?: PolicyContentCheck): PrivacyResult {
  // Page not loaded, OR empty/blocked (bot challenge, interstitial, failed render) = no verdict.
  // Never issue a verdict from a page we did not really read (avoids false "no-privacy-policy" or
  // false "compliant" from an empty page).
  const htmlLen = scan.html.replace(/\s+/g, '').length;
  const looksEmpty = scan.links.length < 3 && htmlLen < 2500;
  if (!scan.reachable || looksEmpty) {
    return {
      scanned: false,
      verdict: null,
      score: 0,
      findings: [],
      summary: emptySummary(),
      finalUrl: scan.finalUrl || scan.requestedUrl,
      error: scan.error || (looksEmpty ? 'empty-or-blocked' : undefined),
    };
  }

  const pol = detectPolicies(scan);
  const cmp = detectCmp(scan);
  const cm = detectConsentMode(scan);
  const gf = detectGoogleFonts(scan);
  const tr = detectTrackers(scan);
  const ck = classifyCookies(scan);

  // STRICT model: "compliant" ONLY if NO tracking tool fires
  // pre-consent. If anything fires -> at least "partial, check the blocking". No blind trust in the
  // self-declared consent state: from outside we cannot confirm that it is really blocked.
  const cookieVendors = ck.vendors;
  const networkVendors = tr.trackers.map((t) => t.name);
  const hasConsentMgmt = !!cmp.id || cm.present;
  // CERTAIN (non-compliant): non-essential cookie pre-consent, OR network trackers with no consent management at all.
  const certainVendors = dedupe([...cookieVendors, ...(hasConsentMgmt ? [] : networkVendors)]);
  // AMBIGUOUS (partial): network trackers pre-consent WITH a consent system present, but no proof
  // of cookies. They may be gated/cookieless, but we cannot confirm it from outside -> "check the blocking".
  const ambiguousVendors = hasConsentMgmt
    ? dedupe(networkVendors.filter((v) => !cookieVendors.includes(v)))
    : [];
  const allVendors = dedupe([...certainVendors, ...ambiguousVendors]);
  const hasCertain = certainVendors.length > 0;
  const hasAmbiguous = ambiguousVendors.length > 0;

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
  if (!pol.hasPrivacy) {
    findings.push({ id: 'no-privacy-policy', severity: 'serious' });
  }

  // Cookie policy missing, but only if the site uses cookies/trackers (otherwise it is not needed).
  if (!pol.hasCookie && (hasCertain || hasAmbiguous)) {
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

  // --- Tier A checks from the legal research checklist (2026-07-04; the precise sources are in the localized texts downstream) ---

  // Banner visible with "Accept" but with NO reject or X at the first level (Italian DPA guidelines 231/2021 s.7.1-7.2:
  // continuing without consent must be as easy as consenting). Conservative: only if the banner
  // was found AND has a recognized accept control.
  if (scan.banner?.found && scan.banner.accept && !scan.banner.reject && !scan.banner.close) {
    findings.push({ id: 'banner-no-reject', severity: 'serious' });
  }
  // Banner without a link to the notice (guidelines 231/2021 s.7.2: the banner points to the full notice).
  if (scan.banner?.found && !scan.banner.policyLink) {
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
  if (policyCheck?.checked && policyCheck.missing.length >= 3) {
    findings.push({
      id: 'privacy-policy-incomplete',
      severity: 'moderate',
      data: { missing: policyCheck.missing.join(','), count: policyCheck.missing.length },
    });
  }

  // --- Tier B stateful (2026-07-05): evidence = ONLY new non-essential cookies (certain) ---
  const p2 = scan.phase2;
  if (p2) {
    // Scrolling makes tracking cookies appear = the site treats scrolling as consent
    // (forbidden: Italian DPA guidelines 231/2021 + EDPB Guidelines 05/2020, example 16).
    const scrollVendors = vendorsFromCookieList(p2.scroll.newCookies);
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
      const rejVendors = vendorsFromCookieList(p2.reject.newCookies);
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

/** Unique vendors from the NON-essential cookie names of a list (Tier B: evidence on the diffs). */
function vendorsFromCookieList(list: { name: string; domain: string }[]): string[] {
  const vendors = new Set<string>();
  for (const c of list || []) {
    const p = classifyCookieName(c.name);
    if (p) vendors.add(p.name);
  }
  return [...vendors];
}

function emptySummary() {
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
