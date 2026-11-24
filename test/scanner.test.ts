// Unit tests for the PURE logic of the gdpr-scanner Worker.
//
// Covers detect.ts (detection) + verdict.ts (STRICT model) with deterministic RawScan fixtures.
// Goal: block regressions on false positives/negatives (e.g. "onetrust" in a link, custom banner
// vs cookie-policy link, {consent:'default'} that must not trigger Consent Mode, exempt Matomo/Plausible).
//
// No browser: these functions are pure (RawScan input -> deterministic output).
import { test, expect, describe } from 'bun:test';

import type { RawScan } from '../src/types';
import {
  detectPolicies,
  detectCmp,
  detectConsentMode,
  detectGoogleFonts,
  detectTrackers,
  cookieVendors,
  findPrivacyPolicyUrl,
  pageLanguage,
  CUSTOM_CMP,
} from '../src/detect';
import type { CmpEvidence } from '../src/detect';
import { buildResult, notScannedResult } from '../src/verdict';
import worker from '../src/index';
import { classifyCookieName } from '../data/cookie-patterns';

// ---------------------------------------------------------------------------
// Helper: builds a complete RawScan from the defaults + a partial override.
// Default = a "healthy, substantial" page (reachable, long html, >=3 links) so that, unless overridden, it does NOT fall
// into buildResult's scanned:false branch and we can isolate the single signal under test.
//
// `globals` accepts a PARTIAL override (deep merge): in the tests we often pass only cmpGlobals or
// only dataLayer, the other fields stay at their defaults.
// ---------------------------------------------------------------------------
type ScanOverride = Omit<Partial<RawScan>, 'globals'> & { globals?: Partial<RawScan['globals']> };

function makeScan(partial: ScanOverride = {}): RawScan {
  const base: RawScan = {
    requestedUrl: 'https://example.com',
    finalUrl: 'https://example.com',
    status: 200,
    reachable: true,
    // long html (>2500 non-whitespace chars) to pass buildResult's "looksEmpty" gate.
    html: '<!doctype html><html><body><main>' + 'contenuto reale della pagina. '.repeat(120) + '</main></body></html>',
    // >=3 links to pass the "looksEmpty" gate (links.length < 3). Neutral links (not policies).
    links: [
      { href: '/', text: 'Home' },
      { href: '/chi-siamo', text: 'Chi siamo' },
      { href: '/contatti', text: 'Contatti' },
    ],
    network: [],
    cookies: [],
    globals: { dataLayer: [], googleTagDataEntries: null, hasTcfApi: false, cmpGlobals: [] },
  };
  return {
    ...base,
    ...partial,
    // globals must be deep-merged (otherwise a partial override would wipe the fields not passed).
    globals: { ...base.globals, ...(partial.globals ?? {}) },
  };
}

// Reusable policy links (privacy + cookie) for the cases where we want the policies present, plus
// one ordinary link: a page needs 3 links to be judged without a tracker.
const POLICY_LINKS = [
  { href: '/privacy', text: 'Privacy Policy' },
  { href: '/cookie-policy', text: 'Cookie Policy' },
  { href: '/contatti', text: 'Contatti' },
];

// Shortcut: find a finding by id.
function finding(res: ReturnType<typeof buildResult>, id: string) {
  return res.findings.find((f) => f.id === id);
}

// ===========================================================================
// 1. Clean site -> compliant
// ===========================================================================
describe('1. clean site (zero trackers, policies present, custom banner)', () => {
  const scan = makeScan({
    links: [...POLICY_LINKS, { href: '/', text: 'Home' }, { href: '/servizi', text: 'Servizi' }],
    html:
      '<!doctype html><html><body><div class="site-cookie-banner">Usiamo i cookie</div><main>' +
      'contenuto reale della pagina. '.repeat(120) +
      '</main></body></html>',
    network: [],
    cookies: [],
  });
  const res = buildResult(scan);

  test('scanned true + compliant verdict', () => {
    expect(res.scanned).toBe(true);
    expect(res.verdict).toBe('compliant');
  });
  test('no critical/serious/moderate finding', () => {
    expect(res.findings.some((f) => f.severity === 'critical')).toBe(false);
    expect(res.findings.some((f) => f.severity === 'serious')).toBe(false);
    expect(res.findings.some((f) => f.severity === 'moderate')).toBe(false);
  });
  test('summary: policies present, no trackers, custom banner detected', () => {
    expect(res.summary.privacyPolicy).toBe(true);
    expect(res.summary.cookiePolicy).toBe(true);
    expect(res.summary.trackers).toEqual([]);
    expect(res.summary.cmp).toBe(CUSTOM_CMP); // custom banner -> __custom__ sentinel
  });
  test('full score (no penalty)', () => {
    expect(res.score).toBe(100);
  });
});

// ===========================================================================
// 2. _ga cookie pre-consent + Iubenda -> non-compliant (trackers-before-consent)
// ===========================================================================
describe('2. _ga cookie pre-consent + Iubenda', () => {
  const scan = makeScan({
    links: POLICY_LINKS,
    cookies: [{ name: '_ga', domain: 'example.com' }],
    network: [{ url: 'https://cdn.iubenda.com/cs/iubenda_cs.js', type: 'script' }],
  });
  const res = buildResult(scan);

  test('non-compliant verdict', () => {
    expect(res.verdict).toBe('non-compliant');
  });
  test('trackers-before-consent critical finding with Google Analytics', () => {
    const f = finding(res, 'trackers-before-consent');
    expect(f).toBeDefined();
    expect(f?.severity).toBe('critical');
    expect(String(f?.data?.vendors)).toContain('Google Analytics');
  });
  test('Iubenda recognized as a CMP (no no-cmp finding)', () => {
    expect(res.summary.cmp).toBe('Iubenda');
    expect(finding(res, 'no-cmp')).toBeUndefined();
  });
});

// ===========================================================================
// 3. GA on the network only (no cookie) + Consent Mode -> partial (trackers-maybe-ungated)
// ===========================================================================
describe('3. GA on the network (no cookie) + Consent Mode present', () => {
  const scan = makeScan({
    links: POLICY_LINKS,
    cookies: [], // no cookie -> ambiguous, not certain
    network: [
      { url: 'https://www.googletagmanager.com/gtag/js?id=G-XXX', type: 'script' },
      { url: 'https://www.google-analytics.com/g/collect?v=2&gcs=G100', type: 'image' },
    ],
  });
  const res = buildResult(scan);

  test('partial verdict', () => {
    expect(res.verdict).toBe('partial');
  });
  test('trackers-maybe-ungated moderate finding (NOT trackers-before-consent)', () => {
    expect(finding(res, 'trackers-maybe-ungated')).toBeDefined();
    expect(finding(res, 'trackers-maybe-ungated')?.severity).toBe('moderate');
    expect(finding(res, 'trackers-before-consent')).toBeUndefined();
  });
  test('Consent Mode detected in summary', () => {
    expect(res.summary.consentMode).not.toBeNull();
  });
  test('no critical finding', () => {
    expect(res.findings.some((f) => f.severity === 'critical')).toBe(false);
  });
});

// ===========================================================================
// 4. GA on the network with NO consent management -> non-compliant
// ===========================================================================
describe('4. GA on the network without consent management', () => {
  const scan = makeScan({
    links: POLICY_LINKS,
    cookies: [],
    network: [{ url: 'https://www.google-analytics.com/collect', type: 'image' }],
  });
  const res = buildResult(scan);

  test('non-compliant verdict (certain tracker, no consent management)', () => {
    expect(res.verdict).toBe('non-compliant');
  });
  test('trackers-before-consent critical finding', () => {
    expect(finding(res, 'trackers-before-consent')?.severity).toBe('critical');
  });
  test('no-cmp serious finding (no consent dialog)', () => {
    expect(finding(res, 'no-cmp')?.severity).toBe('serious');
  });
});

// ===========================================================================
// 5. Matomo / Plausible (exempt) even pre-consent -> do NOT count
// ===========================================================================
describe('5. Matomo/Plausible exempt pre-consent', () => {
  test('Matomo on the network pre-consent -> compliant', () => {
    const scan = makeScan({
      links: POLICY_LINKS,
      network: [{ url: 'https://stats.example.com/matomo/matomo.js', type: 'script' }],
    });
    const res = buildResult(scan);
    expect(res.verdict).toBe('compliant');
    expect(res.summary.trackers).toEqual([]);
    expect(finding(res, 'trackers-before-consent')).toBeUndefined();
  });

  test('Plausible on the network pre-consent -> compliant', () => {
    const scan = makeScan({
      links: POLICY_LINKS,
      network: [{ url: 'https://plausible.io/js/script.js', type: 'script' }],
    });
    const res = buildResult(scan);
    expect(res.verdict).toBe('compliant');
    expect(res.summary.trackers).toEqual([]);
  });

  test('detectTrackers does not list the exempt ones', () => {
    const scan = makeScan({
      network: [
        { url: 'https://plausible.io/js/script.js', type: 'script' },
        { url: 'https://cdn.example.com/matomo.js', type: 'script' },
      ],
    });
    const tr = detectTrackers(scan);
    expect(tr.trackers).toEqual([]);
  });
});

// ===========================================================================
// 6. Google Fonts CDN -> google-fonts-cdn finding (partial)
// ===========================================================================
describe('6. Google Fonts from the CDN', () => {
  const scan = makeScan({
    links: POLICY_LINKS,
    network: [{ url: 'https://fonts.googleapis.com/css2?family=Poppins', type: 'stylesheet' }],
  });
  const res = buildResult(scan);

  test('detectGoogleFonts.found true', () => {
    expect(detectGoogleFonts(scan).found).toBe(true);
  });
  test('google-fonts-cdn moderate finding', () => {
    expect(finding(res, 'google-fonts-cdn')?.severity).toBe('moderate');
  });
  test('partial verdict (moderate only, no critical)', () => {
    expect(res.verdict).toBe('partial');
    expect(res.summary.googleFonts).toBe(true);
  });
  test('Google Fonts is NOT classified as a tracker', () => {
    // gstatic/googleapis fonts have a dedicated check, they do not end up among the trackers.
    expect(detectTrackers(scan).trackers).toEqual([]);
  });
});

// ===========================================================================
// 7. Empty page (links:[], short html) -> scanned:false
// ===========================================================================
describe('7. empty page / not evaluable', () => {
  const scan = makeScan({
    reachable: true,
    html: '<html><body></body></html>', // short
    links: [],
    network: [],
  });
  const res = buildResult(scan);

  test('scanned false, verdict null', () => {
    expect(res.scanned).toBe(false);
    expect(res.verdict).toBeNull();
  });
  test('no findings and empty summary', () => {
    expect(res.findings).toEqual([]);
    expect(res.summary.privacyPolicy).toBe(false);
  });
  test('error empty-or-blocked', () => {
    expect(res.error).toBe('empty-or-blocked');
  });
});

// ===========================================================================
// 8. reachable:false -> scanned:false
// ===========================================================================
describe('8. reachable false', () => {
  const scan = makeScan({
    reachable: false,
    html: '',
    links: [],
    error: 'navigation-failed',
  });
  const res = buildResult(scan);

  test('scanned false, verdict null', () => {
    expect(res.scanned).toBe(false);
    expect(res.verdict).toBeNull();
  });
  test('error propagated from the scan', () => {
    expect(res.error).toBe('navigation-failed');
  });
  test('a long page with reachable:false stays not evaluable', () => {
    // even with substantial html, if reachable=false -> scanned:false
    const s2 = makeScan({ reachable: false, html: 'x'.repeat(5000), links: POLICY_LINKS });
    expect(buildResult(s2).scanned).toBe(false);
  });
});

// ===========================================================================
// 9. Custom banner: real class detected; cookie link/text must NOT be a false positive
// ===========================================================================
describe('9. custom banner vs false positive on cookie link/text', () => {
  test('class="site-cookie-banner" detected as a custom CMP', () => {
    const scan = makeScan({
      html: '<html><body><div class="site-cookie-banner">Usiamo cookie</div></body></html>',
    });
    const cmp = detectCmp(scan);
    expect(cmp.id).toBe('custom');
    expect(cmp.name).toBe(CUSTOM_CMP);
  });

  test('href="/cookie-consent-guide" must NOT be detected as a banner', () => {
    // Link to a guide that TALKS about cookie consent: it is not a banner -> no CMP.
    const scan = makeScan({
      html: '<html><body><a href="/cookie-consent-guide">Guida al cookie consent</a></body></html>',
      links: [{ href: '/cookie-consent-guide', text: 'Guida al cookie consent' }, ...POLICY_LINKS],
    });
    const cmp = detectCmp(scan);
    expect(cmp.id).toBeNull();
    expect(cmp.name).toBeNull();
  });

  test('"cookieconsent" text in the body (not in id/class) must NOT be detected as a banner', () => {
    const scan = makeScan({
      html: '<html><body><p>Per saperne di più cerca cookieconsent online.</p></body></html>',
    });
    const cmp = detectCmp(scan);
    expect(cmp.id).toBeNull();
  });

  test('id="cookieconsent" (real attribute) instead YES -> custom banner', () => {
    // counter-check: the same token inside a real id attribute must trigger the custom banner.
    const scan = makeScan({
      html: '<html><body><div id="cookieconsent">...</div></body></html>',
    });
    expect(detectCmp(scan).id).toBe('custom');
  });
});

// ===========================================================================
// 10. Known CMP Iubenda (host/global/cookie); "onetrust" in a link does NOT trigger OneTrust
// ===========================================================================
describe('10. detectCmp recognizes Iubenda; onetrust in a link does not count', () => {
  test('Iubenda from host cdn.iubenda.com', () => {
    const scan = makeScan({ network: [{ url: 'https://cdn.iubenda.com/cs/iubenda_cs.js', type: 'script' }] });
    expect(detectCmp(scan).id).toBe('iubenda');
    expect(detectCmp(scan).name).toBe('Iubenda');
  });

  test('Iubenda from global _iub', () => {
    const scan = makeScan({ globals: { cmpGlobals: ['_iub'] } });
    expect(detectCmp(scan).id).toBe('iubenda');
  });

  test('Iubenda from cookie _iub_cs', () => {
    const scan = makeScan({ cookies: [{ name: '_iub_cs', domain: 'example.com' }] });
    expect(detectCmp(scan).id).toBe('iubenda');
  });

  test('"onetrust" inside an href must NOT trigger OneTrust', () => {
    const scan = makeScan({
      html: '<html><body><a href="https://example.com/onetrust-info">OneTrust info</a></body></html>',
      links: [{ href: 'https://example.com/onetrust-info', text: 'OneTrust info' }],
    });
    const cmp = detectCmp(scan);
    expect(cmp.id).toBeNull(); // no CMP: the token is in a link, not in id/class
  });

  test('OneTrust YES if the selector is in a real id/class', () => {
    // counter-check: the known selector #onetrust-banner-sdk in the markup triggers OneTrust.
    const scan = makeScan({
      html: '<html><body><div id="onetrust-banner-sdk">...</div></body></html>',
    });
    expect(detectCmp(scan).id).toBe('onetrust');
  });

  test('window.__tcfapi present -> generic IAB TCF CMP (no known name)', () => {
    // An IAB TCF compliant CMP that is not among the known ones by name: we recognize it as "present".
    const scan = makeScan({ globals: { hasTcfApi: true } });
    expect(detectCmp(scan).id).toBe('tcf');
    expect(detectCmp(scan).name).toBe('IAB TCF');
  });

  test('a known CMP takes priority over generic TCF', () => {
    // Iubenda (host) + __tcfapi: Iubenda must win, not the generic fallback.
    const scan = makeScan({
      network: [{ url: 'https://cdn.iubenda.com/cs/iubenda_cs.js', type: 'script' }],
      globals: { hasTcfApi: true },
    });
    expect(detectCmp(scan).id).toBe('iubenda');
  });
});

// ===========================================================================
// 11. Consent Mode: gcs=G100/G111 -> present; dataLayer tuple -> present;
//     {consent:'default'} (object) -> NOT a false positive
// ===========================================================================
describe('11. detectConsentMode', () => {
  test('gcs=G100 on the network -> present', () => {
    const scan = makeScan({
      network: [{ url: 'https://www.google-analytics.com/g/collect?gcs=G100&v=2', type: 'image' }],
    });
    const cm = detectConsentMode(scan);
    expect(cm.present).toBe(true);
  });

  test('dataLayer ["consent","default",{...}] -> present', () => {
    const scan = makeScan({
      globals: { dataLayer: [['consent', 'default', { analytics_storage: 'denied' }]] },
    });
    const cm = detectConsentMode(scan);
    expect(cm.present).toBe(true);
  });

  test('dataLayer {consent:"default"} (object) -> must NOT give a false positive', () => {
    const scan = makeScan({
      globals: { dataLayer: [{ consent: 'default', foo: 'bar' }] },
    });
    const cm = detectConsentMode(scan);
    expect(cm.present).toBe(false);
    expect(cm.version).toBeNull();
  });

  test('gcs=G111 (all granted) -> present', () => {
    const scan = makeScan({
      network: [{ url: 'https://www.google-analytics.com/g/collect?gcs=G111', type: 'image' }],
    });
    const cm = detectConsentMode(scan);
    expect(cm.present).toBe(true);
  });

  test('gcd on the network -> Consent Mode v2', () => {
    const scan = makeScan({
      network: [{ url: 'https://www.google-analytics.com/g/collect?gcd=11t1t1t1t5', type: 'image' }],
    });
    const cm = detectConsentMode(scan);
    expect(cm.present).toBe(true);
    expect(cm.version).toBe('v2');
  });

  test('a non-empty dataLayer alone is not a Google tag: no no-consent-mode finding', () => {
    const scan = makeScan({ links: POLICY_LINKS, globals: { dataLayer: [['config', 'G-XXX']] } });
    const cm = detectConsentMode(scan);
    expect(cm.hasGoogleTag).toBe(false);
    expect(cm.present).toBe(false);
    expect(finding(buildResult(scan), 'no-consent-mode')).toBeUndefined();
  });

  test('a request to a Google tag host without consent signals -> no-consent-mode minor', () => {
    const scan = makeScan({
      links: POLICY_LINKS,
      globals: { dataLayer: [['config', 'G-XXX']] },
      network: [{ url: 'https://www.googletagmanager.com/gtag/js?id=G-XXX', type: 'script' }],
    });
    expect(detectConsentMode(scan).hasGoogleTag).toBe(true);
    expect(finding(buildResult(scan), 'no-consent-mode')?.severity).toBe('minor');
  });

});

// ===========================================================================
// 11b. gcd: sent on every Google hit, so only a set signal proves Consent Mode
// ===========================================================================
describe('11b. gcd parameter', () => {
  const hit = (q: string) => ({ url: `https://www.google-analytics.com/g/collect?v=2&${q}&tid=G-1`, type: 'ping' });
  const cmFor = (...qs: string[]) => detectConsentMode(makeScan({ network: qs.map(hit) }));
  const result = (cm: ReturnType<typeof detectConsentMode>) => [cm.present, cm.version];

  test('all four signals "l" (not set with Consent Mode) -> not present', () => {
    expect(result(cmFor('gcd=11l1l1l1l5'))).toEqual([false, null]);
  });
  test('one "p" (denied by default): only analytics_storage set -> present, v1', () => {
    expect(result(cmFor('gcd=11l1p1l1l5'))).toEqual([true, 'v1']);
  });
  test('"r" and "v" (after an update) on all four signals -> present, v2', () => {
    expect(result(cmFor('gcd=11r1r1r1r5'))).toEqual([true, 'v2']);
    expect(result(cmFor('gcd=11v1v1v1v5'))).toEqual([true, 'v2']);
    expect(result(cmFor('gcd=11l1l1n1l5'))).toEqual([true, 'v2']); // ad_user_data granted after update
  });
  test('separator and closing digits of any value', () => {
    expect(result(cmFor('gcd=13p3p3p3p5'))).toEqual([true, 'v2']);
    expect(result(cmFor('gcd=10t7t2t9t0'))).toEqual([true, 'v2']);
    expect(result(cmFor('gcd=13l3l3l3l1'))).toEqual([false, null]);
  });
  test('a letter outside the documented table decides nothing', () => {
    expect(result(cmFor('gcd=11x1x1x1x5'))).toEqual([false, null]);
    expect(result(cmFor('gcd=11l1L1z1l5'))).toEqual([false, null]);
    expect(result(cmFor('gcd=11x1p1l1l5'))).toEqual([true, 'v1']); // the "p" still counts
  });
  test('garbage or a missing value decides nothing', () => {
    for (const q of ['gcd=', 'gcd=abc', 'gcd=11p', 'gcd=11p1p1p1p1p1p5', 'gcd=p1p1p1p5', 'gcd=11%70%31p1p1p5', 'gcd=11p1p1p1p5x']) {
      expect([q, ...result(cmFor(q))]).toEqual([q, false, null]);
    }
  });
  test('gcs on a hit whose gcd has all four signals "l" proves nothing', () => {
    expect(result(cmFor('gcd=13l3l3l3l1&gcs=G111'))).toEqual([false, null]);
    expect(result(cmFor('gcs=G111&gcd=11l1l1l1l5'))).toEqual([false, null]);
  });
  test('an empty gcs proves nothing', () => {
    expect(result(cmFor('gcs='))).toEqual([false, null]);
    expect(result(cmFor('gcs=&gcd=garbage'))).toEqual([false, null]);
  });
  test('gcs counts on a hit with no gcd, or with an unparseable one', () => {
    expect(result(cmFor('gcs=G100'))).toEqual([true, 'v1']);
    expect(result(cmFor('gcd=garbage&gcs=G100'))).toEqual([true, 'v1']);
  });
  test('a gcd with a fifth segment is ignored whole; gcs on the same hit then counts', () => {
    expect(result(cmFor('gcd=13r3r3r3r5l1'))).toEqual([false, null]);
    expect(result(cmFor('gcd=13l3l3l3l1l1&gcs=G100'))).toEqual([true, 'v1']);
  });
  test('an unparseable gcd falls back to the other evidence', () => {
    expect(result(cmFor('gcd=garbage', 'gcs=G100'))).toEqual([true, 'v1']);
    const withCommand = detectConsentMode(
      makeScan({ network: [hit('gcd=garbage')], globals: { dataLayer: [['consent', 'default', { ad_storage: 'denied' }]] } }),
    );
    expect(result(withCommand)).toEqual([true, 'v1']);
  });
  test('a Google tag with only an all-"l" gcd and no other evidence -> no-consent-mode', () => {
    const res = buildResult(makeScan({ links: POLICY_LINKS, network: [hit('gcd=11l1l1l1l5')] }));
    expect(finding(res, 'no-consent-mode')?.severity).toBe('minor');
    expect(res.summary.consentMode).toBeNull();
  });
});

// ===========================================================================
// 12. cookieVendors / classifyCookieName: known trackers recognized, technical cookies not
// ===========================================================================
describe('12. cookieVendors recognizes trackers, not technical cookies', () => {
  test('_ga / _fbp / _hjSession recognized', () => {
    expect(classifyCookieName('_ga')).not.toBeNull();
    expect(classifyCookieName('_ga_ABC123')).not.toBeNull(); // prefix match
    expect(classifyCookieName('_fbp')).not.toBeNull();
    expect(classifyCookieName('_hjSession_123')).not.toBeNull(); // prefix match
  });

  test('technical cookie PHPSESSID NOT recognized', () => {
    expect(classifyCookieName('PHPSESSID')).toBeNull();
  });

  test('other common technical cookies NOT recognized', () => {
    expect(classifyCookieName('csrftoken')).toBeNull();
    expect(classifyCookieName('session_id')).toBeNull();
    expect(classifyCookieName('XSRF-TOKEN')).toBeNull();
    expect(classifyCookieName('')).toBeNull();
  });

  test('cookieVendors aggregates unique vendors', () => {
    const scan = makeScan({
      cookies: [
        { name: '_ga', domain: 'example.com' },
        { name: '_ga_ABC', domain: 'example.com' },
        { name: '_fbp', domain: 'example.com' },
        { name: 'PHPSESSID', domain: 'example.com' }, // ignored
      ],
    });
    const vendors = cookieVendors(scan.cookies);
    expect(vendors).toContain('Google Analytics');
    expect(vendors).toContain('Meta Pixel');
    // Google Analytics appears only once even with two _ga cookies.
    expect(vendors.filter((v) => v === 'Google Analytics').length).toBe(1);
  });
});

// ===========================================================================
// 13. Expanded trackers/cookies: Adobe, Criteo, Yandex, Taboola, Quantcast
// ===========================================================================
describe('13. expanded trackers/cookies', () => {
  test('Yandex Metrica (host) -> tracker analytics', () => {
    const scan = makeScan({ network: [{ url: 'https://mc.yandex.ru/watch/12345', type: 'image' }] });
    expect(detectTrackers(scan).trackers.some((t) => t.name === 'Yandex Metrica')).toBe(true);
  });
  test('Criteo (host) -> tracker advertising', () => {
    const scan = makeScan({ network: [{ url: 'https://static.criteo.net/js/ld/ld.js', type: 'script' }] });
    expect(detectTrackers(scan).trackers.some((t) => t.name === 'Criteo')).toBe(true);
  });
  test('Adobe Analytics (omtrdc.net) -> tracker', () => {
    const scan = makeScan({ network: [{ url: 'https://example.sc.omtrdc.net/b/ss/x', type: 'image' }] });
    expect(detectTrackers(scan).trackers.some((t) => t.name === 'Adobe Analytics')).toBe(true);
  });
  test('Taboola (host) -> tracker', () => {
    const scan = makeScan({ network: [{ url: 'https://cdn.taboola.com/libtrc/unip/123/tfa.js', type: 'script' }] });
    expect(detectTrackers(scan).trackers.some((t) => t.name === 'Taboola')).toBe(true);
  });
  test('cookies __qca / cto_bundle / _ym_uid recognized', () => {
    expect(classifyCookieName('__qca')).not.toBeNull();
    expect(classifyCookieName('cto_bundle')).not.toBeNull();
    expect(classifyCookieName('_ym_uid')).not.toBeNull();
  });
  test('Criteo pre-consent without a CMP -> non-compliant', () => {
    const scan = makeScan({
      links: POLICY_LINKS,
      network: [{ url: 'https://static.criteo.net/js/ld/ld.js', type: 'script' }],
    });
    expect(buildResult(scan).verdict).toBe('non-compliant');
  });
});

// ===========================================================================
// Extra: multilingual detectPolicies (privacy/cookie from href or text)
// ===========================================================================
describe('extra. detectPolicies', () => {
  test('privacy + cookie from href', () => {
    const scan = makeScan({ links: POLICY_LINKS });
    const pol = detectPolicies(scan);
    expect(pol.hasPrivacy).toBe(true);
    expect(pol.hasCookie).toBe(true);
  });

  test('multilingual privacy (datenschutz / informativa)', () => {
    const scan = makeScan({
      links: [
        { href: '/datenschutz', text: 'Datenschutz' },
        { href: '/note-legali', text: 'Informativa privacy' },
      ],
    });
    expect(detectPolicies(scan).hasPrivacy).toBe(true);
  });

  test('no policy link -> false', () => {
    const scan = makeScan({ links: [{ href: '/', text: 'Home' }] });
    const pol = detectPolicies(scan);
    expect(pol.hasPrivacy).toBe(false);
    expect(pol.hasCookie).toBe(false);
  });

  test('buildResult: privacy missing -> no-privacy-policy serious finding', () => {
    const scan = makeScan({ links: [{ href: '/', text: 'Home' }, { href: '/a', text: 'A' }, { href: '/b', text: 'B' }] });
    const res = buildResult(scan);
    expect(finding(res, 'no-privacy-policy')?.severity).toBe('serious');
  });
});

// ---------------------------------------------------------------------------
// Tier A: banner UX + pre-ticked checkboxes + poor privacy notice
// ---------------------------------------------------------------------------
describe('Tier A: banner UX / pre-ticked / privacy notice', () => {
  const POLICY = [
    { href: 'https://example.com/privacy', text: 'Privacy policy' },
    { href: 'https://example.com/cookie', text: 'Cookie policy' },
    { href: 'https://example.com/x', text: 'X' },
  ];

  test('banner with Accept but no reject or X, known CMP -> banner-no-reject serious', () => {
    const scan = makeScan({
      links: POLICY,
      globals: { cmpGlobals: ['_iub'] },
      banner: { found: true, accept: true, reject: false, close: false, settings: false, unknown: 0, policyLink: true },
    });
    const res = buildResult(scan);
    expect(finding(res, 'banner-no-reject')?.severity).toBe('serious');
    expect(res.verdict).toBe('partial');
  });

  test('banner with reject at the first level -> NO banner-no-reject', () => {
    const scan = makeScan({
      links: POLICY,
      banner: { found: true, accept: true, reject: true, close: false, settings: false, unknown: 0, policyLink: true },
    });
    expect(finding(buildResult(scan), 'banner-no-reject')).toBeUndefined();
  });

  test('banner with only an X -> NO banner-no-reject (X = continue without consent, guidelines s.7.1)', () => {
    const scan = makeScan({
      links: POLICY,
      banner: { found: true, accept: true, reject: false, close: true, settings: false, unknown: 0, policyLink: true },
    });
    expect(finding(buildResult(scan), 'banner-no-reject')).toBeUndefined();
  });

  test('banner without a notice link -> banner-no-policy-link minor', () => {
    const scan = makeScan({
      links: POLICY,
      banner: { found: true, accept: true, reject: true, close: false, settings: false, unknown: 0, policyLink: false },
    });
    expect(finding(buildResult(scan), 'banner-no-policy-link')?.severity).toBe('minor');
  });

  test('no banner observed -> no banner finding', () => {
    const scan = makeScan({ links: POLICY }); // banner undefined
    const res = buildResult(scan);
    expect(finding(res, 'banner-no-reject')).toBeUndefined();
    expect(finding(res, 'banner-no-policy-link')).toBeUndefined();
  });

  test('pre-ticked consent checkboxes -> preticked-consent serious with count/sample', () => {
    const scan = makeScan({ links: POLICY, preticked: { count: 2, sample: 'Acconsento al marketing' } });
    const f = finding(buildResult(scan), 'preticked-consent');
    expect(f?.severity).toBe('serious');
    expect(f?.data?.count).toBe(2);
  });

  test('zero pre-ticked -> no finding', () => {
    const scan = makeScan({ links: POLICY, preticked: { count: 0, sample: '' } });
    expect(finding(buildResult(scan), 'preticked-consent')).toBeUndefined();
  });

  test('notice with >=3 missing elements -> privacy-policy-incomplete moderate', () => {
    const scan = makeScan({ links: POLICY });
    const res = buildResult(scan, { checked: true, missing: ['titolare', 'base-giuridica', 'reclamo'] });
    const f = finding(res, 'privacy-policy-incomplete');
    expect(f?.severity).toBe('moderate');
    expect(String(f?.data?.missing)).toContain('titolare');
  });

  test('notice with only 2 missing OR not read -> no finding (conservative)', () => {
    const scan = makeScan({ links: POLICY });
    expect(finding(buildResult(scan, { checked: true, missing: ['titolare', 'reclamo'] }), 'privacy-policy-incomplete')).toBeUndefined();
    expect(finding(buildResult(scan, { checked: false, missing: [] }), 'privacy-policy-incomplete')).toBeUndefined();
  });

  const page = (lang: string) => '<!doctype html><html lang="' + lang + '"><body>' + 'contenuto della pagina. '.repeat(150) + '</body></html>';
  const FOUR_MISSING = { checked: true, missing: ['titolare', 'finalita', 'reclamo', 'conservazione'] };

  test('German page whose notice came back checked with four missing keys -> no finding', () => {
    const res = buildResult(makeScan({ links: POLICY, html: page('de') }), FOUR_MISSING);
    expect(finding(res, 'privacy-policy-incomplete')).toBeUndefined();
  });

  test('Italian, English or Spanish page with the same notice result -> finding', () => {
    for (const lang of ['it', 'it-IT', 'en-GB', 'es']) {
      const res = buildResult(makeScan({ links: POLICY, html: page(lang) }), FOUR_MISSING);
      expect([lang, finding(res, 'privacy-policy-incomplete')?.severity]).toEqual([lang, 'moderate']);
    }
  });
});

// ---------------------------------------------------------------------------
// Tier B stateful: scroll test + reject test (evidence = cookie diff only)
// ---------------------------------------------------------------------------
describe('Tier B: scroll / reject / banner reappearance', () => {
  const POLICY = [
    { href: 'https://example.com/privacy', text: 'Privacy policy' },
    { href: 'https://example.com/cookie', text: 'Cookie policy' },
    { href: 'https://example.com/x', text: 'X' },
  ];
  const BANNER_OK = { found: true, accept: true, reject: true, close: false, settings: false, unknown: 0, policyLink: true };

  test('_ga cookie appeared after scroll -> scroll-activates-trackers serious', () => {
    const scan = makeScan({
      links: POLICY,
      banner: BANNER_OK,
      phase2: { scroll: { newCookies: [{ name: '_ga', domain: '.example.com' }] } },
    });
    const f = finding(buildResult(scan), 'scroll-activates-trackers');
    expect(f?.severity).toBe('serious');
    expect(String(f?.data?.vendors)).toContain('Google Analytics');
  });

  test('technical/unknown cookie after scroll -> NO finding (conservative)', () => {
    const scan = makeScan({
      links: POLICY,
      banner: BANNER_OK,
      phase2: { scroll: { newCookies: [{ name: 'sessionid', domain: 'example.com' }] } },
    });
    expect(finding(buildResult(scan), 'scroll-activates-trackers')).toBeUndefined();
  });

  test('_fbp cookie after the rejection (clean click) -> trackers-after-reject critical + non-compliant', () => {
    const scan = makeScan({
      links: POLICY,
      banner: BANNER_OK,
      phase2: {
        scroll: { newCookies: [] },
        reject: { clicked: true, bannerGone: true, newCookies: [{ name: '_fbp', domain: '.example.com' }], reloaded: true, bannerReappeared: false },
      },
    });
    const res = buildResult(scan);
    expect(finding(res, 'trackers-after-reject')?.severity).toBe('critical');
    expect(res.verdict).toBe('non-compliant');
  });

  test('ambiguous click (banner did NOT disappear) -> no post-reject judgment', () => {
    const scan = makeScan({
      links: POLICY,
      banner: BANNER_OK,
      phase2: {
        scroll: { newCookies: [] },
        reject: { clicked: true, bannerGone: false, newCookies: [{ name: '_fbp', domain: '.example.com' }], reloaded: true, bannerReappeared: true },
      },
    });
    const res = buildResult(scan);
    expect(finding(res, 'trackers-after-reject')).toBeUndefined();
    expect(finding(res, 'banner-reappears-after-reject')).toBeUndefined();
  });

  test('banner reappears on reload after the rejection -> banner-reappears-after-reject moderate', () => {
    const scan = makeScan({
      links: POLICY,
      banner: BANNER_OK,
      phase2: {
        scroll: { newCookies: [] },
        reject: { clicked: true, bannerGone: true, newCookies: [], reloaded: true, bannerReappeared: true },
      },
    });
    expect(finding(buildResult(scan), 'banner-reappears-after-reject')?.severity).toBe('moderate');
  });

  test('reload failed (reloaded false) -> no judgment on reappearance', () => {
    const scan = makeScan({
      links: POLICY,
      banner: BANNER_OK,
      phase2: {
        scroll: { newCookies: [] },
        reject: { clicked: true, bannerGone: true, newCookies: [], reloaded: false, bannerReappeared: true },
      },
    });
    expect(finding(buildResult(scan), 'banner-reappears-after-reject')).toBeUndefined();
  });

  test('scan without phase2 (time budget exhausted) -> no Tier B finding', () => {
    const scan = makeScan({ links: POLICY, banner: BANNER_OK });
    const res = buildResult(scan);
    expect(finding(res, 'scroll-activates-trackers')).toBeUndefined();
    expect(finding(res, 'trackers-after-reject')).toBeUndefined();
    expect(finding(res, 'banner-reappears-after-reject')).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// banner-no-reject: raised only when the banner is fully understood and there is something to refuse
// ---------------------------------------------------------------------------
describe('banner-no-reject: doubt and nothing to refuse mean no finding', () => {
  const POLICY = [
    { href: 'https://example.com/privacy', text: 'Privacy policy' },
    { href: 'https://example.com/cookie', text: 'Cookie policy' },
    { href: 'https://example.com/x', text: 'X' },
  ];
  const ONLY_ACCEPT = { found: true, accept: true, reject: false, close: false, settings: false, unknown: 0, policyLink: true };

  test('"Ho capito" notice banner on a site with no tracker, no cookie and no consent platform -> no finding', () => {
    const res = buildResult(makeScan({ links: POLICY, banner: ONLY_ACCEPT }));
    expect(finding(res, 'banner-no-reject')).toBeUndefined();
    expect(res.verdict).toBe('compliant');
  });

  test('a home-made banner alone is not something to refuse', () => {
    const scan = makeScan({
      links: POLICY,
      html: '<html lang="it"><body><div class="site-cookie-banner">Usiamo cookie</div>' + 'contenuto. '.repeat(300) + '</body></html>',
      banner: ONLY_ACCEPT,
    });
    expect(detectCmp(scan).id).toBe('custom');
    expect(finding(buildResult(scan), 'banner-no-reject')).toBeUndefined();
  });

  test('a tracker cookie seen -> finding', () => {
    const res = buildResult(makeScan({ links: POLICY, cookies: [{ name: '_ga', domain: 'example.com' }], banner: ONLY_ACCEPT }));
    expect(finding(res, 'banner-no-reject')?.severity).toBe('serious');
  });

  test('a network tracker seen (consent platform present) -> finding', () => {
    const res = buildResult(
      makeScan({
        links: POLICY,
        globals: { cmpGlobals: ['Cookiebot'] },
        network: [{ url: 'https://connect.facebook.net/en_US/fbevents.js', type: 'script' }],
        banner: ONLY_ACCEPT,
      }),
    );
    expect(finding(res, 'banner-no-reject')?.severity).toBe('serious');
  });

  test('an IAB TCF API counts as a known consent platform', () => {
    const res = buildResult(makeScan({ links: POLICY, globals: { hasTcfApi: true }, banner: ONLY_ACCEPT }));
    expect(finding(res, 'banner-no-reject')).toBeDefined();
  });

  test('one control the patterns do not know -> doubt, no finding', () => {
    const res = buildResult(
      makeScan({ links: POLICY, cookies: [{ name: '_ga', domain: 'example.com' }], banner: { ...ONLY_ACCEPT, unknown: 1 } }),
    );
    expect(finding(res, 'banner-no-reject')).toBeUndefined();
    expect(finding(res, 'trackers-before-consent')).toBeDefined(); // the other findings stand
  });

  test('"Accept / Manage preferences": a settings control is not a first-level reject -> finding', () => {
    const res = buildResult(makeScan({ links: POLICY, globals: { cmpGlobals: ['_iub'] }, banner: { ...ONLY_ACCEPT, settings: true } }));
    expect(finding(res, 'banner-no-reject')?.severity).toBe('serious');
  });

  for (const [cookie, cmp] of [
    ['CookieConsentShown', 'Cookiebot'],
    ['usercentrics_lang', 'Usercentrics'],
    ['euconsent-v2-backup', 'Iubenda'],
  ]) {
    test(`a platform credited only from the site cookie "${cookie}" never raises banner-no-reject`, () => {
      const res = buildResult(makeScan({ links: POLICY, cookies: [{ name: cookie, domain: 'example.com' }], banner: ONLY_ACCEPT }));
      expect(finding(res, 'banner-no-reject')).toBeUndefined();
      expect(res.summary.cmp).toBe(cmp); // the summary still names it
      expect(detectCmp(makeScan({ cookies: [{ name: cookie, domain: 'example.com' }] })).evidence).toBe('cookie');
    });
  }

  test('a cookie-only platform may still lower a severity: request-only tracker is moderate, no no-cmp', () => {
    const res = buildResult(
      makeScan({
        links: POLICY,
        cookies: [{ name: 'CookieConsentShown', domain: 'example.com' }],
        network: [{ url: 'https://connect.facebook.net/en_US/fbevents.js', type: 'script' }],
      }),
    );
    expect(finding(res, 'trackers-maybe-ungated')?.severity).toBe('moderate');
    expect(finding(res, 'trackers-before-consent')).toBeUndefined();
    expect(finding(res, 'no-cmp')).toBeUndefined();
  });

  test('the same cookie with the platform host, global or markup -> finding', () => {
    const cookies = [{ name: 'CookieConsentShown', domain: 'example.com' }];
    const cases: Array<[CmpEvidence, ScanOverride]> = [
      ['host', { network: [{ url: 'https://consent.cookiebot.com/uc.js', type: 'script' }] }],
      ['global', { globals: { cmpGlobals: ['Cookiebot'] } }],
      ['selector', { html: '<html><body><div id="CybotCookiebotDialog">Cookie</div>' + 'contenuto. '.repeat(300) + '</body></html>' }],
    ];
    for (const [expected, extra] of cases) {
      const scan = makeScan({ links: POLICY, cookies, banner: ONLY_ACCEPT, ...extra });
      expect([detectCmp(scan).evidence, finding(buildResult(scan), 'banner-no-reject')?.severity]).toEqual([expected, 'serious']);
    }
  });

  test('an IAB TCF API is stronger evidence than a cookie name of a listed platform', () => {
    const cmp = detectCmp(makeScan({ cookies: [{ name: 'euconsent-v2', domain: 'example.com' }], globals: { hasTcfApi: true } }));
    expect([cmp.id, cmp.evidence]).toEqual(['tcf', 'tcf']);
  });

  test('a settings control is itself something to refuse: home-made banner, nothing seen -> finding', () => {
    const scan = makeScan({
      links: POLICY,
      html: '<html lang="it"><body><div class="site-cookie-banner">Usiamo cookie</div>' + 'contenuto. '.repeat(300) + '</body></html>',
      banner: { ...ONLY_ACCEPT, settings: true },
    });
    expect(detectCmp(scan).id).toBe('custom');
    expect(finding(buildResult(scan), 'banner-no-reject')?.severity).toBe('serious');
  });
});

// ---------------------------------------------------------------------------
// Pages that cannot be judged: error status, not HTML, no navigation
// ---------------------------------------------------------------------------
describe('pages that get no verdict, or no policy-link findings', () => {
  const challenge =
    '<html><head><title>Just a moment...</title><script>' +
    'window._cf_chl_opt={cvId:"3",cType:"managed"};'.repeat(80) +
    '</script></head><body><h1>Checking your browser</h1></body></html>';

  test('403 challenge page with substantial html -> scanned false, empty-or-blocked', () => {
    const res = buildResult(makeScan({ status: 403, html: challenge, links: [] }));
    expect(res.scanned).toBe(false);
    expect(res.verdict).toBeNull();
    expect(res.error).toBe('empty-or-blocked');
    expect(res.findings).toEqual([]);
  });

  test('any status >= 400 gets no verdict, even with links and trackers', () => {
    for (const status of [400, 404, 429, 500, 503]) {
      const res = buildResult(makeScan({ status, links: POLICY_LINKS, cookies: [{ name: '_ga', domain: 'example.com' }] }));
      expect([status, res.scanned, res.error]).toEqual([status, false, 'empty-or-blocked']);
    }
  });

  test('a document that is not HTML gets no verdict', () => {
    for (const contentType of ['application/pdf', 'text/plain', 'image/png', 'application/json']) {
      const res = buildResult(makeScan({ contentType }));
      expect([contentType, res.scanned, res.error]).toEqual([contentType, false, 'empty-or-blocked']);
    }
  });

  test('text/html, application/xhtml+xml, empty or absent content type are judged', () => {
    for (const contentType of ['text/html', 'application/xhtml+xml', '', undefined]) {
      expect([contentType, buildResult(makeScan({ contentType })).scanned]).toEqual([contentType, true]);
    }
  });

  test('status 0 (unknown) is judged as before', () => {
    expect(buildResult(makeScan({ status: 0 })).scanned).toBe(true);
  });

  test('trackers and one link: judged, no policy findings, the other findings stand', () => {
    const res = buildResult(
      makeScan({
        links: [{ href: '/', text: 'Home' }],
        cookies: [{ name: '_ga', domain: 'example.com' }],
        network: [{ url: 'https://fonts.googleapis.com/css2?family=Inter', type: 'stylesheet' }],
      }),
    );
    expect(res.scanned).toBe(true);
    expect(finding(res, 'no-privacy-policy')).toBeUndefined();
    expect(finding(res, 'no-cookie-policy')).toBeUndefined();
    expect(finding(res, 'trackers-before-consent')).toBeDefined();
    expect(finding(res, 'google-fonts-cdn')).toBeDefined();
  });

  test('a tracker seen only in the requests, and two links: judged', () => {
    const res = buildResult(
      makeScan({ links: [{ href: '/', text: 'Home' }, { href: '#', text: 'Skip' }], network: [{ url: 'https://connect.facebook.net/en_US/fbevents.js', type: 'script' }] }),
    );
    expect(res.scanned).toBe(true);
    expect(finding(res, 'trackers-before-consent')).toBeDefined();
    expect(finding(res, 'no-privacy-policy')).toBeUndefined();
  });

  // A JavaScript challenge or an empty application shell: 200, text/html, kilobytes of script, no navigation.
  const shell =
    '<!doctype html><html><head><script>' + 'window.__chl={a:1,b:"managed"};'.repeat(120) + '</script></head><body><div id="root"></div></body></html>';
  for (const [name, links] of [
    ['0 links', []],
    ['1 link', [{ href: '/', text: 'Home' }]],
    ['2 links', [{ href: '/', text: 'Home' }, { href: '#', text: 'Skip' }]],
  ] as const) {
    test(`a long page with ${name} and nothing non-essential seen -> no verdict`, () => {
      for (const contentType of ['text/html', '']) {
        const res = buildResult(makeScan({ html: shell, links: [...links], contentType }));
        expect([contentType, res.scanned, res.verdict, res.error]).toEqual([contentType, false, null, 'empty-or-blocked']);
      }
    });
  }

  test('few links with only an exempt tool, a tag manager or Google Fonts -> no verdict', () => {
    for (const url of ['https://stats.example.com/matomo.js', 'https://www.googletagmanager.com/gtm.js?id=GTM-1', 'https://fonts.googleapis.com/css2?family=Inter']) {
      const res = buildResult(makeScan({ html: shell, links: [{ href: '/', text: 'Home' }], network: [{ url, type: 'script' }] }));
      expect([url, res.scanned, res.error]).toEqual([url, false, 'empty-or-blocked']);
    }
  });

  test('a tiny page with few links is still not evaluable, even with a tracker cookie', () => {
    const res = buildResult(makeScan({ html: '<html><body>Hi</body></html>', links: [{ href: '/', text: 'Home' }] }));
    expect(res.error).toBe('empty-or-blocked');
    const withCookie = buildResult(
      makeScan({ html: '<html><body>Hi</body></html>', links: [{ href: '/', text: 'Home' }], cookies: [{ name: '_ga', domain: 'example.com' }] }),
    );
    expect([withCookie.scanned, withCookie.error]).toEqual([false, 'empty-or-blocked']);
  });

  test('notScannedResult: no verdict, empty summary, the given error', () => {
    expect(notScannedResult('https://example.com/', 'daily-budget')).toEqual({
      scanned: false,
      verdict: null,
      score: 0,
      findings: [],
      summary: { trackers: [], tagManager: false, cmp: null, consentMode: null, googleFonts: false, privacyPolicy: false, cookiePolicy: false },
      finalUrl: 'https://example.com/',
      error: 'daily-budget',
    });
  });
});

// ---------------------------------------------------------------------------
// Policy links in other languages, and pages in a language the words do not cover
// ---------------------------------------------------------------------------
describe('policy links across languages', () => {
  const NAV = [
    { href: 'https://example.com/', text: 'Home' },
    { href: 'https://example.com/a', text: 'A' },
  ];
  const privacyLinks: Array<[lang: string, href: string, text: string]> = [
    ['fr', 'https://x.fr/politique-de-confidentialite', 'Politique de confidentialité'],
    ['fr', 'https://x.fr/mentions', 'Données personnelles'],
    ['fr', 'https://x.fr/donnees-personnelles', 'Vos données'],
    ['pl', 'https://x.pl/polityka-prywatnosci', 'Polityka prywatności'],
    ['sv', 'https://x.se/integritetspolicy', 'Integritetspolicy'],
    ['da', 'https://x.dk/privatlivspolitik', 'Privatlivspolitik'],
    ['nb', 'https://x.no/personvernerklaering', 'Personvernerklæring'],
    ['fi', 'https://x.fi/tietosuojaseloste', 'Tietosuojaseloste'],
    ['de', 'https://x.de/datenschutz', 'Datenschutzerklärung'],
    ['pt', 'https://x.pt/privacidade', 'Política de privacidade'],
  ];
  for (const [lang, href, text] of privacyLinks) {
    test(`${lang}: "${text}" is a privacy link, found by both detectPolicies and findPrivacyPolicyUrl`, () => {
      const scan = makeScan({ links: [...NAV, { href, text }] });
      expect(detectPolicies(scan).hasPrivacy).toBe(true);
      expect(findPrivacyPolicyUrl(scan)).toBe(href);
    });
  }

  test('cookie policy words: Swedish "kakor", Finnish "evästeet", Norwegian "informasjonskapsler", Polish "ciasteczka"', () => {
    for (const [href, text] of [
      ['https://x.se/om-kakor', 'Om kakor'],
      ['https://x.fi/evasteet', 'Evästeet'],
      ['https://x.no/informasjonskapsler', 'Informasjonskapsler'],
      ['https://x.pl/polityka-ciasteczek', 'Polityka ciasteczek'],
    ]) {
      expect([text, detectPolicies(makeScan({ links: [...NAV, { href, text }] })).hasCookie]).toEqual([text, true]);
    }
  });

  test('"kakor" and "ciasteczka" alone are cakes and biscuits, not a cookie policy', () => {
    for (const [href, text] of [
      ['https://x.se/kakor', 'Kakor och bakverk'],
      ['https://x.pl/ciasteczka', 'Ciasteczka maślane'],
    ]) {
      expect([text, detectPolicies(makeScan({ links: [...NAV, { href, text }] })).hasCookie]).toEqual([text, false]);
    }
  });

  test('a cookie policy link alone is not the privacy notice', () => {
    const scan = makeScan({ links: [...NAV, { href: 'https://example.com/cookie-policy', text: 'Cookie policy' }] });
    expect(findPrivacyPolicyUrl(scan)).toBeNull();
  });

  // Which page is read as the privacy notice: menus come before footers.
  const H = 'https://site.example.com';
  const at = (links: Array<[path: string, text: string]>) =>
    makeScan({ finalUrl: H + '/', requestedUrl: H + '/', links: links.map(([p, text]) => ({ href: p.startsWith('http') ? p : H + p, text })) });

  test('a weak word in a menu link does not beat the footer notice', () => {
    for (const [menuPath, menuText] of [
      ['/servizi/consulenza-gdpr', 'Consulenza GDPR'],
      ['/blog/nuova-privacy-di-whatsapp', 'La nuova privacy di WhatsApp'],
      ['/prodotti/scheda-informativa', 'Scheda informativa'],
      ['/legal/confidentiality-agreement', 'Confidentiality agreement'],
      ['/om-oss/integritet-och-kvalitet', 'Integritet och kvalitet'],
    ]) {
      const scan = at([['/', 'Home'], [menuPath, menuText], ['/contatti', 'Contatti'], ['/privacy-policy', 'Privacy Policy']]);
      expect([menuText, findPrivacyPolicyUrl(scan)]).toEqual([menuText, H + '/privacy-policy']);
      expect(detectPolicies(scan).hasPrivacy).toBe(true);
    }
  });

  test('weak words alone count for presence, but no page is read as the notice', () => {
    const scan = at([['/', 'Home'], ['/servizi/gdpr', 'Consulenza GDPR'], ['/legal/nda', 'Confidentiality agreement']]);
    expect(detectPolicies(scan).hasPrivacy).toBe(true);
    expect(findPrivacyPolicyUrl(scan)).toBeNull();
  });

  test('among strong links on the same host the last one wins, and the same host beats another host', () => {
    const scan = at([
      ['/informativa-privacy', 'Informativa privacy'],
      ['/', 'Home'],
      ['/privacy-policy', 'Privacy'],
      ['https://www.iubenda.com/privacy-policy/123', 'Privacy Policy'],
    ]);
    expect(findPrivacyPolicyUrl(scan)).toBe(H + '/privacy-policy');
    const offHost = at([['/', 'Home'], ['https://www.iubenda.com/privacy-policy/1', 'Privacy Policy'], ['https://legal.example.org/privacy-notice', 'Notice']]);
    expect(findPrivacyPolicyUrl(offHost)).toBe('https://legal.example.org/privacy-notice');
  });

  test('a whole link text "Privacy" or "Informativa" is strong, unless the link goes to a cookie page', () => {
    expect(findPrivacyPolicyUrl(at([['/', 'Home'], ['/note', 'Informativa']]))).toBe(H + '/note');
    expect(findPrivacyPolicyUrl(at([['/', 'Home'], ['/p', 'Privacy']]))).toBe(H + '/p');
    expect(findPrivacyPolicyUrl(at([['/', 'Home'], ['/cookie', 'Informativa']]))).toBeNull();
  });

  test('pageLanguage reads the primary subtag of <html lang>', () => {
    expect(pageLanguage('<!doctype html><html class="x" lang="de-AT"><body>')).toBe('de');
    expect(pageLanguage("<html xml:lang='CS'>")).toBe('cs');
    expect(pageLanguage('<html data-lang="fr"><body>')).toBe('');
    expect(pageLanguage('<html><body lang="fr">')).toBe('');
    expect(pageLanguage('<!-- x --><HTML LANG = " IT ">')).toBe('it');
    expect(pageLanguage('<html lang="english">')).toBe('');
    expect(pageLanguage('<htmlx lang="fr"><html lang="es">')).toBe('es');
  });

  test('pageLanguage is linear on hostile markup (each case under 50 ms)', () => {
    for (const html of [
      '<html lang=' + ' '.repeat(65_000),
      '<html lang =' + ' '.repeat(30_000) + '>',
      '<html ' + 'lang '.repeat(500),
      '<html' + (' lang' + ' '.repeat(60)).repeat(1000),
      '<htmlx'.repeat(10_000),
      '<html lang="' + ' '.repeat(200_000) + 'it">',
    ]) {
      const t0 = performance.now();
      pageLanguage(html);
      expect(performance.now() - t0).toBeLessThan(50);
    }
  });

  test('page in a language the words do not cover (Czech) -> no missing-policy findings', () => {
    const res = buildResult(
      makeScan({
        html: '<!doctype html><html lang="cs"><body>' + 'obsah stránky. '.repeat(300) + '</body></html>',
        links: [...NAV, { href: 'https://x.cz/ochrana-osobnich-udaju', text: 'Ochrana osobních údajů' }],
        cookies: [{ name: '_ga', domain: 'x.cz' }],
      }),
    );
    expect(finding(res, 'no-privacy-policy')).toBeUndefined();
    expect(finding(res, 'no-cookie-policy')).toBeUndefined();
    expect(finding(res, 'trackers-before-consent')).toBeDefined();
  });

  test('page in a covered language (Norwegian Nynorsk, nn) without links -> findings raised', () => {
    const res = buildResult(
      makeScan({
        html: '<!doctype html><html lang="nn"><body>' + 'innhald. '.repeat(400) + '</body></html>',
        links: [...NAV, { href: 'https://x.no/om', text: 'Om oss' }],
        cookies: [{ name: '_ga', domain: 'x.no' }],
      }),
    );
    expect(finding(res, 'no-privacy-policy')).toBeDefined();
    expect(finding(res, 'no-cookie-policy')).toBeDefined();
  });
});

describe('access control on POST /scan', () => {
  // BROWSER throws if touched, proving that a refused request never opens a browser.
  const browser = new Proxy({}, { get() { throw new Error('browser must not be used'); } });
  const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
  const SECRET = 's3cret-'.repeat(5); // 35 characters
  const kv = { get: async () => null, put: async () => {} };
  const call = (env: Record<string, unknown>, headers: Record<string, string> = {}, body = '{}') =>
    worker.fetch(
      new Request('https://scanner.test/scan', { method: 'POST', headers, body }),
      { BROWSER: browser, ...env } as never,
      ctx,
    );

  test('returns 503 and does not open the browser when SCANNER_SECRET is not configured', async () => {
    const res = await call({ SCAN_KV: kv }, { authorization: 'Bearer anything' }, '{"url":"https://example.com"}');
    expect(res.status).toBe(503);
    const data = (await res.json()) as { error: string; message: string };
    expect(data.error).toBe('not-configured');
    expect(data.message).toContain('SCANNER_SECRET');
  });

  test('returns 503 when SCANNER_SECRET is an empty string', async () => {
    expect((await call({ SCANNER_SECRET: '', SCAN_KV: kv })).status).toBe(503);
  });

  test('returns 503 when SCANNER_SECRET is shorter than 32 characters, even with the right token', async () => {
    const short = 'x'.repeat(31);
    const res = await call({ SCANNER_SECRET: short, SCAN_KV: kv }, { authorization: `Bearer ${short}` }, '{"url":"https://example.com"}');
    expect(res.status).toBe(503);
    expect(((await res.json()) as { message: string }).message).toContain('32');
    const ok = 'x'.repeat(32);
    expect((await call({ SCANNER_SECRET: ok, SCAN_KV: kv }, { authorization: `Bearer ${ok}` }, '{"url":""}')).status).toBe(400);
  });

  test('returns 503 and does not open the browser when SCAN_KV is not bound', async () => {
    const res = await call({ SCANNER_SECRET: SECRET }, { authorization: `Bearer ${SECRET}` }, '{"url":"https://example.com"}');
    expect(res.status).toBe(503);
    expect(((await res.json()) as { message: string }).message).toContain('SCAN_KV');
  });

  test('returns 401 with a wrong or missing secret', async () => {
    const body = '{"url":"https://example.com"}';
    expect((await call({ SCANNER_SECRET: SECRET, SCAN_KV: kv }, { authorization: 'Bearer nope' }, body)).status).toBe(401);
    expect((await call({ SCANNER_SECRET: SECRET, SCAN_KV: kv }, {}, body)).status).toBe(401);
    expect((await call({ SCANNER_SECRET: SECRET, SCAN_KV: kv }, { authorization: `Bearer ${SECRET}x` }, body)).status).toBe(401);
  });

  test('accepts the right secret with a KV binding (request reaches input validation, no browser needed)', async () => {
    const res = await call({ SCANNER_SECRET: SECRET, SCAN_KV: kv }, { authorization: `Bearer ${SECRET}` }, '{"url":""}');
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe('bad-url');
  });
});
