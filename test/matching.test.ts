// A request belongs to a vendor when its host is the vendor's host or a subdomain. These tests
// hold the cases where looking for a vendor name anywhere in the URL would accuse the wrong site.
import { test, expect, describe } from 'bun:test';
import type { RawScan } from '../src/types';
import { hostMatches, matchesHostRule, pathUnder, requestParts } from '../src/hosts';
import { classifyTrackerUrl } from '../data/tracker-hosts';
import { classifyCookieName, COOKIE_PATTERNS } from '../data/cookie-patterns';
import { detectCmp, detectConsentMode, detectGoogleFonts, detectTrackers } from '../src/detect';
import { buildResult } from '../src/verdict';

function makeScan(partial: Partial<RawScan> = {}): RawScan {
  return {
    requestedUrl: 'https://example.com',
    finalUrl: 'https://example.com',
    status: 200,
    reachable: true,
    html: '<!doctype html><html><body><main>' + 'real page content. '.repeat(200) + '</main></body></html>',
    links: [
      { href: 'https://example.com/', text: 'Home' },
      { href: 'https://example.com/privacy', text: 'Privacy Policy' },
      { href: 'https://example.com/cookie-policy', text: 'Cookie Policy' },
    ],
    network: [],
    cookies: [],
    globals: { dataLayer: [], googleTagDataEntries: null, hasTcfApi: false, cmpGlobals: [] },
    ...partial,
  };
}
const req = (url: string) => ({ url, type: 'script' });

describe('host and path rules', () => {
  test('hostMatches: the host itself and its subdomains, nothing that merely contains it', () => {
    expect(hostMatches('hotjar.com', 'hotjar.com')).toBe(true);
    expect(hostMatches('static.hotjar.com', 'hotjar.com')).toBe(true);
    expect(hostMatches('nothotjar.com', 'hotjar.com')).toBe(false);
    expect(hostMatches('hotjar.com.example.org', 'hotjar.com')).toBe(false);
  });
  test('pathUnder: a path segment, not a prefix of a longer word', () => {
    expect(pathUnder('/tr', '/tr')).toBe(true);
    expect(pathUnder('/tr/', '/tr')).toBe(true);
    expect(pathUnder('/tr/x', '/tr')).toBe(true);
    expect(pathUnder('/track', '/tr')).toBe(false);
    expect(pathUnder('/adsense', '/ads')).toBe(false);
  });
  test('matchesHostRule: host, host/path and one-host-per-country forms', () => {
    expect(matchesHostRule('google.com/ads', requestParts('https://www.google.com/ads/ga-audiences?v=1'))).toBe(true);
    expect(matchesHostRule('google.com/ads', requestParts('https://www.google.com/adsense/start'))).toBe(false);
    expect(matchesHostRule('google.com/ads', requestParts('https://www.google.com/recaptcha/api.js'))).toBe(false);
    expect(matchesHostRule('adservice.google.*', requestParts('https://adservice.google.it/adsid/integrator.js'))).toBe(true);
    expect(matchesHostRule('adservice.google.*', requestParts('https://adservice.google.com/x'))).toBe(true);
    expect(matchesHostRule('adservice.google.*', requestParts('https://notadservice.google.it/x'))).toBe(false);
    expect(matchesHostRule('hotjar.com', requestParts('not a url'))).toBe(false);
  });
  test('"label.vendor.*": the label starts the host and "*" is a country or generic ending', () => {
    for (const host of ['adservice.google.it', 'adservice.google.com', 'adservice.google.co.uk', 'adservice.google.com.br']) {
      expect([host, matchesHostRule('adservice.google.*', requestParts(`https://${host}/x.js`))]).toEqual([host, true]);
    }
    for (const host of [
      'adservice.google.evil.example', // somebody else's domain after the label
      'cdn.adservice.google.evil.example',
      'cdn.adservice.google.it', // the label must start the host
      'adservice.google.',
      'adservice.google.info.example',
      'adservice.google.c',
    ]) {
      expect([host, matchesHostRule('adservice.google.*', requestParts(`https://${host}/x.js`))]).toEqual([host, false]);
    }
  });
  test('requestParts drops the root dot and lowers the case', () => {
    expect(requestParts('https://Static.Hotjar.COM./C/x.js')).toEqual({ host: 'static.hotjar.com', path: '/c/x.js' });
    expect(requestParts('nonsense')).toEqual({ host: '', path: '/' });
  });
});

describe('classifyTrackerUrl: real trackers', () => {
  const real: Array<[url: string, name: string]> = [
    ['https://www.google-analytics.com/g/collect?v=2&tid=G-XXXX', 'Google Analytics'],
    ['https://region1.google-analytics.com/g/collect', 'Google Analytics'],
    ['https://www.googletagmanager.com/gtm.js?id=GTM-XXXX', 'Google Tag Manager'],
    ['https://www.facebook.com/tr/?id=1&ev=PageView', 'Meta Pixel'],
    ['https://www.facebook.com/tr?id=1&ev=PageView', 'Meta Pixel'],
    ['https://connect.facebook.net/en_US/fbevents.js', 'Meta (Pixel/SDK)'],
    ['https://static.hotjar.com/c/hotjar-123.js', 'Hotjar'],
    ['https://www.clarity.ms/tag/abcdef', 'Microsoft Clarity'],
    ['https://cdn.segment.com/analytics.js/v1/key/analytics.min.js', 'Segment'],
    ['https://adservice.google.it/adsid/integrator.js', 'Google Ads'],
    ['https://www.google.com/pagead/1p-user-list/123/', 'Google Ads'],
    ['https://stats.example.org/matomo.php?idsite=1', 'Matomo'],
    ['https://matomo.example.org/piwik.js', 'Matomo'],
    ['https://mc.yandex.ru/metrika/tag.js', 'Yandex Metrica'],
  ];
  for (const [url, name] of real) {
    test(url, () => expect(classifyTrackerUrl(url)?.name).toBe(name));
  }
});

describe('classifyTrackerUrl: look-alikes that must not be flagged', () => {
  const innocent: string[] = [
    'https://cheap.io/app.js', // contains "heap.io"
    'https://example.com/assets/customer-segment.common.js', // contains "segment.com"
    'https://example.com/img/hotjar.com-logo.png',
    'https://my-facebook.community/tr/pixel.gif', // "facebook.community" contains "facebook.com"
    'https://example.com/out?to=https://www.google-analytics.com/collect', // only in the query string
    'https://example.com/partners/criteo.com.html',
    'https://doubleclick.net.example.org/x.js',
    'https://www.facebook.com/tracking-policy', // facebook.com, but not the pixel endpoint
    'https://www.google.com/adsense/start/',
    'https://www.gstatic.com/recaptcha/releases/abc/recaptcha__en.js', // functional
    'https://js.stripe.com/v3/', // functional
    'https://cdn.jsdelivr.net/npm/matomo-tracker@1/index.js', // functional host, even with the word in the path
    'not a url',
    '',
  ];
  for (const url of innocent) {
    test(JSON.stringify(url), () => expect(classifyTrackerUrl(url)).toBeNull());
  }

  test('a clean site that only links to such URLs stays compliant', () => {
    const res = buildResult(makeScan({ network: innocent.filter(Boolean).map(req) }));
    expect(res.verdict).toBe('compliant');
    expect(res.summary.trackers).toEqual([]);
    expect(detectTrackers(makeScan({ network: innocent.filter(Boolean).map(req) })).trackers).toEqual([]);
  });
});

describe('classifyTrackerUrl: host rules come before keyword entries', () => {
  test('"matomo" in the path of a known vendor does not hide the vendor', () => {
    expect(classifyTrackerUrl('https://cdn.segment.com/next-integrations/integrations/matomo/2.0/matomo.js')?.name).toBe('Segment');
    expect(classifyTrackerUrl('https://static.criteo.net/js/matomo-bridge.js')?.name).toBe('Criteo');
    expect(classifyTrackerUrl('https://www.google-analytics.com/matomo')?.name).toBe('Google Analytics');
  });
  test('Segment loaded from a URL with "matomo" in the path, no consent platform -> non-compliant', () => {
    const res = buildResult(makeScan({ network: [req('https://cdn.segment.com/next-integrations/integrations/matomo/2.0/matomo.js')] }));
    expect(res.verdict).toBe('non-compliant');
    expect(res.summary.trackers).toEqual(['Segment']);
  });
  test('a self-hosted Matomo is still recognized (and exempt)', () => {
    const t = classifyTrackerUrl('https://stats.example.org/matomo.php?idsite=1');
    expect([t?.name, t?.exempt]).toEqual(['Matomo', true]);
  });
  test('a host that only looks like a country host of a vendor is not that vendor', () => {
    expect(classifyTrackerUrl('https://adservice.google.evil.example/x.js')).toBeNull();
    expect(classifyTrackerUrl('https://cdn.adservice.google.evil.example/x.js')).toBeNull();
  });
});

describe('consent platforms, fonts and Google tags are matched by host', () => {
  test('a CMP name in a query string or in a path is not a CMP', () => {
    for (const url of ['https://example.com/go?to=consent.cookiebot.com', 'https://example.com/blog/iubenda.com-review', 'https://cookiebot.eu.example.org/x.js']) {
      expect([url, detectCmp(makeScan({ network: [req(url)] })).id]).toEqual([url, null]);
    }
  });
  test('the real hosts are recognized, subdomains included', () => {
    expect(detectCmp(makeScan({ network: [req('https://consent.cookiebot.com/uc.js')] })).id).toBe('cookiebot');
    expect(detectCmp(makeScan({ network: [req('https://cdn.iubenda.com/cs/iubenda_cs.js')] })).id).toBe('iubenda');
    expect(detectCmp(makeScan({ network: [req('https://cdn.cookielaw.org/scripttemplates/otSDKStub.js')] })).id).toBe('onetrust');
  });
  test('an entry without a dot is a word: OneTrust older scripts are found by "optanon"', () => {
    expect(detectCmp(makeScan({ network: [req('https://optanon.blob.core.windows.net/consent/abc.js')] })).id).toBe('onetrust');
    for (const type of ['xhr', 'fetch']) {
      expect([type, detectCmp(makeScan({ network: [{ url: 'https://example.com/optanon/consent.json', type }] })).id]).toEqual([type, 'onetrust']);
    }
  });
  test('the word counts only on requests that load code, not on an image or a stylesheet', () => {
    for (const type of ['image', 'stylesheet', 'font', 'media', 'document', 'other']) {
      const scan = makeScan({ network: [{ url: 'https://victim.example/img/optanon-screenshot.png', type }] });
      expect([type, detectCmp(scan).id]).toEqual([type, null]);
    }
  });
  test('a host signature counts on any request type', () => {
    expect(detectCmp(makeScan({ network: [{ url: 'https://cdn.cookielaw.org/logos/abc/logo.png', type: 'image' }] })).id).toBe('onetrust');
  });
  test('Google Fonts only when the request goes to the fonts hosts', () => {
    expect(detectGoogleFonts(makeScan({ network: [req('https://fonts.googleapis.com/css2?family=Inter')] })).found).toBe(true);
    expect(detectGoogleFonts(makeScan({ network: [req('https://fonts.gstatic.com/s/inter/v1/a.woff2')] })).found).toBe(true);
    expect(detectGoogleFonts(makeScan({ network: [req('https://example.com/css?from=fonts.googleapis.com')] })).found).toBe(false);
    expect(detectGoogleFonts(makeScan({ network: [req('https://fonts.googleapis.com.example.org/css')] })).found).toBe(false);
  });
  test('"Google tag present" needs a request to a Google tag host', () => {
    expect(detectConsentMode(makeScan({ network: [req('https://www.googletagmanager.com/gtag/js?id=G-1')] })).hasGoogleTag).toBe(true);
    expect(detectConsentMode(makeScan({ network: [req('https://example.com/js/googleads-helper.js')] })).hasGoogleTag).toBe(false);
  });
});

describe('cookies that live on the vendor domain are not judged by name', () => {
  test('a first-party cookie called fr, NID, IDE, MUID or bcookie is not a tracker', () => {
    for (const name of ['fr', 'NID', 'IDE', 'test_cookie', 'MUID', 'bcookie', 'li_sugr', 'UserMatchHistory', 'personalization_id']) {
      expect([name, classifyCookieName(name)]).toEqual([name, null]);
    }
  });
  test('a site with its own "fr" language cookie is not accused of running the Meta pixel', () => {
    const res = buildResult(makeScan({ cookies: [{ name: 'fr', domain: 'example.com' }] }));
    expect(res.verdict).toBe('compliant');
    expect(res.findings).toEqual([]);
  });
  test('first-party tracker cookies are still recognized', () => {
    expect(classifyCookieName('_ga_ABC123')?.name).toBe('Google Analytics');
    expect(classifyCookieName('_fbp')?.name).toBe('Meta Pixel');
    expect(classifyCookieName('_clck')?.name).toBe('Microsoft Clarity');
  });
});

describe('cookie names: the documented shape, not a prefix', () => {
  const vendorCookies: Array<[name: string, vendor: string]> = [
    ['_ga', 'Google Analytics'],
    ['_ga_ABC123XYZ', 'Google Analytics'],
    ['_gid', 'Google Analytics'],
    ['_gat', 'Google Analytics'],
    ['_gat_UA-123456-1', 'Google Analytics'],
    ['_gat_gtag_UA_123456_1', 'Google Analytics'],
    ['__utma', 'Google Analytics (Universal)'],
    ['__utmz', 'Google Analytics (Universal)'],
    ['_gcl_au', 'Google Ads (conversion linker)'],
    ['_gcl_aw', 'Google Ads (conversion linker)'],
    ['_gac_UA-123456-1', 'Google Ads'],
    ['_gac_gb_ABC123', 'Google Ads'],
    ['_hjSessionUser_123456', 'Hotjar'],
    ['_hjSession_123456', 'Hotjar'],
    ['_hjFirstSeen', 'Hotjar'],
    ['_hjid', 'Hotjar'],
    ['mp_0123456789abcdef0123456789abcdef_mixpanel', 'Mixpanel'],
    ['AMCV_0123456789ABCDEF01234567%40AdobeOrg', 'Adobe Experience Cloud'],
    ['AMCV_0123456789ABCDEF01234567@AdobeOrg', 'Adobe Experience Cloud'],
    ['cto_bundle', 'Criteo'],
    ['_pinterest_ct_ua', 'Pinterest Tag'],
  ];
  for (const [name, vendor] of vendorCookies) {
    test(`${name} -> ${vendor}`, () => expect(classifyCookieName(name)?.name).toBe(vendor));
  }

  const siteCookies = ['_gallery_seen', '_gaming_pref', '_gate', '_gadget', '_ga_', '_gat_', 'mp_lang', 'mp_session', 'cto_cart', '_hjk', '_hj', '_gcli', '__utmost', '__utm', 'AMCV_', 'mboxes'];
  for (const name of siteCookies) {
    test(`a site's own "${name}" is not a tracker cookie`, () => expect(classifyCookieName(name)).toBeNull());
  }

  test('a site whose only cookies merely start like a tracker cookie stays compliant', () => {
    const res = buildResult(makeScan({ cookies: ['_gallery_seen', 'mp_lang', 'cto_cart', '_gate'].map((name) => ({ name, domain: 'example.com' })) }));
    expect(res.verdict).toBe('compliant');
    expect(res.findings).toEqual([]);
  });

  test('no two entries match the same cookie, so no entry hides another', () => {
    for (const [name] of vendorCookies) {
      const hits = COOKIE_PATTERNS.filter((p) => (typeof p.match === 'string' ? name === p.match : p.match.test(name)));
      expect([name, hits.length]).toEqual([name, 1]);
    }
  });
});

describe('hostile markup does not stall the banner patterns', () => {
  test('a megabyte of unterminated class attributes is scanned in well under a second', () => {
    const html = ('<div class="' + 'x'.repeat(5000)).repeat(200); // 1 MB, no closing quote anywhere
    const t0 = performance.now();
    const cmp = detectCmp(makeScan({ html }));
    const ms = performance.now() - t0;
    expect(cmp.id).toBeNull();
    expect(ms).toBeLessThan(1000);
  });
  test('a banner class is still found at the start of a long attribute', () => {
    const html = '<div class="site-cookie-banner ' + 'utility '.repeat(400) + '">We use cookies</div>' + 'x'.repeat(3000);
    expect(detectCmp(makeScan({ html })).id).toBe('custom');
  });
});
