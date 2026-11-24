// What the browser step hands back is produced by the scanned page, so it is checked again in the
// Worker (clampScan), and the browser step itself has a deadline. No browser is needed here.
import { test, expect, describe } from 'bun:test';
import { bannerGoneAfterReject, clampScan, scan, SCAN_DEADLINE_MS } from '../src/scanner';
import type { RawScan } from '../src/types';

function base(): RawScan {
  return {
    requestedUrl: 'https://example.com/',
    finalUrl: 'https://example.com/',
    status: 200,
    contentType: 'text/html',
    reachable: true,
    html: '<html><body>ok</body></html>',
    links: [{ href: 'https://example.com/privacy', text: 'Privacy' }],
    network: [{ url: 'https://www.google-analytics.com/g/collect', type: 'xhr' }],
    cookies: [{ name: '_ga', domain: '.example.com' }],
    globals: { dataLayer: [['consent', 'default', { ad_storage: 'denied' }]], googleTagDataEntries: { ad_storage: { default: false } }, hasTcfApi: false, cmpGlobals: ['_iub'] },
    banner: { found: true, accept: true, reject: true, close: false, settings: true, unknown: 2, policyLink: true },
    preticked: { count: 1, sample: 'Acconsento alla newsletter' },
    phase2: { scroll: { newCookies: [] }, reject: { clicked: true, bannerGone: true, newCookies: [], reloaded: true, bannerReappeared: false } },
  };
}
/** A scan with some fields replaced by shapes a hostile page could produce. */
const hostile = (patch: Record<string, unknown>): RawScan => ({ ...base(), ...patch }) as unknown as RawScan;
const big = (n: number) => 'x'.repeat(n);

describe('clampScan: a normal scan passes unchanged', () => {
  test('every field is kept as it was', () => {
    expect(clampScan(base())).toEqual(base());
  });
  test('optional fields stay absent', () => {
    const { banner, preticked, phase2, contentType, ...rest } = base();
    expect(clampScan(rest as RawScan)).toEqual(rest as RawScan);
  });
  test('a scan that was not read keeps its error code', () => {
    expect(clampScan({ ...base(), reachable: false, error: 'private-address' }).error).toBe('private-address');
  });
});

describe('clampScan: hostile shapes', () => {
  test('strings are cut', () => {
    const r = clampScan(hostile({ finalUrl: big(100_000), html: big(5_000_000), contentType: 'TEXT/HTML; charset=' + big(10_000) }));
    expect(r.finalUrl.length).toBe(2048);
    expect(r.html.length).toBe(2_000_000);
    expect(r.contentType).toBe('text/html');
  });

  test('arrays are sliced and their items rebuilt', () => {
    const r = clampScan(
      hostile({
        links: Array.from({ length: 5000 }, (_, i) => ({ href: big(10_000) + i, text: big(10_000), extra: big(1000) })),
        cookies: Array.from({ length: 10_000 }, () => ({ name: big(5000), domain: big(5000), value: big(5000) })),
        network: Array.from({ length: 10_000 }, () => ({ url: big(10_000), type: big(1000) })),
      }),
    );
    expect(r.links.length).toBe(400);
    expect(r.links[0]).toEqual({ href: big(2048), text: big(80) });
    expect(r.cookies.length).toBe(300);
    expect(r.cookies[0]).toEqual({ name: big(256), domain: big(256) });
    expect(r.network.length).toBe(3000);
    expect(r.network[0]!.url.length).toBe(2048);
    expect(r.network[0]!.type.length).toBe(40);
  });

  test('wrong types become empty values, never exceptions', () => {
    const r = clampScan(
      hostile({
        links: 'not an array',
        cookies: { length: 1e9 },
        network: null,
        finalUrl: { toString: 'x' },
        status: 'NaN',
        reachable: 'yes',
        html: 42,
        globals: 'none',
      }),
    );
    expect(r.links).toEqual([]);
    expect(r.cookies).toEqual([]);
    expect(r.network).toEqual([]);
    expect(r.finalUrl).toBe('');
    expect(r.status).toBe(0);
    expect(r.reachable).toBe(false);
    expect(r.html).toBe('42');
    expect(r.globals).toEqual({ dataLayer: [], googleTagDataEntries: null, hasTcfApi: false, cmpGlobals: [] });
  });

  test('items of the wrong type inside arrays', () => {
    const r = clampScan(hostile({ links: [null, 7, 'x', [1], { href: 9, text: true }], cookies: [undefined, { name: ['a'] }] }));
    expect(r.links).toEqual([
      { href: '', text: '' },
      { href: '', text: '' },
      { href: '', text: '' },
      { href: '', text: '' },
      { href: '9', text: 'true' },
    ]);
    expect(r.cookies).toEqual([
      { name: '', domain: '' },
      { name: '', domain: '' },
    ]);
  });

  test('the dataLayer is bounded in entries and in total size', () => {
    const many = clampScan(hostile({ globals: { ...base().globals, dataLayer: Array.from({ length: 10_000 }, (_, i) => ({ event: i })) } }));
    expect(many.globals.dataLayer.length).toBe(200);
    const heavy = clampScan(hostile({ globals: { ...base().globals, dataLayer: [big(150_000), big(150_000), { event: 'x' }] } }));
    expect(heavy.globals.dataLayer).toEqual([big(150_000)]); // the second entry passes the 200 KB total
    const notArray = clampScan(hostile({ globals: { ...base().globals, dataLayer: { 0: 'a', length: 1 } } }));
    expect(notArray.globals.dataLayer).toEqual([]);
  });

  test('a dataLayer entry that cannot be serialized is skipped', () => {
    const cyclic: Record<string, unknown> = { event: 'loop' };
    cyclic.self = cyclic;
    const r = clampScan(hostile({ globals: { ...base().globals, dataLayer: [cyclic, { event: 'ok' }, 10n] } }));
    expect(r.globals.dataLayer).toEqual([{ event: 'ok' }]);
  });

  test('googleTagDataEntries over the size bound is dropped', () => {
    const r = clampScan(hostile({ globals: { ...base().globals, googleTagDataEntries: { a: big(300_000) } } }));
    expect(r.globals.googleTagDataEntries).toBeNull();
  });

  test('only known consent-platform globals are kept, once each', () => {
    const r = clampScan(hostile({ globals: { ...base().globals, cmpGlobals: ['_iub', '_iub', 'evil', 7, big(1000)], hasTcfApi: 'true' } }));
    expect(r.globals.cmpGlobals).toEqual(['_iub']);
    expect(r.globals.hasTcfApi).toBe(false);
  });

  test('banner: a malformed or missing field takes the value that accuses nothing; labels are cut', () => {
    const r = clampScan(
      hostile({
        banner: {
          found: 'yes',
          accept: 1,
          reject: 0,
          unknown: 1e12,
          settings: -4,
          policyLink: { toString: 'x' },
          __proto__x: true,
          note: big(1000),
          flag: true,
          count: 3,
          dbg: { el: big(5000), ctrls: Array.from({ length: 100 }, () => big(5000)), more: big(1000) },
        },
      }),
    ).banner as unknown as Record<string, unknown>; // a page may put a number where a flag is expected
    expect(r).toEqual({
      found: false, // "yes" is not true: no banner
      accept: false, // 1 is not true: no accept control
      reject: true, // 0 is not false: a reject control is assumed
      close: true, // missing: a close control is assumed
      settings: true,
      policyLink: true, // malformed: a link is assumed
      unknown: 1000, // an integer, capped
      flag: true, // fields ux.ts may add: booleans kept
      count: 3, // and non-negative integers kept
      dbg: { el: big(120), ctrls: Array.from({ length: 8 }, () => big(120)) },
    });
  });

  test('a malformed unrecognized-control counter means doubt, and no banner-no-reject', () => {
    const accusing = { found: true, accept: true, reject: false, close: false, settings: false, policyLink: true };
    for (const unknown of [NaN, -3, 0.4, Infinity, '0', null, undefined]) {
      const banner = clampScan(hostile({ banner: { ...accusing, unknown } })).banner as unknown as Record<string, unknown>;
      expect([String(unknown), banner.unknown]).toEqual([String(unknown), 1]);
    }
    expect((clampScan(hostile({ banner: { ...accusing, unknown: 0 } })).banner as unknown as Record<string, unknown>).unknown).toBe(0);
  });

  test('a scan that is not an object does not throw', () => {
    for (const raw of [null, undefined, 42, 'x']) {
      expect(clampScan(raw as unknown as RawScan)).toMatchObject({ reachable: false, html: '', links: [], cookies: [] });
    }
  });

  test('banner null stays null, a banner that is not an object becomes null', () => {
    expect(clampScan(hostile({ banner: null })).banner).toBeNull();
    expect(clampScan(hostile({ banner: 'found' })).banner).toBeNull();
  });

  test('preticked: count is an integer in range, sample is a short string', () => {
    const cases: Array<[unknown, number]> = [[NaN, 0], [-5, 0], [1e9, 1000], ['7', 0], [3.9, 3], [Infinity, 0]];
    for (const [count, expected] of cases) {
      expect([count, clampScan(hostile({ preticked: { count, sample: { a: 1 } } })).preticked]).toEqual([count, { count: expected, sample: '' }]);
    }
    expect(clampScan(hostile({ preticked: { count: 2, sample: big(10_000) } })).preticked).toEqual({ count: 2, sample: big(90) });
  });

  test('phase2: cookie lists rebuilt, flags must be real booleans', () => {
    const r = clampScan(
      hostile({
        phase2: {
          scroll: { newCookies: Array.from({ length: 1000 }, () => ({ name: big(1000), domain: 'x' })) },
          reject: { clicked: 'true', bannerGone: 1, newCookies: 'many', reloaded: true, bannerReappeared: null },
        },
      }),
    );
    expect(r.phase2!.scroll.newCookies.length).toBe(300);
    expect(r.phase2!.scroll.newCookies[0]).toEqual({ name: big(256), domain: 'x' });
    expect(r.phase2!.reject).toEqual({ clicked: false, bannerGone: false, newCookies: [], reloaded: true, bannerReappeared: false });
  });

  test('a large hostile scan is clamped quickly', () => {
    const t0 = performance.now();
    clampScan(
      hostile({
        html: big(20_000_000),
        links: Array.from({ length: 100_000 }, () => ({ href: big(100), text: big(100) })),
        globals: { ...base().globals, dataLayer: Array.from({ length: 100_000 }, () => ({ e: big(100) })) },
      }),
    );
    expect(performance.now() - t0).toBeLessThan(300);
  });
});

describe('reject test', () => {
  test('a failed observation after the click is not "banner gone"', () => {
    expect(bannerGoneAfterReject(null)).toBe(false);
  });
  test('banner still there: not gone; no banner found: gone', () => {
    const banner = { found: true, accept: true, reject: true, close: false, settings: false, unknown: 0, policyLink: false };
    expect(bannerGoneAfterReject({ banner, preticked: { count: 0, sample: '' } })).toBe(false);
    expect(bannerGoneAfterReject({ banner: null, preticked: { count: 0, sample: '' } })).toBe(true);
  });
});

describe('scan deadline', () => {
  test('the deadline is 45 s', () => {
    expect(SCAN_DEADLINE_MS).toBe(45_000);
  });

  test('a browser that never starts gives scan-timeout at the deadline, not a hang', async () => {
    const neverAnswers = { fetch: () => new Promise<Response>(() => {}) };
    const t0 = performance.now();
    const r = await scan(neverAnswers, 'https://example.com/', 'test', { deadlineMs: 300 });
    const took = performance.now() - t0;
    expect(r).toMatchObject({ reachable: false, error: 'scan-timeout', requestedUrl: 'https://example.com/', html: '', links: [] });
    expect(took).toBeGreaterThanOrEqual(290);
    expect(took).toBeLessThan(1500);
  });

  test('a launch that fails is an error for the caller, before the deadline', async () => {
    const broken = { fetch: async () => new Response('no browser', { status: 500 }) };
    const t0 = performance.now();
    await expect(scan(broken, 'https://example.com/', 'test', { deadlineMs: 5_000 })).rejects.toThrow();
    expect(performance.now() - t0).toBeLessThan(2_000);
  });
});

describe('launch retry', () => {
  /** A browser binding that answers every launch with the given status and text, and counts the launches. */
  const refusing = (status: number, text: string) => {
    const b = { launches: 0, fetch: async () => (b.launches++, new Response(text, { status })) };
    return b;
  };

  test('a 429 for the daily browser time is not retried', async () => {
    const b = refusing(429, 'Browser time limit exceeded for today');
    await expect(scan(b, 'https://example.com/', 'test', { deadlineMs: 5_000 })).rejects.toThrow();
    expect(b.launches).toBe(1);
  });

  test('another error is not retried', async () => {
    const b = refusing(500, 'internal');
    await expect(scan(b, 'https://example.com/', 'test', { deadlineMs: 5_000 })).rejects.toThrow();
    expect(b.launches).toBe(1);
  });

  test('a 429 for too many new browsers is retried once, after a short wait', async () => {
    const b = refusing(429, 'Too many requests');
    const t0 = performance.now();
    await expect(scan(b, 'https://example.com/', 'test')).rejects.toThrow();
    expect(b.launches).toBe(2);
    const took = performance.now() - t0;
    expect(took).toBeGreaterThanOrEqual(3_400);
    expect(took).toBeLessThan(6_000);
  }, 10_000);
});
