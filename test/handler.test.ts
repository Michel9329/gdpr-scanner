// The request handler with the browser step replaced: cache, daily cap, error codes, debug gating.
// The cap is the budget guard, so the tests insist on WHEN the counter moves.
import { test, expect, describe } from 'bun:test';
import { handleRequest, type Deps, type Env } from '../src/index';
import type { RawScan } from '../src/types';

const SECRET = 'k'.repeat(40);
const TODAY = `count:${new Date().toISOString().slice(0, 10)}`;

function fakeKv(initial: Record<string, string> = {}, opts: { failGet?: (key: string) => boolean; failPut?: (key: string) => boolean } = {}) {
  const store = new Map<string, string>(Object.entries(initial));
  return {
    store,
    get: async (key: string) => {
      if (opts.failGet?.(key)) throw new Error('kv get failed');
      return store.get(key) ?? null;
    },
    put: async (key: string, value: string) => {
      if (opts.failPut?.(key)) throw new Error('kv put failed');
      store.set(key, value);
    },
  };
}

function goodScan(url: string): RawScan {
  return {
    requestedUrl: url,
    finalUrl: url,
    status: 200,
    reachable: true,
    html: '<!doctype html><html><body><main>' + 'real page content. '.repeat(200) + '</main></body></html>',
    links: [
      { href: url, text: 'Home' },
      { href: url + 'privacy', text: 'Privacy Policy' },
      { href: url + 'cookie-policy', text: 'Cookie Policy' },
    ],
    network: [],
    cookies: [],
    globals: { dataLayer: [], googleTagDataEntries: null, hasTcfApi: false, cmpGlobals: [] },
  };
}
const failedScan = (url: string): RawScan => ({ ...goodScan(url), reachable: false, html: '', links: [], error: 'navigation-failed' });

interface Bench {
  kv: ReturnType<typeof fakeKv>;
  scanned: string[];
  call: (url: unknown, headers?: Record<string, string>, env?: Partial<Env>) => Promise<{ status: number; body: any; res: Response }>;
}

/** A handler wired to a fake KV and a fake browser step. `scanImpl` decides what a scan returns. */
function bench(scanImpl: (url: string, kv: ReturnType<typeof fakeKv>) => RawScan | Promise<RawScan>, kv = fakeKv()): Bench {
  const scanned: string[] = [];
  const deps: Deps = {
    scan: async (_browser, url) => {
      scanned.push(url);
      return scanImpl(url, kv);
    },
    checkPolicyContent: async () => ({ checked: false, missing: [] }),
  };
  const call: Bench['call'] = async (url, headers = {}, env = {}) => {
    const pending: Promise<unknown>[] = [];
    const ctx = { waitUntil: (p: Promise<unknown>) => pending.push(p), passThroughOnException() {} } as unknown as ExecutionContext;
    const res = await handleRequest(
      new Request('https://scanner.test/scan', {
        method: 'POST',
        headers: { authorization: `Bearer ${SECRET}`, 'content-type': 'application/json', ...headers },
        body: JSON.stringify({ url }),
      }),
      { BROWSER: {}, SCANNER_SECRET: SECRET, SCAN_KV: kv as unknown as KVNamespace, ...env },
      ctx,
      deps,
    );
    await Promise.all(pending);
    return { status: res.status, body: await res.clone().json(), res };
  };
  return { kv, scanned, call };
}

describe('daily cap: the slot is taken before the browser starts', () => {
  test('the counter is already 1 while the first scan is running', async () => {
    let seenDuringScan: string | undefined;
    const b = bench((url, kv) => {
      seenDuringScan = kv.store.get(TODAY);
      return goodScan(url);
    });
    const r = await b.call('https://example.com');
    expect(r.body.scanned).toBe(true);
    expect(seenDuringScan).toBe('1');
    expect(b.kv.store.get(TODAY)).toBe('1');
  });

  test('a scan that fails still uses a slot, and is not cached', async () => {
    const b = bench(failedScan);
    const r = await b.call('https://example.com');
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ scanned: false, verdict: null, error: 'navigation-failed' });
    expect(b.kv.store.get(TODAY)).toBe('1');
    expect([...b.kv.store.keys()].filter((k) => k.startsWith('scan:'))).toEqual([]);
  });

  test('pages that never load cannot run past the cap', async () => {
    const b = bench(failedScan);
    const env = { DAILY_CAP: '3' };
    for (let i = 0; i < 3; i++) expect((await b.call(`https://site${i}.example.com`, {}, env)).body.error).toBe('navigation-failed');
    const over = await b.call('https://site3.example.com', {}, env);
    expect(over.body).toMatchObject({ scanned: false, error: 'daily-budget' });
    expect(b.scanned.length).toBe(3); // the fourth never reached the browser
    expect(b.kv.store.get(TODAY)).toBe('3');
  });

  test('a scan that throws uses a slot and reports a stable code, not the exception', async () => {
    const b = bench(() => {
      throw new Error('Protocol error: Target closed (session 42, token abc)');
    });
    const r = await b.call('https://example.com');
    expect(r.body).toMatchObject({ scanned: false, error: 'scan-failed' });
    expect(JSON.stringify(r.body)).not.toContain('Target closed');
    expect(b.kv.store.get(TODAY)).toBe('1');
  });

  test('if the counter cannot be written the browser is not started', async () => {
    const b = bench(goodScan, fakeKv({}, { failPut: (k) => k.startsWith('count:') }));
    const r = await b.call('https://example.com');
    expect(r.body).toMatchObject({ scanned: false, error: 'budget-unavailable' });
    expect(b.scanned).toEqual([]);
  });

  test('if the counter cannot be read the browser is not started', async () => {
    const b = bench(goodScan, fakeKv({}, { failGet: (k) => k.startsWith('count:') }));
    const r = await b.call('https://example.com');
    expect(r.body).toMatchObject({ scanned: false, error: 'budget-unavailable' });
    expect(b.scanned).toEqual([]);
  });

  test('DAILY_CAP must be a positive integer, anything else means the default of 20', async () => {
    for (const bad of ['abc', '0', '-3', '2.5', '']) {
      const under = bench(goodScan, fakeKv({ [TODAY]: '19' }));
      expect([bad, (await under.call('https://example.com', {}, { DAILY_CAP: bad })).body.scanned]).toEqual([bad, true]);
      const at = bench(goodScan, fakeKv({ [TODAY]: '20' }));
      expect([bad, (await at.call('https://example.com', {}, { DAILY_CAP: bad })).body.error]).toEqual([bad, 'daily-budget']);
    }
    const custom = bench(goodScan, fakeKv({ [TODAY]: '2' }));
    expect((await custom.call('https://example.com', {}, { DAILY_CAP: '2' })).body.error).toBe('daily-budget');
  });
});

describe('cache', () => {
  test('a second request for the same URL is served from the cache and uses no slot', async () => {
    const b = bench(goodScan);
    const first = await b.call('https://example.com/a');
    expect(first.body.cached).toBeUndefined();
    const second = await b.call('https://example.com/a#top');
    expect(second.body).toMatchObject({ scanned: true, cached: true, finalUrl: 'https://example.com/a' });
    expect(b.scanned.length).toBe(1);
    expect(b.kv.store.get(TODAY)).toBe('1');
  });

  test('another page of the same host gets its own scan', async () => {
    // A verdict read from one page (or from wherever it redirected) must not stand for the site.
    const b = bench((url) => (url === 'https://example.com/license.txt' ? { ...goodScan(url), finalUrl: 'https://elsewhere.example.com/landing' } : goodScan(url)));
    await b.call('https://example.com/license.txt');
    for (const other of ['https://example.com/', 'https://example.com/license.txt?x=1', 'http://example.com/license.txt']) {
      const r = await b.call(other);
      expect([other, r.body.cached, r.body.finalUrl]).toEqual([other, undefined, new URL(other).toString()]);
    }
    expect(b.scanned.length).toBe(4);
  });

  test('the key is a hash of the whole URL, under a new prefix', async () => {
    const b = bench(goodScan);
    await b.call('https://example.com/a?b=1');
    const keys = [...b.kv.store.keys()].filter((k) => k.startsWith('scan:'));
    expect(keys.length).toBe(1);
    expect(keys[0]).toMatch(/^scan:v2:[0-9a-f]{64}$/);
    expect(keys[0]).not.toContain('example.com');
  });

  test('x-fresh: 1 forces a new scan', async () => {
    const b = bench(goodScan);
    await b.call('https://example.com');
    const again = await b.call('https://example.com', { 'x-fresh': '1' });
    expect(again.body.cached).toBeUndefined();
    expect(b.scanned.length).toBe(2);
    expect(b.kv.store.get(TODAY)).toBe('2');
  });

  test('a cache that cannot be read is a miss, not an error', async () => {
    const b = bench(goodScan, fakeKv({}, { failGet: (k) => k.startsWith('scan:') }));
    expect((await b.call('https://example.com')).body.scanned).toBe(true);
  });

  test('"Example.COM." and "example.com" share one cache entry', async () => {
    const b = bench(goodScan);
    await b.call('https://Example.COM./');
    expect(b.scanned).toEqual(['https://example.com/']);
    expect((await b.call('example.com')).body.cached).toBe(true);
  });
});

describe('targets that are not public websites never reach the browser', () => {
  const bad: unknown[] = [
    '', 'http://localhost/', 'http://localhost./', 'http://127.0.0.1/', 'http://0x7f.1/', 'http://2130706433/', 'http://169.254.169.254/latest/',
    'http://10.0.0.8/', 'http://[::1]/', 'http://intranet/', 'http://db.internal/', 'https://example.com:8443/', 'https://user:pw@example.com/',
    'file:///etc/passwd', 'javascript:alert(1)', 42, null, { url: 'https://example.com' }, ['https://example.com'],
  ];
  for (const url of bad) {
    test(JSON.stringify(url), async () => {
      const b = bench(goodScan);
      const r = await b.call(url);
      expect(r.status).toBe(400);
      expect(r.body.error).toBe('bad-url');
      expect(b.scanned).toEqual([]);
      expect(b.kv.store.size).toBe(0); // no slot used, nothing cached
    });
  }

  test('a body that is not JSON is refused before anything else happens', async () => {
    const b = bench(goodScan);
    const res = await handleRequest(
      new Request('https://scanner.test/scan', { method: 'POST', headers: { authorization: `Bearer ${SECRET}` }, body: '{not json' }),
      { BROWSER: {}, SCANNER_SECRET: SECRET, SCAN_KV: b.kv as unknown as KVNamespace },
      { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext,
    );
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toBe('bad-json');
  });
});

describe('debug output and response headers', () => {
  test('x-debug does nothing unless DEBUG is "1"', async () => {
    const b = bench(goodScan);
    expect((await b.call('https://example.com', { 'x-debug': '1' })).body._debug).toBeUndefined();
    const on = await b.call('https://example.org', { 'x-debug': '1' }, { DEBUG: '1' });
    expect(on.body._debug).toMatchObject({ cookies: [], requests: 0 });
  });

  test('the exception text is shown only in debug mode', async () => {
    const b = bench(() => {
      throw new Error('boom-detail');
    });
    const on = await b.call('https://example.com', { 'x-debug': '1' }, { DEBUG: '1' });
    expect(on.body._debug.exception).toContain('boom-detail');
  });

  test('debug data is never written to the cache', async () => {
    const b = bench(goodScan);
    await b.call('https://example.com', { 'x-debug': '1' }, { DEBUG: '1' });
    const stored = [...b.kv.store.entries()].filter(([k]) => k.startsWith('scan:'));
    expect(stored.length).toBe(1);
    expect(stored[0]![1]).not.toContain('_debug');
  });

  test('responses are not cacheable by intermediaries', async () => {
    const b = bench(goodScan);
    expect((await b.call('https://example.com')).res.headers.get('cache-control')).toBe('no-store');
  });
});

describe('routing', () => {
  const env = { BROWSER: {}, SCANNER_SECRET: SECRET } as Env;
  const ctx = { waitUntil() {}, passThroughOnException() {} } as unknown as ExecutionContext;
  test('GET / answers without a secret and says nothing else', async () => {
    const res = await handleRequest(new Request('https://scanner.test/'), env, ctx);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('gdpr-scanner ok');
  });
  test('anything other than POST /scan is 404', async () => {
    for (const [method, path] of [['GET', '/scan'], ['POST', '/'], ['POST', '/scan/extra'], ['PUT', '/scan'], ['GET', '/.env']] as const) {
      const res = await handleRequest(new Request('https://scanner.test' + path, { method }), env, ctx);
      expect([method, path, res.status]).toEqual([method, path, 404]);
    }
  });
});
