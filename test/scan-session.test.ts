// The browser session of scan() driven by a fake browser and page. The fake records what scan()
// asks of it and lets each test fire the events a real page fires (request, response, dialog,
// popup, targetcreated), so the guards of src/scanner.ts run without a browser. The launch and the
// waits are passed through scan()'s options; the code under test is the production path.
import { test, expect, describe } from 'bun:test';
import { scan, type ScanBrowser } from '../src/scanner';

type Handler = (...args: any[]) => unknown;

class Emitter {
  handlers = new Map<string, Handler[]>();
  on(event: string, fn: Handler) {
    const list = this.handlers.get(event) ?? [];
    list.push(fn);
    this.handlers.set(event, list);
    return this;
  }
  emit(event: string, ...args: unknown[]) {
    for (const fn of this.handlers.get(event) ?? []) fn(...args);
  }
}

class FakeRequest {
  handled: 'continue' | 'abort' | null = null;
  constructor(readonly href: string, readonly nav: boolean, readonly frameRef: unknown) {}
  url() { return this.href; }
  isNavigationRequest() { return this.nav; }
  frame() { return this.frameRef; }
  resourceType() { return this.nav ? 'document' : 'script'; }
  continue() { this.handled ??= 'continue'; return Promise.resolve(); }
  abort() { this.handled ??= 'abort'; return Promise.resolve(); }
}

class FakeResponse {
  constructor(readonly req: FakeRequest, readonly ip: string, readonly code = 200, readonly type = 'text/html; charset=utf-8', readonly port = 443) {}
  remoteAddress() { return { ip: this.ip, port: this.port }; }
  url() { return this.req.href; }
  request() { return this.req; }
  status() { return this.code; }
  headers() { return { 'content-type': this.type }; }
}

/** What the fake page answers when scan() reads it. */
interface Answers {
  html?: unknown;
  links?: unknown;
  globals?: unknown;
  ux?: unknown;
  cookies?: { name: string; domain: string }[];
  /** isolatedRealm() throws, as if the isolated world were missing. */
  noRealm?: boolean;
}

class FakePage extends Emitter {
  calls: string[] = [];
  closed = false;
  current = 'about:blank';
  userAgent = '';
  readonly frameRef = { name: 'main frame' };
  readonly targetRef = { type: () => 'page', _targetId: 'MAIN' };
  readonly cdp = { sent: [] as Array<[string, unknown]>, send: (m: string, p: unknown) => (this.cdp.sent.push([m, p]), Promise.resolve({})) };
  /** What the first goto() does; the default loads one public page. */
  load: (page: FakePage, url: string) => Promise<FakeResponse | null> = async (page, url) => {
    const req = page.request(url, true);
    const res = page.respond(req, '93.184.216.34');
    page.current = url;
    return res;
  };
  private gotos = 0;
  constructor(readonly answers: Answers = {}) {
    super();
  }
  request(url: string, nav = false) {
    const req = new FakeRequest(url, nav, nav ? this.frameRef : { name: 'other frame' });
    this.emit('request', req);
    return req;
  }
  respond(req: FakeRequest, ip: string, port = 443) {
    const res = new FakeResponse(req, ip, 200, 'text/html; charset=utf-8', port);
    this.emit('response', res);
    return res;
  }
  private kind(args: unknown[]) {
    if (args[0] === 'observe' || args[0] === 'click-reject') return args[0];
    if (args.length === 1 && typeof args[0] === 'number') return 'html';
    if (args.length === 5) return 'links';
    if (args.length === 3 && Array.isArray(args[0])) return 'globals';
    return 'other';
  }
  private answer(kind: string) {
    const a = this.answers;
    if (kind === 'observe') return a.ux ?? { banner: null, preticked: { count: 0, sample: '' } };
    if (kind === 'click-reject') return { clicked: false };
    if (kind === 'html') return a.html ?? '<!DOCTYPE html><html lang="it"><body>' + 'pagina vera. '.repeat(300) + '</body></html>';
    if (kind === 'links') return a.links ?? [{ href: 'https://example.com/privacy', text: 'Privacy' }];
    if (kind === 'globals') return a.globals ?? { dataLayer: [], googleTagDataEntries: null, hasTcfApi: false, cmpGlobals: [] };
    return true;
  }
  readonly realm = {
    evaluate: (_fn: unknown, ...args: unknown[]) => {
      const k = this.kind(args);
      this.calls.push('isolated:' + k);
      return Promise.resolve(this.answer(k));
    },
  };
  mainFrame() {
    return Object.assign(this.frameRef, {
      isolatedRealm: () => {
        if (this.answers.noRealm) throw new Error('no isolated world');
        return this.realm;
      },
    });
  }
  evaluate(_fn: unknown, ...args: unknown[]) {
    const k = this.kind(args);
    this.calls.push('main:' + k);
    return Promise.resolve(this.answer(k));
  }
  target() { return this.targetRef; }
  createCDPSession() { return Promise.resolve(this.cdp); }
  setBypassServiceWorker(v: boolean) { this.calls.push('bypassServiceWorker:' + v); return Promise.resolve(); }
  setViewport() { return Promise.resolve(); }
  setUserAgent(ua: string) { this.userAgent = ua; return Promise.resolve(); }
  setRequestInterception(v: boolean) { this.calls.push('interception:' + v); return Promise.resolve(); }
  async goto(url: string) {
    if (this.gotos++ > 0) return null; // the reload of the reject test
    return this.load(this, url);
  }
  url() { return this.current; }
  cookies() { return Promise.resolve(this.answers.cookies ?? []); }
  close() { this.closed = true; return Promise.resolve(); }
}

class FakeBrowser extends Emitter {
  closed = false;
  constructor(readonly page: FakePage) {
    super();
  }
  newPage() { return Promise.resolve(this.page); }
  userAgent() { return Promise.resolve('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/126.0.0.0 Safari/537.36'); }
  close() { this.closed = true; return Promise.resolve(); }
}

/** Runs scan() on a fake browser with instant waits. */
async function run(page: FakePage, options: { deadlineMs?: number } = {}) {
  const browser = new FakeBrowser(page);
  const result = await scan({}, 'https://example.com/', 'test-suffix/1.0', {
    ...options,
    launch: async () => browser as unknown as ScanBrowser,
    wait: async () => {},
  });
  return { result, browser };
}

describe('a whole session on a fake page', () => {
  test('a normal page is read, and the browser is closed', async () => {
    const { result, browser } = await run(new FakePage());
    expect(result).toMatchObject({ reachable: true, status: 200, contentType: 'text/html', finalUrl: 'https://example.com/' });
    expect(result.error).toBeUndefined();
    expect(browser.closed).toBe(true);
  });

  test('the User-Agent is the browser\'s own, without "Headless", plus the suffix', async () => {
    const page = new FakePage();
    await run(page);
    expect(page.userAgent).toBe('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 test-suffix/1.0');
  });
});

describe('the address check', () => {
  test('after a response from a private address the page is closed, later requests are aborted, and the scan reports private-address', async () => {
    const page = new FakePage();
    let doc: FakeRequest | undefined;
    let later: FakeRequest | undefined;
    page.load = async (p, url) => {
      doc = p.request(url, true);
      p.respond(doc, '10.0.0.7');
      later = p.request('https://cdn.example.com/app.js');
      throw new Error('Navigating frame was detached');
    };
    const { result, browser } = await run(page);
    expect(doc!.handled).toBe('continue'); // the name was public: the request had left
    expect(later!.handled).toBe('abort');
    expect(page.closed).toBe(true);
    expect(result).toMatchObject({ reachable: false, error: 'private-address', html: '', links: [] });
    expect(browser.closed).toBe(true);
  });

  test('a private address seen while the page is read still drops the scan', async () => {
    const page = new FakePage();
    const original = page.cookies.bind(page);
    let fired = false;
    page.cookies = () => {
      if (!fired) {
        fired = true;
        page.respond(page.request('https://tracker.example.com/p.gif'), 'fd00::1');
      }
      return original();
    };
    const { result } = await run(page);
    expect(result.error).toBe('private-address');
  });
});

describe('a browser behind a forward proxy (Cloudflare Browser Run)', () => {
  test('every response reports the proxy on [::1]:9001: the page is read normally', async () => {
    const page = new FakePage();
    page.load = async (p, url) => {
      const doc = p.request(url, true);
      const res = p.respond(doc, '[::1]', 9001);
      p.respond(p.request('https://cdn.example.com/app.js'), '[::1]', 9001);
      return res;
    };
    const { result } = await run(page);
    expect(result.error).toBeUndefined();
    expect(result.reachable).toBe(true);
    expect(page.closed).toBe(false);
  });

  test('a private address on the port of the URL is still a private address', async () => {
    const page = new FakePage();
    page.load = async (p, url) => {
      p.respond(p.request(url, true), '127.0.0.1', 443);
      throw new Error('Navigating frame was detached');
    };
    const { result } = await run(page);
    expect(result.error).toBe('private-address');
  });
});

describe('the request guard', () => {
  test('a redirect of the page to an address the scanner does not load: aborted, blocked-redirect', async () => {
    const page = new FakePage();
    let redirect: FakeRequest | undefined;
    page.load = async (p, url) => {
      p.request(url, true);
      redirect = p.request('http://127.0.0.1/admin', true);
      throw new Error('net::ERR_BLOCKED_BY_CLIENT at https://example.com/');
    };
    const { result } = await run(page);
    expect(redirect!.handled).toBe('abort');
    expect(result.error).toBe('blocked-redirect');
  });

  test('requests to blocked hosts are aborted, others continue, and all are recorded', async () => {
    const page = new FakePage();
    const seen: FakeRequest[] = [];
    page.load = async (p, url) => {
      const doc = p.request(url, true);
      seen.push(p.request('https://www.google-analytics.com/g/collect'), p.request('http://router.lan/x'), p.request('https://cdn.example.com:8443/a.js'));
      p.current = url;
      return p.respond(doc, '93.184.216.34');
    };
    const { result } = await run(page);
    expect(seen.map((r) => r.handled)).toEqual(['continue', 'abort', 'continue']);
    expect(result.network.map((n) => n.url)).toContain('http://router.lan/x');
  });
});

describe('the session setup', () => {
  test('the page\'s requests bypass service workers, and interception is on', async () => {
    const page = new FakePage();
    await run(page);
    expect(page.calls).toContain('bypassServiceWorker:true');
    expect(page.calls).toContain('interception:true');
  });

  test('downloads are denied', async () => {
    const page = new FakePage();
    await run(page);
    expect(page.cdp.sent).toContainEqual(['Browser.setDownloadBehavior', { behavior: 'deny' }]);
  });

  test('a new page target is closed; the scanned page and other target types are not', async () => {
    const page = new FakePage();
    const browserRef: { b?: FakeBrowser } = {};
    page.load = async (p, url) => {
      browserRef.b!.emit('targetcreated', { type: () => 'page', _targetId: 'POPUP-1', page: () => Promise.resolve(null) });
      browserRef.b!.emit('targetcreated', { type: () => 'service_worker', _targetId: 'SW-1', page: () => Promise.resolve(null) });
      browserRef.b!.emit('targetcreated', p.target());
      const doc = p.request(url, true);
      p.current = url;
      return p.respond(doc, '93.184.216.34');
    };
    const browser = new FakeBrowser(page);
    browserRef.b = browser;
    await scan({}, 'https://example.com/', 'x', { launch: async () => browser as unknown as ScanBrowser, wait: async () => {} });
    const closed = page.cdp.sent.filter(([m]) => m === 'Target.closeTarget').map(([, p]) => (p as { targetId: string }).targetId);
    expect(closed).toEqual(['POPUP-1']);
  });

  test('a popup the page opens is closed', async () => {
    const page = new FakePage();
    const popup = new FakePage();
    page.load = async (p, url) => {
      p.emit('popup', popup);
      const doc = p.request(url, true);
      p.current = url;
      return p.respond(doc, '93.184.216.34');
    };
    await run(page);
    expect(popup.closed).toBe(true);
  });

  test('dialogs are dismissed, a beforeunload dialog is accepted', async () => {
    const page = new FakePage();
    const answered: string[] = [];
    const dialog = (type: string) => ({
      type: () => type,
      dismiss: () => (answered.push(type + ':dismiss'), Promise.resolve()),
      accept: () => (answered.push(type + ':accept'), Promise.resolve()),
    });
    page.load = async (p, url) => {
      p.emit('dialog', dialog('alert'));
      p.emit('dialog', dialog('prompt'));
      p.emit('dialog', dialog('beforeunload'));
      const doc = p.request(url, true);
      p.current = url;
      return p.respond(doc, '93.184.216.34');
    };
    await run(page);
    expect(answered).toEqual(['alert:dismiss', 'prompt:dismiss', 'beforeunload:accept']);
  });
});

describe('what the page hands back', () => {
  test('every value goes through clampScan', async () => {
    const page = new FakePage({
      html: 'x'.repeat(3_000_000),
      links: Array.from({ length: 1000 }, (_, i) => ({ href: 'https://example.com/' + i, text: 't'.repeat(500) })),
      ux: { banner: { found: true, accept: true, reject: false, close: false, settings: false, unknown: NaN, policyLink: true }, preticked: { count: -2, sample: 's'.repeat(500) } },
      globals: { dataLayer: 'not a list', googleTagDataEntries: null, hasTcfApi: 'yes', cmpGlobals: ['not-a-cmp'] },
    });
    const { result } = await run(page);
    expect(result.html.length).toBe(2_000_000);
    expect(result.links.length).toBe(400);
    expect(result.links[0]!.text.length).toBe(80);
    expect((result.banner as unknown as { unknown: number }).unknown).toBe(1);
    expect(result.preticked).toEqual({ count: 0, sample: 's'.repeat(90) });
    expect(result.globals).toEqual({ dataLayer: [], googleTagDataEntries: null, hasTcfApi: false, cmpGlobals: [] });
  });

  test('markup, links and banner are read in the isolated world; the page\'s variables in the main world', async () => {
    const page = new FakePage();
    await run(page);
    expect(page.calls).toEqual(expect.arrayContaining(['isolated:html', 'isolated:links', 'isolated:observe', 'main:globals']));
    expect(page.calls.filter((c) => c === 'main:html' || c === 'main:links' || c === 'main:observe')).toEqual([]);
  });

  test('without an isolated world the reads fall back to the main world', async () => {
    const page = new FakePage({ noRealm: true, html: '<html><body>' + 'fallback '.repeat(400) + '</body></html>' });
    const { result } = await run(page);
    expect(page.calls).toEqual(expect.arrayContaining(['main:html', 'main:links', 'main:observe']));
    expect(result.html).toContain('fallback');
  });
});

describe('the launch', () => {
  const tooMany = () => Promise.reject(new Error('Unable to create new browser: code: 429: message: Too many requests'));

  test('no retry when too little of the deadline would be left after the wait', async () => {
    let launches = 0;
    const launch = () => (launches++, tooMany());
    await expect(scan({}, 'https://example.com/', 'x', { deadlineMs: 20_000, launch, wait: async () => {} })).rejects.toThrow();
    expect(launches).toBe(1);
  });

  test('a 429 for the daily browser time is not retried, even with time left', async () => {
    let launches = 0;
    const launch = () => (launches++, Promise.reject(new Error('Unable to create new browser: code: 429: message: Browser time limit exceeded for today')));
    await expect(scan({}, 'https://example.com/', 'x', { launch, wait: async () => {} })).rejects.toThrow();
    expect(launches).toBe(1);
  });

  test('one retry when enough of the deadline is left', async () => {
    let launches = 0;
    const launch = () => (launches++, tooMany());
    await expect(scan({}, 'https://example.com/', 'x', { launch, wait: async () => {} })).rejects.toThrow();
    expect(launches).toBe(2);
  });
});
