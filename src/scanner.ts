// Collects raw observations through a headless browser (Cloudflare Browser Run, driven with Puppeteer).
// GDPR KEY POINT: we load the page and do NOT click any banner -> everything that fires here is
// "before consent". If non-essential trackers fire in this state = violation.
//
// The scanned page is hostile input. What it can reach is limited by the request guard and the
// address check below; what it hands back is read where its own JavaScript cannot interfere when
// possible, and re-validated in the Worker by clampScan() in every case.
import puppeteer from '@cloudflare/puppeteer';
import type { BannerObs, Phase2Obs, RawScan, ScanErrorCode } from './types';
import { CMP_SIGNATURES } from '../data/cmp-signatures';
import { decideRequest, MAX_URL_LENGTH, responseFromPrivateAddress } from './net-guard';
import { POLICY_LINK_HINTS } from './detect';
import { UX_FN, type UxObservation } from './ux';

const CMP_GLOBALS = [...new Set(CMP_SIGNATURES.flatMap((c) => c.globals))];

// Bounds on what is kept from a page. The markup and the links are cut inside the page, in the
// isolated world, before they travel to the Worker; clampScan() applies every bound again once the
// values have arrived. The page's own variables (dataLayer, google_tag_data, the consent globals) are
// read in its main world, where its scripts control the built-in functions: there the bounds can be
// defeated, so a hostile page can still send a large value, which is cut only after it has reached
// the Worker.
const MAX_HTML_CHARS = 2_000_000;
const MAX_REQUESTS = 3000;
const MAX_LINKS = 400;
const MAX_POLICY_LINKS = 60;
const MAX_LINK_TEXT = 80;
const MAX_COOKIES = 300;
const MAX_COOKIE_FIELD = 256;
const MAX_DATALAYER_ENTRIES = 200;
const MAX_DATALAYER_CHARS = 200_000;
const MAX_BANNER_LABEL = 120;
const MAX_BANNER_CONTROLS = 8;
const MAX_PRETICKED_SAMPLE = 90;
const MAX_PRETICKED_COUNT = 1000;

/** The whole browser session, launch included, ends within this time: past it the browser is
 *  closed and the scan returns `scan-timeout`. Also the unit of the daily cap's worst case. */
export const SCAN_DEADLINE_MS = 45_000;
/** Longest wait for the first load (networkidle2). */
const NAV_TIMEOUT_MS = 35_000;
/** Time kept after the first load for reading the page (waits, markup, links, globals, banner). */
const READ_RESERVE_MS = 9_000;
/** Longest wait for browser.close() once the scan is over or the deadline has passed. */
const CLOSE_TIMEOUT_MS = 5_000;

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

type Browser = Awaited<ReturnType<typeof puppeteer.launch>>;
type Page = Awaited<ReturnType<Browser['newPage']>>;
/** The browser scan() drives, as `@cloudflare/puppeteer` returns it. */
export type ScanBrowser = Browser;

/** What scan() takes from outside. Production passes none of them; the tests replace them. */
export interface ScanOptions {
  /** Deadline of the whole browser session. Default SCAN_DEADLINE_MS. */
  deadlineMs?: number;
  /** Starts a browser from the binding. Default `puppeteer.launch`. */
  launch?: (binding: unknown) => Promise<Browser>;
  /** Waits that long. Default a timer. */
  wait?: (ms: number) => Promise<void>;
}

const defaultLaunch = (binding: unknown): Promise<Browser> => puppeteer.launch(binding as Parameters<typeof puppeteer.launch>[0]);

/** What the scan has seen so far: also what a scan cut short reports. */
interface ScanState {
  url: string;
  finalUrl: string;
  status: number;
  contentType: string;
  network: { url: string; type: string }[];
}

/** The page was not read: no verdict downstream. */
const notScanned = (st: ScanState, error: ScanErrorCode): RawScan => ({
  requestedUrl: st.url,
  finalUrl: st.finalUrl,
  status: st.status,
  contentType: st.contentType,
  reachable: false,
  html: '',
  links: [],
  network: st.network.slice(), // a scan cut by the deadline may still be recording
  cookies: [],
  globals: { dataLayer: [], googleTagDataEntries: null, hasTcfApi: false, cmpGlobals: [] },
  error,
});

/** Lower-case media type without parameters ("text/html"), or ''. */
const mediaType = (header: unknown): string =>
  (typeof header === 'string' ? header : '').split(';')[0]!.trim().toLowerCase().slice(0, 100);

/** Wait before the single launch retry. */
const LAUNCH_RETRY_MS = 3500;
/** The retry happens only if at least this much of the deadline is left after the wait. */
const LAUNCH_RETRY_MIN_LEFT_MS = 30_000;

/**
 * Launches the browser, with one retry after a short wait on a 429 that says too many browsers
 * were started. The retry is for a brief 429 on a plan that allows several new browsers a second.
 * It does not get past the Workers Free limit of one new browser every 20 seconds, and a 429 for
 * the daily browser time is not retried. It runs only while enough of the deadline is left.
 */
async function launchWithRetry(io: SessionIo, binding: unknown, timeLeft: () => number): Promise<Browser> {
  const launch = () => io.launch(binding);
  try {
    return await launch();
  } catch (e) {
    const msg = String(e);
    const retry = /429|rate.?limit/i.test(msg) && !/time limit exceeded/i.test(msg) && timeLeft() - LAUNCH_RETRY_MS >= LAUNCH_RETRY_MIN_LEFT_MS;
    if (!retry) throw e;
  }
  await io.wait(LAUNCH_RETRY_MS);
  if (timeLeft() <= 0) throw new Error('launch: deadline passed before the retry');
  return await launch();
}

/** The resolved ScanOptions, passed down to every step of the session. */
interface SessionIo {
  deadlineMs: number;
  launch: (binding: unknown) => Promise<Browser>;
  wait: (ms: number) => Promise<void>;
}

async function closeQuietly(browser: Browser | null): Promise<void> {
  if (!browser) return;
  await Promise.race([browser.close().catch(() => {}), sleep(CLOSE_TIMEOUT_MS)]);
}

/**
 * Scans one page. Never takes longer than SCAN_DEADLINE_MS (plus up to CLOSE_TIMEOUT_MS to close
 * the browser): a page that blocks the browser (a busy loop, a dialog nobody answers) gets
 * `scan-timeout`, not a 180 s wait for the protocol timeout. `options` exists for the tests.
 */
export async function scan(browserBinding: unknown, url: string, userAgentSuffix: string, options: ScanOptions = {}): Promise<RawScan> {
  const deadlineMs = options.deadlineMs ?? SCAN_DEADLINE_MS;
  const io: SessionIo = { deadlineMs, launch: options.launch ?? defaultLaunch, wait: options.wait ?? sleep };
  const t0 = Date.now();
  const st: ScanState = { url, finalUrl: url, status: 0, contentType: '', network: [] };
  const session: { browser: Browser | null; over: boolean } = { browser: null, over: false };
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<RawScan>((resolve) => {
    timer = setTimeout(() => resolve(notScanned(st, 'scan-timeout')), deadlineMs);
  });
  const run = runScan(io, session, browserBinding, url, userAgentSuffix, t0, st);
  run.catch(() => {}); // after the deadline nobody awaits it any more
  try {
    return await Promise.race([run, deadline]);
  } finally {
    clearTimeout(timer);
    session.over = true;
    await closeQuietly(session.browser);
  }
}

async function runScan(
  io: SessionIo,
  session: { browser: Browser | null; over: boolean },
  browserBinding: unknown,
  url: string,
  userAgentSuffix: string,
  t0: number,
  st: ScanState,
): Promise<RawScan> {
  const elapsed = () => Date.now() - t0;
  const browser = await launchWithRetry(io, browserBinding, () => (session.over ? 0 : io.deadlineMs - elapsed()));
  session.browser = browser;
  if (session.over) {
    // The deadline passed during the launch: scan() has already closed what it knew about.
    await closeQuietly(browser);
    return notScanned(st, 'scan-timeout');
  }

  // Set by the guards below. Once one is set nothing more of the page is read or reported.
  let privateAddressHit = false;
  let blockedRedirect = false;
  const stopReason = (): ScanErrorCode | null => (privateAddressHit ? 'private-address' : blockedRedirect ? 'blocked-redirect' : null);
  let firstLoadDone = false;

  try {
    const page = await browser.newPage();

    // Other pages (popups, window.open from a click handler) are outside the request guard and
    // the address check, which watch this page only: they are closed as soon as they appear.
    // Best effort: a popup's first request leaves before it is closed (seen in a local test).
    const cdp = await page.createCDPSession().catch(() => null);
    const closeTarget = (targetId: string | undefined) =>
      targetId && cdp ? cdp.send('Target.closeTarget', { targetId }).then(() => true, () => false) : Promise.resolve(false);
    // Not earlier than this event: closing a popup while Puppeteer is still attaching it (on
    // Target.targetCreated) left the scan hanging until the deadline in a local test.
    browser.on('targetcreated', (target) => {
      try {
        if (target.type() !== 'page' || target === page.target()) return;
        closeTarget((target as unknown as { _targetId?: string })._targetId)
          .then((closed) => (closed ? undefined : target.page().then((p) => p?.close())))
          .catch(() => {});
      } catch {
        /* noop */
      }
    });
    page.on('popup', (p) => {
      p?.close().catch(() => {});
    });
    // An alert(), confirm() or prompt() blocks the page until it is answered.
    page.on('dialog', (d) => {
      (d.type() === 'beforeunload' ? d.accept() : d.dismiss()).catch(() => {});
    });
    // Requests answered by a service worker would skip the request guard.
    await page.setBypassServiceWorker(true).catch(() => {});
    // Downloads are refused. The platform may not allow it: then a download stays possible.
    try {
      if (!cdp) throw new Error('no CDP session');
      await cdp.send('Browser.setDownloadBehavior', { behavior: 'deny' }).catch(() => cdp.send('Page.setDownloadBehavior', { behavior: 'deny' }));
    } catch (e) {
      console.log('[gdpr-scanner] downloads not denied:', String(e).slice(0, 200));
    }

    await page.setViewport({ width: 1366, height: 768 });
    // The browser's own User-Agent, without the "Headless" marker, plus the scanner's suffix.
    try {
      const ua = (await browser.userAgent()).replace('HeadlessChrome/', 'Chrome/');
      await page.setUserAgent(`${ua} ${userAgentSuffix}`);
    } catch {
      /* the browser's default User-Agent stays */
    }

    // Request guard: every request, a document redirect included (it arrives here as a new
    // request to the Location), is judged by decideRequest() before it leaves. A navigation of
    // the main frame must go to an address the scanner would accept as a target.
    // A SINGLE handler: it records the observation, then continue() or abort().
    await page.setRequestInterception(true);
    page.on('request', (req) => {
      let u = '';
      let mainNavigation = false;
      try {
        u = req.url();
        mainNavigation = req.isNavigationRequest() && req.frame() === page.mainFrame();
      } catch {
        /* noop */
      }
      try {
        if (st.network.length < MAX_REQUESTS) st.network.push({ url: u.slice(0, MAX_URL_LENGTH), type: req.resourceType() });
      } catch {
        /* noop */
      }
      const decision = stopReason() ? 'abort' : decideRequest(u, mainNavigation);
      if (decision === 'continue') {
        req.continue().catch(() => {});
        return;
      }
      if (decision === 'blocked-redirect') blockedRedirect = true;
      req.abort('blockedbyclient').catch(() => {});
    });

    // The guard only sees names, and a public name can resolve to a private address. So the
    // address each response really came from is checked too: one answer from a private address
    // and the page is closed at once; every later request is aborted. Where the browser reaches
    // the web through a proxy (Cloudflare's Browser Run) the address is the proxy's and this check
    // has nothing to read: see responseFromPrivateAddress().
    page.on('response', (res) => {
      try {
        const { ip, port } = res.remoteAddress();
        if (responseFromPrivateAddress(ip, port, res.url())) {
          privateAddressHit = true;
          page.close().catch(() => {});
          return;
        }
        if (!firstLoadDone && res.request().isNavigationRequest() && res.request().frame() === page.mainFrame()) {
          st.status = res.status();
          st.contentType = mediaType(res.headers()['content-type']);
        }
      } catch {
        /* noop */
      }
    });

    try {
      // networkidle2 = waits until the JS has rendered and the network has calmed down (captures
      // SPAs and late-loading trackers), for at most NAV_TIMEOUT_MS and never into the time kept
      // for reading the page before the deadline.
      const navTimeout = Math.max(5_000, Math.min(NAV_TIMEOUT_MS, io.deadlineMs - elapsed() - READ_RESERVE_MS));
      const resp = await page.goto(url, { waitUntil: 'networkidle2', timeout: navTimeout });
      if (resp) {
        st.status = resp.status();
        st.contentType = mediaType(resp.headers()['content-type']);
      }
      st.finalUrl = page.url();
    } catch (e) {
      // Timeout (ad-heavy site that never reaches idle, or a slow one): the page may still be loaded
      // -> we try to capture it. A real error (DNS/connection) or an empty page -> not evaluable.
      const stopped = stopReason();
      if (stopped) return notScanned(st, stopped);
      const timedOut = /timeout|timed out/i.test(String(e));
      if (!timedOut) return notScanned(st, 'navigation-failed');
      const loaded = await page
        .evaluate(() => {
          const d = (globalThis as unknown as { document?: { readyState?: string; body?: unknown } }).document;
          return !!d && d.readyState !== 'loading' && !!d.body;
        })
        .catch(() => false);
      if (!loaded) return notScanned(st, 'navigation-timeout');
      st.finalUrl = page.url() || st.finalUrl;
    }
    firstLoadDone = true;
    {
      const stopped = stopReason();
      if (stopped) return notScanned(st, stopped);
    }

    const raw = await readPage(io, page, st, elapsed);
    const stopped = stopReason(); // a response from a private address may have arrived meanwhile
    if (stopped) return notScanned(st, stopped);
    return clampScan(raw);
  } catch (e) {
    // Closing the page on a private address makes every pending call fail: that is the reason
    // to report, not the error it caused.
    const stopped = stopReason();
    if (stopped) return notScanned(st, stopped);
    throw e;
  }
}

/**
 * Runs `fn` in the page's isolated world: same DOM, but the page's scripts cannot redefine the
 * built-ins it uses (slice, JSON, getters). Falls back to the main world if that world is missing.
 */
function inIsolatedWorld<A extends unknown[], R>(page: Page, fn: (...args: A) => R, ...args: A): Promise<Awaited<R>> {
  let realm: { evaluate: (f: (...a: A) => R, ...a: A) => Promise<Awaited<R>> } | null = null;
  try {
    realm = (page.mainFrame() as unknown as { isolatedRealm(): typeof realm }).isolatedRealm();
  } catch {
    realm = null;
  }
  if (realm && typeof realm.evaluate === 'function') return realm.evaluate(fn, ...args);
  return page.evaluate(fn as never, ...(args as unknown as never[])) as Promise<Awaited<R>>;
}

/** Reads the loaded page: Tier A (pre-consent state), then Tier B (scroll, reject, reload). */
async function readPage(io: SessionIo, page: Page, st: ScanState, elapsed: () => number): Promise<RawScan> {
  // networkidle2 already waited for render + network: short wait for delayed pings (consent mode).
  await io.wait(2500);

  // Markup, cut inside the page so that no more than MAX_HTML_CHARS travel to the Worker.
  const html = await inIsolatedWorld(
    page,
    (max: number) => {
      const d = (globalThis as unknown as { document?: any }).document;
      if (!d || !d.documentElement) return '';
      const doctype = d.doctype ? `<!DOCTYPE ${String(d.doctype.name)}>` : '';
      return (doctype + String(d.documentElement.outerHTML)).slice(0, max);
    },
    MAX_HTML_CHARS,
  );
  const cookieList = async () => (await page.cookies()).slice(0, MAX_COOKIES).map((c) => ({ name: c.name, domain: c.domain }));
  const cookies = await cookieList();

  // Policy links sit in the footer. On a home page with thousands of links a plain "first N"
  // cuts them off and the report says the site has no privacy policy, so they are kept first.
  const links = await inIsolatedWorld(
    page,
    (maxLinks: number, maxPolicy: number, maxUrl: number, maxText: number, hints: string[]) => {
      const d = (globalThis as unknown as { document?: any }).document;
      const policy: { href: string; text: string }[] = [];
      const other: { href: string; text: string }[] = [];
      if (!d) return policy;
      const els = d.querySelectorAll('a[href]');
      for (let i = 0; i < els.length; i++) {
        const a = els[i];
        const link = {
          href: String(a.href || '').slice(0, maxUrl),
          text: String(a.textContent || '').slice(0, 2000).trim().slice(0, maxText),
        };
        const hay = `${link.href} ${link.text}`.toLowerCase();
        if (hints.some((h) => hay.includes(h))) {
          if (policy.length < maxPolicy) policy.push(link);
        } else if (other.length < maxLinks) {
          other.push(link);
        }
      }
      return policy.concat(other).slice(0, maxLinks);
    },
    MAX_LINKS,
    MAX_POLICY_LINKS,
    MAX_URL_LENGTH,
    MAX_LINK_TEXT,
    POLICY_LINK_HINTS,
  );

  // The page's own globals exist only in its main world, where its scripts can redefine any
  // built-in: what comes back is bounded again by clampScan().
  const globals = await page.evaluate(
    (cmpGlobals: string[], maxEntries: number, maxChars: number) => {
      // Inside the page: globalThis === window. Cast to Record to avoid the DOM lib in the Worker tsconfig.
      const w = globalThis as unknown as Record<string, unknown>;
      // dataLayer: gtag pushes array-like "arguments" objects -> normalize them to arrays. Each
      // entry is serialized on its own (no functions, no cycles) and the total size is capped.
      const dataLayer: unknown[] = [];
      try {
        const raw = Array.prototype.slice.call((w['dataLayer'] as ArrayLike<unknown>) || [], 0, maxEntries);
        let used = 0;
        for (const e of raw) {
          try {
            const entry =
              e && typeof e === 'object' && !Array.isArray(e) && typeof (e as { length?: number }).length === 'number'
                ? Array.prototype.slice.call(e as ArrayLike<unknown>)
                : e;
            const text = JSON.stringify(entry);
            if (text === undefined) continue;
            used += text.length;
            if (used > maxChars) break;
            dataLayer.push(JSON.parse(text));
          } catch {
            /* entry that cannot be serialized: skipped */
          }
        }
      } catch {
        /* noop */
      }
      let googleTagDataEntries: unknown = null;
      try {
        const entries = (w['google_tag_data'] as { ics?: { entries?: unknown } } | undefined)?.ics?.entries ?? null;
        if (entries) {
          const text = JSON.stringify(entries);
          googleTagDataEntries = text && text.length <= maxChars ? JSON.parse(text) : Object.keys(entries as object).slice(0, 50);
        }
      } catch {
        /* noop */
      }
      const present = cmpGlobals.filter((g) => {
        try {
          return typeof w[g] !== 'undefined';
        } catch {
          return false;
        }
      });
      let hasTcfApi = false;
      try {
        hasTcfApi = typeof w['__tcfapi'] === 'function';
      } catch {
        /* noop */
      }
      return { dataLayer, googleTagDataEntries, hasTcfApi, cmpGlobals: present };
    },
    CMP_GLOBALS,
    MAX_DATALAYER_ENTRIES,
    MAX_DATALAYER_CHARS,
  );

  // --- UX observation of the banner + pre-ticked checkboxes (Tier A) ---
  // All DOM-side in UX_FN (ux.ts), also used after the click and after the reload in Tier B.
  // Conservative: if anything goes wrong -> null/zero, no accusation.
  // Extra wait: many custom banners appear with a setTimeout after load: without it the banner
  // is still hidden and is not observed (a conservative miss).
  await io.wait(1200);
  const observe = async () => (await inIsolatedWorld(page, UX_FN, 'observe').catch(() => null)) as UxObservation | null;
  const ux = await observe();
  const banner = ux?.banner ?? null;
  const preticked = ux?.preticked ?? { count: 0, sample: '' };

  // SNAPSHOT for the main PRE-consent analysis: the Tier B phases (scroll, click, reload) generate
  // more requests/cookies that must NOT pollute the "pre-consent" judgment (they go into the phase2 diffs).
  const networkMain = st.network.slice();

  // --- Tier B: scroll test + reject test, same browser session ---
  // Each phase runs only if it fits in the time left before the deadline; otherwise Tier A is
  // kept (never lose the base verdict for one extra test). Evidence = ONLY new non-essential
  // cookies (certain); network requests after the phase are not judged (conservative).
  let phase2: RawScan['phase2'];
  try {
    const diff = (after: { name: string; domain: string }[], before: { name: string; domain: string }[]) =>
      after.filter((a) => !before.some((b) => b.name === a.name && b.domain === a.domain));

    // 1) SCROLL TEST (~2 s): scrolling is NOT consent (Italian DPA guidelines 231/2021; EDPB Ex. 16).
    //    If scrolling makes non-essential cookies appear = the site treats scrolling as consent.
    if (elapsed() < io.deadlineMs - 6_000) {
      const cookiesPreScroll = await cookieList();
      await page
        .evaluate(() => {
          const w = globalThis as unknown as { scrollTo?: (x: number, y: number) => void; document?: any };
          try {
            w.scrollTo?.(0, (w.document?.body?.scrollHeight as number) || 6000);
          } catch {
            /* noop */
          }
        })
        .catch(() => {});
      await io.wait(1600);
      const cookiesPostScroll = await cookieList();
      phase2 = { scroll: { newCookies: diff(cookiesPostScroll, cookiesPreScroll) } };

      // 2) REJECT TEST (only if the banner has a reject control, ~6-10 s, started before 18 s):
      //    clicks "Rifiuta" (Reject), checks that the banner disappears, that NO tracking cookies
      //    fire after the rejection, and that the choice is remembered on reload (banner not shown
      //    again, guidelines 231/2021 s.7.1).
      if (banner?.found && banner.reject && elapsed() < 18_000) {
        const clickRes = (await inIsolatedWorld(page, UX_FN, 'click-reject').catch(() => null)) as { clicked?: boolean } | null;
        if (clickRes?.clicked) {
          await io.wait(1600);
          const afterClick = await observe();
          const bannerGone = bannerGoneAfterReject(afterClick);
          const cookiesPostReject = await cookieList();
          const rej: NonNullable<RawScan['phase2']>['reject'] = {
            clicked: true,
            bannerGone,
            newCookies: diff(cookiesPostReject, cookiesPostScroll),
            reloaded: false,
            bannerReappeared: false,
          };
          // The reload (at most 12 s + 2.5 s) starts only before 26 s, so it ends before the deadline.
          if (bannerGone && elapsed() < 26_000) {
            try {
              await page.goto(st.finalUrl, { waitUntil: 'domcontentloaded', timeout: 12_000 });
              await io.wait(2500);
              const again = await observe();
              rej.reloaded = true;
              rej.bannerReappeared = !!(again?.banner?.found && (again.banner.accept || again.banner.reject));
            } catch {
              /* reload failed: reloaded=false, no judgment on reappearance */
            }
          }
          phase2.reject = rej;
        }
      }
    }
  } catch {
    /* Tier B is best-effort: on error only Tier A remains */
  }

  return {
    requestedUrl: st.url,
    finalUrl: st.finalUrl,
    status: st.status,
    contentType: st.contentType,
    reachable: true,
    html,
    links,
    network: networkMain,
    cookies,
    globals,
    banner,
    preticked,
    phase2,
  };
}

/**
 * Whether the banner went away after the reject click. If it is STILL visible, the click may have
 * opened a preferences panel: ambiguous state, no judgments downstream (false disables them all).
 * An observation that failed (null) is not "gone" either.
 */
export function bannerGoneAfterReject(afterClick: UxObservation | null): boolean {
  return afterClick !== null && !afterClick.banner?.found;
}

// ---------------------------------------------------------------------------------------------
// clampScan: every value that came from the page, checked again in the Worker.

const text = (v: unknown, max: number): string =>
  (typeof v === 'string' ? v : typeof v === 'number' || typeof v === 'boolean' ? String(v) : '').slice(0, max);
const list = (v: unknown, max: number): unknown[] => (Array.isArray(v) ? v.slice(0, max) : []);
const field = (v: unknown, key: string): unknown => (v && typeof v === 'object' ? (v as Record<string, unknown>)[key] : undefined);
const intIn = (v: unknown, min: number, max: number): number => {
  const n = typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : min;
  return Math.min(max, Math.max(min, n));
};
const cookieOf = (c: unknown) => ({ name: text(field(c, 'name'), MAX_COOKIE_FIELD), domain: text(field(c, 'domain'), MAX_COOKIE_FIELD) });

/** JSON size of a value, or Infinity when it cannot be serialized. */
function jsonSize(v: unknown): number {
  try {
    const s = JSON.stringify(v);
    return s === undefined ? 0 : s.length;
  } catch {
    return Infinity;
  }
}

/**
 * The value each banner field takes when the page sent it missing or malformed: the one that raises
 * no finding downstream. No banner; no accept control; a reject and a close control; a link to the
 * notice; one unrecognized control (the banner is judged only when that count is 0). The findings
 * `banner-no-reject` and `banner-no-policy-link` need the opposite values, so doubt never accuses.
 */
const BANNER_DOUBT: Record<string, boolean | number> = {
  found: false,
  accept: false,
  reject: true,
  close: true,
  settings: true,
  policyLink: true,
  unknown: 1,
};

/**
 * Re-validates a scan in the Worker: types coerced, strings cut, arrays sliced, sizes bounded.
 * The values were produced by the scanned page (in its main world they may come from redefined
 * built-ins), so none of the bounds applied in the page is trusted. Pure: no I/O.
 */
export function clampScan(raw: RawScan): RawScan {
  if (!raw || typeof raw !== 'object') raw = {} as RawScan;
  const g = typeof raw.globals === 'object' && raw.globals ? raw.globals : ({} as Partial<RawScan['globals']>);

  const dataLayer: unknown[] = [];
  let used = 0;
  for (const entry of list(g.dataLayer, MAX_DATALAYER_ENTRIES)) {
    const size = jsonSize(entry);
    if (size === Infinity) continue;
    used += size;
    if (used > MAX_DATALAYER_CHARS) break;
    dataLayer.push(entry);
  }
  const gtd = g.googleTagDataEntries ?? null;
  const googleTagDataEntries = jsonSize(gtd) <= MAX_DATALAYER_CHARS ? gtd : null;
  const known = new Set(CMP_GLOBALS);
  const cmpGlobals = [...new Set(list(g.cmpGlobals, CMP_GLOBALS.length * 2).filter((x): x is string => typeof x === 'string' && known.has(x)))];

  let banner: RawScan['banner'] = raw.banner === undefined ? undefined : null;
  if (raw.banner && typeof raw.banner === 'object') {
    // The banner's fields are flags and counters (ux.ts decides which). A field of BANNER_DOUBT that
    // is missing or malformed keeps its doubt value. Any other field: a boolean is kept, a
    // non-negative integer is capped, anything else is dropped. `dbg` holds labels.
    const b = raw.banner as BannerObs & { dbg?: unknown };
    const out: Record<string, unknown> = { ...BANNER_DOUBT };
    for (const [k, v] of Object.entries(b).slice(0, 32)) {
      if (!/^[a-zA-Z]{1,32}$/.test(k) || k === 'dbg') continue;
      const kind = Object.prototype.hasOwnProperty.call(BANNER_DOUBT, k) ? typeof BANNER_DOUBT[k] : typeof v;
      if (typeof v === 'boolean' && kind === 'boolean') out[k] = v;
      else if (typeof v === 'number' && kind === 'number' && Number.isInteger(v) && v >= 0) out[k] = Math.min(v, MAX_PRETICKED_COUNT);
    }
    if (b.dbg !== undefined) {
      out.dbg = {
        el: text(field(b.dbg, 'el'), MAX_BANNER_LABEL),
        ctrls: list(field(b.dbg, 'ctrls'), MAX_BANNER_CONTROLS).map((c) => text(c, MAX_BANNER_LABEL)),
      };
    }
    banner = out as unknown as BannerObs;
  }

  let phase2: Phase2Obs | undefined;
  if (raw.phase2 && typeof raw.phase2 === 'object') {
    phase2 = { scroll: { newCookies: list(field(raw.phase2.scroll, 'newCookies'), MAX_COOKIES).map(cookieOf) } };
    const r = raw.phase2.reject;
    if (r && typeof r === 'object') {
      phase2.reject = {
        clicked: r.clicked === true,
        bannerGone: r.bannerGone === true,
        newCookies: list(r.newCookies, MAX_COOKIES).map(cookieOf),
        reloaded: r.reloaded === true,
        bannerReappeared: r.bannerReappeared === true,
      };
    }
  }

  const out: RawScan = {
    requestedUrl: text(raw.requestedUrl, MAX_URL_LENGTH),
    finalUrl: text(raw.finalUrl, MAX_URL_LENGTH),
    status: intIn(raw.status, 0, 999),
    reachable: raw.reachable === true,
    html: text(raw.html, MAX_HTML_CHARS),
    links: list(raw.links, MAX_LINKS).map((l) => ({ href: text(field(l, 'href'), MAX_URL_LENGTH), text: text(field(l, 'text'), MAX_LINK_TEXT) })),
    network: list(raw.network, MAX_REQUESTS).map((r) => ({ url: text(field(r, 'url'), MAX_URL_LENGTH), type: text(field(r, 'type'), 40) })),
    cookies: list(raw.cookies, MAX_COOKIES).map(cookieOf),
    globals: { dataLayer, googleTagDataEntries, hasTcfApi: g.hasTcfApi === true, cmpGlobals },
  };
  if (raw.contentType !== undefined) out.contentType = mediaType(raw.contentType);
  if (banner !== undefined) out.banner = banner;
  if (raw.preticked !== undefined) {
    out.preticked = {
      count: intIn(field(raw.preticked, 'count'), 0, MAX_PRETICKED_COUNT),
      sample: text(field(raw.preticked, 'sample'), MAX_PRETICKED_SAMPLE),
    };
  }
  if (phase2) out.phase2 = phase2;
  if (raw.error !== undefined) out.error = raw.error;
  return out;
}
