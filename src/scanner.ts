// Collects raw observations through a headless browser (Browser Rendering / Puppeteer).
// GDPR KEY POINT: we load the page and do NOT click any banner -> everything that fires here is
// "before consent". If non-essential trackers fire in this state = violation.
import puppeteer from '@cloudflare/puppeteer';
import type { RawScan } from './types';
import { CMP_SIGNATURES } from '../data/cmp-signatures';

const CMP_GLOBALS = [...new Set(CMP_SIGNATURES.flatMap((c) => c.globals))];

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** Shape of the UX_FN result in 'observe' mode. */
interface UxObservation {
  banner: (NonNullable<RawScan['banner']> & { dbg?: unknown }) | null;
  preticked: { count: number; sample: string };
}

/**
 * Single DOM-side function for the UX observation (Tier A) and the reject click (Tier B).
 * Serialized by puppeteer: it MUST be self-contained (no closure over Node variables).
 * mode 'observe' -> { banner, preticked }; mode 'click-reject' -> { clicked }.
 * The Worker tsconfig has no DOM lib: document is accessed via a cast, as in the globals evaluate.
 */
const UX_FN = (mode: string) => {
  const w = globalThis as unknown as { document?: any; getComputedStyle?: (el: any) => any };
  const d = w.document;
  const empty = { banner: null, preticked: { count: 0, sample: '' } };
  if (!d) return mode === 'click-reject' ? { clicked: false } : empty;

  const visible = (el: any): boolean => {
    try {
      const r = el.getBoundingClientRect();
      if (!r || r.width < 2 || r.height < 2) return false;
      const cs = w.getComputedStyle ? w.getComputedStyle(el) : null;
      if (cs && (cs.display === 'none' || cs.visibility === 'hidden' || Number(cs.opacity) === 0)) return false;
      return true;
    } catch {
      return false;
    }
  };

  const ACCEPT_RE = /accett|acconsent|accept|agree|allow (?:all|cookies)|consenti|aceptar|va bene|ho capito|got it|entendido/i;
  const REJECT_RE = /rifiut|reject|decline|deny|nega|rechaz|continua senza|senza accettare|only (?:essential|necessary)|solo (?:necessari|essenzial|los necesarios)|necessari soltanto|essenziali soltanto/i;
  // The ACCEPT/REJECT/CLOSE/POLICY patterns are data: Italian, Spanish and English button labels
  // matched against the scanned site's banner text.
  const CLOSE_RE = /^(?:x|×|✕|✖)$|close|chiudi|cerrar/i;
  const POLICY_RE = /privacy|cookie|informativa|pol[ii]tica/i;

  // A REAL cookie banner is an overlay (fixed/sticky, itself or a nearby ancestor): this excludes the
  // in-flow consent blocks inside forms (e.g. div.cnt-mf-consent of a contact form, a false match).
  const isOverlay = (el: any): boolean => {
    let cur = el;
    for (let i = 0; i < 4 && cur && cur.nodeType === 1; i++) {
      try {
        const cs = w.getComputedStyle ? w.getComputedStyle(cur) : null;
        if (cs && (cs.position === 'fixed' || cs.position === 'sticky')) return true;
      } catch {
        /* noop */
      }
      cur = cur.parentElement;
    }
    return false;
  };

  /** Finds the largest visible cookie banner (candidates: id/class cookie/consent/gdpr + overlay). */
  const findBanner = (): any => {
    const cands: any[] = Array.prototype.slice
      .call(d.querySelectorAll('[id*="cookie" i],[class*="cookie" i],[id*="consent" i],[class*="consent" i],[id*="gdpr" i],[class*="gdpr" i],[id*="iubenda" i],[class*="cc-window" i]'))
      .filter((el: any) => {
        if (!visible(el)) return false;
        if (!isOverlay(el)) return false;
        const t = String(el.textContent || '');
        if (t.length < 30 || t.length > 6000) return false; // neither icons nor whole pages
        if (!/cookie|consens|consent|trattament|tracciament/i.test(t)) return false;
        return !!el.querySelector('button,[role="button"],a,input[type="button"],input[type="submit"]');
      });
    let best: any = null;
    let bestArea = 0;
    for (const el of cands) {
      const r = el.getBoundingClientRect();
      const area = r.width * r.height;
      if (area > bestArea) {
        bestArea = area;
        best = el;
      }
    }
    return best;
  };

  const controls = (root: any): any[] =>
    Array.prototype.slice
      .call(root.querySelectorAll('button,[role="button"],a,input[type="button"],input[type="submit"]'))
      .filter(visible);

  const label = (el: any) =>
    `${String(el.textContent || '').trim()} ${String(el.getAttribute?.('aria-label') || '')} ${String(el.value || '')}`.trim().slice(0, 120);

  // --- click-reject mode (Tier B): clicks the first reject control in the banner ---
  if (mode === 'click-reject') {
    try {
      const best = findBanner();
      if (!best) return { clicked: false };
      for (const c of controls(best)) {
        const t = label(c);
        if (t && REJECT_RE.test(t)) {
          c.click();
          return { clicked: true };
        }
      }
    } catch {
      /* noop */
    }
    return { clicked: false };
  }

  // --- observe mode (Tier A): first-level banner + pre-ticked checkboxes ---
  let banner: any = null;
  try {
    const best = findBanner();
    if (best) {
      const ctrls = controls(best);
      let accept = false;
      let reject = false;
      let close = false;
      for (const c of ctrls) {
        const t = label(c);
        if (!t) continue;
        if (REJECT_RE.test(t)) { reject = true; continue; } // reject first: "non accettare" (Italian: do not accept) also matches ACCEPT_RE
        if (ACCEPT_RE.test(t)) { accept = true; continue; }
        if (t.length <= 24 && CLOSE_RE.test(t)) close = true;
      }
      const policyLink = Array.prototype.slice
        .call(best.querySelectorAll('a[href]'))
        .some((a: any) => POLICY_RE.test(`${String(a.getAttribute('href') || '')} ${String(a.textContent || '')}`));
      banner = {
        found: true,
        accept,
        reject,
        close,
        policyLink,
        // observability (downstream debug only): chosen element + labels of the controls seen
        dbg: {
          el: `${String(best.tagName || '')}.${String(best.className || '').slice(0, 80)}`,
          ctrls: ctrls.map(label).slice(0, 8),
        },
      };
    }
  } catch {
    banner = null;
  }

  // pre-ticked consent checkboxes in forms (EDPB: pre-ticked = invalid consent)
  let count = 0;
  let sample = '';
  try {
    const boxes: any[] = Array.prototype.slice.call(d.querySelectorAll('form input[type="checkbox"]'));
    // Data: Italian/Spanish/English words that mark a checkbox as consent or marketing.
    const CTX_RE = /consens|acconsent|privacy|informativa|newsletter|marketing|promozion|comunicazioni commerciali|profilaz|consent|subscribe|suscri|acepto/i;
    for (const b of boxes) {
      if (!b.checked) continue;
      if (!visible(b)) continue; // honeypots/hidden checkboxes: cannot be judged
      let ctx = '';
      try {
        const id = b.getAttribute('id');
        const lab = id ? d.querySelector(`label[for="${id}"]`) : null;
        ctx = String((lab || b.closest('label') || b.parentElement || {}).textContent || '').trim().slice(0, 160);
      } catch {
        /* noop */
      }
      if (!CTX_RE.test(ctx)) continue; // conservative: only checkboxes that are clearly consent/marketing
      count++;
      if (!sample) sample = ctx.slice(0, 90);
    }
  } catch {
    /* noop */
  }

  return { banner, preticked: { count, sample } };
};

/** launch with a single retry on 429 (the Free tier limits the rate of new browsers). */
async function launchWithRetry(binding: unknown, attempts = 2): Promise<Awaited<ReturnType<typeof puppeteer.launch>>> {
  for (let i = 0; i < attempts; i++) {
    try {
      return await puppeteer.launch(binding as Parameters<typeof puppeteer.launch>[0]);
    } catch (e) {
      if (i < attempts - 1 && /429|rate.?limit/i.test(String(e))) {
        await sleep(3500);
        continue;
      }
      throw e;
    }
  }
  throw new Error('launch: unreachable');
}

/** Private or internal host (anti-SSRF), aligned with normalizeUrl in index.ts. Used by the request interception. */
function isPrivateHost(rawHost: string): boolean {
  const host = (rawHost || '').toLowerCase();
  if (!host) return true;
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    return true;
  }
  if (host.includes(':')) return true; // IPv6 literal
  // Literal IP in any encoding (decimal, hex or octal, bare or dotted)
  if (host.split('.').every((p) => /^(?:0x[0-9a-f]+|\d+)$/i.test(p))) {
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
      const p = host.split('.').map(Number);
      if (p[0] === 0 || p[0] === 10 || p[0] === 127) return true;
      if (p[0] === 169 && p[1] === 254) return true;
      if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
      if (p[0] === 192 && p[1] === 168) return true;
      if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;
      return false; // public IPv4 (e.g. a sub-resource via IP) -> allowed
    }
    return true; // obfuscated/non-standard IP form -> block
  }
  return false; // normal hostname (domain) -> allowed
}

export async function scan(browserBinding: unknown, url: string, userAgentSuffix = 'gdpr-scanner/0.1'): Promise<RawScan> {
  const t0 = Date.now(); // budget-guard Tier B: the caller is expected to cut off at ~55s
  const network: { url: string; type: string }[] = [];
  let browser: Awaited<ReturnType<typeof puppeteer.launch>> | null = null;

  try {
    browser = await launchWithRetry(browserBinding);
    const page = await browser.newPage();
    await page.setViewport({ width: 1366, height: 768 });
    await page.setUserAgent(
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 ' + userAgentSuffix,
    );

    // Request-level anti-SSRF: with interception on, we ABORT every request (including 3xx redirects,
    // which arrive here as a new request to the Location) aimed at a private/internal host. This way
    // a site answering 302 -> http://169.254.169.254/ never triggers the internal fetch and the content
    // never reaches the report. A SINGLE handler: it records the observation, then continue() or abort().
    // Re-tested on a stable network on 2026-06-20.
    await page.setRequestInterception(true);
    page.on('request', (req) => {
      let u = '';
      try {
        u = req.url();
      } catch {
        /* noop */
      }
      try {
        network.push({ url: u, type: req.resourceType() });
      } catch {
        /* noop */
      }
      try {
        const parsed = new URL(u);
        // Only http(s): data:, blob: and about: URLs have an empty hostname and must NOT be blocked (inline images etc.).
        if ((parsed.protocol === 'http:' || parsed.protocol === 'https:') && isPrivateHost(parsed.hostname)) {
          req.abort('blockedbyclient').catch(() => {});
          return;
        }
      } catch {
        /* unparsable url: let the default below decide */
      }
      req.continue().catch(() => {});
    });

    let status = 0;
    let finalUrl = url;
    try {
      // networkidle2 = waits until the JS has rendered and the network has calmed down (captures SPAs + late-loading
      // trackers). 25->35s (2026-07-05): heavy sites/slow SPAs
      // did not finish rendering in time -> "empty" page -> no result. The Tier B budget guard
      // below skips the interactive phases if the load already used up the time, so the scan
      // stays under the caller's timeout (55s).
      const resp = await page.goto(url, { waitUntil: 'networkidle2', timeout: 35000 });
      status = resp ? resp.status() : 0;
      finalUrl = page.url();
    } catch (e) {
      // Timeout (ad-heavy site that never reaches idle, or a slow one): the page may still be loaded
      // -> we try to capture it. A real error (DNS/connection) or an empty page -> not evaluable.
      const loaded = await page
        .evaluate(() => {
          const d = (globalThis as unknown as { document?: { readyState?: string; body?: unknown } }).document;
          return !!d && d.readyState !== 'loading' && !!d.body;
        })
        .catch(() => false);
      if (!/timeout|timed out/i.test(String(e)) || !loaded) {
        return {
          requestedUrl: url,
          finalUrl: finalUrl,
          status,
          reachable: false,
          html: '',
          links: [],
          network,
          cookies: [],
          globals: { dataLayer: [], googleTagDataEntries: null, hasTcfApi: false, cmpGlobals: [] },
          error: `navigation: ${String(e)}`,
        };
      }
      finalUrl = page.url() || finalUrl;
    }

    // SSRF (EXP-1), defense in depth: the interception above already aborts fetches to private hosts,
    // but if for any reason we still ended up on an internal host, we do NOT process the page.
    try {
      if (isPrivateHost(new URL(finalUrl).hostname)) {
        return {
          requestedUrl: url,
          finalUrl,
          status,
          reachable: false,
          html: '',
          links: [],
          network,
          cookies: [],
          globals: { dataLayer: [], googleTagDataEntries: null, hasTcfApi: false, cmpGlobals: [] },
          error: 'redirect-to-private',
        };
      }
    } catch {
      /* unparsable finalUrl: carry on */
    }

    // networkidle2 already waited for render + network: short wait for delayed pings (consent mode).
    await sleep(2500);

    const html = await page.content();
    const cookies = (await page.cookies()).map((c) => ({ name: c.name, domain: c.domain }));

    const links = (await page.$$eval('a[href]', (els: unknown[]) =>
      (els as Array<{ href?: unknown; textContent?: unknown }>).slice(0, 400).map((a) => ({
        href: String(a.href || ''),
        text: String(a.textContent || '').trim().slice(0, 80),
      })),
    )) as { href: string; text: string }[];

    const globals = await page.evaluate((cmpGlobals: string[]) => {
      // Inside the page: globalThis === window. Cast to Record to avoid the DOM lib in the Worker tsconfig.
      const w = globalThis as unknown as Record<string, unknown>;
      // dataLayer: gtag pushes array-like "arguments" objects -> normalize them to arrays.
      let dl: unknown[] = [];
      try {
        const raw = (w['dataLayer'] as unknown[]) || [];
        dl = raw.map((e) => {
          try {
            if (Array.isArray(e)) return e.slice();
            if (e && typeof e === 'object' && typeof (e as { length?: number }).length === 'number')
              return Array.prototype.slice.call(e as ArrayLike<unknown>);
            return e;
          } catch {
            return null;
          }
        });
      } catch {
        /* noop */
      }
      let gtde: unknown = null;
      try {
        const gtd = w['google_tag_data'] as { ics?: { entries?: unknown } } | undefined;
        gtde = gtd?.ics?.entries ?? null;
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
      let hasTcf = false;
      try {
        hasTcf = typeof w['__tcfapi'] === 'function';
      } catch {
        /* noop */
      }
      // Serialize safely (no functions, no cycles).
      let gtdeSafe: unknown = null;
      try {
        gtdeSafe = JSON.parse(JSON.stringify(gtde));
      } catch {
        gtdeSafe = gtde ? Object.keys(gtde as object) : null;
      }
      let dlSafe: unknown[] = [];
      try {
        dlSafe = JSON.parse(JSON.stringify(dl));
      } catch {
        dlSafe = [];
      }
      return { dataLayer: dlSafe, googleTagDataEntries: gtdeSafe, hasTcfApi: hasTcf, cmpGlobals: present };
    }, CMP_GLOBALS);

    // --- UX observation of the banner + pre-ticked checkboxes (Tier A, 2026-07-04) ---
    // All DOM-side in UX_FN (module scope, also reused after the click and after the reload in Tier B).
    // Conservative: if anything goes wrong -> null/zero, no accusation.
    // Extra wait: many custom banners appear with a setTimeout after load (e.g. on some sites
    // after a few seconds): without it the banner is still hidden and is not observed (a conservative miss).
    await sleep(1200);
    const ux = (await page.evaluate(UX_FN, 'observe').catch(() => null)) as UxObservation | null;
    const banner = ux?.banner ?? null;
    const preticked = ux?.preticked ?? { count: 0, sample: '' };

    // SNAPSHOT for the main PRE-consent analysis: the Tier B phases (scroll, click, reload) generate
    // more requests/cookies that must NOT pollute the "pre-consent" judgment (they go into the phase2 diffs).
    const networkMain = network.slice();

    // --- Tier B: scroll test + reject test, same browser session ---
    // Budget-guarded: the caller cuts off at 55s -> if time is short the phase is skipped and Tier A is
    // kept (never lose the base verdict for one extra test). Evidence = ONLY new non-essential
    // cookies (certain); network requests after the phase are not judged (conservative).
    let phase2: RawScan['phase2'];
    try {
      const elapsed = () => Date.now() - t0;
      const cookieList = async () => (await page.cookies()).map((c) => ({ name: c.name, domain: c.domain }));
      const diff = (after: { name: string; domain: string }[], before: { name: string; domain: string }[]) =>
        after.filter((a) => !before.some((b) => b.name === a.name && b.domain === a.domain));

      // 1) SCROLL TEST (always, ~2s): scrolling is NOT consent (Italian DPA guidelines 231/2021; EDPB Ex. 16).
      //    If scrolling makes non-essential cookies appear = the site treats scrolling as consent.
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
      await sleep(1600);
      const cookiesPostScroll = await cookieList();
      phase2 = { scroll: { newCookies: diff(cookiesPostScroll, cookiesPreScroll) } };

      // 2) REJECT TEST (only if the banner has a reject control, ~6-10s): clicks "Rifiuta" (Reject),
      //    checks that the banner disappears, that NO tracking cookies fire after the rejection,
      //    and that the choice is remembered on reload (banner not shown again, guidelines 231/2021 s.7.1).
      if (banner?.found && banner.reject && elapsed() < 18_000) {
        const clickRes = (await page.evaluate(UX_FN, 'click-reject').catch(() => null)) as { clicked?: boolean } | null;
        if (clickRes?.clicked) {
          await sleep(1600);
          const afterClick = (await page.evaluate(UX_FN, 'observe').catch(() => null)) as UxObservation | null;
          // If the banner is STILL visible, the click may have opened a preferences panel:
          // ambiguous state, no judgments downstream (bannerGone=false disables them all).
          const bannerGone = !afterClick?.banner?.found;
          const cookiesPostReject = await cookieList();
          const rej: NonNullable<RawScan['phase2']>['reject'] = {
            clicked: true,
            bannerGone,
            newCookies: diff(cookiesPostReject, cookiesPostScroll),
            reloaded: false,
            bannerReappeared: false,
          };
          if (bannerGone && elapsed() < 26_000) {
            try {
              await page.goto(finalUrl, { waitUntil: 'domcontentloaded', timeout: 12_000 });
              await sleep(2500);
              const again = (await page.evaluate(UX_FN, 'observe').catch(() => null)) as UxObservation | null;
              rej.reloaded = true;
              rej.bannerReappeared = !!(again?.banner?.found && (again.banner.accept || again.banner.reject));
            } catch {
              /* reload failed: reloaded=false, no judgment on reappearance */
            }
          }
          phase2.reject = rej;
        }
      }
    } catch {
      /* Tier B is best-effort: on error only Tier A remains */
    }

    return {
      requestedUrl: url,
      finalUrl,
      status,
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
  } finally {
    if (browser) {
      try {
        await browser.close();
      } catch {
        /* noop */
      }
    }
  }
}
