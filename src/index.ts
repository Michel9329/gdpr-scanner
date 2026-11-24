// gdpr-scanner Worker: POST /scan {url} -> PrivacyResult.
// Closed by default: SCANNER_SECRET must be set, and callers must send `Authorization: Bearer <SCANNER_SECRET>`.
import { scan } from './scanner';
import { buildResult, notScannedResult } from './verdict';
import { checkPolicyContent } from './policy-check';
import { normalizeTargetUrl } from './net-guard';
import type { PrivacyResult } from './types';

export interface Env {
  BROWSER: unknown;
  SCANNER_SECRET?: string;
  SCAN_KV?: KVNamespace;
  /** Optional. Appended to the User-Agent so site owners can identify the scanner, e.g. "my-scanner/1.0 (+https://example.com/about)". */
  SCANNER_UA_SUFFIX?: string;
  /** Optional. Max browser sessions per UTC day (default 20). */
  DAILY_CAP?: string;
  /** Optional. "1" lets a request ask for raw details with the `x-debug: 1` header. Off by default. */
  DEBUG?: string;
}

/** The two steps that leave the Worker. Tests replace them; production uses the real ones. */
export interface Deps {
  scan: typeof scan;
  checkPolicyContent: typeof checkPolicyContent;
}
const realDeps: Deps = { scan, checkPolicyContent };

// Default daily cap. Workers Free gives 600 seconds of browser time a day
// (developers.cloudflare.com/browser-run/limits/). The cap counts sessions, not seconds. A session
// lasts at most the 45-second scan deadline (SCAN_DEADLINE_MS in scanner.ts) plus up to 5 s to close
// the browser, so 20 sessions use at most 1,000 s; a browser that does not close in those 5 s keeps
// using time until Cloudflare's 60-second inactivity timeout. The live sites scanned for version 0.2,
// on a local Chromium, took 8 to 12 s each: at 12 s a scan, 20 scans use 240 s; at 25 s, 500 s.
// The cap is the operator's to set from their plan (DAILY_CAP).
const DEFAULT_DAILY_CAP = 20;
// The same URL is not scanned again for 6 hours. An authorized caller can force it with `x-fresh: 1`.
const CACHE_TTL = 60 * 60 * 6;
const COUNTER_TTL = 60 * 60 * 48;
// A short secret can be guessed or brute-forced: below this length /scan refuses to run.
const MIN_SECRET_LENGTH = 32;
const DEFAULT_UA_SUFFIX = 'gdpr-scanner/0.2';

/** Constant-time comparison: HMAC both sides with a per-call random key (equal length digests), then compare the digests byte by byte
 *  (portable: crypto.subtle.timingSafeEqual exists only in Workers, not in Bun where the tests run). */
async function secretMatches(given: string, expected: string): Promise<boolean> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', crypto.getRandomValues(new Uint8Array(32)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const [a, b] = await Promise.all([crypto.subtle.sign('HMAC', key, enc.encode(given)), crypto.subtle.sign('HMAC', key, enc.encode(expected))]);
  const x = new Uint8Array(a);
  const y = new Uint8Array(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < x.length; i++) diff |= x[i]! ^ (y[i] ?? 0);
  return diff === 0;
}

export async function handleRequest(req: Request, env: Env, ctx: ExecutionContext, deps: Deps = realDeps): Promise<Response> {
  const url = new URL(req.url);

  if (req.method === 'GET' && url.pathname === '/') {
    return new Response('gdpr-scanner ok', { status: 200 });
  }
  if (req.method !== 'POST' || url.pathname !== '/scan') {
    return json({ error: 'not-found' }, 404);
  }

  // Auth: closed by default. Without SCANNER_SECRET the endpoint refuses to run (it would let anyone
  // spend your Browser Run minutes). With a wrong or missing token it answers 401.
  if (!env.SCANNER_SECRET || env.SCANNER_SECRET.length < MIN_SECRET_LENGTH) {
    return json(
      { error: 'not-configured', message: `Set the SCANNER_SECRET secret (at least ${MIN_SECRET_LENGTH} characters) before using /scan.` },
      503,
    );
  }
  if (!(await secretMatches(req.headers.get('authorization') || '', `Bearer ${env.SCANNER_SECRET}`))) {
    return json({ error: 'unauthorized' }, 401);
  }
  // The daily cap lives in KV: without it scans would be unlimited, so refuse to run.
  const kv = env.SCAN_KV;
  if (!kv) {
    return json({ error: 'not-configured', message: 'Configure the SCAN_KV binding (see wrangler.toml) before using /scan: it holds the daily cap and the cache.' }, 503);
  }

  let body: { url?: unknown } | null = null;
  try {
    body = (await req.json()) as { url?: unknown };
  } catch {
    return json({ error: 'bad-json' }, 400);
  }

  const target = normalizeTargetUrl(typeof body?.url === 'string' ? body.url : '');
  if (!target) return json({ error: 'bad-url' }, 400);
  const cacheKey = await scanCacheKey(target);

  // 1) Cache of the exact URL asked for: avoids a new browser session (saves budget, faster). The
  //    key is the full URL, never the host: a verdict read from one page, or from wherever that page
  //    redirected, is not the verdict of the other pages of the site.
  if (req.headers.get('x-fresh') !== '1') {
    try {
      const cached = await kv.get(cacheKey);
      if (cached) return json({ ...JSON.parse(cached), cached: true }, 200);
    } catch {
      /* a cache that cannot be read is a cache miss */
    }
  }

  // 2) Daily cap. The slot is taken BEFORE the browser starts: a scan that fails or times out has
  //    still spent browser time, and a cap that counted only successful scans would not hold
  //    against a caller who sends pages that never load. If the counter cannot be read or
  //    written the scan does not run.
  const dailyCap = positiveInt(env.DAILY_CAP) ?? DEFAULT_DAILY_CAP;
  const counterKey = `count:${new Date().toISOString().slice(0, 10)}`;
  try {
    const used = parseInt((await kv.get(counterKey)) || '0', 10) || 0;
    if (used >= dailyCap) return json(notScannedResult(target, 'daily-budget'), 200);
    await kv.put(counterKey, String(used + 1), { expirationTtl: COUNTER_TTL });
  } catch {
    return json(notScannedResult(target, 'budget-unavailable'), 200);
  }

  // 3) The scan.
  const wantsDebug = env.DEBUG === '1' && req.headers.get('x-debug') === '1';
  const suffix = env.SCANNER_UA_SUFFIX || DEFAULT_UA_SUFFIX;
  let result: PrivacyResult;
  let debug: Record<string, unknown> | undefined;
  try {
    const raw = await deps.scan(env.BROWSER, target, suffix);
    // Minimum notice content (Arts. 12-13): plain fetch, zero browser time.
    // Fails soft (checked:false) on SPA/timeout/suspicious redirects -> no finding.
    const policyCheck = raw.reachable ? await deps.checkPolicyContent(raw, `Mozilla/5.0 ${suffix}`) : { checked: false, missing: [] };
    result = buildResult(raw, policyCheck);
    if (wantsDebug) {
      const requestUrls = raw.network.map((r) => r.url).join(' ');
      debug = {
        banner: raw.banner ?? null,
        preticked: raw.preticked ?? null,
        phase2: raw.phase2 ?? null,
        policyCheck,
        cookies: raw.cookies.map((c) => c.name),
        gcs: (requestUrls.match(/[?&]gcs=(G1\w+)/) || [])[1] || null,
        gcd: /[?&]gcd=/.test(requestUrls),
        requests: raw.network.length,
      };
    }
  } catch (e) {
    // Unexpected error: "not evaluable" (conservative), not a 500. The detail goes to the Worker
    // log, and to the caller only in debug mode.
    console.log('[gdpr-scanner] scan failed:', String(e));
    result = notScannedResult(target, 'scan-failed');
    if (wantsDebug) debug = { exception: String(e) };
  }

  if (result.scanned) {
    ctx.waitUntil(kv.put(cacheKey, JSON.stringify(result), { expirationTtl: CACHE_TTL }).catch(() => {}));
  }
  return json(debug ? { ...result, _debug: debug } : result, 200);
}

export default {
  fetch: (req: Request, env: Env, ctx: ExecutionContext): Promise<Response> => handleRequest(req, env, ctx),
};

function json(data: unknown, status: number): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

/** KV key of a cached result: a hash of the normalized target URL (path and query included). */
export async function scanCacheKey(target: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(target)));
  return 'scan:v2:' + Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}

function positiveInt(raw: string | undefined): number | null {
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : null;
}
