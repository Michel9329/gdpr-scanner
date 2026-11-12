// gdpr-scanner Worker: POST /scan {url} -> PrivacyResult.
// Closed by default: SCANNER_SECRET must be set, and callers must send `Authorization: Bearer <SCANNER_SECRET>`.
import { scan } from './scanner';
import { buildResult } from './verdict';
import { checkPolicyContent } from './policy-check';
import type { PrivacyResult } from './types';

interface Env {
  BROWSER: unknown;
  SCANNER_SECRET?: string;
  SCAN_KV?: KVNamespace;
  /** Optional. Appended to the User-Agent so site owners can identify the scanner, e.g. "my-scanner/1.0 (+https://example.com/about)". */
  SCANNER_UA_SUFFIX?: string;
  /** Optional. Max scans per UTC day (default 25). */
  DAILY_CAP?: string;
  DEBUG?: string; // if "1" enables the x-debug output (default OFF: in production the x-debug header is inert).
}

// Default daily scan cap, to protect the Browser Rendering free-tier budget (10 browser minutes/day
// at the time of writing). A scan takes roughly 18-28 s, so ~25 scans/day is a cautious default.
// Override with the DAILY_CAP env var. Requires the SCAN_KV binding (the counter lives there).
const DEFAULT_DAILY_CAP = 25;
// 6h: the same domain is not re-scanned (was 12h). Shorter = a less "stale" verdict after a site becomes
// compliant, while still protecting the Free budget. Immediate re-scan = x-fresh header.
const CACHE_TTL = 60 * 60 * 6;
// A short secret can be guessed or brute-forced: below this length /scan refuses to run.
const MIN_SECRET_LENGTH = 32;

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

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(req.url);

    if (req.method === 'GET' && url.pathname === '/') {
      return new Response('gdpr-scanner ok', { status: 200 });
    }
    if (req.method !== 'POST' || url.pathname !== '/scan') {
      return json({ error: 'not-found' }, 404);
    }

    // Auth: closed by default. Without SCANNER_SECRET the endpoint refuses to run (it would let anyone
    // spend your Browser Rendering minutes). With a wrong or missing token it answers 401.
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
    if (!env.SCAN_KV) {
      return json({ error: 'not-configured', message: 'Configure the SCAN_KV binding (see wrangler.toml) before using /scan: it holds the daily cap and the cache.' }, 503);
    }

    let body: { url?: unknown } | null = null;
    try {
      body = (await req.json()) as { url?: unknown };
    } catch {
      return json({ error: 'bad-json' }, 400);
    }

    const target = normalizeUrl(typeof body?.url === 'string' ? body.url : '');
    if (!target) return json({ error: 'bad-url' }, 400);
    const domain = new URL(target).hostname.toLowerCase();

    // 1) Per-domain cache: avoids a new browser session (saves budget, faster).
    //    Bypass with the `x-fresh: 1` header (forced re-scan; gated by the secret, authorized callers only).
    const fresh = req.headers.get('x-fresh') === '1';
    if (env.SCAN_KV && !fresh) {
      try {
        const cached = await env.SCAN_KV.get(`scan:${domain}`);
        if (cached) return json({ ...JSON.parse(cached), cached: true }, 200);
      } catch {
        /* soft cache miss */
      }
    }

    // 2) Daily cap: protects the Free budget. Over the cap -> "not evaluable" (graceful).
    const dailyCap = parseInt(env.DAILY_CAP || '', 10) || DEFAULT_DAILY_CAP;
    const day = new Date().toISOString().slice(0, 10);
    let count = 0;
    if (env.SCAN_KV) {
      try {
        count = parseInt((await env.SCAN_KV.get(`count:${day}`)) || '0', 10) || 0;
      } catch {
        count = 0;
      }
      if (count >= dailyCap) {
        return json(unevaluated(target, 'daily-budget'), 200);
      }
    }

    const suffix = env.SCANNER_UA_SUFFIX || 'gdpr-scanner/0.1';
    const ua = { suffix, full: `Mozilla/5.0 ${suffix}` };
    try {
      const raw = await scan(env.BROWSER, target, ua.suffix);
      // Minimum notice content (Arts. 12-13): plain fetch, zero Browser Rendering budget.
      // Fails soft (checked:false) on SPA/timeout/suspicious redirects -> no finding.
      const policyCheck = raw.reachable ? await checkPolicyContent(raw, ua.full) : { checked: false, missing: [] };
      const result = buildResult(raw, policyCheck);
      // Save cache and increment the counter only if the scan succeeded (no waste on errors).
      if (env.SCAN_KV && result.scanned) {
        ctx.waitUntil(
          Promise.all([
            env.SCAN_KV.put(`scan:${domain}`, JSON.stringify(result), { expirationTtl: CACHE_TTL }),
            env.SCAN_KV.put(`count:${day}`, String(count + 1), { expirationTtl: 60 * 60 * 48 }),
          ]).catch(() => {}),
        );
      }
      if (env.DEBUG === '1' && req.headers.get('x-debug') === '1') {
        (result as unknown as Record<string, unknown>)._debug = {
          banner: raw.banner ?? null,
          preticked: raw.preticked ?? null,
          phase2: raw.phase2 ?? null,
          policyCheck,
          cookies: raw.cookies.map((c) => c.name),
          gcs: (raw.network.map((r) => r.url).join(' ').match(/[?&]gcs=(G1\w+)/) || [])[1] || null,
          gcd: /[?&]gcd=/.test(raw.network.map((r) => r.url).join(' ')),
          google: raw.network
            .filter((r) => /google-analytics|googletagmanager|doubleclick|\/collect|gtag\/js/.test(r.url))
            .map((r) => r.url.slice(0, 120))
            .slice(0, 6),
        };
      }
      return json(result, 200);
    } catch (e) {
      // Unexpected error: return "not evaluable" (conservative), not 500.
      return json(unevaluated(target, `scan: ${String(e)}`), 200);
    }
  },
};

function json(data: unknown, status: number): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

/** "Not evaluable" result (page not scanned): conservative, no accusation. */
function unevaluated(finalUrl: string, error: string): PrivacyResult {
  return {
    scanned: false,
    verdict: null,
    score: 0,
    findings: [],
    summary: {
      trackers: [],
      tagManager: false,
      cmp: null,
      consentMode: null,
      googleFonts: false,
      privacyPolicy: false,
      cookiePolicy: false,
    },
    finalUrl,
    error,
  };
}

/** Normalizes the URL + SSRF guard (no localhost / private IPs / metadata). */
function normalizeUrl(raw: string): string | null {
  let s = (raw || '').trim();
  if (!s) return null;
  if (s.length > 2048) return null;
  if (!/^https?:\/\//i.test(s)) s = 'https://' + s;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
  const host = u.hostname.toLowerCase();
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal') || host.endsWith('.local')) {
    return null;
  }
  if (host.includes(':')) return null; // IPv6 literal (loopback ::1, etc.): excluded
  // Literal IP in ANY encoding (bare or dotted, dec/hex/octal) = not a domain -> reject.
  // Also closes dotted hex 0x7f.0x0.0x0.0x1, which slipped past the decimal regex.
  if (host.split('.').every((p) => /^(?:0x[0-9a-f]+|\d+)$/i.test(p))) return null;
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) {
    if (host.split('.').some((p) => p.length > 1 && p[0] === '0')) return null; // octal form (0177.0.0.1)
    const p = host.split('.').map(Number);
    if (p[0] === 0 || p[0] === 10 || p[0] === 127) return null;
    if (p[0] === 169 && p[1] === 254) return null; // link-local / metadata
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return null;
    if (p[0] === 192 && p[1] === 168) return null;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return null; // CGNAT
  }
  return u.toString();
}
