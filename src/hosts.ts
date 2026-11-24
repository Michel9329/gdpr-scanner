// Host and path matching for the detection lists. A request belongs to a vendor when its host IS
// the vendor's host or a subdomain of it. Substring matching is not used: "cheap.io" is not
// "heap.io", and a path such as /customer-segment.common.js is not segment.com.

import { canonicalHost } from './net-guard';

export interface RequestParts {
  /** lower-case hostname, "" when the URL cannot be parsed */
  host: string;
  /** lower-case pathname, always starting with "/" */
  path: string;
}

export function requestParts(rawUrl: string): RequestParts {
  try {
    const u = new URL(rawUrl);
    return { host: canonicalHost(u.hostname), path: (u.pathname || '/').toLowerCase() };
  } catch {
    return { host: '', path: '/' };
  }
}

/** True when `host` is `domain` or one of its subdomains. */
export function hostMatches(host: string, domain: string): boolean {
  return host === domain || host.endsWith('.' + domain);
}

/** True when `path` is `prefix` or lies under it ("/tr" matches "/tr" and "/tr/x", not "/track"). */
export function pathUnder(path: string, prefix: string): boolean {
  return path === prefix || path.startsWith(prefix.endsWith('/') ? prefix : prefix + '/');
}

/** The tail a "label.vendor.*" rule accepts: a country or generic ending such as "it", "com",
 *  "co.uk" or "com.br". Anything longer ("evil.example") is somebody else's domain. */
const SUFFIX_TAIL = /^[a-z]{2,3}(?:\.[a-z]{2})?$/;

/**
 * Matches one list entry against a request. Three entry forms:
 *   "vendor.com"        the host or any subdomain
 *   "vendor.com/path"   the same, and the request path under /path
 *   "label.vendor.*"    the host is "label.vendor." followed by a country or generic ending
 *                       (two or three letters, optionally a dot and two more letters): vendors
 *                       that use one host per country. No subdomains, no longer tails.
 */
export function matchesHostRule(rule: string, req: RequestParts): boolean {
  if (!req.host) return false;
  const slash = rule.indexOf('/');
  const hostRule = slash === -1 ? rule : rule.slice(0, slash);
  const pathRule = slash === -1 ? '' : rule.slice(slash);
  let hostOk: boolean;
  if (hostRule.endsWith('.*')) {
    const head = hostRule.slice(0, -1); // "label.vendor."
    hostOk = req.host.startsWith(head) && SUFFIX_TAIL.test(req.host.slice(head.length));
  } else {
    hostOk = hostMatches(req.host, hostRule);
  }
  return hostOk && (!pathRule || pathUnder(req.path, pathRule));
}
