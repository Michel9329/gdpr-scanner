// Decides which hosts the scanner may talk to. One implementation for the three places that need
// it: the scan target (index.ts), every request the headless browser makes (scanner.ts) and the
// plain fetch of the privacy notice (policy-check.ts).
//
// The scanner loads pages chosen by its callers and follows links chosen by those pages. Neither
// may point it at a machine that is not a public website.
//
// Names are checked here, before a request. A public name can still resolve to a private address,
// so scanner.ts also checks the address each response actually came from (isPrivateAddress).

export type HostKind = 'name' | 'public-ip' | 'blocked';

/** Suffixes that never belong to a public website: special-use names (RFC 6761: .localhost, .test,
 *  .invalid, .example; RFC 6762: .local; RFC 7686: .onion; RFC 8375: .home.arpa; ICANN's .internal)
 *  and names used on private networks (.lan, .home, .corp, .intranet, .localdomain, .private,
 *  Kubernetes' .svc). .box is not here: it is a delegated top-level domain. */
const PRIVATE_SUFFIXES = [
  '.localhost', '.local', '.internal', '.home.arpa', '.test', '.invalid', '.example', '.onion',
  '.lan', '.home', '.corp', '.intranet', '.localdomain', '.private', '.svc',
];

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
/** Longest URL the scanner accepts as a target or keeps from a page. */
export const MAX_URL_LENGTH = 2048;

/** "Example.COM." and "example.com" are the same host: lower case, no trailing root dot. */
export function canonicalHost(rawHost: string): string {
  const host = (rawHost || '').trim().toLowerCase();
  // A loop, not /\.+$/: that regex is quadratic on a long run of dots, and hosts come from scanned pages.
  let end = host.length;
  while (end > 0 && host.charCodeAt(end - 1) === 46) end--;
  return host.slice(0, end);
}

/** True for a dotted-decimal IPv4 address that is not publicly routable. */
export function isPrivateIpv4(ip: string): boolean {
  const m = IPV4_RE.exec(ip);
  if (!m) return false;
  const [a, b, c] = [Number(m[1]), Number(m[2]), Number(m[3])];
  if (a === 0 || a === 10 || a === 127) return true; // "this network", private, loopback
  if (a === 100 && b >= 64 && b <= 127) return true; // carrier-grade NAT
  if (a === 169 && b === 254) return true; // link-local, cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true; // protocol assignments, documentation
  if (a === 192 && b === 88 && c === 99) return true; // 6to4 relay anycast
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a === 198 && b === 51 && c === 100) return true; // documentation
  if (a === 203 && b === 0 && c === 113) return true; // documentation
  return a >= 224; // multicast, reserved, broadcast
}

/** Parses IPv6 text ("::", a dotted IPv4 tail, no brackets, no zone id) into 16 bytes, or null. */
export function parseIpv6(text: string): Uint8Array | null {
  let s = text;
  const lastColon = s.lastIndexOf(':');
  if (lastColon < 0) return null;
  const tail = s.slice(lastColon + 1);
  if (tail.includes('.')) {
    // "::ffff:127.0.0.1": the dotted tail is the last two groups.
    const m = IPV4_RE.exec(tail);
    if (!m) return null;
    const p = m.slice(1).map(Number);
    if (p.some((n) => n > 255)) return null;
    s = s.slice(0, lastColon + 1) + ((p[0]! << 8) | p[1]!).toString(16) + ':' + ((p[2]! << 8) | p[3]!).toString(16);
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const groups = (h: string) => (h === '' ? [] : h.split(':'));
  const head = groups(halves[0]!);
  const rest = halves.length === 2 ? groups(halves[1]!) : [];
  const all = [...head, ...rest];
  if (all.some((g) => !/^[0-9a-f]{1,4}$/i.test(g))) return null;
  if (halves.length === 1 ? all.length !== 8 : all.length > 7) return null;
  const words = [...head, ...Array(8 - all.length).fill('0'), ...rest].map((g) => parseInt(g, 16));
  const bytes = new Uint8Array(16);
  words.forEach((w, i) => {
    bytes[i * 2] = w >> 8;
    bytes[i * 2 + 1] = w & 0xff;
  });
  return bytes;
}

const v4 = (b: Uint8Array, at: number[]): string => at.map((i) => b[i]).join('.');
const startsWith = (b: Uint8Array, prefix: number[]): boolean => prefix.every((x, i) => b[i] === x);

/** True for an address (IPv4 or IPv6, with or without brackets or zone id) the scanner must not
 *  read from. Used on the address a connection actually reached, as the browser reports it.
 *  Text that contains ':' but does not parse as IPv6 counts as private. */
export function isPrivateAddress(rawIp: string): boolean {
  const ip = (rawIp || '').trim().toLowerCase().replace(/^\[/, '').replace(/\]$/, '').replace(/%.*$/, '');
  if (!ip) return false;
  if (IPV4_RE.test(ip)) return isPrivateIpv4(ip);
  if (!ip.includes(':')) return false; // not an address
  const b = parseIpv6(ip);
  if (!b) return true;
  const last4 = [12, 13, 14, 15];
  // Forms that carry an IPv4 address: the IPv4 rules decide.
  if (startsWith(b, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])) return isPrivateIpv4(v4(b, last4)); // ::ffff:0:0/96 mapped
  if (startsWith(b, [0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0])) return isPrivateIpv4(v4(b, last4)); // ::ffff:0:0:0/96 translated
  if (startsWith(b, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])) return isPrivateIpv4(v4(b, last4)); // ::/96 compatible, with :: and ::1
  if (startsWith(b, [0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0])) return isPrivateIpv4(v4(b, last4)); // 64:ff9b::/96 NAT64
  if (startsWith(b, [0, 0x64, 0xff, 0x9b, 0, 1])) {
    // 64:ff9b:1::/48 local-use NAT64 (RFC 8215): the IPv4 sits where the network's prefix length
    // puts it (RFC 6052). The length is not known here, so every allowed position is checked.
    const forms = [[6, 7, 9, 10], [7, 9, 10, 11], [9, 10, 11, 12], last4];
    return forms.some((at) => isPrivateIpv4(v4(b, at)));
  }
  if (startsWith(b, [0x20, 0x02])) return isPrivateIpv4(v4(b, [2, 3, 4, 5])); // 2002::/16 6to4
  if (startsWith(b, [0x20, 0x01, 0, 0])) return true; // 2001::/32 Teredo
  if (startsWith(b, [0x20, 0x01, 0x0d, 0xb8])) return true; // 2001:db8::/32 documentation
  if (startsWith(b, [0x20, 0x01, 0]) && ((b[3]! & 0xf0) === 0x10 || (b[3]! & 0xf0) === 0x20)) return true; // 2001:10::/28, 2001:20::/28 ORCHID
  if (startsWith(b, [0x3f, 0xff]) && (b[2]! & 0xf0) === 0) return true; // 3fff::/20 documentation
  if (startsWith(b, [0x5f, 0])) return true; // 5f00::/16 segment routing (SRv6) identifiers
  if (startsWith(b, [0x01, 0, 0, 0, 0, 0, 0, 0])) return true; // 100::/64 discard-only
  if ((b[0]! & 0xfe) === 0xfc) return true; // fc00::/7 unique local
  if (b[0] === 0xfe && (b[1]! & 0xc0) === 0x80) return true; // fe80::/10 link-local
  if (b[0] === 0xfe && (b[1]! & 0xc0) === 0xc0) return true; // fec0::/10 site-local (deprecated)
  return b[0] === 0xff; // ff00::/8 multicast
}

/** Classifies a hostname: a public-looking name, a public IPv4 literal, or something to refuse. */
export function classifyHost(rawHost: string): HostKind {
  const host = canonicalHost(rawHost);
  if (!host) return 'blocked';
  if (host.includes(':') || host.startsWith('[')) return 'blocked'; // IPv6 literal
  const labels = host.split('.');
  if (labels.some((l) => l === '')) return 'blocked';
  if (labels.every((l) => /^(?:0x[0-9a-f]*|\d+)$/i.test(l))) {
    // An IP literal. The URL parser already rewrites hex, octal and integer forms as dotted
    // decimal; anything that still looks numeric but is not plain dotted decimal is refused.
    const m = IPV4_RE.exec(host);
    if (!m) return 'blocked';
    if (m.slice(1).some((p) => Number(p) > 255 || (p.length > 1 && p[0] === '0'))) return 'blocked';
    return isPrivateIpv4(host) ? 'blocked' : 'public-ip';
  }
  if (labels.length < 2) return 'blocked'; // "intranet", "router", "localhost": never a public site
  if (PRIVATE_SUFFIXES.some((s) => host.endsWith(s))) return 'blocked';
  return 'name';
}

/** A URL the scanner may fetch by itself: http(s), the default port, no credentials, a public host name. */
export function isPublicWebUrl(u: URL): boolean {
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
  if (u.username || u.password) return false;
  if (u.port) return false; // the URL parser drops the default port, so anything left is non-default
  return classifyHost(u.hostname) === 'name';
}

export type RequestDecision = 'continue' | 'abort' | 'blocked-redirect';

/** Schemes a scanned page may use for its own requests. data:, blob: and about: never leave the browser. */
const BROWSER_SCHEMES = new Set(['http:', 'https:', 'data:', 'blob:', 'about:']);

/**
 * What the browser does with one request of the scanned page.
 * `mainNavigation`: a navigation of the main frame, which includes the redirects of the document.
 * It must lead to a URL the scanner would accept as a target ('blocked-redirect' otherwise).
 * Other requests may use other ports and public IP literals: the address each response came from
 * is checked separately. Anything that does not parse is aborted.
 */
export function decideRequest(rawUrl: string, mainNavigation: boolean): RequestDecision {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    return mainNavigation ? 'blocked-redirect' : 'abort';
  }
  if (mainNavigation) return isPublicWebUrl(u) ? 'continue' : 'blocked-redirect';
  if (!BROWSER_SCHEMES.has(u.protocol)) return 'abort';
  if (u.username || u.password) return 'abort';
  if ((u.protocol === 'http:' || u.protocol === 'https:') && classifyHost(u.hostname) === 'blocked') return 'abort';
  return 'continue';
}

/** Normalizes the target of a scan, or returns null when it is not a public website address.
 *  A bare host ("example.com/page") gets https. */
export function normalizeTargetUrl(raw: string): string | null {
  let s = (raw || '').trim();
  if (!s || s.length > MAX_URL_LENGTH) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  if (!isPublicWebUrl(u)) return null;
  u.hostname = canonicalHost(u.hostname);
  u.hash = '';
  return u.toString();
}
