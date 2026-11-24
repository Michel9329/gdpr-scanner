// Which hosts the scanner may talk to. Every case here is a way a caller, or a scanned page, could
// try to point the scanner at something that is not a public website.
import { test, expect, describe } from 'bun:test';
import { type RequestDecision, canonicalHost, classifyHost, decideRequest, isPrivateAddress, isPrivateIpv4, isPublicWebUrl, normalizeTargetUrl, responseFromPrivateAddress, parseIpv6 } from '../src/net-guard';

describe('normalizeTargetUrl: accepted', () => {
  const ok: Array<[input: string, expected: string]> = [
    ['example.com', 'https://example.com/'],
    ['  example.com/page  ', 'https://example.com/page'],
    ['https://example.com/path?x=1#section', 'https://example.com/path?x=1'],
    ['HTTP://Example.COM', 'http://example.com/'],
    ['https://example.com.', 'https://example.com/'],
    ['https://sub.domain.example.co.uk/a', 'https://sub.domain.example.co.uk/a'],
    ['https://example.com:443/', 'https://example.com/'],
    ['http://example.com:80/', 'http://example.com/'],
    ['https://münchen.example.com/', 'https://xn--mnchen-3ya.example.com/'],
  ];
  for (const [input, expected] of ok) {
    test(JSON.stringify(input), () => expect(normalizeTargetUrl(input)).toBe(expected));
  }
});

describe('normalizeTargetUrl: refused', () => {
  const refused: Array<[why: string, input: string]> = [
    ['empty', ''],
    ['blank', '   '],
    ['too long', 'https://example.com/' + 'a'.repeat(2100)],
    ['other scheme', 'ftp://example.com/'],
    ['javascript', 'javascript:alert(1)'],
    ['file', 'file:///etc/passwd'],
    ['data', 'data:text/html,hello'],
    ['localhost', 'http://localhost/'],
    ['localhost, upper case', 'http://LOCALHOST/'],
    ['localhost with the root dot', 'http://localhost./'],
    ['subdomain of localhost', 'http://app.localhost/'],
    ['subdomain of localhost with the root dot', 'http://app.localhost./'],
    ['mDNS name', 'http://printer.local/'],
    ['.internal', 'http://metadata.google.internal/'],
    ['.internal with the root dot', 'http://db.internal./'],
    ['home network name', 'http://router.home.arpa/'],
    ['single label', 'http://intranet/'],
    ['single label after a wrong scheme', 'ftp://x'],
    ['loopback', 'http://127.0.0.1/'],
    ['loopback, short form', 'http://127.1/'],
    ['loopback as an integer', 'http://2130706433/'],
    ['loopback in hex', 'http://0x7f000001/'],
    ['loopback in dotted hex', 'http://0x7f.0.0.1/'],
    ['loopback in octal', 'http://0177.0.0.1/'],
    ['private 10/8', 'http://10.0.0.1/'],
    ['cloud metadata', 'http://169.254.169.254/latest/meta-data/'],
    ['private 192.168/16', 'http://192.168.1.1/'],
    ['private 172.16/12', 'http://172.20.0.1/'],
    ['carrier-grade NAT', 'http://100.64.0.1/'],
    ['public IPv4 literal (sites are scanned by name)', 'http://8.8.8.8/'],
    ['IPv6 loopback', 'http://[::1]/'],
    ['IPv6 link-local', 'http://[fe80::1]/'],
    ['IPv6 public literal', 'http://[2606:4700::1111]/'],
    ['credentials in the URL', 'https://user:pass@example.com/'],
    ['user name in the URL', 'https://user@example.com/'],
    ['non-default port', 'https://example.com:8443/'],
    ['ssh port', 'http://example.com:22/'],
    ['wrong default port for the scheme', 'https://example.com:80/'],
    ['port that is not a number', 'https://example.com:abc/'],
    ['not a URL', 'https://exa mple.com/'],
  ];
  for (const [why, input] of refused) {
    test(why, () => expect(normalizeTargetUrl(input)).toBeNull());
  }

  test('a non-string never reaches the parser as a URL', () => {
    expect(normalizeTargetUrl(undefined as unknown as string)).toBeNull();
    expect(normalizeTargetUrl(null as unknown as string)).toBeNull();
  });
});

describe('classifyHost', () => {
  test('public names', () => {
    for (const h of ['example.com', 'Example.COM', 'example.com.', 'a.b.c.example.org', 'xn--mnchen-3ya.example.com', 'fritz.box', 'test.com', 'my.home.example.com']) {
      expect(classifyHost(h)).toBe('name');
    }
  });
  test('public IPv4 literals are told apart from names', () => {
    expect(classifyHost('8.8.8.8')).toBe('public-ip');
    expect(classifyHost('93.184.216.34')).toBe('public-ip');
  });
  test('everything else is blocked', () => {
    const blocked = [
      '', ' ', 'localhost', 'localhost.', 'x.localhost', 'x.local', 'x.internal', 'x.home.arpa', 'intranet', 'a..b',
      '127.0.0.1', '10.1.2.3', '172.31.255.255', '192.168.0.10', '169.254.1.1', '100.127.0.1', '0.0.0.0', '224.0.0.1',
      '255.255.255.255', '192.0.2.5', '198.51.100.7', '203.0.113.9', '198.18.0.1',
      '256.1.1.1', '1.2.3', '0x7f.1', '0177.0.0.1', '2130706433', '::1', '[::1]', 'fe80::1',
    ];
    for (const h of blocked) expect([h, classifyHost(h)]).toEqual([h, 'blocked']);
  });
  test('names used on private networks and special-use names are blocked', () => {
    const names = [
      'router.lan', 'nas.home', 'pc.corp', 'db.intranet', 'printer.localdomain', 'vault.private', 'kubernetes.default.svc',
      'x.test', 'x.invalid', 'x.example', 'site.example.', 'hidden.onion', 'ROUTER.LAN.',
    ];
    for (const h of names) expect([h, classifyHost(h)]).toEqual([h, 'blocked']);
  });
  test('a long run of dots is handled in linear time', () => {
    const t0 = performance.now();
    expect(canonicalHost('.'.repeat(200_000) + 'a' + '.'.repeat(200_000))).toBe('.'.repeat(200_000) + 'a');
    expect(performance.now() - t0).toBeLessThan(300);
  });
  test('the edge of each private range is public on the other side', () => {
    for (const h of ['9.255.255.255', '11.0.0.0', '172.15.255.255', '172.32.0.0', '192.167.255.255', '192.169.0.0', '100.63.255.255', '100.128.0.0', '169.253.255.255', '223.255.255.255']) {
      expect([h, classifyHost(h)]).toEqual([h, 'public-ip']);
    }
  });
});

describe('isPrivateAddress (the address a connection really reached)', () => {
  test('private IPv4 and IPv6', () => {
    for (const ip of ['127.0.0.1', '10.0.0.5', '169.254.169.254', '192.168.1.20', '::1', '[::1]', '::', 'fe80::1', 'FE80::ABCD', 'fd12:3456:789a::1', 'fc00::1', 'ff02::1', '::ffff:10.0.0.1', '::ffff:127.0.0.1']) {
      expect([ip, isPrivateAddress(ip)]).toEqual([ip, true]);
    }
  });
  test('public addresses and non-addresses', () => {
    for (const ip of ['8.8.8.8', '93.184.216.34', '2606:4700::1111', '2a00:1450:4002::200e', '::ffff:8.8.8.8', '', 'example.com']) {
      expect([ip, isPrivateAddress(ip)]).toEqual([ip, false]);
    }
  });
  test('IPv6 forms that are, or carry, a private IPv4 address', () => {
    const embedded = [
      '::ffff:7f00:1', // 127.0.0.1 as the browser writes it
      '[::ffff:7f00:1]',
      '::ffff:a9fe:a9fe', // 169.254.169.254
      '::ffff:a00:1', // 10.0.0.1
      '::ffff:c0a8:101', // 192.168.1.1
      '0:0:0:0:0:ffff:7f00:1',
      '0:0:0:0:0:0:0:1', // loopback, not compressed
      '0000:0000:0000:0000:0000:0000:0000:0001',
      '::7f00:1', // IPv4-compatible
      '::127.0.0.1',
      '64:ff9b::7f00:1', // NAT64
      '64:ff9b::a9fe:a9fe',
      '64:ff9b::10.0.0.1',
      '64:ff9b:1::7f00:1', // local-use NAT64, /96 position
      '64:ff9b:1:7f00:0:100::', // local-use NAT64, /48 position (127.0.0.1)
      '2002:7f00:1::', // 6to4 of 127.0.0.1
      '2002:a9fe:a9fe::1',
    ];
    for (const ip of embedded) expect([ip, isPrivateAddress(ip)]).toEqual([ip, true]);
  });
  test('IPv4-translated addresses (::ffff:0:0:0/96) carry the IPv4 rules', () => {
    for (const ip of ['::ffff:0:7f00:1', '::ffff:0:a9fe:a9fe', '0:0:0:0:ffff:0:a00:1', '::ffff:0:127.0.0.1']) expect([ip, isPrivateAddress(ip)]).toEqual([ip, true]);
    expect(isPrivateAddress('::ffff:0:808:808')).toBe(false);
  });
  test('ORCHID, the 3fff::/20 documentation range and SRv6 identifiers are not websites', () => {
    for (const ip of ['2001:10::1', '2001:1f::1', '2001:20::1', '2001:2f:ffff::1', '3fff::1', '3fff:fff::1', '5f00::1', '5f00:ffff::1']) {
      expect([ip, isPrivateAddress(ip)]).toEqual([ip, true]);
    }
    for (const ip of ['2001:30::1', '2001:f::1', '3fff:1000::1', '5f01::1', '5eff::1']) expect([ip, isPrivateAddress(ip)]).toEqual([ip, false]);
  });
  test('IPv6 ranges that are never a public website', () => {
    for (const ip of ['fec0::1', 'feff::1', '2001:db8::1', '2001:0:4136:e378:8000:63bf:3fff:fdd2', '100::1', 'fe80::1%eth0', '::1%lo', '[fe80::1%25eth0]']) {
      expect([ip, isPrivateAddress(ip)]).toEqual([ip, true]);
    }
  });
  test('text with a colon that is not an IPv6 address counts as private', () => {
    for (const ip of [':::1', '1::2::3', 'gggg::1', '1:2:3:4:5:6:7:8:9', '1:2:3:4:5:6:7', '::ffff:999.0.0.1', '::ffff:1.2.3', 'example.com:80', ':', '12345::1']) {
      expect([ip, isPrivateAddress(ip)]).toEqual([ip, true]);
    }
  });
  test('public IPv6, also when it carries a public IPv4', () => {
    for (const ip of ['2001:4860:4860::8888', '2606:4700:4700::1111', '::ffff:808:808', '::ffff:8.8.8.8', '64:ff9b::808:808', '2002:808:808::1', '2001:db9::1', '2001:1::1', '101::1', 'fbff::1', 'fe7f::1']) {
      expect([ip, isPrivateAddress(ip)]).toEqual([ip, false]);
    }
  });
  test('parseIpv6 reads every written form of the same address', () => {
    const loop = Array.from(parseIpv6('::1')!);
    for (const s of ['0:0:0:0:0:0:0:1', '::0:1', '0::1', '::0.0.0.1']) expect([s, Array.from(parseIpv6(s)!)]).toEqual([s, loop]);
    expect(Array.from(parseIpv6('::ffff:127.0.0.1')!)).toEqual(Array.from(parseIpv6('::ffff:7f00:1')!));
    expect(parseIpv6('1::2::3')).toBeNull();
    expect(parseIpv6('example.com')).toBeNull();
  });
  test('isPrivateIpv4 only judges dotted decimal', () => {
    expect(isPrivateIpv4('10.0.0.1')).toBe(true);
    expect(isPrivateIpv4('not-an-ip')).toBe(false);
  });
});

describe('decideRequest (every request of the scanned page)', () => {
  const sub: Array<[url: string, expected: RequestDecision]> = [
    ['https://www.google-analytics.com/g/collect?v=2', 'continue'],
    ['https://cdn.example.com:8443/app.js', 'continue'], // other port: the address check covers it
    ['https://93.184.216.34/pixel.gif', 'continue'], // public IP literal: same
    ['data:image/png;base64,iVBORw0KGgo=', 'continue'],
    ['blob:https://example.com/0b7e5a40-1b8c-4f8a-9f5e-1c2d3e4f5a6b', 'continue'],
    ['about:blank', 'continue'],
    ['not a url', 'abort'],
    ['', 'abort'],
    ['ftp://example.com/file', 'abort'],
    ['file:///etc/passwd', 'abort'],
    ['chrome://settings', 'abort'],
    ['filesystem:https://example.com/temporary/x', 'abort'],
    ['ws://example.com/socket', 'abort'],
    ['https://user:pw@example.com/x.js', 'abort'],
    ['https://user@example.com/x.js', 'abort'],
    ['http://127.0.0.1/', 'abort'],
    ['http://169.254.169.254/latest/meta-data/', 'abort'],
    ['http://localhost./', 'abort'],
    ['http://[::1]:8080/', 'abort'],
    ['http://router.lan/', 'abort'],
    ['http://0x7f000001/', 'abort'],
  ];
  for (const [url, expected] of sub) test(`subresource ${JSON.stringify(url)}`, () => expect(decideRequest(url, false)).toBe(expected));

  const nav: Array<[url: string, expected: RequestDecision]> = [
    ['https://example.com/', 'continue'],
    ['http://www.example.com/it/', 'continue'],
    ['https://example.com:8443/', 'blocked-redirect'],
    ['http://example.com:22/', 'blocked-redirect'],
    ['https://93.184.216.34/', 'blocked-redirect'],
    ['http://127.0.0.1/', 'blocked-redirect'],
    ['http://localtest.me.lan/', 'blocked-redirect'],
    ['https://user:pw@example.com/', 'blocked-redirect'],
    ['data:text/html,hi', 'blocked-redirect'],
    ['about:blank', 'blocked-redirect'],
    ['ftp://example.com/', 'blocked-redirect'],
    ['not a url', 'blocked-redirect'],
  ];
  for (const [url, expected] of nav) test(`main-frame navigation ${JSON.stringify(url)}`, () => expect(decideRequest(url, true)).toBe(expected));
});

describe('isPublicWebUrl and canonicalHost', () => {
  test('a URL object is judged on scheme, credentials, port and host', () => {
    expect(isPublicWebUrl(new URL('https://example.com/privacy'))).toBe(true);
    expect(isPublicWebUrl(new URL('https://example.com:8080/privacy'))).toBe(false);
    expect(isPublicWebUrl(new URL('https://a:b@example.com/privacy'))).toBe(false);
    expect(isPublicWebUrl(new URL('http://169.254.169.254/latest'))).toBe(false);
    expect(isPublicWebUrl(new URL('http://localhost./'))).toBe(false);
    expect(isPublicWebUrl(new URL('mailto:info@example.com'))).toBe(false);
  });
  test('canonicalHost lowers the case and drops the root dot', () => {
    expect(canonicalHost(' Example.COM.. ')).toBe('example.com');
    expect(canonicalHost('')).toBe('');
  });
});

describe('responseFromPrivateAddress', () => {
  test.each([
    // the proxy of Cloudflare's Browser Run: its port is not the URL's
    ['[::1]', 9001, 'https://www.example.com/', false],
    ['[::1]', 9001, 'http://www.example.com/', false],
    ['127.0.0.1', 3128, 'https://www.example.com/', false],
    // a private peer on the port of the URL: the name really resolved there
    ['[::1]', 443, 'https://www.example.com/', true],
    ['127.0.0.1', 80, 'http://localtest.me/', true],
    ['10.0.0.5', 443, 'https://rebind.example.com/', true],
    ['169.254.169.254', 80, 'http://rebind.example.com/latest', true],
    ['127.0.0.1', 8443, 'https://cdn.example.com:8443/a.js', true],
    // no port to compare, or a URL that does not parse: the address counts
    ['127.0.0.1', undefined, 'https://www.example.com/', true],
    ['127.0.0.1', 0, 'https://www.example.com/', true],
    ['127.0.0.1', 9001, 'not a url', true],
    // public peers and no address at all
    ['93.184.216.34', 443, 'https://www.example.com/', false],
    ['2606:4700::1111', 443, 'https://www.example.com/', false],
    ['', 443, 'https://www.example.com/', false],
    [undefined, undefined, 'https://www.example.com/', false],
  ] as [string | undefined, number | undefined, string, boolean][])('%s:%s for %s -> %s', (ip, port, url, expected) => {
    expect(responseFromPrivateAddress(ip, port, url)).toBe(expected);
  });
});
