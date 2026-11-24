// UX_FN runs inside the scanned page. Here it runs against a small stand-in for the DOM, enough to
// check how each control of a banner is read: reject, accept, close, settings, information link
// or unknown. The same function is also run in a real Chromium on fixture pages (see README, Tests).
import { test, expect, describe, afterAll } from 'bun:test';
import { UX_FN, type UxObservation } from '../src/ux';
import { buildResult } from '../src/verdict';
import type { RawScan } from '../src/types';

interface Node {
  nodeType: 1;
  tagName: string;
  className: string;
  value: string;
  hostname: string;
  parentElement: Node | null;
  children: Node[];
  clicked?: boolean;
  readonly textContent: string;
  getAttribute(n: string): string | null;
  getBoundingClientRect(): { width: number; height: number };
  querySelectorAll(sel: string): Node[];
  querySelector(sel: string): Node | null;
  click(): void;
}

function el(tag: string, text: string, attrs: Record<string, string> = {}, children: Node[] = []): Node {
  const node: Node = {
    nodeType: 1,
    tagName: tag.toUpperCase(),
    className: attrs.class || '',
    value: attrs.value || '',
    hostname: attrs.hostname || '',
    parentElement: null,
    children,
    get textContent() {
      return text + children.map((c) => c.textContent).join(' ');
    },
    getAttribute: (n: string) => (n in attrs ? attrs[n] : null),
    getBoundingClientRect: () => ({ width: 600, height: 120 }),
    querySelectorAll: (sel: string) => {
      const out: Node[] = [];
      const walk = (n: Node) => {
        for (const c of n.children) {
          if (sel === 'a[href]' ? c.tagName === 'A' && 'href' in attrsOf(c) : ['BUTTON', 'A'].includes(c.tagName)) out.push(c);
          walk(c);
        }
      };
      walk(node);
      return out;
    },
    querySelector: (sel: string) => node.querySelectorAll(sel)[0] || null,
    click() {
      node.clicked = true;
    },
  };
  attrsMap.set(node, attrs);
  for (const c of children) c.parentElement = node;
  return node;
}
const attrsMap = new WeakMap<Node, Record<string, string>>();
const attrsOf = (n: Node) => attrsMap.get(n) || {};

const g = globalThis as Record<string, unknown>;
const saved = { document: g.document, getComputedStyle: g.getComputedStyle, location: g.location };
afterAll(() => Object.assign(g, saved));

/** Puts a banner with these controls on the stand-in page and runs UX_FN in both modes. */
function run(controls: Node[]): { obs: UxObservation; clicked: Node | undefined } {
  const banner = el('div', 'Questo sito usa cookie di profilazione di terze parti. Leggi la ', { id: 'cookie-banner' }, controls);
  g.document = { querySelectorAll: (sel: string) => (sel.startsWith('form') ? [] : [banner]), querySelector: () => null };
  g.getComputedStyle = () => ({ display: 'block', visibility: 'visible', opacity: '1', position: 'fixed' });
  g.location = { hostname: 'site.example' };
  const obs = UX_FN('observe') as UxObservation;
  UX_FN('click-reject');
  return { obs, clicked: controls.find((c) => c.clicked) };
}
const policy = () => el('a', 'cookie policy', { href: '/cookie-policy' });
const buttons = (...labels: string[]) => [policy(), ...labels.map((l) => el('button', l))];

describe('reject labels are recognized (and tested before accept)', () => {
  const pairs: Array<[accept: string, reject: string]> = [
    ['Accetta', 'Rifiuta'],
    ['Accetta tutti', 'Non accettare'],
    ['Accetto', 'Non accetto'],
    ['Accept all', 'Refuse all'],
    ['Accept', 'Disagree'],
    ['I agree', 'I do not agree'],
    ['I agree', 'I don’t agree'],
    ['Accept', 'No, thanks'],
    ['Accept all', 'Necessary only'],
    ['Accept all', 'Use necessary cookies only'],
    ['Accept all', 'Accept only essential cookies'],
    ['Accetta tutti', 'Solo i cookie necessari'],
    ['Accetta tutti', 'Solo cookie tecnici'],
    ['Accetta tutti', 'Accetta solo i necessari'],
    ['Accetta', 'Continua senza accettare'],
    ['Tout accepter', 'Tout refuser'],
    ['Accepter', 'Continuer sans accepter'],
    ['J’accepte', 'Je n’accepte pas'],
    ['Alle akzeptieren', 'Ablehnen'],
    ['Zustimmen', 'Nur notwendige Cookies'],
    ['Einverstanden', 'Nicht einverstanden'],
    ['Alle akzeptieren', 'Ohne Zustimmung fortfahren'],
    ['Aceptar', 'No aceptar'],
    ['Aceptar todas', 'Rechazar todas'],
    ['Aceptar', 'Solo las necesarias'],
    ['Allow all', "Don't allow"],
    ['Allow cookies', 'Do not allow cookies'],
  ];
  for (const [acc, rej] of pairs) {
    test(`${acc} / ${rej}`, () => {
      const { obs, clicked } = run(buttons(acc, rej));
      expect(obs.banner).toMatchObject({ found: true, accept: true, reject: true, unknown: 0 });
      expect(clicked?.textContent).toBe(rej); // click-reject presses the reject, never the accept
    });
  }
});

describe('accept labels in the five languages', () => {
  for (const acc of ['Accetta', 'Acconsento', 'Consenti tutti', 'Ho capito', 'Accept', 'I agree', 'Got it', 'OK', 'Aceptar', 'Entendido', 'Tout accepter', 'J’ai compris', 'Alle akzeptieren', 'Zustimmen', 'Alle zulassen', 'Verstanden']) {
    test(acc, () => expect(run(buttons(acc)).obs.banner).toMatchObject({ accept: true, reject: false, close: false, unknown: 0 }));
  }
});

describe('settings, close, information links and unknown controls', () => {
  test('"Accept / Manage preferences": settings, nothing unknown', () => {
    expect(run(buttons('Accept', 'Manage preferences')).obs.banner).toMatchObject({ accept: true, reject: false, settings: true, unknown: 0 });
  });
  for (const s of ['Personalizza', 'Impostazioni cookie', 'Gestisci le preferenze', 'Customize', 'Cookie settings', 'Configurar', 'Paramétrer', 'Personnaliser', 'Einstellungen', 'Mehr Optionen', 'Zustimmung verwalten']) {
    test(`settings: ${s}`, () => expect(run(buttons('Accept', s)).obs.banner).toMatchObject({ settings: true, unknown: 0 }));
  }
  test('an X button, a "Chiudi" label or an icon button with a close class is a close control', () => {
    expect(run(buttons('Accetta', '×')).obs.banner).toMatchObject({ close: true, unknown: 0 });
    expect(run(buttons('Accetta', 'Chiudi')).obs.banner).toMatchObject({ close: true, unknown: 0 });
    expect(run(buttons('Akzeptieren', 'Schließen')).obs.banner).toMatchObject({ close: true, unknown: 0 });
    expect(run([policy(), el('button', 'Accetta'), el('button', '', { class: 'cc-close' })]).obs.banner).toMatchObject({ close: true, unknown: 0 });
  });
  test('an icon button with no label and no close class is unknown', () => {
    expect(run([policy(), el('button', 'Accetta'), el('button', '')]).obs.banner).toMatchObject({ close: false, unknown: 1 });
  });
  test('a label the patterns do not know is unknown', () => {
    for (const other of ['Nö', 'Salva', 'Speichern', 'Weiter', 'Proceed']) {
      expect([other, run(buttons('Accept', other)).obs.banner?.unknown]).toEqual([other, 1]);
    }
  });
  test('"Allow selection" and "Consenti la selezione" are neither accept nor reject: unknown', () => {
    expect(run(buttons('Allow all', 'Allow selection')).obs.banner).toMatchObject({ accept: true, reject: false, unknown: 1 });
    expect(run(buttons('Consenti tutti', 'Consenti la selezione')).obs.banner).toMatchObject({ accept: true, reject: false, unknown: 1 });
    expect(run(buttons('Accept all', 'Accept selected')).obs.banner).toMatchObject({ accept: true, reject: false, unknown: 1 });
    expect(run(buttons('Alle akzeptieren', 'Ausgewählte akzeptieren')).obs.banner).toMatchObject({ accept: true, reject: false, unknown: 1 });
  });
  test('links that only inform are not choices: policy, "learn more", external sites', () => {
    const links = [
      el('a', 'Privacy policy', { href: '/privacy' }),
      el('a', 'Maggiori informazioni', { href: '/info' }),
      el('a', 'Learn more', { href: '/learn' }),
      el('a', '', { href: 'https://www.cookiebot.com/', hostname: 'www.cookiebot.com' }), // logo link
      el('a', 'Powered by a vendor', { href: 'https://vendor.example/', hostname: 'vendor.example' }),
      el('button', 'Accetta'),
    ];
    expect(run(links).obs.banner).toMatchObject({ accept: true, reject: false, unknown: 0, policyLink: true });
  });
  test('a same-site link with an unknown label, or a "#" link, is unknown', () => {
    expect(run([policy(), el('button', 'Accetta'), el('a', 'Lieber nicht', { href: '#' })]).obs.banner).toMatchObject({ unknown: 1 });
    expect(run([policy(), el('button', 'Accetta'), el('a', 'Partner', { href: '/partner' })]).obs.banner).toMatchObject({ unknown: 1 });
  });
  test('a negated accept in a language the reject words do not cover is unknown, not accept', () => {
    for (const other of ['Niet accepteren', 'Nu accept', 'Accepter ikke', 'Acceptera inte']) {
      expect([other, run(buttons('Accept', other)).obs.banner]).toMatchObject([other, { reject: false, unknown: 1 }]);
    }
  });
  test('click-reject prefers a reject label with no accept word in it', () => {
    const { obs, clicked } = run(buttons('Accetta tutti (non solo i necessari)', 'Rifiuta'));
    expect(obs.banner?.reject).toBe(true);
    expect(clicked?.textContent).toBe('Rifiuta');
  });
  test('"Ho capito" alone: accept, nothing else', () => {
    expect(run(buttons('Ho capito')).obs.banner).toMatchObject({ accept: true, reject: false, close: false, settings: false, unknown: 0 });
  });
});

describe('only a real control can be a choice', () => {
  const lone = (link: Node) => run([policy(), el('button', 'Accetta'), link]);
  const choiceLinks: Array<[text: string, href: string, hostname?: string]> = [
    ['Come rifiutare i cookie', '/cookie-policy'],
    ['opt out', 'https://www.youronlinechoices.com/it/', 'www.youronlinechoices.com'],
    ['How to reject cookies', '/cookies'],
    ['Cosa succede se non accetto', '/faq'],
    ['Browse without cookies: how', '/help/cookies'],
    ['Continua senza pubblicità: abbonati', '/abbonamenti'],
    ['Accetta e continua', '/home'],
  ];
  for (const [text, href, hostname] of choiceLinks) {
    test(`a navigating link "${text}" is neither reject nor accept, counts as unknown, and is never clicked`, () => {
      const link = el('a', text, hostname ? { href, hostname } : { href });
      const { obs, clicked } = lone(link);
      expect(obs.banner).toMatchObject({ accept: true, reject: false, unknown: 1 });
      expect(clicked).toBeUndefined();
    });
  }
  test('a "#" or javascript: link is a real control and can be the reject', () => {
    for (const href of ['#', '#reject', 'javascript:void(0)']) {
      const { obs, clicked } = lone(el('a', 'Rifiuta', { href }));
      expect([href, obs.banner?.reject, clicked?.textContent]).toEqual([href, true, 'Rifiuta']);
    }
  });
  test('a navigating link with no choice in its text stays information', () => {
    expect(lone(el('a', 'Cookie policy', { href: '/cookie-policy' })).obs.banner).toMatchObject({ unknown: 0 });
  });
  test('a lone control that reads as reject and accept is never clicked', () => {
    for (const label of ['OK, no problem, accept', 'Accept all, not just the necessary']) {
      const { obs, clicked } = run([policy(), el('button', label)]);
      expect([label, obs.banner?.reject, clicked]).toEqual([label, true, undefined]);
    }
  });
  test('with a plain accept next to it, a reject that has an accept word is clicked', () => {
    const { clicked } = run(buttons('Accetta solo i necessari', 'Accetta tutti'));
    expect(clicked?.textContent).toBe('Accetta solo i necessari');
  });
});

describe('from observation to verdict', () => {
  const scan = (obs: UxObservation, extra: Partial<RawScan> = {}): RawScan => ({
    requestedUrl: 'https://site.example/',
    finalUrl: 'https://site.example/',
    status: 200,
    reachable: true,
    html: '<html><body>' + 'page content '.repeat(300) + '</body></html>',
    links: [
      { href: 'https://site.example/', text: 'Home' },
      { href: 'https://site.example/privacy', text: 'Privacy' },
      { href: 'https://site.example/cookie-policy', text: 'Cookie policy' },
    ],
    network: [],
    cookies: [],
    globals: { dataLayer: [], googleTagDataEntries: null, hasTcfApi: false, cmpGlobals: ['_iub'] },
    banner: obs.banner,
    ...extra,
  });
  const ids = (s: RawScan) => buildResult(s).findings.map((f) => f.id);

  test('"Accept / Manage preferences" with a known consent platform -> banner-no-reject', () => {
    expect(ids(scan(run(buttons('Accept', 'Manage preferences')).obs))).toContain('banner-no-reject');
  });
  test('"Accept / an unknown label" -> no banner-no-reject', () => {
    expect(ids(scan(run(buttons('Accept', 'Lieber nicht')).obs))).not.toContain('banner-no-reject');
  });
  const nothingSeen = { globals: { dataLayer: [], googleTagDataEntries: null, hasTcfApi: false, cmpGlobals: [] } };
  test('"Ho capito" with no tracker and no known consent platform -> no banner-no-reject', () => {
    expect(ids(scan(run(buttons('Ho capito')).obs, nothingSeen))).not.toContain('banner-no-reject');
  });
  test('"Accept / Manage preferences" with no tracker and no known consent platform -> banner-no-reject', () => {
    expect(ids(scan(run(buttons('Accept', 'Manage preferences')).obs, nothingSeen))).toContain('banner-no-reject');
  });
});
