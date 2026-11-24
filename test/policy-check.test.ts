// The privacy notice is fetched from a link found on the scanned page, so the link is not trusted.
// fetch is replaced: each test states which URLs may be requested and checks that no other is.
// The replacement only records: an expect() inside it would throw inside the code under test,
// where the error is caught, so every check is made after the call.
import { test, expect, describe, afterEach } from 'bun:test';
import { checkPolicyContent, htmlToText, noticeLanguage } from '../src/policy-check';
import type { RawScan } from '../src/types';

const realFetch = globalThis.fetch;
let redirectModes: Array<string | undefined> = [];
afterEach(() => {
  globalThis.fetch = realFetch;
  const modes = redirectModes;
  redirectModes = [];
  // Redirects are followed by hand, hop by hop: every request must have asked for 'manual'.
  expect(modes.filter((m) => m !== 'manual')).toEqual([]);
});

function scanWithPolicyLink(href: string): RawScan {
  return {
    requestedUrl: 'https://example.com/',
    finalUrl: 'https://example.com/',
    status: 200,
    reachable: true,
    html: '',
    links: [{ href, text: 'Privacy Policy' }],
    network: [],
    cookies: [],
    globals: { dataLayer: [], googleTagDataEntries: null, hasTcfApi: false, cmpGlobals: [] },
  };
}

/** Replaces fetch with a table of URL -> response. Records every URL asked for. */
function mockFetch(routes: Record<string, () => Response>): string[] {
  const asked: string[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    asked.push(url);
    redirectModes.push(init?.redirect);
    const route = routes[url];
    if (!route) throw new Error('unexpected request to ' + url);
    return route();
  }) as typeof fetch;
  return asked;
}

const html = (body: string, lang = 'it') =>
  new Response(`<!doctype html><html lang="${lang}"><body>${body}</body></html>`, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } });
const redirect = (location: string, status = 302) => new Response(null, { status, headers: { location } });
// Italian prose without any of the six elements: the notice must read as Italian to be judged.
const filler = 'Questa pagina descrive come il sito tratta i dati delle persone che lo visitano e che ci scrivono. '.repeat(12);
const latin = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. '.repeat(30);
const COMPLETE =
  filler +
  ' Titolare del trattamento: Example Srl. Finalità del trattamento. Base giuridica: art. 6. I tuoi diritti (artt. 15-22). ' +
  'Reclamo al Garante. Periodo di conservazione dei dati.';
const THREE_MISSING = filler + ' Titolare del trattamento: Example Srl. Finalità del trattamento. Base giuridica del trattamento.';

describe('reading the notice', () => {
  test('a complete notice: checked, nothing missing', async () => {
    const asked = mockFetch({ 'https://example.com/privacy': () => html(COMPLETE) });
    const res = await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'));
    expect(res).toEqual({ checked: true, missing: [], url: 'https://example.com/privacy' });
    expect(asked).toEqual(['https://example.com/privacy']);
  });

  test('three elements missing are reported by key', async () => {
    mockFetch({ 'https://example.com/privacy': () => html(THREE_MISSING) });
    const res = await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'));
    expect(res.checked).toBe(true);
    expect(res.missing.sort()).toEqual(['conservazione', 'diritti', 'reclamo']);
  });

  test('scripts and styles are not read as text', async () => {
    mockFetch({ 'https://example.com/privacy': () => html(`<script>var x = "titolare del trattamento, finalità, base giuridica, diritti, reclamo, conservazione";</script>${filler}`) });
    expect((await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'))).checked).toBe(false); // 6 of 6 missing -> not a readable notice
  });

  test('a page too short to judge, an error status, a thrown fetch: no check, no finding', async () => {
    mockFetch({ 'https://example.com/privacy': () => html('Privacy') });
    expect(await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'))).toEqual({ checked: false, missing: [] });
    mockFetch({ 'https://example.com/privacy': () => new Response('gone', { status: 404 }) });
    expect((await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'))).checked).toBe(false);
    mockFetch({});
    expect((await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'))).checked).toBe(false);
  });

  test('a PDF or any non-text answer is not read', async () => {
    mockFetch({ 'https://example.com/privacy': () => new Response(COMPLETE, { status: 200, headers: { 'content-type': 'application/pdf' } }) });
    expect((await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'))).checked).toBe(false);
  });

  test('no privacy link on the page: nothing is fetched', async () => {
    const asked = mockFetch({});
    const scan = scanWithPolicyLink('https://example.com/about');
    scan.links = [{ href: 'https://example.com/about', text: 'About us' }];
    expect((await checkPolicyContent(scan)).checked).toBe(false);
    expect(asked).toEqual([]);
  });
});

describe('the link is not trusted', () => {
  const never: Array<[why: string, href: string]> = [
    ['private address', 'http://169.254.169.254/latest/meta-data/privacy'],
    ['loopback', 'http://127.0.0.1/privacy'],
    ['localhost with the root dot', 'http://localhost./privacy'],
    ['internal name', 'http://wiki.internal/privacy'],
    ['single label', 'http://intranet/privacy'],
    ['public IP literal', 'http://8.8.8.8/privacy'],
    ['non-default port', 'https://example.com:8443/privacy'],
    ['credentials', 'https://user:pw@example.com/privacy'],
  ];
  for (const [why, href] of never) {
    test(`${why}: not requested`, async () => {
      const asked = mockFetch({});
      expect((await checkPolicyContent(scanWithPolicyLink(href))).checked).toBe(false);
      expect(asked).toEqual([]);
    });
  }

  test('a redirect to a private address is not followed', async () => {
    const asked = mockFetch({ 'https://example.com/privacy': () => redirect('http://169.254.169.254/latest/meta-data/') });
    expect((await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'))).checked).toBe(false);
    expect(asked).toEqual(['https://example.com/privacy']); // the second hop was never requested
  });

  test('a redirect to localhost through a relative-looking Location is not followed', async () => {
    const asked = mockFetch({ 'https://example.com/privacy': () => redirect('//localhost./admin') });
    expect((await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'))).checked).toBe(false);
    expect(asked).toEqual(['https://example.com/privacy']);
  });

  test('public redirects are followed, and the final URL is the one reported', async () => {
    const asked = mockFetch({
      'https://example.com/privacy': () => redirect('/it/privacy/', 301),
      'https://example.com/it/privacy/': () => redirect('https://www.example.com/it/privacy/'),
      'https://www.example.com/it/privacy/': () => html(COMPLETE),
    });
    const res = await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'));
    expect(res).toMatchObject({ checked: true, url: 'https://www.example.com/it/privacy/' });
    expect(asked.length).toBe(3);
  });

  test('a redirect loop stops after a few hops', async () => {
    const asked = mockFetch({
      'https://example.com/a': () => redirect('https://example.com/b'),
      'https://example.com/b': () => redirect('https://example.com/a'),
    });
    const scan = scanWithPolicyLink('https://example.com/a');
    scan.links[0]!.text = 'Privacy';
    expect((await checkPolicyContent(scan)).checked).toBe(false);
    expect(asked.length).toBe(4); // the first request and three redirects
  });

  test('a redirect without a Location is the end', async () => {
    mockFetch({ 'https://example.com/privacy': () => new Response(null, { status: 302 }) });
    expect((await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'))).checked).toBe(false);
  });

  test('an endless body is cut off instead of being read to the end', async () => {
    let pulled = 0;
    const chunk = new TextEncoder().encode(('a'.repeat(1023) + ' ').repeat(64)); // 64 KB
    const endless = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += chunk.byteLength;
        if (pulled > 50_000_000) controller.error(new Error('the reader did not stop'));
        else controller.enqueue(chunk);
      },
    });
    mockFetch({ 'https://example.com/privacy': () => new Response(endless, { status: 200, headers: { 'content-type': 'text/html' } }) });
    const res = await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'));
    expect(res.checked).toBe(false); // filler only: every element is missing
    expect(pulled).toBeLessThan(2_000_000); // about 600 KB were read, not 50 MB
  });
});

const pad = ' We describe below how this website handles personal information of visitors and customers.'.repeat(12);
const UK =
  'Privacy notice. Acme Ltd is the controller of your personal data. We use your data for the following purposes: answering enquiries and sending invoices. ' +
  'Our lawful basis for processing is contract and legitimate interests. You have the right to access, rectify, erase and port your data and to object. ' +
  'We keep your data for six years after the end of the contract. You can complain to the Information Commissioner at any time.' +
  pad;
const DE =
  'Datenschutzerklärung. Verantwortlicher im Sinne der DSGVO ist die Muster GmbH. Zwecke der Verarbeitung: Bereitstellung der Website und Beantwortung von Anfragen. ' +
  'Rechtsgrundlage ist Art. 6 Abs. 1 lit. f DSGVO. Sie haben das Recht auf Auskunft nach Art. 15 DSGVO, Berichtigung, Löschung und Widerspruch. ' +
  'Sie können sich bei einer Aufsichtsbehörde beschweren. Speicherdauer: Wir löschen die Daten nach sechs Monaten, wenn sie nicht mehr für die Zwecke erforderlich sind. ' +
  'Die Daten werden auf Servern in der EU gespeichert und nicht an Dritte weitergegeben, es sei denn, wir sind dazu verpflichtet. '.repeat(6);
const NL =
  'Privacyverklaring. Voorbeeld BV is de verwerkingsverantwoordelijke. Doeleinden: het afhandelen van uw bestelling. Rechtsgrond: art. 6 lid 1 sub b AVG. ' +
  'U heeft recht op inzage (art. 15 AVG), rectificatie en verwijdering. U kunt een klacht indienen bij de Autoriteit Persoonsgegevens. Bewaartermijn: zeven jaar. ' +
  'Wij verwerken uw gegevens niet voor andere doeleinden en deze worden niet gedeeld met derden, tenzij dat wettelijk verplicht is. '.repeat(6);
const ES =
  'Política de privacidad. Responsable: Ejemplo SL. Finalidad: gestionar los pedidos y las consultas de usted. Legitimación: ejecución del contrato. ' +
  'Derechos: acceso, rectificación y supresión. Puede presentar una reclamación ante la Agencia Española de Protección de Datos. ' +
  'Los datos se conservarán durante el tiempo necesario. ' +
  'Sus datos no se cederán a terceros y también puede retirar el consentimiento cuando quiera, sin que ello afecte a los tratamientos anteriores. '.repeat(6);
const IT_PLAIN =
  'Informativa. Il titolare è Esempio Srl, con sede a Bergamo. Usiamo i dati allo scopo di rispondere alle richieste e per la fatturazione. ' +
  'Il presupposto di liceità del trattamento è il contratto. Puoi chiedere accesso, rettifica e cancellazione: sono tuoi diritti. ' +
  'Puoi rivolgerti al Garante. I dati sono conservati per dieci anni. ' +
  'Questa pagina descrive anche come trattiamo i dati degli utenti che visitano il sito e che ci scrivono. '.repeat(8);
// Complete notices in languages that are not judged. "to", "by", "we", "for" are Polish or Danish words too.
const PL = (
  'Polityka prywatności. Administratorem danych osobowych jest Przykład sp. z o.o. Dane przetwarzamy w celu realizacji umowy, na podstawie art. 6 ust. 1 lit. b RODO. ' +
  'Masz prawo dostępu do danych (art. 15 RODO), ich sprostowania i usunięcia. Masz prawo wnieść skargę do Prezesa Urzędu Ochrony Danych Osobowych. Dane przechowujemy przez okres 5 lat. ' +
  'To jest informacja o tym, jak dbamy o dane, by były bezpieczne. To my odpowiadamy za dane we wszystkich naszych sklepach, by klienci mogli nam ufać. '
).repeat(4);
const RO = (
  'Politica de confidențialitate. Operatorul datelor este Exemplu SRL. Scopurile prelucrării: executarea contractului, în temeiul art. 6 alin. 1 lit. b din GDPR. ' +
  'Aveți dreptul de acces (art. 15), de rectificare și de ștergere. Aveți dreptul de a depune o plângere la ANSPDCP. Datele sunt păstrate timp de 5 ani. '
).repeat(5);
const DA = (
  'Privatlivspolitik. Den dataansvarlige er Eksempel ApS. Vi behandler dine oplysninger for at opfylde aftalen, jf. art. 6, stk. 1, litra b. ' +
  'Du har ret til indsigt (art. 15), berigtigelse og sletning. Du kan klage til Datatilsynet. Vi opbevarer oplysningerne i 5 år for at kunne dokumentere handlen. '
).repeat(5);

describe('only notices in Italian, English or Spanish are judged', () => {
  const judged: Array<[why: string, body: string, lang: string]> = [
    ['UK English wording ("controller", "lawful basis", "we keep your data", "complain")', UK, 'en-GB'],
    ['English with no lang attribute: told by its words', UK, ''],
    ['Spanish layered notice ("Responsable", "Legitimación", "reclamación", "conservarán")', ES, 'es'],
    ['Italian without the textbook phrases ("Il titolare", "liceità", "conservati")', IT_PLAIN, 'it'],
  ];
  for (const [why, body, lang] of judged) {
    test(`${why}: complete`, async () => {
      mockFetch({ 'https://example.com/privacy': () => (lang ? html(body, lang) : new Response(`<html><body>${body}</body></html>`, { status: 200, headers: { 'content-type': 'text/html' } })) });
      expect(await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'))).toEqual({ checked: true, missing: [], url: 'https://example.com/privacy' });
    });
  }

  const notJudged: Array<[why: string, body: string, lang: string]> = [
    ['German, declared', DE, 'de'],
    ['Dutch, declared', NL, 'nl-NL'],
    ['German with no lang attribute', DE, ''],
    ['German under a wrong lang="it"', DE, 'it'],
    ['a German notice padded with English text', DE.slice(0, 500) + pad, ''],
    ['a Dutch notice padded with English text', NL.slice(0, 330) + pad, ''],
    ['French, declared', COMPLETE, 'fr'],
    ['Latin filler with no lang attribute', latin, ''],
    ['Polish, no lang attribute', PL, ''],
    ['Polish under lang="en" left by the template', PL, 'en'],
    ['Romanian under lang="en"', RO, 'en'],
    ['Danish, no lang attribute', DA, ''],
    ['Danish under lang="en-US"', DA, 'en-US'],
    ['Italian elements inside Latin filler: the text does not read as Italian', latin + COMPLETE.slice(filler.length), 'it'],
    ['a complete Italian notice next to a longer German version', IT_PLAIN + DE, 'it'],
    ['a Polish notice with one English sentence: too few English words to read as English', PL + ' The controller of the data and the purpose of this notice are above. ', 'en'],
    ['a complete English notice with a German part a quarter of its size', UK + DE.slice(0, 300), 'en'],
  ];
  for (const [why, body, lang] of notJudged) {
    test(`${why}: not checked, no finding`, async () => {
      mockFetch({ 'https://example.com/privacy': () => (lang ? html(body, lang) : new Response(`<html><body>${body}</body></html>`, { status: 200, headers: { 'content-type': 'text/html' } })) });
      expect(await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'))).toEqual({ checked: false, missing: [] });
    });
  }

  test('the text decides; the declared language can only refuse', () => {
    expect(noticeLanguage('<html lang="en">', UK)).toBe('en');
    expect(noticeLanguage('<html>', ES)).toBe('es');
    expect(noticeLanguage('<html lang="en">', IT_PLAIN)).toBe('it'); // a wrong lang="en" on an Italian page
    expect(noticeLanguage('<html lang="de">', UK)).toBeNull();
    expect(noticeLanguage('<html lang="en">', PL)).toBeNull();
    expect(noticeLanguage('<html lang="it">', 'short')).toBeNull();
  });

  test('matches on article numbers alone do not make a notice read', async () => {
    // English text, so the language passes; "art. 6" and "art. 15" are its only elements.
    mockFetch({ 'https://example.com/privacy': () => html(pad + ' See art. 6 and art. 15 of the regulation.' + pad, 'en') });
    expect(await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'))).toEqual({ checked: false, missing: [] });
  });

  test('an article number still counts for its element in a notice that was read', async () => {
    const body = UK.replace('Our lawful basis for processing is contract and legitimate interests.', 'We process data under art. 6 of the GDPR.');
    mockFetch({ 'https://example.com/privacy': () => html(body, 'en') });
    expect(await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'))).toEqual({ checked: true, missing: [], url: 'https://example.com/privacy' });
  });
});

describe('the text of the notice is read in linear time', () => {
  test('normal markup gives the same text as before', () => {
    const doc =
      '<!doctype html><html lang="it"><head><title>Privacy</title><style>body{color:red}</style><script>var a="<b>";</script></head>' +
      '<body><p>Titolare &amp; co.</p><SCRIPT type="x">if (a<b) {}</SCRIPT><a href="/x">Link</a> a <> b 3 < 4 <br/><!-- note --></body></html>';
    expect(htmlToText(doc)).toBe(' Privacy Titolare co. Link a <> b 3 '); // "< 4 <br/>" reads as one tag, as before
    expect(htmlToText('plain text, no tags')).toBe('plain text, no tags');
    expect(htmlToText('<p>unclosed <b')).toBe(' unclosed <b');
  });
  test('an unclosed script or style runs to the end of the page, as in a browser', () => {
    expect(htmlToText('<p>before</p><script>never closed')).toBe(' before ');
    expect(htmlToText('<p>before</p><STYLE media="x">p{}')).toBe(' before ');
  });

  const hostile = ['<script', '<style', '<', '</', '</script', '<script>', '&a', '<html', 'diritt', 'keep the '];
  for (const unit of hostile) {
    test(`600 KB of ${JSON.stringify(unit)} in under 300 ms`, async () => {
      // No closing tags after the run: a closing '>' at the end is what made the old regexes quadratic or not.
      const body = '<!doctype html><html lang="it"><body>' + unit.repeat(Math.ceil(600_000 / unit.length));
      mockFetch({ 'https://example.com/privacy': () => new Response(body, { status: 200, headers: { 'content-type': 'text/html' } }) });
      const t0 = performance.now();
      htmlToText(body);
      await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'));
      expect(performance.now() - t0).toBeLessThan(300);
    });
  }

  // Hostile <html> tags for the language check (an old reader of lang= was quadratic on these).
  const tags: Array<[name: string, page: string]> = [
    ['"<html lang=" and 65,000 spaces, no ">"', '<html lang=' + ' '.repeat(65_000)],
    ['"<html lang =" and 30,000 spaces, then ">"', '<html lang =' + ' '.repeat(30_000) + '>'],
    ['"<html" and 1,000 times " lang" with 60 spaces', '<html' + (' lang' + ' '.repeat(60)).repeat(1000)],
    ['10,000 times "<htmlx"', '<htmlx'.repeat(10_000)],
  ];
  for (const [name, page] of tags) {
    test(`language check on ${name} in under 300 ms`, async () => {
      mockFetch({ 'https://example.com/privacy': () => new Response(page + filler.repeat(20), { status: 200, headers: { 'content-type': 'text/html' } }) });
      const t0 = performance.now();
      noticeLanguage(page, filler);
      await checkPolicyContent(scanWithPolicyLink('https://example.com/privacy'));
      expect(performance.now() - t0).toBeLessThan(300);
    });
  }
});
