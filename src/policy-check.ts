// Minimum content check of the privacy notice (Arts. 12-13 GDPR).
// Server-side fetch of the notice page (NO browser: it costs no browser time) + search for the
// 6 mandatory elements in the text. Conservative: if the page cannot be downloaded, is short (probably
// a client-side SPA), is not in Italian, English or Spanish, or cannot be parsed -> checked:false and
// NO finding downstream.
import type { RawScan, PolicyContentCheck } from './types';
import { findPrivacyPolicyUrl, pageLanguage } from './detect';
import { isPublicWebUrl } from './net-guard';

/** Mandatory elements of a privacy notice (Arts. 12-13 GDPR): stable key -> pattern in Italian,
 *  English or Spanish, the only languages judged, and for two of them the GDPR article that names
 *  them. The patterns are deliberately broad (notices vary a lot, and a wrong "missing" is an
 *  accusation): the finding fires only with >=3 missing. "Art. 6" reads the same in every language,
 *  so a match on an article counts for its element but is no sign that the text was understood.
 *  The Italian and Spanish terms are data matched against the scanned notice text. */
const REQUIRED: Array<[key: string, words: RegExp, article?: RegExp]> = [
  ['titolare', /\btitolare\b|\bcontroller\b|\bresponsable\b/i],
  ['finalita', /finalit[aà]|\bscop[oi]\b|purpose|finalidad|\bfines\b/i],
  [
    'base-giuridica',
    /base giuridica|basi giuridiche|liceit[aà]|base legale|legal basis|lawful basis|legal grounds?|base(?:s)? (?:jur[ií]dica|legal)|legitimaci[oó]n/i,
    /art(?:icolo|[ií]culo)?\.? ?6|article 6/i,
  ],
  [
    'diritti',
    /diritt\w+|your rights|right to (?:access|erasure|object|rectif|restrict|data portab|withdraw|be informed)|derechos/i,
    /art(?:t)?(?:icoli|[ií]culos?)?\.? ?15|article 15/i,
  ],
  [
    'reclamo',
    /reclam(?:o|ar|aci[oó]n)|garante|autorit[aà] di controllo|supervisory authority|autoridad de control|complain|information commissioner|agencia espa[nñ]ola de protecci[oó]n de datos|\baepd\b/i,
  ],
  [
    'conservazione',
    /conservazion|conservat[aeio]\b|conserver[aà]nno|retention|\bretain|keep (?:your|the) (?:personal )?(?:data|information)|conservaci[oó]n|conservar[aá]n|periodo di|per quanto tempo|how long|storage period/i,
  ],
];

/** Only notices in these languages are judged: the patterns above know no other. */
const JUDGED_LANGUAGES = new Set(['it', 'en', 'es']);

/** Common words that tell the languages apart. A word that is also common in another European
 *  language is left out ("que", "para", "il", "qui", "sua", "es"; "to", "by" and "we" are Polish,
 *  "for" is Danish). */
const STOP_WORDS: Record<string, string[]> = {
  it: ['gli', 'della', 'delle', 'degli', 'dei', 'di', 'che', 'sono', 'nel', 'nella', 'alla', 'questo', 'questa', 'anche', 'essere', 'tuoi', 'vostri', 'dati'],
  en: ['the', 'and', 'of', 'are', 'with', 'that', 'this', 'your', 'you', 'our', 'be', 'will'],
  es: ['el', 'los', 'las', 'y', 'sus', 'usted', 'datos', 'nuestro', 'nuestra', 'también', 'cuando', 'puede', 'pueden'],
  de: ['der', 'die', 'das', 'und', 'ist', 'nicht', 'mit', 'sie', 'wir', 'ihre', 'für', 'von', 'zu', 'dem', 'werden', 'auf', 'eine', 'oder', 'daten'],
  fr: ['les', 'est', 'et', 'vous', 'nous', 'pour', 'dans', 'aux', 'pas', 'données', 'votre'],
  nl: ['het', 'een', 'zijn', 'wij', 'uw', 'u', 'voor', 'niet', 'op', 'worden', 'wordt', 'deze', 'dat', 'bij', 'heeft', 'kunt', 'gegevens', 'onze', 'ons'],
  pt: ['não', 'uma', 'são', 'seus', 'você', 'nós', 'pelo', 'pela', 'ao', 'dados', 'seu'],
};
const WORD_LANGUAGE = new Map<string, string>();
for (const [lang, words] of Object.entries(STOP_WORDS)) for (const w of words) WORD_LANGUAGE.set(w, lang);
/** Share of the words of a text that must be common words of its language for the text to read as
 *  that language. Measured: real notices 12% (Italian) and 19% (English), the test notices 19-32%;
 *  a notice in a language that is not listed has none or a few stray ones. */
const MIN_LANGUAGE_SHARE = 0.04;

const FETCH_TIMEOUT_MS = 8000;
const MAX_BYTES = 600_000;
const MAX_REDIRECTS = 3;
const MIN_TEXT_LEN = 800; // below this: empty page/SPA/placeholder -> cannot be judged

/**
 * Text of an HTML page for the pattern search: script and style content dropped, tags and entities
 * replaced by a space, whitespace collapsed. One pass with indexOf, linear in the size of the page:
 * the page is not trusted, and the fetch timeout cannot interrupt a regex.
 * An unclosed script or style runs to the end of the page, as a browser reads it.
 */
export function htmlToText(html: string): string {
  const out: string[] = [];
  const n = html.length;
  let i = 0;
  while (i < n) {
    const lt = html.indexOf('<', i);
    if (lt < 0) {
      out.push(html.slice(i));
      break;
    }
    out.push(html.slice(i, lt));
    const raw = rawTextTag(html, lt);
    if (raw) {
      const end = closeTagEnd(html, lt + 1 + raw.length, raw);
      if (end < 0) break;
      out.push(' ');
      i = end;
      continue;
    }
    const gt = html.indexOf('>', lt + 1);
    if (gt < 0) {
      out.push(html.slice(lt)); // no tag can close after this point
      break;
    }
    if (gt === lt + 1) {
      out.push('<'); // "<>" is not a tag
      i = lt + 1;
      continue;
    }
    out.push(' ');
    i = gt + 1;
  }
  return out
    .join('')
    .replace(/&[a-z#0-9]+;/gi, ' ')
    .replace(/\s+/g, ' ');
}

const isTagNameEnd = (c: string | undefined) => c === undefined || c === '>' || c === '/' || /\s/.test(c);

/** 'script' or 'style' when a tag of that name opens at `lt`. */
function rawTextTag(html: string, lt: number): 'script' | 'style' | null {
  for (const name of ['script', 'style'] as const) {
    if (html.slice(lt + 1, lt + 1 + name.length).toLowerCase() === name && isTagNameEnd(html[lt + 1 + name.length])) return name;
  }
  return null;
}

/** Index just after the closing tag of `name`, searched from `from`, or -1. Each character is looked at once. */
function closeTagEnd(html: string, from: number, name: string): number {
  let k = from;
  for (;;) {
    const j = html.indexOf('</', k);
    if (j < 0) return -1;
    const after = j + 2 + name.length;
    if (html.slice(j + 2, after).toLowerCase() === name && isTagNameEnd(html[after])) {
      const gt = html.indexOf('>', after);
      return gt < 0 ? -1 : gt + 1;
    }
    k = j + 2;
  }
}

/** Language of a text by its common words: the clear leader among STOP_WORDS; 'mixed' when a
 *  language that is not judged makes up a real part of it; '' when the leader's common words are too
 *  few, in number or as a share of all the words, to say the text is written in it. */
function wordLanguage(text: string): string {
  const counts = new Map<string, number>();
  let total = 0;
  for (const w of text.slice(0, 60_000).toLowerCase().split(/[^\p{L}]+/u)) {
    if (!w) continue;
    total++;
    const lang = WORD_LANGUAGE.get(w);
    if (lang) counts.set(lang, (counts.get(lang) ?? 0) + 1);
  }
  const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  const [first, second] = ranked;
  if (!first || first[1] < 5 || (second && second[1] === first[1])) return '';
  if (!JUDGED_LANGUAGES.has(first[0])) return first[0];
  const foreign = Math.max(0, ...ranked.filter(([lang]) => !JUDGED_LANGUAGES.has(lang)).map(([, n]) => n));
  if (foreign >= 5 && foreign >= first[1] * 0.15) return 'mixed';
  return first[1] >= total * MIN_LANGUAGE_SHARE ? first[0] : '';
}

/**
 * The language a notice is judged in, or null when it must not be judged. The text decides: it must
 * read as Italian, English or Spanish. The page's <html lang> can only refuse, when it names another
 * language; it is never enough on its own, because templates often leave lang="en" on pages written
 * in other languages.
 */
export function noticeLanguage(html: string, text: string): string | null {
  const declared = pageLanguage(html);
  if (declared && !JUDGED_LANGUAGES.has(declared)) return null;
  const byWords = wordLanguage(text);
  if (byWords && !JUDGED_LANGUAGES.has(byWords)) return null;
  return byWords || null;
}

/** Reads at most `maxBytes` of a response body, then stops the download. */
async function readCapped(resp: Response, maxBytes: number): Promise<string> {
  const reader = resp.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (total < maxBytes) {
      const { done, value } = await reader.read();
      if (done || !value) break;
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const out = new Uint8Array(Math.min(total, maxBytes));
  let offset = 0;
  for (const c of chunks) {
    const part = c.subarray(0, out.length - offset);
    out.set(part, offset);
    offset += part.byteLength;
    if (offset >= out.length) break;
  }
  return new TextDecoder().decode(out);
}

/**
 * Downloads a text page from a public website. The link comes from the scanned page, so every hop
 * is checked BEFORE it is requested: redirects are followed by hand, never by fetch itself.
 * Returns null for anything that is not a readable public page.
 */
async function fetchPublicText(start: URL, userAgent: string, signal: AbortSignal): Promise<{ text: string; url: string } | null> {
  let url = start;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    if (!isPublicWebUrl(url)) return null;
    const resp = await fetch(url.toString(), {
      signal,
      redirect: 'manual',
      headers: { 'user-agent': userAgent, accept: 'text/html,application/xhtml+xml' },
    });
    if (resp.status >= 300 && resp.status < 400) {
      const location = resp.headers.get('location');
      await resp.body?.cancel().catch(() => {});
      if (!location) return null;
      try {
        url = new URL(location, url);
      } catch {
        return null;
      }
      continue;
    }
    if (!resp.ok) return null;
    const type = resp.headers.get('content-type') || '';
    if (type && !/text\/html|application\/xhtml\+xml|text\/plain/i.test(type)) return null;
    return { text: await readCapped(resp, MAX_BYTES), url: url.toString() };
  }
  return null; // too many redirects
}

export async function checkPolicyContent(scan: RawScan, userAgent = 'Mozilla/5.0 gdpr-scanner'): Promise<PolicyContentCheck> {
  const none: PolicyContentCheck = { checked: false, missing: [] };
  const target = findPrivacyPolicyUrl(scan);
  if (!target) return none;
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), FETCH_TIMEOUT_MS);
  try {
    const page = await fetchPublicText(new URL(target), userAgent, ctl.signal);
    if (!page) return none;
    const text = htmlToText(page.text);
    if (text.replace(/\s+/g, '').length < MIN_TEXT_LEN) return none;
    if (!noticeLanguage(page.text, text)) return none;
    const missing = REQUIRED.filter(([, words, article]) => !words.test(text) && !article?.test(text)).map(([k]) => k);
    // Fewer than 2 elements found in words: the page is almost certainly NOT a readable notice
    // (policy rendered via JS -> the static fetch reads only the shell), or not one the patterns
    // understand. A real notice, even a poor one, has at least controller + purposes. Matches on an
    // article number do not count here: they read the same in a language the patterns do not know.
    const foundInWords = REQUIRED.filter(([, words]) => words.test(text)).length;
    if (foundInWords < 2) return none;
    return { checked: true, missing, url: page.url };
  } catch {
    return none;
  } finally {
    clearTimeout(timer);
  }
}
