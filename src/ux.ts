// The function that runs inside the scanned page: it looks at the cookie banner and at pre-ticked
// consent checkboxes, and in a second mode clicks the banner's reject control.
// It is serialized and sent to the browser, so it must be self-contained: no imports at runtime,
// no variables from this module.
import type { RawScan } from './types';

/** Shape of the UX_FN result in 'observe' mode. */
export interface UxObservation {
  banner: (NonNullable<RawScan['banner']> & { dbg?: unknown }) | null;
  preticked: { count: number; sample: string };
}

/**
 * Single DOM-side function for the UX observation (Tier A) and the reject click (Tier B).
 * Serialized by puppeteer: it MUST be self-contained (no closure over Node variables).
 * mode 'observe' -> { banner, preticked }; mode 'click-reject' -> { clicked }.
 * The Worker tsconfig has no DOM lib: document is accessed via a cast, as in the globals evaluate.
 * Exported so it can be run against fixture pages in a real browser.
 */
export const UX_FN = (mode: string) => {
  const w = globalThis as unknown as {
    document?: any;
    location?: { hostname?: string };
    getComputedStyle?: (el: any) => any;
    CSS?: { escape?: (s: string) => string };
  };
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

  // The label patterns are data: Italian, English, Spanish, French and German button labels matched
  // against the scanned site's banner. A link that navigates is never a reject or accept control.
  // Every other control is tested in this order: reject, selection, accept, close, settings,
  // information link. Reject comes first because many reject labels contain an accept word
  // ("Non accettare", "I do not agree", "Accetta solo i necessari").
  const REJECT_RE = new RegExp(
    [
      // a negation followed (at most one word later) by an accept word, in every language
      "\\b(?:non|not|no|ne pas|nicht|don['’]?t)\\s+(?:\\S+\\s+)?(?:accett|accept|acept|agree|allow|consent|autoris|akzeptier|zustimm|einverstanden|annehm|permit)",
      "n['’]accepte pas|pas d['’]accord|stimme nicht zu",
      '^(?:no|nein|non)[.!]?$',
      '\\bno,?\\s+(?:thanks|thank you|grazie|gracias)\\b|\\bnon,?\\s+merci\\b|\\bnein,?\\s+danke\\b',
      'rifiut|\\bnega\\b|rechaz|deneg|refus|reject|decline|\\bdeny\\b|disagree|ablehn|verweiger|opt[- ]?out',
      // continue without accepting
      '\\b(?:senza|without|sin|sans|ohne)\\s+(?:accettare|accepting|aceptar|accepter|akzeptieren|consenso|consent|consentimiento|consentement|zustimmung|einwilligung|cookies?)\\b',
      'continua senza|prosegui senza|continue without|continuar sin|continuer sans',
      // only the necessary cookies
      '\\b(?:solo|soltanto|only|just|nur|uniquement|seulement)\\b.{0,25}(?:necess?ari|t[eé]cnic|essenzial|esencial|necessary|essential|required|functional|strictly|notwendig|essen[sz]iell|erforderlich|technisch|n[eé]cessaire|essentiel|obligatoire)',
      '(?:necessari|tecnici|essenziali|necessary|essential|required|n[eé]cessaires)(?: cookies?)? (?:soltanto|only|uniquement)',
    ].join('|'),
    'i',
  );
  // "Allow selection", "Consenti la selezione": with the choices unticked these act as a reject, so
  // they are neither accept nor reject; they count as unrecognized.
  const SELECTION_RE = /selezion|select(?:ion|ed)|s[eé]lection|selecci[oó]n|auswahl|ausgew[aä]hlt/i;
  const ACCEPT_RE = new RegExp(
    [
      'accett|acconsent|\\bconsenti\\b|va bene|ho capito',
      'accept|agree|allow (?:all|cookies)|got it|i understand|^ok(?:ay)?[.!]?$',
      'acept|entendido|de acuerdo|permitir (?:todas|todo|cookies)',
      "j['’]ai compris|d['’]accord|(?:tout|tous) autoriser|autoriser (?:tout|tous)",
      'akzeptier|zustimmen|stimme zu|einverstanden|annehmen|verstanden|alle (?:zulassen|erlauben)',
    ].join('|'),
    'i',
  );
  // A negation word of any European language next to an accept word, in a label REJECT_RE did not
  // claim: "Niet accepteren", "Nu accept", "Accepter ikke". It may be a reject in words the lists do
  // not know, so it is neither accept nor reject: it counts as unrecognized.
  const NEGATION_RE = /\b(?:non|not|no|ne|nicht|niet|ikke|inte|ej|nie|nu|nem|kein|keine|n[ãa]o)\b|n['’]t\b/i;
  const CLOSE_RE = /^(?:x|×|✕|✖|╳)$|close|chiudi|cerrar|fermer|schlie(?:ß|ss)en|dismiss/i;
  /** class or id of a control with no label that closes the banner (an icon-only X button) */
  const CLOSE_ATTR_RE = /close|dismiss|chiudi/i;
  // A control that opens the preferences panel. It is recognized, but it is not a first-level reject.
  const SETTINGS_RE =
    /preferen|personali[sz]z|personnalis|customi[sz]|manage|settings?\b|impostazion|gestisc|gestion|configur|option|opzion|opcion|einstellung|anpassen|verwalten|param[eèé]tr|g[eé]rer|ajustes/i;
  const POLICY_RE = /privacy|cookie|informativa|pol[ií]tica/i;
  // Text of a link that only informs (policy, more information, legal notice): not a choice.
  const INFO_RE =
    /privacy|cookie|informativa|pol[ií]tica|policy|leggi|maggiori informazioni|ulteriori informazioni|scopri di pi|learn more|read more|more info|mehr erfahren|mehr info|en savoir plus|plus d['’]info|m[aá]s informaci[oó]n|saber m[aá]s|datenschutz|impressum|imprint|note legali|mentions l[eé]gales|aviso legal|confidentialit|privacidad/i;

  // A REAL cookie banner is an overlay (fixed/sticky, itself or a nearby ancestor): consent blocks
  // that sit in the page flow, such as the consent line of a contact form, are not banners.
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
    `${String(el.textContent || '').trim()} ${String(el.getAttribute?.('aria-label') || '')} ${String(el.getAttribute?.('title') || '')} ${String(el.value || '')}`
      .replace(/\s+/g, ' ')
      .trim()
      .slice(0, 120);

  /** A link that leads to another page: an <a> whose href is anything but empty, "#..." or
   *  javascript:. Only a real control can be a choice: such a link is never a reject or an accept
   *  control and is never clicked ("Come rifiutare i cookie" pointing to the cookie policy). */
  const navigates = (el: any): boolean => {
    if (String(el.tagName || '').toUpperCase() !== 'A') return false;
    const href = String(el.getAttribute?.('href') || '').trim();
    return !!href && !href.startsWith('#') && !/^javascript:/i.test(href);
  };

  /** A navigating link that has no text, only informs, or leaves the site: information, not a choice. */
  const isInfoLink = (el: any, t: string): boolean => {
    if (!navigates(el)) return false;
    if (!t || INFO_RE.test(t)) return true;
    const linkHost = String(el.hostname || '');
    const pageHost = String(w.location?.hostname || '');
    return !!linkHost && !!pageHost && linkHost !== pageHost;
  };

  // --- click-reject mode (Tier B): clicks a reject control in the banner ---
  // Only real controls (not navigating links) are candidates. A reject label with no accept word
  // in it ("Rifiuta") is preferred. A candidate whose label also matches the accept pattern
  // ("Accetta solo i necessari") is pressed only when the banner has another, plain accept control:
  // alone, it may be the accept button misread ("OK, no problem, accept"), and pressing it would make
  // the reject test report the site's own consented cookies as set after a rejection.
  if (mode === 'click-reject') {
    try {
      const best = findBanner();
      if (!best) return { clicked: false };
      const real = controls(best).filter((c: any) => !navigates(c) && !!label(c));
      const rejects = real.filter((c: any) => REJECT_RE.test(label(c)));
      const plainAccept = real.some((c: any) => ACCEPT_RE.test(label(c)) && !REJECT_RE.test(label(c)));
      const pick = rejects.find((c: any) => !ACCEPT_RE.test(label(c))) || (plainAccept ? rejects[0] : undefined);
      if (pick) {
        pick.click();
        return { clicked: true };
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
      let settings = false;
      let unknown = 0;
      for (const c of ctrls) {
        const t = label(c);
        // a navigating link with a choice in its text ("Come rifiutare i cookie"): not a control, doubt
        if (t && navigates(c) && (REJECT_RE.test(t) || ACCEPT_RE.test(t) || SELECTION_RE.test(t))) unknown++;
        else if (t && REJECT_RE.test(t)) reject = true;
        else if (t && SELECTION_RE.test(t)) unknown++;
        else if (t && ACCEPT_RE.test(t) && NEGATION_RE.test(t)) unknown++;
        else if (t && ACCEPT_RE.test(t)) accept = true;
        else if (t && t.length <= 24 && CLOSE_RE.test(t)) close = true;
        else if (!t && CLOSE_ATTR_RE.test(`${String(c.className || '')} ${String(c.getAttribute?.('id') || '')}`)) close = true;
        else if (t && SETTINGS_RE.test(t)) settings = true;
        else if (isInfoLink(c, t)) continue;
        else unknown++;
      }
      const policyLink = Array.prototype.slice
        .call(best.querySelectorAll('a[href]'))
        .some((a: any) => POLICY_RE.test(`${String(a.getAttribute('href') || '')} ${String(a.textContent || '')}`));
      banner = {
        found: true,
        accept,
        reject,
        close,
        settings,
        unknown,
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
    // The id comes from the page: escape it before it goes into a selector.
    const esc = (s: string) => (w.CSS?.escape ? w.CSS.escape(s) : s.replace(/["\\]/g, '\\$&'));
    for (const b of boxes) {
      if (!b.checked) continue;
      if (!visible(b)) continue; // honeypots/hidden checkboxes: cannot be judged
      let ctx = '';
      try {
        const id = b.getAttribute('id');
        const lab = id ? d.querySelector(`label[for="${esc(String(id))}"]`) : null;
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
