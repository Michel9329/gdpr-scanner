// Minimum content check of the privacy notice (Arts. 12-13 GDPR).
// Server-side fetch of the notice page (NO browser: zero Browser Rendering budget) + search for the
// 6 mandatory elements in the text. Conservative: if the page cannot be downloaded, is short (probably
// a client-side SPA) or cannot be parsed -> checked:false and NO finding downstream.
import type { RawScan, PolicyContentCheck } from './types';
import { findPrivacyPolicyUrl } from './detect';

/** Mandatory elements of a privacy notice (Arts. 12-13 GDPR): stable key -> multilingual IT/EN/ES pattern.
 *  The patterns are deliberately broad (notices vary a lot): the finding fires only with >=3 missing.
 *  The Italian and Spanish terms are data matched against the scanned notice text. */
const REQUIRED: Array<[key: string, re: RegExp]> = [
  ['titolare', /titolare del trattamento|data controller|responsable del tratamiento/i],
  ['finalita', /finalit[aà]|purpose|finalidad/i],
  ['base-giuridica', /base giuridica|basi giuridiche|legal basis|base(?:s)? (?:jur[ií]dica|legal)|art(?:icolo)?\.? ?6/i],
  ['diritti', /diritt\w+|your rights|derechos|art(?:t)?(?:icoli)?\.? ?15/i],
  ['reclamo', /reclamo|garante|autorit[aà] di controllo|supervisory authority|autoridad de control|complaint/i],
  ['conservazione', /conservazion|retention|conservaci[oó]n|periodo di|per quanto tempo|how long/i],
];

const FETCH_TIMEOUT_MS = 8000;
const MAX_BYTES = 600_000;
const MIN_TEXT_LEN = 800; // below this: empty page/SPA/placeholder -> cannot be judged

/** Private/internal host: the "privacy" link comes from the scanned page (attacker-controlled). */
function isPrivateHost(rawHost: string): boolean {
  const host = (rawHost || '').toLowerCase();
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) return true;
  if (host.includes(':')) return true;
  if (host.split('.').every((p) => /^(?:0x[0-9a-f]+|\d+)$/i.test(p))) return true; // literal IP in any encoding -> block
  return false;
}

/** Crude tag stripping, but enough for text search (script/style removed first). */
function htmlToText(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&[a-z#0-9]+;/gi, ' ')
    .replace(/\s+/g, ' ');
}

export async function checkPolicyContent(scan: RawScan, userAgent = 'Mozilla/5.0 gdpr-scanner/0.1'): Promise<PolicyContentCheck> {
  const none: PolicyContentCheck = { checked: false, missing: [] };
  const target = findPrivacyPolicyUrl(scan);
  if (!target) return none;
  try {
    const u = new URL(target);
    if (isPrivateHost(u.hostname)) return none;
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), FETCH_TIMEOUT_MS);
    let html = '';
    try {
      const resp = await fetch(u.toString(), {
        signal: ctl.signal,
        redirect: 'follow',
        headers: { 'user-agent': userAgent },
      });
      if (!resp.ok) return none;
      const finalHost = new URL(resp.url || u.toString()).hostname;
      if (isPrivateHost(finalHost)) return none; // redirect to an internal host -> do not read
      html = (await resp.text()).slice(0, MAX_BYTES);
    } finally {
      clearTimeout(timer);
    }
    const text = htmlToText(html);
    if (text.replace(/\s+/g, '').length < MIN_TEXT_LEN) return none;
    const missing = REQUIRED.filter(([, re]) => !re.test(text)).map(([k]) => k);
    // If 5-6 of 6 elements are missing, the page is almost certainly NOT a readable notice
    // (policy rendered via JS -> the static fetch reads only the shell: false positive verified
    // on iubenda.com 2026-07-05). A real notice, even a poor one, has at least controller + purposes.
    if (missing.length >= 5) return none;
    return { checked: true, missing, url: u.toString() };
  } catch {
    return none;
  }
}
