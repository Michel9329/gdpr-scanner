// Non-essential cookie names (high signal). Hand-curated for this project.
//
// Covers common analytics/marketing cookies (Google, Meta, Hotjar, Adobe, Criteo, Yandex and others),
// including cases where the tracker is first-party or the request was cached. This is a SECONDARY
// signal: the primary one is host classification (tracker-hosts.ts). The full Open Cookie Database
// (Apache-2.0) is not bundled: at 1-2 MB it would exceed the Worker free-plan size limit.
//
// `match` is either the exact cookie name (a string) or a regular expression that the WHOLE name
// must match (anchored with ^ and $). There is no bare prefix form: a prefix such as "_ga" also
// names a site's own "_gallery_seen" or "_gate", and a wrong name here accuses the wrong site.
// Each expression states the shape the vendor documents, for example "_ga_" plus the container id.
// Entries do not overlap, so the order of the list does not matter.
//
// Only cookies the tracker sets on the visited site's own domain are listed. The scan reads the
// cookies of the page it loaded, so a cookie that lives on the vendor's domain (Facebook's `fr`,
// Google's `NID`, DoubleClick's `IDE`, LinkedIn's `bcookie`) never shows up here: a cookie with one
// of those names on the visited site is something else, and listing them could only accuse the
// wrong site. Those vendors are detected from the network requests instead.

export interface CookiePattern {
  /** Exact cookie name, or an anchored expression the whole name must match. */
  match: string | RegExp;
  /** Who it belongs to (for the "found" list). */
  name: string;
}

export const COOKIE_PATTERNS: CookiePattern[] = [
  // Google Analytics: _ga, _ga_<container-id>, _gid, _gat, _gat_<property-id>, __utma/b/c/t/v/z
  { match: '_ga', name: 'Google Analytics' },
  { match: /^_ga_[A-Z0-9]+$/, name: 'Google Analytics' },
  { match: '_gid', name: 'Google Analytics' },
  { match: '_gat', name: 'Google Analytics' },
  { match: /^_gat_[\w-]+$/, name: 'Google Analytics' },
  { match: /^__utm[a-z]$/, name: 'Google Analytics (Universal)' },
  // Google Ads: conversion linker _gcl_<kind> (_gcl_au, _gcl_aw ...) and _gac_<property-id>
  { match: /^_gcl_[a-z]+$/, name: 'Google Ads (conversion linker)' },
  { match: /^_gac_[\w-]+$/, name: 'Google Ads' },
  // Meta / Facebook
  { match: '_fbp', name: 'Meta Pixel' },
  { match: '_fbc', name: 'Meta Pixel' },
  // Hotjar: _hj followed by an upper-case letter (_hjSession_<id>, _hjSessionUser_<id>, _hjFirstSeen ...) or _hjid
  { match: /^_hj(?:[A-Z]\w*|id)$/, name: 'Hotjar' },
  // Microsoft Clarity / Bing
  { match: '_clck', name: 'Microsoft Clarity' },
  { match: '_clsk', name: 'Microsoft Clarity' },
  { match: '_uetsid', name: 'Microsoft Advertising (UET)' },
  { match: '_uetvid', name: 'Microsoft Advertising (UET)' },
  // TikTok / Pinterest
  { match: '_ttp', name: 'TikTok Pixel' },
  { match: /^_pinterest_\w+$/, name: 'Pinterest Tag' },
  { match: '_pin_unauth', name: 'Pinterest Tag' },
  // Other analytics: Mixpanel names its cookie mp_<project token>_mixpanel
  { match: /^mp_[0-9a-f]+_mixpanel$/, name: 'Mixpanel' },
  { match: /^amplitude_\w+$/, name: 'Amplitude' },
  { match: '__hstc', name: 'HubSpot' },
  { match: 'hubspotutk', name: 'HubSpot' },
  // Adobe (AMCV_<org id>@AdobeOrg, the @ often percent-encoded) / Criteo / Yandex / Taboola / Quantcast
  { match: /^AMCV_[0-9A-Za-z]+(?:@|%40)AdobeOrg$/, name: 'Adobe Experience Cloud' },
  { match: 'mbox', name: 'Adobe Target' },
  { match: 'cto_bundle', name: 'Criteo' },
  { match: '_ym_uid', name: 'Yandex Metrica' },
  { match: '_ym_d', name: 'Yandex Metrica' },
  { match: 't_gid', name: 'Taboola' },
  { match: '__qca', name: 'Quantcast' },
];

/** Classifies a cookie name as non-essential, or null. */
export function classifyCookieName(name: string): CookiePattern | null {
  const n = (name || '').trim();
  if (!n) return null;
  for (const p of COOKIE_PATTERNS) {
    if (typeof p.match === 'string' ? n === p.match : p.match.test(n)) return p;
  }
  return null;
}
