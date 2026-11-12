// Non-essential cookie name patterns (high signal). Hand-curated for this project.
//
// Covers common analytics/marketing cookies (Google, Meta, Hotjar, Adobe, Criteo, Yandex and others),
// including cases where the tracker is first-party or the request was cached. This is a SECONDARY
// signal: the primary one is host classification (tracker-hosts.ts). The full Open Cookie Database
// (Apache-2.0) is not bundled: at 1-2 MB it would exceed the Worker free-plan size limit.
//
// match 'prefix' = cookie name starts with the string (e.g. "_ga" also matches "_ga_ABC123").
// match 'exact'  = cookie name is identical.
//
export type CookieCategory = 'analytics' | 'marketing';

export interface CookiePattern {
  value: string;
  match: 'prefix' | 'exact';
  category: CookieCategory;
  name: string; // who it belongs to (for the "found" list)
}

export const COOKIE_PATTERNS: CookiePattern[] = [
  // Google Analytics / Ads
  { value: '_ga', match: 'prefix', category: 'analytics', name: 'Google Analytics' },
  { value: '_gid', match: 'exact', category: 'analytics', name: 'Google Analytics' },
  { value: '_gat', match: 'prefix', category: 'analytics', name: 'Google Analytics' },
  { value: '__utm', match: 'prefix', category: 'analytics', name: 'Google Analytics (Universal)' },
  { value: '_gcl', match: 'prefix', category: 'marketing', name: 'Google Ads (conversion linker)' },
  { value: '_gac_', match: 'prefix', category: 'marketing', name: 'Google Ads' },
  { value: 'IDE', match: 'exact', category: 'marketing', name: 'Google DoubleClick' },
  { value: 'test_cookie', match: 'exact', category: 'marketing', name: 'Google DoubleClick' },
  { value: 'NID', match: 'exact', category: 'marketing', name: 'Google' },
  // Meta / Facebook
  { value: '_fbp', match: 'exact', category: 'marketing', name: 'Meta Pixel' },
  { value: '_fbc', match: 'exact', category: 'marketing', name: 'Meta Pixel' },
  { value: 'fr', match: 'exact', category: 'marketing', name: 'Meta (Facebook)' },
  // Hotjar
  { value: '_hj', match: 'prefix', category: 'analytics', name: 'Hotjar' },
  // Microsoft Clarity / Bing
  { value: '_clck', match: 'exact', category: 'analytics', name: 'Microsoft Clarity' },
  { value: '_clsk', match: 'exact', category: 'analytics', name: 'Microsoft Clarity' },
  { value: 'MUID', match: 'exact', category: 'marketing', name: 'Microsoft' },
  { value: '_uetsid', match: 'exact', category: 'marketing', name: 'Microsoft Advertising (UET)' },
  { value: '_uetvid', match: 'exact', category: 'marketing', name: 'Microsoft Advertising (UET)' },
  // LinkedIn
  { value: 'li_sugr', match: 'exact', category: 'marketing', name: 'LinkedIn' },
  { value: 'bcookie', match: 'exact', category: 'marketing', name: 'LinkedIn' },
  { value: 'UserMatchHistory', match: 'exact', category: 'marketing', name: 'LinkedIn' },
  // TikTok / Pinterest / Twitter / Snap
  { value: '_ttp', match: 'exact', category: 'marketing', name: 'TikTok Pixel' },
  { value: '_pinterest_', match: 'prefix', category: 'marketing', name: 'Pinterest Tag' },
  { value: '_pin_unauth', match: 'exact', category: 'marketing', name: 'Pinterest Tag' },
  { value: 'personalization_id', match: 'exact', category: 'marketing', name: 'X (Twitter)' },
  // Other analytics
  { value: 'mp_', match: 'prefix', category: 'analytics', name: 'Mixpanel' },
  { value: 'amplitude_', match: 'prefix', category: 'analytics', name: 'Amplitude' },
  { value: '__hstc', match: 'exact', category: 'marketing', name: 'HubSpot' },
  { value: 'hubspotutk', match: 'exact', category: 'marketing', name: 'HubSpot' },
  { value: '_hjSession', match: 'prefix', category: 'analytics', name: 'Hotjar' },
  // Adobe / Criteo / Yandex / Taboola / Quantcast
  { value: 'AMCV_', match: 'prefix', category: 'analytics', name: 'Adobe Experience Cloud' },
  { value: 'mbox', match: 'exact', category: 'marketing', name: 'Adobe Target' },
  { value: 'cto_bundle', match: 'exact', category: 'marketing', name: 'Criteo' },
  { value: 'cto_', match: 'prefix', category: 'marketing', name: 'Criteo' },
  { value: '_ym_uid', match: 'exact', category: 'analytics', name: 'Yandex Metrica' },
  { value: '_ym_d', match: 'exact', category: 'analytics', name: 'Yandex Metrica' },
  { value: 't_gid', match: 'exact', category: 'marketing', name: 'Taboola' },
  { value: '__qca', match: 'exact', category: 'marketing', name: 'Quantcast' },
];

/** Classifies a cookie name as non-essential, or null. */
export function classifyCookieName(name: string): CookiePattern | null {
  const n = (name || '').trim();
  if (!n) return null;
  for (const p of COOKIE_PATTERNS) {
    if (p.match === 'exact' ? n === p.value : n.startsWith(p.value)) return p;
  }
  return null;
}
