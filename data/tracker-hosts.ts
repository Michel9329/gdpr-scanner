// Request URL -> tracker classification (name + purpose). Hand-written for this project.
//
// Provenance: this list was written by hand from publicly known vendor hostnames. It is NOT copied
// or derived from DuckDuckGo Tracker Radar, Disconnect, EasyPrivacy, WhoTracks.me or any other
// third-party list. See data/README.md if you want to extend it from external sources, and check
// their licenses first.
//
// category: 'analytics' | 'advertising' | 'social' | 'tag-manager' | 'session-replay' | 'ab-testing'
// Tag managers (GTM) are not trackers by themselves but orchestrate other tags, so they are reported
// as "tag-manager" (informational), not as a violation on their own.
//
// Conservative: only KNOWN hosts are classified. An unknown host is never flagged.
import { hostMatches, matchesHostRule, requestParts } from '../src/hosts';

export type TrackerCategory =
  | 'analytics'
  | 'advertising'
  | 'social'
  | 'tag-manager'
  | 'session-replay'
  | 'ab-testing';

export interface TrackerHost {
  /** "vendor.com" (the host or a subdomain), "vendor.com/path" (and the request path under /path)
   *  or "label.vendor.*" (one host per country). See matchesHostRule in src/hosts.ts. */
  match: string;
  /** Self-hosted tools have no fixed host: `match` is then a word looked for in the host and path.
   *  Keyword entries are tried only after every host rule, so a word in the path of a known
   *  vendor's URL never hides that vendor. */
  keyword?: boolean;
  name: string;
  category: TrackerCategory;
  /** Analytics that CAN run cookieless/anonymized = exempt from consent (Italian DPA). Conservative:
   *  we do not flag them as a pre-consent violation (we cannot know whether they are anonymized). */
  exempt?: boolean;
}

// Host rules: the first one that matches wins. Keyword entries come after all of them.
export const TRACKER_HOSTS: TrackerHost[] = [
  // --- Google: analytics / tag manager / advertising ---
  { match: 'google-analytics.com', name: 'Google Analytics', category: 'analytics' },
  { match: 'analytics.google.com', name: 'Google Analytics', category: 'analytics' },
  { match: 'googletagmanager.com', name: 'Google Tag Manager', category: 'tag-manager' },
  { match: 'googleadservices.com', name: 'Google Ads', category: 'advertising' },
  { match: 'googlesyndication.com', name: 'Google AdSense', category: 'advertising' },
  { match: 'doubleclick.net', name: 'Google DoubleClick', category: 'advertising' },
  { match: 'google.com/ads', name: 'Google Ads', category: 'advertising' },
  { match: 'google.com/pagead', name: 'Google Ads', category: 'advertising' },
  { match: 'adservice.google.*', name: 'Google Ads', category: 'advertising' },

  // --- Meta / Facebook ---
  { match: 'connect.facebook.net', name: 'Meta (Pixel or SDK)', category: 'advertising' },
  { match: 'facebook.com/tr', name: 'Meta Pixel', category: 'advertising' },

  // --- Microsoft ---
  { match: 'clarity.ms', name: 'Microsoft Clarity', category: 'session-replay' },
  { match: 'bat.bing.com', name: 'Microsoft Advertising (UET)', category: 'advertising' },

  // --- Session replay / heatmap ---
  { match: 'hotjar.com', name: 'Hotjar', category: 'session-replay' },
  { match: 'hotjar.io', name: 'Hotjar', category: 'session-replay' },
  { match: 'mouseflow.com', name: 'Mouseflow', category: 'session-replay' },
  { match: 'fullstory.com', name: 'FullStory', category: 'session-replay' },
  { match: 'inspectlet.com', name: 'Inspectlet', category: 'session-replay' },
  { match: 'smartlook.com', name: 'Smartlook', category: 'session-replay' },

  // --- Social / advertising pixel ---
  { match: 'snap.licdn.com', name: 'LinkedIn Insight Tag', category: 'advertising' },
  { match: 'px.ads.linkedin.com', name: 'LinkedIn Insight Tag', category: 'advertising' },
  { match: 'ads.linkedin.com', name: 'LinkedIn Ads', category: 'advertising' },
  { match: 'analytics.tiktok.com', name: 'TikTok Pixel', category: 'advertising' },
  { match: 'ads.tiktok.com', name: 'TikTok Ads', category: 'advertising' },
  { match: 'static.ads-twitter.com', name: 'Twitter Pixel', category: 'advertising' },
  { match: 'analytics.twitter.com', name: 'Twitter Analytics', category: 'advertising' },
  { match: 'ct.pinterest.com', name: 'Pinterest Tag', category: 'advertising' },
  { match: 's.pinimg.com', name: 'Pinterest Tag', category: 'advertising' },
  { match: 'sc-static.net', name: 'Snap Pixel', category: 'advertising' },
  { match: 'tr.snapchat.com', name: 'Snap Pixel', category: 'advertising' },
  { match: 'analytics.reddit.com', name: 'Reddit Pixel', category: 'advertising' },

  // --- Analytics (third party) ---
  { match: 'matomo', keyword: true, name: 'Matomo', category: 'analytics', exempt: true },
  { match: 'mixpanel.com', name: 'Mixpanel', category: 'analytics' },
  { match: 'segment.com', name: 'Segment', category: 'analytics' },
  { match: 'segment.io', name: 'Segment', category: 'analytics' },
  { match: 'amplitude.com', name: 'Amplitude', category: 'analytics' },
  { match: 'heap.io', name: 'Heap', category: 'analytics' },
  { match: 'heapanalytics.com', name: 'Heap', category: 'analytics' },
  { match: 'plausible.io', name: 'Plausible', category: 'analytics', exempt: true },
  { match: 'hs-analytics.net', name: 'HubSpot Analytics', category: 'analytics' },
  { match: 'hs-scripts.com', name: 'HubSpot', category: 'analytics' },

  // --- A/B testing / personalization ---
  { match: 'optimizely.com', name: 'Optimizely', category: 'ab-testing' },
  { match: 'vwo.com', name: 'VWO', category: 'ab-testing' },
  { match: 'crazyegg.com', name: 'Crazy Egg', category: 'session-replay' },

  // --- Adobe ---
  { match: '2o7.net', name: 'Adobe Analytics', category: 'analytics' },
  { match: 'omtrdc.net', name: 'Adobe Analytics', category: 'analytics' },
  { match: 'demdex.net', name: 'Adobe Audience Manager', category: 'advertising' },
  { match: 'everesttech.net', name: 'Adobe Advertising', category: 'advertising' },

  // --- Advertising networks / DSP ---
  { match: 'criteo.com', name: 'Criteo', category: 'advertising' },
  { match: 'criteo.net', name: 'Criteo', category: 'advertising' },
  { match: 'taboola.com', name: 'Taboola', category: 'advertising' },
  { match: 'outbrain.com', name: 'Outbrain', category: 'advertising' },
  { match: 'adsrvr.org', name: 'The Trade Desk', category: 'advertising' },
  { match: 'amazon-adsystem.com', name: 'Amazon Ads', category: 'advertising' },
  { match: 'quantserve.com', name: 'Quantcast Measurement', category: 'advertising' },
  { match: 'ad.yieldmanager.com', name: 'Yahoo Advertising', category: 'advertising' },
  { match: 'adroll.com', name: 'AdRoll', category: 'advertising' },

  // --- Analytics (third party, EU/RU) ---
  { match: 'mc.yandex.ru', name: 'Yandex Metrica', category: 'analytics' },
  { match: 'mc.yandex.com', name: 'Yandex Metrica', category: 'analytics' },
  { match: 'analytics.yahoo.com', name: 'Yahoo Analytics (Dot)', category: 'analytics' },

  // --- Marketing automation ---
  { match: 'klaviyo.com', name: 'Klaviyo', category: 'analytics' },
  { match: 'pardot.com', name: 'Salesforce Pardot', category: 'analytics' },
  { match: 'marketo.net', name: 'Marketo', category: 'analytics' },
  { match: 'mktoresp.com', name: 'Marketo', category: 'analytics' },

  // --- Social share widgets (with tracking) ---
  { match: 'addthis.com', name: 'AddThis', category: 'social' },
  { match: 'sharethis.com', name: 'ShareThis', category: 'social' },
];

/** Hosts considered "essential/functional" (CDN, fonts, static maps, payment): never reported as a
 *  tracker, whatever the list above says. Google Fonts has its own check in detect.ts. */
export const FUNCTIONAL_HOSTS: string[] = [
  'gstatic.com',
  'cloudflare.com',
  'cloudflareinsights.com', // Cloudflare privacy-first analytics (no cookie): we do not flag it
  'jsdelivr.net',
  'unpkg.com',
  'bunny.net',
  'b-cdn.net',
  'fontawesome.com',
  'recaptcha.net',
  'stripe.com',
  'paypal.com',
  'youtube-nocookie.com', // YouTube embed in privacy mode
];

const HOST_RULES = TRACKER_HOSTS.filter((t) => !t.keyword);
const KEYWORD_RULES = TRACKER_HOSTS.filter((t) => t.keyword);

/** Returns the tracker classification for a request URL, or null for an unknown or functional host.
 *  A URL that cannot be parsed is unknown. Host rules are tried first, keyword entries last. */
export function classifyTrackerUrl(rawUrl: string): TrackerHost | null {
  const req = requestParts(rawUrl);
  if (!req.host) return null;
  if (FUNCTIONAL_HOSTS.some((h) => hostMatches(req.host, h))) return null;
  for (const t of HOST_RULES) {
    if (matchesHostRule(t.match, req)) return t;
  }
  for (const t of KEYWORD_RULES) {
    if ((req.host + req.path).includes(t.match)) return t;
  }
  return null;
}
