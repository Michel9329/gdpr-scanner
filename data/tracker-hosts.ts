// Host -> tracker classification (entity + purpose). Hand-written for this project.
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

export type TrackerCategory =
  | 'analytics'
  | 'advertising'
  | 'social'
  | 'tag-manager'
  | 'session-replay'
  | 'ab-testing';

export interface TrackerHost {
  /** Match: substring of the hostname (case-insensitive). */
  match: string;
  entity: string;
  name: string;
  category: TrackerCategory;
  /** Analytics that CAN run cookieless/anonymized = exempt from consent (Italian DPA). Conservative:
   *  we do not flag them as a pre-consent violation (we cannot know whether they are anonymized). */
  exempt?: boolean;
}

// Order: more specific matches are not needed (they are substrings of distinct hosts).
export const TRACKER_HOSTS: TrackerHost[] = [
  // --- Google: analytics / tag manager / advertising ---
  { match: 'google-analytics.com', entity: 'Google', name: 'Google Analytics', category: 'analytics' },
  { match: 'analytics.google.com', entity: 'Google', name: 'Google Analytics', category: 'analytics' },
  { match: 'googletagmanager.com', entity: 'Google', name: 'Google Tag Manager', category: 'tag-manager' },
  { match: 'googleadservices.com', entity: 'Google', name: 'Google Ads', category: 'advertising' },
  { match: 'googlesyndication.com', entity: 'Google', name: 'Google AdSense', category: 'advertising' },
  { match: 'doubleclick.net', entity: 'Google', name: 'Google DoubleClick', category: 'advertising' },
  { match: 'google.com/ads', entity: 'Google', name: 'Google Ads', category: 'advertising' },
  { match: 'google.com/pagead', entity: 'Google', name: 'Google Ads', category: 'advertising' },
  { match: 'adservice.google', entity: 'Google', name: 'Google Ads', category: 'advertising' },

  // --- Meta / Facebook ---
  { match: 'connect.facebook.net', entity: 'Meta', name: 'Meta (Pixel or SDK)', category: 'advertising' },
  { match: 'facebook.com/tr', entity: 'Meta', name: 'Meta Pixel', category: 'advertising' },

  // --- Microsoft ---
  { match: 'clarity.ms', entity: 'Microsoft', name: 'Microsoft Clarity', category: 'session-replay' },
  { match: 'bat.bing.com', entity: 'Microsoft', name: 'Microsoft Advertising (UET)', category: 'advertising' },

  // --- Session replay / heatmap ---
  { match: 'hotjar.com', entity: 'Hotjar', name: 'Hotjar', category: 'session-replay' },
  { match: 'hotjar.io', entity: 'Hotjar', name: 'Hotjar', category: 'session-replay' },
  { match: 'mouseflow.com', entity: 'Mouseflow', name: 'Mouseflow', category: 'session-replay' },
  { match: 'fullstory.com', entity: 'FullStory', name: 'FullStory', category: 'session-replay' },
  { match: 'inspectlet.com', entity: 'Inspectlet', name: 'Inspectlet', category: 'session-replay' },
  { match: 'smartlook.com', entity: 'Smartlook', name: 'Smartlook', category: 'session-replay' },

  // --- Social / advertising pixel ---
  { match: 'snap.licdn.com', entity: 'LinkedIn', name: 'LinkedIn Insight Tag', category: 'advertising' },
  { match: 'px.ads.linkedin.com', entity: 'LinkedIn', name: 'LinkedIn Insight Tag', category: 'advertising' },
  { match: 'ads.linkedin.com', entity: 'LinkedIn', name: 'LinkedIn Ads', category: 'advertising' },
  { match: 'analytics.tiktok.com', entity: 'TikTok', name: 'TikTok Pixel', category: 'advertising' },
  { match: 'ads.tiktok.com', entity: 'TikTok', name: 'TikTok Ads', category: 'advertising' },
  { match: 'static.ads-twitter.com', entity: 'X (Twitter)', name: 'Twitter Pixel', category: 'advertising' },
  { match: 'analytics.twitter.com', entity: 'X (Twitter)', name: 'Twitter Analytics', category: 'advertising' },
  { match: 'ct.pinterest.com', entity: 'Pinterest', name: 'Pinterest Tag', category: 'advertising' },
  { match: 's.pinimg.com', entity: 'Pinterest', name: 'Pinterest Tag', category: 'advertising' },
  { match: 'sc-static.net', entity: 'Snap', name: 'Snap Pixel', category: 'advertising' },
  { match: 'tr.snapchat.com', entity: 'Snap', name: 'Snap Pixel', category: 'advertising' },
  { match: 'analytics.reddit.com', entity: 'Reddit', name: 'Reddit Pixel', category: 'advertising' },

  // --- Analytics (third party) ---
  { match: 'matomo', entity: 'Matomo', name: 'Matomo', category: 'analytics', exempt: true },
  { match: 'mixpanel.com', entity: 'Mixpanel', name: 'Mixpanel', category: 'analytics' },
  { match: 'segment.com', entity: 'Twilio Segment', name: 'Segment', category: 'analytics' },
  { match: 'segment.io', entity: 'Twilio Segment', name: 'Segment', category: 'analytics' },
  { match: 'amplitude.com', entity: 'Amplitude', name: 'Amplitude', category: 'analytics' },
  { match: 'heap.io', entity: 'Heap', name: 'Heap', category: 'analytics' },
  { match: 'heapanalytics.com', entity: 'Heap', name: 'Heap', category: 'analytics' },
  { match: 'plausible.io', entity: 'Plausible', name: 'Plausible', category: 'analytics', exempt: true },
  { match: 'hs-analytics.net', entity: 'HubSpot', name: 'HubSpot Analytics', category: 'analytics' },
  { match: 'hs-scripts.com', entity: 'HubSpot', name: 'HubSpot', category: 'analytics' },

  // --- A/B testing / personalization ---
  { match: 'optimizely.com', entity: 'Optimizely', name: 'Optimizely', category: 'ab-testing' },
  { match: 'vwo.com', entity: 'VWO', name: 'VWO', category: 'ab-testing' },
  { match: 'crazyegg.com', entity: 'Crazy Egg', name: 'Crazy Egg', category: 'session-replay' },

  // --- Adobe ---
  { match: '2o7.net', entity: 'Adobe', name: 'Adobe Analytics', category: 'analytics' },
  { match: 'omtrdc.net', entity: 'Adobe', name: 'Adobe Analytics', category: 'analytics' },
  { match: 'demdex.net', entity: 'Adobe', name: 'Adobe Audience Manager', category: 'advertising' },
  { match: 'everesttech.net', entity: 'Adobe', name: 'Adobe Advertising', category: 'advertising' },

  // --- Advertising networks / DSP ---
  { match: 'criteo.com', entity: 'Criteo', name: 'Criteo', category: 'advertising' },
  { match: 'criteo.net', entity: 'Criteo', name: 'Criteo', category: 'advertising' },
  { match: 'taboola.com', entity: 'Taboola', name: 'Taboola', category: 'advertising' },
  { match: 'outbrain.com', entity: 'Outbrain', name: 'Outbrain', category: 'advertising' },
  { match: 'adsrvr.org', entity: 'The Trade Desk', name: 'The Trade Desk', category: 'advertising' },
  { match: 'amazon-adsystem.com', entity: 'Amazon', name: 'Amazon Ads', category: 'advertising' },
  { match: 'quantserve.com', entity: 'Quantcast', name: 'Quantcast Measurement', category: 'advertising' },
  { match: 'ad.yieldmanager.com', entity: 'Yahoo', name: 'Yahoo Advertising', category: 'advertising' },
  { match: 'adroll.com', entity: 'AdRoll', name: 'AdRoll', category: 'advertising' },

  // --- Analytics (third party, EU/RU) ---
  { match: 'mc.yandex.ru', entity: 'Yandex', name: 'Yandex Metrica', category: 'analytics' },
  { match: 'mc.yandex.com', entity: 'Yandex', name: 'Yandex Metrica', category: 'analytics' },
  { match: 'analytics.yahoo.com', entity: 'Yahoo', name: 'Yahoo Analytics (Dot)', category: 'analytics' },

  // --- Marketing automation ---
  { match: 'klaviyo.com', entity: 'Klaviyo', name: 'Klaviyo', category: 'analytics' },
  { match: 'pardot.com', entity: 'Salesforce', name: 'Salesforce Pardot', category: 'analytics' },
  { match: 'marketo.net', entity: 'Adobe', name: 'Marketo', category: 'analytics' },
  { match: 'mktoresp.com', entity: 'Adobe', name: 'Marketo', category: 'analytics' },

  // --- Social share widgets (with tracking) ---
  { match: 'addthis.com', entity: 'Oracle', name: 'AddThis', category: 'social' },
  { match: 'sharethis.com', entity: 'ShareThis', name: 'ShareThis', category: 'social' },
];

/** Hosts considered "essential/functional" (CDN, fonts, static maps, payment): NOT a pre-consent
 *  violation by themselves. NB: Google Fonts has a dedicated check (a specific GDPR issue), not here. */
export const FUNCTIONAL_HINTS: string[] = [
  'gstatic.com',
  'cloudflare.com',
  'cloudflareinsights.com', // Cloudflare privacy-first analytics (no cookie): we do not flag it
  'jsdelivr.net',
  'unpkg.com',
  'cdnjs.cloudflare.com',
  'bunny.net',
  'fontawesome.com',
  'recaptcha.net',
  'gstatic.com/recaptcha',
  'stripe.com',
  'paypal.com',
  'youtube-nocookie.com', // YouTube embed in privacy mode
];

/** Returns the tracker classification for a URL, or null for an unknown/functional host. */
export function classifyTrackerHost(rawUrl: string): TrackerHost | null {
  let host = '';
  try {
    host = new URL(rawUrl).hostname.toLowerCase();
  } catch {
    host = (rawUrl || '').toLowerCase();
  }
  // Known functional host (CDN/font/payment/recaptcha) = never a tracker, even if future rules are broad.
  if (FUNCTIONAL_HINTS.some((h) => host.includes(h))) return null;
  const full = (host + (() => { try { return new URL(rawUrl).pathname; } catch { return ''; } })()).toLowerCase();
  for (const t of TRACKER_HOSTS) {
    if (host.includes(t.match) || full.includes(t.match)) return t;
  }
  return null;
}
