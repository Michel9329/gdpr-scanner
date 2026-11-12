// Detection signatures for consent management platforms (cookie banners). Hand-written.
//
// Provenance: written from the vendors' public documentation (CDN hosts, global JS variables, cookie
// names, known DOM selectors). Consent-O-Matic (MIT) was used only as a conceptual reference. The
// scanner never clicks "accept"; it only needs to know whether a CMP is present and which one.
//
// Match: ONE signal (network host, JS global, cookie or DOM selector) is enough to call a CMP
// present. The list covers common CMPs in the Italian/EU market. A home-made banner can be missed;
// in that case the report says "no known CMP", which is not a finding by itself.
//
export interface CmpSignature {
  id: string;
  name: string;
  /** hostname substrings seen in network requests */
  hosts: string[];
  /** property names on window (presence = CMP active) */
  globals: string[];
  /** typical cookie names (or prefixes) of the CMP */
  cookies: string[];
  /** CSS selectors of the banner (for DOM detection) */
  selectors: string[];
}

export const CMP_SIGNATURES: CmpSignature[] = [
  {
    id: 'iubenda',
    name: 'Iubenda',
    hosts: ['cdn.iubenda.com', 'cs.iubenda.com', 'iubenda.com'],
    globals: ['_iub'],
    cookies: ['_iub_cs', 'euconsent-v2'],
    selectors: ['#iubenda-cs-banner', '.iubenda-cs-container', '#iubFooterBtn'],
  },
  {
    id: 'cookiebot',
    name: 'Cookiebot',
    hosts: ['consent.cookiebot.com', 'consentcdn.cookiebot.com', 'cookiebot.eu'],
    globals: ['Cookiebot', 'CookieConsent'],
    cookies: ['CookieConsent'],
    selectors: ['#CybotCookiebotDialog', '#CookiebotWidget'],
  },
  {
    id: 'onetrust',
    name: 'OneTrust',
    hosts: ['cdn.cookielaw.org', 'cdn-ukwest.onetrust.com', 'onetrust.com', 'optanon'],
    globals: ['OneTrust', 'Optanon', 'OptanonActiveGroups'],
    cookies: ['OptanonConsent', 'OptanonAlertBoxClosed'],
    selectors: ['#onetrust-banner-sdk', '#onetrust-consent-sdk'],
  },
  {
    id: 'cookieyes',
    name: 'CookieYes',
    hosts: ['cdn-cookieyes.com', 'cookieyes.com'],
    globals: ['CookieYes', 'cookieyes'],
    cookies: ['cookieyes-consent'],
    selectors: ['.cky-consent-bar', '#cookieyes', '.cky-modal'],
  },
  {
    id: 'usercentrics',
    name: 'Usercentrics',
    hosts: ['usercentrics.eu', 'app.usercentrics.eu', 'api.usercentrics.eu', 'privacy-proxy.usercentrics.eu'],
    globals: ['UC_UI', 'usercentrics', '__ucCmp'],
    cookies: ['usercentrics', 'uc_settings', 'ucData'],
    selectors: ['#usercentrics-root', '#uc-center-container'],
  },
  {
    id: 'complianz',
    name: 'Complianz',
    hosts: [],
    globals: ['cmplz', 'complianz'],
    cookies: ['cmplz_consent_status', 'cmplz_banner-status', 'complianz_consent_status'],
    selectors: ['#cmplz-cookiebanner-container', '.cmplz-cookiebanner'],
  },
  {
    id: 'cookie-script',
    name: 'Cookie Script',
    hosts: ['cookie-script.com', 'cdn.cookie-script.com'],
    globals: ['CookieScript'],
    cookies: ['CookieScriptConsent'],
    selectors: ['#cookiescript_injected', '.cookiescript_badge'],
  },
  {
    id: 'termly',
    name: 'Termly',
    hosts: ['app.termly.io', 'termly.io'],
    globals: ['Termly', 'TERMLY_API_CACHE'],
    cookies: ['TERMLY_API_CACHE'],
    selectors: ['#termly-code-snippet-support', '.termly-styles-root'],
  },
  {
    id: 'didomi',
    name: 'Didomi',
    hosts: ['sdk.privacy-center.org', 'didomi.io'],
    globals: ['Didomi', 'didomiState'],
    cookies: ['didomi_token', 'euconsent-v2'],
    selectors: ['#didomi-host', '.didomi-popup-container'],
  },
  {
    id: 'quantcast',
    name: 'Quantcast Choice',
    hosts: ['quantcast.mgr.consensu.org', 'cmp.quantcast.com'],
    // NB: no __cmp/__tcfapi here (they are generic IAB TCF APIs, not specific to Quantcast: they would cause
    // misattribution). Quantcast is still detected via host/cookie/selectors; generic TCF has its own fallback.
    globals: [],
    cookies: ['euconsent-v2', '__cmpconsentx'],
    selectors: ['.qc-cmp2-container', '#qc-cmp2-ui'],
  },
  {
    id: 'osano',
    name: 'Osano',
    hosts: ['cmp.osano.com', 'osano.com'],
    globals: ['Osano'],
    cookies: ['osano_consentmanager'],
    selectors: ['.osano-cm-window', '.osano-cm-dialog'],
  },
  {
    id: 'borlabs',
    name: 'Borlabs Cookie',
    hosts: [],
    globals: ['BorlabsCookie'],
    cookies: ['borlabs-cookie'],
    selectors: ['#BorlabsCookieBox', '._brlbs-bar'],
  },
];
