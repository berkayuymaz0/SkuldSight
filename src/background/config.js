'use strict';

const VT_API = 'https://www.virustotal.com/api/v3';
const APP_NAME = 'SkuldSight SOC';
const utils = globalThis.VtSocUtils;
const guards = globalThis.VtBackgroundGuards;
const SK = utils.STORAGE_KEYS;
/** Canonical HTTPS endpoints; Dark Reading RSS is behind Cloudflare (no usable XML for extensions). */
const NEWS_FEED_URLS = [
  'https://www.bleepingcomputer.com/feed/',
  'https://cyberscoop.com/feed/',
  'https://krebsonsecurity.com/feed/',
  'https://www.securityweek.com/feed/',
  'https://feeds.feedburner.com/TheHackersNews'
];
const NEWS_CACHE_KEY = SK.newsCache;
const NEWS_CACHE_AT_KEY = SK.newsFetchedAt;
const NEWS_CACHE_TTL_MS = 10 * 60 * 1000;
const NEWS_AUTO_REFRESH_ALARM = 'vtNewsAutoRefresh';
const USOM_INDEX_URL = 'https://siberguvenlik.gov.tr/api/incident/index';
const USOM_API_BASE = 'https://siberguvenlik.gov.tr/api/incident/';
const USOM_CACHE_KEY = SK.usomCache;
const USOM_CACHE_AT_KEY = SK.usomFetchedAt;
const USOM_CACHE_TTL_MS = 10 * 60 * 1000;
const USOM_AUTO_REFRESH_ALARM = 'vtUsomAutoRefresh';
const NEWS_MAX_ITEMS = 20;
const NEWS_FETCH_TIMEOUT_MS = 12000;
/** Limit parallel RSS fetches to reduce connection pressure on slow hosts. */
const NEWS_FEED_FETCH_CONCURRENCY = 3;
/**
 * VT v3: one relationship GET per IoC kind (path /{collection}/{id}/{relationship}?limit=N).
 * file: IPs contacted; ip/domain: resolution history; url: domains contacted.
 * @see https://developers.virustotal.com/reference/files-relationships
 */
const VT_REL_PREVIEW_BY_KIND = {
  file: { relationship: 'contacted_ips', limit: 10 },
  ip: { relationship: 'resolutions', limit: 10 },
  domain: { relationship: 'resolutions', limit: 10 },
  url: { relationship: 'contacted_domains', limit: 10 }
};
/** Optional second relationship when rel preview is enabled (P2; may 403 on some API tiers). */
const VT_REL_SECONDARY_BY_KIND = {
  file: { relationship: 'contacted_domains', limit: 10 },
  ip: { relationship: 'communicating_files', limit: 10 },
  domain: { relationship: 'communicating_files', limit: 10 }
};
const MAX_HISTORY_REL_ITEMS = 5;
const MAX_HISTORY_REL_STR = 200;
const MAX_HISTORY_ENGINE_ROWS = 40;
const MAX_HISTORY_MITRE_IDS = 40;
const NOTIFY_WAIT_MS = 800;
const NOTIFY_MESSAGE_MAX = 250;
/** VT analysis polling after URL submit or reanalyze (single-scan only; batch skips). */
const VT_ANALYSIS_POLL_MAX = 8;
const VT_ANALYSIS_POLL_INTERVAL_MS = 20000;
/** Minimum spacing between VT calls when pro mode disables normal pacing. */
const PRO_MODE_MIN_INTERVAL_MS = 1000;
const VT_429_MAX_RETRIES = 3;
const VT_429_BACKOFF_BASE_MS = 16000;
const VT_429_BACKOFF_MAX_MS = 60000;

// uniqueNotificationId: Her bildirim için benzersiz id (sabit id yeniden uyarmaz).
function uniqueNotificationId(kind) {
  return 'skuldsight-' + String(kind || 'alert') + '-' + String(Date.now());
}

// showNotification: Temel extension bildirimi (benzersiz id, kısaltılmış mesaj).
function showNotification(kind, title, message) {
  try {
    let msg = String(message || '');
    if (msg.length > NOTIFY_MESSAGE_MAX) {
      msg = msg.slice(0, NOTIFY_MESSAGE_MAX - 3) + '...';
    }
    chrome.notifications.create(uniqueNotificationId(kind), {
      type: 'basic',
      iconUrl: chrome.runtime.getURL('assets/icons/icon48.png'),
      title: String(title || APP_NAME),
      message: msg
    });
  } catch (_) {}
}
const MAX_RECENT_ENTRIES = 50;
const MAX_BATCH_HISTORY_ENTRIES = 5;
const ANALYTICS_KEY = SK.analytics;
const ANALYTICS_DAYS_KEEP = 60;
const ANALYTICS_VERSION = 2;

const clampRateSec = utils.clampRateSec;
const normalizeIocInput = utils.normalizeIocInput;

/** Next allowed VT request time (epoch ms); enforced via consumeVtRateSlot inside vtFetch. */
let nextSlotAt = 0;
let rateIntervalMs = clampRateSec() * 1000;
let proModeEnabled = false;
let notifyQueuedEnabled = true;
let notifyNewsEnabled = true;
let notifyContextEnabled = true;

// applySettingsSnapshot: Bellekteki ayar nesnesini anlık görüntüye göre günceller.
