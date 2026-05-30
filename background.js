'use strict';

importScripts('utils.js');
importScripts('background-guards.js');

/**
 * Service worker: VirusTotal API v3 calls, client-side rate limiting, scan job queue,
 * context menu scans, and long-lived ports for popup/content batch and single scans.
 */

const VT_API = 'https://www.virustotal.com/api/v3';
const APP_NAME = 'PixelPaw SOC';
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
const USOM_INDEX_URL = 'https://www.usom.gov.tr/api/incident/index';
const USOM_API_BASE = 'https://www.usom.gov.tr/api/incident/';
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

// uniqueNotificationId: Her bildirim için benzersiz id (sabit id yeniden uyarmaz).
function uniqueNotificationId(kind) {
  return 'pixelpaw-' + String(kind || 'alert') + '-' + String(Date.now());
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
      iconUrl: chrome.runtime.getURL('icons/icon48.png'),
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
function applySettingsSnapshot(data) {
  const src = data || {};
  rateIntervalMs = clampRateSec(src.vtRateIntervalSec) * 1000;
  proModeEnabled = src.vtProMode === true;
  notifyQueuedEnabled = src.vtNotifyQueued !== false;
  notifyNewsEnabled = src.vtNotifyNews !== false;
  notifyContextEnabled = src.vtNotifyContext !== false;
}

// refreshSettingsFromStorage: chrome.storage'dan ayarları okuyup bellekteki kopyayı yeniler.
async function refreshSettingsFromStorage() {
  const data = await chrome.storage.local.get([
    'vtRateIntervalSec',
    'vtProMode',
    'vtNotifyQueued',
    'vtNotifyNews',
    'vtNotifyContext',
    UI_MODE_KEY
  ]);
  applySettingsSnapshot(data);
  currentUiMode = data[UI_MODE_KEY] === 'sidepanel' ? 'sidepanel' : 'popup';
}

// applySettingChanges: Kısmi ayar değişikliklerini uygular ve ilgili yan etkileri tetikler.
function applySettingChanges(changes) {
  if (changes.vtRateIntervalSec) {
    rateIntervalMs = clampRateSec(changes.vtRateIntervalSec.newValue) * 1000;
  }
  if (changes.vtProMode) {
    proModeEnabled = changes.vtProMode.newValue === true;
  }
  if (changes.vtNotifyQueued) {
    notifyQueuedEnabled = changes.vtNotifyQueued.newValue !== false;
  }
  if (changes.vtNotifyNews) {
    notifyNewsEnabled = changes.vtNotifyNews.newValue !== false;
  }
  if (changes.vtNotifyContext) {
    notifyContextEnabled = changes.vtNotifyContext.newValue !== false;
  }
}

const UI_MODE_KEY = SK.uiMode;
/** Latest external scan (context menu or VT badge) for popup/side panel on open (see popup.js). */
const CONTEXT_SCAN_RESULT_KEY = SK.contextScanResult;
const POPUP_PATH = 'popup.html';
const PANEL_PATH = 'popup.html?surface=sidepanel';
/** In-memory UI mode mirror for notification gating without extra storage reads. */
let currentUiMode = 'popup';

// closeGlobalSidePanel: Popup moduna geçerken açık global yan paneli kapatır.
async function closeGlobalSidePanel() {
  if (!chrome.sidePanel || typeof chrome.sidePanel.close !== 'function') {
    return;
  }
  try {
    const win = await chrome.windows.getLastFocused();
    if (win && win.id != null) {
      await chrome.sidePanel.close({ windowId: win.id });
    }
  } catch (_) {}
}

// isExternalScanPersistSource: Sonucu popup/yan panelde göstermek için saklanır.
function isExternalScanPersistSource(source) {
  return source === 'context' || source === 'content';
}

// isContextMenuScanSource: Yalnızca sağ tık menüsü taraması (bildirim için).
function isContextMenuScanSource(source) {
  return source === 'context';
}

// applyUiMode: Toolbar tıklamasında popup veya yan panel açılmasını yapılandırır.
async function applyUiMode(mode) {
  currentUiMode = mode === 'sidepanel' ? 'sidepanel' : 'popup';
  const isPanel = mode === 'sidepanel';
  if (!chrome.sidePanel) {
    try {
      await chrome.action.setPopup({ popup: POPUP_PATH });
    } catch (_) {}
    return;
  }
  try {
    if (isPanel) {
      await chrome.action.setPopup({ popup: '' });
      await chrome.sidePanel.setOptions({ path: PANEL_PATH, enabled: true });
      await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
    } else {
      await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false });
      await chrome.action.setPopup({ popup: POPUP_PATH });
      await closeGlobalSidePanel();
    }
  } catch (_) {
    try {
      await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false });
    } catch (_e) {}
    try {
      await chrome.action.setPopup({ popup: POPUP_PATH });
    } catch (_e2) {}
  }
}

// refreshUiModeFromStorage: Kayıtlı vtUiMode değerine göre arayüz modunu uygular.
async function refreshUiModeFromStorage() {
  const data = await chrome.storage.local.get(UI_MODE_KEY);
  const mode = data[UI_MODE_KEY] === 'sidepanel' ? 'sidepanel' : 'popup';
  currentUiMode = mode;
  await applyUiMode(mode);
}

// shouldNotifyContextMenuScan: Sağ tık bildirimi yalnızca popup modunda (storage okunur).
async function shouldNotifyContextMenuScan() {
  const data = await chrome.storage.local.get(['vtNotifyContext', UI_MODE_KEY]);
  notifyContextEnabled = data.vtNotifyContext !== false;
  currentUiMode = data[UI_MODE_KEY] === 'sidepanel' ? 'sidepanel' : 'popup';
  return notifyContextEnabled && currentUiMode === 'popup';
}

// notifyContextMenuScanOutcome: Popup modunda sağ tık tarama sonuç bildirimi.
async function notifyContextMenuScanOutcome(payload) {
  if (!(await shouldNotifyContextMenuScan())) {
    return;
  }
  if (payload && payload.ok) {
    const s = payload.stats || {};
    showNotification(
      'context',
      APP_NAME + ' — ' + (payload.iocKind || 'IoC'),
      'Malicious: ' +
        (Number(s.malicious) || 0) +
        ', Suspicious: ' +
        (Number(s.suspicious) || 0) +
        ', Undetected: ' +
        (Number(s.undetected) || 0)
    );
    return;
  }
  showNotification(
    'context',
    APP_NAME,
    payload && payload.error ? String(payload.error) : 'Scan failed'
  );
}

// persistContextScanResult: Sağ tık tarama sonucunu popup/yan panel için saklar.
async function persistContextScanResult(payload, rawIoc) {
  const row = {
    ioc: rawIoc != null ? String(rawIoc).trim().slice(0, 2000) : '',
    ts: Date.now(),
    payload:
      payload && payload.ok
        ? trimPayloadForHistory(payload)
        : payload && typeof payload === 'object'
          ? {
              ok: false,
              error: payload.error
                ? String(payload.error).slice(0, 500)
                : 'Scan failed'
            }
          : { ok: false, error: 'Scan failed' }
  };
  if (!row.ioc && row.payload && row.payload.ioc) {
    row.ioc = String(row.payload.ioc);
  }
  await chrome.storage.local.set({ [CONTEXT_SCAN_RESULT_KEY]: row });
}

chrome.storage.onChanged.addListener(function (changes, area) {
  if (area !== 'local') {
    return;
  }
  applySettingChanges(changes);
  if (changes[UI_MODE_KEY]) {
    const mode = changes[UI_MODE_KEY].newValue === 'sidepanel' ? 'sidepanel' : 'popup';
    currentUiMode = mode;
    applyUiMode(mode).catch(function () {});
  }
});

refreshSettingsFromStorage().catch(function () {});
refreshUiModeFromStorage().catch(function () {});

// sleep: Belirtilen süre için Promise ile bekler (alarm/geri deneme için).
function sleep(ms) {
  return new Promise(function (r) {
    setTimeout(r, ms);
  });
}

// decodeXmlEntities: RSS/XML metnindeki varlık referanslarını düz metne çevirir.
function decodeXmlEntities(text) {
  if (text == null) {
    return '';
  }
  return String(text)
    .replace(/<!\[CDATA\[(.*?)\]\]>/gs, '$1')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&#8217;/g, "'")
    .replace(/&#8216;/g, "'")
    .replace(/&#8220;/g, '"')
    .replace(/&#8221;/g, '"')
    .replace(/&#8230;/g, '...')
    .replace(/&#(\d+);/g, function (_, n) {
      const num = Number(n);
      return isFinite(num) ? String.fromCharCode(num) : '';
    });
}

// extractRssTag: Haber RSS çekimi, ayrıştırma veya önbellek yolu.
function extractRssTag(block, tagName) {
  const re = new RegExp('<' + tagName + '[^>]*>([\\s\\S]*?)</' + tagName + '>', 'i');
  const m = String(block || '').match(re);
  return m ? decodeXmlEntities(m[1]).replace(/<[^>]+>/g, '').trim() : '';
}

// feedSourceFromUrl: Haber RSS çekimi, ayrıştırma veya önbellek yolu.
function feedSourceFromUrl(feedUrl) {
  const u = String(feedUrl || '').toLowerCase();
  if (u.indexOf('bleepingcomputer.com') !== -1) {
    return 'BleepingComputer';
  }
  if (u.indexOf('cyberscoop.com') !== -1) {
    return 'CyberScoop';
  }
  if (u.indexOf('krebsonsecurity.com') !== -1) {
    return 'Krebs on Security';
  }
  if (u.indexOf('thehackernews.com') !== -1 || u.indexOf('thehackersnews') !== -1) {
    return 'The Hacker News';
  }
  if (u.indexOf('securityweek.com') !== -1 || u.indexOf('feedburner.com/securityweek') !== -1) {
    return 'SecurityWeek';
  }
  return 'News';
}

// extractAtomLink: Haber RSS çekimi, ayrıştırma veya önbellek yolu.
function extractAtomLink(block) {
  const s = String(block || '');
  const relFirst = /<link[^>]*\brel=["']alternate["'][^>]*\bhref=["']([^"']+)["'][^>]*\/?>/i;
  const mRel = s.match(relFirst);
  if (mRel && mRel[1]) {
    return decodeXmlEntities(mRel[1]).trim();
  }
  const hrefFirst = /<link[^>]*\bhref=["']([^"']+)["'][^>]*\brel=["']alternate["'][^>]*\/?>/i;
  const mHrefRel = s.match(hrefFirst);
  if (mHrefRel && mHrefRel[1]) {
    return decodeXmlEntities(mHrefRel[1]).trim();
  }
  const hrefRe = /<link[^>]*\bhref=["']([^"']+)["'][^>]*\/?>/i;
  const hrefMatch = s.match(hrefRe);
  return hrefMatch && hrefMatch[1] ? decodeXmlEntities(hrefMatch[1]).trim() : '';
}

// rssItemPermalink: RSS <item> içinde makale URL'si; bazı kaynaklarda <link> boş, URL <guid>'dedir.
function rssItemPermalink(block) {
  const link = extractRssTag(block, 'link');
  if (link) {
    return link;
  }
  const guid = extractRssTag(block, 'guid');
  if (guid && /^https?:\/\//i.test(guid)) {
    return guid;
  }
  return '';
}

// parseFeedItems: Haber RSS çekimi, ayrıştırma veya önbellek yolu.
function parseFeedItems(xmlText, feedUrl) {
  const xml = String(xmlText || '');
  const source = feedSourceFromUrl(feedUrl);
  const items = [];
  const itemBlocks = xml.match(/<item\b[\s\S]*?<\/item>/gi) || [];
  if (itemBlocks.length > 0) {
    for (let i = 0; i < itemBlocks.length && items.length < NEWS_MAX_ITEMS; i++) {
      const block = itemBlocks[i];
      const title = extractRssTag(block, 'title');
      const link = rssItemPermalink(block);
      const pubDate = extractRssTag(block, 'pubDate');
      if (!title || !link) {
        continue;
      }
      items.push({
        title: title.slice(0, 300),
        link: link.slice(0, 1000),
        pubDate: pubDate.slice(0, 120),
        source: source
      });
    }
    return items;
  }
  const entryBlocks = xml.match(/<entry\b[\s\S]*?<\/entry>/gi) || [];
  for (let i = 0; i < entryBlocks.length && items.length < NEWS_MAX_ITEMS; i++) {
    const block = entryBlocks[i];
    const title = extractRssTag(block, 'title');
    const link = extractAtomLink(block);
    const pubDate = extractRssTag(block, 'published') || extractRssTag(block, 'updated');
    if (!title || !link) {
      continue;
    }
    items.push({
      title: title.slice(0, 300),
      link: link.slice(0, 1000),
      pubDate: pubDate.slice(0, 120),
      source: source
    });
  }
  return items;
}

// fetchTextWithTimeout: URL'den metin çeker; süre aşımında isteği iptal eder.
async function fetchTextWithTimeout(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(function () {
    controller.abort();
  }, timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'GET',
      cache: 'no-store',
      signal: controller.signal
    });
    const text = await res.text();
    if (!res.ok) {
      throw new Error('[' + url + '] HTTP ' + res.status);
    }
    return text;
  } catch (err) {
    if (err && err.name === 'AbortError') {
      throw new Error('[' + url + '] timeout');
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

// fetchNewsFeedNow: Haber RSS çekimi, ayrıştırma veya önbellek yolu.
async function fetchNewsFeedNow() {
  const urls = NEWS_FEED_URLS;
  const settled = [];
  for (let offset = 0; offset < urls.length; offset += NEWS_FEED_FETCH_CONCURRENCY) {
    const chunk = urls.slice(offset, offset + NEWS_FEED_FETCH_CONCURRENCY);
    const part = await Promise.allSettled(
      chunk.map(async function (url) {
        const text = await fetchTextWithTimeout(url, NEWS_FETCH_TIMEOUT_MS);
        return parseFeedItems(text, url);
      })
    );
    for (let i = 0; i < part.length; i++) {
      settled.push(part[i]);
    }
  }
  const merged = [];
  const errors = [];
  for (let i = 0; i < settled.length; i++) {
    const row = settled[i];
    if (row.status === 'fulfilled') {
      merged.push.apply(merged, row.value || []);
    } else {
      errors.push(
        row.reason && row.reason.message
          ? String(row.reason.message)
          : 'feed failed'
      );
    }
  }
  const seen = {};
  const items = merged
    .filter(function (it) {
      const key = String((it.link || '') + '|' + (it.title || '')).trim();
      if (!key || seen[key]) {
        return false;
      }
      seen[key] = true;
      return true;
    })
    .sort(function (a, b) {
      const ta = Date.parse(a.pubDate || '') || 0;
      const tb = Date.parse(b.pubDate || '') || 0;
      return tb - ta;
    })
    .slice(0, NEWS_MAX_ITEMS);
  if (!items.length && errors.length) {
    throw new Error(errors[0] || 'No news items parsed from feeds');
  }
  const fetchedAt = Date.now();
  if (items.length > 0) {
    await chrome.storage.local.set({
      [NEWS_CACHE_KEY]: items,
      [NEWS_CACHE_AT_KEY]: fetchedAt
    });
  }
  return {
    ok: true,
    items: items,
    fetchedAt: fetchedAt,
    cached: false,
    warning: ''
  };
}

// getNewsPayload: Haber RSS çekimi, ayrıştırma veya önbellek yolu.
async function getNewsPayload(forceRefresh) {
  const data = await chrome.storage.local.get([NEWS_CACHE_KEY, NEWS_CACHE_AT_KEY]);
  const cache = Array.isArray(data[NEWS_CACHE_KEY]) ? data[NEWS_CACHE_KEY] : [];
  const fetchedAt = Number(data[NEWS_CACHE_AT_KEY]) || 0;
  const isFresh = cache.length > 0 && fetchedAt > 0 && Date.now() - fetchedAt < NEWS_CACHE_TTL_MS;
  if (!forceRefresh && isFresh) {
    return { ok: true, items: cache, fetchedAt: fetchedAt, cached: true };
  }
  try {
    const fresh = await fetchNewsFeedNow();
    if (fresh.items && fresh.items.length > 0) {
      return fresh;
    }
    if (cache.length > 0) {
      return {
        ok: true,
        items: cache,
        fetchedAt: fetchedAt,
        cached: true,
        stale: true,
        warning: fresh.warning || 'Feed refresh returned no items'
      };
    }
    return {
      ok: true,
      items: [],
      fetchedAt: Date.now(),
      cached: false,
      warning: fresh.warning || 'Feed refresh returned no items'
    };
  } catch (err) {
    if (cache.length > 0) {
      return {
        ok: true,
        items: cache,
        fetchedAt: fetchedAt,
        cached: true,
        stale: true,
        warning: err && err.message ? String(err.message) : 'Feed refresh failed'
      };
    }
    throw err;
  }
}

// uniqueNewsKey: Haber öğesi için tekrarları önleyecek benzersiz anahtar üretir.
function uniqueNewsKey(item) {
  const link = item && item.link ? String(item.link).trim() : '';
  const title = item && item.title ? String(item.title).trim() : '';
  return (link || title).slice(0, 1200);
}

// parseUsomTags: USOM olay listesi veya detay isteği.
function parseUsomTags(raw) {
  const text = String(raw || '').trim();
  if (!text) {
    return [];
  }
  try {
    const arr = JSON.parse(text);
    if (Array.isArray(arr)) {
      return arr.map(function (v) { return String(v || '').trim(); }).filter(Boolean);
    }
  } catch (_) {}
  return text
    .replace(/[{}[\]"]/g, '')
    .split(/[;,]/)
    .map(function (v) { return String(v || '').trim(); })
    .filter(Boolean);
}

// normalizeUsomItem: USOM olay listesi veya detay isteği.
function normalizeUsomItem(row) {
  if (!row || typeof row !== 'object') {
    return null;
  }
  return {
    id: Number(row.id) || 0,
    slug: row.slug ? String(row.slug).trim() : '',
    title: row.title ? String(row.title).trim().slice(0, 400) : '',
    desc: row.desc ? String(row.desc) : '',
    date: row.date ? String(row.date).trim() : '',
    language: row.language ? String(row.language).trim() : '',
    active: row.active !== false,
    tags: parseUsomTags(row.tags)
  };
}

// usomItemKey: USOM olay listesi veya detay isteği.
function usomItemKey(item) {
  if (!item || typeof item !== 'object') {
    return '';
  }
  if (item.id) {
    return 'id:' + String(item.id);
  }
  if (item.slug) {
    return 'slug:' + String(item.slug);
  }
  return 'title:' + String(item.title || '').trim();
}

// fetchUsomIndexNow: USOM olay listesi veya detay isteği.
async function fetchUsomIndexNow() {
  const text = await fetchTextWithTimeout(USOM_INDEX_URL, NEWS_FETCH_TIMEOUT_MS);
  let json = null;
  try {
    json = JSON.parse(text);
  } catch (_) {
    throw new Error('USOM index returned invalid JSON');
  }
  const list = Array.isArray(json && json.models) ? json.models : [];
  const items = list
    .map(normalizeUsomItem)
    .filter(function (x) { return !!x && !!x.title; })
    .slice(0, 60);
  const fetchedAt = Date.now();
  await chrome.storage.local.set({
    [USOM_CACHE_KEY]: items,
    [USOM_CACHE_AT_KEY]: fetchedAt
  });
  return {
    ok: true,
    items: items,
    fetchedAt: fetchedAt,
    cached: false
  };
}

// getUsomPayload: USOM olay listesi veya detay isteği.
async function getUsomPayload(forceRefresh) {
  const data = await chrome.storage.local.get([USOM_CACHE_KEY, USOM_CACHE_AT_KEY]);
  const cache = Array.isArray(data[USOM_CACHE_KEY]) ? data[USOM_CACHE_KEY] : [];
  const fetchedAt = Number(data[USOM_CACHE_AT_KEY]) || 0;
  const isFresh = cache.length > 0 && fetchedAt > 0 && Date.now() - fetchedAt < USOM_CACHE_TTL_MS;
  if (!forceRefresh && isFresh) {
    return { ok: true, items: cache, fetchedAt: fetchedAt, cached: true };
  }
  try {
    return await fetchUsomIndexNow();
  } catch (err) {
    if (cache.length > 0) {
      return {
        ok: true,
        items: cache,
        fetchedAt: fetchedAt,
        cached: true,
        stale: true,
        warning: err && err.message ? String(err.message) : 'USOM refresh failed'
      };
    }
    throw err;
  }
}

// pickUsomDetailModel: USOM olay listesi veya detay isteği.
function pickUsomDetailModel(raw) {
  if (!raw) return null;
  if (raw.model && typeof raw.model === 'object') return raw.model;
  if (Array.isArray(raw.models) && raw.models[0]) return raw.models[0];
  if (raw.data && typeof raw.data === 'object') return raw.data;
  if (raw.id || raw.title || raw.desc) return raw;
  return null;
}

// fetchUsomDetail: USOM olay listesi veya detay isteği.
async function fetchUsomDetail(query) {
  const id = Number(query && query.id) || 0;
  const slug = query && query.slug ? String(query.slug).trim() : '';
  const candidates = [];
  if (id > 0) {
    candidates.push(USOM_API_BASE + 'view?id=' + encodeURIComponent(String(id)));
    candidates.push(USOM_API_BASE + 'detail?id=' + encodeURIComponent(String(id)));
    candidates.push(USOM_API_BASE + 'index?id=' + encodeURIComponent(String(id)));
    candidates.push(USOM_API_BASE + String(id));
  }
  if (slug) {
    candidates.push(USOM_API_BASE + 'view?slug=' + encodeURIComponent(slug));
    candidates.push(USOM_API_BASE + 'detail?slug=' + encodeURIComponent(slug));
    candidates.push(USOM_API_BASE + slug);
  }
  for (let i = 0; i < candidates.length; i++) {
    const url = candidates[i];
    try {
      const text = await fetchTextWithTimeout(url, NEWS_FETCH_TIMEOUT_MS);
      const json = JSON.parse(text);
      const model = pickUsomDetailModel(json);
      if (model) {
        const normalized = normalizeUsomItem(model);
        if (normalized) {
          return { ok: true, item: normalized, source: url };
        }
      }
    } catch (_) {}
  }
  return { ok: false, error: 'USOM detail endpoint failed' };
}

function buildSeenKeyMap(items, keyResolver) {
  const seen = {};
  const list = Array.isArray(items) ? items : [];
  for (let i = 0; i < list.length; i++) {
    const key = keyResolver(list[i]);
    if (key) {
      seen[key] = true;
    }
  }
  return seen;
}

// countNewNewsItems: Haber RSS çekimi, ayrıştırma veya önbellek yolu.
function countNewNewsItems(prevItems, nextItems) {
  const seen = buildSeenKeyMap(prevItems, uniqueNewsKey);
  const next = Array.isArray(nextItems) ? nextItems : [];
  let count = 0;
  for (let i = 0; i < next.length; i++) {
    const key = uniqueNewsKey(next[i]);
    if (key && !seen[key]) {
      count++;
    }
  }
  return count;
}

// collectNewNewsSources: Haber RSS çekimi, ayrıştırma veya önbellek yolu.
function collectNewNewsSources(prevItems, nextItems) {
  const seen = buildSeenKeyMap(prevItems, uniqueNewsKey);
  const next = Array.isArray(nextItems) ? nextItems : [];
  const sources = {};
  for (let i = 0; i < next.length; i++) {
    const item = next[i];
    const key = uniqueNewsKey(item);
    if (!key || seen[key]) {
      continue;
    }
    const source = String(item && item.source ? item.source : '').trim();
    if (!source) {
      continue;
    }
    sources[source] = true;
  }
  return Object.keys(sources).sort();
}

// notifyNewNewsItems: Yeni haber öğeleri bildirimi.
function notifyNewNewsItems(count, sourceNames) {
  if (!count || count < 1 || !notifyNewsEnabled) {
    return;
  }
  let msg =
    count === 1
      ? '1 new news item is available.'
      : String(count) + ' new news items are available.';
  const list = Array.isArray(sourceNames) ? sourceNames : [];
  if (list.length > 0) {
    const shown = list.slice(0, 3).join(', ');
    const more = list.length > 3 ? ' +' + String(list.length - 3) : '';
    msg += ' Sources: ' + shown + more + '.';
  }
  showNotification('news', APP_NAME + ' — News', msg);
}

// countNewUsomItems: USOM olay listesi veya detay isteği.
function countNewUsomItems(prevItems, nextItems) {
  const seen = {};
  const prev = Array.isArray(prevItems) ? prevItems : [];
  const next = Array.isArray(nextItems) ? nextItems : [];
  for (let i = 0; i < prev.length; i++) {
    const key = usomItemKey(prev[i]);
    if (key) {
      seen[key] = true;
    }
  }
  let count = 0;
  for (let i = 0; i < next.length; i++) {
    const key = usomItemKey(next[i]);
    if (key && !seen[key]) {
      count++;
    }
  }
  return count;
}

// notifyNewUsomItems: Yeni USOM uyarıları bildirimi.
function notifyNewUsomItems(count) {
  if (!count || count < 1 || !notifyNewsEnabled) {
    return;
  }
  const msg =
    count === 1
      ? '1 new USOM alert is available.'
      : String(count) + ' new USOM alerts are available.';
  showNotification('usom', APP_NAME + ' — USOM', msg);
}

// refreshNewsWithOptionalNotification: Haber yenileme; gerekirse bildirim gönderir.
async function refreshNewsWithOptionalNotification(autoRefresh) {
  if (!autoRefresh) {
    return getNewsPayload(true);
  }
  const data = await chrome.storage.local.get([NEWS_CACHE_KEY]);
  const prevItems = Array.isArray(data[NEWS_CACHE_KEY]) ? data[NEWS_CACHE_KEY] : [];
  const payload = await getNewsPayload(true);
  if (!payload || !payload.ok || payload.cached || prevItems.length === 0) {
    return payload;
  }
  const newCount = countNewNewsItems(prevItems, payload.items);
  const newSources = collectNewNewsSources(prevItems, payload.items);
  notifyNewNewsItems(newCount, newSources);
  return payload;
}

// refreshUsomWithOptionalNotification: USOM yenileme; gerekirse bildirim gönderir.
async function refreshUsomWithOptionalNotification(autoRefresh) {
  if (!autoRefresh) {
    return getUsomPayload(true);
  }
  const data = await chrome.storage.local.get([USOM_CACHE_KEY]);
  const prevItems = Array.isArray(data[USOM_CACHE_KEY]) ? data[USOM_CACHE_KEY] : [];
  const payload = await getUsomPayload(true);
  if (!payload || !payload.ok || payload.cached || prevItems.length === 0) {
    return payload;
  }
  const newCount = countNewUsomItems(prevItems, payload.items);
  notifyNewUsomItems(newCount);
  return payload;
}

// ensureNewsAutoRefreshAlarm: Haber RSS çekimi, ayrıştırma veya önbellek yolu.
function ensureNewsAutoRefreshAlarm() {
  try {
    chrome.alarms.create(NEWS_AUTO_REFRESH_ALARM, {
      periodInMinutes: 10
    });
  } catch (_) {}
}

// ensureUsomAutoRefreshAlarm: USOM olay listesi veya detay isteği.
function ensureUsomAutoRefreshAlarm() {
  try {
    chrome.alarms.create(USOM_AUTO_REFRESH_ALARM, {
      periodInMinutes: 10
    });
  } catch (_) {}
}

// notifyQueued: VT hız sınırı kuyruğu bildirimi.
function notifyQueued() {
  if (!notifyQueuedEnabled) {
    return;
  }
  showNotification('queue', APP_NAME, 'Request queued. Waiting for VT rate limit...');
}

// waitRateLimit: VirusTotal API hız sınırı veya HTTP çağrısı.
async function waitRateLimit() {
  if (proModeEnabled) {
    return;
  }
  const now = Date.now();
  const wait = Math.max(0, nextSlotAt - now);
  if (wait > NOTIFY_WAIT_MS) {
    notifyQueued();
  }
  if (wait > 0) {
    await sleep(wait);
  }
}

// markSlot: VirusTotal API hız sınırı veya HTTP çağrısı.
function markSlot() {
  if (proModeEnabled) {
    return;
  }
  nextSlotAt = Date.now() + rateIntervalMs;
}

/** One VT API slot: wait for pacing then reserve the next interval (used by all throttled VT calls). */
async function consumeVtRateSlot() {
  await waitRateLimit();
  markSlot();
}

async function getStoredKeyWithExpiry(keyName, savedAtName) {
  const data = await chrome.storage.local.get([keyName, savedAtName]);
  const key = String(data[keyName] || '').trim();
  const savedAt = Number(data[savedAtName]);
  const isExpired = key && isFinite(savedAt) && savedAt > 0 && utils.isApiKeyExpired(savedAt);
  return { key: key, isExpired: !!isExpired };
}

async function clearStoredKey(keyName, savedAtName) {
  await chrome.storage.local.set({ [keyName]: '', [savedAtName]: 0 });
}

// getApiKey: VirusTotal API hız sınırı veya HTTP çağrısı.
async function getApiKey() {
  const stored = await getStoredKeyWithExpiry('vtApiKey', 'vtApiKeySavedAt');
  if (stored.isExpired) {
    await clearStoredKey('vtApiKey', 'vtApiKeySavedAt');
    throw new Error('VirusTotal API key expired (14 days). Set a new key in options.');
  }
  if (!stored.key) {
    throw new Error('Configure your VirusTotal API key in extension options.');
  }
  return stored.key;
}

/**
 * Connection check: VT v3 GET /users/{id} where `id` is the API key string.
 * Does not use the IoC queue or waitRateLimit (independent of normal scans).
 */
// testVtApiConnection: VirusTotal API hız sınırı veya HTTP çağrısı.
async function testVtApiConnection(overrideKey) {
  let key = String(overrideKey || '').trim();
  if (!key) {
    const stored = await getStoredKeyWithExpiry('vtApiKey', 'vtApiKeySavedAt');
    key = stored.key;
    if (stored.isExpired) {
      await clearStoredKey('vtApiKey', 'vtApiKeySavedAt');
      return { ok: false, error: 'no_api_key' };
    }
  }
  if (!key) {
    return { ok: false, error: 'no_api_key' };
  }
  const url = VT_API + '/users/' + encodeURIComponent(key);
  const res = await fetch(url, {
    method: 'GET',
    headers: {
      'x-apikey': key
    }
  });
  const text = await res.text();
  if (res.status === 401 || res.status === 403) {
    return { ok: false, error: 'unauthorized' };
  }
  if (!res.ok) {
    return {
      ok: false,
      error: 'http_' + res.status,
      detail: text ? text.slice(0, 300) : ''
    };
  }
  try {
    const data = JSON.parse(text);
    const attrs = data && data.data && data.data.attributes;
    const username = attrs && (attrs.username || attrs.first_name || '');
    return { ok: true, username: String(username || '').trim() };
  } catch (e) {
    return { ok: false, error: 'bad_json' };
  }
}

// parseVtErrorBody: VT hata JSON gövdesinden kod ve mesaj çıkarır.
function parseVtErrorBody(text) {
  if (!text) {
    return null;
  }
  try {
    const j = JSON.parse(text);
    const err = j && j.error;
    if (!err || typeof err !== 'object') {
      return null;
    }
    return {
      code: err.code != null ? String(err.code) : '',
      message: err.message != null ? String(err.message) : ''
    };
  } catch (_) {
    return null;
  }
}

// classifyVtHttpError: HTTP durumunu popup i18n anahtarına eşler.
function classifyVtHttpError(status, parsed, iocKind) {
  const st = Number(status) || 0;
  if (st === 404) {
    return { errorKey: 'errorVtNotFound', errorVars: { kind: iocKind || '' } };
  }
  if (st === 401 || st === 403) {
    return { errorKey: 'errorVtUnauthorized', errorVars: {} };
  }
  if (st === 429) {
    return { errorKey: 'errorVtRateLimit', errorVars: {} };
  }
  const detail = (parsed && parsed.message) || '';
  return {
    errorKey: 'errorVtGeneric',
    errorVars: { status: String(st), detail: detail.slice(0, 200) }
  };
}

// makeVtApiError: Analiste yönelik hata nesnesi üretir (errorKey ile).
function makeVtApiError(status, text, meta) {
  const parsed = parseVtErrorBody(text);
  const kind = meta && meta.iocKind ? meta.iocKind : '';
  const classified = classifyVtHttpError(status, parsed, kind);
  const fallback =
    (parsed && parsed.message) || text || 'HTTP ' + status;
  const err = new Error(fallback.slice(0, 500));
  err.vtStatus = status;
  err.vtCode = parsed && parsed.code ? parsed.code : '';
  err.errorKey = classified.errorKey;
  err.errorVars = classified.errorVars;
  err.iocKind = kind;
  return err;
}

// vtFetch: VirusTotal API hız sınırı veya HTTP çağrısı.
async function vtFetch(path, init, meta) {
  const key = await getApiKey();
  await consumeVtRateSlot();
  const res = await fetch(VT_API + path, Object.assign({}, init, {
    headers: Object.assign({
      'x-apikey': key
    }, init && init.headers)
  }));
  const text = await res.text();
  if (!res.ok) {
    throw makeVtApiError(res.status, text, meta);
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    const err = new Error('Invalid JSON from VirusTotal');
    err.errorKey = 'errorVtBadJson';
    err.errorVars = {};
    throw err;
  }
}

// stripIpv6Brackets: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function stripIpv6Brackets(s) {
  if (s.startsWith('[') && s.endsWith(']')) {
    return s.slice(1, -1);
  }
  return s;
}

// isProbablyIpv6: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function isProbablyIpv6(s) {
  const t = stripIpv6Brackets(s);
  if (!/^[0-9a-fA-F:.]+$/.test(t) || t.indexOf(':') === -1) {
    return false;
  }
  const parts = t.split(':');
  if (parts.length < 2 || parts.length > 8) {
    return false;
  }
  return true;
}

// detectIoc: Tarama kuyruğu, geçmiş veya toplu özet depolama.
function detectIoc(raw) {
  const s = String(raw || '').trim();
  if (!s) {
    return { kind: 'unknown', value: s, reason: 'empty' };
  }

  if (/^https?:\/\//i.test(s)) {
    try {
      // eslint-disable-next-line no-new
      new URL(s);
      return { kind: 'url', value: s };
    } catch (_) {
      return { kind: 'unknown', value: s, reason: 'invalid-url' };
    }
  }

  const ipv4Re = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Re.test(s)) {
    return { kind: 'ip', value: s };
  }

  if (isProbablyIpv6(s)) {
    return { kind: 'ip', value: stripIpv6Brackets(s).toLowerCase() };
  }

  if (/^[a-fA-F0-9]{32}$/.test(s)) {
    return { kind: 'file', value: s.toLowerCase(), hashType: 'md5' };
  }
  if (/^[a-fA-F0-9]{40}$/.test(s)) {
    return { kind: 'file', value: s.toLowerCase(), hashType: 'sha1' };
  }
  if (/^[a-fA-F0-9]{64}$/.test(s)) {
    return { kind: 'file', value: s.toLowerCase(), hashType: 'sha256' };
  }

  const domainRe = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
  if (domainRe.test(s) && !/\s/.test(s) && s.length <= 253) {
    return { kind: 'domain', value: s.toLowerCase() };
  }

  return { kind: 'unknown', value: s, reason: 'no-match' };
}

// extractStats: VT yanıtından özet alan veya yardımcı dönüşüm.
function extractStats(data) {
  const attrs = data && data.data && data.data.attributes;
  const stats = attrs && attrs.last_analysis_stats;
  if (!stats) {
    return { malicious: 0, suspicious: 0, undetected: 0, harmless: 0, timeout: 0, failure: 0 };
  }
  return {
    malicious: Number(stats.malicious) || 0,
    suspicious: Number(stats.suspicious) || 0,
    undetected: Number(stats.undetected) || 0,
    harmless: Number(stats.harmless) || 0,
    timeout: Number(stats.timeout) || 0,
    failure: Number(stats.failure) || 0
  };
}

// threatLevel: VT yanıtından özet alan veya yardımcı dönüşüm.
function threatLevel(stats) {
  if (stats.malicious > 0) {
    return 'malicious';
  }
  if (stats.suspicious > 0) {
    return 'suspicious';
  }
  return 'clean';
}

/** VT community reputation score when present (file, domain, IP, URL objects). */
function extractReputation(attrs) {
  if (!attrs || attrs.reputation === undefined || attrs.reputation === null || attrs.reputation === '') {
    return null;
  }
  const r = attrs.reputation;
  if (typeof r === 'number' && isFinite(r)) {
    return r;
  }
  const n = Number(r);
  if (isFinite(n)) {
    return n;
  }
  const s = String(r).trim().slice(0, 64);
  return s || null;
}

// formatBytes: VT yanıtından özet alan veya yardımcı dönüşüm.
function formatBytes(n) {
  const num = Number(n);
  if (!isFinite(num) || num < 0) {
    return '';
  }
  if (num < 1024) {
    return num + ' B';
  }
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = num;
  let i = -1;
  do {
    v /= 1024;
    i++;
  } while (v >= 1024 && i < units.length - 1);
  const rounded = v >= 10 || Math.abs(Math.round(v) - v) < 0.05 ? Math.round(v) : v.toFixed(1);
  return rounded + ' ' + units[i];
}

// formatVtUnix: VT yanıtından özet alan veya yardımcı dönüşüm.
function formatVtUnix(ts) {
  if (ts == null || ts === '') {
    return '';
  }
  const num = Number(ts);
  if (!isFinite(num)) {
    return '';
  }
  try {
    const d = new Date(num * 1000);
    return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  } catch (_) {
    return '';
  }
}

// truncateStr: Uzun metni UI için kısaltır.
function truncateStr(val, max) {
  const s = String(val || '').replace(/\s+/g, ' ').trim();
  const n = Number(max) > 0 ? Number(max) : 120;
  if (!s) {
    return '';
  }
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

// joinLimited: Dizi öğelerini sınırlı sayıda birleştirir.
function joinLimited(arr, sep, max) {
  if (!Array.isArray(arr)) {
    return '';
  }
  const lim = Number(max) > 0 ? Number(max) : 5;
  return arr
    .filter(function (x) {
      return x != null && String(x).trim();
    })
    .slice(0, lim)
    .map(function (x) {
      return String(x).trim();
    })
    .join(sep || ', ');
}

// formatTagsList: VT tags dizisini kısa metne çevirir.
function formatTagsList(tags, max) {
  if (!Array.isArray(tags)) {
    return '';
  }
  return joinLimited(tags, ', ', max || 6);
}

// formatWhoisSummary: Domain whois nesnesinden kısa özet.
function formatWhoisSummary(whois) {
  if (!whois || typeof whois !== 'object') {
    return '';
  }
  const bits = [];
  if (whois.registrar) {
    bits.push(String(whois.registrar));
  }
  if (whois.creation_date != null && whois.creation_date !== '') {
    bits.push('created ' + formatVtUnix(whois.creation_date));
  }
  if (whois.updated_date != null && whois.updated_date !== '') {
    bits.push('updated ' + formatVtUnix(whois.updated_date));
  }
  return bits.join(' · ');
}

// formatDnsRecordValues: last_dns_records içinden A/AAAA/CNAME değerleri.
function formatDnsRecordValues(records, max) {
  if (!Array.isArray(records)) {
    return '';
  }
  const lim = Number(max) > 0 ? Number(max) : 5;
  const out = [];
  for (let i = 0; i < records.length && out.length < lim; i++) {
    const r = records[i];
    if (!r) {
      continue;
    }
    const t = String(r.type || '').toUpperCase();
    const val = r.value != null ? String(r.value).trim() : '';
    if (!val || (t !== 'A' && t !== 'AAAA' && t !== 'CNAME')) {
      continue;
    }
    out.push(t + ' ' + val);
  }
  return out.join('; ');
}

// formatHttpsCertSummary: TLS sertifikasından CN / issuer özeti.
function formatHttpsCertSummary(cert) {
  if (!cert || typeof cert !== 'object') {
    return '';
  }
  const parts = [];
  if (cert.subject && cert.subject.CN) {
    parts.push('CN ' + cert.subject.CN);
  }
  if (cert.issuer && cert.issuer.O) {
    parts.push('issuer ' + cert.issuer.O);
  }
  if (cert.thumbprint_sha256) {
    parts.push('sha256 ' + String(cert.thumbprint_sha256).slice(0, 16) + '…');
  }
  return parts.join(' · ');
}

// formatRedirectChain: URL yönlendirme zincirini kısaltır.
function formatRedirectChain(chain, max) {
  if (!Array.isArray(chain)) {
    return '';
  }
  const lim = Number(max) > 0 ? Number(max) : 4;
  const hops = [];
  for (let i = 0; i < chain.length && hops.length < lim; i++) {
    const hop = chain[i];
    const u =
      (hop && (hop.url || hop.target || hop)) != null
        ? String(hop.url || hop.target || hop).trim()
        : '';
    if (u) {
      hops.push(truncateStr(u, 80));
    }
  }
  return hops.join(' → ');
}

// urlToVtId: VT v3 URL nesne kimliği (base64url, padding yok).
function urlToVtId(urlStr) {
  try {
    const bytes = new TextEncoder().encode(String(urlStr || ''));
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  } catch (_) {
    return '';
  }
}

// shortenHash: Hero satırı için hash kısaltma.
function shortenHash(hash, head, tail) {
  const s = String(hash || '').trim();
  const h = Number(head) > 0 ? Number(head) : 10;
  const t = Number(tail) > 0 ? Number(tail) : 8;
  if (s.length <= h + t + 3) {
    return s;
  }
  return s.slice(0, h) + '…' + s.slice(-t);
}

// buildHeroSummary: IoC türüne göre scan kartı üst satırları.
function buildHeroSummary(kind, detected, attrs, threatContext, reputation) {
  const out = { subtitle: '', iocDisplay: '', tagChips: [], chips: [] };
  const tc = threatContext || {};
  const a = attrs || {};
  if (tc.suggestedLabel) {
    out.chips.push({ type: 'label', value: tc.suggestedLabel });
  }
  out.tagChips = utils.mapTagsToHeroChips(a.tags, 12);
  if (reputation !== null && reputation !== undefined && reputation !== '') {
    const rn = Number(reputation);
    if (!(kind === 'ip' && isFinite(rn) && rn === 0)) {
      out.chips.push({ type: 'reputation', value: String(reputation) });
    }
  }
  switch (kind) {
    case 'file': {
      const name =
        (a.meaningful_name && String(a.meaningful_name).trim()) ||
        (Array.isArray(a.names) && a.names[0] && String(a.names[0]).trim()) ||
        '';
      out.iocDisplay = (detected && detected.value) || a.sha256 || '';
      const sub = [];
      if (name) {
        sub.push(name);
      }
      const sig = a.signature_info || {};
      const sigState = utils.resolveSignatureState(sig);
      if (sigState === 'valid' || sigState === 'invalid') {
        out.chips.push({
          type: 'signature',
          state: sigState
        });
      }
      if (a.type_description || a.type_tag) {
        sub.push(String(a.type_description || a.type_tag));
      }
      out.subtitle = sub.join(' · ');
      break;
    }
    case 'domain': {
      out.iocDisplay = detected.value || '';
      // Registrar / kayıt tarihi yalnızca Details’ta (detailRegistrar, detailCreationDate).
      break;
    }
    case 'ip': {
      out.iocDisplay = detected.value || '';
      // Ülke / AS sahibi yalnızca Details’ta (detailCountry, detailAsOwner).
      break;
    }
    case 'url': {
      const original = detected.value || '';
      out.iocDisplay = original;
      // Başlık / final URL yalnızca Details’ta; HTTP/redirect chip olarak kalır.
      const redir = formatRedirectChain(a.redirection_chain, 3);
      if (redir) {
        out.chips.push({ type: 'redirect', value: redir });
      }
      if (a.last_http_response_code != null && a.last_http_response_code !== '') {
        out.chips.push({
          type: 'http',
          value: 'HTTP ' + String(a.last_http_response_code)
        });
      }
      break;
    }
    default:
      out.iocDisplay = detected.value || '';
      break;
  }
  return out;
}

// stringifyCategories: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function stringifyCategories(cats) {
  if (!cats || typeof cats !== 'object') {
    return '';
  }
  return Object.keys(cats)
    .map(function (k) {
      return k + ': ' + cats[k];
    })
    .join('; ');
}

/**
 * VT v3 object attributes → short detail rows for the popup (label keys for i18n in the UI).
 */
// extractIocDetails: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function extractIocDetails(kind, data) {
  const attrs = data && data.data && data.data.attributes;
  if (!attrs) {
    return [];
  }
  const rows = [];
  const MAX_ROWS = kind === 'file' ? 18 : 16;

  // add: Service worker içi yardımcı; çağrı bağlamı gövdede.
  function add(id, val) {
    if (rows.length >= MAX_ROWS) {
      return;
    }
    if (val === null || val === undefined) {
      return;
    }
    let s = String(val).replace(/\s+/g, ' ').trim();
    if (!s) {
      return;
    }
    if (s.length > 2000) {
      s = s.slice(0, 1997) + '…';
    }
    rows.push({ id: id, value: s });
  }

  switch (kind) {
    case 'file': {
      const name =
        (attrs.meaningful_name && String(attrs.meaningful_name).trim()) ||
        (Array.isArray(attrs.names) && attrs.names[0] && String(attrs.names[0]).trim()) ||
        '';
      add('detailFileName', name);
      if (attrs.size !== undefined && attrs.size !== null && attrs.size !== '') {
        add('detailFileSize', formatBytes(Number(attrs.size)));
      }
      add('detailFileType', attrs.type_description || attrs.type_tag);
      const sig = attrs.signature_info || {};
      if (sig.product) {
        add('detailProduct', sig.product);
      }
      if (sig.description && String(sig.description).trim() && sig.description !== sig.product) {
        add('detailDescription', sig.description);
      }
      if (sig.signers) {
        const signerStr = Array.isArray(sig.signers)
          ? sig.signers
              .filter(function (x) {
                return x;
              })
              .join(', ')
          : String(sig.signers);
        add('detailSigners', signerStr);
      }
      if (sig.copyright) {
        add('detailCopyright', sig.copyright);
      }
      const sigState = utils.resolveSignatureState(sig);
      if (sigState !== 'unknown' || (sig.signers && String(sig.signers).length)) {
        add('detailSignatureStatus', sigState);
      }
      add('detailMd5', attrs.md5);
      add('detailSha1', attrs.sha1);
      add('detailSha256', attrs.sha256);
      add('detailMagic', attrs.magic);
      if (attrs.times_submitted != null && attrs.times_submitted !== '') {
        add('detailTimesSubmitted', String(attrs.times_submitted));
      }
      const pivotFlags = [];
      if (attrs.has_contacted_ips_with_detections) {
        pivotFlags.push('malicious IPs');
      }
      if (attrs.has_contacted_domains_with_detections) {
        pivotFlags.push('malicious domains');
      }
      if (attrs.has_contacted_urls_with_detections) {
        pivotFlags.push('malicious URLs');
      }
      if (pivotFlags.length) {
        add('detailContactedWithDetections', pivotFlags.join(', '));
      }
      add('detailFirstSeen', formatVtUnix(attrs.first_submission_date));
      add('detailLastSeen', formatVtUnix(attrs.last_submission_date));
      add('detailLastAnalysis', formatVtUnix(attrs.last_analysis_date));
      break;
    }
    case 'domain': {
      add('detailRegistrar', attrs.registrar);
      const whois = formatWhoisSummary(attrs.whois);
      if (whois) {
        add('detailWhois', whois);
      }
      const dcats = stringifyCategories(attrs.categories);
      if (dcats) {
        add('detailCategories', dcats);
      }
      add('detailCreationDate', formatVtUnix(attrs.creation_date));
      add('detailLastAnalysis', formatVtUnix(attrs.last_analysis_date));
      const dnsVals = formatDnsRecordValues(attrs.last_dns_records, 5);
      if (dnsVals) {
        add('detailDnsValues', dnsVals);
      }
      if (attrs.total_votes && typeof attrs.total_votes === 'object') {
        const v = attrs.total_votes;
        const votes =
          'harmless ' +
          (Number(v.harmless) || 0) +
          ' / malicious ' +
          (Number(v.malicious) || 0);
        add('detailVotes', votes);
      }
      const cert = formatHttpsCertSummary(attrs.last_https_certificate);
      if (cert) {
        add('detailHttpsCert', cert);
      }
      break;
    }
    case 'ip': {
      add('detailCountry', attrs.country);
      if (attrs.regional_internet_registry) {
        add('detailRir', attrs.regional_internet_registry);
      }
      if (attrs.asn !== undefined && attrs.asn !== null && attrs.asn !== '') {
        add('detailAsn', 'AS' + String(attrs.asn));
      }
      add('detailAsOwner', attrs.as_owner);
      add('detailNetwork', attrs.network);
      add('detailLastAnalysis', formatVtUnix(attrs.last_analysis_date));
      if (attrs.total_votes && typeof attrs.total_votes === 'object') {
        const v = attrs.total_votes;
        add(
          'detailVotes',
          'harmless ' +
            (Number(v.harmless) || 0) +
            ' / malicious ' +
            (Number(v.malicious) || 0)
        );
      }
      if (attrs.jarm) {
        add('detailJarm', truncateStr(attrs.jarm, 64));
      }
      const icert = formatHttpsCertSummary(attrs.last_https_certificate);
      if (icert) {
        add('detailHttpsCert', icert);
      }
      break;
    }
    case 'url': {
      add('detailFinalUrl', attrs.last_final_url);
      add('detailPageTitle', attrs.title);
      if (attrs.last_http_response_code != null && attrs.last_http_response_code !== '') {
        add('detailHttpStatus', String(attrs.last_http_response_code));
      }
      const rchain = formatRedirectChain(attrs.redirection_chain, 5);
      if (rchain) {
        add('detailRedirectChain', rchain);
      }
      add('detailLastAnalysis', formatVtUnix(attrs.last_analysis_date));
      const ucats = stringifyCategories(attrs.categories);
      if (ucats) {
        add('detailCategories', ucats);
      }
      break;
    }
    default:
      break;
  }
  return rows;
}

// relationshipPreviewPath: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function relationshipPreviewPath(kind, objectId, cfg) {
  const rel = cfg.relationship;
  const lim = Number(cfg.limit) > 0 ? Number(cfg.limit) : 5;
  const q = '?limit=' + encodeURIComponent(String(lim));
  const id = encodeURIComponent(objectId);
  switch (kind) {
    case 'file':
      return '/files/' + id + '/' + encodeURIComponent(rel) + q;
    case 'ip':
      return '/ip_addresses/' + id + '/' + encodeURIComponent(rel) + q;
    case 'domain':
      return '/domains/' + id + '/' + encodeURIComponent(rel) + q;
    case 'url':
      return '/urls/' + id + '/' + encodeURIComponent(rel) + q;
    default:
      return '';
  }
}

// resolutionItemLabel: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function resolutionItemLabel(entry) {
  if (!entry || typeof entry !== 'object') {
    return '';
  }
  const attrs = entry.attributes || {};
  const host =
    attrs.host_name ||
    attrs.hostname ||
    attrs.host ||
    attrs.ip_address ||
    attrs.ip ||
    '';
  if (host) {
    return String(host);
  }
  return entry.id != null ? String(entry.id) : '';
}

// parseRelationshipPreviewResponse: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function parseRelationshipPreviewResponse(kind, relationship, json) {
  const meta = json && json.meta;
  const count = meta && meta.count != null ? Number(meta.count) : null;
  const data = json && json.data;
  const items = [];
  if (!Array.isArray(data)) {
    return { relationship: relationship, items: [], count: count };
  }
  for (let i = 0; i < data.length; i++) {
    const entry = data[i];
    if (!entry) {
      continue;
    }
    let label = '';
    const typ = String(entry.type || '');
    if (typ === 'resolution') {
      label = resolutionItemLabel(entry);
    } else {
      label = entry.id != null ? String(entry.id) : resolutionItemLabel(entry);
    }
    label = String(label || '').replace(/\s+/g, ' ').trim();
    if (label) {
      items.push(label);
    }
  }
  return { relationship: relationship, items: items, count: count };
}

// mapPopularThreatItems: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function mapPopularThreatItems(arr, max) {
  const n = Number(max) > 0 ? Number(max) : 8;
  if (!Array.isArray(arr)) {
    return [];
  }
  return arr
    .slice(0, n)
    .map(function (x) {
      if (!x || typeof x !== 'object') {
        return null;
      }
      const value = x.value != null ? String(x.value).trim().slice(0, 500) : '';
      if (!value) {
        return null;
      }
      return { value: value, count: Number(x.count) || 0 };
    })
    .filter(function (x) {
      return !!x;
    });
}

/**
 * VT consensus (popular_threat_classification) + distinct malicious/suspicious
 * detection strings from last_analysis_results — same report, no extra API call.
 */
// extractThreatContext: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function extractThreatContext(attrs, opts) {
  opts = opts || {};
  const maxDistinct = Number(opts.maxDistinctLabels) > 0 ? Number(opts.maxDistinctLabels) : 8;
  const results = attrs && attrs.last_analysis_results;
  const ptc = attrs && attrs.popular_threat_classification;
  const out = {
    summary: {
      malicious: 0,
      suspicious: 0,
      totalEngines: 0,
      vendorsFlagging: 0
    },
    suggestedLabel: '',
    popularNames: [],
    popularCategories: [],
    distinctLabels: []
  };
  if (ptc && typeof ptc === 'object') {
    const sug = ptc.suggested_threat_label;
    if (sug != null && String(sug).trim()) {
      out.suggestedLabel = String(sug).trim().slice(0, 2000);
    }
    out.popularNames = mapPopularThreatItems(ptc.popular_threat_name, 8);
    out.popularCategories = mapPopularThreatItems(ptc.popular_threat_category, 8);
  }
  const byNorm = {};
  if (results && typeof results === 'object') {
    const keys = Object.keys(results);
    out.summary.totalEngines = keys.length;
    let mal = 0;
    let susp = 0;
    for (let i = 0; i < keys.length; i++) {
      const r = results[keys[i]];
      const cat = r && r.category;
      if (cat !== 'malicious' && cat !== 'suspicious') {
        continue;
      }
      if (cat === 'malicious') {
        mal++;
      } else {
        susp++;
      }
      const raw = (r && r.result) != null ? String(r.result).trim() : '';
      if (!raw) {
        continue;
      }
      const norm = raw.toLowerCase();
      if (!byNorm[norm]) {
        byNorm[norm] = { label: raw, count: 0 };
      }
      byNorm[norm].count++;
    }
    out.summary.malicious = mal;
    out.summary.suspicious = susp;
    out.summary.vendorsFlagging = mal + susp;
    out.distinctLabels = Object.keys(byNorm)
      .map(function (k) {
        return byNorm[k];
      })
      .sort(function (a, b) {
        return b.count - a.count;
      })
      .slice(0, maxDistinct);
  }
  return out;
}

// extractMitreFromFileAttributes: Ana file nesnesinden MITRE ID seti.
function extractMitreFromFileAttributes(attrs) {
  const ids = new Set();
  collectMitreFromAttributes(attrs, ids);
  return { ids: Array.from(ids).sort(), sandboxCount: 0, source: 'object' };
}

// mitreIdFromString: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function mitreIdFromString(s) {
  const m = String(s || '').match(/\bT\d{4}(?:\.\d{3})?\b/);
  return m ? m[0] : '';
}

// collectMitreFromAttributes: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function collectMitreFromAttributes(attrs, intoSet) {
  if (!attrs || typeof attrs !== 'object') {
    return;
  }
  const top = attrs.mitre_attack_techniques;
  if (Array.isArray(top)) {
    top.forEach(function (x) {
      const id = x && (x.id || x.technique_id);
      if (id) {
        intoSet.add(String(id));
      }
    });
  }
  const sigm = attrs.sigma_analysis_results;
  if (Array.isArray(sigm)) {
    sigm.forEach(function (row) {
      const mt = row && row.mitre_attack_techniques;
      if (Array.isArray(mt)) {
        mt.forEach(function (x) {
          const id = x && (x.id || x.technique_id);
          if (id) {
            intoSet.add(String(id));
          }
        });
      }
    });
  }
  const sigMatches = attrs.signature_matches;
  if (Array.isArray(sigMatches)) {
    sigMatches.forEach(function (row) {
      const mt = row && row.mitre_attack_techniques;
      if (Array.isArray(mt)) {
        mt.forEach(function (x) {
          const id = x && (x.id || x.technique_id);
          if (id) {
            intoSet.add(String(id));
          }
        });
      }
    });
  }
  const tags = attrs.tags;
  if (Array.isArray(tags)) {
    tags.forEach(function (tag) {
      const id = mitreIdFromString(tag);
      if (id) {
        intoSet.add(id);
      }
    });
  }
}

// extractMitreFromBehavioursJson: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function extractMitreFromBehavioursJson(json) {
  const data = json && json.data;
  const ids = new Set();
  if (!Array.isArray(data)) {
    return { ids: [], sandboxCount: 0 };
  }
  for (let i = 0; i < data.length; i++) {
    const row = data[i];
    const attrs = row && row.attributes;
    collectMitreFromAttributes(attrs, ids);
  }
  const sorted = Array.from(ids).sort();
  return { ids: sorted, sandboxCount: data.length };
}

// trimPayloadForHistory: Tarama kuyruğu, geçmiş veya toplu özet depolama.
function trimPayloadForHistory(payload) {
  if (!payload || !payload.ok) {
    return payload;
  }
  const out = Object.assign({}, payload);
  if (out.relationshipPreview && Array.isArray(out.relationshipPreview.items)) {
    out.relationshipPreview = Object.assign({}, out.relationshipPreview, {
      items: out.relationshipPreview.items
        .slice(0, MAX_HISTORY_REL_ITEMS)
        .map(function (s) {
          return String(s).slice(0, MAX_HISTORY_REL_STR);
        })
    });
  }
  if (out.threatContext) {
    const tc = out.threatContext;
    out.threatContext = {
      summary: tc.summary || {},
      suggestedLabel: tc.suggestedLabel
        ? String(tc.suggestedLabel).slice(0, 500)
        : '',
      popularNames: Array.isArray(tc.popularNames)
        ? tc.popularNames.slice(0, 8)
        : [],
      popularCategories: Array.isArray(tc.popularCategories)
        ? tc.popularCategories.slice(0, 8)
        : [],
      distinctLabels: Array.isArray(tc.distinctLabels)
        ? tc.distinctLabels.slice(0, MAX_HISTORY_ENGINE_ROWS)
        : []
    };
  }
  if (out.mitreTechniques && out.mitreTechniques.ids) {
    out.mitreTechniques = Object.assign({}, out.mitreTechniques, {
      ids: out.mitreTechniques.ids.slice(0, MAX_HISTORY_MITRE_IDS)
    });
  }
  if (out.hero && typeof out.hero === 'object') {
    out.hero = {
      subtitle: out.hero.subtitle ? String(out.hero.subtitle).slice(0, 220) : '',
      iocDisplay: out.hero.iocDisplay ? String(out.hero.iocDisplay).slice(0, 2048) : '',
      tagChips: Array.isArray(out.hero.tagChips) ? out.hero.tagChips.slice(0, 12) : [],
      chips: Array.isArray(out.hero.chips) ? out.hero.chips.slice(0, 8) : []
    };
  }
  if (out.relationshipPreviewSecondary && out.relationshipPreviewSecondary.items) {
    out.relationshipPreviewSecondary = Object.assign({}, out.relationshipPreviewSecondary, {
      items: out.relationshipPreviewSecondary.items
        .slice(0, MAX_HISTORY_REL_ITEMS)
        .map(function (s) {
          return String(s).slice(0, MAX_HISTORY_REL_STR);
        })
    });
  }
  return out;
}

// trimAbuseForHistory: Geçmiş kaydı için AbuseIPDB özet alanları.
function trimAbuseForHistory(abuse) {
  if (!abuse || typeof abuse !== 'object') {
    return null;
  }
  if (abuse.ok !== true) {
    return {
      ok: false,
      error: abuse.error ? String(abuse.error).slice(0, 120) : 'failed'
    };
  }
  return {
    ok: true,
    score: abuse.score,
    totalReports: abuse.totalReports,
    windowDays: abuse.windowDays,
    overallDays: abuse.overallDays,
    includeReports: abuse.includeReports === true,
    windowReportTotal: abuse.windowReportTotal,
    fetchedReports: abuse.fetchedReports,
    lastReportedAt: abuse.lastReportedAt
      ? String(abuse.lastReportedAt).slice(0, 40)
      : null,
    abuseLink: abuse.abuseLink ? String(abuse.abuseLink).slice(0, 256) : '',
    categoryBreakdown: Array.isArray(abuse.categoryBreakdown)
      ? abuse.categoryBreakdown.slice(0, 8).map(function (c) {
          return {
            categoryId: c.categoryId,
            categoryName: String(c.categoryName || '').slice(0, 80),
            count: Number(c.count) || 0
          };
        })
      : []
  };
}

// buildRecentHistoryItem: Tarama kuyruğu, geçmiş veya toplu özet depolama.
function buildRecentHistoryItem(payload) {
  if (!payload || !payload.ok) {
    return null;
  }
  const trimmed = trimPayloadForHistory(payload);
  const item = {
    ts: Date.now(),
    ioc: trimmed.ioc,
    kind: trimmed.iocKind,
    stats: trimmed.stats,
    permalink: trimmed.permalink,
    threatLevel: trimmed.threatLevel,
    details: Array.isArray(trimmed.details) ? trimmed.details : []
  };
  if (trimmed.reputation !== undefined && trimmed.reputation !== null) {
    item.reputation = trimmed.reputation;
  }
  if (trimmed.hero) {
    item.hero = trimmed.hero;
  }
  if (trimmed.threatContext) {
    item.threatContext = trimmed.threatContext;
  }
  if (trimmed.extendedThreatLabels) {
    item.extendedThreatLabels = true;
  }
  if (trimmed.relationshipPreview) {
    item.relationshipPreview = trimmed.relationshipPreview;
  }
  if (trimmed.relationshipPreviewSecondary) {
    item.relationshipPreviewSecondary = trimmed.relationshipPreviewSecondary;
  }
  if (trimmed.mitreTechniques) {
    item.mitreTechniques = trimmed.mitreTechniques;
  }
  if (trimmed.iocKind === 'ip') {
    const abuseHist = trimAbuseForHistory(trimmed.abuseipdb);
    if (abuseHist) {
      item.abuseipdb = abuseHist;
    }
    if (trimmed.threatLevelVt) {
      item.threatLevelVt = trimmed.threatLevelVt;
    }
    if (trimmed.threatLevelAbuse) {
      item.threatLevelAbuse = trimmed.threatLevelAbuse;
    }
  }
  return item;
}

// guiPermalink: VT yanıtından özet alan veya yardımcı dönüşüm.
function guiPermalink(kind, data, fallback) {
  const d = data && data.data;
  if (!d) {
    return fallback || 'https://www.virustotal.com/gui/home/upload';
  }
  const id = encodeURIComponent(d.id || '');
  switch (kind) {
    case 'ip':
      return 'https://www.virustotal.com/gui/ip-address/' + id;
    case 'domain':
      return 'https://www.virustotal.com/gui/domain/' + id;
    case 'file': {
      const sha256 = d.attributes && d.attributes.sha256;
      const h = sha256 || d.id || fallback;
      return 'https://www.virustotal.com/gui/file/' + encodeURIComponent(h);
    }
    case 'url':
      return 'https://www.virustotal.com/gui/url/' + id;
    default:
      return 'https://www.virustotal.com/gui/home/upload';
  }
}

const ABUSE_CATEGORIES = {
  1: 'DNS Compromise',
  2: 'DNS Poisoning',
  3: 'Fraud Orders',
  4: 'DDoS Attack',
  5: 'FTP Brute-Force',
  6: 'Ping of Death',
  7: 'Phishing',
  8: 'Fraud VoIP',
  9: 'Open Proxy',
  10: 'Web Spam',
  11: 'Email Spam',
  12: 'Blog Spam',
  13: 'VPN IP',
  14: 'Port Scan',
  15: 'Hacking',
  16: 'SQL Injection',
  17: 'Spoofing',
  18: 'Brute-Force',
  19: 'Bad Web Bot',
  20: 'Exploited Host',
  21: 'Web App Attack',
  22: 'SSH',
  23: 'IoT Targeted'
};

// buildAbuseCategorySummary: AbuseIPDB rapor listesinden kategori sayımı üretir.
function buildAbuseCategorySummary(results, categoriesMap) {
  const counts = new Map();
  let lastReportedAt = null;
  const list = Array.isArray(results) ? results : [];
  for (let i = 0; i < list.length; i++) {
    const report = list[i];
    if (report && report.reportedAt) {
      const currentDate = new Date(report.reportedAt);
      if (!Number.isNaN(currentDate.getTime())) {
        if (!lastReportedAt || currentDate > new Date(lastReportedAt)) {
          lastReportedAt = report.reportedAt;
        }
      }
    }
    const categories = report && Array.isArray(report.categories) ? report.categories : [];
    for (let j = 0; j < categories.length; j++) {
      const categoryId = categories[j];
      counts.set(categoryId, (counts.get(categoryId) || 0) + 1);
    }
  }
  return {
    categoryBreakdown: Array.from(counts.entries())
      .map(function (entry) {
        const categoryId = entry[0];
        const count = entry[1];
        return {
          categoryId: categoryId,
          categoryName: categoriesMap[categoryId] || 'Unknown Category ' + categoryId,
          count: count
        };
      })
      .sort(function (a, b) {
        return b.count - a.count || a.categoryId - b.categoryId;
      }),
    lastReportedAt: lastReportedAt
  };
}

const ABUSE_RETRY_WAIT_MS = 2000;
const ABUSE_MAX_FETCH_ATTEMPTS = 2;

// classifyAbuseHttpError: AbuseIPDB HTTP durumunu i18n anahtarına eşler.
function classifyAbuseHttpError(status) {
  const st = Number(status) || 0;
  if (st === 401 || st === 403) {
    return 'errorAbuseUnauthorized';
  }
  if (st === 429) {
    return 'errorAbuseRateLimit';
  }
  return 'errorAbuseGeneric';
}

// fetchAbuseJson: AbuseIPDB REST yanıtını ayrıştırır (429’da bir kez yeniden dener).
async function fetchAbuseJson(url, attempt) {
  const tryNo = attempt || 0;
  const response = await fetch(url.toString(), {
    method: 'GET',
    headers: { Accept: 'application/json' }
  });
  const rawText = await response.text();
  let payload = null;
  try {
    payload = rawText ? JSON.parse(rawText) : null;
  } catch (e) {
    const err = new Error('JSON parse error. HTTP ' + response.status);
    err.abuseStatus = response.status;
    err.errorKey = 'errorAbuseGeneric';
    throw err;
  }
  if (response.status === 429 && tryNo + 1 < ABUSE_MAX_FETCH_ATTEMPTS) {
    await sleep(ABUSE_RETRY_WAIT_MS);
    return fetchAbuseJson(url, tryNo + 1);
  }
  if (!response.ok) {
    const detail =
      payload && payload.errors && payload.errors[0] && payload.errors[0].detail
        ? payload.errors[0].detail
        : 'HTTP ' + response.status;
    const err = new Error(detail);
    err.abuseStatus = response.status;
    err.errorKey = classifyAbuseHttpError(response.status);
    throw err;
  }
  return payload;
}

// getAbuseApiKey: Depolanan AbuseIPDB anahtarını döndürür (yoksa null).
async function getAbuseApiKey() {
  const stored = await getStoredKeyWithExpiry('abuseipdbApiKey', 'abuseipdbApiKeySavedAt');
  if (stored.isExpired) {
    await clearStoredKey('abuseipdbApiKey', 'abuseipdbApiKeySavedAt');
    return null;
  }
  return stored.key || null;
}

// resolveAbuseFlagsForIp: Aktif scan preset → AbuseIPDB sorgu bayrakları (IP only).
async function resolveAbuseFlagsForIp() {
  const data = await chrome.storage.local.get(['vtScanPreset', 'vtScanPresets']);
  let presetId = data.vtScanPreset;
  if (presetId !== 'detailed' && presetId !== 'analyst' && presetId !== 'quick') {
    presetId = 'quick';
  }
  const map = utils.migrateScanPresetsStorage(data.vtScanPresets);
  const profile = utils.resolvePresetForKind(map, presetId, 'ip');
  return utils.presetToAbuseFlags(profile);
}

// runAbuseLookup: AbuseIPDB check; isteğe bağlı reports (sayfa 1, 100 kayıt).
async function runAbuseLookup(ip, apiKey, maxAgeInDays, overallDays, includeReports) {
  const checkUrl = new URL('https://api.abuseipdb.com/api/v2/check');
  checkUrl.searchParams.set('ipAddress', ip);
  checkUrl.searchParams.set('maxAgeInDays', String(overallDays));
  checkUrl.searchParams.set('key', apiKey);
  const checkPayload = await fetchAbuseJson(checkUrl);
  const checkData = (checkPayload && checkPayload.data) || {};
  let categoryBreakdown = [];
  let windowReportTotal = 0;
  let fetchedReports = 0;
  let lastReportedAt = checkData.lastReportedAt || null;

  if (includeReports) {
    const perPage = 100;
    const reportsUrl = new URL('https://api.abuseipdb.com/api/v2/reports');
    reportsUrl.searchParams.set('ipAddress', ip);
    reportsUrl.searchParams.set('maxAgeInDays', String(maxAgeInDays));
    reportsUrl.searchParams.set('perPage', String(perPage));
    reportsUrl.searchParams.set('page', '1');
    reportsUrl.searchParams.set('key', apiKey);
    const reportsPayload = await fetchAbuseJson(reportsUrl);
    const reportsData = (reportsPayload && reportsPayload.data) || {};
    const pageResults = Array.isArray(reportsData.results) ? reportsData.results : [];
    const summary = buildAbuseCategorySummary(pageResults, ABUSE_CATEGORIES);
    categoryBreakdown = summary.categoryBreakdown;
    windowReportTotal = Number(reportsData.total || 0);
    fetchedReports = pageResults.length;
    lastReportedAt = summary.lastReportedAt || lastReportedAt;
  }

  const score = checkData.abuseConfidenceScore;
  return {
    ok: true,
    score: typeof score === 'number' ? score : score != null ? Number(score) : null,
    totalReports: checkData.totalReports != null ? checkData.totalReports : 0,
    windowDays: Number(maxAgeInDays),
    overallDays: Number(overallDays),
    includeReports: includeReports === true,
    windowReportTotal: windowReportTotal,
    fetchedReports: fetchedReports,
    lastReportedAt: lastReportedAt,
    countryCode: checkData.countryCode || null,
    countryName: checkData.countryName || null,
    isp: checkData.isp || null,
    domain: checkData.domain || null,
    categoryBreakdown: categoryBreakdown,
    abuseLink: 'https://www.abuseipdb.com/check/' + encodeURIComponent(ip)
  };
}

// abuseThreatFromScore: Abuse skorunu tehdit seviyesine eşler.
function abuseThreatFromScore(score) {
  if (typeof score !== 'number' || !isFinite(score)) {
    return 'clean';
  }
  if (score >= 75) {
    return 'malicious';
  }
  if (score >= 50) {
    return 'suspicious';
  }
  return 'clean';
}

// combineIpThreatLevel: VT ve Abuse skorunu birleşik threatLevel üretir.
function combineIpThreatLevel(vtLevel, abuseScore) {
  const vt = vtLevel || 'clean';
  const abuse = abuseThreatFromScore(abuseScore);
  if (vt === 'malicious' || abuse === 'malicious') {
    return 'malicious';
  }
  if (vt === 'suspicious' || abuse === 'suspicious') {
    return 'suspicious';
  }
  return 'clean';
}

// enrichAbuseForIp: IP için AbuseIPDB verisi (anahtar yoksa yapılandırılmamış döner).
async function enrichAbuseForIp(ip, opts) {
  opts = opts || {};
  const apiKey = await getAbuseApiKey();
  if (!apiKey) {
    return { ok: false, error: 'not_configured' };
  }
  try {
    const flags = opts.abuseFlags || (await resolveAbuseFlagsForIp());
    return await runAbuseLookup(
      ip,
      apiKey,
      flags.maxAgeInDays,
      flags.overallDays,
      flags.includeReports
    );
  } catch (e) {
    return {
      ok: false,
      error: e && e.message ? String(e.message) : 'AbuseIPDB request failed',
      errorKey: e && e.errorKey ? String(e.errorKey) : 'errorAbuseGeneric',
      abuseStatus: e && e.abuseStatus != null ? e.abuseStatus : null
    };
  }
}

// buildAbuseDetailRows: Popup detay listesi için Abuse satırları.
function buildAbuseDetailRows(abuse) {
  if (!abuse || abuse.ok !== true) {
    return [];
  }
  const rows = [];
  if (abuse.score != null && isFinite(abuse.score)) {
    rows.push({ id: 'detailAbuseScore', value: String(abuse.score) + '/100' });
  }
  if (abuse.totalReports != null) {
    rows.push({
      id: 'detailAbuseReports',
      value: String(abuse.totalReports) + ' (' + String(abuse.overallDays || 365) + 'd)'
    });
  }
  if (abuse.lastReportedAt) {
    rows.push({ id: 'detailAbuseLastReported', value: String(abuse.lastReportedAt) });
  }
  const top =
    abuse.categoryBreakdown && abuse.categoryBreakdown[0]
      ? abuse.categoryBreakdown[0]
      : null;
  if (top) {
    rows.push({
      id: 'detailAbuseTopCategory',
      value: '#' + top.categoryId + ' ' + top.categoryName + ' (' + top.count + ')'
    });
  }
  return rows;
}

// mergeAbuseIntoIpPayload: scanIoc IP sonucuna Abuse alanlarını ekler.
function mergeAbuseIntoIpPayload(payload, abuse) {
  payload.abuseipdb = abuse || { ok: false };
  const vtLevel = payload.threatLevel || 'clean';
  payload.threatLevelVt = vtLevel;
  if (abuse && abuse.ok === true) {
    payload.threatLevelAbuse = abuseThreatFromScore(abuse.score);
    payload.threatLevel = combineIpThreatLevel(vtLevel, abuse.score);
    payload.details = (payload.details || []).concat(buildAbuseDetailRows(abuse));
  } else {
    payload.threatLevelAbuse = 'clean';
  }
}

// testAbuseApiConnection: AbuseIPDB check ile bağlantı testi.
async function testAbuseApiConnection(overrideKey) {
  let key = String(overrideKey || '').trim();
  if (!key) {
    key = (await getAbuseApiKey()) || '';
  }
  if (!key) {
    const stored = await getStoredKeyWithExpiry('abuseipdbApiKey', 'abuseipdbApiKeySavedAt');
    if (stored.isExpired) {
      await clearStoredKey('abuseipdbApiKey', 'abuseipdbApiKeySavedAt');
    }
    return { ok: false, error: 'no_api_key' };
  }
  try {
    const url = new URL('https://api.abuseipdb.com/api/v2/check');
    url.searchParams.set('ipAddress', '1.1.1.1');
    url.searchParams.set('maxAgeInDays', '30');
    url.searchParams.set('key', key);
    await fetchAbuseJson(url);
    return { ok: true };
  } catch (e) {
    return {
      ok: false,
      error: 'request_failed',
      detail: e && e.message ? String(e.message) : 'Request failed'
    };
  }
}

// fetchIp: VirusTotal API hız sınırı veya HTTP çağrısı.
async function fetchIp(ip) {
  return vtFetch(
    '/ip_addresses/' + encodeURIComponent(ip),
    { method: 'GET' },
    { iocKind: 'ip' }
  );
}

// fetchDomain: VirusTotal API hız sınırı veya HTTP çağrısı.
async function fetchDomain(domain) {
  return vtFetch('/domains/' + encodeURIComponent(domain), { method: 'GET' }, { iocKind: 'domain' });
}

// fetchFile: VirusTotal API hız sınırı veya HTTP çağrısı.
async function fetchFile(hash) {
  return vtFetch('/files/' + encodeURIComponent(hash), { method: 'GET' }, { iocKind: 'file' });
}

// resolveVtObjectIdForReanalyze: VT analyse uç noktası için nesne kimliği.
function resolveVtObjectIdForReanalyze(iocKind, ioc, vtObjectId) {
  const stored = String(vtObjectId || '').trim();
  if (stored) {
    return stored;
  }
  const value = String(ioc || '').trim();
  if (!value) {
    return '';
  }
  if (iocKind === 'url') {
    return urlToVtId(value);
  }
  if (iocKind === 'ip' || iocKind === 'domain' || iocKind === 'file') {
    return value;
  }
  return '';
}

// vtReanalyzePath: IoC türüne göre VT v3 POST /analyse yolu.
function vtReanalyzePath(iocKind, objectId) {
  const id = encodeURIComponent(objectId);
  if (iocKind === 'ip') {
    return '/ip_addresses/' + id + '/analyse';
  }
  if (iocKind === 'domain') {
    return '/domains/' + id + '/analyse';
  }
  if (iocKind === 'file') {
    return '/files/' + id + '/analyse';
  }
  if (iocKind === 'url') {
    return '/urls/' + id + '/analyse';
  }
  return '';
}

// requestVtReanalysis: VirusTotal'de yeniden analiz kuyruğuna alır.
async function requestVtReanalysis(message) {
  const iocKind = String((message && message.iocKind) || '').toLowerCase();
  const ioc = String((message && message.ioc) || '').trim();
  if (!ioc || ['ip', 'domain', 'url', 'file'].indexOf(iocKind) < 0) {
    const err = new Error('Unsupported IoC for reanalysis');
    err.errorKey = 'errorVtReanalyzeUnsupported';
    err.errorVars = {};
    throw err;
  }
  const objectId = resolveVtObjectIdForReanalyze(iocKind, ioc, message && message.vtObjectId);
  if (!objectId) {
    const err = new Error('Could not resolve VirusTotal object id');
    err.errorKey = 'errorVtReanalyzeUnsupported';
    err.errorVars = {};
    throw err;
  }
  const path = vtReanalyzePath(iocKind, objectId);
  if (!path) {
    const err = new Error('Unsupported IoC for reanalysis');
    err.errorKey = 'errorVtReanalyzeUnsupported';
    err.errorVars = {};
    throw err;
  }
  const json = await vtFetch(path, { method: 'POST' }, { iocKind: iocKind });
  const analysisId = json && json.data && json.data.id ? String(json.data.id) : '';
  return {
    ok: true,
    iocKind: iocKind,
    ioc: ioc,
    vtObjectId: objectId,
    analysisId: analysisId
  };
}

// fetchUrlObject: Önce GET (cache); yoksa POST + GET.
async function fetchUrlObject(urlStr) {
  const meta = { iocKind: 'url' };
  const urlId = urlToVtId(urlStr);
  if (urlId) {
    try {
      return await vtFetch('/urls/' + encodeURIComponent(urlId), { method: 'GET' }, meta);
    } catch (e) {
      if (e.vtStatus !== 404) {
        throw e;
      }
    }
  }
  const posted = await vtFetch(
    '/urls',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({ url: urlStr }).toString()
    },
    meta
  );
  const newId = posted.data && posted.data.id;
  if (!newId) {
    const err = new Error('Unexpected VirusTotal response for URL submit');
    err.errorKey = 'errorVtUrlSubmit';
    err.errorVars = {};
    throw err;
  }
  return vtFetch('/urls/' + encodeURIComponent(newId), { method: 'GET' }, meta);
}

// attachRelationshipPreview: Tek ilişki önizlemesini payload'a ekler.
async function attachRelationshipPreview(payload, detected, data, cfg, targetKey) {
  const objId = data && data.data && data.data.id;
  if (!cfg || !objId) {
    return;
  }
  const path = relationshipPreviewPath(detected.kind, objId, cfg);
  if (!path) {
    return;
  }
  const key = targetKey || 'relationshipPreview';
  try {
    const relJson = await vtFetch(path, { method: 'GET' }, { iocKind: detected.kind });
    payload[key] = parseRelationshipPreviewResponse(detected.kind, cfg.relationship, relJson);
  } catch (e) {
    payload[key] = {
      relationship: cfg.relationship,
      error: e && e.message ? String(e.message) : 'Request failed'
    };
  }
}

/** Serialized VT work: one scan at a time so rate limits and ordering stay predictable. */
const jobQueue = [];
let workerRunning = false;
let jobInFlight = false;

// enqueueJob: Tarama kuyruğu, geçmiş veya toplu özet depolama.
function enqueueJob(run) {
  return new Promise(function (resolve, reject) {
    jobQueue.push({ run: run, resolve: resolve, reject: reject });
    if (!workerRunning) {
      workerRunning = true;
      runWorker();
    }
  });
}

// runWorker: Tarama kuyruğu, geçmiş veya toplu özet depolama.
async function runWorker() {
  while (jobQueue.length > 0) {
    const job = jobQueue.shift();
    jobInFlight = true;
    try {
      const result = await job.run();
      job.resolve(result);
    } catch (e) {
      job.reject(e);
    } finally {
      jobInFlight = false;
    }
  }
  workerRunning = false;
}

// resolveScanFlagsForKind: Aktif preset + IoC türüne göre VT ek sorgu bayrakları.
async function resolveScanFlagsForKind(kind) {
  const data = await chrome.storage.local.get(['vtScanPreset', 'vtScanPresets']);
  let presetId = data.vtScanPreset;
  if (presetId !== 'quick' && presetId !== 'detailed' && presetId !== 'analyst') {
    presetId = 'quick';
  }
  const map = utils.migrateScanPresetsStorage(data.vtScanPresets);
  const profile = utils.resolvePresetForKind(map, presetId, kind);
  return utils.presetToRuntimeFlags(profile);
}

// scanIoc: Tarama kuyruğu, geçmiş veya toplu özet depolama.
async function scanIoc(detected, opts) {
  opts = opts || {};
  const skipExtras = !!opts.skipExtras;
  const scanFlags = skipExtras
    ? {
        relPreview: false,
        relSecondary: false,
        engineBreakdown: false,
        mitre: false
      }
    : await resolveScanFlagsForKind(detected.kind);
  let data;
  let abuseEnrichment = null;
  switch (detected.kind) {
    case 'ip': {
      if (opts.includeAbuse === false) {
        data = await fetchIp(detected.value);
      } else {
        const abuseFlags = await resolveAbuseFlagsForIp();
        const ipResults = await Promise.all([
          fetchIp(detected.value),
          enrichAbuseForIp(detected.value, { abuseFlags: abuseFlags })
        ]);
        data = ipResults[0];
        abuseEnrichment = ipResults[1];
      }
      break;
    }
    case 'domain':
      data = await fetchDomain(detected.value);
      break;
    case 'file':
      data = await fetchFile(detected.value);
      break;
    case 'url':
      data = await fetchUrlObject(detected.value);
      break;
    default:
      throw new Error('Unsupported IoC kind');
  }
  const stats = extractStats(data);
  const level = threatLevel(stats);
  const link = guiPermalink(detected.kind, data, detected.value);
  const details = extractIocDetails(detected.kind, data);
  const attrs = data && data.data && data.data.attributes;
  const payload = {
    ok: true,
    ioc: detected.value,
    iocKind: detected.kind,
    stats: stats,
    threatLevel: level,
    permalink: link,
    rawType: data && data.data && data.data.type,
    details: details
  };
  const vtObjectId = data && data.data && data.data.id ? String(data.data.id).trim() : '';
  if (vtObjectId) {
    payload.vtObjectId = vtObjectId;
  }
  const rep = extractReputation(attrs);
  if (rep !== null) {
    payload.reputation = rep;
  }
  if (attrs) {
    payload.extendedThreatLabels = scanFlags.engineBreakdown === true;
    payload.threatContext = extractThreatContext(attrs, {
      maxDistinctLabels: scanFlags.engineBreakdown ? 20 : 8
    });
    payload.hero = buildHeroSummary(
      detected.kind,
      detected,
      attrs,
      payload.threatContext,
      rep
    );
  }
  if (detected.kind === 'ip') {
    mergeAbuseIntoIpPayload(payload, abuseEnrichment);
  }
  if (skipExtras) {
    return payload;
  }
  if (scanFlags.relPreview) {
    const cfg = VT_REL_PREVIEW_BY_KIND[detected.kind];
    await attachRelationshipPreview(payload, detected, data, cfg, 'relationshipPreview');
    const secCfg = scanFlags.relSecondary ? VT_REL_SECONDARY_BY_KIND[detected.kind] : null;
    if (secCfg) {
      await attachRelationshipPreview(
        payload,
        detected,
        data,
        secCfg,
        'relationshipPreviewSecondary'
      );
    }
  }
  if (scanFlags.mitre && detected.kind === 'file') {
    const fromObj = extractMitreFromFileAttributes(attrs);
    if (fromObj.ids.length > 0) {
      payload.mitreTechniques = fromObj;
    } else {
      const fileId = data && data.data && data.data.id;
      if (fileId) {
        try {
          const behJson = await vtFetch(
            '/files/' + encodeURIComponent(fileId) + '/behaviours?limit=5',
            { method: 'GET' },
            { iocKind: 'file' }
          );
          const beh = extractMitreFromBehavioursJson(behJson);
          beh.source = 'sandbox';
          payload.mitreTechniques = beh;
        } catch (e) {
          payload.mitreTechniques = {
            error: e && e.message ? String(e.message) : 'Request failed'
          };
        }
      }
    }
  }
  return payload;
}

let localDataWriteChain = Promise.resolve();

// enqueueLocalDataWrite: Tarama kuyruğu, geçmiş veya toplu özet depolama.
function enqueueLocalDataWrite(run) {
  localDataWriteChain = localDataWriteChain
    .catch(function () {})
    .then(run);
  return localDataWriteChain;
}

// normalizeBatchSummary: Tarama kuyruğu, geçmiş veya toplu özet depolama.
function normalizeBatchSummary(raw) {
  const src = raw && typeof raw === 'object' ? raw : {};
  const counts = src.counts && typeof src.counts === 'object' ? src.counts : {};
  const byKind = src.byKind && typeof src.byKind === 'object' ? src.byKind : {};
  return {
    id: src.id ? String(src.id).slice(0, 120) : 'batch-' + Date.now(),
    ts: Number(src.ts) || Date.now(),
    fileName: src.fileName ? String(src.fileName).slice(0, 220) : '',
    total: Math.max(0, Number(src.total) || 0),
    counts: {
      malicious: Math.max(0, Number(counts.malicious) || 0),
      suspicious: Math.max(0, Number(counts.suspicious) || 0),
      clean: Math.max(0, Number(counts.clean) || 0),
      error: Math.max(0, Number(counts.error) || 0),
      empty: Math.max(0, Number(counts.empty) || 0)
    },
    byKind: {
      ip: Math.max(0, Number(byKind.ip) || 0),
      domain: Math.max(0, Number(byKind.domain) || 0),
      url: Math.max(0, Number(byKind.url) || 0),
      file: Math.max(0, Number(byKind.file) || 0)
    },
    topRiskItems: Array.isArray(src.topRiskItems)
      ? src.topRiskItems
          .slice(0, 8)
          .map(function (it) {
            if (!it || typeof it !== 'object') {
              return null;
            }
            return {
              ioc: it.ioc ? String(it.ioc).slice(0, 400) : '',
              threatLevel: it.threatLevel === 'malicious' ? 'malicious' : it.threatLevel === 'suspicious' ? 'suspicious' : 'clean',
              kind: it.kind ? String(it.kind).slice(0, 40) : ''
            };
          })
          .filter(Boolean)
      : [],
    csv: src.csv ? String(src.csv).slice(0, 800000) : '',
    csvFileName: src.csvFileName ? String(src.csvFileName).slice(0, 240) : ''
  };
}

/** One storage round-trip for batch summary + recent list (used after batch CSV save). */
async function appendBatchHistoryAndRecent(summaryRaw) {
  return enqueueLocalDataWrite(async function () {
    const summary = normalizeBatchSummary(summaryRaw);
    const data = await chrome.storage.local.get(['vtBatchHistory', 'vtRecentHistory']);
    const batchList = Array.isArray(data.vtBatchHistory) ? data.vtBatchHistory : [];
    const recentList = Array.isArray(data.vtRecentHistory) ? data.vtRecentHistory : [];
    const nextBatch = [summary]
      .concat(
        batchList.filter(function (item) {
          return item && item.id !== summary.id;
        })
      )
      .slice(0, MAX_BATCH_HISTORY_ENTRIES);
    const summaryItem = {
      type: 'batch-summary',
      id: summary.id,
      ts: summary.ts,
      fileName: summary.fileName,
      total: summary.total,
      counts: summary.counts
    };
    const restRecent = recentList.filter(function (e) {
      return !(e && e.type === 'batch-summary' && e.id === summaryItem.id);
    });
    const nextRecent = [summaryItem].concat(restRecent).slice(0, MAX_RECENT_ENTRIES);
    await chrome.storage.local.set({
      vtBatchHistory: nextBatch,
      vtRecentHistory: nextRecent
    });
  });
}

const dayKeyFromTs = utils.dayKeyFromTs;

// defaultAnalytics: Yerel tarama analitiği okuma/yazma veya güncelleme.
function defaultAnalytics() {
  return utils.defaultAnalytics(ANALYTICS_VERSION);
}

// pruneByDay: Yerel tarama analitiği okuma/yazma veya güncelleme.
function pruneByDay(byDay) {
  return utils.pruneByDay(byDay, ANALYTICS_DAYS_KEEP);
}

// normalizeAnalytics: Yerel tarama analitiği okuma/yazma veya güncelleme.
function normalizeAnalytics(raw) {
  return utils.normalizeAnalytics(raw, {
    version: ANALYTICS_VERSION,
    daysKeep: ANALYTICS_DAYS_KEEP
  });
}

// updateAnalytics: Yerel tarama analitiği okuma/yazma veya güncelleme.
function updateAnalytics(mutator) {
  return enqueueLocalDataWrite(async function () {
    const stored = await chrome.storage.local.get([ANALYTICS_KEY]);
    const current = normalizeAnalytics(stored[ANALYTICS_KEY]);
    const next = mutator(current) || current;
    next.byDay = pruneByDay(next.byDay);
    next.lastUpdated = Date.now();
    next.version = ANALYTICS_VERSION;
    await chrome.storage.local.set({ [ANALYTICS_KEY]: next });
  });
}

// analyticsEntryFromPayload: Tek tarama satırından analitik girdisi.
function analyticsEntryFromPayload(payload) {
  const entry = {
    ts: Date.now(),
    kind: payload.iocKind,
    threatLevel: payload.threatLevel
  };
  if (payload.iocKind === 'ip' && payload.abuseipdb && payload.abuseipdb.ok === true) {
    const score = payload.abuseipdb.score;
    if (score != null && isFinite(score)) {
      entry.abuseScore = Number(score);
    }
  }
  return entry;
}

// applyScanStatEntryToAnalytics: Yerel tarama analitiği okuma/yazma veya güncelleme.
function applyScanStatEntryToAnalytics(a, entry) {
  if (!entry || !entry.kind) {
    return;
  }
  const kind = entry.kind;
  const level =
    entry.threatLevel === 'malicious'
      ? 'malicious'
      : entry.threatLevel === 'suspicious'
        ? 'suspicious'
        : 'clean';
  const dayKey = dayKeyFromTs(entry.ts || Date.now());
  a.totalScans += 1;
  a.threats[level] = (a.threats[level] || 0) + 1;
  if (Object.prototype.hasOwnProperty.call(a.byKind, kind)) {
    a.byKind[kind] = (a.byKind[kind] || 0) + 1;
  }
  a.byDay[dayKey] = (a.byDay[dayKey] || 0) + 1;
  if (kind === 'ip') {
    if (!a.abuse || typeof a.abuse !== 'object') {
      a.abuse = { lookups: 0, high: 0, elevated: 0 };
    }
    if (entry.abuseScore != null && isFinite(entry.abuseScore)) {
      a.abuse.lookups += 1;
      const sc = Number(entry.abuseScore);
      if (sc >= 75) {
        a.abuse.high += 1;
      } else if (sc >= 50) {
        a.abuse.elevated += 1;
      }
    }
  }
}

// recordScanStat: Yerel tarama analitiği okuma/yazma veya güncelleme.
function recordScanStat(entry) {
  if (!entry || !entry.kind) {
    return Promise.resolve();
  }
  return updateAnalytics(function (a) {
    applyScanStatEntryToAnalytics(a, entry);
    return a;
  });
}

/** Apply many scan rows in a single analytics read/write (batch port path). */
function recordScanStatsMany(entries) {
  if (!entries || !entries.length) {
    return Promise.resolve();
  }
  return updateAnalytics(function (a) {
    for (let i = 0; i < entries.length; i++) {
      applyScanStatEntryToAnalytics(a, entries[i]);
    }
    return a;
  });
}

// persistSingleScanSuccess: Yerel tarama analitiği okuma/yazma veya güncelleme.
async function persistSingleScanSuccess(payload) {
  const item = buildRecentHistoryItem(payload);
  if (!item) {
    return;
  }
  return enqueueLocalDataWrite(async function () {
    const data = await chrome.storage.local.get(['vtRecentHistory', ANALYTICS_KEY]);
    const list = Array.isArray(data.vtRecentHistory) ? data.vtRecentHistory : [];
    const rest = list.filter(function (e) {
      return e && e.ioc !== item.ioc;
    });
    const nextList = [item].concat(rest).slice(0, MAX_RECENT_ENTRIES);
    const current = normalizeAnalytics(data[ANALYTICS_KEY]);
    applyScanStatEntryToAnalytics(current, analyticsEntryFromPayload(payload));
    current.byDay = pruneByDay(current.byDay);
    current.lastUpdated = Date.now();
    current.version = ANALYTICS_VERSION;
    await chrome.storage.local.set({
      vtRecentHistory: nextList,
      [ANALYTICS_KEY]: current
    });
  });
}

// ensureAnalyticsBackfilled: Yerel tarama analitiği okuma/yazma veya güncelleme.
async function ensureAnalyticsBackfilled() {
  const stored = await chrome.storage.local.get([
    ANALYTICS_KEY,
    'vtRecentHistory',
    'vtBatchHistory'
  ]);
  if (stored[ANALYTICS_KEY] && Number(stored[ANALYTICS_KEY].version) === ANALYTICS_VERSION) {
    return;
  }
  const recent = Array.isArray(stored.vtRecentHistory) ? stored.vtRecentHistory : [];
  const batches = Array.isArray(stored.vtBatchHistory) ? stored.vtBatchHistory : [];
  const a = defaultAnalytics();
  recent.forEach(function (it) {
    if (!it || it.type === 'batch-summary') {
      return;
    }
    const entry = {
      ts: it.ts,
      kind: it.kind,
      threatLevel: it.threatLevel
    };
    if (
      it.kind === 'ip' &&
      it.abuseipdb &&
      it.abuseipdb.ok === true &&
      it.abuseipdb.score != null &&
      isFinite(it.abuseipdb.score)
    ) {
      entry.abuseScore = Number(it.abuseipdb.score);
    }
    applyScanStatEntryToAnalytics(a, entry);
  });
  batches.forEach(function (b) {
    if (!b) return;
    const c = b.counts || {};
    const bk = b.byKind || {};
    const total = Math.max(0, Number(b.total) || 0);
    a.totalScans += total;
    a.threats.malicious += Math.max(0, Number(c.malicious) || 0);
    a.threats.suspicious += Math.max(0, Number(c.suspicious) || 0);
    a.threats.clean += Math.max(0, Number(c.clean) || 0);
    ['ip', 'domain', 'url', 'file'].forEach(function (kk) {
      a.byKind[kk] += Math.max(0, Number(bk[kk]) || 0);
    });
    if (total > 0) {
      const k = dayKeyFromTs(b.ts);
      a.byDay[k] = (a.byDay[k] || 0) + total;
    }
  });
  a.byDay = pruneByDay(a.byDay);
  a.lastUpdated = Date.now();
  await chrome.storage.local.set({ [ANALYTICS_KEY]: a });
}

ensureAnalyticsBackfilled().catch(function () {});

// runScanPrepared: Tarama kuyruğu, geçmiş veya toplu özet depolama.
async function runScanPrepared(prepared, source, scanOpts) {
  scanOpts = scanOpts || {};
  const detected = detectIoc(prepared);
  if (detected.kind === 'unknown') {
    const errPayload = {
      ok: false,
      error: 'Could not classify IoC. Enter a valid IP, domain, URL, or file hash.'
    };
    if (isExternalScanPersistSource(source)) {
      await persistContextScanResult(errPayload, prepared);
    }
    if (isContextMenuScanSource(source)) {
      await notifyContextMenuScanOutcome(errPayload);
    }
    return errPayload;
  }

  const queueAhead = jobQueue.length + (jobInFlight ? 1 : 0);
  const payload = await enqueueJob(function () {
    return scanIoc(detected, scanOpts);
  });

  if (payload.ok && source !== 'batch' && scanOpts.skipRecent !== true && scanOpts.skipAnalytics !== true) {
    await persistSingleScanSuccess(payload);
  } else if (payload.ok && scanOpts.skipAnalytics !== true) {
    await recordScanStat(analyticsEntryFromPayload(payload));
  }

  if (isExternalScanPersistSource(source)) {
    await persistContextScanResult(payload, detected.value);
  }
  if (isContextMenuScanSource(source)) {
    await notifyContextMenuScanOutcome(payload);
  }

  return Object.assign({ queued: queueAhead > 0, queueAhead: queueAhead }, payload);
}

// handleScanInput: Tarama kuyruğu, geçmiş veya toplu özet depolama.
async function handleScanInput(raw, source, opts) {
  opts = opts || {};
  const prepared = opts.stripNoise
    ? normalizeIocInput(raw)
    : String(raw || '').trim();
  return runScanPrepared(prepared, source, opts);
}

// ensureContextMenu: Uzantı olayları veya mesaj/port köprüsü.
function ensureContextMenu() {
  chrome.contextMenus.removeAll(function () {
    chrome.contextMenus.create({
      id: 'vt-check-ioc',
      title: 'Scan selection with ' + APP_NAME,
      contexts: ['selection']
    });
  });
}

chrome.runtime.onInstalled.addListener(function (details) {
  ensureContextMenu();
  ensureNewsAutoRefreshAlarm();
  ensureUsomAutoRefreshAlarm();
  chrome.storage.local.get(UI_MODE_KEY, function (data) {
    if (!data[UI_MODE_KEY]) {
      chrome.storage.local.set({ [UI_MODE_KEY]: 'popup' }, function () {
        refreshUiModeFromStorage().catch(function () {});
      });
      return;
    }
    refreshUiModeFromStorage().catch(function () {});
  });
});
chrome.runtime.onStartup.addListener(function () {
  ensureContextMenu();
  ensureNewsAutoRefreshAlarm();
  ensureUsomAutoRefreshAlarm();
  refreshUiModeFromStorage().catch(function () {});
});

chrome.alarms.onAlarm.addListener(function (alarm) {
  if (!alarm) {
    return;
  }
  if (alarm.name === NEWS_AUTO_REFRESH_ALARM) {
    refreshNewsWithOptionalNotification(true).catch(function () {});
    return;
  }
  if (alarm.name === USOM_AUTO_REFRESH_ALARM) {
    refreshUsomWithOptionalNotification(true).catch(function () {});
  }
});

ensureNewsAutoRefreshAlarm();
ensureUsomAutoRefreshAlarm();

chrome.contextMenus.onClicked.addListener(function (info) {
  const text = (info.selectionText || '').trim();
  if (!text) {
    return;
  }
  handleScanInput(text, 'context').catch(function (err) {
    const msg = err && err.message ? err.message : 'Scan failed';
    const errPayload = { ok: false, error: msg };
    persistContextScanResult(errPayload, text)
      .then(function () {
        return notifyContextMenuScanOutcome(errPayload);
      })
      .catch(function () {});
  });
});

chrome.runtime.onConnect.addListener(function (port) {
  if (!port || !guards.isKnownPortName(port.name) || !guards.isTrustedRuntimeSender(port.sender)) {
    try {
      port.disconnect();
    } catch (_) {}
    return;
  }
  if (port.name === 'vt-single') {
    port.onMessage.addListener(function (msg) {
      if (!guards.isValidSingleScanMessage(msg)) {
        return;
      }
      const src = msg.source === 'content' ? 'content' : 'popup';
      handleScanInput(msg.payload || '', src, {
        stripNoise: !!msg.stripNoise
      })
        .then(function (result) {
          try {
            port.postMessage({ type: 'SCAN_RESULT', result: result });
          } catch (_) {}
        })
        .catch(function (err) {
          try {
            port.postMessage({
              type: 'SCAN_RESULT',
              result: {
                ok: false,
                error: err && err.message ? err.message : 'Scan failed',
                errorKey: err && err.errorKey ? err.errorKey : '',
                errorVars: err && err.errorVars ? err.errorVars : {}
              }
            });
          } catch (_) {}
        });
    });
    return;
  }
  port.onMessage.addListener(function (msg) {
    if (!guards.isValidBatchScanMessage(msg)) {
      return;
    }
    const lines = Array.isArray(msg.lines) ? msg.lines : [];
    const strip = !!msg.stripNoise;
    const includeAbuse = msg.includeAbuse !== false;
    const total = lines.length;
    (async function () {
      const analyticsEntries = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const prepared = strip ? normalizeIocInput(line) : String(line || '').trim();
        if (!prepared) {
          port.postMessage({
            type: 'BATCH_LINE',
            index: i,
            total: total,
            status: 'empty',
            raw: String(line || '')
          });
          continue;
        }
        try {
          const result = await runScanPrepared(prepared, 'batch', {
            skipExtras: true,
            skipRecent: true,
            skipAnalytics: true,
            includeAbuse: includeAbuse
          });
          if (result && result.ok) {
            analyticsEntries.push(analyticsEntryFromPayload(result));
          }
          port.postMessage(
            Object.assign(
              {
                type: 'BATCH_LINE',
                index: i,
                total: total,
                line: prepared
              },
              result
            )
          );
        } catch (err) {
          port.postMessage({
            type: 'BATCH_LINE',
            index: i,
            total: total,
            line: prepared,
            ok: false,
            error: err && err.message ? err.message : 'Scan failed'
          });
        }
      }
      await recordScanStatsMany(analyticsEntries);
      port.postMessage({ type: 'BATCH_DONE' });
    })().catch(function (err) {
      try {
        port.postMessage({
          type: 'BATCH_ERROR',
          error: err && err.message ? err.message : 'Batch failed'
        });
      } catch (_) {}
    });
  });
});

// respondAsync: Uzantı olayları veya mesaj/port köprüsü.
function respondAsync(sendResponse, promise, fallbackMessage, errorFactory) {
  Promise.resolve(promise)
    .then(function (payload) {
      sendResponse(payload);
    })
    .catch(function (err) {
      if (typeof errorFactory === 'function') {
        sendResponse(errorFactory(err));
        return;
      }
      sendResponse({
        ok: false,
        error: err && err.message ? String(err.message) : fallbackMessage
      });
    });
  return true;
}

const backgroundMessageHandlers = {
  GET_NEWS: function (_message, sendResponse) {
    return respondAsync(sendResponse, getNewsPayload(false), 'Failed to load news');
  },
  REFRESH_NEWS: function (message, sendResponse) {
    return respondAsync(
      sendResponse,
      refreshNewsWithOptionalNotification(message.autoRefresh === true),
      'Failed to refresh news'
    );
  },
  GET_USOM: function (_message, sendResponse) {
    return respondAsync(sendResponse, getUsomPayload(false), 'Failed to load USOM feed');
  },
  REFRESH_USOM: function (message, sendResponse) {
    return respondAsync(
      sendResponse,
      refreshUsomWithOptionalNotification(message.autoRefresh === true),
      'Failed to refresh USOM feed'
    );
  },
  GET_USOM_DETAIL: function (message, sendResponse) {
    return respondAsync(sendResponse, fetchUsomDetail(message), 'Failed to load USOM detail');
  },
  GET_QUEUE: function (_message, sendResponse) {
    const pending = jobQueue.length + (jobInFlight ? 1 : 0);
    sendResponse({ pending: pending });
  },
  GET_RECENT_HISTORY: function (_message, sendResponse) {
    chrome.storage.local.get(['vtRecentHistory'], function (data) {
      const list = Array.isArray(data.vtRecentHistory) ? data.vtRecentHistory : [];
      sendResponse({ entries: list });
    });
    return true;
  },
  VT_REANALYZE: function (message, sendResponse) {
    return respondAsync(sendResponse, requestVtReanalysis(message), 'Reanalyze request failed', function (err) {
      return {
        ok: false,
        errorKey: (err && err.errorKey) || 'errorVtReanalyzeFailed',
        error: err && err.message ? String(err.message) : 'Reanalyze request failed',
        errorVars: (err && err.errorVars) || {}
      };
    });
  },
  ENRICH_ABUSE_FOR_IP: function (message, sendResponse) {
    const ip = message && message.ip ? String(message.ip).trim() : '';
    if (!ip) {
      sendResponse({ ok: false, error: 'missing_ip' });
      return false;
    }
    return respondAsync(
      sendResponse,
      enrichAbuseForIp(ip).then(function (abuse) {
        return { ok: true, abuseipdb: abuse || { ok: false } };
      }),
      'AbuseIPDB enrich failed'
    );
  },
  GET_BATCH_HISTORY: function (_message, sendResponse) {
    chrome.storage.local.get(['vtBatchHistory'], function (data) {
      const list = Array.isArray(data.vtBatchHistory) ? data.vtBatchHistory : [];
      sendResponse({ entries: list });
    });
    return true;
  },
  SAVE_BATCH_HISTORY: function (message, sendResponse) {
    return respondAsync(
      sendResponse,
      appendBatchHistoryAndRecent(message.summary).then(function () {
        return { ok: true };
      }),
      'Failed to save batch history'
    );
  },
  CLEAR_HISTORY_SECTION: function (message, sendResponse) {
    const section = message.section === 'batch' ? 'batch' : 'general';
    if (section === 'batch') {
      chrome.storage.local.get(['vtRecentHistory'], function (data) {
        const list = Array.isArray(data.vtRecentHistory) ? data.vtRecentHistory : [];
        const filtered = list.filter(function (entry) {
          return !(entry && entry.type === 'batch-summary');
        });
        chrome.storage.local.set({ vtBatchHistory: [], vtRecentHistory: filtered }, function () {
          sendResponse({ ok: true });
        });
      });
      return true;
    }
    chrome.storage.local.set({ vtRecentHistory: [] }, function () {
      sendResponse({ ok: true });
    });
    return true;
  },
  TEST_VT_CONNECTION: function (message, sendResponse) {
    const override = message.apiKey != null ? String(message.apiKey) : '';
    return respondAsync(
      sendResponse,
      testVtApiConnection(override),
      'Test failed',
      function (err) {
        return {
          ok: false,
          error: 'exception',
          detail: err && err.message ? String(err.message) : 'Test failed'
        };
      }
    );
  },
  TEST_ABUSE_CONNECTION: function (message, sendResponse) {
    const override = message.apiKey != null ? String(message.apiKey) : '';
    return respondAsync(
      sendResponse,
      testAbuseApiConnection(override),
      'Test failed',
      function (err) {
        return {
          ok: false,
          error: 'exception',
          detail: err && err.message ? String(err.message) : 'Test failed'
        };
      }
    );
  },
  APPLY_UI_MODE: function (message, sendResponse) {
    const mode = message.mode === 'sidepanel' ? 'sidepanel' : 'popup';
    return respondAsync(
      sendResponse,
      applyUiMode(mode).then(function () {
        return { ok: true, mode: mode };
      }),
      'Failed to apply UI mode'
    );
  }
};

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  if (!guards.isTrustedRuntimeSender(sender)) {
    sendResponse({ ok: false, error: 'unauthorized_sender' });
    return false;
  }
  if (!message || !message.type) {
    return;
  }
  const handler = backgroundMessageHandlers[message.type];
  if (!handler) {
    return;
  }
  return handler(message, sendResponse);
});
