'use strict';

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
