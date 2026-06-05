'use strict';

/**
 * Shared utilities — core: storage keys, rate clamp, IoC input normalization, day keys.
 * Augments the global VtSocUtils namespace.
 */
(function (global) {
  const U = (global.VtSocUtils = global.VtSocUtils || {});

  const DEFAULT_RATE_INTERVAL_SEC = 16;
  const MIN_RATE_INTERVAL_SEC = 15;
  const MAX_RATE_INTERVAL_SEC = 20;
  const API_KEY_TTL_MS = 14 * 24 * 60 * 60 * 1000;
  const STORAGE_KEYS = {
    contextScanResult: 'vtContextScanResult',
    scanPreset: 'vtScanPreset',
    scanPresets: 'vtScanPresets',
    copySummaryFields: 'vtCopySummaryFields',
    newsReadMap: 'vtNewsReadMap',
    newsCache: 'vtNewsCache',
    newsFetchedAt: 'vtNewsFetchedAt',
    usomCache: 'vtUsomCache',
    usomFetchedAt: 'vtUsomFetchedAt',
    popupActiveTab: 'vtPopupActiveTab',
    analytics: 'vtAnalytics',
    uiMode: 'vtUiMode',
    scanFullUrls: 'vtScanFullUrls'
  };

  // API key saklama zaman damgasının TTL penceresini aşıp aşmadığını döndürür.
  function isApiKeyExpired(savedAt) {
    const ts = Number(savedAt);
    if (!isFinite(ts) || ts <= 0) {
      return false;
    }
    return Date.now() - ts > API_KEY_TTL_MS;
  }

  // Kullanıcı ayarındaki saniye değerini izin verilen aralığa yuvarlar ve sayı değilse varsayılanı döndürür.
  function clampRateSec(sec) {
    const n = Number(sec);
    if (!isFinite(n)) {
      return DEFAULT_RATE_INTERVAL_SEC;
    }
    return Math.min(MAX_RATE_INTERVAL_SEC, Math.max(MIN_RATE_INTERVAL_SEC, Math.round(n)));
  }

  // SOC yapıştırma/defang gürültüsünü ve yaygın hataları gidererek VT’ye uygun IoC metni üretir.
  /**
   * Strip SOC paste/defang noise and common mistakes that still match naive domain regex
   * but are rejected by VirusTotal (e.g. Python bytes repr b'host', or ".com" + "vt" → ".comvt").
   */
  function normalizeIocInput(raw) {
    let s = String(raw || '').trim();
    if (!s) {
      return s;
    }
    s = s.replace(/\uFEFF/g, '');
    let guard = 0;
    while (guard++ < 8) {
      let changed = false;
      const first = s.charCodeAt(0);
      const last = s.charCodeAt(s.length - 1);
      if (
        s.length >= 3 &&
        (first === 98 || first === 66) &&
        (s.charAt(1) === "'" || s.charAt(1) === '"')
      ) {
        const q = s.charAt(1);
        if (last === q.charCodeAt(0) && s.length > 3) {
          s = s.slice(2, -1).trim();
          changed = true;
        }
      }
      if (
        !changed &&
        s.length >= 2 &&
        ((first === 34 && last === 34) || (first === 39 && last === 39))
      ) {
        s = s.slice(1, -1).trim();
        changed = true;
      }
      if (!changed) {
        break;
      }
    }
    s = s.replace(/\bhxxps:\/\//gi, 'https://');
    s = s.replace(/\bhxxp:\/\//gi, 'http://');
    s = s.replace(/\[\.\]/g, '.');
    s = s.trim();

    const vtGlue = /^(.+)\.(com|net|org)vt$/i;
    const glued = vtGlue.exec(s.toLowerCase());
    if (glued) {
      s = glued[1] + '.' + glued[2].toLowerCase();
    }

    return s.trim();
  }

  // Zaman damgasını YYYY-MM-DD gün anahtarına çevirir (günlük analitik gruplama için).
  function dayKeyFromTs(ts) {
    const d = new Date(Number(ts) || Date.now());
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return y + '-' + m + '-' + day;
  }

  Object.assign(U, {
    STORAGE_KEYS: STORAGE_KEYS,
    API_KEY_TTL_MS: API_KEY_TTL_MS,
    isApiKeyExpired: isApiKeyExpired,
    clampRateSec: clampRateSec,
    normalizeIocInput: normalizeIocInput,
    dayKeyFromTs: dayKeyFromTs
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
