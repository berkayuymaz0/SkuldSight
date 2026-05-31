'use strict';

/**
 * Shared utilities — analytics: default/normalize/prune of the local analytics object.
 */
(function (global) {
  const U = (global.VtSocUtils = global.VtSocUtils || {});

  const DEFAULT_ANALYTICS_VERSION = 2;
  const DEFAULT_ANALYTICS_DAYS_KEEP = 60;

  // Boş/yeni analitik yapısı üretir (sürüm alanı ile).
  function defaultAbuseAnalytics() {
    return { lookups: 0, high: 0, elevated: 0 };
  }

  function defaultAnalytics(version) {
    return {
      version: Number(version) || DEFAULT_ANALYTICS_VERSION,
      totalScans: 0,
      threats: { malicious: 0, suspicious: 0, clean: 0 },
      byKind: { ip: 0, domain: 0, url: 0, file: 0 },
      abuse: defaultAbuseAnalytics(),
      byDay: {},
      lastUpdated: 0
    };
  }

  // byDay içinde retention penceresi dışındaki günleri atarak sözlüğü budar.
  function pruneByDay(byDay, daysKeep) {
    const keep = Math.max(1, Number(daysKeep) || DEFAULT_ANALYTICS_DAYS_KEEP);
    const cutoff = Date.now() - keep * 24 * 60 * 60 * 1000;
    const out = {};
    Object.keys(byDay || {}).forEach(function (k) {
      const parts = k.split('-');
      if (parts.length !== 3) {
        return;
      }
      const t = new Date(Number(parts[0]), Number(parts[1]) - 1, Number(parts[2])).getTime();
      if (isFinite(t) && t >= cutoff) {
        out[k] = Math.max(0, Number(byDay[k]) || 0);
      }
    });
    return out;
  }

  // Depodan gelen ham analitik nesnesini sayımlar ve sürümle tutarlı, budanmış forma dönüştürür.
  function normalizeAnalytics(raw, opts) {
    const options = opts || {};
    const version = Number(options.version) || DEFAULT_ANALYTICS_VERSION;
    const daysKeep = Number(options.daysKeep) || DEFAULT_ANALYTICS_DAYS_KEEP;
    const shouldPrune = options.pruneByDay !== false;
    const base = defaultAnalytics(version);
    const src = raw && typeof raw === 'object' ? raw : {};
    const threats = src.threats && typeof src.threats === 'object' ? src.threats : {};
    const byKind = src.byKind && typeof src.byKind === 'object' ? src.byKind : {};
    const abuseSrc = src.abuse && typeof src.abuse === 'object' ? src.abuse : {};
    const byDay = src.byDay && typeof src.byDay === 'object' ? src.byDay : {};
    return {
      version: version,
      totalScans: Math.max(0, Number(src.totalScans) || 0),
      threats: {
        malicious: Math.max(0, Number(threats.malicious) || 0),
        suspicious: Math.max(0, Number(threats.suspicious) || 0),
        clean: Math.max(0, Number(threats.clean) || 0)
      },
      byKind: {
        ip: Math.max(0, Number(byKind.ip) || 0),
        domain: Math.max(0, Number(byKind.domain) || 0),
        url: Math.max(0, Number(byKind.url) || 0),
        file: Math.max(0, Number(byKind.file) || 0)
      },
      abuse: {
        lookups: Math.max(0, Number(abuseSrc.lookups) || 0),
        high: Math.max(0, Number(abuseSrc.high) || 0),
        elevated: Math.max(0, Number(abuseSrc.elevated) || 0)
      },
      byDay: shouldPrune ? pruneByDay(byDay, daysKeep) : byDay,
      lastUpdated: Number(src.lastUpdated) || base.lastUpdated
    };
  }

  Object.assign(U, {
    defaultAbuseAnalytics: defaultAbuseAnalytics,
    defaultAnalytics: defaultAnalytics,
    pruneByDay: pruneByDay,
    normalizeAnalytics: normalizeAnalytics
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
