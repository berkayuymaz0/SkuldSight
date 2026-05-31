'use strict';

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

