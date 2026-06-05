'use strict';

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
async function fetchAbuseJson(url, apiKey, attempt) {
  const tryNo = attempt || 0;
  const headers = { Accept: 'application/json' };
  const key = String(apiKey || '').trim();
  if (key) {
    headers.Key = key;
  }
  const response = await fetch(url.toString(), {
    method: 'GET',
    headers: headers
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
    return fetchAbuseJson(url, apiKey, tryNo + 1);
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

/** Non-throwing presence check so the scan router can treat AbuseIPDB as an optional provider. */
async function hasAbuseApiKey() {
  return !!(await getAbuseApiKey());
}

// loadScanPresetProfile: Aktif preset + IoC türü için profil (tek storage okuması).
async function loadScanPresetProfile(kind) {
  const data = await chrome.storage.local.get(['vtScanPreset', 'vtScanPresets']);
  let presetId = data.vtScanPreset;
  if (presetId !== 'quick' && presetId !== 'detailed' && presetId !== 'analyst') {
    presetId = 'quick';
  }
  const map = utils.migrateScanPresetsStorage(data.vtScanPresets);
  return utils.resolvePresetForKind(map, presetId, kind);
}

// resolveAbuseFlagsForIp: Aktif scan preset → AbuseIPDB sorgu bayrakları (IP only).
async function resolveAbuseFlagsForIp(profile) {
  const prof = profile || (await loadScanPresetProfile('ip'));
  return utils.presetToAbuseFlags(prof);
}

// runAbuseLookup: AbuseIPDB check; isteğe bağlı reports (sayfa 1, 100 kayıt).
async function runAbuseLookup(ip, apiKey, maxAgeInDays, overallDays, includeReports) {
  const checkUrl = new URL('https://api.abuseipdb.com/api/v2/check');
  checkUrl.searchParams.set('ipAddress', ip);
  checkUrl.searchParams.set('maxAgeInDays', String(overallDays));
  const checkPayload = await fetchAbuseJson(checkUrl, apiKey);
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
    const reportsPayload = await fetchAbuseJson(reportsUrl, apiKey);
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
  if (!utils.isPublicRoutableIp(ip)) {
    return {
      ok: false,
      error: 'Private or reserved IP addresses cannot be sent to external lookup services.',
      errorKey: 'errorPrivateIp'
    };
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
    payload.threatLevelAbuse = 'unknown';
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
    await fetchAbuseJson(url, key);
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
