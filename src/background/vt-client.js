'use strict';

function notifyQueued() {
  if (!notifyQueuedEnabled) {
    return;
  }
  showNotification('queue', APP_NAME, 'Request queued. Waiting for VT rate limit...');
}

function effectiveRateIntervalMs() {
  return proModeEnabled ? PRO_MODE_MIN_INTERVAL_MS : rateIntervalMs;
}

// waitRateLimit: VirusTotal API hız sınırı veya HTTP çağrısı.
async function waitRateLimit() {
  const now = Date.now();
  const wait = Math.max(0, nextSlotAt - now);
  if (!proModeEnabled && wait > NOTIFY_WAIT_MS) {
    notifyQueued();
  }
  if (wait > 0) {
    await sleep(wait);
  }
}

// markSlot: VirusTotal API hız sınırı veya HTTP çağrısı.
function markSlot() {
  nextSlotAt = Date.now() + effectiveRateIntervalMs();
}

/** One VT API slot: wait for pacing then reserve the next interval (used by all throttled VT calls). */
async function consumeVtRateSlot() {
  await waitRateLimit();
  markSlot();
}

function parseRetryAfterSec(headerVal) {
  const raw = String(headerVal || '').trim();
  if (!raw) {
    return 0;
  }
  const n = Number(raw);
  if (isFinite(n) && n >= 0) {
    return n;
  }
  const when = Date.parse(raw);
  if (isFinite(when)) {
    return Math.max(0, Math.ceil((when - Date.now()) / 1000));
  }
  return 0;
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

/**
 * Non-throwing presence check used by the scan router so VirusTotal can be
 * treated as one optional provider among others (e.g. AbuseIPDB-only IP scans).
 */
async function hasVtApiKey() {
  const stored = await getStoredKeyWithExpiry('vtApiKey', 'vtApiKeySavedAt');
  if (stored.isExpired) {
    await clearStoredKey('vtApiKey', 'vtApiKeySavedAt');
    return false;
  }
  return !!stored.key;
}

// getApiKey: VirusTotal API hız sınırı veya HTTP çağrısı.
async function getApiKey() {
  const stored = await getStoredKeyWithExpiry('vtApiKey', 'vtApiKeySavedAt');
  if (stored.isExpired) {
    await clearStoredKey('vtApiKey', 'vtApiKeySavedAt');
    const expiredErr = new Error('VirusTotal API key expired (14 days). Set a new key in options.');
    expiredErr.errorKey = 'errorVtKeyExpired';
    expiredErr.errorVars = {};
    throw expiredErr;
  }
  if (!stored.key) {
    const missingErr = new Error('Configure your VirusTotal API key in extension options.');
    missingErr.errorKey = 'errorVtNoKey';
    missingErr.errorVars = {};
    throw missingErr;
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

/** GET /users/{id}/overall_quotas — does not consume API quota. */
async function fetchVtQuotas(overrideKey) {
  let key = String(overrideKey || '').trim();
  if (!key) {
    const stored = await getStoredKeyWithExpiry('vtApiKey', 'vtApiKeySavedAt');
    key = stored.key;
    if (stored.isExpired || !key) {
      return { ok: false, error: 'no_api_key' };
    }
  }
  const url = VT_API + '/users/' + encodeURIComponent(key) + '/overall_quotas';
  const res = await fetch(url, {
    method: 'GET',
    headers: { 'x-apikey': key }
  });
  const text = await res.text();
  if (res.status === 401 || res.status === 403) {
    return { ok: false, error: 'unauthorized' };
  }
  if (!res.ok) {
    return { ok: false, error: 'http_' + res.status, detail: text ? text.slice(0, 200) : '' };
  }
  try {
    const data = JSON.parse(text);
    const attrs = data && data.data && data.data.attributes;
    return {
      ok: true,
      daily: parseQuotaBucket(attrs && attrs.api_requests_daily),
      monthly: parseQuotaBucket(attrs && attrs.api_requests_monthly),
      fetchedAt: Date.now()
    };
  } catch (_) {
    return { ok: false, error: 'bad_json' };
  }
}

function parseQuotaBucket(bucket) {
  if (!bucket || typeof bucket !== 'object') {
    return null;
  }
  const user = bucket.user && typeof bucket.user === 'object' ? bucket.user : bucket;
  const used = Number(user.used);
  const allowed = Number(user.allowed);
  if (!isFinite(allowed) || allowed <= 0) {
    return null;
  }
  const usedN = isFinite(used) && used >= 0 ? used : 0;
  return {
    used: usedN,
    allowed: allowed,
    remaining: Math.max(0, allowed - usedN)
  };
}

/**
 * Poll GET /analyses/{id} until status is completed or attempts exhausted.
 * Each poll consumes one API quota unit when the analysis id is valid.
 */
async function pollVtAnalysis(analysisId, opts) {
  opts = opts || {};
  const id = String(analysisId || '').trim();
  if (!id || opts.enabled === false) {
    return { ok: false, skipped: true };
  }
  const maxAttempts =
    Number(opts.maxAttempts) > 0 ? Number(opts.maxAttempts) : VT_ANALYSIS_POLL_MAX;
  const intervalMs =
    Number(opts.intervalMs) > 0 ? Number(opts.intervalMs) : VT_ANALYSIS_POLL_INTERVAL_MS;
  const meta = { iocKind: opts.iocKind || '' };
  let lastStatus = '';
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    if (attempt > 0) {
      await sleep(intervalMs);
    }
    let json;
    try {
      json = await vtFetch('/analyses/' + encodeURIComponent(id), { method: 'GET' }, meta);
    } catch (e) {
      if (e && e.vtStatus === 404 && attempt + 1 < maxAttempts) {
        continue;
      }
      throw e;
    }
    const attrs = json && json.data && json.data.attributes;
    lastStatus = attrs && attrs.status ? String(attrs.status) : '';
    if (lastStatus === 'completed') {
      return { ok: true, status: lastStatus, attempts: attempt + 1 };
    }
    if (typeof opts.onProgress === 'function') {
      opts.onProgress({
        status: lastStatus || 'queued',
        attempt: attempt + 1,
        maxAttempts: maxAttempts
      });
    }
  }
  return { ok: false, status: lastStatus || 'timeout', attempts: maxAttempts };
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
  let lastErr = null;
  for (let attempt = 0; attempt < VT_429_MAX_RETRIES; attempt++) {
    await consumeVtRateSlot();
    const res = await fetch(
      VT_API + path,
      Object.assign({}, init, {
        headers: Object.assign(
          {
            'x-apikey': key
          },
          init && init.headers
        )
      })
    );
    const text = await res.text();
    if (
      (res.status === 429 || (res.status >= 500 && res.status <= 599)) &&
      attempt + 1 < VT_429_MAX_RETRIES
    ) {
      const waitMs = computeRetryWaitMs(
        attempt,
        parseRetryAfterSec(res.headers.get('Retry-After')),
        VT_429_BACKOFF_BASE_MS,
        VT_429_BACKOFF_MAX_MS
      );
      await sleep(waitMs);
      continue;
    }
    if (!res.ok) {
      lastErr = makeVtApiError(res.status, text, meta);
      throw lastErr;
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
  if (lastErr) {
    throw lastErr;
  }
  const err = new Error('VirusTotal rate limit exceeded');
  err.errorKey = 'errorVtRateLimit';
  err.errorVars = {};
  throw err;
}
