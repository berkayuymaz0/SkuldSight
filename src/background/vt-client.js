'use strict';

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
