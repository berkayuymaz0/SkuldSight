'use strict';

function sleep(ms) {
  return new Promise(function (r) {
    setTimeout(r, ms);
  });
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

function computeRetryWaitMs(attempt, retryAfterSec, baseMs, maxMs) {
  if (retryAfterSec > 0) {
    return retryAfterSec * 1000;
  }
  const jitter = Math.floor(Math.random() * 250);
  return Math.min(maxMs, baseMs * Math.pow(2, attempt)) + jitter;
}

function shouldRetryHttpStatus(status, retryOn) {
  const st = Number(status) || 0;
  if (typeof retryOn === 'function') {
    return retryOn(st);
  }
  if (Array.isArray(retryOn)) {
    return retryOn.indexOf(st) >= 0;
  }
  return st === 429 || (st >= 500 && st <= 599);
}

async function fetchWithRetry(requestFn, opts) {
  opts = opts || {};
  const maxAttempts = Number(opts.maxAttempts) > 0 ? Number(opts.maxAttempts) : 3;
  const baseMs = Number(opts.backoffBaseMs) > 0 ? Number(opts.backoffBaseMs) : 16000;
  const maxMs = Number(opts.backoffMaxMs) > 0 ? Number(opts.backoffMaxMs) : 60000;
  const retryOn = opts.retryOnStatus;
  let last = null;
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    last = await requestFn();
    const response = last && last.response;
    if (!response) {
      return last;
    }
    if (!shouldRetryHttpStatus(response.status, retryOn) || attempt + 1 >= maxAttempts) {
      return last;
    }
    const waitMs = computeRetryWaitMs(
      attempt,
      parseRetryAfterSec(response.headers.get('Retry-After')),
      baseMs,
      maxMs
    );
    await sleep(waitMs);
  }
  return last;
}
