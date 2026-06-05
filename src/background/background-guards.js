'use strict';

(function (global) {
  const ALLOWED_PORTS = new Set(['vt-single', 'vt-batch']);
  const MAX_MESSAGE_TYPE_LEN = 64;
  const MAX_SCAN_PAYLOAD_LEN = 4096;
  const MAX_BATCH_LINES = 250;
  const MAX_BATCH_LINE_LEN = 4096;
  const CONTENT_SCAN_RATE_LIMIT = 10;
  const CONTENT_SCAN_WINDOW_MS = 60000;
  const contentScanTimestamps = new Map();

  const MESSAGE_CONTEXT_MATRIX = {
    GET_CONTENT_SETTINGS: ['content', 'popup', 'options'],
    GET_QUEUE: ['content', 'popup', 'options'],
    GET_NEWS: ['popup', 'options'],
    REFRESH_NEWS: ['popup', 'options'],
    GET_USOM: ['popup', 'options'],
    REFRESH_USOM: ['popup', 'options'],
    GET_USOM_DETAIL: ['popup', 'options'],
    GET_RECENT_HISTORY: ['popup', 'options'],
    GET_BATCH_HISTORY: ['popup', 'options'],
    SAVE_BATCH_HISTORY: ['popup', 'options'],
    CLEAR_HISTORY_SECTION: ['popup', 'options'],
    VT_REANALYZE: ['popup', 'options'],
    GET_VT_QUOTAS: ['popup', 'options'],
    ENRICH_ABUSE_FOR_IP: ['popup', 'options'],
    TEST_VT_CONNECTION: ['popup', 'options'],
    TEST_ABUSE_CONNECTION: ['options'],
    APPLY_UI_MODE: ['popup', 'options']
  };

  function isPlainObject(value) {
    if (!value || typeof value !== 'object') {
      return false;
    }
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
  }

  function getSenderContext(sender) {
    if (!sender || typeof sender !== 'object') {
      return 'unknown';
    }
    const url = String(sender.url || '');
    if (url.indexOf('/src/popup/popup.html') !== -1) {
      return 'popup';
    }
    if (url.indexOf('/src/options/options.html') !== -1) {
      return 'options';
    }
    if (sender.tab && sender.tab.url && /^https:\/\//i.test(String(sender.tab.url))) {
      return 'content';
    }
    if (!sender.tab && url.indexOf('chrome-extension://') === 0) {
      return 'extension';
    }
    return 'unknown';
  }

  function isTrustedRuntimeSender(sender) {
    if (!sender || typeof sender !== 'object') {
      return false;
    }
    if (sender.id && sender.id !== chrome.runtime.id) {
      return false;
    }
    return true;
  }

  function isTrustedExtensionPageSender(sender) {
    const ctx = getSenderContext(sender);
    return ctx === 'popup' || ctx === 'options';
  }

  function isTrustedContentSender(sender) {
    return getSenderContext(sender) === 'content';
  }

  function isMessageAllowedForSender(messageType, sender) {
    const allowed = MESSAGE_CONTEXT_MATRIX[String(messageType || '')];
    if (!allowed) {
      return false;
    }
    const ctx = getSenderContext(sender);
    return allowed.indexOf(ctx) >= 0;
  }

  function canConnectPort(portName, sender) {
    if (!isTrustedRuntimeSender(sender)) {
      return false;
    }
    if (portName === 'vt-batch') {
      return isTrustedExtensionPageSender(sender);
    }
    if (portName === 'vt-single') {
      return isTrustedExtensionPageSender(sender) || isTrustedContentSender(sender);
    }
    return false;
  }

  function isKnownPortName(name) {
    return ALLOWED_PORTS.has(String(name || ''));
  }

  function pruneContentScanTimestamps(list, now) {
    const cutoff = now - CONTENT_SCAN_WINDOW_MS;
    return list.filter(function (ts) {
      return ts > cutoff;
    });
  }

  function checkContentScanRateLimit(tabId) {
    const id = Number(tabId) || 0;
    if (id <= 0) {
      return { ok: false, errorKey: 'errorContentScanRateLimit' };
    }
    const now = Date.now();
    const prev = contentScanTimestamps.get(id) || [];
    const recent = pruneContentScanTimestamps(prev, now);
    if (recent.length >= CONTENT_SCAN_RATE_LIMIT) {
      return { ok: false, errorKey: 'errorContentScanRateLimit' };
    }
    recent.push(now);
    contentScanTimestamps.set(id, recent);
    return { ok: true };
  }

  function isValidSingleScanMessage(msg) {
    if (!isPlainObject(msg)) {
      return false;
    }
    if (typeof msg.type !== 'string' || msg.type.length > MAX_MESSAGE_TYPE_LEN) {
      return false;
    }
    if (msg.type !== 'SCAN_SINGLE') {
      return false;
    }
    const payload = msg.payload != null ? String(msg.payload) : '';
    if (payload.length > MAX_SCAN_PAYLOAD_LEN) {
      return false;
    }
    return true;
  }

  function isValidBatchScanMessage(msg) {
    if (!isPlainObject(msg)) {
      return false;
    }
    if (typeof msg.type !== 'string' || msg.type.length > MAX_MESSAGE_TYPE_LEN) {
      return false;
    }
    if (msg.type !== 'SCAN_BATCH') {
      return false;
    }
    if (!Array.isArray(msg.lines)) {
      return false;
    }
    if (msg.lines.length > MAX_BATCH_LINES) {
      return false;
    }
    for (let i = 0; i < msg.lines.length; i++) {
      if (String(msg.lines[i] || '').length > MAX_BATCH_LINE_LEN) {
        return false;
      }
    }
    return true;
  }

  global.VtBackgroundGuards = {
    getSenderContext: getSenderContext,
    isTrustedRuntimeSender: isTrustedRuntimeSender,
    isTrustedExtensionPageSender: isTrustedExtensionPageSender,
    isTrustedContentSender: isTrustedContentSender,
    isMessageAllowedForSender: isMessageAllowedForSender,
    canConnectPort: canConnectPort,
    checkContentScanRateLimit: checkContentScanRateLimit,
    isKnownPortName: isKnownPortName,
    isValidSingleScanMessage: isValidSingleScanMessage,
    isValidBatchScanMessage: isValidBatchScanMessage
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
