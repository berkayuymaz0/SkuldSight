'use strict';

(function (global) {
  const ALLOWED_PORTS = new Set(['vt-single', 'vt-batch']);
  const MAX_MESSAGE_TYPE_LEN = 64;
  const MAX_SCAN_PAYLOAD_LEN = 4096;
  const MAX_BATCH_LINES = 250;
  const MAX_BATCH_LINE_LEN = 4096;

  function isPlainObject(value) {
    if (!value || typeof value !== 'object') {
      return false;
    }
    const proto = Object.getPrototypeOf(value);
    return proto === Object.prototype || proto === null;
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

  function isKnownPortName(name) {
    return ALLOWED_PORTS.has(String(name || ''));
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
    isTrustedRuntimeSender: isTrustedRuntimeSender,
    isKnownPortName: isKnownPortName,
    isValidSingleScanMessage: isValidSingleScanMessage,
    isValidBatchScanMessage: isValidBatchScanMessage
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
