'use strict';

(function (global) {
  const ALLOWED_PORTS = new Set(['vt-single', 'vt-batch']);

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
    return !!msg && msg.type === 'SCAN_SINGLE';
  }

  function isValidBatchScanMessage(msg) {
    return !!msg && msg.type === 'SCAN_BATCH' && Array.isArray(msg.lines);
  }

  global.VtBackgroundGuards = {
    isTrustedRuntimeSender: isTrustedRuntimeSender,
    isKnownPortName: isKnownPortName,
    isValidSingleScanMessage: isValidSingleScanMessage,
    isValidBatchScanMessage: isValidBatchScanMessage
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
