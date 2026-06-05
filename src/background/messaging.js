'use strict';

// runScanPrepared: Tarama kuyruğu, geçmiş veya toplu özet depolama.
async function runScanPrepared(prepared, source, scanOpts) {
  scanOpts = scanOpts || {};
  const detected = detectIoc(prepared);
  if (detected.kind === 'unknown') {
    const errPayload = {
      ok: false,
      error: 'Could not classify IoC. Enter a valid IP, domain, URL, or file hash.'
    };
    if (isExternalScanPersistSource(source)) {
      await persistContextScanResult(errPayload, prepared);
    }
    if (isContextMenuScanSource(source)) {
      await notifyContextMenuScanOutcome(errPayload);
    }
    return errPayload;
  }

  const queueAhead = jobQueue.length + (jobInFlight ? 1 : 0);
  const payload = await enqueueJob(function () {
    return scanIoc(detected, scanOpts);
  });

  if (payload.ok && source !== 'batch' && scanOpts.skipRecent !== true && scanOpts.skipAnalytics !== true) {
    await persistSingleScanSuccess(payload);
  } else if (payload.ok && scanOpts.skipAnalytics !== true) {
    await recordScanStat(analyticsEntryFromPayload(payload));
  }

  if (isExternalScanPersistSource(source)) {
    await persistContextScanResult(payload, detected.value);
  }
  if (isContextMenuScanSource(source)) {
    await notifyContextMenuScanOutcome(payload);
  }

  return Object.assign({ queued: queueAhead > 0, queueAhead: queueAhead }, payload);
}

// handleScanInput: Tarama kuyruğu, geçmiş veya toplu özet depolama.
async function handleScanInput(raw, source, opts) {
  opts = opts || {};
  const prepared = opts.stripNoise
    ? normalizeIocInput(raw)
    : String(raw || '').trim();
  return runScanPrepared(prepared, source, opts);
}

// ensureContextMenu: Uzantı olayları veya mesaj/port köprüsü.
function ensureContextMenu() {
  chrome.contextMenus.removeAll(function () {
    chrome.contextMenus.create({
      id: 'vt-check-ioc',
      title: 'Scan selection with ' + APP_NAME,
      contexts: ['selection']
    });
  });
}

chrome.runtime.onInstalled.addListener(function (details) {
  ensureContextMenu();
  ensureNewsAutoRefreshAlarm();
  ensureUsomAutoRefreshAlarm();
  chrome.storage.local.get(UI_MODE_KEY, function (data) {
    if (!data[UI_MODE_KEY]) {
      chrome.storage.local.set({ [UI_MODE_KEY]: 'popup' }, function () {
        refreshUiModeFromStorage().catch(function () {});
      });
      return;
    }
    refreshUiModeFromStorage().catch(function () {});
  });
});
chrome.runtime.onStartup.addListener(function () {
  ensureContextMenu();
  ensureNewsAutoRefreshAlarm();
  ensureUsomAutoRefreshAlarm();
  refreshUiModeFromStorage().catch(function () {});
});

chrome.alarms.onAlarm.addListener(function (alarm) {
  if (!alarm) {
    return;
  }
  if (alarm.name === NEWS_AUTO_REFRESH_ALARM) {
    refreshNewsWithOptionalNotification(true).catch(function () {});
    return;
  }
  if (alarm.name === USOM_AUTO_REFRESH_ALARM) {
    refreshUsomWithOptionalNotification(true).catch(function () {});
  }
});

ensureNewsAutoRefreshAlarm();
ensureUsomAutoRefreshAlarm();

chrome.contextMenus.onClicked.addListener(function (info) {
  const text = (info.selectionText || '').trim();
  if (!text) {
    return;
  }
  handleScanInput(text, 'context').catch(function (err) {
    const msg = err && err.message ? err.message : 'Scan failed';
    const errPayload = {
      ok: false,
      error: msg,
      errorKey: err && err.errorKey ? err.errorKey : '',
      errorVars: err && err.errorVars ? err.errorVars : {}
    };
    persistContextScanResult(errPayload, text)
      .then(function () {
        return notifyContextMenuScanOutcome(errPayload);
      })
      .catch(function () {});
  });
});

chrome.runtime.onConnect.addListener(function (port) {
  if (!port || !guards.isKnownPortName(port.name) || !guards.isTrustedRuntimeSender(port.sender)) {
    try {
      port.disconnect();
    } catch (_) {}
    return;
  }
  if (port.name === 'vt-single') {
    port.onMessage.addListener(function (msg) {
      if (!guards.isValidSingleScanMessage(msg)) {
        try {
          port.postMessage({
            type: 'SCAN_RESULT',
            result: {
              ok: false,
              error: 'invalid_message',
              errorKey: 'errorInvalidScanMessage'
            }
          });
        } catch (_) {}
        return;
      }
      const src = msg.source === 'content' ? 'content' : 'popup';
      handleScanInput(msg.payload || '', src, {
        stripNoise: !!msg.stripNoise
      })
        .then(function (result) {
          try {
            port.postMessage({ type: 'SCAN_RESULT', result: result });
          } catch (_) {}
        })
        .catch(function (err) {
          try {
            port.postMessage({
              type: 'SCAN_RESULT',
              result: {
                ok: false,
                error: err && err.message ? err.message : 'Scan failed',
                errorKey: err && err.errorKey ? err.errorKey : '',
                errorVars: err && err.errorVars ? err.errorVars : {}
              }
            });
          } catch (_) {}
        });
    });
    return;
  }
  port.onMessage.addListener(function (msg) {
    if (!guards.isValidBatchScanMessage(msg)) {
      try {
        port.postMessage({
          type: 'BATCH_ERROR',
          error: 'invalid_message',
          errorKey: 'errorInvalidScanMessage'
        });
      } catch (_) {}
      return;
    }
    const lines = Array.isArray(msg.lines) ? msg.lines : [];
    const strip = !!msg.stripNoise;
    const includeAbuse = msg.includeAbuse !== false;
    const total = lines.length;
    let disconnected = false;
    port.onDisconnect.addListener(function () {
      disconnected = true;
    });
    (async function () {
      const analyticsEntries = [];
      for (let i = 0; i < lines.length; i++) {
        if (disconnected) {
          break;
        }
        const line = lines[i];
        const prepared = strip ? normalizeIocInput(line) : String(line || '').trim();
        if (!prepared) {
          port.postMessage({
            type: 'BATCH_LINE',
            index: i,
            total: total,
            status: 'empty',
            raw: String(line || '')
          });
          continue;
        }
        try {
          const result = await runScanPrepared(prepared, 'batch', {
            skipExtras: true,
            skipRecent: true,
            skipAnalytics: true,
            includeAbuse: includeAbuse
          });
          if (result && result.ok) {
            analyticsEntries.push(analyticsEntryFromPayload(result));
          }
          port.postMessage(
            Object.assign(
              {
                type: 'BATCH_LINE',
                index: i,
                total: total,
                line: prepared
              },
              result
            )
          );
        } catch (err) {
          port.postMessage({
            type: 'BATCH_LINE',
            index: i,
            total: total,
            line: prepared,
            ok: false,
            error: err && err.message ? err.message : 'Scan failed'
          });
        }
      }
      if (disconnected) {
        return;
      }
      await recordScanStatsMany(analyticsEntries);
      port.postMessage({ type: 'BATCH_DONE' });
    })().catch(function (err) {
      try {
        port.postMessage({
          type: 'BATCH_ERROR',
          error: err && err.message ? err.message : 'Batch failed'
        });
      } catch (_) {}
    });
  });
});

// respondAsync: Uzantı olayları veya mesaj/port köprüsü.
function respondAsync(sendResponse, promise, fallbackMessage, errorFactory) {
  Promise.resolve(promise)
    .then(function (payload) {
      sendResponse(payload);
    })
    .catch(function (err) {
      if (typeof errorFactory === 'function') {
        sendResponse(errorFactory(err));
        return;
      }
      sendResponse({
        ok: false,
        error: err && err.message ? String(err.message) : fallbackMessage
      });
    });
  return true;
}

const backgroundMessageHandlers = {
  GET_NEWS: function (_message, sendResponse) {
    return respondAsync(sendResponse, getNewsPayload(false), 'Failed to load news');
  },
  REFRESH_NEWS: function (message, sendResponse) {
    return respondAsync(
      sendResponse,
      refreshNewsWithOptionalNotification(message.autoRefresh === true),
      'Failed to refresh news'
    );
  },
  GET_USOM: function (_message, sendResponse) {
    return respondAsync(sendResponse, getUsomPayload(false), 'Failed to load USOM feed');
  },
  REFRESH_USOM: function (message, sendResponse) {
    return respondAsync(
      sendResponse,
      refreshUsomWithOptionalNotification(message.autoRefresh === true),
      'Failed to refresh USOM feed'
    );
  },
  GET_USOM_DETAIL: function (message, sendResponse) {
    return respondAsync(sendResponse, fetchUsomDetail(message), 'Failed to load USOM detail');
  },
  GET_QUEUE: function (_message, sendResponse) {
    const pending = jobQueue.length + (jobInFlight ? 1 : 0);
    sendResponse({ pending: pending });
  },
  GET_RECENT_HISTORY: function (_message, sendResponse) {
    chrome.storage.local.get(['vtRecentHistory'], function (data) {
      const list = Array.isArray(data.vtRecentHistory) ? data.vtRecentHistory : [];
      sendResponse({ entries: list });
    });
    return true;
  },
  VT_REANALYZE: function (message, sendResponse) {
    return respondAsync(sendResponse, requestVtReanalysis(message), 'Reanalyze request failed', function (err) {
      return {
        ok: false,
        errorKey: (err && err.errorKey) || 'errorVtReanalyzeFailed',
        error: err && err.message ? String(err.message) : 'Reanalyze request failed',
        errorVars: (err && err.errorVars) || {}
      };
    });
  },
  GET_VT_QUOTAS: function (message, sendResponse) {
    const override = message && message.apiKey != null ? String(message.apiKey) : '';
    return respondAsync(sendResponse, fetchVtQuotas(override), 'Failed to load VT quotas');
  },
  ENRICH_ABUSE_FOR_IP: function (message, sendResponse) {
    const ip = message && message.ip ? String(message.ip).trim() : '';
    if (!ip) {
      sendResponse({ ok: false, error: 'missing_ip' });
      return false;
    }
    return respondAsync(
      sendResponse,
      enrichAbuseForIp(ip).then(function (abuse) {
        return { ok: true, abuseipdb: abuse || { ok: false } };
      }),
      'AbuseIPDB enrich failed'
    );
  },
  GET_BATCH_HISTORY: function (_message, sendResponse) {
    chrome.storage.local.get(['vtBatchHistory'], function (data) {
      const list = Array.isArray(data.vtBatchHistory) ? data.vtBatchHistory : [];
      sendResponse({ entries: list });
    });
    return true;
  },
  SAVE_BATCH_HISTORY: function (message, sendResponse) {
    return respondAsync(
      sendResponse,
      appendBatchHistoryAndRecent(message.summary).then(function () {
        return { ok: true };
      }),
      'Failed to save batch history'
    );
  },
  CLEAR_HISTORY_SECTION: function (message, sendResponse) {
    const section = message.section === 'batch' ? 'batch' : 'general';
    if (section === 'batch') {
      chrome.storage.local.get(['vtRecentHistory'], function (data) {
        const list = Array.isArray(data.vtRecentHistory) ? data.vtRecentHistory : [];
        const filtered = list.filter(function (entry) {
          return !(entry && entry.type === 'batch-summary');
        });
        chrome.storage.local.set({ vtBatchHistory: [], vtRecentHistory: filtered }, function () {
          sendResponse({ ok: true });
        });
      });
      return true;
    }
    chrome.storage.local.set({ vtRecentHistory: [] }, function () {
      sendResponse({ ok: true });
    });
    return true;
  },
  TEST_VT_CONNECTION: function (message, sendResponse) {
    const override = message.apiKey != null ? String(message.apiKey) : '';
    return respondAsync(
      sendResponse,
      testVtApiConnection(override),
      'Test failed',
      function (err) {
        return {
          ok: false,
          error: 'exception',
          detail: err && err.message ? String(err.message) : 'Test failed'
        };
      }
    );
  },
  TEST_ABUSE_CONNECTION: function (message, sendResponse) {
    const override = message.apiKey != null ? String(message.apiKey) : '';
    return respondAsync(
      sendResponse,
      testAbuseApiConnection(override),
      'Test failed',
      function (err) {
        return {
          ok: false,
          error: 'exception',
          detail: err && err.message ? String(err.message) : 'Test failed'
        };
      }
    );
  },
  APPLY_UI_MODE: function (message, sendResponse) {
    const mode = message.mode === 'sidepanel' ? 'sidepanel' : 'popup';
    return respondAsync(
      sendResponse,
      applyUiMode(mode).then(function () {
        return { ok: true, mode: mode };
      }),
      'Failed to apply UI mode'
    );
  }
};

chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
  if (!guards.isTrustedRuntimeSender(sender)) {
    sendResponse({ ok: false, error: 'unauthorized_sender' });
    return false;
  }
  if (!message || !message.type) {
    return;
  }
  const handler = backgroundMessageHandlers[message.type];
  if (!handler) {
    sendResponse({ ok: false, error: 'unknown_message_type' });
    return false;
  }
  return handler(message, sendResponse);
});
