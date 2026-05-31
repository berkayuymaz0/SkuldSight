'use strict';

function applySettingsSnapshot(data) {
  const src = data || {};
  rateIntervalMs = clampRateSec(src.vtRateIntervalSec) * 1000;
  proModeEnabled = src.vtProMode === true;
  notifyQueuedEnabled = src.vtNotifyQueued !== false;
  notifyNewsEnabled = src.vtNotifyNews !== false;
  notifyContextEnabled = src.vtNotifyContext !== false;
}

// refreshSettingsFromStorage: chrome.storage'dan ayarları okuyup bellekteki kopyayı yeniler.
async function refreshSettingsFromStorage() {
  const data = await chrome.storage.local.get([
    'vtRateIntervalSec',
    'vtProMode',
    'vtNotifyQueued',
    'vtNotifyNews',
    'vtNotifyContext',
    UI_MODE_KEY
  ]);
  applySettingsSnapshot(data);
  currentUiMode = data[UI_MODE_KEY] === 'sidepanel' ? 'sidepanel' : 'popup';
}

// applySettingChanges: Kısmi ayar değişikliklerini uygular ve ilgili yan etkileri tetikler.
function applySettingChanges(changes) {
  if (changes.vtRateIntervalSec) {
    rateIntervalMs = clampRateSec(changes.vtRateIntervalSec.newValue) * 1000;
  }
  if (changes.vtProMode) {
    proModeEnabled = changes.vtProMode.newValue === true;
  }
  if (changes.vtNotifyQueued) {
    notifyQueuedEnabled = changes.vtNotifyQueued.newValue !== false;
  }
  if (changes.vtNotifyNews) {
    notifyNewsEnabled = changes.vtNotifyNews.newValue !== false;
  }
  if (changes.vtNotifyContext) {
    notifyContextEnabled = changes.vtNotifyContext.newValue !== false;
  }
}

const UI_MODE_KEY = SK.uiMode;
/** Latest external scan (context menu or VT badge) for popup/side panel on open (see popup.js). */
const CONTEXT_SCAN_RESULT_KEY = SK.contextScanResult;
const POPUP_PATH = 'src/popup/popup.html';
const PANEL_PATH = 'src/popup/popup.html?surface=sidepanel';
/** In-memory UI mode mirror for notification gating without extra storage reads. */
let currentUiMode = 'popup';

// closeGlobalSidePanel: Popup moduna geçerken açık global yan paneli kapatır.
async function closeGlobalSidePanel() {
  if (!chrome.sidePanel || typeof chrome.sidePanel.close !== 'function') {
    return;
  }
  try {
    const win = await chrome.windows.getLastFocused();
    if (win && win.id != null) {
      await chrome.sidePanel.close({ windowId: win.id });
    }
  } catch (_) {}
}

// isExternalScanPersistSource: Sonucu popup/yan panelde göstermek için saklanır.
function isExternalScanPersistSource(source) {
  return source === 'context' || source === 'content';
}

// isContextMenuScanSource: Yalnızca sağ tık menüsü taraması (bildirim için).
function isContextMenuScanSource(source) {
  return source === 'context';
}

// applyUiMode: Toolbar tıklamasında popup veya yan panel açılmasını yapılandırır.
async function applyUiMode(mode) {
  currentUiMode = mode === 'sidepanel' ? 'sidepanel' : 'popup';
  const isPanel = mode === 'sidepanel';
  if (!chrome.sidePanel) {
    try {
      await chrome.action.setPopup({ popup: POPUP_PATH });
    } catch (_) {}
    return;
  }
  try {
    if (isPanel) {
      await chrome.action.setPopup({ popup: '' });
      await chrome.sidePanel.setOptions({ path: PANEL_PATH, enabled: true });
      await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true });
    } else {
      await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false });
      await chrome.action.setPopup({ popup: POPUP_PATH });
      await closeGlobalSidePanel();
    }
  } catch (_) {
    try {
      await chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false });
    } catch (_e) {}
    try {
      await chrome.action.setPopup({ popup: POPUP_PATH });
    } catch (_e2) {}
  }
}

// refreshUiModeFromStorage: Kayıtlı vtUiMode değerine göre arayüz modunu uygular.
async function refreshUiModeFromStorage() {
  const data = await chrome.storage.local.get(UI_MODE_KEY);
  const mode = data[UI_MODE_KEY] === 'sidepanel' ? 'sidepanel' : 'popup';
  currentUiMode = mode;
  await applyUiMode(mode);
}

// shouldNotifyContextMenuScan: Sağ tık bildirimi yalnızca popup modunda (storage okunur).
async function shouldNotifyContextMenuScan() {
  const data = await chrome.storage.local.get(['vtNotifyContext', UI_MODE_KEY]);
  notifyContextEnabled = data.vtNotifyContext !== false;
  currentUiMode = data[UI_MODE_KEY] === 'sidepanel' ? 'sidepanel' : 'popup';
  return notifyContextEnabled && currentUiMode === 'popup';
}

// notifyContextMenuScanOutcome: Popup modunda sağ tık tarama sonuç bildirimi.
async function notifyContextMenuScanOutcome(payload) {
  if (!(await shouldNotifyContextMenuScan())) {
    return;
  }
  if (payload && payload.ok) {
    const s = payload.stats || {};
    showNotification(
      'context',
      APP_NAME + ' — ' + (payload.iocKind || 'IoC'),
      'Malicious: ' +
        (Number(s.malicious) || 0) +
        ', Suspicious: ' +
        (Number(s.suspicious) || 0) +
        ', Undetected: ' +
        (Number(s.undetected) || 0)
    );
    return;
  }
  showNotification(
    'context',
    APP_NAME,
    payload && payload.error ? String(payload.error) : 'Scan failed'
  );
}

// persistContextScanResult: Sağ tık tarama sonucunu popup/yan panel için saklar.
async function persistContextScanResult(payload, rawIoc) {
  const row = {
    ioc: rawIoc != null ? String(rawIoc).trim().slice(0, 2000) : '',
    ts: Date.now(),
    payload:
      payload && payload.ok
        ? trimPayloadForHistory(payload)
        : payload && typeof payload === 'object'
          ? {
              ok: false,
              error: payload.error
                ? String(payload.error).slice(0, 500)
                : 'Scan failed'
            }
          : { ok: false, error: 'Scan failed' }
  };
  if (!row.ioc && row.payload && row.payload.ioc) {
    row.ioc = String(row.payload.ioc);
  }
  await chrome.storage.local.set({ [CONTEXT_SCAN_RESULT_KEY]: row });
}

chrome.storage.onChanged.addListener(function (changes, area) {
  if (area !== 'local') {
    return;
  }
  applySettingChanges(changes);
  if (changes[UI_MODE_KEY]) {
    const mode = changes[UI_MODE_KEY].newValue === 'sidepanel' ? 'sidepanel' : 'popup';
    currentUiMode = mode;
    applyUiMode(mode).catch(function () {});
  }
});

refreshSettingsFromStorage().catch(function () {});
refreshUiModeFromStorage().catch(function () {});

// sleep: Belirtilen süre için Promise ile bekler (alarm/geri deneme için).
