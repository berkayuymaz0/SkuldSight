(function (NS) {
  const utils = NS.utils;
  const dom = NS.dom;
  const state = NS.state;
  const presetInputs = NS.presetInputs;
  const SCAN_PRESETS_KEY = NS.SCAN_PRESETS_KEY;
  const COPY_SUMMARY_FIELDS_KEY = NS.COPY_SUMMARY_FIELDS_KEY;
  const ANALYTICS_KEY = NS.ANALYTICS_KEY;
  const OPTIONS_DASHBOARD_KEYS = NS.OPTIONS_DASHBOARD_KEYS;
  const t = NS.t;
  const showToast = NS.showToast;
  const chromeErrorMessage = NS.chromeErrorMessage;
  const setButtonBusy = NS.setButtonBusy;
  const applyOptionsLang = NS.applyOptionsLang;
  const applyOptionsTheme = NS.applyOptionsTheme;
  const bindUiModePicker = NS.bindUiModePicker;
  const syncUiModeInputs = NS.syncUiModeInputs;
  const updateRateLabel = NS.updateRateLabel;
  const syncRateControlState = NS.syncRateControlState;
  const clampRateSec = NS.clampRateSec;
  const isApiKeyExpired = NS.isApiKeyExpired;
  const setCopySummaryFieldsToForm = NS.setCopySummaryFieldsToForm;
  const readCopySummaryFieldsFromForm = NS.readCopySummaryFieldsFromForm;
  const normalizeCopySummaryFields = NS.normalizeCopySummaryFields;
  const defaultCopySummaryFields = NS.defaultCopySummaryFields;
  const applyCopySummaryPreset = NS.applyCopySummaryPreset;
  const renderPresetInputs = NS.renderPresetInputs;
  const renderPresetMatrix = NS.renderPresetMatrix;
  const resetScanPresetsToDefaults = NS.resetScanPresetsToDefaults;
  const readPresetInputs = NS.readPresetInputs;
  const renderAnalytics = NS.renderAnalytics;
  const refreshAnalytics = NS.refreshAnalytics;

  // Analitik yenilemeyi requestAnimationFrame ile tek karede birleştirir (gereksiz tekrarları önler).
  function scheduleAnalyticsRefresh(force) {
    if (state.analyticsQueued && force !== true) {
      return;
    }
    state.analyticsQueued = true;
    if (state.analyticsRafId) {
      window.cancelAnimationFrame(state.analyticsRafId);
      state.analyticsRafId = 0;
    }
    state.analyticsRafId = window.requestAnimationFrame(function () {
      state.analyticsRafId = 0;
      state.analyticsQueued = false;
      refreshAnalytics(force === true);
    });
  }

  dom.rateSlider.addEventListener('input', updateRateLabel);
  bindUiModePicker();

  chrome.storage.local.get(
    [
      'vtApiKey',
      'vtApiKeySavedAt',
      'vtUiLang',
      'vtRateIntervalSec',
      'vtUiMode',
      'vtProMode',
      'vtBatchUseAbuse',
      'vtNotifyQueued',
      'vtNotifyNews',
      'vtNotifyContext',
      'vtContentIocBadges',
      'vtDomainBadgeBlacklist',
      'vtPopupTheme',
      'abuseipdbApiKey',
      'abuseipdbApiKeySavedAt',
      SCAN_PRESETS_KEY,
      COPY_SUMMARY_FIELDS_KEY
    ].concat(OPTIONS_DASHBOARD_KEYS),
    function (data) {
      if (chrome.runtime.lastError) {
        return;
      }
      const lang = data.vtUiLang === 'tr' ? 'tr' : 'en';
      VT_I18N.setLang(lang);
      if (dom.uiLang) {
        dom.uiLang.value = lang;
      }
      applyOptionsTheme(data.vtPopupTheme === 'light' ? 'light' : 'dark');
      applyOptionsLang();

      if (data.vtApiKey && !isApiKeyExpired(data.vtApiKeySavedAt)) {
        dom.apiKey.value = data.vtApiKey;
      } else if (data.vtApiKey && isApiKeyExpired(data.vtApiKeySavedAt)) {
        chrome.storage.local.set({ vtApiKey: '', vtApiKeySavedAt: 0 });
      }
      if (dom.abuseApiKey) {
        if (data.abuseipdbApiKey && !isApiKeyExpired(data.abuseipdbApiKeySavedAt)) {
          dom.abuseApiKey.value = data.abuseipdbApiKey;
        } else if (data.abuseipdbApiKey && isApiKeyExpired(data.abuseipdbApiKeySavedAt)) {
          chrome.storage.local.set({ abuseipdbApiKey: '', abuseipdbApiKeySavedAt: 0 });
        }
      }

      const sec = clampRateSec(data.vtRateIntervalSec);
      dom.rateSlider.value = String(sec);
      syncUiModeInputs(data.vtUiMode === 'sidepanel' ? 'sidepanel' : 'popup');
      dom.proMode.checked = data.vtProMode === true;
      if (dom.batchUseAbuse) {
        dom.batchUseAbuse.checked = data.vtBatchUseAbuse !== false;
      }
      dom.notifyQueued.checked = data.vtNotifyQueued !== false;
      dom.notifyNews.checked = data.vtNotifyNews !== false;
      dom.notifyContext.checked = data.vtNotifyContext !== false;
      if (dom.contentIocBadges) {
        dom.contentIocBadges.checked = data.vtContentIocBadges !== false;
      }
      if (dom.blacklist) {
        dom.blacklist.value = String(data.vtDomainBadgeBlacklist || '');
      }
      setCopySummaryFieldsToForm(data[COPY_SUMMARY_FIELDS_KEY]);
      renderPresetInputs(utils.migrateScanPresetsStorage(data[SCAN_PRESETS_KEY]));
      syncRateControlState();
      updateRateLabel();
      state.lastAnalyticsSnapshot = {
        analytics: data[ANALYTICS_KEY],
        batches: data.vtBatchHistory
      };
      renderAnalytics(data[ANALYTICS_KEY], data.vtBatchHistory, true);
    }
  );

  if (dom.uiLang) {
    dom.uiLang.addEventListener('change', function () {
      const lang = dom.uiLang.value === 'tr' ? 'tr' : 'en';
      chrome.storage.local.set({ vtUiLang: lang }, function () {
        if (chrome.runtime.lastError) {
          showToast(chromeErrorMessage('Language save failed'));
          return;
        }
        VT_I18N.setLang(lang);
        applyOptionsLang();
        scheduleAnalyticsRefresh(true);
        showToast(t('toastSaved'));
      });
    });
  }

  dom.keyForm.addEventListener('submit', function (e) {
    e.preventDefault();
    const key = (dom.apiKey.value || '').trim();
    const submitBtn = dom.keyForm.querySelector('button[type="submit"]');
    setButtonBusy(submitBtn, true);
    chrome.storage.local.set({
      vtApiKey: key,
      vtApiKeySavedAt: key ? Date.now() : 0
    }, function () {
      setButtonBusy(submitBtn, false);
      if (chrome.runtime.lastError) {
        showToast(chromeErrorMessage('API key save failed'));
        return;
      }
      showToast(t('toastApiSaved'));
    });
  });

  if (dom.abuseKeyForm) {
    dom.abuseKeyForm.addEventListener('submit', function (e) {
      e.preventDefault();
      const key = (dom.abuseApiKey.value || '').trim();
      const submitBtn = dom.abuseKeyForm.querySelector('button[type="submit"]');
      setButtonBusy(submitBtn, true);
      chrome.storage.local.set({
        abuseipdbApiKey: key,
        abuseipdbApiKeySavedAt: key ? Date.now() : 0
      }, function () {
        setButtonBusy(submitBtn, false);
        if (chrome.runtime.lastError) {
          showToast(chromeErrorMessage('AbuseIPDB key save failed'));
          return;
        }
        showToast(t('toastAbuseApiSaved'));
      });
    });
  }

  if (dom.btnTestAbuseApi) {
    dom.btnTestAbuseApi.addEventListener('click', function () {
      const key = (dom.abuseApiKey && dom.abuseApiKey.value) || '';
      setButtonBusy(dom.btnTestAbuseApi, true);
      chrome.runtime.sendMessage(
        { type: 'TEST_ABUSE_CONNECTION', apiKey: String(key).trim() },
        function (res) {
          setButtonBusy(dom.btnTestAbuseApi, false);
          if (chrome.runtime.lastError) {
            showToast(t('toastAbuseTestFail') + ': ' + chrome.runtime.lastError.message);
            return;
          }
          if (!res || !res.ok) {
            const detail = res && res.detail ? ': ' + res.detail : '';
            showToast(t('toastAbuseTestFail') + detail);
            return;
          }
          showToast(t('toastAbuseTestOk'));
        }
      );
    });
  }

  if (dom.btnTestApi) {
    dom.btnTestApi.addEventListener('click', function () {
      const key = (dom.apiKey.value || '').trim();
      setButtonBusy(dom.btnTestApi, true);
      chrome.runtime.sendMessage(
        { type: 'TEST_VT_CONNECTION', apiKey: key },
        function (res) {
          setButtonBusy(dom.btnTestApi, false);
          if (chrome.runtime.lastError) {
            showToast(t('toastTestFail') + ': ' + chrome.runtime.lastError.message);
            return;
          }
          if (!res) {
            showToast(t('toastTestFail'));
            return;
          }
          if (res.ok) {
            let okMsg = t('toastTestOk');
            if (res.username) {
              okMsg += ': ' + res.username;
            }
            chrome.runtime.sendMessage({ type: 'GET_VT_QUOTAS', apiKey: key }, function (q) {
              if (q && q.ok && q.daily && q.daily.allowed > 0) {
                okMsg +=
                  ' · ' +
                  t('vtQuotaDaily', {
                    remaining: q.daily.remaining,
                    allowed: q.daily.allowed
                  });
              }
              showToast(okMsg);
            });
            return;
          }
          const code = res.error || '';
          if (code === 'no_api_key') {
            showToast(t('optTestErrNoKey'));
          } else if (code === 'unauthorized') {
            showToast(t('optTestErrUnauthorized'));
          } else if (res.detail) {
            showToast(t('toastTestFail') + ': ' + String(res.detail).slice(0, 140));
          } else {
            showToast(t('toastTestFail'));
          }
        }
      );
    });
  }

  dom.behaviorForm.addEventListener('submit', function (e) {
    e.preventDefault();
    const sec = clampRateSec(dom.rateSlider.value);
    const submitBtn = dom.behaviorForm.querySelector('button[type="submit"]');
    setButtonBusy(submitBtn, true);
    chrome.storage.local.set(
      {
        vtRateIntervalSec: sec,
        vtProMode: !!dom.proMode.checked,
        vtBatchUseAbuse: dom.batchUseAbuse ? !!dom.batchUseAbuse.checked : true,
        vtNotifyQueued: !!dom.notifyQueued.checked,
        vtNotifyNews: !!dom.notifyNews.checked,
        vtNotifyContext: !!dom.notifyContext.checked,
        vtContentIocBadges: dom.contentIocBadges ? !!dom.contentIocBadges.checked : true
      },
      function () {
        setButtonBusy(submitBtn, false);
        if (chrome.runtime.lastError) {
          showToast(chromeErrorMessage('Behavior save failed'));
          return;
        }
        showToast(t('toastBehaviorSaved'));
      }
    );
  });

  if (dom.blacklistForm) {
    dom.blacklistForm.addEventListener('submit', function (e) {
      e.preventDefault();
      const submitBtn = dom.blacklistForm.querySelector('button[type="submit"]');
      setButtonBusy(submitBtn, true);
      chrome.storage.local.set(
        {
          vtDomainBadgeBlacklist: dom.blacklist
            ? String(dom.blacklist.value || '').trim()
            : ''
        },
        function () {
          setButtonBusy(submitBtn, false);
          if (chrome.runtime.lastError) {
            showToast(chromeErrorMessage('Blacklist save failed'));
            return;
          }
          showToast(t('toastBlacklistSaved'));
        }
      );
    });
  }

  if (dom.copySummaryForm) {
    dom.copySummaryForm.addEventListener('submit', function (e) {
      e.preventDefault();
      const submitBtn = dom.copySummaryForm.querySelector('button[type="submit"]');
      const nextConfig = normalizeCopySummaryFields(readCopySummaryFieldsFromForm());
      setButtonBusy(submitBtn, true);
      chrome.storage.local.set(
        {
          [COPY_SUMMARY_FIELDS_KEY]: nextConfig
        },
        function () {
          setButtonBusy(submitBtn, false);
          if (chrome.runtime.lastError) {
            showToast(chromeErrorMessage('Copy summary fields save failed'));
            return;
          }
          setCopySummaryFieldsToForm(nextConfig);
          showToast(t('toastSaved'));
        }
      );
    });
  }

  if (dom.btnCopySummaryTemplateReset) {
    dom.btnCopySummaryTemplateReset.addEventListener('click', function () {
      setCopySummaryFieldsToForm(defaultCopySummaryFields());
    });
  }
  if (dom.btnCopyPresetMinimal) {
    dom.btnCopyPresetMinimal.addEventListener('click', function () {
      applyCopySummaryPreset('minimal');
    });
  }
  if (dom.btnCopyPresetAnalyst) {
    dom.btnCopyPresetAnalyst.addEventListener('click', function () {
      applyCopySummaryPreset('analyst');
    });
  }
  if (dom.btnCopyPresetFull) {
    dom.btnCopyPresetFull.addEventListener('click', function () {
      applyCopySummaryPreset('full');
    });
  }
  if (dom.copyMatrixToggles && dom.copyMatrixToggles.length) {
    dom.copyMatrixToggles.forEach(function (btn) {
      btn.addEventListener('click', function () {
        const isOn = btn.getAttribute('aria-pressed') === 'true';
        btn.setAttribute('aria-pressed', isOn ? 'false' : 'true');
        btn.classList.toggle('is-on', !isOn);
      });
    });
  }

  if (dom.btnResetScanPresets) {
    dom.btnResetScanPresets.addEventListener('click', function () {
      resetScanPresetsToDefaults();
    });
  }

  // Form girdilerinden ilgili preset'in salt okunur özet matrisini canlı günceller.
  function refreshPresetMatrixFromForm(name) {
    if (!renderPresetMatrix) {
      return;
    }
    const map = utils.normalizeScanPresetsMap(readPresetInputs());
    renderPresetMatrix(name, map[name]);
  }

  // Bir preset satırındaki tüm girdileri matris tazelemesine bağlar.
  function bindPresetMatrixLiveUpdate() {
    ['quick', 'detailed', 'analyst'].forEach(function (name) {
      const row = presetInputs[name];
      if (!row) {
        return;
      }
      ['rel', 'relSec', 'engine', 'mitre', 'abuseReports', 'abuseWindow', 'abuseOverall'].forEach(
        function (field) {
          const el = row[field];
          if (el && el.addEventListener) {
            el.addEventListener('change', function () {
              refreshPresetMatrixFromForm(name);
            });
          }
        }
      );
    });
  }
  bindPresetMatrixLiveUpdate();

  function bindAbusePresetListeners() {
    ['quick', 'detailed', 'analyst'].forEach(function (name) {
      const row = presetInputs[name];
      if (!row || !row.abuseReports) {
        return;
      }
      row.abuseReports.addEventListener('change', function () {
        if (row.abuseWindow) {
          row.abuseWindow.disabled = !row.abuseReports.checked;
        }
      });
    });
  }
  bindAbusePresetListeners();

  if (dom.presetsForm) {
    dom.presetsForm.addEventListener('submit', function (e) {
      e.preventDefault();
      const map = utils.normalizeScanPresetsMap(readPresetInputs());
      const submitBtn = dom.presetsForm.querySelector('button[type="submit"]');
      setButtonBusy(submitBtn, true);
      chrome.storage.local.set(
        { [SCAN_PRESETS_KEY]: utils.storagePayloadFromPresets(map) },
        function () {
          setButtonBusy(submitBtn, false);
          if (chrome.runtime.lastError) {
            showToast(chromeErrorMessage('Preset save failed'));
            return;
          }
          showToast(t('toastScanPresetsSaved'));
        }
      );
    });
  }

  // İlişki birincil kutusu kapalıyken ikincil pivot kutusunu devre dışı bırakır.
  function wirePresetRelDependencies() {
    ['quick', 'detailed', 'analyst'].forEach(function (name) {
      const row = presetInputs[name];
      if (!row || !row.rel || !row.relSec) {
        return;
      }
      row.rel.addEventListener('change', function () {
        if (!row.rel.checked) {
          row.relSec.checked = false;
        }
        row.relSec.disabled = !row.rel.checked;
      });
    });
  }
  wirePresetRelDependencies();

  if (dom.btnClearHistory) {
    dom.btnClearHistory.addEventListener('click', function () {
      if (!window.confirm(t('optConfirmClearHistory'))) {
        return;
      }
      setButtonBusy(dom.btnClearHistory, true);
      chrome.storage.local.set({ vtRecentHistory: [] }, function () {
        setButtonBusy(dom.btnClearHistory, false);
        if (chrome.runtime.lastError) {
          showToast(chromeErrorMessage('History clear failed'));
          return;
        }
        showToast(t('toastHistoryCleared'));
      });
    });
  }

  if (dom.btnClearBatch) {
    dom.btnClearBatch.addEventListener('click', function () {
      if (!window.confirm(t('optConfirmClearBatch'))) {
        return;
      }
      setButtonBusy(dom.btnClearBatch, true);
      chrome.storage.local.get(['vtRecentHistory'], function (data) {
        if (chrome.runtime.lastError) {
          setButtonBusy(dom.btnClearBatch, false);
          showToast(chromeErrorMessage('Batch clear failed'));
          return;
        }
        const list = Array.isArray(data.vtRecentHistory) ? data.vtRecentHistory : [];
        const filtered = list.filter(function (it) {
          return it && it.type !== 'batch-summary';
        });
        chrome.storage.local.set(
          { vtBatchHistory: [], vtRecentHistory: filtered },
          function () {
            setButtonBusy(dom.btnClearBatch, false);
            if (chrome.runtime.lastError) {
              showToast(chromeErrorMessage('Batch clear failed'));
              return;
            }
            showToast(t('toastBatchCleared'));
          }
        );
      });
    });
  }

  if (dom.proMode) {
    dom.proMode.addEventListener('change', syncRateControlState);
  }

  chrome.storage.onChanged.addListener(function (changes, area) {
    if (area !== 'local') {
      return;
    }
    if (changes.vtUiLang) {
      const lang = changes.vtUiLang.newValue === 'tr' ? 'tr' : 'en';
      VT_I18N.setLang(lang);
      if (dom.uiLang) {
        dom.uiLang.value = lang;
      }
      applyOptionsLang();
      scheduleAnalyticsRefresh(true);
    }
    if (changes.vtPopupTheme) {
      applyOptionsTheme(changes.vtPopupTheme.newValue === 'light' ? 'light' : 'dark');
      if (state.lastAnalyticsSnapshot) {
        renderAnalytics(
          state.lastAnalyticsSnapshot.analytics,
          state.lastAnalyticsSnapshot.batches,
          true
        );
      } else {
        scheduleAnalyticsRefresh(true);
      }
    }
    if (changes.vtUiMode) {
      syncUiModeInputs(changes.vtUiMode.newValue === 'sidepanel' ? 'sidepanel' : 'popup');
    }
    if (changes.vtProMode) {
      dom.proMode.checked = changes.vtProMode.newValue === true;
      syncRateControlState();
    }
    if (changes.vtRateIntervalSec && dom.rateSlider) {
      dom.rateSlider.value = String(clampRateSec(changes.vtRateIntervalSec.newValue));
      syncRateControlState();
      updateRateLabel();
    }
    if (changes.vtNotifyQueued && dom.notifyQueued) {
      dom.notifyQueued.checked = changes.vtNotifyQueued.newValue !== false;
    }
    if (changes.vtBatchUseAbuse && dom.batchUseAbuse) {
      dom.batchUseAbuse.checked = changes.vtBatchUseAbuse.newValue !== false;
    }
    if (changes.vtNotifyNews && dom.notifyNews) {
      dom.notifyNews.checked = changes.vtNotifyNews.newValue !== false;
    }
    if (changes.vtNotifyContext && dom.notifyContext) {
      dom.notifyContext.checked = changes.vtNotifyContext.newValue !== false;
    }
    if (changes.vtContentIocBadges && dom.contentIocBadges) {
      dom.contentIocBadges.checked = changes.vtContentIocBadges.newValue !== false;
    }
    if (changes.vtDomainBadgeBlacklist && dom.blacklist) {
      dom.blacklist.value = String(changes.vtDomainBadgeBlacklist.newValue || '');
    }
    if (changes[COPY_SUMMARY_FIELDS_KEY]) {
      setCopySummaryFieldsToForm(changes[COPY_SUMMARY_FIELDS_KEY].newValue);
    }
    if (changes[SCAN_PRESETS_KEY]) {
      renderPresetInputs(utils.migrateScanPresetsStorage(changes[SCAN_PRESETS_KEY].newValue));
    }
    if (changes[ANALYTICS_KEY] || changes.vtBatchHistory) {
      scheduleAnalyticsRefresh(false);
    }
  });
})(window.VtOptions = window.VtOptions || {});
