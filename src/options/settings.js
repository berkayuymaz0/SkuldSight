(function (NS) {
  const utils = NS.utils;
  const dom = NS.dom;
  const state = NS.state;
  const presetInputs = NS.presetInputs;
  const KIND_ORDER = NS.KIND_ORDER;
  const SCAN_PRESETS_KEY = NS.SCAN_PRESETS_KEY;

  // Ayarlar sayfasında VT_I18N üzerinden çeviri anahtarını çözer.
  function t(key, vars) {
    return VT_I18N.t(key, vars);
  }

  // data-i18n özniteliklerine ve başlığa seçili dile göre metin basar; hız etiketini günceller.
  function applyOptionsLang() {
    document.documentElement.lang = VT_I18N.lang();
    utils.applyI18n(document, t, {
      titleKey: 'popupTitle',
      titleSuffixKey: 'optSettingsDocTitle'
    });
    updateRateLabel();
  }

  // syncUiModeTiles: Seçili moda göre kart görünümünü günceller.
  function syncUiModeTiles(mode) {
    const isPanel = mode === 'sidepanel';
    const popupTile = dom.uiModePopup && dom.uiModePopup.closest('.ui-mode-tile');
    const panelTile = dom.uiModeSidepanel && dom.uiModeSidepanel.closest('.ui-mode-tile');
    if (popupTile) {
      popupTile.classList.toggle('is-selected', !isPanel);
    }
    if (panelTile) {
      panelTile.classList.toggle('is-selected', isPanel);
    }
  }

  // syncUiModeInputs: vtUiMode değerine göre arayüz modu radyo düğmelerini günceller.
  function syncUiModeInputs(mode) {
    const isPanel = mode === 'sidepanel';
    if (dom.uiModePopup) {
      dom.uiModePopup.checked = !isPanel;
    }
    if (dom.uiModeSidepanel) {
      dom.uiModeSidepanel.checked = isPanel;
    }
    syncUiModeTiles(mode);
  }

  // saveUiMode: Modu kaydeder ve arka planda hemen uygular.
  function saveUiMode(mode) {
    const next = mode === 'sidepanel' ? 'sidepanel' : 'popup';
    chrome.storage.local.set({ vtUiMode: next }, function () {
      if (chrome.runtime.lastError) {
        showToast(chromeErrorMessage('UI mode save failed'));
        return;
      }
      chrome.runtime.sendMessage({ type: 'APPLY_UI_MODE', mode: next }, function () {
        if (chrome.runtime.lastError) {
          refreshUiModeFromBackground();
        }
      });
      showToast(t('toastUiModeSaved'));
    });
  }

  // refreshUiModeFromBackground: Service worker'dan modu yeniden uygular.
  function refreshUiModeFromBackground() {
    chrome.runtime.sendMessage({ type: 'APPLY_UI_MODE', mode: readUiModeFromForm() });
  }

  // bindUiModePicker: Mod seçiminde anında kaydet ve uygula.
  function bindUiModePicker() {
    [dom.uiModePopup, dom.uiModeSidepanel].forEach(function (input) {
      if (!input) {
        return;
      }
      input.addEventListener('change', function () {
        if (!input.checked) {
          return;
        }
        const mode = readUiModeFromForm();
        syncUiModeInputs(mode);
        saveUiMode(mode);
      });
    });
  }

  // readUiModeFromForm: Formdan seçili arayüz modunu okur.
  function readUiModeFromForm() {
    if (dom.uiModeSidepanel && dom.uiModeSidepanel.checked) {
      return 'sidepanel';
    }
    return 'popup';
  }

  // Kök öğeye data-theme atayarak açık/koyu tema sınıflarını uygular.
  function applyOptionsTheme(theme) {
    const th = theme === 'light' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', th);
  }

  // Kısa süre görünen toast bildirimini gösterir ve zamanlayıcılarla gizler.
  function showToast(message) {
    if (state.toastTimerId) {
      window.clearTimeout(state.toastTimerId);
      state.toastTimerId = 0;
    }
    if (state.toastHideTimerId) {
      window.clearTimeout(state.toastHideTimerId);
      state.toastHideTimerId = 0;
    }
    dom.toastText.textContent = message || t('toastSaved');
    dom.toast.hidden = false;
    requestAnimationFrame(function () {
      dom.toast.classList.add('visible');
    });
    state.toastTimerId = window.setTimeout(function () {
      dom.toast.classList.remove('visible');
      state.toastHideTimerId = window.setTimeout(function () {
        dom.toast.hidden = true;
        state.toastHideTimerId = 0;
      }, 350);
      state.toastTimerId = 0;
    }, 2200);
  }

  // Değeri JSON’a çevirir; hata olursa String’e düşer (imza karşılaştırması için).
  function serialize(value) {
    try {
      return JSON.stringify(value);
    } catch (e) {
      return String(value);
    }
  }

  // Son toplu tarama kaydından grafikler için güvenli özet nesnesi üretir veya null döner.
  function summarizeBatch(batch) {
    if (!batch || !batch.counts) {
      return null;
    }
    return {
      ts: Number(batch.ts) || 0,
      total: Number(batch.total) || 0,
      fileName: String(batch.fileName || ''),
      counts: {
        malicious: Number(batch.counts.malicious) || 0,
        suspicious: Number(batch.counts.suspicious) || 0,
        clean: Number(batch.counts.clean) || 0,
        error: Number(batch.counts.error) || 0,
        empty: Number(batch.counts.empty) || 0
      }
    };
  }

  // Form gönderiminde düğümü devre dışı bırakır ve yükleme görsel durumunu ayarlar.
  function setButtonBusy(button, busy) {
    if (!button) return;
    button.disabled = !!busy;
    button.classList.toggle('is-loading', !!busy);
    button.setAttribute('aria-busy', busy ? 'true' : 'false');
  }

  // Analitik SVG grafiklerine aria-busy ile yükleniyor durumunu yansıtır.
  function setAnalyticsBusy(busy) {
    const val = busy ? 'true' : 'false';
    if (dom.chartDonut) dom.chartDonut.setAttribute('aria-busy', val);
    if (dom.chartBars) dom.chartBars.setAttribute('aria-busy', val);
    if (dom.chartTimeline) dom.chartTimeline.setAttribute('aria-busy', val);
    if (dom.chartBatch) dom.chartBatch.setAttribute('aria-busy', val);
  }

  // chrome.runtime.lastError varsa önek ile birleştirerek kullanıcıya gösterilecek metin üretir.
  function chromeErrorMessage(prefix) {
    if (!chrome.runtime || !chrome.runtime.lastError) {
      return prefix;
    }
    const detail = String(chrome.runtime.lastError.message || '').trim();
    return detail ? prefix + ': ' + detail : prefix;
  }

  const defaultCopySummaryFields = utils.defaultCopySummaryFields;
  const copySummaryFieldKeys = utils.copySummaryFieldKeys;
  const normalizeCopySummaryFields = utils.normalizeCopySummaryFields;

  function copySummaryInputId(kind, field) {
    const map = {
      threatLevel: 'threat',
      detectionRatio: 'ratio',
      reputation: 'rep',
      suggestedThreat: 'suggested',
      abuseScore: 'abuse-score',
      abuseReports: 'abuse-reports',
      distinctLabels: 'labels',
      reportLink: 'report'
    };
    return 'copy-' + kind + '-' + (map[field] || field);
  }

  function setCopySummaryFieldsToForm(configRaw) {
    const cfg = normalizeCopySummaryFields(configRaw);
    ['ip', 'domain', 'url', 'file'].forEach(function (kind) {
      copySummaryFieldKeys().forEach(function (field) {
        const el = document.getElementById(copySummaryInputId(kind, field));
        if (el) {
          const isOn = cfg[kind][field] === true;
          el.setAttribute('aria-pressed', isOn ? 'true' : 'false');
          el.classList.toggle('is-on', isOn);
        }
      });
    });
    syncCopySummaryPresetButtons(cfg);
  }

  function readCopySummaryFieldsFromForm() {
    const fallback = defaultCopySummaryFields();
    const out = {};
    ['ip', 'domain', 'url', 'file'].forEach(function (kind) {
      out[kind] = {};
      copySummaryFieldKeys().forEach(function (field) {
        const el = document.getElementById(copySummaryInputId(kind, field));
        out[kind][field] = el
          ? el.getAttribute('aria-pressed') === 'true'
          : fallback[kind][field] === true;
      });
    });
    return out;
  }

  function copySummaryConfigsEqual(aRaw, bRaw) {
    const a = normalizeCopySummaryFields(aRaw);
    const b = normalizeCopySummaryFields(bRaw);
    const kinds = ['ip', 'domain', 'url', 'file'];
    for (let i = 0; i < kinds.length; i++) {
      const kind = kinds[i];
      const fields = copySummaryFieldKeys();
      for (let j = 0; j < fields.length; j++) {
        const field = fields[j];
        if ((a[kind][field] === true) !== (b[kind][field] === true)) {
          return false;
        }
      }
    }
    return true;
  }

  function buildCopySummaryPresetConfig(presetName) {
    const next = defaultCopySummaryFields();
    if (presetName === 'minimal') {
      ['ip', 'domain', 'url', 'file'].forEach(function (kind) {
        next[kind].ioc = true;
        next[kind].kind = true;
        next[kind].threatLevel = true;
        next[kind].vt = true;
        next[kind].detectionRatio = true;
        next[kind].reportLink = true;
        next[kind].time = false;
        next[kind].reputation = false;
        next[kind].suggestedThreat = false;
        next[kind].tags = false;
        next[kind].distinctLabels = false;
        next[kind].mitre = false;
      });
      next.ip.abuseScore = false;
      next.ip.abuseReports = false;
      return next;
    }
    if (presetName === 'analyst') {
      ['ip', 'domain', 'url', 'file'].forEach(function (kind) {
        next[kind].ioc = true;
        next[kind].kind = true;
        next[kind].threatLevel = true;
        next[kind].vt = true;
        next[kind].detectionRatio = true;
        next[kind].reputation = true;
        next[kind].suggestedThreat = true;
        next[kind].tags = true;
        next[kind].distinctLabels = true;
        next[kind].time = false;
        next[kind].reportLink = true;
      });
      next.ip.abuseScore = true;
      next.ip.abuseReports = false;
      next.file.mitre = true;
      return next;
    }
    ['ip', 'domain', 'url', 'file'].forEach(function (kind) {
      copySummaryFieldKeys().forEach(function (field) {
        next[kind][field] = true;
      });
    });
    next.domain.abuseScore = false;
    next.domain.abuseReports = false;
    next.url.abuseScore = false;
    next.url.abuseReports = false;
    next.file.abuseScore = false;
    next.file.abuseReports = false;
    return next;
  }

  function setPresetButtonState(button, active) {
    if (!button) {
      return;
    }
    button.classList.toggle('is-active', !!active);
    button.setAttribute('aria-pressed', active ? 'true' : 'false');
  }

  function syncCopySummaryPresetButtons(configRaw) {
    const config = normalizeCopySummaryFields(configRaw);
    const minimal = buildCopySummaryPresetConfig('minimal');
    const analyst = buildCopySummaryPresetConfig('analyst');
    const full = buildCopySummaryPresetConfig('full');
    const matched =
      copySummaryConfigsEqual(config, minimal)
        ? 'minimal'
        : copySummaryConfigsEqual(config, analyst)
          ? 'analyst'
          : copySummaryConfigsEqual(config, full)
            ? 'full'
            : '';
    setPresetButtonState(dom.btnCopyPresetMinimal, matched === 'minimal');
    setPresetButtonState(dom.btnCopyPresetAnalyst, matched === 'analyst');
    setPresetButtonState(dom.btnCopyPresetFull, matched === 'full');
  }

  function applyCopySummaryPreset(presetName) {
    const next = buildCopySummaryPresetConfig(presetName);
    setCopySummaryFieldsToForm(next);
  }

  // Hız sınırı kaydırıcısı değerine göre “n saniye” etiket metnini günceller.
  function updateRateLabel() {
    const v = Number(dom.rateSlider.value) || 16;
    dom.rateLabel.textContent = t('optRateSeconds', { n: v });
  }

  // Pro mod açıkken hız kaydırıcısını devre dışı bırakır.
  function syncRateControlState() {
    const disabled = !!(dom.proMode && dom.proMode.checked);
    dom.rateSlider.disabled = disabled;
  }

  const clampRateSec = utils.clampRateSec;

  // Kayıtlı API anahtarının yerel TTL penceresinin dışında kalıp kalmadığını kontrol eder.
  const isApiKeyExpired = utils.isApiKeyExpired;

  // presetRelCode: relMode → kısa matris kodu.
  function presetRelCode(relMode) {
    if (relMode === 'full') {
      return 'REL+';
    }
    if (relMode === 'primary') {
      return 'REL';
    }
    return '—';
  }

  // renderPresetMatrix: IoC türü × REL / LBL / MITRE özet tablosu (salt okunur).
  function renderPresetMatrix(presetName, profile) {
    const host = document.querySelector('.preset-ioc-matrix[data-preset="' + presetName + '"]');
    if (!host) {
      return;
    }
    const prof = profile || utils.DEFAULT_SCAN_PRESETS[presetName];
    const kinds = utils.IOC_KINDS || KIND_ORDER;
    const table = document.createElement('table');
    table.className = 'preset-matrix-table';
    const thead = document.createElement('thead');
    const hr = document.createElement('tr');
    [
      t('optPresetMatrixKind'),
      t('optPresetColRelCode'),
      t('optPresetColLblCode'),
      t('optPresetColMitreCode'),
      t('optPresetColAbuseCode')
    ].forEach(function (label) {
      const th = document.createElement('th');
      th.scope = 'col';
      th.textContent = label;
      hr.appendChild(th);
    });
    thead.appendChild(hr);
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    kinds.forEach(function (kind) {
      const rowCfg = utils.normalizeScanPresetKind(
        prof[kind],
        utils.DEFAULT_SCAN_PRESETS[presetName][kind]
      );
      const tr = document.createElement('tr');
      const tdKind = document.createElement('th');
      tdKind.scope = 'row';
      tdKind.textContent = NS.kindLabel(kind);
      tr.appendChild(tdKind);
      const abuseCell = kind === 'ip' ? utils.abusePresetSummaryCode(rowCfg) : '—';
      [
        presetRelCode(rowCfg.relMode),
        rowCfg.labels === 'extended' ? 'EXT' : 'STD',
        rowCfg.mitre ? '✓' : '—',
        abuseCell
      ].forEach(function (cell) {
        const td = document.createElement('td');
        td.textContent = cell;
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    host.replaceChildren(table);
  }

  // presetProfileToCheckboxes: IoC matrisinden form onay kutusu özeti (en derin rel + any EXT/MITRE).
  function presetProfileToCheckboxes(profile) {
    const kinds = utils.IOC_KINDS || KIND_ORDER;
    let relMode = 'none';
    kinds.forEach(function (k) {
      const rm = profile[k] && profile[k].relMode;
      if (rm === 'full') {
        relMode = 'full';
      } else if (rm === 'primary' && relMode !== 'full') {
        relMode = 'primary';
      }
    });
    const labelsExtended = kinds.some(function (k) {
      return profile[k] && profile[k].labels === 'extended';
    });
    const mitreOn = kinds.some(function (k) {
      return profile[k] && profile[k].mitre === true;
    });
    return {
      boxes: utils.checkboxesFromRelMode(relMode),
      labelsExtended: labelsExtended,
      mitreOn: mitreOn
    };
  }

  function syncAbusePresetControls(name, ipProfile) {
    const row = presetInputs[name];
    if (!row) {
      return;
    }
    const ip = utils.normalizeScanPresetKind(
      ipProfile,
      utils.DEFAULT_SCAN_PRESETS[name].ip
    );
    if (row.abuseReports) {
      row.abuseReports.checked = ip.abuseReports === true;
    }
    if (row.abuseWindow) {
      row.abuseWindow.value = String(ip.abuseWindowDays);
      row.abuseWindow.disabled = !ip.abuseReports;
    }
    if (row.abuseOverall) {
      row.abuseOverall.value = String(ip.abuseOverallDays);
    }
  }

  // Tarama ön ayarı: IoC matrisi + profille uyumlu onay kutuları.
  function renderPresetInputs(map) {
    const normalized = utils.normalizeScanPresetsMap(map);
    ['quick', 'detailed', 'analyst'].forEach(function (name) {
      const profile = normalized[name] || utils.DEFAULT_SCAN_PRESETS[name];
      renderPresetMatrix(name, profile);
      const row = presetInputs[name];
      const chk = presetProfileToCheckboxes(profile);
      if (!row) {
        return;
      }
      if (row.rel) {
        row.rel.checked = chk.boxes.rel;
      }
      if (row.relSec) {
        row.relSec.checked = chk.boxes.relSecondary;
        row.relSec.disabled = !chk.boxes.rel;
      }
      if (row.engine) {
        row.engine.checked = chk.labelsExtended;
      }
      if (row.mitre) {
        row.mitre.checked = chk.mitreOn;
      }
      syncAbusePresetControls(name, profile.ip);
    });
  }

  // resetScanPresetsToDefaults: v3 fabrika profillerini depoya yazar ve formu günceller.
  function resetScanPresetsToDefaults() {
    const map = utils.getDefaultScanPresetsMap();
    renderPresetInputs(map);
    const btn = dom.btnResetScanPresets;
    if (btn) {
      setButtonBusy(btn, true);
    }
    chrome.storage.local.set(
      { [SCAN_PRESETS_KEY]: utils.storagePayloadFromPresets(map) },
      function () {
        if (btn) {
          setButtonBusy(btn, false);
        }
        if (chrome.runtime.lastError) {
          showToast(chromeErrorMessage('Preset reset failed'));
          return;
        }
        showToast(t('toastScanPresetsReset'));
      }
    );
  }

  // Formdaki onay kutularından düz profil okur; kayıtta tüm IoC türlerine uygulanır.
  function readPresetInputs() {
    function readRow(name) {
      const row = presetInputs[name];
      const relOn = !!(row && row.rel && row.rel.checked);
      const relSecOn = !!(row && row.relSec && row.relSec.checked);
      const flat = {
        relMode: utils.relModeFromCheckboxes(relOn, relSecOn),
        labels: row && row.engine && row.engine.checked ? 'extended' : 'standard',
        mitre: !!(row && row.mitre && row.mitre.checked)
      };
      const abuseReports = !!(row && row.abuseReports && row.abuseReports.checked);
      const abuseWindowDays = row && row.abuseWindow ? Number(row.abuseWindow.value) : 30;
      const abuseOverallDays = row && row.abuseOverall ? Number(row.abuseOverall.value) : 90;
      const profile = {};
      (utils.IOC_KINDS || KIND_ORDER).forEach(function (k) {
        profile[k] = {
          relMode: flat.relMode,
          labels: flat.labels,
          mitre: flat.mitre
        };
      });
      profile.ip = Object.assign({}, profile.ip, {
        abuseReports: abuseReports,
        abuseWindowDays: abuseWindowDays,
        abuseOverallDays: abuseOverallDays
      });
      return profile;
    }
    return {
      quick: readRow('quick'),
      detailed: readRow('detailed'),
      analyst: readRow('analyst')
    };
  }

  const dayKey = utils.dayKeyFromTs;

  NS.t = t;
  NS.applyOptionsLang = applyOptionsLang;
  NS.applyOptionsTheme = applyOptionsTheme;
  NS.syncUiModeInputs = syncUiModeInputs;
  NS.bindUiModePicker = bindUiModePicker;
  NS.showToast = showToast;
  NS.serialize = serialize;
  NS.summarizeBatch = summarizeBatch;
  NS.setButtonBusy = setButtonBusy;
  NS.setAnalyticsBusy = setAnalyticsBusy;
  NS.chromeErrorMessage = chromeErrorMessage;
  NS.updateRateLabel = updateRateLabel;
  NS.syncRateControlState = syncRateControlState;
  NS.clampRateSec = clampRateSec;
  NS.isApiKeyExpired = isApiKeyExpired;
  NS.defaultCopySummaryFields = defaultCopySummaryFields;
  NS.normalizeCopySummaryFields = normalizeCopySummaryFields;
  NS.setCopySummaryFieldsToForm = setCopySummaryFieldsToForm;
  NS.readCopySummaryFieldsFromForm = readCopySummaryFieldsFromForm;
  NS.applyCopySummaryPreset = applyCopySummaryPreset;
  NS.renderPresetInputs = renderPresetInputs;
  NS.renderPresetMatrix = renderPresetMatrix;
  NS.resetScanPresetsToDefaults = resetScanPresetsToDefaults;
  NS.readPresetInputs = readPresetInputs;
  NS.dayKey = dayKey;
})(window.VtOptions = window.VtOptions || {});

