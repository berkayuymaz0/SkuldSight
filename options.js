/**
 * Options page: dashboard analytics (KPIs + charts) and settings forms.
 * Reads vtAnalytics aggregate + vtBatchHistory from chrome.storage.local for the dashboard.
 */
(function () {
  const utils = window.VtSocUtils;
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const SK = utils.STORAGE_KEYS;
  const SCAN_PRESETS_KEY = SK.scanPresets;
  const COPY_SUMMARY_FIELDS_KEY = SK.copySummaryFields;
  const ANALYTICS_KEY = SK.analytics;
  /** Keys read together for the analytics section (avoid duplicate storage reads on theme-only updates). */
  const OPTIONS_DASHBOARD_KEYS = [ANALYTICS_KEY, 'vtBatchHistory'];
  const KIND_ORDER = ['ip', 'domain', 'url', 'file'];
  const TIMELINE_DAYS = 14;

  const normalizeAnalytics = utils.normalizeAnalytics;

  // Sayfa üzerindeki form, toast ve grafik DOM referansları (id ile bağlanır).
  const dom = {
    keyForm: document.getElementById('key-form'),
    langForm: document.getElementById('lang-form'),
    behaviorForm: document.getElementById('behavior-form'),
    presetsForm: document.getElementById('scan-presets-form'),
    btnResetScanPresets: document.getElementById('btn-reset-scan-presets'),
    blacklistForm: document.getElementById('blacklist-form'),
    copySummaryForm: document.getElementById('copy-summary-form'),
    btnCopySummaryTemplateReset: document.getElementById('btn-copy-summary-template-reset'),
    btnCopyPresetMinimal: document.getElementById('btn-copy-preset-minimal'),
    btnCopyPresetAnalyst: document.getElementById('btn-copy-preset-analyst'),
    btnCopyPresetFull: document.getElementById('btn-copy-preset-full'),
    copyMatrixToggles: Array.prototype.slice.call(document.querySelectorAll('.copy-matrix-toggle')),
    uiLang: document.getElementById('ui-lang'),
    apiKey: document.getElementById('api-key'),
    rateSlider: document.getElementById('rate-interval'),
    rateLabel: document.getElementById('rate-interval-label'),
    uiModePopup: document.getElementById('ui-mode-popup'),
    uiModeSidepanel: document.getElementById('ui-mode-sidepanel'),
    proMode: document.getElementById('pro-mode'),
    batchUseAbuse: document.getElementById('batch-use-abuse'),
    notifyQueued: document.getElementById('notify-queued'),
    notifyNews: document.getElementById('notify-news'),
    notifyContext: document.getElementById('notify-context'),
    contentIocBadges: document.getElementById('content-ioc-badges'),
    blacklist: document.getElementById('domain-badge-blacklist'),
    btnClearHistory: document.getElementById('btn-clear-history'),
    btnClearBatch: document.getElementById('btn-clear-batch'),
    btnTestApi: document.getElementById('btn-test-api'),
    abuseKeyForm: document.getElementById('abuse-key-form'),
    abuseApiKey: document.getElementById('abuse-api-key'),
    btnTestAbuseApi: document.getElementById('btn-test-abuse-api'),
    toast: document.getElementById('toast'),
    toastText: document.getElementById('toast-text'),
    kpiTotal: document.getElementById('kpi-total'),
    kpiMal: document.getElementById('kpi-mal'),
    kpiSusp: document.getElementById('kpi-susp'),
    kpiKind: document.getElementById('kpi-kind'),
    kpiKindSub: document.getElementById('kpi-kind-sub'),
    kpiAbuseLookups: document.getElementById('kpi-abuse-lookups'),
    kpiAbuseSub: document.getElementById('kpi-abuse-sub'),
    chartDonut: document.getElementById('chart-donut'),
    chartDonutLegend: document.getElementById('chart-donut-legend'),
    chartDonutMeta: document.getElementById('chart-donut-meta'),
    chartBars: document.getElementById('chart-bars'),
    chartBarsMeta: document.getElementById('chart-bars-meta'),
    chartTimeline: document.getElementById('chart-timeline'),
    chartTimelineMeta: document.getElementById('chart-timeline-meta'),
    chartBatch: document.getElementById('chart-batch'),
    chartBatchMeta: document.getElementById('chart-batch-meta'),
    chartBatchStat: document.getElementById('chart-batch-stat'),
    chartBatchLegend: document.getElementById('chart-batch-legend')
  };

  // Raf tabanlı analitik yenileme ve son çizilen grafik imzaları; toast zamanlayıcıları.
  const state = {
    analyticsRafId: 0,
    analyticsQueued: false,
    /** Last payload from storage; used to repaint charts when only CSS theme tokens change. */
    lastAnalyticsSnapshot: null,
    lastKpiSig: '',
    lastDonutSig: '',
    lastBarsSig: '',
    lastTimelineSig: '',
    lastBatchSig: '',
    toastTimerId: 0,
    toastHideTimerId: 0
  };

  // Tarama şablonu (quick/detailed/analyst) onay kutularının DOM referansları.
  const presetInputs = {
    quick: {
      rel: document.getElementById('preset-quick-rel'),
      relSec: document.getElementById('preset-quick-relsec'),
      engine: document.getElementById('preset-quick-engine'),
      mitre: document.getElementById('preset-quick-mitre'),
      abuseReports: document.getElementById('preset-quick-abuse-reports'),
      abuseWindow: document.getElementById('preset-quick-abuse-window'),
      abuseOverall: document.getElementById('preset-quick-abuse-overall')
    },
    detailed: {
      rel: document.getElementById('preset-detailed-rel'),
      relSec: document.getElementById('preset-detailed-relsec'),
      engine: document.getElementById('preset-detailed-engine'),
      mitre: document.getElementById('preset-detailed-mitre'),
      abuseReports: document.getElementById('preset-detailed-abuse-reports'),
      abuseWindow: document.getElementById('preset-detailed-abuse-window'),
      abuseOverall: document.getElementById('preset-detailed-abuse-overall')
    },
    analyst: {
      rel: document.getElementById('preset-analyst-rel'),
      relSec: document.getElementById('preset-analyst-relsec'),
      engine: document.getElementById('preset-analyst-engine'),
      mitre: document.getElementById('preset-analyst-mitre'),
      abuseReports: document.getElementById('preset-analyst-abuse-reports'),
      abuseWindow: document.getElementById('preset-analyst-abuse-window'),
      abuseOverall: document.getElementById('preset-analyst-abuse-overall')
    }
  };

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
      tdKind.textContent = kindLabel(kind);
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

  // Zaman çizelgesi ekseni için gün/ay kısa etiket (GG/AA) üretir.
  function shortDayLabel(d) {
    return String(d.getDate()).padStart(2, '0') + '/' + String(d.getMonth() + 1).padStart(2, '0');
  }

  // IoC tür kodunu çeviri anahtarıyla insan okunur etikete çevirir.
  function kindLabel(kind) {
    if (kind === 'ip') return t('optKindIp');
    if (kind === 'domain') return t('optKindDomain');
    if (kind === 'url') return t('optKindUrl');
    if (kind === 'file') return t('optKindFile');
    return kind || '—';
  }

  // Zararlı/şüpheli/temiz tehdit seviyesi kodunu yerelleştirilmiş metne çevirir.
  function threatLevelLabel(level) {
    if (level === 'malicious') return t('optThreatMalicious');
    if (level === 'suspicious') return t('optThreatSuspicious');
    return t('optThreatClean');
  }

  // Ham analitik ve toplu geçmişten KPI, günlük zaman çizelgesi ve son toplu tarama özeti için görünüm modeli üretir.
  function buildAnalyticsView(analyticsRaw, batches) {
    const a = normalizeAnalytics(analyticsRaw);
    const batchList = Array.isArray(batches) ? batches : [];

    const days = [];
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    for (let i = TIMELINE_DAYS - 1; i >= 0; i--) {
      const d = new Date(today);
      d.setDate(today.getDate() - i);
      const k = dayKey(d.getTime());
      days.push({ date: d, key: k, count: Number(a.byDay[k]) || 0, label: shortDayLabel(d) });
    }

    let topKind = null;
    let topKindCount = 0;
    KIND_ORDER.forEach(function (k) {
      if (a.byKind[k] > topKindCount) {
        topKind = k;
        topKindCount = a.byKind[k];
      }
    });

    const latestBatch = batchList
      .slice()
      .sort(function (x, y) {
        return (Number(y && y.ts) || 0) - (Number(x && x.ts) || 0);
      })[0] || null;

    return {
      totalScans: a.totalScans,
      threats: a.threats,
      byKind: a.byKind,
      abuse: a.abuse || utils.defaultAbuseAnalytics(),
      days: days,
      topKind: topKind,
      topKindCount: topKindCount,
      latestBatch: latestBatch
    };
  }

  // SVG ad alanında öğe oluşturur, öznitelikleri atar ve istenirse ebeveyne ekler.
  function svg(name, attrs, parent) {
    const el = document.createElementNS(SVG_NS, name);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (attrs[k] !== undefined && attrs[k] !== null) {
          el.setAttribute(k, String(attrs[k]));
        }
      });
    }
    if (parent) {
      parent.appendChild(el);
    }
    return el;
  }

  // Düğümün tüm alt öğelerini kaldırarak grafik konteynerini boşaltır.
  function clearNode(node) {
    if (!node) return;
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  // CSS değişkeninden renk okur; yoksa veya hata olursa yedek hex değerini döndürür.
  function themeColor(name, fallback) {
    try {
      const v = getComputedStyle(document.documentElement).getPropertyValue(name);
      const trimmed = (v || '').trim();
      return trimmed || fallback;
    } catch (e) {
      return fallback;
    }
  }

  // Grafik çizimleri için tema uyumlu renk paletini toplar.
  function chartColors() {
    return {
      malicious: themeColor('--danger', '#f87171'),
      suspicious: themeColor('--warn', '#fbbf24'),
      clean: themeColor('--accent', '#34d399'),
      info: themeColor('--info', '#38bdf8'),
      muted: themeColor('--muted', '#91a2be'),
      border: 'rgba(148,163,184,0.18)',
      empty: 'rgba(148,163,184,0.18)'
    };
  }

  // Grafik hedefini temizleyip veri yokken ortalanmış boş durum metni gösterir.
  function showEmpty(node, message) {
    clearNode(node);
    const text = message || t('optChartNoData');
    if (node.tagName && node.tagName.toLowerCase() === 'svg') {
      const vb = (node.getAttribute('viewBox') || '0 0 360 160').split(/\s+/).map(Number);
      const w = vb[2] || 360;
      const h = vb[3] || 160;
      const t1 = svg('text', {
        x: w / 2, y: h / 2,
        'text-anchor': 'middle',
        'dominant-baseline': 'middle',
        'font-family': 'inherit',
        'font-size': '13',
        fill: themeColor('--muted', '#91a2be')
      }, node);
      t1.textContent = text;
      return;
    }
    const div = document.createElement('div');
    div.className = 'chart-empty';
    div.textContent = text;
    node.appendChild(div);
  }

  // Chart header chip metnini günceller; boşsa kısa placeholder basar.
  function setChartChip(el, text) {
    if (!el) return;
    el.textContent = text && String(text).trim() ? String(text) : '—';
  }

  // Tehdit dağılımı için halka dilimi (donut) ve açıklama lejantını çizer.
  function renderDonut(target, legendEl, threats) {
    if (!target) return;
    clearNode(target);
    clearNode(legendEl);
    const total = threats.malicious + threats.suspicious + threats.clean;
    const colors = chartColors();
    target.classList.add('chart-fade');
    setChartChip(dom.chartDonutMeta, t('optChartThreatsTotal') + ': ' + total);

    const cx = 100;
    const cy = 100;
    const r = 78;
    const stroke = 14;
    const circumference = 2 * Math.PI * r;

    svg('circle', {
      cx: cx, cy: cy, r: r,
      fill: 'none',
      stroke: colors.empty,
      'stroke-width': stroke
    }, target);

    if (total > 0) {
      const segments = [
        { key: 'malicious', value: threats.malicious, color: colors.malicious },
        { key: 'suspicious', value: threats.suspicious, color: colors.suspicious },
        { key: 'clean', value: threats.clean, color: colors.clean }
      ].filter(function (s) { return s.value > 0; });

      let offset = 0;
      segments.forEach(function (s) {
        const len = (s.value / total) * circumference;
        const c = svg('circle', {
          cx: cx, cy: cy, r: r,
          fill: 'none',
          stroke: s.color,
          'stroke-width': stroke,
          opacity: '0.88',
          'stroke-dasharray': len + ' ' + (circumference - len),
          'stroke-dashoffset': -offset,
          transform: 'rotate(-90 ' + cx + ' ' + cy + ')',
          'stroke-linecap': 'butt'
        }, target);
        const title = svg('title', {}, c);
        title.textContent = threatLevelLabel(s.key) + ': ' + s.value;
        offset += len;
      });
    }

    const totalText = svg('text', {
      x: cx, y: cy - 3,
      'text-anchor': 'middle',
      'font-family': 'inherit',
      'font-size': '20',
      'font-weight': '600',
      fill: themeColor('--text', '#e5edf8')
    }, target);
    totalText.textContent = String(total);

    const totalSub = svg('text', {
      x: cx, y: cy + 14,
      'text-anchor': 'middle',
      'font-family': 'inherit',
      'font-size': '10',
      'letter-spacing': '0.06em',
      'text-transform': 'uppercase',
      fill: colors.muted
    }, target);
    totalSub.textContent = t('optChartThreatsTotal');

    const legendData = [
      { key: 'malicious', label: t('optThreatMalicious'), value: threats.malicious, color: colors.malicious },
      { key: 'suspicious', label: t('optThreatSuspicious'), value: threats.suspicious, color: colors.suspicious },
      { key: 'clean', label: t('optThreatClean'), value: threats.clean, color: colors.clean }
    ];
    legendData.forEach(function (item) {
      const li = document.createElement('li');
      li.className = 'legend-item';
      const dot = document.createElement('span');
      dot.className = 'legend-dot';
      dot.style.setProperty('--legend-color', item.color);
      const label = document.createElement('span');
      label.className = 'legend-label';
      label.textContent = item.label;
      const value = document.createElement('span');
      value.className = 'legend-value';
      value.textContent = String(item.value);
      li.appendChild(dot);
      li.appendChild(label);
      li.appendChild(value);
      legendEl.appendChild(li);
    });
  }

  // IoC türüne göre yatay çubuk grafiği çizer (sadece sıfırdan büyük değerler).
  function renderBars(target, byKind) {
    if (!target) return;
    clearNode(target);
    target.classList.add('chart-fade');
    const items = KIND_ORDER.map(function (k) {
      return { key: k, label: kindLabel(k), value: byKind[k] || 0 };
    }).filter(function (it) { return it.value > 0; });

    if (items.length === 0) {
      setChartChip(dom.chartBarsMeta, '');
      showEmpty(target, t('optChartNoData'));
      return;
    }

    const max = items.reduce(function (m, it) { return Math.max(m, it.value); }, 0);
    const top = items.reduce(function (best, it) {
      return !best || it.value > best.value ? it : best;
    }, null);
    setChartChip(dom.chartBarsMeta, (top ? top.label : '—') + ': ' + (top ? top.value : 0));

    items.forEach(function (it) {
      const row = document.createElement('div');
      row.className = 'bar-row';

      const label = document.createElement('span');
      label.className = 'bar-label';
      label.textContent = it.label;

      const track = document.createElement('div');
      track.className = 'bar-track';
      track.title = it.label + ': ' + it.value;

      const fill = document.createElement('div');
      fill.className = 'bar-fill';
      const pct = max > 0 ? Math.max(2, (it.value / max) * 100) : 0;
      fill.style.width = pct + '%';
      track.appendChild(fill);

      const value = document.createElement('span');
      value.className = 'bar-value';
      value.textContent = String(it.value);

      row.appendChild(label);
      row.appendChild(track);
      row.appendChild(value);
      target.appendChild(row);
    });
  }

  // Son N günün tarama hacmini sütun yüksekliği ve seyrek tarih etiketleriyle gösterir.
  function renderTimeline(target, days) {
    if (!target) return;
    clearNode(target);
    target.classList.add('chart-fade');
    const total = days.reduce(function (s, d) { return s + d.count; }, 0);

    if (total === 0) {
      setChartChip(dom.chartTimelineMeta, '');
      showEmpty(target, t('optChartNoData'));
      return;
    }

    const max = days.reduce(function (m, d) { return Math.max(m, d.count); }, 0) || 1;
    setChartChip(dom.chartTimelineMeta, t('optChartActivityPeak', { n: max }));

    const peak = document.createElement('div');
    peak.className = 'timeline-axis';
    peak.textContent = t('optChartActivityPeak', { n: max });
    target.appendChild(peak);

    const track = document.createElement('div');
    track.className = 'timeline-track';
    const bars = document.createElement('div');
    bars.className = 'timeline-bars';
    days.forEach(function (d) {
      const bar = document.createElement('div');
      bar.className = 'timeline-bar' + (d.count > 0 ? '' : ' is-empty');
      const pct = d.count > 0 ? Math.max(3, (d.count / max) * 100) : 5;
      bar.style.height = pct + '%';
      bar.title = d.key + ': ' + d.count;
      bars.appendChild(bar);
    });
    track.appendChild(bars);
    target.appendChild(track);

    const labels = document.createElement('div');
    labels.className = 'timeline-labels';
    const sparseIdx = [0, Math.floor(days.length / 2), days.length - 1];
    sparseIdx.forEach(function (i) {
      const span = document.createElement('span');
      span.textContent = days[i] ? days[i].label : '';
      labels.appendChild(span);
    });
    target.appendChild(labels);
  }

  // Son toplu taramanın zararlı/şüpheli/temiz/hata/boş dağılımını çubuk ve lejantla çizer.
  function renderBatch(target, legendEl, metaEl, latest) {
    if (!target) return;
    clearNode(target);
    clearNode(legendEl);
    target.classList.add('chart-fade');
    const colors = chartColors();

    if (!latest || !latest.counts) {
      metaEl.textContent = t('optChartBatchEmpty');
      setChartChip(dom.chartBatchStat, '');
      showEmpty(target, t('optChartNoData'));
      return;
    }

    const c = latest.counts;
    const total = Math.max(1, Number(latest.total) || 0);
    setChartChip(dom.chartBatchStat, t('optChartThreatsTotal') + ': ' + total);
    const segments = [
      { key: 'malicious', label: t('optThreatMalicious'), value: c.malicious || 0, color: colors.malicious },
      { key: 'suspicious', label: t('optThreatSuspicious'), value: c.suspicious || 0, color: colors.suspicious },
      { key: 'clean', label: t('optThreatClean'), value: c.clean || 0, color: colors.clean },
      { key: 'error', label: t('batchError'), value: c.error || 0, color: colors.muted },
      { key: 'empty', label: t('batchEmpty'), value: c.empty || 0, color: colors.border }
    ];

    const barH = 11;
    const barY = 7;
    const width = 360;
    target.setAttribute('viewBox', '0 0 ' + width + ' 26');

    svg('rect', {
      x: 0, y: barY, width: width, height: barH,
      rx: 4, ry: 4, fill: colors.empty
    }, target);

    let offset = 0;
    segments.forEach(function (s) {
      if (s.value <= 0) return;
      const w = (s.value / total) * width;
      const r = svg('rect', {
        x: offset, y: barY,
        width: Math.max(2, w),
        height: barH,
        fill: s.color,
        opacity: '0.82'
      }, target);
      const tt = svg('title', {}, r);
      tt.textContent = s.label + ': ' + s.value;
      offset += w;
    });

    const fileName = latest.fileName ? String(latest.fileName) : t('batchSummaryUnknownFile');
    metaEl.textContent = t('optChartBatchMeta', {
      total: total,
      file: fileName.length > 64 ? fileName.slice(0, 61) + '…' : fileName
    });

    segments.forEach(function (s) {
      if (s.value <= 0) return;
      const li = document.createElement('li');
      li.className = 'legend-item';
      const dot = document.createElement('span');
      dot.className = 'legend-dot';
      dot.style.setProperty('--legend-color', s.color);
      const label = document.createElement('span');
      label.className = 'legend-label';
      label.textContent = s.label;
      const value = document.createElement('span');
      value.className = 'legend-value';
      value.textContent = String(s.value);
      li.appendChild(dot);
      li.appendChild(label);
      li.appendChild(value);
      legendEl.appendChild(li);
    });
  }

  // Üst KPI kutularına toplam tarama, tehdit sayıları ve baskın IoC türünü yazar.
  function renderKpis(a) {
    if (dom.kpiTotal) dom.kpiTotal.textContent = String(a.totalScans);
    if (dom.kpiMal) dom.kpiMal.textContent = String(a.threats.malicious);
    if (dom.kpiSusp) dom.kpiSusp.textContent = String(a.threats.suspicious);
    if (dom.kpiKind) {
      dom.kpiKind.textContent = a.topKind ? kindLabel(a.topKind) : '—';
    }
    if (dom.kpiKindSub) {
      dom.kpiKindSub.textContent = a.topKind
        ? t('optKpiTopKindCount', { n: a.topKindCount })
        : t('optKpiTopKindSub');
    }
    const abuse = a.abuse || utils.defaultAbuseAnalytics();
    if (dom.kpiAbuseLookups) {
      dom.kpiAbuseLookups.textContent = String(abuse.lookups || 0);
    }
    if (dom.kpiAbuseSub) {
      dom.kpiAbuseSub.textContent = t('optKpiAbuseSubCounts', {
        high: abuse.high || 0,
        elevated: abuse.elevated || 0
      });
    }
  }

  // Tüm analitik panellerini imza ile karşılaştırarak yalnız değişen grafikleri yeniden çizer.
  function renderAnalytics(analyticsRaw, batches, force) {
    const view = buildAnalyticsView(analyticsRaw, batches);
    const kpiSig = serialize({
      totalScans: view.totalScans,
      malicious: view.threats.malicious,
      suspicious: view.threats.suspicious,
      topKind: view.topKind,
      topKindCount: view.topKindCount,
      abuse: view.abuse
    });
    if (force || kpiSig !== state.lastKpiSig) {
      renderKpis(view);
      state.lastKpiSig = kpiSig;
    }

    const donutSig = serialize(view.threats);
    if (force || donutSig !== state.lastDonutSig) {
      renderDonut(dom.chartDonut, dom.chartDonutLegend, view.threats);
      state.lastDonutSig = donutSig;
    }

    const barsSig = serialize(view.byKind);
    if (force || barsSig !== state.lastBarsSig) {
      renderBars(dom.chartBars, view.byKind);
      state.lastBarsSig = barsSig;
    }

    const timelineSig = serialize(view.days.map(function (d) { return d.count; }));
    if (force || timelineSig !== state.lastTimelineSig) {
      renderTimeline(dom.chartTimeline, view.days);
      state.lastTimelineSig = timelineSig;
    }

    const batchSig = serialize(summarizeBatch(view.latestBatch));
    if (force || batchSig !== state.lastBatchSig) {
      renderBatch(dom.chartBatch, dom.chartBatchLegend, dom.chartBatchMeta, view.latestBatch);
      state.lastBatchSig = batchSig;
    }
  }

  // Depodan analitik ve toplu geçmişi okuyup panelleri yeniler; hata durumunda toast gösterir.
  function refreshAnalytics(force) {
    setAnalyticsBusy(true);
    chrome.storage.local.get(OPTIONS_DASHBOARD_KEYS, function (data) {
      if (chrome.runtime.lastError) {
        showToast(chromeErrorMessage('Analytics refresh failed'));
        setAnalyticsBusy(false);
        return;
      }
      state.lastAnalyticsSnapshot = {
        analytics: data[ANALYTICS_KEY],
        batches: data.vtBatchHistory
      };
      renderAnalytics(data[ANALYTICS_KEY], data.vtBatchHistory, force === true);
      setAnalyticsBusy(false);
    });
  }

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
            showToast(okMsg);
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
      if (!window.confirm('Clear recent lookups? This cannot be undone.')) {
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
      if (!window.confirm('Clear batch history? This cannot be undone.')) {
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
})();
