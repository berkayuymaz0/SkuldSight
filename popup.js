/**
 * Popup script: wires the IoC textarea to the background worker via long-lived ports
 * (single scan and batch), renders VT results, recent history, and CSV export.
 */
(function () {
  if (new URLSearchParams(location.search).get('surface') === 'sidepanel') {
    document.documentElement.setAttribute('data-surface', 'sidepanel');
  }

  const utils = window.VtSocUtils;
  /** Max wait for a single-scan result before showing a timeout error (SW may have restarted). */
  const SINGLE_SCAN_TIMEOUT_MS = 180000;

  const input = document.getElementById('ioc-input');
  const inputSurfaceCard = document.getElementById('input-surface-card');
  const btnScanInputExpand = document.getElementById('btn-scan-input-expand');
  const scanCompactPreview = document.getElementById('scan-compact-preview');
  const presetQuick = document.getElementById('preset-quick');
  const presetDetailed = document.getElementById('preset-detailed');
  const presetAnalyst = document.getElementById('preset-analyst');
  const btnScan = document.getElementById('btn-scan');
  const btnFileAction = document.getElementById('btn-file-action');
  const btnOptions = document.getElementById('btn-options');
  const btnOptionsInline = document.getElementById('btn-options-inline');
  const btnLangToggle = document.getElementById('btn-lang-toggle');
  const langToggleLabel = document.getElementById('lang-toggle-label');
  const btnThemeToggle = document.getElementById('btn-theme-toggle');
  const btnCopySummary = document.getElementById('btn-copy-summary');
  const btnClearRecent = document.getElementById('btn-clear-recent');
  const connStatus = document.getElementById('conn-status');
  const batchWrap = document.getElementById('batch-wrap');
  const btnBatchDownload = document.getElementById('btn-batch-download');
  const batchProgressLabel = document.getElementById('batch-progress-label');
  const batchBarFill = document.getElementById('batch-bar-fill');
  const batchLinesEl = document.getElementById('batch-lines');
  const resultWrap = document.getElementById('result-wrap');
  const btnResultClose = document.getElementById('btn-result-close');
  const resultCard = document.getElementById('result-card');
  const resultKind = document.getElementById('result-kind');
  const resultIoc = document.getElementById('result-ioc');
  const resultVerdict = document.getElementById('result-verdict');
  const resultThreatDashboard = document.getElementById('result-threat-dashboard');
  const resultChart = document.getElementById('result-chart');
  const resultChartRatio = document.getElementById('result-chart-ratio');
  const resultChartBar = document.getElementById('result-chart-bar');
  const resultChartLegend = document.getElementById('result-chart-legend');
  const resultVtEmpty = document.getElementById('result-vt-empty');
  const resultVtPill = document.getElementById('result-vt-pill');
  const resultAbuseCard = document.getElementById('result-abuse-card');
  const resultAbusePill = document.getElementById('result-abuse-pill');
  const resultEngineBlock = document.getElementById('result-engine-block');
  const resultEngineSummary = document.getElementById('result-engine-summary');
  const resultEngineList = document.getElementById('result-engine-list');
  const resultRelBlock = document.getElementById('result-rel-block');
  const resultRelCaption = document.getElementById('result-rel-caption');
  const resultRelError = document.getElementById('result-rel-error');
  const resultRelList = document.getElementById('result-rel-list');
  const resultMitreBlock = document.getElementById('result-mitre-block');
  const resultMitreError = document.getElementById('result-mitre-error');
  const resultMitreMeta = document.getElementById('result-mitre-meta');
  const resultMitreList = document.getElementById('result-mitre-list');
  const resultDetailsBlock = document.getElementById('result-details-block');
  const resultDetailsEl = document.getElementById('result-details');
  const resultEngineDetails = document.getElementById('result-engine-details');
  const resultRelDetails = document.getElementById('result-rel-details');
  const resultMitreDetails = document.getElementById('result-mitre-details');
  const resultDetailsCollapsible = document.getElementById('result-details-collapsible');
  const resultLiveAnnounce = document.getElementById('result-live-announce');
  const resultHeroSubline = document.getElementById('result-hero-subline');
  const resultHeroTags = document.getElementById('result-hero-tags');
  const resultHeroChips = document.getElementById('result-hero-chips');
  const resultReputation = document.getElementById('result-reputation');
  const resultRepSep = document.getElementById('result-rep-sep');
  const scanQuotaHint = document.getElementById('scan-quota-hint');
  const copyToast = document.getElementById('copy-toast');
  const resultLink = document.getElementById('result-link');
  const resultAbuseBlock = document.getElementById('result-abuse-block');
  const errorMsg = document.getElementById('error-msg');
  const noKeyHint = document.getElementById('no-key-hint');
  const queueBadge = document.getElementById('queue-badge');
  const recentList = document.getElementById('recent-list');
  const recentEmpty = document.getElementById('recent-empty');
  const recentTabGeneral = document.getElementById('recent-tab-general');
  const recentTabBatch = document.getElementById('recent-tab-batch');
  const recentPanelGeneral = document.getElementById('recent-panel-general');
  const recentPanelBatch = document.getElementById('recent-panel-batch');
  const batchHistoryList = document.getElementById('batch-history-list');
  const batchHistoryEmpty = document.getElementById('batch-history-empty');
  const fileIocList = document.getElementById('file-ioc-list');
  const tabScan = document.getElementById('tab-scan');
  const tabNews = document.getElementById('tab-news');
  const tabUsom = document.getElementById('tab-usom');
  const panelScan = document.getElementById('panel-scan');
  const panelNews = document.getElementById('panel-news');
  const panelUsom = document.getElementById('panel-usom');
  const btnNewsRefresh = document.getElementById('btn-news-refresh');
  const newsUpdatedAt = document.getElementById('news-updated-at');
  const newsStatus = document.getElementById('news-status');
  const newsList = document.getElementById('news-list');
  const newsEmpty = document.getElementById('news-empty');
  const newsSourceFilter = document.getElementById('news-source-filter');
  const newsSearch = document.getElementById('news-search');
  const btnUsomRefresh = document.getElementById('btn-usom-refresh');
  const usomUpdatedAt = document.getElementById('usom-updated-at');
  const usomStatus = document.getElementById('usom-status');
  const usomList = document.getElementById('usom-list');
  const usomEmpty = document.getElementById('usom-empty');
  const usomSearch = document.getElementById('usom-search');
  const characterSprite = document.querySelector('.Character_spritesheet');
  const mascotBubble = document.getElementById('mascot-bubble');
  const mascotHost = document.querySelector('.header-mascot');
  const NEWS_READ_MAP_KEY = 'vtNewsReadMap';
  /** Mirror background.js cache keys so popup follows SW-only auto refresh (alarms). */
  const VT_NEWS_CACHE_KEY = 'vtNewsCache';
  const VT_NEWS_FETCHED_AT_KEY = 'vtNewsFetchedAt';
  const VT_USOM_CACHE_KEY = 'vtUsomCache';
  const VT_USOM_FETCHED_AT_KEY = 'vtUsomFetchedAt';
  const POPUP_ACTIVE_TAB_KEY = 'vtPopupActiveTab';
  /** Pending external scan; shown once then removed from storage. */
  const CONTEXT_SCAN_RESULT_KEY = 'vtContextScanResult';
  const COPY_SUMMARY_FIELDS_KEY = 'vtCopySummaryFields';
  const SCAN_PRESET_KEY = 'vtScanPreset';
  const SCAN_PRESETS_KEY = 'vtScanPresets';
  let scanPresets = utils.normalizeScanPresetsMap(null);

  let queueTimer = null;
  let lastResultPayload = null;
  let singleScanTimer = null;
  /** Bumped when a new scan starts; port/timeouts ignore callbacks from older sessions. */
  let scanSessionId = 0;
  /** Bumped when a recent entry open request starts; stale async callbacks are ignored. */
  let recentOpenRequestId = 0;
  let lastBatchExportRows = [];
  let lastBatchSummaryRows = [];
  let lastBatchSourceLines = [];
  let lastImportedFileName = '';
  let copyToastTimer = null;
  let scrollResultDelayTimer = null;
  let activeTab = 'scan';
  let newsLoading = false;
  let usomLoading = false;
  let lastNewsPayload = null;
  let lastUsomPayload = null;
  let newsSourceValue = 'all';
  let newsSearchValue = '';
  let usomSearchValue = '';
  let expandedUsomKey = '';
  let usomDetailCache = {};
  let newsReadMap = {};
  let newsNewKeys = {};
  let activeRecentTab = 'general';
  let copySummaryFields = null;
  let characterTurnTimer = null;
  let characterPauseTimer = null;
  let lastMascotBubbleIndex = -1;
  let nextBubbleKind = 'humor';
  let nextTechnicalCategoryIndex = 0;
  let batchUseAbuse = true;

  const MASCOT_BUBBLES = window.VT_MASCOT_BUBBLES || {
    tr: { humor: [], technical: {} },
    en: { humor: [], technical: {} }
  };

  // t: Popup içi yardımcı; çağrı bağlamı gövdede.
  function t(key, vars) {
    return VT_I18N.t(key, vars);
  }

  const defaultCopySummaryFields = utils.defaultCopySummaryFields;
  const copySummaryFieldKeys = utils.copySummaryFieldKeys;
  const normalizeCopySummaryFields = utils.normalizeCopySummaryFields;

  function safeJoinValues(values, fallback) {
    const list = Array.isArray(values)
      ? values
          .map(function (x) {
            return String(x || '').trim();
          })
          .filter(Boolean)
      : [];
    return list.length ? list.join(', ') : fallback;
  }

  function buildSummaryTemplateValues(payload) {
    const p = payload && typeof payload === 'object' ? payload : {};
    const stats = p.stats && typeof p.stats === 'object' ? p.stats : {};
    const totalEngines =
      (Number(stats.malicious) || 0) +
      (Number(stats.suspicious) || 0) +
      (Number(stats.undetected) || 0) +
      (Number(stats.harmless) || 0) +
      (Number(stats.timeout) || 0) +
      (Number(stats.failure) || 0);
    const tc = p.threatContext && typeof p.threatContext === 'object' ? p.threatContext : {};
    const abuse = p.abuseipdb && typeof p.abuseipdb === 'object' ? p.abuseipdb : {};
    const summary = VtSocUtils.buildSummaryLine(p, t);
    const tags =
      p.hero && Array.isArray(p.hero.tagChips)
        ? safeJoinValues(
            p.hero.tagChips.map(function (chip) {
              return chip && chip.value ? chip.value : '';
            }),
            '—'
          )
        : '—';
    const mitre =
      p.mitreTechniques && Array.isArray(p.mitreTechniques.ids)
        ? safeJoinValues(p.mitreTechniques.ids, '—')
        : '—';
    return {
      summary: summary,
      ioc: p.ioc ? String(p.ioc) : '',
      kind: p.iocKind ? String(p.iocKind) : '',
      threatLevel: p.threatLevel ? String(p.threatLevel) : 'clean',
      malicious: String(Number(stats.malicious) || 0),
      suspicious: String(Number(stats.suspicious) || 0),
      undetected: String(Number(stats.undetected) || 0),
      detectionRatio:
        totalEngines > 0
          ? String((Number(stats.malicious) || 0) + (Number(stats.suspicious) || 0)) +
            '/' +
            String(totalEngines)
          : '—',
      reputation:
        p.reputation !== undefined && p.reputation !== null && p.reputation !== ''
          ? String(p.reputation)
          : '—',
      suggestedThreat:
        tc.suggestedLabel && String(tc.suggestedLabel).trim()
          ? String(tc.suggestedLabel).trim()
          : '—',
      tags: tags,
      distinctLabels: safeJoinValues(
        Array.isArray(tc.distinctLabels)
          ? tc.distinctLabels.map(function (row) {
              return row && row.label ? row.label : '';
            })
          : [],
        '—'
      ),
      abuseScore:
        abuse.ok === true && abuse.score !== undefined && abuse.score !== null
          ? String(abuse.score)
          : '—',
      abuseReports:
        abuse.ok === true && abuse.totalReports !== undefined && abuse.totalReports !== null
          ? String(abuse.totalReports)
          : '—',
      mitre: mitre,
      time: new Date().toISOString(),
      reportLink: p.permalink ? String(p.permalink).trim() : '—'
    };
  }

  function enabledSummaryFieldsForKind(kind) {
    const cfg = normalizeCopySummaryFields(copySummaryFields);
    if (kind === 'ip' || kind === 'domain' || kind === 'url' || kind === 'file') {
      return cfg[kind];
    }
    return cfg.domain;
  }

  // clearElement: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function clearElement(el) {
    if (el) {
      el.replaceChildren();
    }
  }

  // appendFragment: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function appendFragment(parent, children) {
    const frag = document.createDocumentFragment();
    children.forEach(function (child) {
      frag.appendChild(child);
    });
    parent.appendChild(frag);
  }

  // applyPresetMap: Depodaki preset haritasını (v1/v2) belleğe yükler.
  function applyPresetMap(rawMap) {
    scanPresets = utils.migrateScanPresetsStorage(rawMap);
  }

  // syncPresetButtons: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function syncPresetButtons(activePreset) {
    const tipKeys = {
      quick: 'scanPresetQuickTip',
      detailed: 'scanPresetDetailedTip',
      analyst: 'scanPresetAnalystTip'
    };
    [presetQuick, presetDetailed, presetAnalyst].forEach(function (btn) {
      if (!btn) {
        return;
      }
      const id = btn.getAttribute('data-preset');
      const isActive = id === activePreset;
      btn.classList.toggle('is-active', isActive);
      btn.setAttribute('aria-pressed', isActive ? 'true' : 'false');
      const tipKey = tipKeys[id];
      if (tipKey) {
        const tip = t(tipKey);
        if (tip && tip !== tipKey) {
          btn.title = tip;
        }
      }
    });
  }

  // updateScanQuotaHint: Aktif preset + girişteki IoC türüne göre tahmini VT çağrısı.
  function updateScanQuotaHint(presetId) {
    if (!scanQuotaHint) {
      return;
    }
    chrome.storage.local.get([SCAN_PRESET_KEY, SCAN_PRESETS_KEY], function (data) {
      const active =
        presetId ||
        (data && typeof data[SCAN_PRESET_KEY] === 'string' ? data[SCAN_PRESET_KEY] : '') ||
        'quick';
      applyPresetMap(data[SCAN_PRESETS_KEY]);
      const detected = utils.detectIocKind(input ? input.value : '');
      const kind = detected !== 'unknown' ? detected : 'file';
      const profile = utils.resolvePresetForKind(scanPresets, active, kind);
      const n = utils.estimateVtCallsForPreset(profile, kind);
      const abuseN = utils.estimateAbuseCallsForPreset(profile, kind);
      const isSidepanel = document.documentElement.getAttribute('data-surface') === 'sidepanel';
      let fullHint;
      let shortHint;
      if (kind === 'ip' && abuseN > 0) {
        fullHint = t('scanQuotaHintIp', { vt: n, abuse: abuseN });
        shortHint = t('scanQuotaHintIpShort', { vt: n, abuse: abuseN });
      } else {
        fullHint = t('scanQuotaHint', { n: n });
        shortHint = t('scanQuotaHintShort', { n: n });
      }
      scanQuotaHint.textContent = isSidepanel ? shortHint : fullHint;
      if (isSidepanel) {
        scanQuotaHint.title = fullHint;
      } else {
        scanQuotaHint.removeAttribute('title');
      }
      scanQuotaHint.hidden = false;
    });
  }

  // applyScanPreset: Seçili modu kaydeder; VT ek sorguları tarama anında IoC türüne göre çözülür.
  function applyScanPreset(presetId, persistChoice) {
    if (!scanPresets[presetId]) {
      return;
    }
    syncPresetButtons(presetId);
    updateScanQuotaHint(presetId);
    if (persistChoice !== false) {
      chrome.storage.local.set({ [SCAN_PRESET_KEY]: presetId });
    }
  }

  /**
   * MV3: A cold service worker can cause "Receiving end does not exist" on the first message.
   * `chrome.runtime.lastError` must be read; transient errors get one short delayed retry.
   */
  // sendToBackground: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function sendToBackground(message, callback) {
    // attempt: Popup içi yardımcı; çağrı bağlamı gövdede.
    function attempt(n) {
      chrome.runtime.sendMessage(message, function (res) {
        var err = chrome.runtime.lastError;
        if (err) {
          var em = (err.message || '').toLowerCase();
          var transient =
            em.indexOf('receiving end') !== -1 ||
            em.indexOf('could not establish connection') !== -1;
          if (n < 1 && transient) {
            window.setTimeout(function () {
              attempt(n + 1);
            }, 100);
            return;
          }
          callback(undefined, err);
          return;
        }
        callback(res, undefined);
      });
    }
    attempt(0);
  }

  /**
   * MV3: Wake the service worker with a lightweight message before `runtime.connect`
   * so cold starts are less likely to drop the port handshake (single + batch scans).
   */
  // wakeServiceWorkerThen: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function wakeServiceWorkerThen(callback) {
    sendToBackground({ type: 'GET_QUEUE' }, function (_res, err) {
      callback(err);
    });
  }

  // getPopupTheme: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function getPopupTheme() {
    return document.documentElement.getAttribute('data-theme') === 'light'
      ? 'light'
      : 'dark';
  }

  // syncThemeToggleLabels: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function syncThemeToggleLabels() {
    if (!btnThemeToggle) {
      return;
    }
    const theme = getPopupTheme();
    btnThemeToggle.setAttribute(
      'aria-label',
      theme === 'light' ? t('themeSwitchToDark') : t('themeSwitchToLight')
    );
  }

  // setPopupTheme: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function setPopupTheme(theme, writeStorage) {
    const th = theme === 'light' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', th);
    const sun = document.querySelector('.theme-icon-sun');
    const moon = document.querySelector('.theme-icon-moon');
    if (sun && moon) {
      if (th === 'light') {
        sun.hidden = true;
        moon.hidden = false;
      } else {
        sun.hidden = false;
        moon.hidden = true;
      }
    }
    if (btnThemeToggle) {
      btnThemeToggle.setAttribute('aria-pressed', th === 'light' ? 'true' : 'false');
    }
    syncThemeToggleLabels();
    if (writeStorage) {
      chrome.storage.local.set({ vtPopupTheme: th });
    }
  }

  // updateScanCompactPreview: Kompakt şeritte IoC önizlemesini günceller.
  function updateScanCompactPreview() {
    if (!scanCompactPreview) {
      return;
    }
    const raw = input ? String(input.value || '').trim() : '';
    const firstLine =
      raw
        .split(/\r?\n/)
        .map(function (line) {
          return line.trim();
        })
        .filter(Boolean)[0] || '';
    if (firstLine) {
      scanCompactPreview.textContent =
        firstLine.length > 52 ? firstLine.slice(0, 49) + '…' : firstLine;
      scanCompactPreview.classList.remove('is-empty');
      return;
    }
    scanCompactPreview.textContent = t('scanCompactPreviewEmpty');
    scanCompactPreview.classList.add('is-empty');
  }

  // setScanInputExpanded: Tarama giriş kartını tam veya kompakt moda alır.
  function setScanInputExpanded(expanded) {
    if (!inputSurfaceCard) {
      return;
    }
    const isExpanded = expanded !== false;
    inputSurfaceCard.classList.toggle('is-compact', !isExpanded);
    inputSurfaceCard.setAttribute('data-scan-input-expanded', isExpanded ? 'true' : 'false');
    if (btnScanInputExpand) {
      btnScanInputExpand.hidden = isExpanded;
      btnScanInputExpand.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
      btnScanInputExpand.setAttribute('aria-label', t('scanInputCompactHint'));
    }
    if (input) {
      input.rows = 4;
      input.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
    }
    if (!isExpanded) {
      updateScanCompactPreview();
    }
  }

  // collapseScanInput: Sonuç odaklı görünüm için giriş alanını daraltır.
  function collapseScanInput() {
    setScanInputExpanded(false);
  }

  // dismissScanResultView: Sonuç kartını ve ilgili hata durumunu kapatır.
  function dismissScanResultView() {
    closeResult();
    hideError();
  }

  // expandScanInput: Yeni tarama için formu açar ve önceki sonucu kapatır.
  function expandScanInput() {
    dismissScanResultView();
    if (batchWrap) {
      batchWrap.hidden = true;
    }
    if (btnBatchDownload) {
      btnBatchDownload.hidden = true;
    }
    setFileActionMode('load');
    setScanInputExpanded(true);
    if (input) {
      input.focus();
    }
  }

  // applyPopupLang: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function applyPopupLang() {
    utils.applyI18n(document, t, { titleKey: 'popupTitle' });
    if (btnScanInputExpand) {
      btnScanInputExpand.setAttribute('aria-label', t('scanInputCompactHint'));
    }
    if (inputSurfaceCard && inputSurfaceCard.classList.contains('is-compact')) {
      updateScanCompactPreview();
    }
    if (btnResultClose) {
      btnResultClose.setAttribute('aria-label', t('closeResult'));
    }
    syncFileActionButtonLabel();
    updateQueueBadge();
    refreshConnStatusLabels();
    syncThemeToggleLabels();
    if (lastResultPayload && (!batchWrap || batchWrap.hidden)) {
      renderResult(lastResultPayload, { preserveScroll: true });
    }
    if (lastNewsPayload) {
      renderNews(lastNewsPayload);
    }
    loadBatchHistoryList();
  }

  // refreshConnStatusLabels: Arayüz yardımcısı; gövde içinde kullanım ayrıntıları.
  function refreshConnStatusLabels() {
    if (!connStatus || connStatus.hidden) {
      return;
    }
    if (connStatus.classList.contains('conn-status-ok')) {
      connStatus.textContent = t('popupConnOk');
    } else if (connStatus.classList.contains('conn-status-bad')) {
      connStatus.textContent = t('popupConnFail');
    } else if (connStatus.classList.contains('conn-status-checking')) {
      connStatus.textContent = t('popupConnChecking');
    }
  }

  // runAutoConnectionTest: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function runAutoConnectionTest() {
    if (!connStatus) {
      return;
    }
    chrome.storage.local.get(['vtApiKey'], function (data) {
      if (chrome.runtime.lastError) {
        return;
      }
      const key = data.vtApiKey && String(data.vtApiKey).trim();
      if (!key) {
        connStatus.hidden = true;
        connStatus.textContent = '';
        connStatus.className = 'conn-status';
        return;
      }
      connStatus.hidden = false;
      connStatus.textContent = t('popupConnChecking');
      connStatus.className = 'conn-status conn-status-checking';
      sendToBackground({ type: 'TEST_VT_CONNECTION', apiKey: '' }, function (res, err) {
        if (!connStatus) {
          return;
        }
        if (err || !res || !res.ok) {
          connStatus.textContent = t('popupConnFail');
          connStatus.className = 'conn-status conn-status-bad';
        } else {
          connStatus.textContent = t('popupConnOk');
          connStatus.className = 'conn-status conn-status-ok';
        }
      });
    });
  }

  // syncLangToggleLabel: Dil düğmesinde EN/TR kısaltmasını gösterir.
  function syncLangToggleLabel() {
    if (!langToggleLabel) {
      return;
    }
    langToggleLabel.textContent = VT_I18N.lang() === 'tr' ? 'TR' : 'EN';
  }

  // setUiLang: Arayüz dilini değiştirir; isteğe bağlı depolamaya yazar.
  function setUiLang(lang, persist) {
    const v = lang === 'tr' ? 'tr' : 'en';
    VT_I18N.setLang(v);
    syncLangToggleLabel();
    if (!persist) {
      return;
    }
    chrome.storage.local.set({ vtUiLang: v }, function () {
      if (chrome.runtime.lastError) {
        return;
      }
      applyPopupLang();
      loadRecentList();
    });
  }

  // openOptions: Popup içi yardımcı; çağrı bağlamı gövdede.
  function openOptions() {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open(chrome.runtime.getURL('options.html'));
    }
  }

  // pickMascotBubbleText: Arayüz yardımcısı; gövde içinde kullanım ayrıntıları.
  function pickMascotBubbleText() {
    const lang = VT_I18N.lang && VT_I18N.lang() === 'tr' ? 'tr' : 'en';
    const packs = MASCOT_BUBBLES[lang] || MASCOT_BUBBLES.en;
    const humorPool = Array.isArray(packs.humor) ? packs.humor : [];
    const technicalGroups = packs.technical && typeof packs.technical === 'object' ? packs.technical : {};
    const technicalKeys = Object.keys(technicalGroups).filter(function (k) {
      return Array.isArray(technicalGroups[k]) && technicalGroups[k].length > 0;
    });
    const shouldShowTechnical = nextBubbleKind === 'technical' && technicalKeys.length > 0;
    let pool = humorPool;
    if (shouldShowTechnical) {
      const key = technicalKeys[nextTechnicalCategoryIndex % technicalKeys.length];
      pool = technicalGroups[key];
      nextTechnicalCategoryIndex = (nextTechnicalCategoryIndex + 1) % technicalKeys.length;
      nextBubbleKind = 'humor';
    } else {
      nextBubbleKind = technicalKeys.length > 0 ? 'technical' : 'humor';
    }
    if (!pool.length) {
      return '';
    }
    if (pool.length === 1) {
      lastMascotBubbleIndex = 0;
      return pool[0];
    }
    let idx = Math.floor(Math.random() * pool.length);
    if (idx === lastMascotBubbleIndex) {
      idx = (idx + 1) % pool.length;
    }
    lastMascotBubbleIndex = idx;
    return pool[idx];
  }

  // refreshMascotBubbleText: Arayüz yardımcısı; gövde içinde kullanım ayrıntıları.
  function refreshMascotBubbleText() {
    if (!mascotBubble) {
      return;
    }
    mascotBubble.textContent = pickMascotBubbleText();
  }

  // setLoading: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function setLoading(on) {
    btnScan.disabled = on;
    if (input) {
      input.setAttribute('aria-busy', on ? 'true' : 'false');
    }
  }

  // clearSingleScanTimer: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function clearSingleScanTimer() {
    if (singleScanTimer !== null) {
      window.clearTimeout(singleScanTimer);
      singleScanTimer = null;
    }
  }

  // hideError: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function hideError() {
    errorMsg.hidden = true;
    errorMsg.textContent = '';
  }

  // resetScanPanelOnOpen: Popup/side panel her açılışında varsayılan tarama görünümü.
  function resetScanPanelOnOpen() {
    setScanInputExpanded(true);
    dismissScanResultView();
    if (batchWrap) {
      batchWrap.hidden = true;
    }
    if (btnBatchDownload) {
      btnBatchDownload.hidden = true;
    }
    setFileActionMode('load');
  }

  // showPendingContextScan: Bekleyen dış tarama sonucunu gösterir.
  function showPendingContextScan(row) {
    if (!row || typeof row !== 'object' || !row.payload) {
      return;
    }
    if (batchWrap) {
      batchWrap.hidden = true;
    }
    const iocText =
      row.ioc ||
      (row.payload && row.payload.ioc ? String(row.payload.ioc) : '');
    if (input && iocText) {
      input.value = iocText;
    }
    const payload = row.payload;
    if (payload.ok) {
      renderResult(payload);
      return;
    }
    dismissScanResultView();
    if (payload.error) {
      showError(resolveErrorMessage(payload));
      collapseScanInput();
    }
  }

  // consumePendingContextScan: Dış taramayı bir kez gösterir, storage'dan siler.
  function consumePendingContextScan(row) {
    if (!row || typeof row !== 'object' || !row.payload) {
      return;
    }
    showPendingContextScan(row);
    chrome.storage.local.remove(CONTEXT_SCAN_RESULT_KEY);
  }

  // closeResult: Tarama sonucu kartını gizler.
  function closeResult() {
    if (resultWrap) {
      resultWrap.hidden = true;
    }
    if (resultCard) {
      resultCard.hidden = false;
    }
    lastResultPayload = null;
    syncAbuseCardVisibility(null);
  }

  // resolveErrorMessage: VT errorKey veya ham metinden kullanıcı mesajı.
  function resolveErrorMessage(source) {
    if (source && typeof source === 'object') {
      if (source.errorKey) {
        const msg = t(source.errorKey, source.errorVars || {});
        if (msg && msg !== source.errorKey) {
          return msg;
        }
      }
      if (source.error) {
        return String(source.error);
      }
    }
    if (typeof source === 'string' && source) {
      return source;
    }
    return t('errorScanFailed');
  }

  // showError: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function showError(text) {
    errorMsg.textContent = resolveErrorMessage(
      typeof text === 'object' ? text : { error: text }
    );
    errorMsg.hidden = false;
    resultWrap.hidden = true;
  }

  // formatNewsDate: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function formatNewsDate(raw) {
    if (!raw) {
      return '';
    }
    const d = new Date(raw);
    if (!isFinite(d.getTime())) {
      return String(raw);
    }
    return d.toLocaleString();
  }

  // setStatusMessage: Ortak status etiketi güncelleme yardımcı fonksiyonu.
  function setStatusMessage(node, message, isError) {
    if (!node) {
      return;
    }
    node.hidden = !message;
    node.textContent = message || '';
    node.classList.toggle('is-error', !!isError);
  }

  // setNewsStatus: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function setNewsStatus(message, isError) {
    setStatusMessage(newsStatus, message, isError);
  }

  // setUsomStatus: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function setUsomStatus(message, isError) {
    setStatusMessage(usomStatus, message, isError);
  }

  // usomItemKey: USOM olay listesi veya detay isteği.
  function usomItemKey(item) {
    if (!item || typeof item !== 'object') {
      return '';
    }
    if (item.id) {
      return 'id:' + String(item.id);
    }
    if (item.slug) {
      return 'slug:' + String(item.slug);
    }
    const title = String(item.title || '').trim();
    const date = String(item.date || '').trim();
    const link = String(item.link || '').trim();
    const fallback = [title, date, link].filter(Boolean).join('|');
    return 'fallback:' + (fallback || JSON.stringify(item));
  }

  // sanitizeUsomHtml: USOM olay listesi veya detay isteği.
  function sanitizeUsomHtml(rawHtml) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(String(rawHtml || ''), 'text/html');
    const allowed = {
      P: true,
      BR: true,
      A: true,
      UL: true,
      OL: true,
      LI: true,
      STRONG: true,
      B: true,
      EM: true,
      I: true,
      H3: true,
      H4: true
    };
    // walk: Popup içi yardımcı; çağrı bağlamı gövdede.
    function walk(node) {
      const children = Array.prototype.slice.call(node.childNodes || []);
      children.forEach(function (child) {
        if (child.nodeType !== Node.ELEMENT_NODE) {
          return;
        }
        if (!allowed[child.tagName]) {
          const text = doc.createTextNode(child.textContent || '');
          child.replaceWith(text);
          return;
        }
        const attrs = Array.prototype.slice.call(child.attributes || []);
        attrs.forEach(function (attr) {
          const name = String(attr.name || '').toLowerCase();
          if (child.tagName === 'A' && name === 'href') {
            const href = String(attr.value || '').trim();
            if (/^https?:\/\//i.test(href)) {
              child.setAttribute('target', '_blank');
              child.setAttribute('rel', 'noopener noreferrer');
            } else {
              child.removeAttribute('href');
            }
            return;
          }
          child.removeAttribute(attr.name);
        });
        walk(child);
      });
    }
    walk(doc.body);
    return doc.body.innerHTML;
  }

  // normalizeExternalHttpUrl: Sadece http/https dış linklerini kabul eder.
  function normalizeExternalHttpUrl(rawUrl) {
    const href = String(rawUrl || '').trim();
    if (!href) {
      return '#';
    }
    try {
      const parsed = new URL(href);
      if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
        return parsed.href;
      }
    } catch (_) {}
    return '#';
  }

  // usomHtmlToPlainText: USOM olay listesi veya detay isteği.
  function usomHtmlToPlainText(rawHtml) {
    const parser = new DOMParser();
    const doc = parser.parseFromString(String(rawHtml || ''), 'text/html');
    return String((doc.body && doc.body.textContent) || '')
      .replace(/\s+\n/g, '\n')
      .replace(/\n{3,}/g, '\n\n')
      .trim();
  }

  // fillUsomItemDetail: USOM olay listesi veya detay isteği.
  function fillUsomItemDetail(detailNode, item) {
    if (!detailNode) {
      return;
    }
    detailNode.innerHTML = '';
    const copyBtn = document.createElement('button');
    copyBtn.type = 'button';
    copyBtn.className = 'usom-copy-btn';
    copyBtn.textContent = '⧉';
    copyBtn.title = t('usomCopyAlert');
    copyBtn.setAttribute('aria-label', t('usomCopyAlert'));
    copyBtn.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      const title = item && item.title ? String(item.title) : '';
      const date = item && item.date ? String(item.date) : '';
      const tags = item && Array.isArray(item.tags) && item.tags.length ? item.tags.join(', ') : '';
      const body = usomHtmlToPlainText(item && item.desc ? item.desc : '');
      const fullText = [
        title ? 'Title: ' + title : '',
        date ? 'Date: ' + date : '',
        tags ? 'Tags: ' + tags : '',
        body
      ].filter(Boolean).join('\n\n');
      copyToClipboard(fullText)
        .then(function () {
          showCopyToast(t('usomCopyDone'));
        })
        .catch(function () {});
    });

    const body = document.createElement('div');
    body.className = 'usom-item-detail-body';
    body.innerHTML = sanitizeUsomHtml(item && item.desc ? item.desc : '');

    detailNode.appendChild(copyBtn);
    detailNode.appendChild(body);
  }

  // loadUsomDetailInto: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function loadUsomDetailInto(item, detailNode) {
    if (!item || !detailNode) return;
    const key = usomItemKey(item);
    if (key && usomDetailCache[key]) {
      fillUsomItemDetail(detailNode, usomDetailCache[key]);
      return;
    }
    fillUsomItemDetail(detailNode, item);
    sendToBackground(
      { type: 'GET_USOM_DETAIL', id: item.id, slug: item.slug },
      function (res, err) {
        if (err || !res || !res.ok || !res.item) {
          return;
        }
        if (key) {
          usomDetailCache[key] = res.item;
        }
        fillUsomItemDetail(detailNode, res.item);
      }
    );
  }

  // renderUsom: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function renderUsom(payload) {
    if (!usomList || !usomEmpty || !usomUpdatedAt) {
      return;
    }
    lastUsomPayload = payload || null;
    const allItems = payload && Array.isArray(payload.items) ? payload.items : [];
    const q = usomSearchValue.trim().toLowerCase();
    const items = allItems.filter(function (item) {
      if (!q) {
        return true;
      }
      const title = String(item && item.title ? item.title : '').toLowerCase();
      const tags = Array.isArray(item && item.tags) ? item.tags.join(' ').toLowerCase() : '';
      return title.indexOf(q) !== -1 || tags.indexOf(q) !== -1;
    });

    clearElement(usomList);
    if (!items.length) {
      usomEmpty.hidden = false;
      expandedUsomKey = '';
    } else {
      usomEmpty.hidden = true;
      const rows = [];
      items.forEach(function (item) {
        const key = usomItemKey(item);
        const li = document.createElement('li');
        li.className = 'usom-item';
        const title = document.createElement('p');
        title.className = 'usom-item-title';
        title.textContent = item.title || '';
        const meta = document.createElement('p');
        meta.className = 'usom-item-meta';
        meta.textContent = [formatNewsDate(item.date), (item.tags || []).slice(0, 3).join(', ')]
          .filter(Boolean)
          .join(' · ');
        const detail = document.createElement('div');
        detail.className = 'usom-item-detail';
        detail.hidden = true;
        li.appendChild(title);
        li.appendChild(meta);
        li.appendChild(detail);
        if (expandedUsomKey && expandedUsomKey === key) {
          li.classList.add('is-expanded');
          detail.hidden = false;
          loadUsomDetailInto(item, detail);
        }
        li.addEventListener('click', function () {
          const isExpanded = !detail.hidden;
          if (isExpanded) {
            detail.hidden = true;
            li.classList.remove('is-expanded');
            if (expandedUsomKey === key) {
              expandedUsomKey = '';
            }
            return;
          }
          expandedUsomKey = key;
          renderUsom(lastUsomPayload || payload);
        });
        rows.push(li);
      });
      appendFragment(usomList, rows);
    }

    if (payload && payload.fetchedAt) {
      usomUpdatedAt.textContent = t('usomUpdatedAt', { time: formatNewsDate(payload.fetchedAt) });
    } else {
      usomUpdatedAt.textContent = '';
    }
    if (payload && payload.warning && (payload.cached || payload.stale)) {
      setUsomStatus(t('usomUsingCache'), false);
    } else {
      setUsomStatus('', false);
    }
  }

  // loadUsom: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function loadUsom(forceRefresh) {
    if (usomLoading) {
      return;
    }
    usomLoading = true;
    if (btnUsomRefresh) {
      btnUsomRefresh.disabled = true;
    }
    setUsomStatus(t('usomLoading'), false);
    sendToBackground(
      { type: forceRefresh ? 'REFRESH_USOM' : 'GET_USOM' },
      function (res, err) {
        usomLoading = false;
        if (btnUsomRefresh) {
          btnUsomRefresh.disabled = false;
        }
        if (err || !res || !res.ok) {
          setUsomStatus(t('usomErrorLoad'), true);
          return;
        }
        renderUsom(res);
      }
    );
  }

  const NEWS_SOURCE_CLASS_BY_NAME = {
    BleepingComputer: 'bleepingcomputer',
    CyberScoop: 'cyberscoop',
    'Krebs on Security': 'krebs-on-security',
    'The Hacker News': 'the-hacker-news',
    SecurityWeek: 'securityweek',
    'Dark Reading': 'dark-reading'
  };

  // newsSourceClassName: Haber kaynağı etiketi için renk sınıfını döndürür.
  function newsSourceClassName(source) {
    const name = String(source || '').trim();
    const slug = NEWS_SOURCE_CLASS_BY_NAME[name] || 'news';
    return 'news-item-source news-item-source--' + slug;
  }

  // newsItemKey: Haber RSS çekimi, ayrıştırma veya önbellek yolu.
  function newsItemKey(item) {
    const link = item && item.link ? String(item.link).trim() : '';
    const title = item && item.title ? String(item.title).trim() : '';
    return (link || title).slice(0, 1200);
  }

  // saveNewsReadMap: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function saveNewsReadMap() {
    chrome.storage.local.set({ [NEWS_READ_MAP_KEY]: newsReadMap });
  }

  // markNewsItemRead: Haber RSS çekimi, ayrıştırma veya önbellek yolu.
  function markNewsItemRead(item) {
    const key = newsItemKey(item);
    if (!key || newsReadMap[key]) {
      return;
    }
    newsReadMap[key] = true;
    if (newsNewKeys[key]) {
      delete newsNewKeys[key];
    }
    saveNewsReadMap();
  }

  // renderNews: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function renderNews(payload) {
    if (!newsList || !newsEmpty || !newsUpdatedAt) {
      return;
    }
    lastNewsPayload = payload || null;
    const allItems = payload && Array.isArray(payload.items) ? payload.items : [];
    if (newsSourceFilter) {
      const seen = { all: true };
      const current = newsSourceFilter.value || 'all';
      allItems.forEach(function (item) {
        const src = String(item && item.source ? item.source : '').trim();
        if (src) {
          seen[src] = true;
        }
      });
      clearElement(newsSourceFilter);
      const optAll = document.createElement('option');
      optAll.value = 'all';
      optAll.textContent = t('newsSourceAll');
      const sourceOptions = [optAll];
      Object.keys(seen)
        .filter(function (k) {
          return k !== 'all';
        })
        .sort()
        .forEach(function (src) {
          const opt = document.createElement('option');
          opt.value = src;
          opt.textContent = src;
          sourceOptions.push(opt);
        });
      appendFragment(newsSourceFilter, sourceOptions);
      newsSourceValue = seen[current] ? current : 'all';
      newsSourceFilter.value = newsSourceValue;
    }
    const filterVal = newsSourceFilter ? newsSourceFilter.value : 'all';
    const searched = allItems.filter(function (item) {
      return filterVal === 'all' || String(item.source || '') === filterVal;
    });
    const q = newsSearchValue.trim().toLowerCase();
    const searchFiltered = searched.filter(function (item) {
      if (!q) {
        return true;
      }
      return String(item.title || '').toLowerCase().indexOf(q) !== -1;
    });
    const items = searchFiltered.slice().sort(function (a, b) {
      const ta = Date.parse(a.pubDate || '') || 0;
      const tb = Date.parse(b.pubDate || '') || 0;
      return tb - ta;
    });
    clearElement(newsList);
    if (!items.length) {
      newsEmpty.hidden = false;
    } else {
      newsEmpty.hidden = true;
      const newsRows = [];
      items.forEach(function (item) {
        const li = document.createElement('li');
        li.className = 'news-item';
        const itemKey = newsItemKey(item);
        const isRead = !!(itemKey && newsReadMap[itemKey]);
        const isNew = !!(itemKey && newsNewKeys[itemKey] && !isRead);
        if (isRead) {
          li.classList.add('is-read');
        }
        const link = document.createElement('a');
        link.className = 'news-item-link';
        link.href = normalizeExternalHttpUrl(item.link);
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.textContent = item.title || '';
        link.addEventListener('click', function () {
          markNewsItemRead(item);
          renderNews(lastNewsPayload);
        });
        const meta = document.createElement('span');
        meta.className = 'news-item-meta';
        const date = document.createElement('span');
        date.className = 'news-item-date';
        date.textContent = formatNewsDate(item.pubDate || '');
        const source = document.createElement('span');
        const sourceName = String(item.source || '').trim();
        source.className = newsSourceClassName(sourceName);
        source.textContent = sourceName;
        if (isNew) {
          const badge = document.createElement('span');
          badge.className = 'news-item-badge-new';
          badge.textContent = t('newsBadgeNew');
          meta.appendChild(badge);
        }
        meta.appendChild(date);
        meta.appendChild(source);
        li.appendChild(link);
        li.appendChild(meta);
        newsRows.push(li);
      });
      appendFragment(newsList, newsRows);
    }
    if (payload && payload.fetchedAt) {
      newsUpdatedAt.textContent = t('newsUpdatedAt', {
        time: formatNewsDate(payload.fetchedAt)
      });
    } else {
      newsUpdatedAt.textContent = '';
    }
    if (payload && payload.warning && (payload.cached || payload.stale)) {
      setNewsStatus(t('newsUsingCache'), false);
    } else {
      setNewsStatus('', false);
    }
  }

  // loadNews: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function loadNews(forceRefresh, autoRefresh) {
    if (newsLoading) {
      return;
    }
    newsLoading = true;
    if (btnNewsRefresh) {
      btnNewsRefresh.disabled = true;
    }
    setNewsStatus(t('newsLoading'), false);
    sendToBackground(
      {
        type: forceRefresh ? 'REFRESH_NEWS' : 'GET_NEWS',
        autoRefresh: forceRefresh && autoRefresh === true
      },
      function (res, err) {
      newsLoading = false;
      if (btnNewsRefresh) {
        btnNewsRefresh.disabled = false;
      }
      if (err || !res || !res.ok) {
        setNewsStatus(t('newsErrorLoad'), true);
        return;
      }
      if (
        lastNewsPayload &&
        Array.isArray(lastNewsPayload.items) &&
        Array.isArray(res.items)
      ) {
        const prevKeys = {};
        lastNewsPayload.items.forEach(function (item) {
          const key = newsItemKey(item);
          if (key) {
            prevKeys[key] = true;
          }
        });
        newsNewKeys = {};
        res.items.forEach(function (item) {
          const key = newsItemKey(item);
          if (key && !prevKeys[key]) {
            newsNewKeys[key] = true;
          }
        });
      }
      renderNews(res);
      }
    );
  }

  // setActiveTab: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function setActiveTab(nextTab, persist) {
    const prevTab = activeTab;
    const next = nextTab === 'news' ? 'news' : nextTab === 'usom' ? 'usom' : 'scan';
    activeTab = next;
    if (characterSprite) {
      if (characterTurnTimer) {
        window.clearTimeout(characterTurnTimer);
        characterTurnTimer = null;
      }
      if (characterPauseTimer) {
        window.clearTimeout(characterPauseTimer);
        characterPauseTimer = null;
      }
      characterSprite.classList.remove('is-turning');
      characterSprite.classList.remove('face-down', 'face-right', 'face-up', 'face-left');
      const tabOrder = { scan: 0, news: 1, usom: 2 };
      let turnFace = 'face-down';
      if (tabOrder[next] > tabOrder[prevTab]) {
        turnFace = 'face-right';
      } else if (tabOrder[next] < tabOrder[prevTab]) {
        turnFace = 'face-left';
      }
      characterSprite.classList.add('is-turning');
      characterSprite.classList.add('is-paused');
      characterPauseTimer = window.setTimeout(function () {
        characterSprite.classList.remove('is-paused');
        characterSprite.classList.remove('face-down', 'face-right', 'face-up', 'face-left');
        characterSprite.classList.add(turnFace);
        characterTurnTimer = window.setTimeout(function () {
          characterSprite.classList.remove('face-down', 'face-right', 'face-up', 'face-left');
          characterSprite.classList.add('face-down');
          characterSprite.classList.remove('is-turning');
          characterTurnTimer = null;
        }, 260);
        characterPauseTimer = null;
      }, 110);
    }
    if (tabScan) {
      tabScan.classList.toggle('is-active', activeTab === 'scan');
      tabScan.setAttribute('aria-pressed', activeTab === 'scan' ? 'true' : 'false');
    }
    if (tabNews) {
      tabNews.classList.toggle('is-active', activeTab === 'news');
      tabNews.setAttribute('aria-pressed', activeTab === 'news' ? 'true' : 'false');
    }
    if (tabUsom) {
      tabUsom.classList.toggle('is-active', activeTab === 'usom');
      tabUsom.setAttribute('aria-pressed', activeTab === 'usom' ? 'true' : 'false');
    }
    if (panelScan) {
      panelScan.hidden = activeTab !== 'scan';
    }
    if (panelNews) {
      panelNews.hidden = activeTab !== 'news';
    }
    if (panelUsom) {
      panelUsom.hidden = activeTab !== 'usom';
    }
    if (activeTab === 'news') {
      loadNews(false);
    }
    if (activeTab === 'usom') {
      loadUsom(false);
    }
    if (persist !== false) {
      chrome.storage.local.set({ [POPUP_ACTIVE_TAB_KEY]: activeTab });
    }
  }

  // showCopyToast: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function showCopyToast(message) {
    if (!copyToast) {
      return;
    }
    copyToast.textContent = message || '';
    copyToast.hidden = false;
    if (copyToastTimer !== null) {
      window.clearTimeout(copyToastTimer);
    }
    copyToastTimer = window.setTimeout(function () {
      copyToastTimer = null;
      copyToast.hidden = true;
      copyToast.textContent = '';
    }, 2000);
  }

  // copyToClipboard: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function copyToClipboard(text) {
    const val = String(text || '');
    function fallbackCopy() {
      return new Promise(function (resolve, reject) {
        try {
          if (!document.body) {
            reject(new Error('copy_failed'));
            return;
          }
          const ta = document.createElement('textarea');
          ta.value = val;
          ta.style.position = 'fixed';
          ta.style.left = '-9999px';
          document.body.appendChild(ta);
          ta.select();
          const ok = document.execCommand('copy');
          document.body.removeChild(ta);
          if (!ok) {
            reject(new Error('copy_failed'));
            return;
          }
          resolve();
        } catch (err) {
          reject(err);
        }
      });
    }
    // Fallback for contexts where the Clipboard API is unavailable.
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      return navigator.clipboard.writeText(val).catch(function () {
        return fallbackCopy();
      });
    }
    return fallbackCopy();
  }

  // threatLabelFromLevel: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function threatLabelFromLevel(level) {
    if (level === 'malicious') {
      return t('threatMalicious');
    }
    if (level === 'suspicious') {
      return t('threatSuspicious');
    }
    return t('threatClean');
  }

  // suggestedLabelInHero: Konsensüs etiketi hero chip’lerinde mi?
  function suggestedLabelInHero(payload) {
    const chips = payload && payload.hero && payload.hero.chips;
    if (!Array.isArray(chips)) {
      return false;
    }
    return chips.some(function (c) {
      return c && c.type === 'label' && c.value;
    });
  }

  // threatContextHasExtraContent: Grafik dışında gösterilecek VT consensus içeriği var mı?
  function threatContextHasExtraContent(tc, payload) {
    if (!tc || typeof tc !== 'object') {
      return false;
    }
    const hasLabel = !!(tc.suggestedLabel && String(tc.suggestedLabel).trim()) && !suggestedLabelInHero(payload);
    const hasLists =
      (tc.popularNames && tc.popularNames.length > 0) ||
      (tc.popularCategories && tc.popularCategories.length > 0) ||
      (payload.extendedThreatLabels && tc.distinctLabels && tc.distinctLabels.length > 0);
    return hasLabel || hasLists;
  }

  // engineTotals: VT motor özet sayıları.
  function engineTotals(stats) {
    const s = stats || {};
    const mal = Number(s.malicious) || 0;
    const susp = Number(s.suspicious) || 0;
    const und = Number(s.undetected) || 0;
    const harmless = Number(s.harmless) || 0;
    const timeout = Number(s.timeout) || 0;
    const failure = Number(s.failure) || 0;
    const sum = mal + susp + und + harmless + timeout + failure;
    return {
      mal: mal,
      susp: susp,
      und: und,
      other: harmless + timeout + failure,
      sum: sum,
      detected: mal + susp
    };
  }

  function vtThreatFromStats(stats) {
    const totals = engineTotals(stats);
    if (totals.mal > 0) {
      return 'malicious';
    }
    if (totals.susp > 0) {
      return 'suspicious';
    }
    return 'clean';
  }

  function setProviderPill(el, text, levelClass) {
    if (!el) {
      return;
    }
    if (!text) {
      el.hidden = true;
      el.textContent = '';
      return;
    }
    el.hidden = false;
    el.textContent = text;
    el.className = 'result-provider-pill' + (levelClass ? ' is-' + levelClass : '');
  }

  function abuseTierClass(score) {
    const tier = utils.abuseScoreToRiskTier(score);
    return tier === 'unknown' ? 'neutral' : tier === 'low' ? 'clean' : tier === 'medium' ? 'suspicious' : tier === 'high' ? 'suspicious' : tier === 'critical' ? 'malicious' : 'neutral';
  }

  function isIpScanPayload(payload) {
    return !!(payload && payload.iocKind === 'ip');
  }

  // AbuseIPDB kartı yalnızca IP taramalarında gösterilir.
  function syncAbuseCardVisibility(payload) {
    const show = isIpScanPayload(payload);
    if (resultThreatDashboard) {
      resultThreatDashboard.classList.toggle('is-ip-scan', show);
      if (payload && payload.iocKind) {
        resultThreatDashboard.setAttribute('data-ioc-kind', payload.iocKind);
      } else {
        resultThreatDashboard.removeAttribute('data-ioc-kind');
      }
    }
    if (resultAbuseCard) {
      resultAbuseCard.hidden = !show;
      if (show) {
        resultAbuseCard.removeAttribute('aria-hidden');
      } else {
        resultAbuseCard.setAttribute('aria-hidden', 'true');
      }
    }
    if (!show) {
      if (resultAbuseBlock) {
        clearElement(resultAbuseBlock);
      }
      setProviderPill(resultAbusePill, '', '');
    }
  }

  function updateHybridVerdict(payload) {
    if (!resultVerdict || !payload) {
      return;
    }
    const combined = payload.threatLevel || 'neutral';
    resultVerdict.className = 'result-verdict is-' + combined;
    if (payload.iocKind === 'ip') {
      const vtLevel = payload.threatLevelVt || vtThreatFromStats(payload.stats);
      const abuse = payload.abuseipdb;
      /* Kartlarda VT/Abuse ayrıntısı var; hero’da yalnızca birleşik seviye (taşma önlenir). */
      resultVerdict.textContent = threatLabelFromLevel(combined);
      setProviderPill(resultVtPill, threatLabelFromLevel(vtLevel), vtLevel);
      if (abuse && abuse.ok === true && abuse.score != null && isFinite(abuse.score)) {
        setProviderPill(resultAbusePill, abuse.score + '/100', abuseTierClass(abuse.score));
      } else if (abuse && abuse.error === 'not_configured') {
        setProviderPill(resultAbusePill, t('abuseNotConfiguredShort'), 'neutral');
      } else {
        setProviderPill(resultAbusePill, '', '');
      }
      return;
    }
    resultVerdict.textContent = threatLabelFromLevel(combined);
    setProviderPill(resultVtPill, '', '');
    setProviderPill(resultAbusePill, '', '');
  }

  // renderResultChart: Motor dağılımı ve özet metrikleri.
  function renderResultChart(stats, threatLevel) {
    const totals = engineTotals(stats);
    if (!resultChart || !resultChartBar) {
      return false;
    }
    if (totals.sum <= 0) {
      resultChart.hidden = true;
      clearElement(resultChartBar);
      if (resultChartLegend) {
        resultChartLegend.textContent = '';
      }
      if (resultVtEmpty) {
        resultVtEmpty.hidden = false;
      }
      return false;
    }
    resultChart.hidden = false;
    if (resultVtEmpty) {
      resultVtEmpty.hidden = true;
    }

    if (resultChartRatio) {
      clearElement(resultChartRatio);
      const lead = document.createElement('span');
      lead.className = 'result-chart-stat-lead';
      lead.textContent = t('chartRatioLine', {
        d: totals.detected,
        sum: totals.sum
      });
      resultChartRatio.appendChild(lead);
      [
        { cls: 'is-mal', label: t('statMalShort'), val: totals.mal, seg: 'mal' },
        { cls: 'is-susp', label: t('statSuspShort'), val: totals.susp, seg: 'susp' },
        { cls: 'is-und', label: t('statUndShort'), val: totals.und, seg: 'und' },
        { cls: 'is-other', label: t('statOtherShort'), val: totals.other, seg: 'other' }
      ].forEach(function (m) {
        if (m.val <= 0 && m.seg === 'other') {
          return;
        }
        const chip = document.createElement('span');
        chip.className = 'result-chart-stat ' + m.cls;
        const lab = document.createElement('span');
        lab.className = 'result-chart-stat-label';
        lab.textContent = m.label;
        const num = document.createElement('span');
        num.className = 'result-chart-stat-val';
        num.textContent = String(m.val);
        chip.appendChild(lab);
        chip.appendChild(num);
        resultChartRatio.appendChild(chip);
      });
    }

    const pct = function (n) {
      return Math.max(0, Math.min(100, (n / totals.sum) * 100));
    };
    const segments = [
      { key: 'mal', count: totals.mal, pct: pct(totals.mal) },
      { key: 'susp', count: totals.susp, pct: pct(totals.susp) },
      { key: 'und', count: totals.und, pct: pct(totals.und) },
      { key: 'other', count: totals.other, pct: pct(totals.other) }
    ].filter(function (seg) {
      return seg.count > 0;
    });

    clearElement(resultChartBar);
    const barNodes = segments.map(function (seg) {
      const el = document.createElement('span');
      el.className = 'result-chart-seg is-' + seg.key;
      el.style.flexGrow = String(seg.count);
      el.style.flexBasis = seg.pct.toFixed(2) + '%';
      el.title =
        t('chartSeg_' + seg.key) + ': ' + seg.count + ' (' + Math.round(seg.pct) + '%)';
      return el;
    });
    appendFragment(resultChartBar, barNodes);

    if (resultChartLegend) {
      resultChartLegend.textContent = segments
        .map(function (seg) {
          return t('chartSeg_' + seg.key) + ' ' + Math.round(seg.pct) + '%';
        })
        .join(' · ');
    }

    const flaggedPct = Math.round(pct(totals.detected));
    resultChartBar.setAttribute('aria-valuenow', String(flaggedPct));
    resultChartBar.setAttribute(
      'aria-label',
      t('chartBarAria', {
        d: totals.detected,
        sum: totals.sum,
        mal: totals.mal,
        susp: totals.susp
      })
    );
    return true;
  }

  function renderThreatDashboard(payload) {
    const isIp = isIpScanPayload(payload);
    syncAbuseCardVisibility(payload);
    const hasVt = renderResultChart(payload.stats, payload.threatLevel);
    const hasAbuseData = isIp && !!payload.abuseipdb;

    if (!resultThreatDashboard) {
      updateHybridVerdict(payload);
      if (isIp) {
        renderAbuseBlock(payload);
      }
      return;
    }

    resultThreatDashboard.hidden = !hasVt && !hasAbuseData;
    resultThreatDashboard.classList.toggle('is-ip-hybrid', isIp && hasAbuseData);

    updateHybridVerdict(payload);
    if (isIp) {
      renderAbuseBlock(payload);
    }
  }

  // buildSummaryLine: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function buildSummaryLine(payload) {
    const values = buildSummaryTemplateValues(payload);
    const kind = values.kind || '';
    const enabled = enabledSummaryFieldsForKind(kind);
    const lines = [];
    if (enabled.ioc) lines.push(t('summaryIoc', { ioc: values.ioc || '' }));
    if (enabled.kind) lines.push(t('summaryType', { kind: values.kind || '' }));
    if (enabled.threatLevel && values.threatLevel) {
      lines.push(t('summaryThreatLevel', { level: threatLabelFromLevel(values.threatLevel) }));
    }
    if (enabled.vt) {
      lines.push(
        t('summaryVtDetections', {
          mal: values.malicious,
          susp: values.suspicious,
          und: values.undetected
        })
      );
    }
    if (enabled.detectionRatio && values.detectionRatio !== '—') {
      lines.push(t('summaryDetectionRatio', { ratio: values.detectionRatio }));
    }
    if (enabled.reputation && values.reputation !== '—') {
      lines.push(t('summaryReputation', { rep: values.reputation }));
    }
    if (enabled.suggestedThreat && values.suggestedThreat !== '—') {
      lines.push(t('summarySuggestedThreat', { label: values.suggestedThreat }));
    }
    if (enabled.abuseScore && values.abuseScore !== '—') {
      lines.push(t('summaryAbuseScore', { score: values.abuseScore }));
    }
    if (enabled.abuseReports && values.abuseReports !== '—') {
      lines.push(t('summaryAbuseReports', { reports: values.abuseReports }));
    }
    if (enabled.tags && values.tags !== '—') {
      lines.push(t('summaryTags', { tags: values.tags }));
    }
    if (enabled.distinctLabels && values.distinctLabels !== '—') {
      lines.push(t('summaryDistinctLabels', { labels: values.distinctLabels }));
    }
    if (enabled.mitre && values.mitre !== '—') {
      lines.push(t('summaryMitre', { ids: values.mitre }));
    }
    if (enabled.time) {
      lines.push(t('summaryTime', { time: values.time }));
    }
    if (enabled.reportLink) {
      lines.push(t('summaryReport', { link: values.reportLink }));
    }
    return lines.join('\n');
  }

  // updateQueueBadge: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function updateQueueBadge() {
    sendToBackground({ type: 'GET_QUEUE' }, function (res, err) {
      if (err || !res) {
        return;
      }
      const n = Number(res.pending) || 0;
      if (n > 0) {
        queueBadge.hidden = false;
        queueBadge.textContent =
          n === 1 ? t('queueOne') : t('queueMany', { n: n });
      } else {
        queueBadge.hidden = true;
      }
    });
  }

  // startQueuePoll: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function startQueuePoll() {
    stopQueuePoll();
    updateQueueBadge();
    queueTimer = window.setInterval(updateQueueBadge, 2000);
  }

  // stopQueuePoll: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function stopQueuePoll() {
    if (queueTimer !== null) {
      window.clearInterval(queueTimer);
      queueTimer = null;
    }
  }

  // getScrollContainer: Gerçek dikey kaydırma kapsayıcısını bulur.
  function getScrollContainer(el) {
    let node = el && el.parentElement;
    while (node && node !== document.body) {
      const style = window.getComputedStyle(node);
      const overflowY = style.overflowY;
      const scrollable =
        overflowY === 'auto' ||
        overflowY === 'scroll' ||
        overflowY === 'overlay';
      if (scrollable && node.scrollHeight > node.clientHeight + 1) {
        return node;
      }
      node = node.parentElement;
    }
    return null;
  }

  // alignResultCardInScrollView: Sonuç bölümünü panelin görünür üstüne hizalar.
  function alignResultCardInScrollView(opts) {
    opts = opts || {};
    if (!resultWrap || resultWrap.hidden) {
      return;
    }
    const scrollRoot =
      (panelScan && panelScan.scrollHeight > panelScan.clientHeight + 1
        ? panelScan
        : null) || getScrollContainer(resultWrap);
    const anchor = resultWrap;
    if (!scrollRoot) {
      (resultCard || resultWrap).scrollIntoView({
        block: 'start',
        behavior: opts.force ? 'auto' : 'smooth'
      });
      return;
    }

    const rootRect = scrollRoot.getBoundingClientRect();
    const anchorRect = anchor.getBoundingClientRect();
    const paddingTop = 8;
    const belowLookupGap = 12;
    const anchorScrollTop = scrollRoot.scrollTop + (anchorRect.top - rootRect.top);
    let desiredScrollTop = anchorScrollTop - paddingTop;

    if (inputSurfaceCard && inputSurfaceCard.classList.contains('is-compact')) {
      const lookup =
        btnScanInputExpand && !btnScanInputExpand.hidden
          ? btnScanInputExpand
          : inputSurfaceCard;
      const lookupRect = lookup.getBoundingClientRect();
      const lookupVisible =
        lookupRect.bottom > rootRect.top + 2 &&
        lookupRect.top < rootRect.bottom - 2;
      if (lookupVisible) {
        desiredScrollTop =
          scrollRoot.scrollTop + (anchorRect.top - lookupRect.bottom - belowLookupGap);
      }
    }

    const maxScroll = Math.max(0, scrollRoot.scrollHeight - scrollRoot.clientHeight);
    const nextTop = Math.max(0, Math.min(desiredScrollTop, maxScroll));
    if (!opts.force && Math.abs(scrollRoot.scrollTop - nextTop) < 3) {
      return;
    }

    scrollRoot.scrollTo({
      top: nextTop,
      behavior: opts.force ? 'auto' : 'smooth'
    });
  }

  // scrollResultIntoView: Layout oturduktan sonra sonuç bölümünü hizalar.
  function scrollResultIntoView(opts) {
    opts = opts || {};
    if (!resultWrap || resultWrap.hidden) {
      return;
    }
    if (scrollResultDelayTimer !== null) {
      window.clearTimeout(scrollResultDelayTimer);
      scrollResultDelayTimer = null;
    }
    const run = function () {
      requestAnimationFrame(function () {
        requestAnimationFrame(function () {
          alignResultCardInScrollView(opts);
        });
      });
    };
    const isCompact =
      inputSurfaceCard && inputSurfaceCard.classList.contains('is-compact');
    if (isCompact && !opts.force) {
      scrollResultDelayTimer = window.setTimeout(run, 260);
      return;
    }
    if (isCompact && opts.force) {
      scrollResultDelayTimer = window.setTimeout(run, 40);
      return;
    }
    run();
  }

  // renderHeroFromPayload: Scan kartı üst satırı (IoC türüne göre).
  function renderHeroFromPayload(payload) {
    const hero = payload && payload.hero ? payload.hero : {};
    if (resultIoc) {
      const fullIoc = (payload && payload.ioc) || hero.iocDisplay || '';
      resultIoc.textContent = fullIoc;
      if (fullIoc.length > 80) {
        resultIoc.title = fullIoc;
      } else {
        resultIoc.removeAttribute('title');
      }
      if (payload && payload.iocKind) {
        resultIoc.setAttribute('data-ioc-kind', payload.iocKind);
      }
    }
    if (resultHeroSubline) {
      if (hero.subtitle) {
        resultHeroSubline.hidden = false;
        resultHeroSubline.textContent = hero.subtitle;
      } else {
        resultHeroSubline.hidden = true;
        resultHeroSubline.textContent = '';
      }
    }
    let repVal = '';
    if (payload && payload.reputation !== undefined && payload.reputation !== null && payload.reputation !== '') {
      repVal = String(payload.reputation);
    }
    const chips = Array.isArray(hero.chips) ? hero.chips : [];
    chips.forEach(function (c) {
      if (c && c.type === 'reputation' && c.value) {
        repVal = String(c.value);
      }
    });
    if (resultReputation && resultRepSep) {
      const rn = repVal !== '' ? Number(repVal) : NaN;
      const showRep = repVal !== '' && !(isFinite(rn) && rn === 0);
      if (showRep) {
        resultReputation.hidden = false;
        resultRepSep.hidden = false;
        resultReputation.textContent = t('heroReputation', { n: repVal });
        let cls = 'result-reputation';
        if (isFinite(rn) && rn < 0) {
          cls += ' is-rep-neg';
        } else if (isFinite(rn) && rn > 0) {
          cls += ' is-rep-pos';
        } else {
          cls += ' is-rep-neu';
        }
        resultReputation.className = cls;
      } else {
        resultReputation.hidden = true;
        resultRepSep.hidden = true;
        resultReputation.textContent = '';
      }
    }
    const tagChips = Array.isArray(hero.tagChips) ? hero.tagChips : [];
    if (resultHeroTags) {
      clearElement(resultHeroTags);
      if (tagChips.length) {
        resultHeroTags.hidden = false;
        const tagNodes = tagChips.map(function (c) {
          const el = document.createElement('span');
          const tone = c && c.tone ? String(c.tone) : 'neutral';
          el.className = 'result-hero-chip is-tag is-tag-' + tone;
          el.textContent = c && c.value ? String(c.value) : '';
          return el;
        });
        appendFragment(resultHeroTags, tagNodes);
      } else {
        resultHeroTags.hidden = true;
      }
    }
    if (resultHeroChips) {
      clearElement(resultHeroChips);
      const visible = chips.filter(function (c) {
        return c && c.type !== 'reputation' && c.type !== 'tag' && c.value;
      });
      if (visible.length) {
        resultHeroChips.hidden = false;
        const nodes = visible.map(function (c) {
          const el = document.createElement('span');
          el.className = 'result-hero-chip is-' + String(c.type || 'misc');
          if (c.type === 'signature') {
            const st =
              c.state ||
              (utils.resolveSignatureState
                ? utils.resolveSignatureState({ verified: c.value })
                : 'unknown');
            el.textContent =
              st === 'valid' ? t('heroSignatureVerified') : t('heroSignatureUnverified');
            el.className += st === 'valid' ? ' is-sig-valid' : ' is-sig-invalid';
          } else {
            el.textContent = String(c.value);
          }
          return el;
        });
        appendFragment(resultHeroChips, nodes);
      } else {
        resultHeroChips.hidden = true;
      }
    }
  }

  function appendAbuseStatGrid(parent, abuse) {
    const grid = document.createElement('div');
    grid.className = 'abuse-stat-grid';
    const items = [];
    if (abuse.totalReports != null) {
      items.push({
        label: t('abuseStatTotalReports'),
        value: String(abuse.totalReports),
        sub: t('abuseStatOverallDays', { days: abuse.overallDays || 365 })
      });
    }
    if (abuse.includeReports && abuse.windowReportTotal != null) {
      items.push({
        label: t('abuseStatWindowReports'),
        value: String(abuse.windowReportTotal),
        sub: t('abuseStatWindowDays', { days: abuse.windowDays || 90 })
      });
    }
    if (abuse.fetchedReports != null && abuse.includeReports) {
      items.push({
        label: t('abuseStatFetched'),
        value: String(abuse.fetchedReports),
        sub: t('abuseStatPageNote')
      });
    }
    if (abuse.lastReportedAt) {
      items.push({
        label: t('abuseStatLastReported'),
        value: String(abuse.lastReportedAt).slice(0, 16).replace('T', ' '),
        sub: ''
      });
    }
    items.forEach(function (item) {
      const cell = document.createElement('div');
      cell.className = 'abuse-stat-cell';
      const lab = document.createElement('span');
      lab.className = 'abuse-stat-label';
      lab.textContent = item.label;
      const val = document.createElement('strong');
      val.className = 'abuse-stat-value';
      val.textContent = item.value;
      cell.appendChild(lab);
      cell.appendChild(val);
      if (item.sub) {
        const sub = document.createElement('span');
        sub.className = 'abuse-stat-sub';
        sub.textContent = item.sub;
        cell.appendChild(sub);
      }
      grid.appendChild(cell);
    });
    if (items.length) {
      parent.appendChild(grid);
    }
  }

  function appendAbuseCategoryBars(parent, categories) {
    const cats = Array.isArray(categories) ? categories.slice(0, 5) : [];
    if (!cats.length) {
      return;
    }
    const max = Math.max.apply(
      null,
      cats.map(function (c) {
        return Number(c.count) || 0;
      })
    );
    const wrap = document.createElement('div');
    wrap.className = 'abuse-category-bars';
    const heading = document.createElement('p');
    heading.className = 'abuse-category-bars-title';
    heading.textContent = t('abuseTopCategories');
    wrap.appendChild(heading);
    cats.forEach(function (item) {
      const row = document.createElement('div');
      row.className = 'abuse-category-row';
      const label = document.createElement('span');
      label.className = 'abuse-category-row-label';
      label.textContent = '#' + item.categoryId + ' ' + item.categoryName;
      label.title = item.categoryName;
      const track = document.createElement('div');
      track.className = 'abuse-category-row-track';
      const fill = document.createElement('span');
      fill.className = 'abuse-category-row-fill';
      const count = Number(item.count) || 0;
      fill.style.width = (max > 0 ? Math.max(8, (count / max) * 100) : 0) + '%';
      const num = document.createElement('span');
      num.className = 'abuse-category-row-count';
      num.textContent = String(count);
      track.appendChild(fill);
      row.appendChild(label);
      row.appendChild(track);
      row.appendChild(num);
      wrap.appendChild(row);
    });
    parent.appendChild(wrap);
  }

  // renderAbuseBlock: IP taramaları için AbuseIPDB özet bölümü.
  function renderAbuseBlock(payload) {
    if (!resultAbuseBlock) {
      return;
    }
    clearElement(resultAbuseBlock);
    if (!isIpScanPayload(payload)) {
      syncAbuseCardVisibility(payload);
      return;
    }
    const abuse = payload.abuseipdb;
    if (!abuse || abuse.ok !== true) {
      if (abuse && abuse.error === 'not_configured') {
        const note = document.createElement('p');
        note.className = 'result-abuse-note';
        note.textContent = t('abuseNotConfigured');
        resultAbuseBlock.appendChild(note);
      } else if (abuse && abuse.error) {
        const err = document.createElement('p');
        err.className = 'result-abuse-note is-error';
        err.textContent = abuseErrorMessage(abuse);
        resultAbuseBlock.appendChild(err);
      }
      return;
    }

    if (abuse.score != null && isFinite(abuse.score)) {
      const tier = utils.abuseScoreToRiskTier(abuse.score);
      const meter = document.createElement('div');
      meter.className = 'abuse-score-meter is-tier-' + tier;
      const track = document.createElement('div');
      track.className = 'abuse-score-track';
      track.setAttribute('role', 'meter');
      track.setAttribute('aria-valuemin', '0');
      track.setAttribute('aria-valuemax', '100');
      track.setAttribute('aria-valuenow', String(Math.round(abuse.score)));
      track.setAttribute('aria-label', t('abuseScoreLine', { score: abuse.score }));
      const fill = document.createElement('span');
      fill.className = 'abuse-score-fill';
      fill.style.width = Math.max(0, Math.min(100, abuse.score)) + '%';
      track.appendChild(fill);
      const readout = document.createElement('div');
      readout.className = 'abuse-score-readout';
      const val = document.createElement('span');
      val.className = 'abuse-score-value';
      val.textContent = String(Math.round(abuse.score));
      const max = document.createElement('span');
      max.className = 'abuse-score-max';
      max.textContent = '/100';
      readout.appendChild(val);
      readout.appendChild(max);
      const cap = document.createElement('p');
      cap.className = 'abuse-score-caption';
      cap.textContent = t('abuseConfidenceCaption');
      const meterRow = document.createElement('div');
      meterRow.className = 'abuse-score-meter-row';
      meterRow.appendChild(track);
      meterRow.appendChild(readout);
      meter.appendChild(meterRow);
      meter.appendChild(cap);
      resultAbuseBlock.appendChild(meter);
    }

    appendAbuseStatGrid(resultAbuseBlock, abuse);

    if (abuse.includeReports) {
      appendAbuseCategoryBars(resultAbuseBlock, abuse.categoryBreakdown);
    } else {
      const hint = document.createElement('p');
      hint.className = 'result-abuse-check-only';
      hint.textContent = t('abuseCheckOnlyHint');
      resultAbuseBlock.appendChild(hint);
    }

    if (abuse.abuseLink) {
      const foot = document.createElement('div');
      foot.className = 'result-abuse-foot';
      const link = document.createElement('a');
      link.className = 'result-abuse-link';
      link.href = abuse.abuseLink;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.textContent = t('abuseOpenReport');
      foot.appendChild(link);
      resultAbuseBlock.appendChild(foot);
    }
  }

  // renderResult: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function renderResult(payload, opts) {
    opts = opts || {};
    hideError();
    lastResultPayload = payload;
    resultWrap.hidden = false;
    resultCard.hidden = false;
    if (payload && payload.ioc && input) {
      input.value = payload.ioc;
    }
    collapseScanInput();
    resultCard.setAttribute('data-level', payload.threatLevel || 'neutral');
    resultKind.textContent = (payload.iocKind || '').toUpperCase();
    renderHeroFromPayload(payload);
    renderThreatDashboard(payload);
    if (resultEngineBlock && resultEngineSummary && resultEngineList) {
      const tc = payload.threatContext;
      const legacyEb = payload.engineBreakdown;
      if (tc && threatContextHasExtraContent(tc, payload)) {
        resultEngineBlock.hidden = false;
        clearElement(resultEngineSummary);
        if (tc.suggestedLabel && !suggestedLabelInHero(payload)) {
          const sug = document.createElement('div');
          sug.className = 'threat-suggested';
          sug.textContent = tc.suggestedLabel;
          resultEngineSummary.appendChild(sug);
        }
        clearElement(resultEngineList);
        // addSection: Popup içi yardımcı; çağrı bağlamı gövdede.
        function addSection(titleKey, rows, formatter) {
          if (!rows || !rows.length) {
            return;
          }
          const hdr = document.createElement('li');
          hdr.className = 'result-extra-section-title';
          hdr.textContent = t(titleKey);
          resultEngineList.appendChild(hdr);
          rows.forEach(function (row) {
            const li = document.createElement('li');
            li.className = 'result-extra-li';
            li.textContent = formatter(row);
            resultEngineList.appendChild(li);
          });
        }
        addSection('threatPopularNamesHeading', tc.popularNames, function (it) {
          const c = Number(it.count) || 0;
          return it.value + (c > 1 ? ' (' + c + '×)' : '');
        });
        addSection('threatPopularCategoriesHeading', tc.popularCategories, function (it) {
          const c = Number(it.count) || 0;
          return it.value + (c > 1 ? ' (' + c + '×)' : '');
        });
        if (payload.extendedThreatLabels) {
          addSection('threatDistinctLabelsHeading', tc.distinctLabels, function (it) {
            const c = Number(it.count) || 0;
            return it.label + (c > 1 ? ' (' + c + '×)' : '');
          });
        }
      } else if (legacyEb && legacyEb.summary && Array.isArray(legacyEb.engines)) {
        resultEngineBlock.hidden = false;
        resultEngineSummary.textContent = '';
        const leg = document.createElement('div');
        leg.className = 'threat-meta';
        leg.textContent = t('legacyEngineHeading');
        resultEngineSummary.appendChild(leg);
        clearElement(resultEngineList);
        legacyEb.engines.forEach(function (row) {
          const li = document.createElement('li');
          const cat = row.category || '';
          li.className =
            'result-extra-li' +
            (cat === 'malicious' ? ' is-mal' : cat === 'suspicious' ? ' is-susp' : '');
          const name = document.createElement('span');
          name.className = 'result-extra-engine';
          name.textContent = row.engine || '';
          const res = document.createElement('span');
          res.className = 'result-extra-result';
          res.textContent = row.result ? String(row.result) : '';
          li.appendChild(name);
          li.appendChild(res);
          resultEngineList.appendChild(li);
        });
      } else {
        resultEngineBlock.hidden = true;
        clearElement(resultEngineSummary);
        clearElement(resultEngineList);
      }
    }
    if (resultRelBlock && resultRelError && resultRelList) {
      const rp = payload.relationshipPreview;
      const rp2 = payload.relationshipPreviewSecondary;
      let anyRel = false;
      clearElement(resultRelList);
      if (rp && (rp.error || (Array.isArray(rp.items) && rp.items.length > 0))) {
        resultRelBlock.hidden = false;
        anyRel = true;
        if (resultRelCaption) {
          const relKey =
            'relPreview_' + String(rp.relationship || 'unknown').replace(/[^a-z0-9_]/gi, '_');
          let capText = t(relKey);
          if (capText === relKey) {
            capText = String(rp.relationship || '');
          }
          if (rp.count != null && !isNaN(Number(rp.count))) {
            capText += ' — ' + t('relationshipTotalKnown', { n: rp.count });
          }
          resultRelCaption.textContent = capText;
        }
        if (rp.error) {
          resultRelError.hidden = false;
          resultRelError.textContent = t('relationshipPreviewError', {
            rel: rp.relationship || '',
            msg: String(rp.error).slice(0, 400)
          });
        } else {
          resultRelError.hidden = true;
          resultRelError.textContent = '';
        }
        (rp.items || []).forEach(function (item) {
          const li = document.createElement('li');
          li.className = 'result-extra-li';
          li.textContent = String(item);
          resultRelList.appendChild(li);
        });
      }
      if (rp2 && (rp2.error || (Array.isArray(rp2.items) && rp2.items.length > 0))) {
        resultRelBlock.hidden = false;
        anyRel = true;
        const hdr = document.createElement('li');
        hdr.className = 'result-extra-section-title';
        const relKey2 =
          'relPreview_' + String(rp2.relationship || 'unknown').replace(/[^a-z0-9_]/gi, '_');
        let cap2 = t(relKey2);
        if (cap2 === relKey2) {
          cap2 = String(rp2.relationship || '');
        }
        hdr.textContent = cap2;
        resultRelList.appendChild(hdr);
        (rp2.items || []).forEach(function (item) {
          const li = document.createElement('li');
          li.className = 'result-extra-li';
          li.textContent = String(item);
          resultRelList.appendChild(li);
        });
      }
      if (!anyRel) {
        resultRelBlock.hidden = true;
        resultRelError.hidden = true;
        if (resultRelCaption) {
          resultRelCaption.textContent = '';
        }
      }
    }
    if (resultMitreBlock && resultMitreError && resultMitreMeta && resultMitreList) {
      const mt = payload.mitreTechniques;
      if (mt && (mt.error || (Array.isArray(mt.ids) && mt.ids.length > 0))) {
        resultMitreBlock.hidden = false;
        if (mt.error) {
          resultMitreError.hidden = false;
          resultMitreError.textContent = t('mitreError', { msg: String(mt.error).slice(0, 400) });
          resultMitreMeta.textContent = '';
          clearElement(resultMitreList);
        } else {
          resultMitreError.hidden = true;
          resultMitreError.textContent = '';
          if (mt.source === 'object') {
            resultMitreMeta.textContent = t('mitreObjectCount', { n: mt.ids.length });
          } else {
            resultMitreMeta.textContent = t('mitreSandboxCount', { n: mt.sandboxCount || 0 });
          }
          clearElement(resultMitreList);
          const mitreRows = [];
          mt.ids.forEach(function (id) {
            const li = document.createElement('li');
            li.className = 'mitre-id';
            li.textContent = id;
            mitreRows.push(li);
          });
          appendFragment(resultMitreList, mitreRows);
        }
      } else {
        resultMitreBlock.hidden = true;
        resultMitreError.hidden = true;
        resultMitreMeta.textContent = '';
        clearElement(resultMitreList);
      }
    }
    if (resultDetailsEl && resultDetailsBlock) {
      const rows = payload.details;
      clearElement(resultDetailsEl);
      if (!Array.isArray(rows) || rows.length === 0) {
        resultDetailsBlock.hidden = true;
      } else {
        resultDetailsBlock.hidden = false;
        const detailRows = [];
        rows.forEach(function (row) {
          const wrap = document.createElement('div');
          wrap.className = 'detail-row';
          const lab = document.createElement('span');
          lab.className = 'detail-label';
          lab.textContent = t(row.id);
          const val = document.createElement('span');
          val.className = 'detail-value';
          if (row.id === 'detailSignatureStatus') {
            const st = row.value;
            if (st === 'valid' || st === 'invalid' || st === 'unknown') {
              val.textContent = t(utils.signatureStatusI18nKey(st));
            } else {
              val.textContent = row.value;
            }
          } else {
            val.textContent = row.value;
          }
          wrap.appendChild(lab);
          wrap.appendChild(val);
          detailRows.push(wrap);
        });
        appendFragment(resultDetailsEl, detailRows);
      }
    }
    resultLink.href = normalizeExternalHttpUrl(payload.permalink);

    if (resultEngineDetails && resultEngineBlock) {
      resultEngineDetails.hidden = resultEngineBlock.hidden;
    }
    if (resultRelDetails && resultRelBlock) {
      resultRelDetails.hidden = resultRelBlock.hidden;
    }
    if (resultMitreDetails && resultMitreBlock) {
      resultMitreDetails.hidden = resultMitreBlock.hidden;
    }
    if (resultDetailsCollapsible && resultDetailsBlock) {
      resultDetailsCollapsible.hidden = resultDetailsBlock.hidden;
    }

    if (resultLiveAnnounce) {
      resultLiveAnnounce.textContent = '';
      requestAnimationFrame(function () {
        resultLiveAnnounce.textContent = t('resultScanLoaded');
      });
    }
    if (opts.preserveScroll !== true) {
      scrollResultIntoView({ force: true });
    }
  }

  // checkKeyAndHint: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function checkKeyAndHint() {
    chrome.storage.local.get(['vtApiKey', 'vtApiKeySavedAt'], function (data) {
      if (chrome.runtime.lastError) {
        return;
      }
      const key = data.vtApiKey && String(data.vtApiKey).trim();
      const savedAt = Number(data.vtApiKeySavedAt);
      const expired =
        !!key &&
        isFinite(savedAt) &&
        savedAt > 0 &&
        utils.isApiKeyExpired(savedAt);
      if (expired) {
        chrome.storage.local.set({ vtApiKey: '', vtApiKeySavedAt: 0 });
      }
      const has = !!key && !expired;
      noKeyHint.hidden = has;
    });
  }

  // getLinesFromInput: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function getLinesFromInput() {
    const raw = input.value || '';
    return raw
      .split(/\r?\n/)
      .map(function (l) {
        return l.trim();
      })
      .filter(function (l) {
        return l.length > 0;
      });
  }

  // unquoteCsvCell: Popup içi yardımcı; çağrı bağlamı gövdede.
  function unquoteCsvCell(s) {
    s = String(s || '').trim();
    if (s.length >= 2 && s[0] === '"' && s[s.length - 1] === '"') {
      return s.slice(1, -1).replace(/""/g, '"');
    }
    return s;
  }

  // firstColumnFromDelimited: Popup içi yardımcı; çağrı bağlamı gövdede.
  function firstColumnFromDelimited(line) {
    const str = String(line || '');
    const value = str.trim();
    if (!value) {
      return '';
    }
    let inQuotes = false;
    let cell = '';
    for (let i = 0; i < value.length; i++) {
      const ch = value[i];
      if (ch === '"') {
        if (inQuotes && value[i + 1] === '"') {
          cell += '""';
          i += 1;
          continue;
        }
        inQuotes = !inQuotes;
        cell += ch;
        continue;
      }
      if (!inQuotes && (ch === '\t' || ch === ';' || ch === ',')) {
        break;
      }
      cell += ch;
    }
    return unquoteCsvCell(cell.trim());
  }

  /** Parse CSV/plain text: BOM strip, skip comments, first column per row, drop header row if it looks like a label row. */
  function parseFileToIocLines(text) {
    let t = String(text || '');
    if (t.charCodeAt(0) === 0xfeff) {
      t = t.slice(1);
    }
    const raw = t.split(/\r?\n/);
    const out = [];
    for (let i = 0; i < raw.length; i++) {
      const trimmed = raw[i].trim();
      if (!trimmed || trimmed.indexOf('#') === 0) {
        continue;
      }
      const cell = firstColumnFromDelimited(trimmed);
      if (cell) {
        out.push(cell);
      }
    }
    if (out.length > 0) {
      const h = out[0].toLowerCase();
      if (
        /^(ioc|indicator|value|hash|ip|domain|url|type|source)(,|;|\t|$)/i.test(
          h
        ) ||
        h === 'ioc'
      ) {
        out.shift();
      }
    }
    return out;
  }

  // resetBatchExport: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function resetBatchExport() {
    lastBatchExportRows = [];
    lastBatchSummaryRows = [];
    lastBatchSourceLines = [];
    syncFileActionButtonLabel();
    syncBatchDownloadButton();
  }

  // initBatchExport: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function initBatchExport(lines) {
    lastBatchSourceLines = lines.slice();
    lastBatchExportRows = [];
    lastBatchSummaryRows = [];
    syncFileActionButtonLabel();
    syncBatchDownloadButton();
  }

  // fileActionMode: Popup içi yardımcı; çağrı bağlamı gövdede.
  function fileActionMode() {
    if (!btnFileAction) {
      return 'load';
    }
    return btnFileAction.getAttribute('data-mode') === 'download'
      ? 'download'
      : 'load';
  }

  // setFileActionMode: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function setFileActionMode(mode) {
    if (!btnFileAction) {
      return;
    }
    btnFileAction.setAttribute('data-mode', mode === 'download' ? 'download' : 'load');
    syncFileActionButtonLabel();
    syncBatchDownloadButton();
  }

  // syncFileActionButtonLabel: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function syncFileActionButtonLabel() {
    if (!btnFileAction) {
      return;
    }
    const isDownload = fileActionMode() === 'download';
    if (isDownload) {
      btnFileAction.classList.remove('is-icon-only');
      btnFileAction.textContent = t('downloadResultsCsv');
      btnFileAction.title = t('downloadResultsCsv');
      btnFileAction.setAttribute('aria-label', t('downloadResultsCsv'));
      return;
    }
    btnFileAction.classList.add('is-icon-only');
    clearElement(btnFileAction);
    btnFileAction.appendChild(createFileActionIcon());
    btnFileAction.title = t('loadFromFileTitle');
    btnFileAction.setAttribute('aria-label', t('loadFromFile'));
  }

  function syncBatchDownloadButton() {
    if (!btnBatchDownload) {
      return;
    }
    const shouldShow =
      fileActionMode() === 'download' &&
      !!batchWrap &&
      batchWrap.hidden === false &&
      lastBatchExportRows.length > 0;
    btnBatchDownload.hidden = !shouldShow;
  }

  // createFileActionIcon: Popup içi yardımcı; çağrı bağlamı gövdede.
  function createFileActionIcon() {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', 'file-action-icon');
    svg.setAttribute('viewBox', '0 0 24 24');
    svg.setAttribute('width', '16');
    svg.setAttribute('height', '16');
    svg.setAttribute('fill', 'none');
    svg.setAttribute('stroke', 'currentColor');
    svg.setAttribute('stroke-width', '2');
    svg.setAttribute('stroke-linecap', 'round');
    svg.setAttribute('stroke-linejoin', 'round');
    svg.setAttribute('aria-hidden', 'true');
    [
      'M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z',
      'M14 3v5h5',
      'M12 11v6',
      'M9 14l3 3 3-3'
    ].forEach(function (d) {
      const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
      path.setAttribute('d', d);
      svg.appendChild(path);
    });
    return svg;
  }

  // escapeCsvField: Popup içi yardımcı; çağrı bağlamı gövdede.
  function escapeCsvField(val) {
    const s = val == null ? '' : String(val);
    if (/[",\n\r]/.test(s)) {
      return '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
  }

  function abuseCsvFields(msg) {
    const abuse = msg && msg.abuseipdb;
    const top =
      abuse && abuse.ok === true && Array.isArray(abuse.categoryBreakdown)
        ? abuse.categoryBreakdown[0]
        : null;
    return {
      abuse_confidence_score:
        abuse && abuse.ok === true && abuse.score != null && isFinite(abuse.score)
          ? abuse.score
          : '',
      abuse_total_reports:
        abuse && abuse.ok === true && abuse.totalReports != null ? abuse.totalReports : '',
      abuse_overall_window_days:
        abuse && abuse.ok === true && abuse.overallDays != null ? abuse.overallDays : '',
      abuse_recent_reports:
        abuse && abuse.ok === true && abuse.windowReportTotal != null
          ? abuse.windowReportTotal
          : '',
      abuse_top_category:
        top && top.categoryName
          ? '#' + top.categoryId + ' ' + top.categoryName
          : '',
      abuse_last_reported_utc:
        abuse && abuse.ok === true && abuse.lastReportedAt
          ? String(abuse.lastReportedAt).slice(0, 19).replace('T', ' ')
          : '',
      vt_threat_level: msg && msg.threatLevelVt ? msg.threatLevelVt : '',
      abuse_threat_level: msg && msg.threatLevelAbuse ? msg.threatLevelAbuse : ''
    };
  }

  function abuseErrorMessage(abuse) {
    if (!abuse || !abuse.error) {
      return '';
    }
    if (abuse.error === 'not_configured') {
      return t('abuseNotConfigured');
    }
    if (abuse.errorKey && t(abuse.errorKey) !== abuse.errorKey) {
      return t(abuse.errorKey);
    }
    return String(abuse.error);
  }

  const BATCH_CSV_COLUMNS = [
    ['Source File', 'source_file'],
    ['Row No', 'line_no'],
    ['Input Original', 'input_raw'],
    ['Input Normalized', 'input_scanned'],
    ['Scan Status', 'status'],
    ['IoC', 'ioc'],
    ['IoC Type', 'type'],
    ['Overall Threat', 'threat'],
    ['VT Threat', 'vt_threat_level'],
    ['Abuse Threat', 'abuse_threat_level'],
    ['VT Malicious', 'mal'],
    ['VT Suspicious', 'susp'],
    ['VT Undetected', 'und'],
    ['VT Harmless', 'harmless'],
    ['VT Timeout', 'timeout'],
    ['VT Failure', 'failure'],
    ['Detected Engines', 'detected_engines'],
    ['Total Engines', 'total_engines'],
    ['Detection Ratio', 'ratio'],
    ['Reputation Score', 'rep'],
    ['Abuse Enabled (Batch)', 'abuse_enabled'],
    ['Abuse Confidence Score', 'abuse_confidence_score'],
    ['Abuse Reports (Overall)', 'abuse_total_reports'],
    ['Abuse Window (Days)', 'abuse_overall_window_days'],
    ['Abuse Reports (Recent)', 'abuse_recent_reports'],
    ['Abuse Top Category', 'abuse_top_category'],
    ['Abuse Last Reported (UTC)', 'abuse_last_reported_utc'],
    ['Suggested Label', 'suggested_label'],
    ['Creation Date', 'detail_creation_date'],
    ['First Seen', 'detail_first_seen'],
    ['Last Seen', 'detail_last_seen'],
    ['Last Analysis', 'detail_last_analysis'],
    ['Country', 'detail_country'],
    ['ASN', 'detail_asn'],
    ['AS Owner', 'detail_as_owner'],
    ['Registrar', 'detail_registrar'],
    ['Tags', 'detail_tags'],
    ['Summary Details', 'details_summary'],
    ['Report URL', 'permalink'],
    ['Error', 'error'],
    ['Scanned At (UTC)', 'scanned_at']
  ];

  function emptyBatchDetailFields() {
    return {
      detail_creation_date: '',
      detail_first_seen: '',
      detail_last_seen: '',
      detail_last_analysis: '',
      detail_registrar: '',
      detail_country: '',
      detail_asn: '',
      detail_as_owner: '',
      detail_tags: '',
      suggested_label: '',
      details_summary: '',
      abuse_enabled: '',
      abuse_confidence_score: '',
      abuse_total_reports: '',
      abuse_overall_window_days: '',
      abuse_recent_reports: '',
      abuse_top_category: '',
      abuse_last_reported_utc: '',
      vt_threat_level: '',
      abuse_threat_level: ''
    };
  }

  function buildBatchExportBaseRow(src, idx, nowIso) {
    return {
      source_file: lastImportedFileName || '',
      line_no: idx + 1,
      input_raw: src,
      input_scanned: '',
      status: '',
      ioc: '',
      type: '',
      threat: '',
      mal: '',
      susp: '',
      und: '',
      harmless: '',
      timeout: '',
      failure: '',
      detected_engines: '',
      total_engines: '',
      ratio: '',
      rep: '',
      permalink: '',
      error: '',
      ...emptyBatchDetailFields(),
      abuse_enabled: batchUseAbuse ? 'yes' : 'no',
      scanned_at: nowIso
    };
  }

  // buildBatchCsv: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function buildBatchCsv(rows) {
    const lines = [
      BATCH_CSV_COLUMNS.map(function (col) {
        return escapeCsvField(col[0]);
      }).join(',')
    ];
    rows.forEach(function (r) {
      lines.push(
        BATCH_CSV_COLUMNS.map(function (col) {
          return r[col[1]];
        })
          .map(escapeCsvField)
          .join(',')
      );
    });
    return lines.join('\r\n');
  }

  // appendBatchExportRow: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function appendBatchExportRow(msg, lines, idx) {
    const src = lines[idx] != null ? lines[idx] : '';
    const nowIso = new Date().toISOString();
    if (msg.status === 'empty') {
      lastBatchExportRows.push(
        Object.assign(buildBatchExportBaseRow(src, idx, nowIso), {
        status: 'empty',
      })
      );
      return;
    }
    if (!msg.ok) {
      lastBatchExportRows.push(
        Object.assign(buildBatchExportBaseRow(src, idx, nowIso), {
        input_scanned: msg.line != null ? msg.line : src,
        status: 'error',
        ioc: msg.line != null ? msg.line : '',
        error: msg.error || ''
      })
      );
      return;
    }
    const s = msg.stats || {};
    const total =
      (Number(s.malicious) || 0) +
      (Number(s.suspicious) || 0) +
      (Number(s.undetected) || 0) +
      (Number(s.harmless) || 0) +
      (Number(s.timeout) || 0) +
      (Number(s.failure) || 0);
    const detected = (Number(s.malicious) || 0) + (Number(s.suspicious) || 0);
    const details = Array.isArray(msg.details) ? msg.details : [];
    const detailById = {};
    const detailSummary = [];
    details.forEach(function (row) {
      if (!row || !row.id) {
        return;
      }
      const id = String(row.id);
      const value = row.value != null ? String(row.value) : '';
      if (!value) {
        return;
      }
      detailById[id] = value;
      detailSummary.push(id + ': ' + value);
    });
    const suggestedLabel =
      msg.threatContext && msg.threatContext.suggestedLabel
        ? String(msg.threatContext.suggestedLabel)
        : '';
    lastBatchExportRows.push({
      source_file: lastImportedFileName || '',
      line_no: idx + 1,
      input_raw: src,
      input_scanned: msg.line != null ? msg.line : src,
      status: 'ok',
      ioc: msg.ioc || '',
      type: msg.iocKind || '',
      threat: msg.threatLevel || '',
      mal: s.malicious != null ? s.malicious : '',
      susp: s.suspicious != null ? s.suspicious : '',
      und: s.undetected != null ? s.undetected : '',
      harmless: s.harmless != null ? s.harmless : '',
      timeout: s.timeout != null ? s.timeout : '',
      failure: s.failure != null ? s.failure : '',
      detected_engines: detected,
      total_engines: total,
      ratio: total > 0 ? detected + '/' + total : '',
      rep:
        msg.reputation !== undefined && msg.reputation !== null && msg.reputation !== ''
          ? msg.reputation
          : '',
      abuse_enabled: batchUseAbuse ? 'yes' : 'no',
      ...abuseCsvFields(msg),
      detail_creation_date: detailById.detailCreationDate || '',
      detail_first_seen: detailById.detailFirstSeen || '',
      detail_last_seen: detailById.detailLastSeen || '',
      detail_last_analysis: detailById.detailLastAnalysis || '',
      detail_registrar: detailById.detailRegistrar || '',
      detail_country: detailById.detailCountry || '',
      detail_asn: detailById.detailAsn || '',
      detail_as_owner: detailById.detailAsOwner || '',
      detail_tags:
        msg.hero && Array.isArray(msg.hero.tagChips) && msg.hero.tagChips.length
          ? msg.hero.tagChips
              .map(function (c) {
                return c && c.value ? String(c.value) : '';
              })
              .filter(Boolean)
              .join(', ')
          : '',
      suggested_label: suggestedLabel,
      details_summary: detailSummary.join(' | '),
      permalink: msg.permalink || '',
      error: '',
      scanned_at: nowIso
    });
  }

  // downloadBatchCsv: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function downloadBatchCsv() {
    if (!lastBatchExportRows.length) {
      return;
    }
    const csv = '\ufeff' + buildBatchCsv(lastBatchExportRows);
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'vt-batch-' + new Date().toISOString().replace(/[:.]/g, '-') + '.csv';
    a.click();
    URL.revokeObjectURL(url);
  }

  // setBatchLineStatus: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function setBatchLineStatus(li, text, cls) {
    const statusEl = li._statusEl || li.querySelector('.batch-line-status');
    statusEl.textContent = text;
    statusEl.className = 'batch-line-status ' + cls;
    const lineText = li._lineTextEl || li.querySelector('.batch-line-text');
    const line = lineText ? lineText.textContent : '';
    li.setAttribute('aria-label', line ? line + ', ' + text : text);
  }

  // runBatchScan: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function runBatchScan(lines, session) {
    const total = lines.length;
    initBatchExport(lines);
    hideError();
    lastResultPayload = null;
    resultWrap.hidden = false;
    if (resultCard) {
      resultCard.hidden = true;
    }
    batchWrap.hidden = false;
    if (btnBatchDownload) {
      btnBatchDownload.hidden = true;
    }
    clearElement(batchLinesEl);
    batchBarFill.style.width = '0%';
    batchProgressLabel.textContent = '0 / ' + total;

    const pendingLabel = t('batchPending');
    const items = lines.map(function (line, idx) {
      const li = document.createElement('li');
      li.className = 'batch-line';
      const lineText = document.createElement('span');
      lineText.className = 'batch-line-text';
      lineText.textContent = line;
      const st = document.createElement('span');
      st.className = 'batch-line-status is-pending';
      st.textContent = pendingLabel;
      li._lineTextEl = lineText;
      li._statusEl = st;
      li.appendChild(lineText);
      li.appendChild(st);
      li.dataset.index = String(idx);
      li.setAttribute('aria-label', line + ', ' + pendingLabel);
      return li;
    });
    appendFragment(batchLinesEl, items);

    setLoading(true);
    startQueuePoll();

    wakeServiceWorkerThen(function (wakeErr) {
      if (session !== scanSessionId) {
        return;
      }
      if (wakeErr) {
        setLoading(false);
        stopQueuePoll();
        resetBatchExport();
        showError(wakeErr.message || t('errorExtension'));
        return;
      }

      const port = chrome.runtime.connect({ name: 'vt-batch' });
      let completed = 0;
      let lastBatchOk = null;
      let batchEndExpected = false;
      const processedBatchIndexes = new Set();

      port.onDisconnect.addListener(function () {
        void chrome.runtime.lastError; // required: clear extension error state on disconnect
        if (session !== scanSessionId) {
          return;
        }
        stopQueuePoll();
        updateQueueBadge();
        if (!batchEndExpected) {
          setLoading(false);
          showError(t('errorBatchDisconnected'));
        }
        batchEndExpected = false;
      });

      port.onMessage.addListener(function (msg) {
        if (session !== scanSessionId) {
          return;
        }
        if (!msg || !msg.type) {
          return;
        }
        if (msg.type === 'BATCH_LINE') {
          const idx = Number(msg.index);
          if (!isFinite(idx) || idx < 0 || idx >= total) {
            return;
          }
          if (processedBatchIndexes.has(idx)) {
            return;
          }
          processedBatchIndexes.add(idx);
          appendBatchSummaryRowFromMessage(msg);
          const li = items[idx];
          if (!li) {
            return;
          }
          completed += 1;
          const frac = total ? Math.round((completed / total) * 100) : 100;
          batchBarFill.style.width = frac + '%';
          batchProgressLabel.textContent = completed + ' / ' + total;

          if (msg.status === 'empty') {
            setBatchLineStatus(li, t('batchEmpty'), 'is-empty');
            appendBatchExportRow(msg, lastBatchSourceLines, idx);
            return;
          }
          if (msg.line) {
            const lineText = li._lineTextEl || li.querySelector('.batch-line-text');
            if (lineText) {
              lineText.textContent = msg.line;
            }
          }
          if (msg.ok) {
            lastBatchOk = msg;
            const tl = msg.threatLevel || 'clean';
            let cls = 'is-clean';
            if (tl === 'malicious') {
              cls = 'is-malicious';
            } else if (tl === 'suspicious') {
              cls = 'is-suspicious';
            }
            setBatchLineStatus(li, threatLabelFromLevel(tl), cls);
          } else {
            setBatchLineStatus(li, t('batchError'), 'is-error');
            li.title = msg.error || '';
          }
          appendBatchExportRow(msg, lastBatchSourceLines, idx);
        }
        if (msg.type === 'BATCH_DONE') {
          batchEndExpected = true;
          port.disconnect();
          setLoading(false);
          stopQueuePoll();
          updateQueueBadge();
          saveBatchSummary(
            lastBatchSummaryRows.length ? lastBatchSummaryRows : lastBatchExportRows,
            lastBatchExportRows
          );
          collapseScanInput();
          if (resultCard) {
            resultCard.hidden = true;
          }
          if (lastBatchExportRows.length > 0) {
            setFileActionMode('download');
          }
          syncBatchDownloadButton();
        }
        if (msg.type === 'BATCH_ERROR') {
          batchEndExpected = true;
          port.disconnect();
          setLoading(false);
          stopQueuePoll();
          updateQueueBadge();
          showError(msg.error || t('errorBatchFailed'));
          collapseScanInput();
          if (resultCard) {
            resultCard.hidden = true;
          }
          if (lastBatchExportRows.length > 0) {
            setFileActionMode('download');
          }
          syncBatchDownloadButton();
        }
      });

      port.postMessage({
        type: 'SCAN_BATCH',
        lines: lines,
        stripNoise: true,
        includeAbuse: batchUseAbuse
      });
    });
  }

  // runSingleScan: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function runSingleScan(line, session) {
    resetBatchExport();
    hideError();
    resultWrap.hidden = true;
    if (resultCard) {
      resultCard.hidden = false;
    }
    batchWrap.hidden = true;
    setLoading(true);
    startQueuePoll();
    clearSingleScanTimer();
    let didTimeout = false;
    let port = null;
    singleScanTimer = window.setTimeout(function () {
      singleScanTimer = null;
      if (session !== scanSessionId) {
        return;
      }
      didTimeout = true;
      setLoading(false);
      stopQueuePoll();
      updateQueueBadge();
      showError(t('errorScanTimeout'));
      collapseScanInput();
      if (port) {
        try {
          port.disconnect();
        } catch (_) {}
      }
    }, SINGLE_SCAN_TIMEOUT_MS);

    wakeServiceWorkerThen(function (wakeErr) {
      if (session !== scanSessionId || didTimeout) {
        clearSingleScanTimer();
        return;
      }
      if (wakeErr) {
        clearSingleScanTimer();
        setLoading(false);
        stopQueuePoll();
        showError(wakeErr.message || t('errorExtension'));
        return;
      }

      var portFinished = false;
      port = chrome.runtime.connect({ name: 'vt-single' });
      port.onMessage.addListener(function (msg) {
        if (!msg || msg.type !== 'SCAN_RESULT' || didTimeout) {
          return;
        }
        portFinished = true;
        var res = msg.result;
        clearSingleScanTimer();
        try {
          port.disconnect();
        } catch (_) {}
        if (session !== scanSessionId) {
          return;
        }
        setLoading(false);
        stopQueuePoll();
        updateQueueBadge();
        loadRecentList();
        if (!res) {
          showError(t('errorNoResponse'));
          return;
        }
        if (!res.ok) {
          showError(resolveErrorMessage(res));
          collapseScanInput();
          return;
        }
        renderResult(res);
      });
      port.onDisconnect.addListener(function () {
        void chrome.runtime.lastError; // required: clear extension error state on disconnect
        clearSingleScanTimer();
        if (didTimeout) {
          return;
        }
        if (session !== scanSessionId) {
          return;
        }
        if (!portFinished) {
          setLoading(false);
          stopQueuePoll();
          updateQueueBadge();
          showError(t('errorExtension'));
        }
      });
      port.postMessage({
        type: 'SCAN_SINGLE',
        payload: line,
        stripNoise: true,
        source: 'popup'
      });
    });
  }

  // runScan: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function runScan() {
    const lines = getLinesFromInput();
    dismissScanResultView();
    recentOpenRequestId += 1;
    if (lines.length === 0) {
      showError(t('errorEmptyIoc'));
      return;
    }
    scanSessionId += 1;
    const session = scanSessionId;
    if (lines.length === 1) {
      runSingleScan(lines[0], session);
    } else {
      runBatchScan(lines, session);
    }
  }

  // loadRecentList: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function loadRecentList() {
    sendToBackground({ type: 'GET_RECENT_HISTORY' }, function (res, err) {
      if (err || !res || !Array.isArray(res.entries)) {
        return;
      }
      const entries = res.entries.filter(function (e) {
        return e && e.type !== 'batch-summary';
      });
      clearElement(recentList);
      if (entries.length === 0) {
        recentEmpty.hidden = false;
        return;
      }
      recentEmpty.hidden = true;
      const recentRows = [];
      entries.forEach(function (e) {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'recent-item';
        const tl = e.threatLevel || 'clean';
        let badgeClass = 'l-clean';
        if (tl === 'malicious') {
          badgeClass = 'l-mal';
        } else if (tl === 'suspicious') {
          badgeClass = 'l-susp';
        }
        const s = e.stats || {};
        const tlText = threatLabelFromLevel(tl);
        const labelHint =
          e.threatContext && e.threatContext.suggestedLabel
            ? String(e.threatContext.suggestedLabel).slice(0, 48)
            : '';
        const ioc = document.createElement('span');
        ioc.className = 'recent-item-ioc';
        ioc.textContent = (e.ioc || '') + (labelHint ? ' · ' + labelHint : '');
        const meta = document.createElement('span');
        meta.className = 'recent-item-meta';
        const badge = document.createElement('span');
        badge.className = 'recent-badge ' + badgeClass;
        badge.textContent = tlText;
        const kind = document.createElement('span');
        kind.textContent = (e.kind || '').toUpperCase();
        const stats = document.createElement('span');
        stats.textContent = 'M' + (s.malicious || 0) + ' S' + (s.suspicious || 0);
        const when = document.createElement('span');
        when.className = 'recent-item-when';
        when.textContent = formatRecentDate(e.ts);
        meta.appendChild(badge);
        meta.appendChild(kind);
        meta.appendChild(stats);
        meta.appendChild(when);
        btn.appendChild(ioc);
        btn.appendChild(meta);
        btn.addEventListener('click', function () {
          openRecentEntry(e);
        });
        recentRows.push(btn);
      });
      appendFragment(recentList, recentRows);
    });
  }

  // payloadFromRecentEntry: Geçmiş satırından tam sonuç yükü.
  function payloadFromRecentEntry(e) {
    if (!e) {
      return null;
    }
    const payload = {
      ok: true,
      ioc: e.ioc,
      iocKind: e.kind,
      stats: e.stats,
      threatLevel: e.threatLevel,
      reputation: e.reputation,
      permalink: e.permalink,
      details: Array.isArray(e.details) ? e.details : [],
      hero: e.hero,
      threatContext: e.threatContext,
      extendedThreatLabels: e.extendedThreatLabels,
      engineBreakdown: e.engineBreakdown,
      relationshipPreview: e.relationshipPreview,
      relationshipPreviewSecondary: e.relationshipPreviewSecondary,
      mitreTechniques: e.mitreTechniques
    };
    if (e.kind === 'ip') {
      if (e.abuseipdb) {
        payload.abuseipdb = e.abuseipdb;
      }
      if (e.threatLevelVt) {
        payload.threatLevelVt = e.threatLevelVt;
      }
      if (e.threatLevelAbuse) {
        payload.threatLevelAbuse = e.threatLevelAbuse;
      }
    }
    return payload;
  }

  function mergeAbuseIntoRecentPayload(payload, abuse) {
    if (!payload || payload.iocKind !== 'ip' || !abuse) {
      return payload;
    }
    payload.abuseipdb = abuse;
    const vtLevel =
      payload.threatLevelVt ||
      (payload.stats ? vtThreatFromStats(payload.stats) : payload.threatLevel || 'clean');
    payload.threatLevelVt = vtLevel;
    if (abuse.ok === true && abuse.score != null && isFinite(abuse.score)) {
      const score = Number(abuse.score);
      payload.threatLevelAbuse =
        score >= 75 ? 'malicious' : score >= 50 ? 'suspicious' : 'clean';
    } else if (abuse.error === 'not_configured') {
      payload.threatLevelAbuse = payload.threatLevelAbuse || 'clean';
    }
    return payload;
  }

  // openRecentEntry: Geçmişten sonuç kartını açar (eski kayıtlarda Abuse yenilenir).
  function openRecentEntry(e) {
    recentOpenRequestId += 1;
    const requestId = recentOpenRequestId;
    const payload = payloadFromRecentEntry(e);
    if (!payload) {
      return;
    }
    if (activeTab !== 'scan') {
      setActiveTab('scan', false);
    }
    input.value = e.ioc || '';
    hideError();
    batchWrap.hidden = true;

    function finish() {
      if (requestId !== recentOpenRequestId) {
        return;
      }
      renderResult(payload);
    }

    if (payload.iocKind === 'ip' && !payload.abuseipdb) {
      sendToBackground({ type: 'ENRICH_ABUSE_FOR_IP', ip: payload.ioc }, function (res, err) {
        if (!err && res && res.abuseipdb) {
          mergeAbuseIntoRecentPayload(payload, res.abuseipdb);
        }
        finish();
      });
      return;
    }
    finish();
  }

  // formatRecentDate: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function formatRecentDate(ts) {
    const n = Number(ts);
    if (!isFinite(n) || n <= 0) {
      return '';
    }
    return new Date(n).toLocaleString();
  }

  // renderBatchHistory: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function renderBatchHistory(entries) {
    if (!batchHistoryList || !batchHistoryEmpty) {
      return;
    }
    clearElement(batchHistoryList);
    const list = Array.isArray(entries) ? entries : [];
    if (list.length === 0) {
      batchHistoryEmpty.hidden = false;
      return;
    }
    batchHistoryEmpty.hidden = true;
    const historyRows = [];
    list.forEach(function (entry) {
      const li = document.createElement('li');
      li.className = 'batch-history-item';
      const counts = entry && entry.counts ? entry.counts : {};
      const name = entry && entry.fileName ? String(entry.fileName) : t('batchSummaryUnknownFile');
      const total = Math.max(0, Number(entry && entry.total) || 0);
      const riskyCount = (Number(counts.malicious) || 0) + (Number(counts.suspicious) || 0);
      const cleanCount = Number(counts.clean) || 0;
      const errorCount = (Number(counts.error) || 0) + (Number(counts.empty) || 0);
      const meta =
        t('batchSummaryMeta', {
          total: total,
          mal: Number(counts.malicious) || 0,
          susp: Number(counts.suspicious) || 0,
          clean: Number(counts.clean) || 0,
          err: (Number(counts.error) || 0) + (Number(counts.empty) || 0)
        }) +
        (entry && entry.ts ? ' · ' + formatRecentDate(entry.ts) : '');
      const top = Array.isArray(entry && entry.topRiskItems) ? entry.topRiskItems.slice(0, 3) : [];
      const titleEl = document.createElement('div');
      titleEl.className = 'batch-history-title';
      titleEl.textContent = name;
      const metaEl = document.createElement('div');
      metaEl.className = 'batch-history-meta';
      metaEl.textContent = meta;
      const countsEl = document.createElement('div');
      countsEl.className = 'batch-history-counts';
      const riskEl = document.createElement('span');
      riskEl.className = 'batch-count-pill batch-count-risk';
      riskEl.textContent = t('batchRiskCount', { n: riskyCount });
      const cleanEl = document.createElement('span');
      cleanEl.className = 'batch-count-pill batch-count-clean';
      cleanEl.textContent = t('batchCleanCount', { n: cleanCount });
      countsEl.appendChild(riskEl);
      countsEl.appendChild(cleanEl);
      const topEl = document.createElement('div');
      topEl.className = 'batch-history-top';
      const actionsEl = document.createElement('div');
      actionsEl.className = 'batch-history-actions';
      const btnDownload = document.createElement('button');
      btnDownload.type = 'button';
      btnDownload.className = 'batch-mini-action batch-mini-download';
      const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
      svg.setAttribute('class', 'batch-mini-icon');
      svg.setAttribute('viewBox', '0 0 24 24');
      svg.setAttribute('width', '14');
      svg.setAttribute('height', '14');
      svg.setAttribute('fill', 'none');
      svg.setAttribute('stroke', 'currentColor');
      svg.setAttribute('stroke-width', '2.1');
      svg.setAttribute('stroke-linecap', 'round');
      svg.setAttribute('stroke-linejoin', 'round');
      svg.setAttribute('aria-hidden', 'true');
      ['M12 4v11', 'M8 11l4 4 4-4', 'M5 19h14'].forEach(function (d) {
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', d);
        svg.appendChild(path);
      });
      btnDownload.appendChild(svg);
      btnDownload.title = t('batchActionDownloadTable');
      btnDownload.setAttribute('aria-label', t('batchActionDownloadTable'));
      if (!top.length) {
        topEl.textContent = t('batchSummaryNoRiskItems');
      } else {
        topEl.textContent = top
          .map(function (it) {
            return '[' + (it.threatLevel || 'clean') + '] ' + (it.ioc || '');
          })
          .join(' | ');
      }
      if (errorCount > 0) {
        metaEl.textContent += ' · ' + t('batchErrorCount', { n: errorCount });
      }
      btnDownload.addEventListener('click', function (ev) {
        ev.stopPropagation();
        downloadBatchHistoryCsv(entry);
      });
      actionsEl.appendChild(btnDownload);
      li.appendChild(titleEl);
      li.appendChild(metaEl);
      li.appendChild(countsEl);
      li.appendChild(topEl);
      li.appendChild(actionsEl);
      historyRows.push(li);
    });
    appendFragment(batchHistoryList, historyRows);
  }

  // downloadBatchHistoryCsv: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function downloadBatchHistoryCsv(entry) {
    const csv = entry && entry.csv ? String(entry.csv) : '';
    if (!csv) {
      showCopyToast(t('batchActionNoTable'));
      return;
    }
    const blob = new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download =
      (entry && entry.csvFileName ? String(entry.csvFileName) : '') ||
      'vt-batch-history-' + new Date(entry && entry.ts ? entry.ts : Date.now()).toISOString().replace(/[:.]/g, '-') + '.csv';
    a.click();
    URL.revokeObjectURL(url);
  }

  // loadBatchHistoryList: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function loadBatchHistoryList() {
    sendToBackground({ type: 'GET_BATCH_HISTORY' }, function (res, err) {
      if (err || !res || !Array.isArray(res.entries)) {
        return;
      }
      renderBatchHistory(res.entries);
    });
  }

  // setActiveRecentTab: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function setActiveRecentTab(next) {
    activeRecentTab = next === 'batch' ? 'batch' : 'general';
    if (recentTabGeneral) {
      recentTabGeneral.classList.toggle('is-active', activeRecentTab === 'general');
      recentTabGeneral.setAttribute('aria-pressed', activeRecentTab === 'general' ? 'true' : 'false');
    }
    if (recentTabBatch) {
      recentTabBatch.classList.toggle('is-active', activeRecentTab === 'batch');
      recentTabBatch.setAttribute('aria-pressed', activeRecentTab === 'batch' ? 'true' : 'false');
    }
    if (recentPanelGeneral) {
      recentPanelGeneral.hidden = activeRecentTab !== 'general';
    }
    if (recentPanelBatch) {
      recentPanelBatch.hidden = activeRecentTab !== 'batch';
    }
  }

  // summarizeBatchRows: Popup içi yardımcı; çağrı bağlamı gövdede.
  function summarizeBatchRows(rows) {
    const list = Array.isArray(rows) ? rows : [];
    const counts = { malicious: 0, suspicious: 0, clean: 0, error: 0, empty: 0 };
    const byKind = { ip: 0, domain: 0, url: 0, file: 0 };
    const topRiskItems = [];
    list.forEach(function (row) {
      const status = String(row && row.status ? row.status : '');
      const threat = String(row && row.threat ? row.threat : '');
      if (status === 'empty') {
        counts.empty += 1;
        return;
      }
      if (status === 'error') {
        counts.error += 1;
        return;
      }
      if (threat === 'malicious') {
        counts.malicious += 1;
      } else if (threat === 'suspicious') {
        counts.suspicious += 1;
      } else {
        counts.clean += 1;
      }
      const kind = row && row.type ? String(row.type) : '';
      if (Object.prototype.hasOwnProperty.call(byKind, kind)) {
        byKind[kind] += 1;
      }
      if ((threat === 'malicious' || threat === 'suspicious') && topRiskItems.length < 8) {
        topRiskItems.push({
          ioc: row && row.ioc ? String(row.ioc) : String((row && row.input_scanned) || ''),
          threatLevel: threat,
          kind: kind
        });
      }
    });
    return {
      id: 'batch-' + Date.now(),
      ts: Date.now(),
      fileName: lastImportedFileName || '',
      total: list.length,
      counts: counts,
      byKind: byKind,
      topRiskItems: topRiskItems
    };
  }

  // appendBatchSummaryRowFromMessage: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function appendBatchSummaryRowFromMessage(msg) {
    if (!msg || msg.type !== 'BATCH_LINE') {
      return;
    }
    if (msg.status === 'empty') {
      lastBatchSummaryRows.push({ status: 'empty', threat: '', ioc: '', type: '' });
      return;
    }
    if (!msg.ok) {
      lastBatchSummaryRows.push({
        status: 'error',
        threat: '',
        ioc: msg.line != null ? String(msg.line) : '',
        type: ''
      });
      return;
    }
    lastBatchSummaryRows.push({
      status: 'ok',
      threat: msg.threatLevel || 'clean',
      ioc: msg.ioc || (msg.line != null ? String(msg.line) : ''),
      type: msg.iocKind || ''
    });
  }

  // saveBatchSummary: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function saveBatchSummary(rows, exportRows) {
    if (!rows || rows.length === 0) {
      return;
    }
    const summary = summarizeBatchRows(rows);
    if (Array.isArray(exportRows) && exportRows.length > 0) {
      summary.csv = buildBatchCsv(exportRows);
      summary.csvFileName =
        'vt-batch-' + new Date(summary.ts).toISOString().replace(/[:.]/g, '-') + '.csv';
    }
    sendToBackground({ type: 'SAVE_BATCH_HISTORY', summary: summary }, function () {
      loadRecentList();
      loadBatchHistoryList();
    });
  }

  if (input) {
    input.addEventListener('input', function () {
      updateScanQuotaHint();
    });
  }

  [
    { node: presetQuick, name: 'quick' },
    { node: presetDetailed, name: 'detailed' },
    { node: presetAnalyst, name: 'analyst' }
  ].forEach(function (preset) {
    if (!preset.node) {
      return;
    }
    preset.node.addEventListener('click', function () {
      applyScanPreset(preset.name);
    });
  });

  if (btnScanInputExpand) {
    btnScanInputExpand.addEventListener('click', function () {
      expandScanInput();
    });
  }

  if (btnScan) {
    btnScan.addEventListener('click', runScan);
  }
  if (input) {
    input.addEventListener('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        runScan();
      }
    });
  }
  if (btnOptions) {
    btnOptions.addEventListener('click', openOptions);
  }
  if (btnOptionsInline) {
    btnOptionsInline.addEventListener('click', openOptions);
  }

  if (btnResultClose) {
    btnResultClose.addEventListener('click', closeResult);
  }

  if (btnLangToggle) {
    btnLangToggle.addEventListener('click', function () {
      const next = VT_I18N.lang() === 'tr' ? 'en' : 'tr';
      setUiLang(next, true);
    });
  }

  if (btnCopySummary) {
    btnCopySummary.addEventListener('click', function () {
      if (!lastResultPayload || !lastResultPayload.ioc) {
        return;
      }
      copyToClipboard(buildSummaryLine(lastResultPayload))
        .then(function () {
          showCopyToast(t('copySummaryDone'));
        })
        .catch(function () {});
    });
  }

  if (btnClearRecent) {
    btnClearRecent.addEventListener('click', function () {
      sendToBackground({ type: 'CLEAR_HISTORY_SECTION', section: activeRecentTab }, function (_res, err) {
        if (err) {
          return;
        }
        if (activeRecentTab === 'batch') {
          loadBatchHistoryList();
        } else {
          loadRecentList();
        }
      });
    });
  }

  if (btnFileAction && fileIocList) {
    btnFileAction.addEventListener('click', function () {
      if (fileActionMode() === 'download') {
        downloadBatchCsv();
        return;
      }
      fileIocList.click();
    });
    fileIocList.addEventListener('change', function () {
      const f = fileIocList.files && fileIocList.files[0];
      if (!f) {
        return;
      }
      const reader = new FileReader();
      reader.onload = function () {
        const lines = parseFileToIocLines(reader.result);
        lastImportedFileName = f.name || '';
        fileIocList.value = '';
        if (lines.length === 0) {
          showError(t('fileImportEmpty'));
          return;
        }
        input.value = lines.join('\n');
        setFileActionMode('load');
        hideError();
      };
      reader.onerror = function () {
        fileIocList.value = '';
        showError(t('fileReadError'));
      };
      reader.readAsText(f, 'UTF-8');
    });
  }

  if (btnBatchDownload) {
    btnBatchDownload.addEventListener('click', function () {
      downloadBatchCsv();
    });
  }

  // initLangAndUi: Popup DOM veya kullanıcı etkileşimi ile ilgili.
  function initLangAndUi() {
    chrome.storage.local.get(
      [
        'vtUiLang',
        SCAN_PRESETS_KEY,
        'vtPopupTheme',
        NEWS_READ_MAP_KEY,
        POPUP_ACTIVE_TAB_KEY,
        SCAN_PRESET_KEY,
        CONTEXT_SCAN_RESULT_KEY,
        COPY_SUMMARY_FIELDS_KEY,
        'vtBatchUseAbuse'
      ],
      function (data) {
        if (chrome.runtime.lastError) {
          setPopupTheme('dark', false);
          syncLangToggleLabel();
          applyPopupLang();
          resetScanPanelOnOpen();
          runAutoConnectionTest();
          return;
        }
        const v = data.vtUiLang === 'tr' ? 'tr' : 'en';
        VT_I18N.setLang(v);
        syncLangToggleLabel();
        applyPresetMap(data[SCAN_PRESETS_KEY]);
        const savedPreset =
          data && typeof data[SCAN_PRESET_KEY] === 'string'
            ? data[SCAN_PRESET_KEY]
            : '';
        if (savedPreset === 'quick' || savedPreset === 'detailed' || savedPreset === 'analyst') {
          applyScanPreset(savedPreset, false);
        } else {
          applyScanPreset('quick', false);
        }
        newsReadMap =
          data && data[NEWS_READ_MAP_KEY] && typeof data[NEWS_READ_MAP_KEY] === 'object'
            ? data[NEWS_READ_MAP_KEY]
            : {};
        const savedTab =
          data && data[POPUP_ACTIVE_TAB_KEY] === 'news'
            ? 'news'
            : data && data[POPUP_ACTIVE_TAB_KEY] === 'usom'
              ? 'usom'
              : 'scan';
        const pendingRow = data[CONTEXT_SCAN_RESULT_KEY];
        copySummaryFields = normalizeCopySummaryFields(data[COPY_SUMMARY_FIELDS_KEY]);
        batchUseAbuse = data.vtBatchUseAbuse !== false;
        setPopupTheme(data.vtPopupTheme === 'light' ? 'light' : 'dark', false);
        resetScanPanelOnOpen();
        applyPopupLang();
        if (pendingRow && pendingRow.payload) {
          setActiveTab('scan', false);
          consumePendingContextScan(pendingRow);
        } else {
          setActiveTab(savedTab, false);
        }
        runAutoConnectionTest();
      }
    );
  }

  if (btnThemeToggle) {
    btnThemeToggle.addEventListener('click', function () {
      const next = getPopupTheme() === 'light' ? 'dark' : 'light';
      setPopupTheme(next, true);
    });
  }

  initLangAndUi();
  setFileActionMode('load');
  checkKeyAndHint();
  loadRecentList();
  loadBatchHistoryList();
  setActiveRecentTab('general');

  [
    { node: tabScan, name: 'scan' },
    { node: tabNews, name: 'news' },
    { node: tabUsom, name: 'usom' }
  ].forEach(function (tab) {
    if (!tab.node) {
      return;
    }
    tab.node.addEventListener('click', function () {
      setActiveTab(tab.name);
    });
  });
  if (recentTabGeneral) {
    recentTabGeneral.addEventListener('click', function () {
      setActiveRecentTab('general');
    });
  }
  if (recentTabBatch) {
    recentTabBatch.addEventListener('click', function () {
      setActiveRecentTab('batch');
    });
  }
  if (btnNewsRefresh) {
    btnNewsRefresh.addEventListener('click', function () {
      loadNews(true);
    });
  }
  if (btnUsomRefresh) {
    btnUsomRefresh.addEventListener('click', function () {
      loadUsom(true);
    });
  }
  if (newsSourceFilter) {
    newsSourceFilter.addEventListener('change', function () {
      newsSourceValue = newsSourceFilter.value || 'all';
      if (lastNewsPayload) {
        renderNews(lastNewsPayload);
      }
    });
  }
  if (newsSearch) {
    newsSearch.addEventListener('input', function () {
      newsSearchValue = String(newsSearch.value || '');
      if (lastNewsPayload) {
        renderNews(lastNewsPayload);
      }
    });
  }
  if (usomSearch) {
    usomSearch.addEventListener('input', function () {
      usomSearchValue = String(usomSearch.value || '');
      if (lastUsomPayload) {
        renderUsom(lastUsomPayload);
      }
    });
  }

  if (mascotHost && mascotBubble) {
    refreshMascotBubbleText();
    mascotHost.addEventListener('mouseenter', refreshMascotBubbleText);
  }

  chrome.storage.onChanged.addListener(function (changes, area) {
    if (area === 'local' && (changes.vtApiKey || changes.vtApiKeySavedAt)) {
      checkKeyAndHint();
      runAutoConnectionTest();
    }
    if (area === 'local' && changes.vtRecentHistory) {
      loadRecentList();
    }
    if (area === 'local' && changes.vtBatchHistory) {
      loadBatchHistoryList();
    }
    if (area === 'local' && changes.vtUiLang) {
      const v = changes.vtUiLang.newValue === 'tr' ? 'tr' : 'en';
      VT_I18N.setLang(v);
      syncLangToggleLabel();
      applyPopupLang();
      loadRecentList();
    }
    if (area === 'local' && changes.vtPopupTheme) {
      const nv = changes.vtPopupTheme.newValue;
      setPopupTheme(nv === 'light' ? 'light' : 'dark', false);
    }
    if (area === 'local' && changes[COPY_SUMMARY_FIELDS_KEY]) {
      copySummaryFields = normalizeCopySummaryFields(
        changes[COPY_SUMMARY_FIELDS_KEY].newValue
      );
    }
    if (area === 'local' && changes[SCAN_PRESETS_KEY]) {
      applyPresetMap(changes[SCAN_PRESETS_KEY].newValue);
    }
    if (area === 'local' && changes[SCAN_PRESET_KEY]) {
      const nextPreset = changes[SCAN_PRESET_KEY].newValue;
      if (nextPreset === 'quick' || nextPreset === 'detailed' || nextPreset === 'analyst') {
        applyScanPreset(nextPreset, false);
      }
    }
    if (area === 'local' && changes.vtBatchUseAbuse) {
      batchUseAbuse = changes.vtBatchUseAbuse.newValue !== false;
    }
    if (area === 'local' && changes[CONTEXT_SCAN_RESULT_KEY]) {
      const row = changes[CONTEXT_SCAN_RESULT_KEY].newValue;
      if (row && row.payload) {
        setActiveTab('scan', false);
        consumePendingContextScan(row);
      }
    }
    if (
      area === 'local' &&
      document.visibilityState === 'visible' &&
      activeTab === 'news' &&
      !newsLoading &&
      (changes[VT_NEWS_CACHE_KEY] || changes[VT_NEWS_FETCHED_AT_KEY])
    ) {
      loadNews(false);
    }
    if (
      area === 'local' &&
      document.visibilityState === 'visible' &&
      activeTab === 'usom' &&
      !usomLoading &&
      (changes[VT_USOM_CACHE_KEY] || changes[VT_USOM_FETCHED_AT_KEY])
    ) {
      loadUsom(false);
    }
  });

  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'visible') {
      updateQueueBadge();
      loadRecentList();
      loadBatchHistoryList();
      if (activeTab === 'news') {
        loadNews(false);
      }
      if (activeTab === 'usom') {
        loadUsom(false);
      }
    }
  });

  if (input) {
    input.focus();
  }
})();
