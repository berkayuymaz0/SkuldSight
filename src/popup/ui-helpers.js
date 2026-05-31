  // t: Popup içi yardımcı; çağrı bağlamı gövdede.
  function t(key, vars) {
    return VT_I18N.t(key, vars);
  }

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
    const kbdHint = document.querySelector('.kbd-hint[data-i18n="kbdScan"]');
    if (kbdHint) {
      const isMac =
        /Mac|iPhone|iPad|iPod/i.test(navigator.platform || '') ||
        (navigator.userAgentData && navigator.userAgentData.platform === 'macOS');
      kbdHint.textContent = t(isMac ? 'kbdScanMac' : 'kbdScan');
    }
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
    document.documentElement.lang = v;
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
      window.open(chrome.runtime.getURL('src/options/options.html'));
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
    if (btnScan) {
      btnScan.disabled = on;
    }
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
    if (!errorMsg) {
      return;
    }
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
    syncVtReanalyzeButton(null);
    clearVtReanalyzeStatus();
    vtReanalyzeStatusIocKey = '';
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
    if (errorMsg) {
      errorMsg.textContent = resolveErrorMessage(
        typeof text === 'object' ? text : { error: text }
      );
      errorMsg.hidden = false;
    }
    if (resultWrap) {
      resultWrap.hidden = true;
    }
  }

