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

  const BATCH_CSV_COLUMN_DEFS = [
    ['batchCsvSourceFile', 'source_file'],
    ['batchCsvRowNo', 'line_no'],
    ['batchCsvInputOriginal', 'input_raw'],
    ['batchCsvInputNormalized', 'input_scanned'],
    ['batchCsvScanStatus', 'status'],
    ['batchCsvIoc', 'ioc'],
    ['batchCsvIocType', 'type'],
    ['batchCsvOverallThreat', 'threat'],
    ['batchCsvVtThreat', 'vt_threat_level'],
    ['batchCsvAbuseThreat', 'abuse_threat_level'],
    ['batchCsvVtMalicious', 'mal'],
    ['batchCsvVtSuspicious', 'susp'],
    ['batchCsvVtUndetected', 'und'],
    ['batchCsvVtHarmless', 'harmless'],
    ['batchCsvVtTimeout', 'timeout'],
    ['batchCsvVtFailure', 'failure'],
    ['batchCsvDetectedEngines', 'detected_engines'],
    ['batchCsvTotalEngines', 'total_engines'],
    ['batchCsvDetectionRatio', 'ratio'],
    ['batchCsvReputationScore', 'rep'],
    ['batchCsvAbuseEnabled', 'abuse_enabled'],
    ['batchCsvAbuseConfidence', 'abuse_confidence_score'],
    ['batchCsvAbuseReportsOverall', 'abuse_total_reports'],
    ['batchCsvAbuseWindow', 'abuse_overall_window_days'],
    ['batchCsvAbuseReportsRecent', 'abuse_recent_reports'],
    ['batchCsvAbuseTopCategory', 'abuse_top_category'],
    ['batchCsvAbuseLastReported', 'abuse_last_reported_utc'],
    ['batchCsvSuggestedLabel', 'suggested_label'],
    ['batchCsvCreationDate', 'detail_creation_date'],
    ['batchCsvFirstSeen', 'detail_first_seen'],
    ['batchCsvLastSeen', 'detail_last_seen'],
    ['batchCsvLastAnalysis', 'detail_last_analysis'],
    ['batchCsvCountry', 'detail_country'],
    ['batchCsvAsn', 'detail_asn'],
    ['batchCsvAsOwner', 'detail_as_owner'],
    ['batchCsvRegistrar', 'detail_registrar'],
    ['batchCsvTags', 'detail_tags'],
    ['batchCsvSummaryDetails', 'details_summary'],
    ['batchCsvReportUrl', 'permalink'],
    ['batchCsvError', 'error'],
    ['batchCsvScannedAt', 'scanned_at']
  ];

  function getBatchCsvColumns() {
    return BATCH_CSV_COLUMN_DEFS.map(function (col) {
      return [t(col[0]), col[1]];
    });
  }

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
    const columns = getBatchCsvColumns();
    const lines = [
      columns.map(function (col) {
        return escapeCsvField(col[0]);
      }).join(',')
    ];
    rows.forEach(function (r) {
      lines.push(
        columns.map(function (col) {
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
  // downloadCsvBlob: CSV metnini blob olarak indirir (BOM çağıran tarafça eklenir).
  function downloadCsvBlob(csvText, filename) {
    const blob = new Blob([csvText], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function downloadBatchCsv() {
    if (!lastBatchExportRows.length) {
      return;
    }
    downloadCsvBlob(
      '\ufeff' + buildBatchCsv(lastBatchExportRows),
      'vt-batch-' + new Date().toISOString().replace(/[:.]/g, '-') + '.csv'
    );
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
    if (!resultWrap || !batchWrap || !batchLinesEl || !batchBarFill || !batchProgressLabel) {
      return;
    }
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
      const abuseLevel =
        score >= 75 ? 'malicious' : score >= 50 ? 'suspicious' : 'clean';
      payload.threatLevelAbuse = abuseLevel;
      /* Hero birleşik seviyesi VT + Abuse'tan yeniden hesaplanır (arka plan ile aynı kural). */
      payload.threatLevel =
        vtLevel === 'malicious' || abuseLevel === 'malicious'
          ? 'malicious'
          : vtLevel === 'suspicious' || abuseLevel === 'suspicious'
            ? 'suspicious'
            : 'clean';
    } else if (abuse.error === 'not_configured') {
      payload.threatLevelAbuse = payload.threatLevelAbuse || 'unknown';
      payload.threatLevel = vtLevel;
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
    const filename =
      (entry && entry.csvFileName ? String(entry.csvFileName) : '') ||
      'vt-batch-history-' + new Date(entry && entry.ts ? entry.ts : Date.now()).toISOString().replace(/[:.]/g, '-') + '.csv';
    downloadCsvBlob('\ufeff' + csv, filename);
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

  if (btnVtReanalyze) {
    btnVtReanalyze.addEventListener('click', handleVtReanalyzeClick);
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
        document.documentElement.lang = v;
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
  let newsSearchDebounce = null;
  let usomSearchDebounce = null;
  if (newsSearch) {
    newsSearch.addEventListener('input', function () {
      newsSearchValue = String(newsSearch.value || '');
      if (newsSearchDebounce !== null) {
        window.clearTimeout(newsSearchDebounce);
      }
      newsSearchDebounce = window.setTimeout(function () {
        newsSearchDebounce = null;
        if (lastNewsPayload) {
          renderNews(lastNewsPayload);
        }
      }, 120);
    });
  }
  if (usomSearch) {
    usomSearch.addEventListener('input', function () {
      usomSearchValue = String(usomSearch.value || '');
      if (usomSearchDebounce !== null) {
        window.clearTimeout(usomSearchDebounce);
      }
      usomSearchDebounce = window.setTimeout(function () {
        usomSearchDebounce = null;
        if (lastUsomPayload) {
          renderUsom(lastUsomPayload);
        }
      }, 120);
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
      document.documentElement.lang = v;
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
