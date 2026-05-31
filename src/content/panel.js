'use strict';

  function panelDisplayLabel(iocKind, value) {
    const v = String(value || '');
    if (iocKind === 'file' && socUtils && socUtils.shortenHash) {
      return socUtils.shortenHash(v);
    }
    if (iocKind === 'url' && v.length > 56) {
      return v.slice(0, 48) + '…' + v.slice(-8);
    }
    return v;
  }

  // Sabit konumlu mini sonuç paneli öğesini bir kez oluşturup document’e ekler.
  function ensureDomainPanel() {
    if (domainPanel) {
      return domainPanel;
    }
    domainPanel = document.createElement('div');
    domainPanel.setAttribute('data-vt-domain-panel', '1');
    domainPanel.className = 'vt-domain-panel';
    domainPanel.setAttribute('data-vt-theme', contentTheme);
    domainPanel.hidden = true;
    document.documentElement.appendChild(domainPanel);
    return domainPanel;
  }

  // Mini paneli gizler ve içeriğini temizler.
  function hideDomainPanel() {
    if (!domainPanel) {
      return;
    }
    domainPanel.hidden = true;
    domainPanel.innerHTML = '';
    panelLastScanResult = null;
  }

  // Sayfadaki tüm VT rozetlerini ve geçici işaretleyicileri kaldırıp sayacı sıfırlar.
  function clearDomainDecorations() {
    badgeCount = 0;
    inlineScanCache.clear();
    document.querySelectorAll('[' + DOMAIN_BTN_ATTR + '="1"]').forEach(function (el) {
      el.remove();
    });
    document.querySelectorAll('[' + IP_BTN_ATTR + '="1"]').forEach(function (el) {
      el.remove();
    });
    document.querySelectorAll('[' + URL_BTN_ATTR + '="1"]').forEach(function (el) {
      el.remove();
    });
    document.querySelectorAll('[' + HASH_BTN_ATTR + '="1"]').forEach(function (el) {
      el.remove();
    });
    document.querySelectorAll('[' + DOMAIN_TOKEN_ATTR + '="1"]').forEach(function (el) {
      const txt = document.createTextNode(el.textContent || '');
      el.replaceWith(txt);
    });
    document.querySelectorAll('[' + IP_TOKEN_ATTR + '="1"]').forEach(function (el) {
      const txt = document.createTextNode(el.textContent || '');
      el.replaceWith(txt);
    });
    document.querySelectorAll('[' + URL_TOKEN_ATTR + '="1"]').forEach(function (el) {
      const txt = document.createTextNode(el.textContent || '');
      el.replaceWith(txt);
    });
    document.querySelectorAll('[' + HASH_TOKEN_ATTR + '="1"]').forEach(function (el) {
      const txt = document.createTextNode(el.textContent || '');
      el.replaceWith(txt);
    });
    hideDomainPanel();
  }

  // Debounce zamanlayıcısını ve MutationObserver’ı durdurarak DOM izlemeyi kapatır.
  function stopDomainObserver() {
    if (domainScanDebounceTimer !== null) {
      window.clearTimeout(domainScanDebounceTimer);
      domainScanDebounceTimer = null;
    }
    pendingMutationRoots.clear();
    if (!observer) {
      return;
    }
    observer.disconnect();
    observer = null;
  }

  function applyContentIocSettings() {
    if (!contentIocBadgesEnabled || isCurrentPageBlacklisted()) {
      stopDomainObserver();
      clearDomainDecorations();
      return;
    }
    startDomainObserver();
  }

  function copyTextToClipboard(text) {
    const value = String(text || '');
    if (!value) {
      return Promise.reject(new Error('empty'));
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(value);
    }
    return new Promise(function (resolve, reject) {
      const ta = document.createElement('textarea');
      ta.value = value;
      ta.setAttribute('readonly', '');
      ta.style.cssText = 'position:fixed;left:-9999px;top:0;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy');
        resolve();
      } catch (err) {
        reject(err);
      } finally {
        ta.remove();
      }
    });
  }

  function buildPanelSummaryLine(res, domain) {
    const payload = Object.assign({}, res || {}, {
      ioc: (res && res.ioc) || domain || '',
      iocKind: (res && res.iocKind) || 'domain'
    });
    if (typeof VtSocUtils !== 'undefined' && VtSocUtils.buildSummaryLine) {
      return VtSocUtils.buildSummaryLine(payload, ct);
    }
    const s = payload.stats || {};
    return (
      payload.ioc +
      ' | mal ' +
      (s.malicious || 0) +
      ' susp ' +
      (s.suspicious || 0) +
      ' | ' +
      (payload.permalink || '')
    );
  }

  function panelHtmlHead(domain) {
    return (
      '<div class="vt-domain-panel-head">' +
      '<strong class="vt-domain-panel-domain">' +
      escapePanelHtml(domain) +
      '</strong>' +
      '<button type="button" class="vt-domain-panel-close" data-vt-close="1" aria-label="' +
      escapePanelHtml(ct('panelClose')) +
      '">✕</button>' +
      '</div>'
    );
  }

  // Mini panel için “taranıyor” durumunun HTML içeriğini üretir.
  function panelHtmlLoading(domain) {
    return (
      panelHtmlHead(domain) +
      '<div class="vt-domain-panel-status">' +
      ct('domainBadgeScanning') +
      '</div>'
    );
  }

  // Tarama hatası mesajını gösteren panel HTML’ini üretir.
  function panelHtmlError(domain, error) {
    return (
      panelHtmlHead(domain) +
      '<div class="vt-domain-panel-status is-error">' +
      escapePanelHtml(String(error || ct('domainBadgeScanFailed')).slice(0, 180)) +
      '</div>'
    );
  }

  function panelAbuseSectionHtml(res) {
    const abuse = res && res.abuseipdb;
    if (!abuse || abuse.ok !== true) {
      if (abuse && abuse.error === 'not_configured') {
        return (
          '<div class="vt-panel-abuse-compact is-note">' +
          escapePanelHtml(ct('abuseNotConfigured')) +
          '</div>'
        );
      }
      return '';
    }
    const parts = [];
    if (abuse.score != null && isFinite(abuse.score)) {
      parts.push(String(abuse.score));
    }
    if (abuse.totalReports != null) {
      parts.push(String(abuse.totalReports));
    }
    let summary = '';
    if (parts.length === 2) {
      summary = ct('panelAbuseCompact')
        .replace('{score}', parts[0])
        .replace('{reports}', parts[1]);
    } else if (parts.length === 1 && abuse.score != null) {
      summary = parts[0] + '/100';
    }
    const cats = Array.isArray(abuse.categoryBreakdown) ? abuse.categoryBreakdown.slice(0, 2) : [];
    let catLine = '';
    if (cats.length) {
      catLine = cats
        .map(function (c) {
          return (
            '#' +
            String(c.categoryId) +
            ' ' +
            String(c.categoryName || '').slice(0, 18) +
            ' (' +
            String(c.count) +
            ')'
          );
        })
        .join(' · ');
    }
    return (
      '<div class="vt-panel-abuse-compact">' +
      '<span class="vt-panel-abuse-tag">ABU</span>' +
      (summary
        ? '<span class="vt-panel-abuse-sum">' + escapePanelHtml(summary) + '</span>'
        : '') +
      (catLine ? '<span class="vt-panel-abuse-cats">' + escapePanelHtml(catLine) + '</span>' : '') +
      '</div>'
    );
  }

  function panelAbuseFootLink(res) {
    const abuse = res && res.abuseipdb;
    if (!abuse || abuse.ok !== true || !abuse.abuseLink) {
      return '';
    }
    return (
      '<a class="vt-domain-panel-link vt-panel-abuse-link" href="' +
      escapePanelHtml(abuse.abuseLink) +
      '" target="_blank" rel="noopener noreferrer">' +
      escapePanelHtml(ct('panelAbuseOpenShort')) +
      '</a>'
    );
  }

  function escapePanelHtml(value) {
    return String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function sanitizePermalink(url) {
    const s = String(url || '').trim();
    if (s.indexOf('https://www.virustotal.com/') === 0) {
      return s;
    }
    return '#';
  }

  function inlineScanCacheSet(key, value) {
    if (inlineScanCache.has(key)) {
      inlineScanCache.delete(key);
    }
    inlineScanCache.set(key, value);
    while (inlineScanCache.size > INLINE_SCAN_CACHE_MAX) {
      const oldest = inlineScanCache.keys().next().value;
      if (oldest === undefined) {
        break;
      }
      inlineScanCache.delete(oldest);
    }
  }

  function panelMetaValueEmpty(value) {
    const v = String(value ?? '').trim();
    return !v || v === '—' || v === '-';
  }

  function formatPanelDateShort(value) {
    const raw = String(value ?? '').trim();
    if (!raw || raw === '—') {
      return '';
    }
    const m = raw.match(/^(\d{4}-\d{2}-\d{2})/);
    return m ? m[1] : raw.length > 16 ? raw.slice(0, 16) + '…' : raw;
  }

  function panelFactHtml(label, value) {
    if (panelMetaValueEmpty(value)) {
      return '';
    }
    return (
      '<div class="vt-panel-fact">' +
      '<span class="vt-panel-fact-k">' +
      escapePanelHtml(label) +
      '</span>' +
      '<span class="vt-panel-fact-v">' +
      escapePanelHtml(String(value)) +
      '</span></div>'
    );
  }

  function panelHtmlResult(label, res, iocKind) {
    const s = res && res.stats ? res.stats : {};
    const permalink = sanitizePermalink(res && res.permalink ? String(res.permalink) : '#');
    const totalEngines =
      (Number(s.malicious) || 0) +
      (Number(s.suspicious) || 0) +
      (Number(s.undetected) || 0) +
      (Number(s.harmless) || 0) +
      (Number(s.timeout) || 0) +
      (Number(s.failure) || 0);
    const detected = (Number(s.malicious) || 0) + (Number(s.suspicious) || 0);
    const detectionRatio = totalEngines > 0 ? detected + ' / ' + totalEngines : '—';
    const details = res && Array.isArray(res.details) ? res.details : [];
    let creationDate = '—';
    let lastAnalysis = '—';
    for (let i = 0; i < details.length; i++) {
      const row = details[i];
      if (!row) {
        continue;
      }
      if (row.id === 'detailCreationDate' && row.value) {
        creationDate = String(row.value);
      }
      if (row.id === 'detailLastAnalysis' && row.value) {
        lastAnalysis = String(row.value);
      }
    }
    const threatLabel =
      res && res.threatContext && res.threatContext.suggestedLabel
        ? String(res.threatContext.suggestedLabel).slice(0, 48)
        : '';
    const repRaw =
      res && res.reputation !== undefined && res.reputation !== null && res.reputation !== ''
        ? String(res.reputation)
        : '';
    const rep =
      repRaw && repRaw !== '0' && repRaw !== '—' ? repRaw : '';
    const abuseHtml = iocKind === 'ip' ? panelAbuseSectionHtml(res) : '';
    const abuseFootLink = iocKind === 'ip' ? panelAbuseFootLink(res) : '';
    const vtLinkLabel = iocKind === 'ip' ? ct('openReportShort') : ct('domainBadgeOpenVtReport');
    const lastShort = formatPanelDateShort(lastAnalysis);
    const facts =
      panelFactHtml(ct('domainBadgeThreatLabel'), threatLabel) +
      panelFactHtml(ct('domainBadgeCreationDate'), creationDate) +
      panelFactHtml(ct('domainBadgeReputation'), rep) +
      panelFactHtml(ct('panelMetaLast'), lastShort);
    const factsBlock = facts ? '<div class="vt-panel-facts">' + facts + '</div>' : '';
    return (
      panelHtmlHead(label) +
      '<div class="vt-domain-panel-metrics">' +
      '<span class="vt-domain-panel-chip is-mal">' +
      ct('domainBadgeMalShort') +
      ' <strong>' +
      String(s.malicious || 0) +
      '</strong></span>' +
      '<span class="vt-domain-panel-chip is-susp">' +
      ct('domainBadgeSuspShort') +
      ' <strong>' +
      String(s.suspicious || 0) +
      '</strong></span>' +
      '<span class="vt-domain-panel-chip is-und">' +
      ct('domainBadgeUndShort') +
      ' <strong>' +
      String(s.undetected || 0) +
      '</strong></span>' +
      (detectionRatio !== '—'
        ? '<span class="vt-domain-panel-chip is-ratio" title="' +
          escapePanelHtml(ct('domainBadgeDetectionRatio')) +
          '"><strong>' +
          escapePanelHtml(detectionRatio) +
          '</strong></span>'
        : '') +
      '</div>' +
      factsBlock +
      abuseHtml +
      '<div class="vt-domain-panel-foot">' +
      '<button type="button" class="vt-domain-panel-copy" data-vt-copy-summary="1">' +
      ct('copySummary') +
      '</button>' +
      abuseFootLink +
      '<a class="vt-domain-panel-link" href="' +
      escapePanelHtml(permalink) +
      '" target="_blank" rel="noopener noreferrer">' +
      vtLinkLabel +
      '</a>' +
      '</div>'
    );
  }

