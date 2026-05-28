'use strict';

/**
 * Content script: detect visible domains and public IPs, add badges, and open a mini result panel.
 */
(function () {
  const socUtils = typeof window !== 'undefined' ? window.VtSocUtils : null;
  const DOMAIN_BTN_ATTR = 'data-vt-domain-badge';
  const DOMAIN_VALUE_ATTR = 'data-vt-domain-value';
  const DOMAIN_TOKEN_ATTR = 'data-vt-domain-token';
  const IP_BTN_ATTR = 'data-vt-ip-badge';
  const IP_VALUE_ATTR = 'data-vt-ip-value';
  const IP_TOKEN_ATTR = 'data-vt-ip-token';
  const MAX_BADGES = 120;
  const DOMAIN_TEXT_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;
  const IPV4_OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
  const COMBINED_IP_RE = new RegExp(
    '\\b' +
      IPV4_OCTET +
      '(?:\\.' +
      IPV4_OCTET +
      '){3}\\b|\\b(?:(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|[A-Fa-f0-9]{1,4}:(?:(?::[A-Fa-f0-9]{1,4}){1,6})|:(?:(?::[A-Fa-f0-9]{1,4}){1,7}|:))\\b',
    'g'
  );
  const DOMAIN_SCAN_DEBOUNCE_MS = 120;
  const MAX_MUTATION_ROOTS_PER_FLUSH = 60;
  const inlineScanCache = new Map();
  let domainPanel = null;
  let observer = null;
  let blacklistRules = [];
  let badgeCount = 0;
  let domainScanDebounceTimer = null;
  let contentTheme = 'dark';
  let panelLastScanResult = null;
  const pendingMutationRoots = new Set();

  function applyContentTheme(theme) {
    contentTheme = theme === 'light' ? 'light' : 'dark';
    document.querySelectorAll('.vt-domain-badge, .vt-ip-badge').forEach(function (btn) {
      btn.setAttribute('data-vt-theme', contentTheme);
    });
    if (domainPanel) {
      domainPanel.setAttribute('data-vt-theme', contentTheme);
    }
  }

  // İçerik betiğinde VT_I18N dilini kullanıcı ayarına göre Türkçe veya İngilizce yapar.
  function syncContentLang(isTr) {
    if (typeof VT_I18N !== 'undefined' && VT_I18N.setLang) {
      VT_I18N.setLang(isTr ? 'tr' : 'en');
    }
  }

  // VT_I18N yüklüyse çeviri anahtarını çözer; değilse anahtarı olduğu gibi döndürür.
  function ct(key, vars) {
    if (typeof VT_I18N !== 'undefined' && VT_I18N.t) {
      return VT_I18N.t(key, vars);
    }
    return key;
  }

  chrome.storage.local.get(
    ['vtUiLang', 'vtDomainBadgeBlacklist', 'vtPopupTheme'],
    function (d) {
      syncContentLang(d.vtUiLang === 'tr');
      applyContentTheme(d.vtPopupTheme === 'light' ? 'light' : 'dark');
      blacklistRules = parseBlacklistRules(d.vtDomainBadgeBlacklist);
      applyBlacklistState();
    }
  );

  chrome.storage.onChanged.addListener(function (changes, area) {
    if (area !== 'local') {
      return;
    }
    if (changes.vtUiLang) {
      syncContentLang(changes.vtUiLang.newValue === 'tr');
    }
    if (changes.vtPopupTheme) {
      applyContentTheme(changes.vtPopupTheme.newValue === 'light' ? 'light' : 'dark');
    }
    if (changes.vtDomainBadgeBlacklist) {
      blacklistRules = parseBlacklistRules(changes.vtDomainBadgeBlacklist.newValue);
      applyBlacklistState();
    }
  });

  // Kara liste metnini satırlara bölüp yorumları atarak küçük harf kural dizisi üretir.
  function parseBlacklistRules(raw) {
    return String(raw || '')
      .split(/\r?\n/)
      .map(function (line) {
        return line.trim().toLowerCase();
      })
      .filter(function (line) {
        return !!line && line.indexOf('#') !== 0;
      });
  }

  // Geçerli sayfa URL’si veya alan adı, kayıtlı kara liste kurallarından birine uyuyorsa true döner.
  function isCurrentPageBlacklisted() {
    if (!blacklistRules || blacklistRules.length === 0) {
      return false;
    }
    const href = String(location.href || '').toLowerCase();
    const host = String(location.hostname || '').toLowerCase();
    const path = String(location.pathname || '').toLowerCase();
    for (let i = 0; i < blacklistRules.length; i++) {
      const rule = blacklistRules[i];
      if (rule === '*') {
        return true;
      }
      if (rule.indexOf('://') >= 0) {
        if (href.indexOf(rule) === 0) {
          return true;
        }
        continue;
      }
      if (rule[0] === '/') {
        if (path.indexOf(rule) === 0) {
          return true;
        }
        continue;
      }
      if (rule.indexOf('*.') === 0) {
        const suffix = rule.slice(2);
        if (host === suffix || host.endsWith('.' + suffix)) {
          return true;
        }
        continue;
      }
      if (host === rule || host.endsWith('.' + rule)) {
        return true;
      }
    }
    return false;
  }

  // Metnin gerçek bir alan adı adayı olup olmadığını (localhost/IP hariç) doğrular.
  function isDomainCandidate(hostname) {
    const host = String(hostname || '').trim().toLowerCase();
    if (!host || host.length > 253) {
      return false;
    }
    if (host === 'localhost') {
      return false;
    }
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
      return false;
    }
    return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host);
  }

  function isIPv4(ip) {
    return new RegExp(
      '^(?:' + IPV4_OCTET + ')(?:\\.(?:' + IPV4_OCTET + ')){3}$'
    ).test(ip);
  }

  function isIPv6(ip) {
    return /^((?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|[A-Fa-f0-9]{1,4}:(?:(?::[A-Fa-f0-9]{1,4}){1,6})|:(?:(?::[A-Fa-f0-9]{1,4}){1,7}|:))$/.test(
      ip
    );
  }

  function isPublicIPv4(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(Number.isNaN)) {
      return false;
    }
    const a = parts[0];
    const b = parts[1];
    if (a === 10 || a === 127 || a === 0) {
      return false;
    }
    if (a === 169 && b === 254) {
      return false;
    }
    if (a === 192 && b === 168) {
      return false;
    }
    if (a === 172 && b >= 16 && b <= 31) {
      return false;
    }
    if (a >= 224) {
      return false;
    }
    return true;
  }

  function isPublicIPv6(ip) {
    const lower = ip.toLowerCase();
    if (lower === '::' || lower === '::1') {
      return false;
    }
    if (lower.startsWith('fc') || lower.startsWith('fd')) {
      return false;
    }
    if (
      lower.startsWith('fe8') ||
      lower.startsWith('fe9') ||
      lower.startsWith('fea') ||
      lower.startsWith('feb')
    ) {
      return false;
    }
    if (lower.startsWith('ff')) {
      return false;
    }
    return true;
  }

  function isSupportedPublicIP(ip) {
    if (isIPv4(ip)) {
      return isPublicIPv4(ip);
    }
    if (isIPv6(ip)) {
      return isPublicIPv6(ip);
    }
    return false;
  }

  function inlineCacheKey(kind, value) {
    return kind + ':' + String(value || '').toLowerCase();
  }

  function createBadgeIconSvg(kind) {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('class', 'vt-badge-glyph');
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('width', '11');
    svg.setAttribute('height', '11');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    if (kind === 'domain') {
      const circle = document.createElementNS(ns, 'circle');
      circle.setAttribute('cx', '8');
      circle.setAttribute('cy', '8');
      circle.setAttribute('r', '5.25');
      circle.setAttribute('fill', 'none');
      circle.setAttribute('stroke', 'currentColor');
      circle.setAttribute('stroke-width', '1.15');
      const meridian = document.createElementNS(ns, 'ellipse');
      meridian.setAttribute('cx', '8');
      meridian.setAttribute('cy', '8');
      meridian.setAttribute('rx', '2.15');
      meridian.setAttribute('ry', '5.25');
      meridian.setAttribute('fill', 'none');
      meridian.setAttribute('stroke', 'currentColor');
      meridian.setAttribute('stroke-width', '1');
      const parallel = document.createElementNS(ns, 'path');
      parallel.setAttribute('d', 'M2.75 8h10.5');
      parallel.setAttribute('fill', 'none');
      parallel.setAttribute('stroke', 'currentColor');
      parallel.setAttribute('stroke-width', '1');
      svg.appendChild(circle);
      svg.appendChild(meridian);
      svg.appendChild(parallel);
    } else {
      const paths = [
        'M3 3.25h3.25v3.25H3zM9.75 3.25H13v3.25H9.75zM3 9.5h3.25V12.75H3zM9.75 9.5H13V12.75H9.75z',
        'M5.1 8h1.35M9.55 8h1.35M8 5.1v1.35M8 9.55v1.35'
      ];
      paths.forEach(function (d, idx) {
        const el = document.createElementNS(ns, 'path');
        el.setAttribute('d', d);
        if (idx < 4) {
          el.setAttribute('fill', 'currentColor');
          el.setAttribute('stroke', 'none');
        } else {
          el.setAttribute('fill', 'none');
          el.setAttribute('stroke', 'currentColor');
          el.setAttribute('stroke-width', '1.05');
          el.setAttribute('stroke-linecap', 'round');
        }
        svg.appendChild(el);
      });
    }
    return svg;
  }

  function applyBadgeRiskState(btn, payload) {
    if (!btn || !payload || !payload.ok) {
      return;
    }
    const risk =
      socUtils && socUtils.payloadToBadgeRisk
        ? socUtils.payloadToBadgeRisk(payload)
        : payload.threatLevel || 'clean';
    btn.setAttribute('data-vt-risk', risk);
    btn.classList.remove('vt-badge-pending');
    if (btn.classList.contains('vt-ip-badge')) {
      let scoreEl = btn.querySelector('.vt-badge-score');
      const abuse = payload.abuseipdb;
      if (abuse && abuse.ok === true && abuse.score != null && isFinite(abuse.score)) {
        if (!scoreEl) {
          scoreEl = document.createElement('span');
          scoreEl.className = 'vt-badge-score';
          btn.appendChild(scoreEl);
        }
        scoreEl.textContent = String(Math.round(abuse.score));
        btn.classList.add('vt-badge-has-score');
      } else {
        if (scoreEl) {
          scoreEl.remove();
        }
        btn.classList.remove('vt-badge-has-score');
      }
    }
  }

  function applyBadgeRiskStateForAll(kind, value, payload) {
    const btnAttr = kind === 'ip' ? IP_BTN_ATTR : DOMAIN_BTN_ATTR;
    const valAttr = kind === 'ip' ? IP_VALUE_ATTR : DOMAIN_VALUE_ATTR;
    const norm = String(value || '').toLowerCase();
    document.querySelectorAll('[' + btnAttr + '="1"]').forEach(function (btn) {
      const v = String(btn.getAttribute(valAttr) || '').toLowerCase();
      if (v === norm) {
        applyBadgeRiskState(btn, payload);
      }
    });
  }

  function createDomainBadge(hostname) {
    badgeCount += 1;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.setAttribute(DOMAIN_BTN_ATTR, '1');
    btn.setAttribute(DOMAIN_VALUE_ATTR, hostname);
    btn.title = ct('domainBadgeButtonTitle', { host: hostname });
    btn.className = 'vt-domain-badge vt-badge-pending';
    btn.appendChild(createBadgeIconSvg('domain'));
    btn.setAttribute('data-vt-theme', contentTheme);
    btn.addEventListener('click', onDomainBadgeClick, true);
    return btn;
  }

  function createIpBadge(ip) {
    badgeCount += 1;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.setAttribute(IP_BTN_ATTR, '1');
    btn.setAttribute(IP_VALUE_ATTR, ip);
    btn.title = ct('ipBadgeButtonTitle', { ip: ip });
    btn.className = 'vt-ip-badge vt-badge-pending';
    btn.setAttribute('data-vt-theme', contentTheme);
    btn.appendChild(createBadgeIconSvg('ip'));
    btn.addEventListener('click', onIpBadgeClick, true);
    return btn;
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
    document.querySelectorAll('[' + DOMAIN_TOKEN_ATTR + '="1"]').forEach(function (el) {
      const txt = document.createTextNode(el.textContent || '');
      el.replaceWith(txt);
    });
    document.querySelectorAll('[' + IP_TOKEN_ATTR + '="1"]').forEach(function (el) {
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

  // Kara listeye göre rozetleri ya tamamen kaldırır ya da gözlemci ile taramayı yeniden başlatır.
  function applyBlacklistState() {
    if (isCurrentPageBlacklisted()) {
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
      domain +
      '</strong>' +
      '<button type="button" class="vt-domain-panel-close" data-vt-close="1" aria-label="Close">✕</button>' +
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
      String(error || ct('domainBadgeScanFailed')).slice(0, 180) +
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
    const permalink = res && res.permalink ? String(res.permalink) : '#';
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
      permalink +
      '" target="_blank" rel="noopener noreferrer">' +
      vtLinkLabel +
      '</a>' +
      '</div>'
    );
  }

  // Panel içindeki kapat düğmesine tıklanınca paneli kapatma dinleyicisini bağlar.
  function attachPanelHandlers(domain) {
    if (!domainPanel) {
      return;
    }
    const closeBtn = domainPanel.querySelector('[data-vt-close="1"]');
    if (closeBtn) {
      closeBtn.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        hideDomainPanel();
      });
    }
    const copyBtn = domainPanel.querySelector('[data-vt-copy-summary="1"]');
    if (copyBtn) {
      copyBtn.addEventListener('click', function (e) {
        e.preventDefault();
        e.stopPropagation();
        if (!panelLastScanResult) {
          return;
        }
        const label = copyBtn.textContent;
        copyTextToClipboard(buildPanelSummaryLine(panelLastScanResult, domain))
          .then(function () {
            copyBtn.textContent = ct('copySummaryDone');
            window.setTimeout(function () {
              copyBtn.textContent = label;
            }, 1400);
          })
          .catch(function () {});
      });
    }
  }

  // Sabit mini paneli tetikleyen öğenin yakınında ekran sınırlarına göre konumlandırır.
  function positionPanelNear(el) {
    const panel = ensureDomainPanel();
    panel.hidden = false;
    const rect = el.getBoundingClientRect();
    const pad = 8;
    const width = 248;
    let left = rect.left;
    let top = rect.bottom + 6;
    if (left + width > window.innerWidth - pad) {
      left = window.innerWidth - width - pad;
    }
    if (left < pad) {
      left = pad;
    }
    if (top + 132 > window.innerHeight - pad) {
      top = rect.top - 138;
    }
    if (top < pad) {
      top = pad;
    }
    panel.style.left = left + 'px';
    panel.style.top = top + 'px';
  }

  // Service worker’ı hafif bir mesajla uyandırıp ardından callback’i çalıştırır (bağlantı öncesi).
  function wakeServiceWorkerThen(callback) {
    chrome.runtime.sendMessage({ type: 'GET_QUEUE' }, function () {
      void chrome.runtime.lastError;
      callback();
    });
  }

  function showCachedOrScanPanel(iocKind, value, anchorBtn) {
    const cacheKey = inlineCacheKey(iocKind, value);
    const cached = inlineScanCache.get(cacheKey);
    if (cached && cached.ok) {
      panelLastScanResult = cached;
      const panel = ensureDomainPanel();
      panel.innerHTML = panelHtmlResult(value, cached, iocKind);
      attachPanelHandlers(value);
      positionPanelNear(anchorBtn);
      applyBadgeRiskStateForAll(iocKind, value, cached);
      return;
    }
    runInlineScan(iocKind, value, anchorBtn);
  }

  function runInlineScan(iocKind, value, anchorBtn) {
    const panel = ensureDomainPanel();
    panelLastScanResult = null;
    panel.innerHTML = panelHtmlLoading(value);
    attachPanelHandlers(value);
    positionPanelNear(anchorBtn);
    wakeServiceWorkerThen(function () {
      const cport = chrome.runtime.connect({ name: 'vt-single' });
      let handled = false;
      cport.onMessage.addListener(function (msg) {
        if (!msg || msg.type !== 'SCAN_RESULT' || handled) {
          return;
        }
        handled = true;
        const res = msg.result;
        if (!res || !res.ok) {
          panelLastScanResult = null;
          panel.innerHTML = panelHtmlError(
            value,
            res && res.error ? res.error : ct('domainBadgeScanFailed')
          );
        } else {
          panelLastScanResult = res;
          inlineScanCache.set(inlineCacheKey(iocKind, value), res);
          applyBadgeRiskStateForAll(iocKind, value, res);
          panel.innerHTML = panelHtmlResult(value, res, iocKind);
        }
        attachPanelHandlers(value);
        positionPanelNear(anchorBtn);
        try {
          cport.disconnect();
        } catch (_) {}
      });
      cport.onDisconnect.addListener(function () {
        void chrome.runtime.lastError;
      });
      cport.postMessage({
        type: 'SCAN_SINGLE',
        payload: value,
        stripNoise: false,
        source: 'content'
      });
    });
  }

  function onDomainBadgeClick(ev) {
    ev.preventDefault();
    ev.stopPropagation();
    const btn = ev.currentTarget;
    const domain = btn && btn.getAttribute(DOMAIN_VALUE_ATTR);
    if (!domain) {
      return;
    }
    showCachedOrScanPanel('domain', domain, btn);
  }

  function onIpBadgeClick(ev) {
    ev.preventDefault();
    ev.stopPropagation();
    const btn = ev.currentTarget;
    const ip = btn && btn.getAttribute(IP_VALUE_ATTR);
    if (!ip) {
      return;
    }
    showCachedOrScanPanel('ip', ip, btn);
  }

  // Metin düğümünün rozetleme için uygun olup olmadığını (script/input vb. hariç) kontrol eder.
  function shouldSkipTextNode(node) {
    if (!node || !node.parentElement) {
      return true;
    }
    if (!node.nodeValue || node.nodeValue.trim().length < 4) {
      return true;
    }
    const p = node.parentElement;
    if (
      p.closest('script,style,noscript,textarea,input,select,option,button,code,pre,[contenteditable="true"]')
    ) {
      return true;
    }
    if (p.closest('[' + DOMAIN_TOKEN_ATTR + '="1"]')) {
      return true;
    }
    if (p.closest('[' + IP_TOKEN_ATTR + '="1"]')) {
      return true;
    }
    if (p.closest('[' + DOMAIN_BTN_ATTR + '="1"]')) {
      return true;
    }
    if (p.closest('[' + IP_BTN_ATTR + '="1"]')) {
      return true;
    }
    return false;
  }

  function decorateIpsInTextNode(textNode) {
    if (badgeCount >= MAX_BADGES) {
      return false;
    }
    const original = String(textNode.nodeValue || '');
    COMBINED_IP_RE.lastIndex = 0;
    let m = null;
    let lastIndex = 0;
    let changed = false;
    const frag = document.createDocumentFragment();
    while ((m = COMBINED_IP_RE.exec(original))) {
      if (badgeCount >= MAX_BADGES) {
        break;
      }
      const ip = m[0];
      const start = m.index;
      const end = start + ip.length;
      if (!isSupportedPublicIP(ip)) {
        continue;
      }
      if (start > lastIndex) {
        frag.appendChild(document.createTextNode(original.slice(lastIndex, start)));
      }
      const wrap = document.createElement('span');
      wrap.setAttribute(IP_TOKEN_ATTR, '1');
      wrap.style.whiteSpace = 'nowrap';
      wrap.appendChild(document.createTextNode(ip));
      wrap.appendChild(createIpBadge(ip));
      frag.appendChild(wrap);
      lastIndex = end;
      changed = true;
    }
    if (!changed) {
      return false;
    }
    if (lastIndex < original.length) {
      frag.appendChild(document.createTextNode(original.slice(lastIndex)));
    }
    textNode.parentNode.replaceChild(frag, textNode);
    return true;
  }

  function processVisibleTextIps(root) {
    const base =
      root && root.nodeType === Node.ELEMENT_NODE
        ? root
        : document.body || document.documentElement;
    if (!base) {
      return;
    }
    const walker = document.createTreeWalker(base, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) {
      const n = walker.currentNode;
      if (shouldSkipTextNode(n)) {
        continue;
      }
      COMBINED_IP_RE.lastIndex = 0;
      if (!COMBINED_IP_RE.test(n.nodeValue || '')) {
        continue;
      }
      nodes.push(n);
    }
    for (let i = 0; i < nodes.length; i++) {
      if (badgeCount >= MAX_BADGES) {
        break;
      }
      decorateIpsInTextNode(nodes[i]);
    }
  }

  // Bir metin düğümündeki alan adı eşleşmelerini span + rozet ile böler (üst sınır: MAX_BADGES).
  function decorateDomainsInTextNode(textNode) {
    if (badgeCount >= MAX_BADGES) {
      return false;
    }
    const original = String(textNode.nodeValue || '');
    DOMAIN_TEXT_RE.lastIndex = 0;
    let m = null;
    let lastIndex = 0;
    let changed = false;
    const frag = document.createDocumentFragment();
    while ((m = DOMAIN_TEXT_RE.exec(original))) {
      if (badgeCount >= MAX_BADGES) {
        break;
      }
      const full = m[0];
      const start = m.index;
      const end = start + full.length;
      const beforeCh = start > 0 ? original[start - 1] : '';
      if (beforeCh === '@') {
        continue;
      }
      const domain = full.toLowerCase();
      if (!isDomainCandidate(domain)) {
        continue;
      }
      if (start > lastIndex) {
        frag.appendChild(document.createTextNode(original.slice(lastIndex, start)));
      }
      const wrap = document.createElement('span');
      wrap.setAttribute(DOMAIN_TOKEN_ATTR, '1');
      wrap.style.whiteSpace = 'nowrap';
      wrap.appendChild(document.createTextNode(full));
      wrap.appendChild(createDomainBadge(domain));
      frag.appendChild(wrap);
      lastIndex = end;
      changed = true;
    }
    if (!changed) {
      return false;
    }
    if (lastIndex < original.length) {
      frag.appendChild(document.createTextNode(original.slice(lastIndex)));
    }
    textNode.parentNode.replaceChild(frag, textNode);
    return true;
  }

  // Verilen kök altındaki görünür metin düğümlerinde alan adı rozetlemesi uygular.
  function processVisibleTextDomains(root) {
    const base =
      root && root.nodeType === Node.ELEMENT_NODE
        ? root
        : document.body || document.documentElement;
    if (!base) {
      return;
    }
    const walker = document.createTreeWalker(base, NodeFilter.SHOW_TEXT);
    const nodes = [];
    while (walker.nextNode()) {
      const n = walker.currentNode;
      if (shouldSkipTextNode(n)) {
        continue;
      }
      DOMAIN_TEXT_RE.lastIndex = 0;
      if (!DOMAIN_TEXT_RE.test(n.nodeValue || '')) {
        continue;
      }
      nodes.push(n);
    }
    for (let i = 0; i < nodes.length; i++) {
      if (badgeCount >= MAX_BADGES) {
        break;
      }
      decorateDomainsInTextNode(nodes[i]);
    }
  }

  // Debounce sonunda biriken mutasyon köklerinde veya tüm belgede domain taramasını çalıştırır.
  function flushPendingDomainScan() {
    domainScanDebounceTimer = null;
    if (isCurrentPageBlacklisted()) {
      pendingMutationRoots.clear();
      return;
    }
    const docRoot = document.body || document.documentElement;
    if (!docRoot) {
      pendingMutationRoots.clear();
      return;
    }
    if (pendingMutationRoots.size === 0) {
      processVisibleTextIps(docRoot);
      processVisibleTextDomains(docRoot);
      return;
    }
    const roots = Array.from(pendingMutationRoots);
    pendingMutationRoots.clear();
    const flushCount = Math.min(roots.length, MAX_MUTATION_ROOTS_PER_FLUSH);
    for (let i = 0; i < flushCount; i++) {
      if (badgeCount >= MAX_BADGES) {
        break;
      }
      const el = roots[i];
      if (!el || el.nodeType !== Node.ELEMENT_NODE || !el.isConnected) {
        continue;
      }
      if (!docRoot.contains(el)) {
        continue;
      }
      processVisibleTextIps(el);
      processVisibleTextDomains(el);
    }
    if (roots.length > flushCount) {
      for (let i = flushCount; i < roots.length; i++) {
        pendingMutationRoots.add(roots[i]);
      }
      scheduleDomainScan();
    }
  }

  // Alan adı taramasını kısa gecikmeyle tek seferde birleştirerek (debounce) zamanlar.
  function scheduleDomainScan() {
    if (isCurrentPageBlacklisted()) {
      return;
    }
    if (domainScanDebounceTimer !== null) {
      window.clearTimeout(domainScanDebounceTimer);
    }
    domainScanDebounceTimer = window.setTimeout(flushPendingDomainScan, DOMAIN_SCAN_DEBOUNCE_MS);
  }

  // DOM’a eklenen düğümleri izleyerek yeniden rozet taraması için kökleri kuyruğa alır.
  function onMutationForDomains(mutations) {
    let dirty = false;
    for (let i = 0; i < mutations.length; i++) {
      const m = mutations[i];
      if (m.type !== 'childList' || !m.addedNodes || m.addedNodes.length === 0) {
        continue;
      }
      for (let j = 0; j < m.addedNodes.length; j++) {
        const node = m.addedNodes[j];
        if (node.nodeType === Node.ELEMENT_NODE) {
          pendingMutationRoots.add(node);
          dirty = true;
        } else if (node.nodeType === Node.TEXT_NODE && node.parentElement) {
          pendingMutationRoots.add(node.parentElement);
          dirty = true;
        }
      }
    }
    if (dirty) {
      scheduleDomainScan();
    }
  }

  // İlk tam taramayı yapar ve document üzerinde MutationObserver ile dinamik içeriği izler.
  function startDomainObserver() {
    if (observer || isCurrentPageBlacklisted()) {
      return;
    }
    pendingMutationRoots.clear();
    if (domainScanDebounceTimer !== null) {
      window.clearTimeout(domainScanDebounceTimer);
      domainScanDebounceTimer = null;
    }
    const docRoot = document.body || document.documentElement;
    processVisibleTextIps(docRoot);
    processVisibleTextDomains(docRoot);
    observer = new MutationObserver(onMutationForDomains);
    observer.observe(document.documentElement || document.body, {
      childList: true,
      subtree: true
    });
  }

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      hideDomainPanel();
    }
  });

  document.addEventListener(
    'scroll',
    function () {
      hideDomainPanel();
    },
    true
  );

  document.addEventListener(
    'click',
    function (e) {
      if (!domainPanel || domainPanel.hidden) {
        return;
      }
      const t = e.target;
      if (
        (t && t.closest && t.closest('[data-vt-domain-panel="1"]')) ||
        (t && t.closest && t.closest('[' + DOMAIN_BTN_ATTR + '="1"]')) ||
        (t && t.closest && t.closest('[' + IP_BTN_ATTR + '="1"]'))
      ) {
        return;
      }
      hideDomainPanel();
    },
    true
  );

  applyBlacklistState();
})();
