'use strict';

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
      const label = panelDisplayLabel(iocKind, value);
      panel.innerHTML = panelHtmlResult(label, cached, iocKind);
      attachPanelHandlers(value);
      positionPanelNear(anchorBtn);
      applyBadgeRiskStateForAll(iocKind, value, cached);
      return;
    }
    runInlineScan(iocKind, value, anchorBtn);
  }

  function runInlineScan(iocKind, value, anchorBtn) {
    const panel = ensureDomainPanel();
    const label = panelDisplayLabel(iocKind, value);
    panelLastScanResult = null;
    panel.innerHTML = panelHtmlLoading(label);
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
            label,
            res && res.error ? res.error : ct('domainBadgeScanFailed')
          );
        } else {
          panelLastScanResult = res;
          inlineScanCacheSet(inlineCacheKey(iocKind, value), res);
          applyBadgeRiskStateForAll(iocKind, value, res);
          panel.innerHTML = panelHtmlResult(label, res, iocKind);
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

  function onUrlBadgeClick(ev) {
    ev.preventDefault();
    ev.stopPropagation();
    const btn = ev.currentTarget;
    const url = btn && btn.getAttribute(URL_VALUE_ATTR);
    if (!url) {
      return;
    }
    showCachedOrScanPanel('url', url, btn);
  }

  function onHashBadgeClick(ev) {
    ev.preventDefault();
    ev.stopPropagation();
    const btn = ev.currentTarget;
    const hash = btn && btn.getAttribute(HASH_VALUE_ATTR);
    if (!hash) {
      return;
    }
    showCachedOrScanPanel('file', hash, btn);
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
    if (p.closest('[' + URL_TOKEN_ATTR + '="1"]')) {
      return true;
    }
    if (p.closest('[' + HASH_TOKEN_ATTR + '="1"]')) {
      return true;
    }
    if (p.closest('[' + DOMAIN_BTN_ATTR + '="1"]')) {
      return true;
    }
    if (p.closest('[' + IP_BTN_ATTR + '="1"]')) {
      return true;
    }
    if (p.closest('[' + URL_BTN_ATTR + '="1"]')) {
      return true;
    }
    if (p.closest('[' + HASH_BTN_ATTR + '="1"]')) {
      return true;
    }
    return false;
  }

  function overlapsRange(range, occupied) {
    if (socUtils && socUtils.overlapsAny) {
      return socUtils.overlapsAny(range, occupied);
    }
    for (let i = 0; i < occupied.length; i++) {
      if (range.start < occupied[i].end && occupied[i].start < range.end) {
        return true;
      }
    }
    return false;
  }

  function collectIocRanges(original) {
    const occupied = [];
    const ranges = [];

    function addRange(r) {
      if (overlapsRange(r, occupied)) {
        return;
      }
      occupied.push(r);
      ranges.push(r);
    }

    if (socUtils && socUtils.findUrlsInText) {
      socUtils.findUrlsInText(original).forEach(function (u) {
        addRange({ start: u.start, end: u.end, value: u.value, kind: 'url' });
      });
    }

    COMBINED_IP_RE.lastIndex = 0;
    let m = null;
    while ((m = COMBINED_IP_RE.exec(original))) {
      const ip = m[0];
      if (!isSupportedPublicIP(ip)) {
        continue;
      }
      addRange({ start: m.index, end: m.index + ip.length, value: ip, kind: 'ip' });
    }

    DOMAIN_TEXT_RE.lastIndex = 0;
    while ((m = DOMAIN_TEXT_RE.exec(original))) {
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
      addRange({ start: start, end: end, value: domain, kind: 'domain', display: full });
    }

    if (socUtils && socUtils.findFileHashesInText) {
      socUtils.findFileHashesInText(original).forEach(function (h) {
        addRange({ start: h.start, end: h.end, value: h.value, kind: 'file' });
      });
    }

    ranges.sort(function (a, b) {
      return a.start - b.start;
    });
    return ranges;
  }

  function createBadgeForRange(r) {
    if (r.kind === 'url') {
      return createUrlBadge(r.value);
    }
    if (r.kind === 'ip') {
      return createIpBadge(r.value);
    }
    if (r.kind === 'domain') {
      return createDomainBadge(r.value);
    }
    if (r.kind === 'file') {
      return createHashBadge(r.value);
    }
    return null;
  }

