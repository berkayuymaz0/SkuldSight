'use strict';

  function decorateTextNodeWithIocs(textNode) {
    if (badgeCount >= MAX_BADGES) {
      return false;
    }
    const original = String(textNode.nodeValue || '');
    const ranges = collectIocRanges(original);
    if (!ranges.length) {
      return false;
    }
    let lastIndex = 0;
    const frag = document.createDocumentFragment();
    for (let i = 0; i < ranges.length; i++) {
      if (badgeCount >= MAX_BADGES) {
        break;
      }
      const r = ranges[i];
      if (r.start > lastIndex) {
        frag.appendChild(document.createTextNode(original.slice(lastIndex, r.start)));
      }
      const displayText = r.display || original.slice(r.start, r.end);
      const tokenAttr = TOKEN_ATTR_BY_KIND[r.kind];
      const wrap = document.createElement('span');
      if (tokenAttr) {
        wrap.setAttribute(tokenAttr, '1');
      }
      wrap.style.whiteSpace = 'nowrap';
      wrap.appendChild(document.createTextNode(displayText));
      const btn = createBadgeForRange(r);
      if (btn) {
        wrap.appendChild(btn);
      }
      frag.appendChild(wrap);
      lastIndex = r.end;
    }
    if (lastIndex < original.length) {
      frag.appendChild(document.createTextNode(original.slice(lastIndex)));
    }
    textNode.parentNode.replaceChild(frag, textNode);
    return true;
  }

  function textNodeMayContainIoc(text) {
    const s = String(text || '');
    return /https?:\/\/|hxxps?:\/\/|hxxp:\/\/|\b(?:\d{1,3}\.){3}\d{1,3}\b|(?:[a-z0-9-]+\.)+[a-z]{2,63}\b|[a-fA-F0-9]{32,64}|(?:[A-Fa-f0-9]{1,4}:){2,}|::[A-Fa-f0-9]/i.test(
      s
    );
  }

  function processVisibleTextIocs(root) {
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
      if (nodes.length >= MAX_TEXT_NODES_PER_FLUSH) {
        break;
      }
      const n = walker.currentNode;
      if (shouldSkipTextNode(n)) {
        continue;
      }
      if (!textNodeMayContainIoc(n.nodeValue || '')) {
        continue;
      }
      nodes.push(n);
    }
    for (let i = 0; i < nodes.length; i++) {
      if (badgeCount >= MAX_BADGES) {
        break;
      }
      decorateTextNodeWithIocs(nodes[i]);
    }
  }

  // Debounce sonunda biriken mutasyon köklerinde veya tüm belgede domain taramasını çalıştırır.
  function flushPendingDomainScan() {
    domainScanDebounceTimer = null;
    if (!contentIocBadgesEnabled || isCurrentPageBlacklisted()) {
      pendingMutationRoots.clear();
      return;
    }
    const docRoot = document.body || document.documentElement;
    if (!docRoot) {
      pendingMutationRoots.clear();
      return;
    }
    if (pendingMutationRoots.size === 0) {
      processVisibleTextIocs(docRoot);
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
      processVisibleTextIocs(el);
    }
    if (roots.length > flushCount) {
      for (let i = flushCount; i < roots.length; i++) {
        pendingMutationRoots.add(roots[i]);
      }
      scheduleDomainScan();
    }
  }

  let domainScanIdleId = null;

  function cancelScheduledDomainScan() {
    if (domainScanDebounceTimer !== null) {
      window.clearTimeout(domainScanDebounceTimer);
      domainScanDebounceTimer = null;
    }
    if (domainScanIdleId !== null && typeof cancelIdleCallback === 'function') {
      cancelIdleCallback(domainScanIdleId);
      domainScanIdleId = null;
    }
  }

  // Alan adı taramasını kısa gecikmeyle tek seferde birleştirerek (debounce) zamanlar.
  function scheduleDomainScan() {
    if (!contentIocBadgesEnabled || isCurrentPageBlacklisted()) {
      return;
    }
    cancelScheduledDomainScan();
    const run = function () {
      domainScanDebounceTimer = null;
      domainScanIdleId = null;
      flushPendingDomainScan();
    };
    if (typeof requestIdleCallback === 'function') {
      domainScanIdleId = window.requestIdleCallback(run, {
        timeout: DOMAIN_SCAN_DEBOUNCE_MS + 50
      });
      return;
    }
    domainScanDebounceTimer = window.setTimeout(run, DOMAIN_SCAN_DEBOUNCE_MS);
  }

  // DOM’a eklenen düğümleri izleyerek yeniden rozet taraması için kökleri kuyruğa alır.
  // Bizim eklediğimiz rozet/sarmalayıcı düğümleri için mutasyonları yok say (gereksiz yeniden tarama döngüsünü azaltır).
  function isOwnVtDecoration(node) {
    if (!node || node.nodeType !== Node.ELEMENT_NODE || !node.hasAttribute) {
      return false;
    }
    return (
      node.hasAttribute(DOMAIN_TOKEN_ATTR) ||
      node.hasAttribute(IP_TOKEN_ATTR) ||
      node.hasAttribute(URL_TOKEN_ATTR) ||
      node.hasAttribute(HASH_TOKEN_ATTR) ||
      node.hasAttribute(DOMAIN_BTN_ATTR) ||
      node.hasAttribute(IP_BTN_ATTR) ||
      node.hasAttribute(URL_BTN_ATTR) ||
      node.hasAttribute(HASH_BTN_ATTR)
    );
  }

  function onMutationForDomains(mutations) {
    let dirty = false;
    for (let i = 0; i < mutations.length; i++) {
      const m = mutations[i];
      if (m.type === 'characterData') {
        const parent = m.target && m.target.parentElement;
        if (parent) {
          pendingMutationRoots.add(parent);
          dirty = true;
        }
        continue;
      }
      if (m.type !== 'childList' || !m.addedNodes || m.addedNodes.length === 0) {
        continue;
      }
      for (let j = 0; j < m.addedNodes.length; j++) {
        const node = m.addedNodes[j];
        if (node.nodeType === Node.ELEMENT_NODE) {
          if (isOwnVtDecoration(node)) {
            continue;
          }
          pendingMutationRoots.add(node);
          dirty = true;
        } else if (node.nodeType === Node.TEXT_NODE && node.parentElement) {
          if (isOwnVtDecoration(node.parentElement)) {
            continue;
          }
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
    if (observer || !contentIocBadgesEnabled || isCurrentPageBlacklisted()) {
      return;
    }
    pendingMutationRoots.clear();
    cancelScheduledDomainScan();
    const docRoot = document.body || document.documentElement;
    processVisibleTextIocs(docRoot);
    observer = new MutationObserver(onMutationForDomains);
    observer.observe(document.documentElement || document.body, {
      childList: true,
      subtree: true,
      characterData: true
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
        (t && t.closest && t.closest('[' + IP_BTN_ATTR + '="1"]')) ||
        (t && t.closest && t.closest('[' + URL_BTN_ATTR + '="1"]')) ||
        (t && t.closest && t.closest('[' + HASH_BTN_ATTR + '="1"]'))
      ) {
        return;
      }
      hideDomainPanel();
    },
    true
  );

  /* Başlangıç taraması, ayarlar yüklendikten sonra detect.js'teki storage.get
     callback'inden tetiklenir; burada senkron çalıştırmak varsayılan ayarlarla
     gereksiz tam tarama yapardı (race). */
