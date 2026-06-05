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

  // sanitizeVtPermalink: VirusTotal GUI bağlantılarını URL parse ile doğrular.
  function sanitizeVtPermalink(rawUrl) {
    const href = String(rawUrl || '').trim();
    if (!href) {
      return '#';
    }
    try {
      const parsed = new URL(href);
      if (parsed.protocol !== 'https:') {
        return '#';
      }
      if (parsed.hostname !== 'www.virustotal.com') {
        return '#';
      }
      return parsed.href;
    } catch (_) {
      return '#';
    }
  }

  // sanitizeAbuseReportUrl: AbuseIPDB check bağlantılarını URL parse ile doğrular.
  function sanitizeAbuseReportUrl(rawUrl) {
    const href = String(rawUrl || '').trim();
    if (!href) {
      return '';
    }
    try {
      const parsed = new URL(href);
      if (parsed.protocol !== 'https:') {
        return '';
      }
      if (parsed.hostname !== 'www.abuseipdb.com') {
        return '';
      }
      if (!parsed.pathname.startsWith('/check/')) {
        return '';
      }
      return parsed.href;
    } catch (_) {
      return '';
    }
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
        title ? t('usomCopyTitle') + ' ' + title : '',
        date ? t('usomCopyDate') + ' ' + date : '',
        tags ? t('usomCopyTags') + ' ' + tags : '',
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
        /* Yavaş yanıt geldiğinde satır yeniden render edilmiş veya kapatılmış olabilir;
           kopuk ya da artık açık olmayan node'u doldurma. */
        if (!detailNode.isConnected || (key && expandedUsomKey !== key)) {
          return;
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
    SecurityWeek: 'securityweek'
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
      const reduceMotion =
        typeof window.matchMedia === 'function' &&
        window.matchMedia('(prefers-reduced-motion: reduce)').matches;
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
      if (reduceMotion) {
        characterSprite.classList.add('face-down');
      } else {
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

