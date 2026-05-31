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
    const confirmedTimeout = Number(s.confirmedTimeout) || 0;
    const typeUnsupported = Number(s.typeUnsupported) || 0;
    const sum = mal + susp + und + harmless + timeout + failure + confirmedTimeout + typeUnsupported;
    return {
      mal: mal,
      susp: susp,
      und: und,
      other: harmless + timeout + failure + confirmedTimeout + typeUnsupported,
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

  function severityChipLabel(level) {
    const short = String(level || '').replace(/^SEVERITY_/, '');
    const key = 'vtSeverity_' + short;
    const msg = t(key);
    return msg !== key ? msg : short;
  }

  function renderAnalysisFreshness(payload) {
    if (!resultVtFreshness) {
      return;
    }
    const fresh = payload && payload.analysisFreshness;
    if (!fresh || fresh.days == null) {
      resultVtFreshness.hidden = true;
      resultVtFreshness.textContent = '';
      resultVtFreshness.className = 'result-vt-freshness';
      return;
    }
    resultVtFreshness.hidden = false;
    resultVtFreshness.textContent =
      fresh.days === 0 ? t('analysisFreshnessToday') : t('analysisFreshnessDays', { n: fresh.days });
    resultVtFreshness.className =
      'result-vt-freshness' + (fresh.stale ? ' is-stale' : '');
    if (fresh.stale) {
      resultVtFreshness.title = t('analysisFreshnessStale');
    } else {
      resultVtFreshness.removeAttribute('title');
    }
  }

  function appendRelationshipListItems(listEl, items, onPivot) {
    (items || []).forEach(function (item) {
      const row = item && typeof item === 'object' ? item : { label: String(item || '') };
      const label = row.label ? String(row.label) : '';
      if (!label) {
        return;
      }
      const li = document.createElement('li');
      li.className = 'result-extra-li result-rel-li';
      const mal = Number(row.malicious) || 0;
      const susp = Number(row.suspicious) || 0;
      if (mal > 0 || susp > 0) {
        li.classList.add(mal > 0 ? 'is-mal' : 'is-susp');
      }
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'result-rel-pivot';
      btn.textContent = label;
      if (mal > 0 || susp > 0) {
        btn.textContent += ' (M' + mal + (susp > 0 ? ' S' + susp : '') + ')';
      }
      btn.addEventListener('click', function () {
        if (typeof onPivot === 'function') {
          onPivot(label, row.iocKind);
        }
      });
      li.appendChild(btn);
      listEl.appendChild(li);
    });
  }

  function pivotToScan(ioc, iocKind) {
    if (!input || !ioc) {
      return;
    }
    input.value = ioc;
    hideError();
    if (typeof runScan === 'function') {
      runScan();
    }
  }

  // renderResultChart: Motor dağılımı ve özet metrikleri.
  function renderResultChart(stats, payload) {
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
      if (resultChartRatio) {
        clearElement(resultChartRatio);
      }
      if (resultVtEmpty) {
        resultVtEmpty.hidden = false;
      }
      if (payload) {
        renderAnalysisFreshness(payload);
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

    if (payload) {
      renderAnalysisFreshness(payload);
    }

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

  function canVtReanalyzePayload(payload) {
    if (!payload || payload.ok !== true || !payload.ioc || !payload.iocKind) {
      return false;
    }
    return ['ip', 'domain', 'url', 'file'].indexOf(payload.iocKind) >= 0;
  }

  function clearVtReanalyzeStatus() {
    if (!vtReanalyzeStatus) {
      return;
    }
    vtReanalyzeStatus.hidden = true;
    vtReanalyzeStatus.textContent = '';
    vtReanalyzeStatus.classList.remove('is-success', 'is-error', 'is-pending');
  }

  function showVtReanalyzeStatus(message, tone) {
    if (!vtReanalyzeStatus) {
      return;
    }
    const msg = String(message || '').trim();
    if (!msg) {
      clearVtReanalyzeStatus();
      return;
    }
    vtReanalyzeStatus.textContent = msg;
    vtReanalyzeStatus.hidden = false;
    vtReanalyzeStatus.classList.remove('is-success', 'is-error', 'is-pending');
    if (tone === 'error') {
      vtReanalyzeStatus.classList.add('is-error');
    } else if (tone === 'pending') {
      vtReanalyzeStatus.classList.add('is-pending');
    } else {
      vtReanalyzeStatus.classList.add('is-success');
    }
  }

  function syncVtReanalyzeButton(payload) {
    if (!btnVtReanalyze) {
      return;
    }
    const show = canVtReanalyzePayload(payload);
    btnVtReanalyze.hidden = !show;
    if (!show) {
      btnVtReanalyze.disabled = false;
      btnVtReanalyze.removeAttribute('aria-busy');
      clearVtReanalyzeStatus();
      vtReanalyzeStatusIocKey = '';
      return;
    }
    const statusKey = payload.iocKind + ':' + payload.ioc;
    if (statusKey !== vtReanalyzeStatusIocKey) {
      clearVtReanalyzeStatus();
      vtReanalyzeStatusIocKey = statusKey;
    }
    btnVtReanalyze.disabled = false;
    btnVtReanalyze.removeAttribute('aria-busy');
    btnVtReanalyze.title = t('vtReanalyzeTitle');
    btnVtReanalyze.setAttribute('aria-label', t('vtReanalyzeTitle'));
  }

  function handleVtReanalyzeClick() {
    const payload = lastResultPayload;
    if (!canVtReanalyzePayload(payload)) {
      return;
    }
    if (btnVtReanalyze) {
      btnVtReanalyze.disabled = true;
      btnVtReanalyze.setAttribute('aria-busy', 'true');
    }
    showVtReanalyzeStatus(t('vtReanalyzePending'), 'pending');
    sendToBackground(
      {
        type: 'VT_REANALYZE',
        iocKind: payload.iocKind,
        ioc: payload.ioc,
        vtObjectId: payload.vtObjectId || '',
        waitForCompletion: true
      },
      function (res, err) {
        if (btnVtReanalyze) {
          btnVtReanalyze.disabled = false;
          btnVtReanalyze.removeAttribute('aria-busy');
        }
        if (err) {
          showVtReanalyzeStatus(t('errorVtReanalyzeFailed'), 'error');
          return;
        }
        if (res && res.ok && res.scan && res.scan.ok) {
          renderResult(res.scan);
          showVtReanalyzeStatus(t('vtReanalyzeComplete'), 'success');
          return;
        }
        if (res && res.ok && res.poll && res.poll.ok === false) {
          showVtReanalyzeStatus(t('vtReanalyzePollTimeout'), 'success');
          return;
        }
        if (res && res.ok) {
          showVtReanalyzeStatus(t('vtReanalyzeQueued'), 'success');
          return;
        }
        const key = res && res.errorKey ? res.errorKey : 'errorVtReanalyzeFailed';
        const vars = res && res.errorVars && typeof res.errorVars === 'object' ? res.errorVars : {};
        showVtReanalyzeStatus(t(key, vars), 'error');
      }
    );
  }

  function renderThreatDashboard(payload) {
    const isIp = isIpScanPayload(payload);
    syncAbuseCardVisibility(payload);
    syncVtReanalyzeButton(payload);
    const hasVt = renderResultChart(payload.stats, payload);
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
        return c && c.type !== 'reputation' && c.type !== 'tag' && (c.value || c.type === 'signature' || c.type === 'severity');
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
          } else if (c.type === 'severity') {
            el.textContent = severityChipLabel(c.level || c.value);
            el.className += ' is-severity';
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
    if (resultKind) {
      resultKind.textContent = (payload.iocKind || '').toUpperCase();
    }
    renderHeroFromPayload(payload);
    renderThreatDashboard(payload);
    if (resultEngineBlock && resultEngineSummary && resultEngineList) {
      const tc = payload.threatContext;
      const eb = payload.engineBreakdown;
      const hasTc = tc && threatContextHasExtraContent(tc, payload);
      const hasEb = eb && Array.isArray(eb.engines) && eb.engines.length > 0;
      if (hasTc || hasEb) {
        resultEngineBlock.hidden = false;
        clearElement(resultEngineSummary);
        clearElement(resultEngineList);
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
        if (hasTc) {
          if (tc.suggestedLabel && !suggestedLabelInHero(payload)) {
            const sug = document.createElement('div');
            sug.className = 'threat-suggested';
            sug.textContent = tc.suggestedLabel;
            resultEngineSummary.appendChild(sug);
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
        }
        if (hasEb) {
          const hdr = document.createElement('li');
          hdr.className = 'result-extra-section-title';
          hdr.textContent = t('engineBreakdownHeading');
          resultEngineList.appendChild(hdr);
          eb.engines.forEach(function (row) {
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
        }
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
          const errMsg = rp.errorKey
            ? t(rp.errorKey, rp.errorVars || {})
            : t('relationshipPreviewError', {
                rel: rp.relationship || '',
                msg: String(rp.error).slice(0, 400)
              });
          resultRelError.textContent = errMsg;
        } else {
          resultRelError.hidden = true;
          resultRelError.textContent = '';
        }
        appendRelationshipListItems(resultRelList, rp.items, pivotToScan);
      }
      if (rp2 && (rp2.error || (Array.isArray(rp2.items) && rp2.items.length > 0))) {
        resultRelBlock.hidden = false;
        anyRel = true;
        if (rp2.error) {
          resultRelError.hidden = false;
          const errMsg2 = rp2.errorKey
            ? t(rp2.errorKey, rp2.errorVars || {})
            : String(rp2.error).slice(0, 400);
          resultRelError.textContent = errMsg2;
        }
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
        appendRelationshipListItems(resultRelList, rp2.items, pivotToScan);
      }
      if (!anyRel) {
        resultRelBlock.hidden = true;
        resultRelError.hidden = true;
        if (resultRelCaption) {
          resultRelCaption.textContent = '';
        }
      }
    }
    if (resultSandboxBlock && resultSandboxList) {
      const sand = payload.sandboxVerdicts;
      if (Array.isArray(sand) && sand.length > 0) {
        if (resultSandboxDetails) {
          resultSandboxDetails.hidden = false;
        }
        resultSandboxBlock.hidden = false;
        clearElement(resultSandboxList);
        sand.forEach(function (row) {
          const li = document.createElement('li');
          li.className =
            'result-extra-li' +
            (row.category === 'malicious'
              ? ' is-mal'
              : row.category === 'suspicious'
                ? ' is-susp'
                : '');
          let line = row.name || '';
          if (row.category) {
            line += ' · ' + row.category;
          }
          if (row.confidence != null && isFinite(row.confidence)) {
            line += ' (' + row.confidence + '%)';
          }
          if (row.malwareNames && row.malwareNames.length) {
            line +=
              ' — ' +
              t('sandboxMalwareNames', { names: row.malwareNames.join(', ') });
          }
          li.textContent = line;
          resultSandboxList.appendChild(li);
        });
      } else {
        if (resultSandboxDetails) {
          resultSandboxDetails.hidden = true;
        }
        resultSandboxBlock.hidden = true;
        clearElement(resultSandboxList);
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
    if (resultSandboxDetails && resultSandboxBlock) {
      resultSandboxDetails.hidden = resultSandboxBlock.hidden;
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

