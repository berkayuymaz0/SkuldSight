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

