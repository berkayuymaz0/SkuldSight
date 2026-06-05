// Options modules share state through the window.VtOptions namespace.
// Load order (see options.html): state -> settings -> analytics -> init.
(function (NS) {
  const utils = window.VtSocUtils;
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const SK = utils.STORAGE_KEYS;
  const SCAN_PRESETS_KEY = SK.scanPresets;
  const COPY_SUMMARY_FIELDS_KEY = SK.copySummaryFields;
  const ANALYTICS_KEY = SK.analytics;
  /** Keys read together for the analytics section (avoid duplicate storage reads on theme-only updates). */
  const OPTIONS_DASHBOARD_KEYS = [ANALYTICS_KEY, 'vtBatchHistory'];
  const KIND_ORDER = ['ip', 'domain', 'url', 'file'];
  const TIMELINE_DAYS = 14;

  const normalizeAnalytics = utils.normalizeAnalytics;

  // Sayfa üzerindeki form, toast ve grafik DOM referansları (id ile bağlanır).
  const dom = {
    keyForm: document.getElementById('key-form'),
    langForm: document.getElementById('lang-form'),
    behaviorForm: document.getElementById('behavior-form'),
    presetsForm: document.getElementById('scan-presets-form'),
    btnResetScanPresets: document.getElementById('btn-reset-scan-presets'),
    blacklistForm: document.getElementById('blacklist-form'),
    copySummaryForm: document.getElementById('copy-summary-form'),
    btnCopySummaryTemplateReset: document.getElementById('btn-copy-summary-template-reset'),
    btnCopyPresetMinimal: document.getElementById('btn-copy-preset-minimal'),
    btnCopyPresetAnalyst: document.getElementById('btn-copy-preset-analyst'),
    btnCopyPresetFull: document.getElementById('btn-copy-preset-full'),
    copyMatrixToggles: Array.prototype.slice.call(document.querySelectorAll('.copy-matrix-toggle')),
    uiLang: document.getElementById('ui-lang'),
    apiKey: document.getElementById('api-key'),
    rateSlider: document.getElementById('rate-interval'),
    rateLabel: document.getElementById('rate-interval-label'),
    uiModePopup: document.getElementById('ui-mode-popup'),
    uiModeSidepanel: document.getElementById('ui-mode-sidepanel'),
    proMode: document.getElementById('pro-mode'),
    batchUseAbuse: document.getElementById('batch-use-abuse'),
    notifyQueued: document.getElementById('notify-queued'),
    notifyNews: document.getElementById('notify-news'),
    notifyContext: document.getElementById('notify-context'),
    contentIocBadges: document.getElementById('content-ioc-badges'),
    scanFullUrls: document.getElementById('scan-full-urls'),
    blacklist: document.getElementById('domain-badge-blacklist'),
    btnClearHistory: document.getElementById('btn-clear-history'),
    btnClearBatch: document.getElementById('btn-clear-batch'),
    btnTestApi: document.getElementById('btn-test-api'),
    abuseKeyForm: document.getElementById('abuse-key-form'),
    abuseApiKey: document.getElementById('abuse-api-key'),
    btnTestAbuseApi: document.getElementById('btn-test-abuse-api'),
    toast: document.getElementById('toast'),
    toastText: document.getElementById('toast-text'),
    kpiTotal: document.getElementById('kpi-total'),
    kpiMal: document.getElementById('kpi-mal'),
    kpiSusp: document.getElementById('kpi-susp'),
    kpiKind: document.getElementById('kpi-kind'),
    kpiKindSub: document.getElementById('kpi-kind-sub'),
    kpiAbuseLookups: document.getElementById('kpi-abuse-lookups'),
    kpiAbuseSub: document.getElementById('kpi-abuse-sub'),
    chartDonut: document.getElementById('chart-donut'),
    chartDonutLegend: document.getElementById('chart-donut-legend'),
    chartDonutMeta: document.getElementById('chart-donut-meta'),
    chartBars: document.getElementById('chart-bars'),
    chartBarsMeta: document.getElementById('chart-bars-meta'),
    chartTimeline: document.getElementById('chart-timeline'),
    chartTimelineMeta: document.getElementById('chart-timeline-meta'),
    chartBatch: document.getElementById('chart-batch'),
    chartBatchMeta: document.getElementById('chart-batch-meta'),
    chartBatchStat: document.getElementById('chart-batch-stat'),
    chartBatchLegend: document.getElementById('chart-batch-legend')
  };

  // Raf tabanlı analitik yenileme ve son çizilen grafik imzaları; toast zamanlayıcıları.
  const state = {
    analyticsRafId: 0,
    analyticsQueued: false,
    /** Last payload from storage; used to repaint charts when only CSS theme tokens change. */
    lastAnalyticsSnapshot: null,
    lastKpiSig: '',
    lastDonutSig: '',
    lastBarsSig: '',
    lastTimelineSig: '',
    lastBatchSig: '',
    toastTimerId: 0,
    toastHideTimerId: 0
  };

  // Tarama şablonu (quick/detailed/analyst) onay kutularının DOM referansları.
  const presetInputs = {
    quick: {
      rel: document.getElementById('preset-quick-rel'),
      relSec: document.getElementById('preset-quick-relsec'),
      engine: document.getElementById('preset-quick-engine'),
      mitre: document.getElementById('preset-quick-mitre'),
      abuseReports: document.getElementById('preset-quick-abuse-reports'),
      abuseWindow: document.getElementById('preset-quick-abuse-window'),
      abuseOverall: document.getElementById('preset-quick-abuse-overall')
    },
    detailed: {
      rel: document.getElementById('preset-detailed-rel'),
      relSec: document.getElementById('preset-detailed-relsec'),
      engine: document.getElementById('preset-detailed-engine'),
      mitre: document.getElementById('preset-detailed-mitre'),
      abuseReports: document.getElementById('preset-detailed-abuse-reports'),
      abuseWindow: document.getElementById('preset-detailed-abuse-window'),
      abuseOverall: document.getElementById('preset-detailed-abuse-overall')
    },
    analyst: {
      rel: document.getElementById('preset-analyst-rel'),
      relSec: document.getElementById('preset-analyst-relsec'),
      engine: document.getElementById('preset-analyst-engine'),
      mitre: document.getElementById('preset-analyst-mitre'),
      abuseReports: document.getElementById('preset-analyst-abuse-reports'),
      abuseWindow: document.getElementById('preset-analyst-abuse-window'),
      abuseOverall: document.getElementById('preset-analyst-abuse-overall')
    }
  };

  NS.utils = utils;
  NS.SVG_NS = SVG_NS;
  NS.SK = SK;
  NS.SCAN_PRESETS_KEY = SCAN_PRESETS_KEY;
  NS.COPY_SUMMARY_FIELDS_KEY = COPY_SUMMARY_FIELDS_KEY;
  NS.ANALYTICS_KEY = ANALYTICS_KEY;
  NS.OPTIONS_DASHBOARD_KEYS = OPTIONS_DASHBOARD_KEYS;
  NS.KIND_ORDER = KIND_ORDER;
  NS.TIMELINE_DAYS = TIMELINE_DAYS;
  NS.normalizeAnalytics = normalizeAnalytics;
  NS.dom = dom;
  NS.state = state;
  NS.presetInputs = presetInputs;
})(window.VtOptions = window.VtOptions || {});

