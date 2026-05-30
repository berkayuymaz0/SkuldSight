'use strict';

(function (global) {
  // VT istek aralığı ve yerel analitik özet nesnesi için varsayılan sabitler.
  const DEFAULT_RATE_INTERVAL_SEC = 16;
  const MIN_RATE_INTERVAL_SEC = 15;
  const MAX_RATE_INTERVAL_SEC = 20;
  const DEFAULT_ANALYTICS_VERSION = 2;
  const DEFAULT_ANALYTICS_DAYS_KEEP = 60;
  const API_KEY_TTL_MS = 14 * 24 * 60 * 60 * 1000;
  const SCAN_PRESETS_VERSION = 3;
  const SCAN_PRESET_IDS = ['quick', 'detailed', 'analyst'];
  const IOC_KINDS = ['ip', 'domain', 'url', 'file'];
  const STORAGE_KEYS = {
    contextScanResult: 'vtContextScanResult',
    scanPreset: 'vtScanPreset',
    scanPresets: 'vtScanPresets',
    copySummaryFields: 'vtCopySummaryFields',
    newsReadMap: 'vtNewsReadMap',
    newsCache: 'vtNewsCache',
    newsFetchedAt: 'vtNewsFetchedAt',
    usomCache: 'vtUsomCache',
    usomFetchedAt: 'vtUsomFetchedAt',
    popupActiveTab: 'vtPopupActiveTab',
    analytics: 'vtAnalytics',
    uiMode: 'vtUiMode'
  };
  const COPY_SUMMARY_KINDS = ['ip', 'domain', 'url', 'file'];
  const COPY_SUMMARY_FIELD_KEYS = [
    'ioc',
    'kind',
    'threatLevel',
    'vt',
    'detectionRatio',
    'reputation',
    'suggestedThreat',
    'abuseScore',
    'abuseReports',
    'tags',
    'distinctLabels',
    'mitre',
    'time',
    'reportLink'
  ];
  const DEFAULT_COPY_SUMMARY_FIELDS = {
    ip: {
      ioc: true,
      kind: true,
      threatLevel: true,
      vt: true,
      detectionRatio: true,
      reputation: true,
      suggestedThreat: true,
      abuseScore: true,
      abuseReports: true,
      tags: true,
      distinctLabels: false,
      mitre: false,
      time: true,
      reportLink: true
    },
    domain: {
      ioc: true,
      kind: true,
      threatLevel: true,
      vt: true,
      detectionRatio: true,
      reputation: true,
      suggestedThreat: true,
      abuseScore: false,
      abuseReports: false,
      tags: true,
      distinctLabels: true,
      mitre: false,
      time: true,
      reportLink: true
    },
    url: {
      ioc: true,
      kind: true,
      threatLevel: true,
      vt: true,
      detectionRatio: true,
      reputation: true,
      suggestedThreat: true,
      abuseScore: false,
      abuseReports: false,
      tags: true,
      distinctLabels: true,
      mitre: false,
      time: true,
      reportLink: true
    },
    file: {
      ioc: true,
      kind: true,
      threatLevel: true,
      vt: true,
      detectionRatio: true,
      reputation: true,
      suggestedThreat: true,
      abuseScore: false,
      abuseReports: false,
      tags: true,
      distinctLabels: true,
      mitre: true,
      time: true,
      reportLink: true
    }
  };

  /** IoC türü başına VT sorgu profili (relMode, labels, mitre). */
  const DEFAULT_SCAN_PRESETS = {
    quick: {
      ip: {
        relMode: 'none',
        labels: 'standard',
        mitre: false,
        abuseReports: false,
        abuseWindowDays: 30,
        abuseOverallDays: 90
      },
      domain: { relMode: 'none', labels: 'standard', mitre: false },
      url: { relMode: 'none', labels: 'standard', mitre: false },
      file: { relMode: 'none', labels: 'standard', mitre: false }
    },
    detailed: {
      ip: {
        relMode: 'primary',
        labels: 'standard',
        mitre: false,
        abuseReports: true,
        abuseWindowDays: 30,
        abuseOverallDays: 180
      },
      domain: { relMode: 'full', labels: 'standard', mitre: false },
      url: { relMode: 'primary', labels: 'standard', mitre: false },
      file: { relMode: 'full', labels: 'standard', mitre: true }
    },
    analyst: {
      ip: {
        relMode: 'full',
        labels: 'extended',
        mitre: false,
        abuseReports: true,
        abuseWindowDays: 90,
        abuseOverallDays: 365
      },
      domain: { relMode: 'full', labels: 'extended', mitre: false },
      url: { relMode: 'primary', labels: 'extended', mitre: false },
      file: { relMode: 'full', labels: 'extended', mitre: true }
    }
  };

  const ABUSE_WINDOW_DAY_CHOICES = [30, 90];
  const ABUSE_OVERALL_DAY_CHOICES = [90, 180, 365];

  function clampAbuseDays(value, fallback, allowed) {
    const n = Number(value);
    if (isFinite(n) && allowed.indexOf(n) >= 0) {
      return n;
    }
    const fb = Number(fallback);
    if (isFinite(fb) && allowed.indexOf(fb) >= 0) {
      return fb;
    }
    return allowed[0];
  }

  // API key saklama zaman damgasının TTL penceresini aşıp aşmadığını döndürür.
  function isApiKeyExpired(savedAt) {
    const ts = Number(savedAt);
    if (!isFinite(ts) || ts <= 0) {
      return false;
    }
    return Date.now() - ts > API_KEY_TTL_MS;
  }

  // Kullanıcı ayarındaki saniye değerini izin verilen aralığa yuvarlar ve sayı değilse varsayılanı döndürür.
  function clampRateSec(sec) {
    const n = Number(sec);
    if (!isFinite(n)) {
      return DEFAULT_RATE_INTERVAL_SEC;
    }
    return Math.min(MAX_RATE_INTERVAL_SEC, Math.max(MIN_RATE_INTERVAL_SEC, Math.round(n)));
  }

  // SOC yapıştırma/defang gürültüsünü ve yaygın hataları gidererek VT’ye uygun IoC metni üretir.
  /**
   * Strip SOC paste/defang noise and common mistakes that still match naive domain regex
   * but are rejected by VirusTotal (e.g. Python bytes repr b'host', or ".com" + "vt" → ".comvt").
   */
  function normalizeIocInput(raw) {
    let s = String(raw || '').trim();
    if (!s) {
      return s;
    }
    s = s.replace(/\uFEFF/g, '');
    let guard = 0;
    while (guard++ < 8) {
      let changed = false;
      const first = s.charCodeAt(0);
      const last = s.charCodeAt(s.length - 1);
      if (
        s.length >= 3 &&
        (first === 98 || first === 66) &&
        (s.charAt(1) === "'" || s.charAt(1) === '"')
      ) {
        const q = s.charAt(1);
        if (last === q.charCodeAt(0) && s.length > 3) {
          s = s.slice(2, -1).trim();
          changed = true;
        }
      }
      if (
        !changed &&
        s.length >= 2 &&
        ((first === 34 && last === 34) || (first === 39 && last === 39))
      ) {
        s = s.slice(1, -1).trim();
        changed = true;
      }
      if (!changed) {
        break;
      }
    }
    s = s.replace(/\bhxxps:\/\//gi, 'https://');
    s = s.replace(/\bhxxp:\/\//gi, 'http://');
    s = s.replace(/\[\.\]/g, '.');
    s = s.trim();

    const vtGlue = /^(.+)\.(com|net|org)vt$/i;
    const glued = vtGlue.exec(s.toLowerCase());
    if (glued) {
      s = glued[1] + '.' + glued[2].toLowerCase();
    }

    return s.trim();
  }

  // Zaman damgasını YYYY-MM-DD gün anahtarına çevirir (günlük analitik gruplama için).
  function dayKeyFromTs(ts) {
    const d = new Date(Number(ts) || Date.now());
    const y = d.getFullYear();
    const m = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');
    return y + '-' + m + '-' + day;
  }

  // Boş/yeni analitik yapısı üretir (sürüm alanı ile).
  function defaultAbuseAnalytics() {
    return { lookups: 0, high: 0, elevated: 0 };
  }

  function defaultAnalytics(version) {
    return {
      version: Number(version) || DEFAULT_ANALYTICS_VERSION,
      totalScans: 0,
      threats: { malicious: 0, suspicious: 0, clean: 0 },
      byKind: { ip: 0, domain: 0, url: 0, file: 0 },
      abuse: defaultAbuseAnalytics(),
      byDay: {},
      lastUpdated: 0
    };
  }

  // byDay içinde retention penceresi dışındaki günleri atarak sözlüğü budar.
  function pruneByDay(byDay, daysKeep) {
    const keep = Math.max(1, Number(daysKeep) || DEFAULT_ANALYTICS_DAYS_KEEP);
    const cutoff = Date.now() - keep * 24 * 60 * 60 * 1000;
    const out = {};
    Object.keys(byDay || {}).forEach(function (k) {
      const parts = k.split('-');
      if (parts.length !== 3) {
        return;
      }
      const t = new Date(Number(parts[0]), Number(parts[1]) - 1, Number(parts[2])).getTime();
      if (isFinite(t) && t >= cutoff) {
        out[k] = Math.max(0, Number(byDay[k]) || 0);
      }
    });
    return out;
  }

  // Depodan gelen ham analitik nesnesini sayımlar ve sürümle tutarlı, budanmış forma dönüştürür.
  function normalizeAnalytics(raw, opts) {
    const options = opts || {};
    const version = Number(options.version) || DEFAULT_ANALYTICS_VERSION;
    const daysKeep = Number(options.daysKeep) || DEFAULT_ANALYTICS_DAYS_KEEP;
    const shouldPrune = options.pruneByDay !== false;
    const base = defaultAnalytics(version);
    const src = raw && typeof raw === 'object' ? raw : {};
    const threats = src.threats && typeof src.threats === 'object' ? src.threats : {};
    const byKind = src.byKind && typeof src.byKind === 'object' ? src.byKind : {};
    const abuseSrc = src.abuse && typeof src.abuse === 'object' ? src.abuse : {};
    const byDay = src.byDay && typeof src.byDay === 'object' ? src.byDay : {};
    return {
      version: version,
      totalScans: Math.max(0, Number(src.totalScans) || 0),
      threats: {
        malicious: Math.max(0, Number(threats.malicious) || 0),
        suspicious: Math.max(0, Number(threats.suspicious) || 0),
        clean: Math.max(0, Number(threats.clean) || 0)
      },
      byKind: {
        ip: Math.max(0, Number(byKind.ip) || 0),
        domain: Math.max(0, Number(byKind.domain) || 0),
        url: Math.max(0, Number(byKind.url) || 0),
        file: Math.max(0, Number(byKind.file) || 0)
      },
      abuse: {
        lookups: Math.max(0, Number(abuseSrc.lookups) || 0),
        high: Math.max(0, Number(abuseSrc.high) || 0),
        elevated: Math.max(0, Number(abuseSrc.elevated) || 0)
      },
      byDay: shouldPrune ? pruneByDay(byDay, daysKeep) : byDay,
      lastUpdated: Number(src.lastUpdated) || base.lastUpdated
    };
  }

  // data-i18n / placeholder / title öznitelikli DOM düğümlerine çeviri uygular; istenirse document.title günceller.
  function applyI18n(root, translate, opts) {
    const doc = root || global.document;
    const options = opts || {};
    if (!doc || typeof translate !== 'function') {
      return;
    }
    doc.querySelectorAll('[data-i18n]').forEach(function (el) {
      const key = el.getAttribute('data-i18n');
      if (key) {
        el.textContent = translate(key);
      }
    });
    doc.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) {
      const key = el.getAttribute('data-i18n-placeholder');
      if (key) {
        el.placeholder = translate(key);
      }
    });
    doc.querySelectorAll('[data-i18n-title]').forEach(function (el) {
      const key = el.getAttribute('data-i18n-title');
      if (key) {
        el.title = translate(key);
      }
    });
    doc.querySelectorAll('[data-i18n-aria-label]').forEach(function (el) {
      const key = el.getAttribute('data-i18n-aria-label');
      if (key) {
        el.setAttribute('aria-label', translate(key));
      }
    });
    if (options.titleKey && doc.title !== undefined) {
      const parts = [translate(options.titleKey)];
      if (options.titleSuffixKey) {
        parts.push(translate(options.titleSuffixKey));
      }
      doc.title = parts.filter(Boolean).join(options.titleJoiner || ' — ');
    }
  }

  function formatReputationSummary(rep) {
    if (rep === undefined || rep === null || rep === '') {
      return '—';
    }
    return String(rep);
  }

  /**
   * VT file signature_info.verified is a string (e.g. "Valid", "Unsigned") or boolean.
   * @returns {'valid'|'invalid'|'unknown'}
   */
  function resolveSignatureState(signatureInfo) {
    const sig = signatureInfo && typeof signatureInfo === 'object' ? signatureInfo : {};
    const raw = sig.verified;
    if (raw === undefined || raw === null || raw === '') {
      const signers = sig.signers;
      const hasSigners = Array.isArray(signers)
        ? signers.some(function (x) {
            return x;
          })
        : !!String(signers || '').trim();
      return hasSigners ? 'valid' : 'unknown';
    }
    if (typeof raw === 'boolean') {
      return raw ? 'valid' : 'invalid';
    }
    const s = String(raw).trim().toLowerCase();
    if (/^(valid|signed|true|yes|ok|verified)$/.test(s)) {
      return 'valid';
    }
    if (/^(invalid|unsigned|false|no|expired|revoked|not\s*signed|unverified|a\s*problem)/.test(s)) {
      return 'invalid';
    }
    return 'unknown';
  }

  // detailSignatureStatus satırı için i18n anahtarı.
  function signatureStatusI18nKey(state) {
    if (state === 'valid') {
      return 'detailSignatureValid';
    }
    if (state === 'invalid') {
      return 'detailSignatureInvalid';
    }
    return 'detailSignatureUnknown';
  }

  // Özet satırında gösterilecek imza metni.
  function formatSignatureDetailValue(signatureInfo, translate) {
    const t = typeof translate === 'function' ? translate : function (k) {
      return k;
    };
    const state = resolveSignatureState(signatureInfo);
    const key = signatureStatusI18nKey(state);
    const label = t(key);
    const raw =
      signatureInfo &&
      signatureInfo.verified !== undefined &&
      signatureInfo.verified !== null &&
      signatureInfo.verified !== ''
        ? String(signatureInfo.verified).trim()
        : '';
    if (raw && label !== raw && state !== 'unknown') {
      return label + ' (' + raw + ')';
    }
    return label !== key ? label : raw || t('detailSignatureUnknown');
  }

  const SUMMARY_KIND_I18N = {
    ip: 'optKindIp',
    domain: 'optKindDomain',
    url: 'optKindUrl',
    file: 'optKindFile'
  };

  /** Detail row order per IoC kind (matches extractIocDetails in background.js). */
  const SUMMARY_DETAIL_ORDER = {
    file: [
      'detailFileName',
      'detailFileSize',
      'detailFileType',
      'detailProduct',
      'detailDescription',
      'detailSigners',
      'detailCopyright',
      'detailSignatureStatus',
      'detailMd5',
      'detailSha1',
      'detailSha256',
      'detailMagic',
      'detailTimesSubmitted',
      'detailContactedWithDetections',
      'detailFirstSeen',
      'detailLastSeen',
      'detailLastAnalysis'
    ],
    domain: [
      'detailRegistrar',
      'detailWhois',
      'detailCategories',
      'detailCreationDate',
      'detailLastAnalysis',
      'detailDnsValues',
      'detailVotes',
      'detailHttpsCert'
    ],
    ip: [
      'detailCountry',
      'detailRir',
      'detailAsn',
      'detailAsOwner',
      'detailNetwork',
      'detailLastAnalysis',
      'detailVotes',
      'detailJarm',
      'detailHttpsCert',
      'detailAbuseScore',
      'detailAbuseReports',
      'detailAbuseLastReported',
      'detailAbuseTopCategory'
    ],
    url: [
      'detailFinalUrl',
      'detailPageTitle',
      'detailHttpStatus',
      'detailRedirectChain',
      'detailLastAnalysis',
      'detailCategories'
    ]
  };

  function normSummaryToken(s) {
    return String(s || '')
      .replace(/\s+/g, ' ')
      .trim()
      .toLowerCase();
  }

  function summaryValueSeen(seen, value) {
    const n = normSummaryToken(value);
    if (!n) {
      return true;
    }
    if (seen.has(n)) {
      return true;
    }
    seen.add(n);
    return false;
  }

  function pushSummaryLine(lines, seen, text, value) {
    const v = String(value != null ? value : '')
      .replace(/\s+/g, ' ')
      .trim();
    if (!v) {
      return;
    }
    if (summaryValueSeen(seen, v)) {
      return;
    }
    lines.push(text);
  }

  function formatDetailRowValue(row, translate) {
    const t = typeof translate === 'function' ? translate : function (k) {
      return k;
    };
    let val = row.value;
    if (row.id === 'detailSignatureStatus') {
      if (val === 'valid' || val === 'invalid' || val === 'unknown') {
        val = t(signatureStatusI18nKey(val));
      }
    }
    return String(val != null ? val : '')
      .replace(/\s+/g, ' ')
      .trim();
  }

  function localizedIocKind(kind, translate) {
    const t = typeof translate === 'function' ? translate : function (k) {
      return k;
    };
    const key = SUMMARY_KIND_I18N[kind];
    return key ? t(key) : kind || '';
  }

  function buildSummaryLine(payload, translate) {
    const t = typeof translate === 'function' ? translate : function (key) {
      return key;
    };
    const p = payload && typeof payload === 'object' ? payload : {};
    const s = p.stats || {};
    const kind = p.iocKind || '';
    const iocNorm = normSummaryToken(p.ioc);
    const seen = new Set();
    if (iocNorm) {
      seen.add(iocNorm);
    }
    const lines = [];

    lines.push(
      t('summaryIoc', {
        ioc: p.ioc || ''
      })
    );
    const kindLabel = localizedIocKind(kind, t);
    if (kindLabel) {
      lines.push(
        t('summaryType', {
          kind: kindLabel
        })
      );
    }
    lines.push(
      t('summaryVtDetections', {
        mal: s.malicious || 0,
        susp: s.suspicious || 0,
        und: s.undetected || 0
      })
    );

    const rep = formatReputationSummary(p.reputation);
    if (rep !== '—') {
      pushSummaryLine(lines, seen, t('summaryReputation', { rep: rep }), rep);
    }

    const tc = p.threatContext;
    const suggested =
      (tc && tc.suggestedLabel && String(tc.suggestedLabel).trim()) || '';
    if (suggested) {
      pushSummaryLine(
        lines,
        seen,
        t('summarySuggestedThreat', { label: suggested }),
        suggested
      );
    }

    const detailMap = {};
    if (Array.isArray(p.details)) {
      p.details.forEach(function (row) {
        if (row && row.id) {
          detailMap[row.id] = row;
        }
      });
    }
    const detailOrder = SUMMARY_DETAIL_ORDER[kind] || [];
    detailOrder.forEach(function (id) {
      const row = detailMap[id];
      if (!row) {
        return;
      }
      const val = formatDetailRowValue(row, t);
      if (!val) {
        return;
      }
      if (iocNorm && normSummaryToken(val) === iocNorm) {
        return;
      }
      pushSummaryLine(lines, seen, t(id) + ': ' + val, val);
    });

    const hero = p.hero;
    if (hero && Array.isArray(hero.tagChips) && hero.tagChips.length) {
      const tags = hero.tagChips
        .map(function (c) {
          return c && c.value ? String(c.value).trim() : '';
        })
        .filter(Boolean)
        .slice(0, 12)
        .join(', ');
      pushSummaryLine(lines, seen, t('summaryTags', { tags: tags }), tags);
    }

    if (tc && Array.isArray(tc.popularNames) && tc.popularNames.length) {
      const names = tc.popularNames
        .map(function (x) {
          return x && x.value ? String(x.value).trim() : '';
        })
        .filter(Boolean)
        .slice(0, 6)
        .join(', ');
      if (names && normSummaryToken(names) !== normSummaryToken(suggested)) {
        pushSummaryLine(
          lines,
          seen,
          t('summaryPopularNames', { names: names }),
          names
        );
      }
    }

    if (tc && Array.isArray(tc.distinctLabels) && tc.distinctLabels.length) {
      const labels = tc.distinctLabels
        .map(function (x) {
          if (!x) {
            return '';
          }
          const lbl = x.label != null ? String(x.label).trim() : '';
          if (!lbl) {
            return '';
          }
          const cnt = Number(x.count) || 0;
          return cnt > 1 ? lbl + ' (' + cnt + ')' : lbl;
        })
        .filter(Boolean)
        .slice(0, 8)
        .join(', ');
      const sugNorm = normSummaryToken(suggested);
      const labelsNorm = normSummaryToken(labels);
      if (
        labels &&
        labelsNorm !== sugNorm &&
        (!sugNorm || labelsNorm.indexOf(sugNorm) === -1)
      ) {
        pushSummaryLine(
          lines,
          seen,
          t('summaryDistinctLabels', { labels: labels }),
          labels
        );
      }
    }

    const mit = p.mitreTechniques;
    if (mit && Array.isArray(mit.ids) && mit.ids.length > 0) {
      const ids = mit.ids.slice(0, 12).join(', ');
      pushSummaryLine(lines, seen, t('summaryMitre', { ids: ids }), ids);
    }

    lines.push(
      t('summaryTime', {
        time: new Date().toISOString()
      })
    );
    lines.push(
      t('summaryReport', {
        link: p.permalink ? String(p.permalink).trim() : '—'
      })
    );

    return lines.join('\n');
  }

  // normalizeScanPresetKind: Tek IoC türü için preset satırı.
  function normalizeScanPresetKind(raw, fallback) {
    const fb = fallback || { relMode: 'none', labels: 'standard', mitre: false };
    const src = raw && typeof raw === 'object' ? raw : {};
    let relMode = src.relMode;
    if (relMode !== 'none' && relMode !== 'primary' && relMode !== 'full') {
      if (src.rel === true) {
        relMode = src.relSecondary === false ? 'primary' : 'full';
      } else if (src.rel === false) {
        relMode = 'none';
      } else {
        relMode = fb.relMode;
      }
    }
    let labels = src.labels === 'extended' ? 'extended' : 'standard';
    if (src.engine === true) {
      labels = 'extended';
    } else if (src.engine === false) {
      labels = 'standard';
    } else if (src.labels !== 'extended' && src.labels !== 'standard') {
      labels = fb.labels;
    }
    const fbIp =
      fb && fb.abuseReports !== undefined
        ? fb
        : DEFAULT_SCAN_PRESETS.quick.ip;
    return {
      relMode: relMode,
      labels: labels,
      mitre: src.mitre === true ? true : src.mitre === false ? false : fb.mitre === true,
      abuseReports:
        src.abuseReports === true
          ? true
          : src.abuseReports === false
            ? false
            : fbIp.abuseReports === true,
      abuseWindowDays: clampAbuseDays(
        src.abuseWindowDays,
        fbIp.abuseWindowDays,
        ABUSE_WINDOW_DAY_CHOICES
      ),
      abuseOverallDays: clampAbuseDays(
        src.abuseOverallDays,
        fbIp.abuseOverallDays,
        ABUSE_OVERALL_DAY_CHOICES
      )
    };
  }

  // normalizeScanPresetProfile: Bir preset için dört IoC profilini birleştirir.
  function normalizeScanPresetProfile(raw, fallbackProfile) {
    const fb = fallbackProfile || DEFAULT_SCAN_PRESETS.quick;
    const src = raw && typeof raw === 'object' ? raw : {};
    if (src.relMode || src.labels || src.mitre !== undefined || src.rel !== undefined) {
      const flat = normalizeScanPresetKind(src, fb.ip || fb.domain);
      const out = {};
      IOC_KINDS.forEach(function (k) {
        out[k] = flat;
      });
      return out;
    }
    const out = {};
    IOC_KINDS.forEach(function (k) {
      out[k] = normalizeScanPresetKind(src[k], fb[k]);
    });
    return out;
  }

  // migrateScanPresetsStorage: v1/v2 → v3 (IoC başına profil).
  function migrateScanPresetsStorage(raw) {
    if (raw && raw.version === SCAN_PRESETS_VERSION && raw.presets) {
      return normalizeScanPresetsMap(raw.presets);
    }
    if (raw && raw.version === 2 && raw.presets) {
      const out = {};
      SCAN_PRESET_IDS.forEach(function (id) {
        const flat = normalizeScanPresetKind(raw.presets[id], DEFAULT_SCAN_PRESETS[id].ip);
        const profile = {};
        IOC_KINDS.forEach(function (k) {
          profile[k] = flat;
        });
        out[id] = normalizeScanPresetProfile(profile, DEFAULT_SCAN_PRESETS[id]);
      });
      return out;
    }
    const legacy = raw && typeof raw === 'object' ? raw : {};
    if (legacy.quick || legacy.detailed || legacy.analyst) {
      const out = {};
      SCAN_PRESET_IDS.forEach(function (id) {
        const leg = legacy[id];
        const flat = normalizeScanPresetKind(
          {
            rel: leg && leg.rel,
            engine: leg && leg.engine,
            mitre: leg && leg.mitre,
            relSecondary: leg && leg.relSecondary
          },
          DEFAULT_SCAN_PRESETS[id].ip
        );
        if (leg && leg.rel === true && flat.relMode === 'none') {
          flat.relMode = 'full';
        }
        const profile = {};
        IOC_KINDS.forEach(function (k) {
          profile[k] = flat;
        });
        out[id] = normalizeScanPresetProfile(profile, DEFAULT_SCAN_PRESETS[id]);
      });
      return out;
    }
    return normalizeScanPresetsMap(null);
  }

  // getDefaultScanPresetsMap: Fabrika varsayılanı (v3, IoC başına profil).
  function getDefaultScanPresetsMap() {
    return normalizeScanPresetsMap({});
  }

  // normalizeScanPresetsMap: quick/detailed/analyst → IoC profilleri.
  function normalizeScanPresetsMap(rawMap) {
    const map = rawMap && typeof rawMap === 'object' ? rawMap : {};
    const out = {};
    SCAN_PRESET_IDS.forEach(function (id) {
      out[id] = normalizeScanPresetProfile(map[id], DEFAULT_SCAN_PRESETS[id]);
    });
    return out;
  }

  // resolvePresetForKind: Aktif preset + IoC türü → tek profil satırı.
  function resolvePresetForKind(presetMap, presetId, iocKind) {
    const map = presetMap || {};
    const id =
      presetId === 'detailed' || presetId === 'analyst' || presetId === 'quick'
        ? presetId
        : 'quick';
    const profile = map[id] || DEFAULT_SCAN_PRESETS[id];
    const kind = IOC_KINDS.indexOf(iocKind) >= 0 ? iocKind : 'file';
    return normalizeScanPresetKind(profile[kind], DEFAULT_SCAN_PRESETS[id][kind]);
  }

  // presetToRuntimeFlags: IoC profil satırı → tarama bayrakları.
  function presetToRuntimeFlags(profile) {
    const p = normalizeScanPresetKind(profile, DEFAULT_SCAN_PRESETS.quick.ip);
    return {
      relPreview: p.relMode !== 'none',
      relSecondary: p.relMode === 'full',
      engineBreakdown: p.labels === 'extended',
      mitre: p.mitre === true
    };
  }

  // presetToAbuseFlags: IP profil satırı → AbuseIPDB sorgu bayrakları.
  function presetToAbuseFlags(profile) {
    const p = normalizeScanPresetKind(profile, DEFAULT_SCAN_PRESETS.quick.ip);
    return {
      includeReports: p.abuseReports === true,
      maxAgeInDays: p.abuseWindowDays,
      overallDays: p.abuseOverallDays
    };
  }

  // abusePresetSummaryCode: Options matris hücresi için kısa Abuse özeti.
  function abusePresetSummaryCode(profile) {
    const p = normalizeScanPresetKind(profile, DEFAULT_SCAN_PRESETS.quick.ip);
    if (!p.abuseReports) {
      return 'CHK';
    }
    return 'R' + p.abuseWindowDays + '/' + p.abuseOverallDays;
  }

  // estimateAbuseCallsForPreset: Tahmini AbuseIPDB HTTP çağrısı (IP taramaları).
  function estimateAbuseCallsForPreset(profile, iocKind) {
    if (iocKind !== 'ip') {
      return 0;
    }
    const p = normalizeScanPresetKind(profile, DEFAULT_SCAN_PRESETS.quick.ip);
    return p.abuseReports ? 2 : 1;
  }

  // storagePayloadFromPresets: chrome.storage.local için v3 nesnesi.
  function storagePayloadFromPresets(map) {
    return {
      version: SCAN_PRESETS_VERSION,
      presets: normalizeScanPresetsMap(map)
    };
  }

  // classifyVtTagTone: VT community tag rengi / tonu.
  function classifyVtTagTone(tag) {
    const s = String(tag || '').toLowerCase();
    if (
      /malware|trojan|ransom|phish|exploit|backdoor|dropper|stealer|virus|worm|rat|miner|keylog|rootkit|apt|packed|obfus|shellcode|cve-|cve_/.test(
        s
      )
    ) {
      return 'threat';
    }
    if (/legitimate|signed|trusted|clean|safe|whitelisted|known|benign|valid/.test(s)) {
      return 'good';
    }
    if (/suspicious|risk|untrusted|unsigned|invalid|pua|adware|grayware|greyware|spam/.test(s)) {
      return 'warn';
    }
    if (
      /peexe|elf|macho|pdf|docx|android|ios|assembly|installer|package|xar|script|powershell|macro/.test(
        s
      )
    ) {
      return 'file';
    }
    return 'neutral';
  }

  // mapTagsToHeroChips: VT tags → hero chip dizisi (Details’ta gösterilmez).
  function mapTagsToHeroChips(tags, max) {
    if (!Array.isArray(tags)) {
      return [];
    }
    const lim = Number(max) > 0 ? Number(max) : 12;
    const out = [];
    for (let i = 0; i < tags.length && out.length < lim; i++) {
      const val = String(tags[i] || '').replace(/\s+/g, ' ').trim();
      if (!val) {
        continue;
      }
      out.push({
        type: 'tag',
        value: val.slice(0, 80),
        tone: classifyVtTagTone(val)
      });
    }
    return out;
  }

  const URL_TEXT_RE = /\b(?:https?:\/\/|hxxps?:\/\/|hxxp:\/\/)[^\s<>"')\]]+/gi;
  const FILE_HASH_TEXT_RE =
    /(?<![a-fA-F0-9])([a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})(?![a-fA-F0-9])/g;

  function trimUrlTrailingPunct(s) {
    return String(s || '').replace(/[.,;:!?)\]}>]+$/, '');
  }

  function normalizeUrlCandidate(raw) {
    let s = normalizeIocInput(String(raw || '').trim());
    s = trimUrlTrailingPunct(s);
    return s;
  }

  function isLikelyHttpUrl(raw) {
    const u = normalizeUrlCandidate(raw);
    if (!u) {
      return false;
    }
    try {
      const parsed = new URL(u);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch (_) {
      return false;
    }
  }

  function isFileHashToken(raw) {
    const v = String(raw || '').trim().toLowerCase();
    if (/^[a-f0-9]{32}$/.test(v)) {
      return { value: v, hashType: 'md5' };
    }
    if (/^[a-f0-9]{40}$/.test(v)) {
      return { value: v, hashType: 'sha1' };
    }
    if (/^[a-f0-9]{64}$/.test(v)) {
      return { value: v, hashType: 'sha256' };
    }
    return null;
  }

  function rangesOverlap(a, b) {
    return a.start < b.end && b.start < a.end;
  }

  function overlapsAny(range, occupied) {
    for (let i = 0; i < occupied.length; i++) {
      if (rangesOverlap(range, occupied[i])) {
        return true;
      }
    }
    return false;
  }

  function findUrlsInText(text) {
    const src = String(text || '');
    const out = [];
    const occupied = [];
    URL_TEXT_RE.lastIndex = 0;
    let m = null;
    while ((m = URL_TEXT_RE.exec(src))) {
      const raw = m[0];
      const start = m.index;
      const normalized = normalizeUrlCandidate(raw);
      if (!isLikelyHttpUrl(normalized)) {
        continue;
      }
      const range = { start: start, end: start + raw.length, value: normalized, kind: 'url' };
      if (overlapsAny(range, occupied)) {
        continue;
      }
      occupied.push(range);
      out.push(range);
    }
    return out;
  }

  function findFileHashesInText(text) {
    const src = String(text || '');
    const out = [];
    FILE_HASH_TEXT_RE.lastIndex = 0;
    let m = null;
    while ((m = FILE_HASH_TEXT_RE.exec(src))) {
      const token = m[1];
      const info = isFileHashToken(token);
      if (!info) {
        continue;
      }
      out.push({
        start: m.index,
        end: m.index + m[0].length,
        value: info.value,
        hashType: info.hashType,
        kind: 'file'
      });
    }
    return out;
  }

  function shortenHash(hash, head, tail) {
    const s = String(hash || '').trim();
    const h = Number(head) > 0 ? Number(head) : 10;
    const t = Number(tail) > 0 ? Number(tail) : 8;
    if (s.length <= h + t + 3) {
      return s;
    }
    return s.slice(0, h) + '…' + s.slice(-t);
  }

  // detectIocKind: Popup kota ipucu için hafif IoC sınıflandırma.
  function detectIocKind(raw) {
    const s = String(raw || '').trim();
    if (!s) {
      return 'unknown';
    }
    if (/^https?:\/\//i.test(s)) {
      return 'url';
    }
    const ipv4Re = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipv4Re.test(s)) {
      return 'ip';
    }
    if (/^[a-fA-F0-9]{32}$/.test(s) || /^[a-fA-F0-9]{40}$/.test(s) || /^[a-fA-F0-9]{64}$/.test(s)) {
      return 'file';
    }
    const domainRe = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
    if (domainRe.test(s) && !/\s/.test(s)) {
      return 'domain';
    }
    return 'unknown';
  }

  // estimateVtCallsForPreset: Tahmini VT HTTP çağrısı (üst sınır); profile = tek IoC satırı.
  function estimateVtCallsForPreset(profile, iocKind) {
    const kind = IOC_KINDS.indexOf(iocKind) >= 0 ? iocKind : 'file';
    const p = normalizeScanPresetKind(profile, DEFAULT_SCAN_PRESETS.quick[kind]);
    let max = 2;
    if (iocKind === 'url') {
      max = 2;
    } else {
      max = 1;
    }
    if (p.relMode === 'primary') {
      max += 1;
    } else if (p.relMode === 'full') {
      max += 2;
    }
    if (p.mitre && (!iocKind || iocKind === 'file')) {
      max += 1;
    }
    return max;
  }

  // abuseScoreToRiskTier: AbuseIPDB skorunu rozet risk katmanına eşler.
  function abuseScoreToRiskTier(score) {
    if (typeof score !== 'number' || !isFinite(score)) {
      return 'unknown';
    }
    if (score <= 24) {
      return 'low';
    }
    if (score <= 49) {
      return 'medium';
    }
    if (score <= 74) {
      return 'high';
    }
    return 'critical';
  }

  // payloadToBadgeRisk: Tarama sonucundan inline rozet risk seviyesi.
  function payloadToBadgeRisk(payload) {
    if (!payload || !payload.ok) {
      return 'unknown';
    }
    const level = payload.threatLevel || 'clean';
    if (level === 'malicious') {
      return 'malicious';
    }
    if (level === 'suspicious') {
      return 'suspicious';
    }
    return 'clean';
  }

  // relModeFromCheckboxes: Options formu → relMode.
  function relModeFromCheckboxes(relOn, relSecondaryOn) {
    if (!relOn) {
      return 'none';
    }
    return relSecondaryOn ? 'full' : 'primary';
  }

  // checkboxesFromRelMode: relMode → form checkbox durumu.
  function checkboxesFromRelMode(relMode) {
    if (relMode === 'full') {
      return { rel: true, relSecondary: true };
    }
    if (relMode === 'primary') {
      return { rel: true, relSecondary: false };
    }
    return { rel: false, relSecondary: false };
  }

  function defaultCopySummaryFields() {
    const out = {};
    COPY_SUMMARY_KINDS.forEach(function (kind) {
      out[kind] = Object.assign({}, DEFAULT_COPY_SUMMARY_FIELDS[kind]);
    });
    return out;
  }

  function copySummaryFieldKeys() {
    return COPY_SUMMARY_FIELD_KEYS.slice();
  }

  function normalizeCopySummaryFields(raw) {
    const src = raw && typeof raw === 'object' ? raw : {};
    const fallback = defaultCopySummaryFields();
    const out = {};
    COPY_SUMMARY_KINDS.forEach(function (kind) {
      const row = src[kind] && typeof src[kind] === 'object' ? src[kind] : {};
      out[kind] = {};
      COPY_SUMMARY_FIELD_KEYS.forEach(function (field) {
        if (row[field] === true || row[field] === false) {
          out[kind][field] = row[field];
        } else {
          out[kind][field] = fallback[kind][field] === true;
        }
      });
    });
    return out;
  }

  global.VtSocUtils = {
    STORAGE_KEYS: STORAGE_KEYS,
    clampRateSec: clampRateSec,
    normalizeIocInput: normalizeIocInput,
    dayKeyFromTs: dayKeyFromTs,
    defaultAnalytics: defaultAnalytics,
    defaultAbuseAnalytics: defaultAbuseAnalytics,
    pruneByDay: pruneByDay,
    normalizeAnalytics: normalizeAnalytics,
    applyI18n: applyI18n,
    buildSummaryLine: buildSummaryLine,
    resolveSignatureState: resolveSignatureState,
    signatureStatusI18nKey: signatureStatusI18nKey,
    formatSignatureDetailValue: formatSignatureDetailValue,
    SCAN_PRESETS_VERSION: SCAN_PRESETS_VERSION,
    SCAN_PRESET_IDS: SCAN_PRESET_IDS,
    DEFAULT_SCAN_PRESETS: DEFAULT_SCAN_PRESETS,
    API_KEY_TTL_MS: API_KEY_TTL_MS,
    isApiKeyExpired: isApiKeyExpired,
    getDefaultScanPresetsMap: getDefaultScanPresetsMap,
    IOC_KINDS: IOC_KINDS,
    migrateScanPresetsStorage: migrateScanPresetsStorage,
    normalizeScanPresetsMap: normalizeScanPresetsMap,
    normalizeScanPresetKind: normalizeScanPresetKind,
    normalizeScanPresetProfile: normalizeScanPresetProfile,
    resolvePresetForKind: resolvePresetForKind,
    presetToRuntimeFlags: presetToRuntimeFlags,
    presetToAbuseFlags: presetToAbuseFlags,
    abusePresetSummaryCode: abusePresetSummaryCode,
    estimateAbuseCallsForPreset: estimateAbuseCallsForPreset,
    ABUSE_WINDOW_DAY_CHOICES: ABUSE_WINDOW_DAY_CHOICES,
    ABUSE_OVERALL_DAY_CHOICES: ABUSE_OVERALL_DAY_CHOICES,
    storagePayloadFromPresets: storagePayloadFromPresets,
    estimateVtCallsForPreset: estimateVtCallsForPreset,
    classifyVtTagTone: classifyVtTagTone,
    mapTagsToHeroChips: mapTagsToHeroChips,
    detectIocKind: detectIocKind,
    relModeFromCheckboxes: relModeFromCheckboxes,
    checkboxesFromRelMode: checkboxesFromRelMode,
    abuseScoreToRiskTier: abuseScoreToRiskTier,
    payloadToBadgeRisk: payloadToBadgeRisk
    ,
    defaultCopySummaryFields: defaultCopySummaryFields,
    copySummaryFieldKeys: copySummaryFieldKeys,
    normalizeCopySummaryFields: normalizeCopySummaryFields,
    normalizeUrlCandidate: normalizeUrlCandidate,
    isLikelyHttpUrl: isLikelyHttpUrl,
    isFileHashToken: isFileHashToken,
    findUrlsInText: findUrlsInText,
    findFileHashesInText: findFileHashesInText,
    rangesOverlap: rangesOverlap,
    overlapsAny: overlapsAny,
    shortenHash: shortenHash
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
