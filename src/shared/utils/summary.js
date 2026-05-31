'use strict';

/**
 * Shared utilities — summary/i18n: applyI18n, signature formatting, copyable summary builder.
 */
(function (global) {
  const U = (global.VtSocUtils = global.VtSocUtils || {});

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

  const SUMMARY_DETAIL_FIELD_KEY = {
    detailAbuseScore: 'abuseScore',
    detailAbuseReports: 'abuseReports'
  };

  function buildSummaryLine(payload, translate, enabledFields) {
    const t = typeof translate === 'function' ? translate : function (key) {
      return key;
    };
    /* enabledFields verilirse yalnızca true alanlar yazılır; verilmezse tüm
       alanlar (geriye dönük uyumlu davranış). */
    function fieldOn(key) {
      return !enabledFields || enabledFields[key] === true;
    }
    const p = payload && typeof payload === 'object' ? payload : {};
    const s = p.stats || {};
    const kind = p.iocKind || '';
    const iocNorm = normSummaryToken(p.ioc);
    const seen = new Set();
    if (iocNorm) {
      seen.add(iocNorm);
    }
    const lines = [];

    if (fieldOn('ioc')) {
      lines.push(
        t('summaryIoc', {
          ioc: p.ioc || ''
        })
      );
    }
    const kindLabel = localizedIocKind(kind, t);
    if (kindLabel && fieldOn('kind')) {
      lines.push(
        t('summaryType', {
          kind: kindLabel
        })
      );
    }
    if (fieldOn('vt')) {
      lines.push(
        t('summaryVtDetections', {
          mal: s.malicious || 0,
          susp: s.suspicious || 0,
          und: s.undetected || 0
        })
      );
    }

    const rep = formatReputationSummary(p.reputation);
    if (rep !== '—' && fieldOn('reputation')) {
      pushSummaryLine(lines, seen, t('summaryReputation', { rep: rep }), rep);
    }

    const tc = p.threatContext;
    const suggested =
      (tc && tc.suggestedLabel && String(tc.suggestedLabel).trim()) || '';
    if (suggested && fieldOn('suggestedThreat')) {
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
      const fieldKey = SUMMARY_DETAIL_FIELD_KEY[id];
      if (fieldKey && !fieldOn(fieldKey)) {
        return;
      }
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
    if (hero && Array.isArray(hero.tagChips) && hero.tagChips.length && fieldOn('tags')) {
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

    if (tc && Array.isArray(tc.distinctLabels) && tc.distinctLabels.length && fieldOn('distinctLabels')) {
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
    if (mit && Array.isArray(mit.ids) && mit.ids.length > 0 && fieldOn('mitre')) {
      const ids = mit.ids.slice(0, 12).join(', ');
      pushSummaryLine(lines, seen, t('summaryMitre', { ids: ids }), ids);
    }

    if (fieldOn('time')) {
      lines.push(
        t('summaryTime', {
          time: new Date().toISOString()
        })
      );
    }
    if (fieldOn('reportLink')) {
      lines.push(
        t('summaryReport', {
          link: p.permalink ? String(p.permalink).trim() : '—'
        })
      );
    }

    return lines.join('\n');
  }

  Object.assign(U, {
    applyI18n: applyI18n,
    resolveSignatureState: resolveSignatureState,
    signatureStatusI18nKey: signatureStatusI18nKey,
    formatSignatureDetailValue: formatSignatureDetailValue,
    buildSummaryLine: buildSummaryLine
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
