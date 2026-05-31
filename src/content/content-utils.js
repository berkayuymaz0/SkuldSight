'use strict';

/**
 * Lightweight subset of utils.js for content scripts (IOC detection, badge risk, copy summary).
 */
(function (global) {
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

  global.VtSocUtils = {
    buildSummaryLine: buildSummaryLine,
    payloadToBadgeRisk: payloadToBadgeRisk,
    findUrlsInText: findUrlsInText,
    findFileHashesInText: findFileHashesInText,
    overlapsAny: overlapsAny,
    shortenHash: shortenHash
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);
