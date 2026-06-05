'use strict';

/**
 * Shared utilities — IoC detection & badges: tag tones, URL/hash text scanning,
 * kind detection, risk tiers, rel-mode checkboxes, copy-summary field config.
 */
(function (global) {
  const U = (global.VtSocUtils = global.VtSocUtils || {});

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
    let s = U.normalizeIocInput(String(raw || '').trim());
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

  // isIpv6: Strict-ish IPv6 doğrulayıcı (tek '::', isteğe bağlı IPv4 sonu, zone id).
  function isIpv6(raw) {
    let s = String(raw || '').trim();
    if (s.startsWith('[') && s.endsWith(']')) {
      s = s.slice(1, -1);
    }
    const pct = s.indexOf('%');
    if (pct !== -1) {
      s = s.slice(0, pct);
    }
    if (!s || s.indexOf(':') === -1) {
      return false;
    }
    const halves = s.split('::');
    if (halves.length > 2) {
      return false;
    }
    const compressed = halves.length === 2;
    const ipv4Re = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    function countGroups(seg) {
      if (seg === '') {
        return 0;
      }
      const g = seg.split(':');
      let n = 0;
      for (let i = 0; i < g.length; i++) {
        const piece = g[i];
        if (/^[0-9a-fA-F]{1,4}$/.test(piece)) {
          n += 1;
        } else if (i === g.length - 1 && ipv4Re.test(piece)) {
          n += 2;
        } else {
          return -1;
        }
      }
      return n;
    }
    const head = countGroups(halves[0]);
    if (head < 0) {
      return false;
    }
    if (!compressed) {
      return head === 8;
    }
    const tail = countGroups(halves[1]);
    if (tail < 0) {
      return false;
    }
    return head + tail <= 7;
  }

  function parseIpv4Octets(ip) {
    const parts = String(ip || '').trim().split('.');
    if (parts.length !== 4) {
      return null;
    }
    const out = [];
    for (let i = 0; i < 4; i++) {
      const n = Number(parts[i]);
      if (!Number.isInteger(n) || n < 0 || n > 255) {
        return null;
      }
      out.push(n);
    }
    return out;
  }

  function normalizeIpv6ForCheck(raw) {
    let s = String(raw || '').trim().toLowerCase();
    if (s.startsWith('[') && s.endsWith(']')) {
      s = s.slice(1, -1);
    }
    const pct = s.indexOf('%');
    if (pct !== -1) {
      s = s.slice(0, pct);
    }
    return s;
  }

  function isPublicRoutableIpv4(ip) {
    const o = parseIpv4Octets(ip);
    if (!o) {
      return false;
    }
    const a = o[0];
    const b = o[1];
    const c = o[2];
    if (a === 0 || a === 10 || a === 127) {
      return false;
    }
    if (a === 100 && b >= 64 && b <= 127) {
      return false;
    }
    if (a === 169 && b === 254) {
      return false;
    }
    if (a === 172 && b >= 16 && b <= 31) {
      return false;
    }
    if (a === 192 && b === 168) {
      return false;
    }
    if (a >= 224) {
      return false;
    }
    if (a === 192 && b === 0 && (c === 0 || c === 2)) {
      return false;
    }
    if (a === 198 && (b === 18 || b === 19)) {
      return false;
    }
    if (a === 198 && b === 51 && c === 100) {
      return false;
    }
    if (a === 203 && b === 0 && c === 113) {
      return false;
    }
    return true;
  }

  function isPublicRoutableIpv6(ip) {
    const s = normalizeIpv6ForCheck(ip);
    if (!s || !isIpv6(s)) {
      return false;
    }
    if (s === '::1' || s === '::') {
      return false;
    }
    const head = s.split(':')[0] || '';
    if (/^fe[89ab][0-9a-f]{0,2}$/i.test(head)) {
      return false;
    }
    if (/^f[cd][0-9a-f]{0,2}$/i.test(head)) {
      return false;
    }
    if (/^ff[0-9a-f]{0,2}$/i.test(head)) {
      return false;
    }
    if (s === '2001:db8' || s.indexOf('2001:db8:') === 0) {
      return false;
    }
    return true;
  }

  // isPublicRoutableIp: RFC1918/reserved aralıkları dış API'lere gönderilmesin diye kontrol eder.
  function isPublicRoutableIp(ip) {
    const s = String(ip || '').trim();
    if (!s) {
      return false;
    }
    if (s.indexOf(':') !== -1) {
      return isPublicRoutableIpv6(s);
    }
    return isPublicRoutableIpv4(s);
  }

  // detectIocKind: Tek IoC sınıflandırıcı (detectIoc ile aynı kurallar).
  function detectIocKind(raw) {
    const s = String(raw || '').trim();
    if (!s) {
      return 'unknown';
    }
    if (/^https?:\/\//i.test(s)) {
      try {
        // eslint-disable-next-line no-new
        new URL(s);
        return 'url';
      } catch (_) {
        return 'unknown';
      }
    }
    const ipv4Re = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipv4Re.test(s)) {
      return 'ip';
    }
    if (isIpv6(s)) {
      return 'ip';
    }
    if (/^[a-fA-F0-9]{32}$/.test(s) || /^[a-fA-F0-9]{40}$/.test(s) || /^[a-fA-F0-9]{64}$/.test(s)) {
      return 'file';
    }
    const domainRe = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
    if (domainRe.test(s) && !/\s/.test(s) && s.length <= 253) {
      return 'domain';
    }
    return 'unknown';
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

  Object.assign(U, {
    classifyVtTagTone: classifyVtTagTone,
    mapTagsToHeroChips: mapTagsToHeroChips,
    normalizeUrlCandidate: normalizeUrlCandidate,
    isLikelyHttpUrl: isLikelyHttpUrl,
    isFileHashToken: isFileHashToken,
    rangesOverlap: rangesOverlap,
    overlapsAny: overlapsAny,
    findUrlsInText: findUrlsInText,
    findFileHashesInText: findFileHashesInText,
    shortenHash: shortenHash,
    isIpv6: isIpv6,
    isPublicRoutableIp: isPublicRoutableIp,
    detectIocKind: detectIocKind,
    abuseScoreToRiskTier: abuseScoreToRiskTier,
    payloadToBadgeRisk: payloadToBadgeRisk,
    relModeFromCheckboxes: relModeFromCheckboxes,
    checkboxesFromRelMode: checkboxesFromRelMode,
    defaultCopySummaryFields: defaultCopySummaryFields,
    copySummaryFieldKeys: copySummaryFieldKeys,
    normalizeCopySummaryFields: normalizeCopySummaryFields
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
