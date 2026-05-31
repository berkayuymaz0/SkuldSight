'use strict';

function stripIpv6Brackets(s) {
  if (s.startsWith('[') && s.endsWith(']')) {
    return s.slice(1, -1);
  }
  return s;
}

// isProbablyIpv6: Paylaşılan strict IPv6 doğrulayıcısına yönlendirir.
function isProbablyIpv6(s) {
  return utils.isIpv6(s);
}

// detectIoc: Tarama kuyruğu, geçmiş veya toplu özet depolama.
function detectIoc(raw) {
  const s = String(raw || '').trim();
  if (!s) {
    return { kind: 'unknown', value: s, reason: 'empty' };
  }

  if (/^https?:\/\//i.test(s)) {
    try {
      // eslint-disable-next-line no-new
      new URL(s);
      return { kind: 'url', value: s };
    } catch (_) {
      return { kind: 'unknown', value: s, reason: 'invalid-url' };
    }
  }

  const ipv4Re = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Re.test(s)) {
    return { kind: 'ip', value: s };
  }

  if (isProbablyIpv6(s)) {
    return { kind: 'ip', value: stripIpv6Brackets(s).toLowerCase() };
  }

  if (/^[a-fA-F0-9]{32}$/.test(s)) {
    return { kind: 'file', value: s.toLowerCase(), hashType: 'md5' };
  }
  if (/^[a-fA-F0-9]{40}$/.test(s)) {
    return { kind: 'file', value: s.toLowerCase(), hashType: 'sha1' };
  }
  if (/^[a-fA-F0-9]{64}$/.test(s)) {
    return { kind: 'file', value: s.toLowerCase(), hashType: 'sha256' };
  }

  const domainRe = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$/;
  if (domainRe.test(s) && !/\s/.test(s) && s.length <= 253) {
    return { kind: 'domain', value: s.toLowerCase() };
  }

  return { kind: 'unknown', value: s, reason: 'no-match' };
}

// extractStats: VT yanıtından özet alan veya yardımcı dönüşüm.
function extractStats(data) {
  const attrs = data && data.data && data.data.attributes;
  const stats = attrs && attrs.last_analysis_stats;
  if (!stats) {
    return { malicious: 0, suspicious: 0, undetected: 0, harmless: 0, timeout: 0, failure: 0 };
  }
  return {
    malicious: Number(stats.malicious) || 0,
    suspicious: Number(stats.suspicious) || 0,
    undetected: Number(stats.undetected) || 0,
    harmless: Number(stats.harmless) || 0,
    timeout: Number(stats.timeout) || 0,
    failure: Number(stats.failure) || 0
  };
}

// threatLevel: VT yanıtından özet alan veya yardımcı dönüşüm.
function threatLevel(stats) {
  if (stats.malicious > 0) {
    return 'malicious';
  }
  if (stats.suspicious > 0) {
    return 'suspicious';
  }
  return 'clean';
}

/** VT community reputation score when present (file, domain, IP, URL objects). */
function extractReputation(attrs) {
  if (!attrs || attrs.reputation === undefined || attrs.reputation === null || attrs.reputation === '') {
    return null;
  }
  const r = attrs.reputation;
  if (typeof r === 'number' && isFinite(r)) {
    return r;
  }
  const n = Number(r);
  if (isFinite(n)) {
    return n;
  }
  const s = String(r).trim().slice(0, 64);
  return s || null;
}

// formatBytes: VT yanıtından özet alan veya yardımcı dönüşüm.
function formatBytes(n) {
  const num = Number(n);
  if (!isFinite(num) || num < 0) {
    return '';
  }
  if (num < 1024) {
    return num + ' B';
  }
  const units = ['KB', 'MB', 'GB', 'TB'];
  let v = num;
  let i = -1;
  do {
    v /= 1024;
    i++;
  } while (v >= 1024 && i < units.length - 1);
  const rounded = v >= 10 || Math.abs(Math.round(v) - v) < 0.05 ? Math.round(v) : v.toFixed(1);
  return rounded + ' ' + units[i];
}

// formatVtUnix: VT yanıtından özet alan veya yardımcı dönüşüm.
function formatVtUnix(ts) {
  if (ts == null || ts === '') {
    return '';
  }
  const num = Number(ts);
  if (!isFinite(num)) {
    return '';
  }
  try {
    const d = new Date(num * 1000);
    return d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
  } catch (_) {
    return '';
  }
}

// truncateStr: Uzun metni UI için kısaltır.
function truncateStr(val, max) {
  const s = String(val || '').replace(/\s+/g, ' ').trim();
  const n = Number(max) > 0 ? Number(max) : 120;
  if (!s) {
    return '';
  }
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

// joinLimited: Dizi öğelerini sınırlı sayıda birleştirir.
function joinLimited(arr, sep, max) {
  if (!Array.isArray(arr)) {
    return '';
  }
  const lim = Number(max) > 0 ? Number(max) : 5;
  return arr
    .filter(function (x) {
      return x != null && String(x).trim();
    })
    .slice(0, lim)
    .map(function (x) {
      return String(x).trim();
    })
    .join(sep || ', ');
}

// formatTagsList: VT tags dizisini kısa metne çevirir.
function formatTagsList(tags, max) {
  if (!Array.isArray(tags)) {
    return '';
  }
  return joinLimited(tags, ', ', max || 6);
}

// formatWhoisSummary: Domain whois nesnesinden kısa özet.
function formatWhoisSummary(whois) {
  if (!whois || typeof whois !== 'object') {
    return '';
  }
  const bits = [];
  if (whois.registrar) {
    bits.push(String(whois.registrar));
  }
  if (whois.creation_date != null && whois.creation_date !== '') {
    bits.push('created ' + formatVtUnix(whois.creation_date));
  }
  if (whois.updated_date != null && whois.updated_date !== '') {
    bits.push('updated ' + formatVtUnix(whois.updated_date));
  }
  return bits.join(' · ');
}

// formatDnsRecordValues: last_dns_records içinden A/AAAA/CNAME değerleri.
function formatDnsRecordValues(records, max) {
  if (!Array.isArray(records)) {
    return '';
  }
  const lim = Number(max) > 0 ? Number(max) : 5;
  const out = [];
  for (let i = 0; i < records.length && out.length < lim; i++) {
    const r = records[i];
    if (!r) {
      continue;
    }
    const t = String(r.type || '').toUpperCase();
    const val = r.value != null ? String(r.value).trim() : '';
    if (!val || (t !== 'A' && t !== 'AAAA' && t !== 'CNAME')) {
      continue;
    }
    out.push(t + ' ' + val);
  }
  return out.join('; ');
}

// formatHttpsCertSummary: TLS sertifikasından CN / issuer özeti.
function formatHttpsCertSummary(cert) {
  if (!cert || typeof cert !== 'object') {
    return '';
  }
  const parts = [];
  if (cert.subject && cert.subject.CN) {
    parts.push('CN ' + cert.subject.CN);
  }
  if (cert.issuer && cert.issuer.O) {
    parts.push('issuer ' + cert.issuer.O);
  }
  if (cert.thumbprint_sha256) {
    parts.push('sha256 ' + String(cert.thumbprint_sha256).slice(0, 16) + '…');
  }
  return parts.join(' · ');
}

// formatRedirectChain: URL yönlendirme zincirini kısaltır.
function formatRedirectChain(chain, max) {
  if (!Array.isArray(chain)) {
    return '';
  }
  const lim = Number(max) > 0 ? Number(max) : 4;
  const hops = [];
  for (let i = 0; i < chain.length && hops.length < lim; i++) {
    const hop = chain[i];
    const u =
      (hop && (hop.url || hop.target || hop)) != null
        ? String(hop.url || hop.target || hop).trim()
        : '';
    if (u) {
      hops.push(truncateStr(u, 80));
    }
  }
  return hops.join(' → ');
}

// urlToVtId: VT v3 URL nesne kimliği (base64url, padding yok).
function urlToVtId(urlStr) {
  try {
    const bytes = new TextEncoder().encode(String(urlStr || ''));
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  } catch (_) {
    return '';
  }
}

// buildHeroSummary: IoC türüne göre scan kartı üst satırları.
function buildHeroSummary(kind, detected, attrs, threatContext, reputation) {
  const out = { subtitle: '', iocDisplay: '', tagChips: [], chips: [] };
  const tc = threatContext || {};
  const a = attrs || {};
  if (tc.suggestedLabel) {
    out.chips.push({ type: 'label', value: tc.suggestedLabel });
  }
  out.tagChips = utils.mapTagsToHeroChips(a.tags, 12);
  if (reputation !== null && reputation !== undefined && reputation !== '') {
    const rn = Number(reputation);
    if (!(kind === 'ip' && isFinite(rn) && rn === 0)) {
      out.chips.push({ type: 'reputation', value: String(reputation) });
    }
  }
  switch (kind) {
    case 'file': {
      const name =
        (a.meaningful_name && String(a.meaningful_name).trim()) ||
        (Array.isArray(a.names) && a.names[0] && String(a.names[0]).trim()) ||
        '';
      out.iocDisplay = (detected && detected.value) || a.sha256 || '';
      const sub = [];
      if (name) {
        sub.push(name);
      }
      const sig = a.signature_info || {};
      const sigState = utils.resolveSignatureState(sig);
      if (sigState === 'valid' || sigState === 'invalid') {
        out.chips.push({
          type: 'signature',
          state: sigState
        });
      }
      if (a.type_description || a.type_tag) {
        sub.push(String(a.type_description || a.type_tag));
      }
      out.subtitle = sub.join(' · ');
      break;
    }
    case 'domain': {
      out.iocDisplay = detected.value || '';
      // Registrar / kayıt tarihi yalnızca Details’ta (detailRegistrar, detailCreationDate).
      break;
    }
    case 'ip': {
      out.iocDisplay = detected.value || '';
      // Ülke / AS sahibi yalnızca Details’ta (detailCountry, detailAsOwner).
      break;
    }
    case 'url': {
      const original = detected.value || '';
      out.iocDisplay = original;
      // Başlık / final URL yalnızca Details’ta; HTTP/redirect chip olarak kalır.
      const redir = formatRedirectChain(a.redirection_chain, 3);
      if (redir) {
        out.chips.push({ type: 'redirect', value: redir });
      }
      if (a.last_http_response_code != null && a.last_http_response_code !== '') {
        out.chips.push({
          type: 'http',
          value: 'HTTP ' + String(a.last_http_response_code)
        });
      }
      break;
    }
    default:
      out.iocDisplay = detected.value || '';
      break;
  }
  return out;
}

// stringifyCategories: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function stringifyCategories(cats) {
  if (!cats || typeof cats !== 'object') {
    return '';
  }
  return Object.keys(cats)
    .map(function (k) {
      return k + ': ' + cats[k];
    })
    .join('; ');
}

/**
 * VT v3 object attributes → short detail rows for the popup (label keys for i18n in the UI).
 */
// extractIocDetails: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function extractIocDetails(kind, data) {
  const attrs = data && data.data && data.data.attributes;
  if (!attrs) {
    return [];
  }
  const rows = [];
  const MAX_ROWS = kind === 'file' ? 18 : 16;

  // add: Service worker içi yardımcı; çağrı bağlamı gövdede.
  function add(id, val) {
    if (rows.length >= MAX_ROWS) {
      return;
    }
    if (val === null || val === undefined) {
      return;
    }
    let s = String(val).replace(/\s+/g, ' ').trim();
    if (!s) {
      return;
    }
    if (s.length > 2000) {
      s = s.slice(0, 1997) + '…';
    }
    rows.push({ id: id, value: s });
  }

  switch (kind) {
    case 'file': {
      const name =
        (attrs.meaningful_name && String(attrs.meaningful_name).trim()) ||
        (Array.isArray(attrs.names) && attrs.names[0] && String(attrs.names[0]).trim()) ||
        '';
      add('detailFileName', name);
      if (attrs.size !== undefined && attrs.size !== null && attrs.size !== '') {
        add('detailFileSize', formatBytes(Number(attrs.size)));
      }
      add('detailFileType', attrs.type_description || attrs.type_tag);
      const sig = attrs.signature_info || {};
      if (sig.product) {
        add('detailProduct', sig.product);
      }
      if (sig.description && String(sig.description).trim() && sig.description !== sig.product) {
        add('detailDescription', sig.description);
      }
      if (sig.signers) {
        const signerStr = Array.isArray(sig.signers)
          ? sig.signers
              .filter(function (x) {
                return x;
              })
              .join(', ')
          : String(sig.signers);
        add('detailSigners', signerStr);
      }
      if (sig.copyright) {
        add('detailCopyright', sig.copyright);
      }
      const sigState = utils.resolveSignatureState(sig);
      if (sigState !== 'unknown' || (sig.signers && String(sig.signers).length)) {
        add('detailSignatureStatus', sigState);
      }
      add('detailMd5', attrs.md5);
      add('detailSha1', attrs.sha1);
      add('detailSha256', attrs.sha256);
      add('detailMagic', attrs.magic);
      if (attrs.times_submitted != null && attrs.times_submitted !== '') {
        add('detailTimesSubmitted', String(attrs.times_submitted));
      }
      const pivotFlags = [];
      if (attrs.has_contacted_ips_with_detections) {
        pivotFlags.push('malicious IPs');
      }
      if (attrs.has_contacted_domains_with_detections) {
        pivotFlags.push('malicious domains');
      }
      if (attrs.has_contacted_urls_with_detections) {
        pivotFlags.push('malicious URLs');
      }
      if (pivotFlags.length) {
        add('detailContactedWithDetections', pivotFlags.join(', '));
      }
      add('detailFirstSeen', formatVtUnix(attrs.first_submission_date));
      add('detailLastSeen', formatVtUnix(attrs.last_submission_date));
      add('detailLastAnalysis', formatVtUnix(attrs.last_analysis_date));
      break;
    }
    case 'domain': {
      add('detailRegistrar', attrs.registrar);
      const whois = formatWhoisSummary(attrs.whois);
      if (whois) {
        add('detailWhois', whois);
      }
      const dcats = stringifyCategories(attrs.categories);
      if (dcats) {
        add('detailCategories', dcats);
      }
      add('detailCreationDate', formatVtUnix(attrs.creation_date));
      add('detailLastAnalysis', formatVtUnix(attrs.last_analysis_date));
      const dnsVals = formatDnsRecordValues(attrs.last_dns_records, 5);
      if (dnsVals) {
        add('detailDnsValues', dnsVals);
      }
      if (attrs.total_votes && typeof attrs.total_votes === 'object') {
        const v = attrs.total_votes;
        const votes =
          'harmless ' +
          (Number(v.harmless) || 0) +
          ' / malicious ' +
          (Number(v.malicious) || 0);
        add('detailVotes', votes);
      }
      const cert = formatHttpsCertSummary(attrs.last_https_certificate);
      if (cert) {
        add('detailHttpsCert', cert);
      }
      break;
    }
    case 'ip': {
      add('detailCountry', attrs.country);
      if (attrs.regional_internet_registry) {
        add('detailRir', attrs.regional_internet_registry);
      }
      if (attrs.asn !== undefined && attrs.asn !== null && attrs.asn !== '') {
        add('detailAsn', 'AS' + String(attrs.asn));
      }
      add('detailAsOwner', attrs.as_owner);
      add('detailNetwork', attrs.network);
      add('detailLastAnalysis', formatVtUnix(attrs.last_analysis_date));
      if (attrs.total_votes && typeof attrs.total_votes === 'object') {
        const v = attrs.total_votes;
        add(
          'detailVotes',
          'harmless ' +
            (Number(v.harmless) || 0) +
            ' / malicious ' +
            (Number(v.malicious) || 0)
        );
      }
      if (attrs.jarm) {
        add('detailJarm', truncateStr(attrs.jarm, 64));
      }
      const icert = formatHttpsCertSummary(attrs.last_https_certificate);
      if (icert) {
        add('detailHttpsCert', icert);
      }
      break;
    }
    case 'url': {
      add('detailFinalUrl', attrs.last_final_url);
      add('detailPageTitle', attrs.title);
      if (attrs.last_http_response_code != null && attrs.last_http_response_code !== '') {
        add('detailHttpStatus', String(attrs.last_http_response_code));
      }
      const rchain = formatRedirectChain(attrs.redirection_chain, 5);
      if (rchain) {
        add('detailRedirectChain', rchain);
      }
      add('detailLastAnalysis', formatVtUnix(attrs.last_analysis_date));
      const ucats = stringifyCategories(attrs.categories);
      if (ucats) {
        add('detailCategories', ucats);
      }
      break;
    }
    default:
      break;
  }
  return rows;
}

// relationshipPreviewPath: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function relationshipPreviewPath(kind, objectId, cfg) {
  const rel = cfg.relationship;
  const lim = Number(cfg.limit) > 0 ? Number(cfg.limit) : 5;
  const q = '?limit=' + encodeURIComponent(String(lim));
  const id = encodeURIComponent(objectId);
  switch (kind) {
    case 'file':
      return '/files/' + id + '/' + encodeURIComponent(rel) + q;
    case 'ip':
      return '/ip_addresses/' + id + '/' + encodeURIComponent(rel) + q;
    case 'domain':
      return '/domains/' + id + '/' + encodeURIComponent(rel) + q;
    case 'url':
      return '/urls/' + id + '/' + encodeURIComponent(rel) + q;
    default:
      return '';
  }
}

// resolutionItemLabel: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function resolutionItemLabel(entry) {
  if (!entry || typeof entry !== 'object') {
    return '';
  }
  const attrs = entry.attributes || {};
  const host =
    attrs.host_name ||
    attrs.hostname ||
    attrs.host ||
    attrs.ip_address ||
    attrs.ip ||
    '';
  if (host) {
    return String(host);
  }
  return entry.id != null ? String(entry.id) : '';
}

// parseRelationshipPreviewResponse: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function parseRelationshipPreviewResponse(kind, relationship, json) {
  const meta = json && json.meta;
  const count = meta && meta.count != null ? Number(meta.count) : null;
  const data = json && json.data;
  const items = [];
  if (!Array.isArray(data)) {
    return { relationship: relationship, items: [], count: count };
  }
  for (let i = 0; i < data.length; i++) {
    const entry = data[i];
    if (!entry) {
      continue;
    }
    let label = '';
    const typ = String(entry.type || '');
    if (typ === 'resolution') {
      label = resolutionItemLabel(entry);
    } else {
      label = entry.id != null ? String(entry.id) : resolutionItemLabel(entry);
    }
    label = String(label || '').replace(/\s+/g, ' ').trim();
    if (label) {
      items.push(label);
    }
  }
  return { relationship: relationship, items: items, count: count };
}

// mapPopularThreatItems: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function mapPopularThreatItems(arr, max) {
  const n = Number(max) > 0 ? Number(max) : 8;
  if (!Array.isArray(arr)) {
    return [];
  }
  return arr
    .slice(0, n)
    .map(function (x) {
      if (!x || typeof x !== 'object') {
        return null;
      }
      const value = x.value != null ? String(x.value).trim().slice(0, 500) : '';
      if (!value) {
        return null;
      }
      return { value: value, count: Number(x.count) || 0 };
    })
    .filter(function (x) {
      return !!x;
    });
}

/**
 * VT consensus (popular_threat_classification) + distinct malicious/suspicious
 * detection strings from last_analysis_results — same report, no extra API call.
 */
// extractThreatContext: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function extractThreatContext(attrs, opts) {
  opts = opts || {};
  const maxDistinct = Number(opts.maxDistinctLabels) > 0 ? Number(opts.maxDistinctLabels) : 8;
  const results = attrs && attrs.last_analysis_results;
  const ptc = attrs && attrs.popular_threat_classification;
  const out = {
    summary: {
      malicious: 0,
      suspicious: 0,
      totalEngines: 0,
      vendorsFlagging: 0
    },
    suggestedLabel: '',
    popularNames: [],
    popularCategories: [],
    distinctLabels: []
  };
  if (ptc && typeof ptc === 'object') {
    const sug = ptc.suggested_threat_label;
    if (sug != null && String(sug).trim()) {
      out.suggestedLabel = String(sug).trim().slice(0, 2000);
    }
    out.popularNames = mapPopularThreatItems(ptc.popular_threat_name, 8);
    out.popularCategories = mapPopularThreatItems(ptc.popular_threat_category, 8);
  }
  const byNorm = {};
  if (results && typeof results === 'object') {
    const keys = Object.keys(results);
    out.summary.totalEngines = keys.length;
    let mal = 0;
    let susp = 0;
    for (let i = 0; i < keys.length; i++) {
      const r = results[keys[i]];
      const cat = r && r.category;
      if (cat !== 'malicious' && cat !== 'suspicious') {
        continue;
      }
      if (cat === 'malicious') {
        mal++;
      } else {
        susp++;
      }
      const raw = (r && r.result) != null ? String(r.result).trim() : '';
      if (!raw) {
        continue;
      }
      const norm = raw.toLowerCase();
      if (!byNorm[norm]) {
        byNorm[norm] = { label: raw, count: 0 };
      }
      byNorm[norm].count++;
    }
    out.summary.malicious = mal;
    out.summary.suspicious = susp;
    out.summary.vendorsFlagging = mal + susp;
    out.distinctLabels = Object.keys(byNorm)
      .map(function (k) {
        return byNorm[k];
      })
      .sort(function (a, b) {
        return b.count - a.count;
      })
      .slice(0, maxDistinct);
  }
  return out;
}

// extractMitreFromFileAttributes: Ana file nesnesinden MITRE ID seti.
function extractMitreFromFileAttributes(attrs) {
  const ids = new Set();
  collectMitreFromAttributes(attrs, ids);
  return { ids: Array.from(ids).sort(), sandboxCount: 0, source: 'object' };
}

// mitreIdFromString: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function mitreIdFromString(s) {
  const m = String(s || '').match(/\bT\d{4}(?:\.\d{3})?\b/);
  return m ? m[0] : '';
}

// collectMitreFromAttributes: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function collectMitreFromAttributes(attrs, intoSet) {
  if (!attrs || typeof attrs !== 'object') {
    return;
  }
  const top = attrs.mitre_attack_techniques;
  if (Array.isArray(top)) {
    top.forEach(function (x) {
      const id = x && (x.id || x.technique_id);
      if (id) {
        intoSet.add(String(id));
      }
    });
  }
  const sigm = attrs.sigma_analysis_results;
  if (Array.isArray(sigm)) {
    sigm.forEach(function (row) {
      const mt = row && row.mitre_attack_techniques;
      if (Array.isArray(mt)) {
        mt.forEach(function (x) {
          const id = x && (x.id || x.technique_id);
          if (id) {
            intoSet.add(String(id));
          }
        });
      }
    });
  }
  const sigMatches = attrs.signature_matches;
  if (Array.isArray(sigMatches)) {
    sigMatches.forEach(function (row) {
      const mt = row && row.mitre_attack_techniques;
      if (Array.isArray(mt)) {
        mt.forEach(function (x) {
          const id = x && (x.id || x.technique_id);
          if (id) {
            intoSet.add(String(id));
          }
        });
      }
    });
  }
  const tags = attrs.tags;
  if (Array.isArray(tags)) {
    tags.forEach(function (tag) {
      const id = mitreIdFromString(tag);
      if (id) {
        intoSet.add(id);
      }
    });
  }
}

// extractMitreFromBehavioursJson: Arka plan yardımcısı; gövde içinde kullanım ayrıntıları.
function extractMitreFromBehavioursJson(json) {
  const data = json && json.data;
  const ids = new Set();
  if (!Array.isArray(data)) {
    return { ids: [], sandboxCount: 0 };
  }
  for (let i = 0; i < data.length; i++) {
    const row = data[i];
    const attrs = row && row.attributes;
    collectMitreFromAttributes(attrs, ids);
  }
  const sorted = Array.from(ids).sort();
  return { ids: sorted, sandboxCount: data.length };
}

// trimPayloadForHistory: Tarama kuyruğu, geçmiş veya toplu özet depolama.
function trimPayloadForHistory(payload) {
  if (!payload || !payload.ok) {
    return payload;
  }
  const out = Object.assign({}, payload);
  if (out.relationshipPreview && Array.isArray(out.relationshipPreview.items)) {
    out.relationshipPreview = Object.assign({}, out.relationshipPreview, {
      items: out.relationshipPreview.items
        .slice(0, MAX_HISTORY_REL_ITEMS)
        .map(function (s) {
          return String(s).slice(0, MAX_HISTORY_REL_STR);
        })
    });
  }
  if (out.threatContext) {
    const tc = out.threatContext;
    out.threatContext = {
      summary: tc.summary || {},
      suggestedLabel: tc.suggestedLabel
        ? String(tc.suggestedLabel).slice(0, 500)
        : '',
      popularNames: Array.isArray(tc.popularNames)
        ? tc.popularNames.slice(0, 8)
        : [],
      popularCategories: Array.isArray(tc.popularCategories)
        ? tc.popularCategories.slice(0, 8)
        : [],
      distinctLabels: Array.isArray(tc.distinctLabels)
        ? tc.distinctLabels.slice(0, MAX_HISTORY_ENGINE_ROWS)
        : []
    };
  }
  if (out.mitreTechniques && out.mitreTechniques.ids) {
    out.mitreTechniques = Object.assign({}, out.mitreTechniques, {
      ids: out.mitreTechniques.ids.slice(0, MAX_HISTORY_MITRE_IDS)
    });
  }
  if (out.hero && typeof out.hero === 'object') {
    out.hero = {
      subtitle: out.hero.subtitle ? String(out.hero.subtitle).slice(0, 220) : '',
      iocDisplay: out.hero.iocDisplay ? String(out.hero.iocDisplay).slice(0, 2048) : '',
      tagChips: Array.isArray(out.hero.tagChips) ? out.hero.tagChips.slice(0, 12) : [],
      chips: Array.isArray(out.hero.chips) ? out.hero.chips.slice(0, 8) : []
    };
  }
  if (out.relationshipPreviewSecondary && out.relationshipPreviewSecondary.items) {
    out.relationshipPreviewSecondary = Object.assign({}, out.relationshipPreviewSecondary, {
      items: out.relationshipPreviewSecondary.items
        .slice(0, MAX_HISTORY_REL_ITEMS)
        .map(function (s) {
          return String(s).slice(0, MAX_HISTORY_REL_STR);
        })
    });
  }
  return out;
}

// trimAbuseForHistory: Geçmiş kaydı için AbuseIPDB özet alanları.
function trimAbuseForHistory(abuse) {
  if (!abuse || typeof abuse !== 'object') {
    return null;
  }
  if (abuse.ok !== true) {
    return {
      ok: false,
      error: abuse.error ? String(abuse.error).slice(0, 120) : 'failed'
    };
  }
  return {
    ok: true,
    score: abuse.score,
    totalReports: abuse.totalReports,
    windowDays: abuse.windowDays,
    overallDays: abuse.overallDays,
    includeReports: abuse.includeReports === true,
    windowReportTotal: abuse.windowReportTotal,
    fetchedReports: abuse.fetchedReports,
    lastReportedAt: abuse.lastReportedAt
      ? String(abuse.lastReportedAt).slice(0, 40)
      : null,
    abuseLink: abuse.abuseLink ? String(abuse.abuseLink).slice(0, 256) : '',
    categoryBreakdown: Array.isArray(abuse.categoryBreakdown)
      ? abuse.categoryBreakdown.slice(0, 8).map(function (c) {
          return {
            categoryId: c.categoryId,
            categoryName: String(c.categoryName || '').slice(0, 80),
            count: Number(c.count) || 0
          };
        })
      : []
  };
}

// buildRecentHistoryItem: Tarama kuyruğu, geçmiş veya toplu özet depolama.
function buildRecentHistoryItem(payload) {
  if (!payload || !payload.ok) {
    return null;
  }
  const trimmed = trimPayloadForHistory(payload);
  const item = {
    ts: Date.now(),
    ioc: trimmed.ioc,
    kind: trimmed.iocKind,
    stats: trimmed.stats,
    permalink: trimmed.permalink,
    threatLevel: trimmed.threatLevel,
    details: Array.isArray(trimmed.details) ? trimmed.details : []
  };
  if (trimmed.reputation !== undefined && trimmed.reputation !== null) {
    item.reputation = trimmed.reputation;
  }
  if (trimmed.hero) {
    item.hero = trimmed.hero;
  }
  if (trimmed.threatContext) {
    item.threatContext = trimmed.threatContext;
  }
  if (trimmed.extendedThreatLabels) {
    item.extendedThreatLabels = true;
  }
  if (trimmed.relationshipPreview) {
    item.relationshipPreview = trimmed.relationshipPreview;
  }
  if (trimmed.relationshipPreviewSecondary) {
    item.relationshipPreviewSecondary = trimmed.relationshipPreviewSecondary;
  }
  if (trimmed.mitreTechniques) {
    item.mitreTechniques = trimmed.mitreTechniques;
  }
  if (trimmed.iocKind === 'ip') {
    const abuseHist = trimAbuseForHistory(trimmed.abuseipdb);
    if (abuseHist) {
      item.abuseipdb = abuseHist;
    }
    if (trimmed.threatLevelVt) {
      item.threatLevelVt = trimmed.threatLevelVt;
    }
    if (trimmed.threatLevelAbuse) {
      item.threatLevelAbuse = trimmed.threatLevelAbuse;
    }
  }
  return item;
}

// guiPermalink: VT yanıtından özet alan veya yardımcı dönüşüm.
function guiPermalink(kind, data, fallback) {
  const d = data && data.data;
  if (!d) {
    return fallback || 'https://www.virustotal.com/gui/home/upload';
  }
  const id = encodeURIComponent(d.id || '');
  switch (kind) {
    case 'ip':
      return 'https://www.virustotal.com/gui/ip-address/' + id;
    case 'domain':
      return 'https://www.virustotal.com/gui/domain/' + id;
    case 'file': {
      const sha256 = d.attributes && d.attributes.sha256;
      const h = sha256 || d.id || fallback;
      return 'https://www.virustotal.com/gui/file/' + encodeURIComponent(h);
    }
    case 'url':
      return 'https://www.virustotal.com/gui/url/' + id;
    default:
      return 'https://www.virustotal.com/gui/home/upload';
  }
}

