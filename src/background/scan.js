'use strict';

function assertPublicRoutableIp(ip) {
  if (!utils.isPublicRoutableIp(ip)) {
    const err = new Error(
      'Private or reserved IP addresses cannot be sent to external lookup services.'
    );
    err.errorKey = 'errorPrivateIp';
    err.errorVars = { ip: String(ip || '') };
    throw err;
  }
}

async function fetchIp(ip) {
  return vtFetch(
    '/ip_addresses/' + encodeURIComponent(ip),
    { method: 'GET' },
    { iocKind: 'ip' }
  );
}

// fetchDomain: VirusTotal API hız sınırı veya HTTP çağrısı.
async function fetchDomain(domain) {
  return vtFetch('/domains/' + encodeURIComponent(domain), { method: 'GET' }, { iocKind: 'domain' });
}

// fetchFile: VirusTotal API hız sınırı veya HTTP çağrısı.
async function fetchFile(hash) {
  return vtFetch('/files/' + encodeURIComponent(hash), { method: 'GET' }, { iocKind: 'file' });
}

// resolveVtObjectIdForReanalyze: VT analyse uç noktası için nesne kimliği.
function resolveVtObjectIdForReanalyze(iocKind, ioc, vtObjectId) {
  const stored = String(vtObjectId || '').trim();
  if (stored) {
    return stored;
  }
  const value = String(ioc || '').trim();
  if (!value) {
    return '';
  }
  if (iocKind === 'url') {
    return urlToVtId(value);
  }
  if (iocKind === 'ip' || iocKind === 'domain' || iocKind === 'file') {
    return value;
  }
  return '';
}

// vtReanalyzePath: IoC türüne göre VT v3 POST /analyse yolu.
function vtReanalyzePath(iocKind, objectId) {
  const id = encodeURIComponent(objectId);
  if (iocKind === 'ip') {
    return '/ip_addresses/' + id + '/analyse';
  }
  if (iocKind === 'domain') {
    return '/domains/' + id + '/analyse';
  }
  if (iocKind === 'file') {
    return '/files/' + id + '/analyse';
  }
  if (iocKind === 'url') {
    return '/urls/' + id + '/analyse';
  }
  return '';
}

// requestVtReanalysis: VirusTotal'de yeniden analiz kuyruğuna alır.
async function requestVtReanalysis(message) {
  const iocKind = String((message && message.iocKind) || '').toLowerCase();
  const ioc = String((message && message.ioc) || '').trim();
  if (!ioc || ['ip', 'domain', 'url', 'file'].indexOf(iocKind) < 0) {
    const err = new Error('Unsupported IoC for reanalysis');
    err.errorKey = 'errorVtReanalyzeUnsupported';
    err.errorVars = {};
    throw err;
  }
  if (iocKind === 'ip') {
    assertPublicRoutableIp(ioc);
  }
  const objectId = resolveVtObjectIdForReanalyze(iocKind, ioc, message && message.vtObjectId);
  if (!objectId) {
    const err = new Error('Could not resolve VirusTotal object id');
    err.errorKey = 'errorVtReanalyzeUnsupported';
    err.errorVars = {};
    throw err;
  }
  const path = vtReanalyzePath(iocKind, objectId);
  if (!path) {
    const err = new Error('Unsupported IoC for reanalysis');
    err.errorKey = 'errorVtReanalyzeUnsupported';
    err.errorVars = {};
    throw err;
  }
  const json = await vtFetch(path, { method: 'POST' }, { iocKind: iocKind });
  const analysisId = json && json.data && json.data.id ? String(json.data.id) : '';
  const result = {
    ok: true,
    iocKind: iocKind,
    ioc: ioc,
    vtObjectId: objectId,
    analysisId: analysisId
  };
  if (message && message.waitForCompletion && analysisId) {
    const poll = await pollVtAnalysis(analysisId, {
      iocKind: iocKind,
      onProgress: message.onProgress
    });
    result.poll = poll;
    if (poll.ok) {
      const detected = detectIoc(ioc);
      if (detected.kind !== 'unknown') {
        result.scan = await scanIoc(detected, { skipExtras: false, skipPolling: true });
      }
    }
  }
  return result;
}

// fetchUrlObject: Önce GET (cache); yoksa POST + poll + GET.
async function fetchUrlObject(urlStr, opts) {
  opts = opts || {};
  const meta = { iocKind: 'url' };
  const shouldPoll = opts.skipPolling !== true;
  const urlId = urlToVtId(urlStr);
  if (urlId) {
    try {
      return await vtFetch('/urls/' + encodeURIComponent(urlId), { method: 'GET' }, meta);
    } catch (e) {
      if (e.vtStatus !== 404) {
        throw e;
      }
    }
  }
  const posted = await vtFetch(
    '/urls',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({ url: urlStr }).toString()
    },
    meta
  );
  const postedData = posted && posted.data;
  const postedType = postedData && postedData.type ? String(postedData.type) : '';
  const postedId = postedData && postedData.id ? String(postedData.id) : '';
  if (!postedId) {
    const err = new Error('Unexpected VirusTotal response for URL submit');
    err.errorKey = 'errorVtUrlSubmit';
    err.errorVars = {};
    throw err;
  }
  if (shouldPoll && postedType === 'analysis') {
    await pollVtAnalysis(postedId, { iocKind: 'url' });
  }
  const fetchId = postedType === 'url' ? postedId : urlToVtId(urlStr);
  return vtFetch('/urls/' + encodeURIComponent(fetchId), { method: 'GET' }, meta);
}

// attachRelationshipPreview: Tek ilişki önizlemesini payload'a ekler.
async function attachRelationshipPreview(payload, detected, data, cfg, targetKey) {
  const objId = data && data.data && data.data.id;
  if (!cfg || !objId) {
    return;
  }
  const path = relationshipPreviewPath(detected.kind, objId, cfg);
  if (!path) {
    return;
  }
  const key = targetKey || 'relationshipPreview';
  try {
    const relJson = await vtFetch(path, { method: 'GET' }, { iocKind: detected.kind });
    payload[key] = parseRelationshipPreviewResponse(detected.kind, cfg.relationship, relJson);
  } catch (e) {
    const relErr = {
      relationship: cfg.relationship,
      error: e && e.message ? String(e.message) : 'Request failed'
    };
    if (e && e.vtStatus === 403) {
      relErr.errorKey = 'errorVtRelationshipPremium';
    } else if (e && e.errorKey) {
      relErr.errorKey = e.errorKey;
    }
    payload[key] = relErr;
  }
}

/** Serialized VT work: one scan at a time so rate limits and ordering stay predictable. */
const jobQueue = [];
let workerRunning = false;
let jobInFlight = false;

// enqueueJob: Tarama kuyruğu, geçmiş veya toplu özet depolama.
function enqueueJob(run) {
  return new Promise(function (resolve, reject) {
    jobQueue.push({ run: run, resolve: resolve, reject: reject });
    if (!workerRunning) {
      workerRunning = true;
      runWorker();
    }
  });
}

// runWorker: Tarama kuyruğu, geçmiş veya toplu özet depolama.
async function runWorker() {
  try {
    while (jobQueue.length > 0) {
      const job = jobQueue.shift();
      jobInFlight = true;
      try {
        const result = await job.run();
        job.resolve(result);
      } catch (e) {
        job.reject(e);
      } finally {
        jobInFlight = false;
      }
    }
  } finally {
    workerRunning = false;
    if (jobQueue.length > 0) {
      workerRunning = true;
      runWorker();
    }
  }
}

/**
 * IP lookups can be served by VirusTotal and/or AbuseIPDB. Each provider is
 * queried independently so a missing key or a failure in one never blocks the
 * other — and additional providers can be wired in the same way later.
 */
async function gatherIpProviderData(detected, opts, presetProfile) {
  assertPublicRoutableIp(detected.value);
  const includeAbuse = opts.includeAbuse !== false;
  const vtAvailable = await hasVtApiKey();
  const abuseAvailable = includeAbuse ? await hasAbuseApiKey() : false;

  if (!vtAvailable && !abuseAvailable) {
    const err = new Error(
      includeAbuse
        ? 'No API key configured. Add a VirusTotal or AbuseIPDB key in options.'
        : 'Configure your VirusTotal API key in extension options.'
    );
    err.errorKey = includeAbuse ? 'errorNoProvider' : 'errorVtNoKey';
    err.errorVars = {};
    throw err;
  }

  const out = { vtData: null, vtError: null, abuseEnrichment: null };
  const tasks = [];

  if (vtAvailable) {
    tasks.push(
      fetchIp(detected.value).then(
        function (d) {
          out.vtData = d;
        },
        function (e) {
          out.vtError = e;
        }
      )
    );
  }

  if (abuseAvailable) {
    const abuseFlags = await resolveAbuseFlagsForIp(presetProfile);
    tasks.push(
      enrichAbuseForIp(detected.value, { abuseFlags: abuseFlags }).then(function (a) {
        out.abuseEnrichment = a;
      })
    );
  } else if (includeAbuse) {
    /* Key not set: keep the marker so the UI shows the "AbuseIPDB not set" hint. */
    out.abuseEnrichment = { ok: false, error: 'not_configured' };
  }

  await Promise.all(tasks);

  /* VT was the only available provider and it failed → surface its error
     (preserves single-provider behavior). When AbuseIPDB is also available we
     fall through to an Abuse-only payload instead of failing the whole scan. */
  if (vtAvailable && !abuseAvailable && !out.vtData) {
    throw out.vtError || new Error('VirusTotal request failed');
  }

  return out;
}

/** Build an IP scan payload from AbuseIPDB alone (VirusTotal unavailable or errored). */
function buildAbuseOnlyIpPayload(detected, abuse, vtError) {
  const payload = {
    ok: true,
    ioc: detected.value,
    iocKind: 'ip',
    stats: extractStats(null),
    threatLevel: 'clean',
    permalink: (abuse && abuse.abuseLink) || guiPermalink('ip', null, detected.value),
    rawType: 'ip_address',
    details: [],
    vtUnavailable: true,
    hero: { subtitle: '', iocDisplay: detected.value, tagChips: [], chips: [] }
  };
  if (vtError && vtError.errorKey) {
    payload.vtErrorKey = String(vtError.errorKey);
  }
  mergeAbuseIntoIpPayload(payload, abuse);
  /* No VT verdict to combine: the VT side is unknown, threatLevel stays Abuse-driven. */
  payload.threatLevelVt = 'unknown';
  return payload;
}

function enrichScanPayload(payload, detected, data, attrs, scanFlags) {
  const rep = extractReputation(attrs);
  if (rep !== null) {
    payload.reputation = rep;
  }
  const threatSeverity = extractThreatSeverity(attrs);
  if (threatSeverity) {
    payload.threatSeverity = threatSeverity;
  }
  if (attrs && attrs.last_analysis_date != null) {
    payload.lastAnalysisDate = Number(attrs.last_analysis_date);
    payload.analysisFreshness = formatAnalysisFreshness(attrs.last_analysis_date);
  }
  if (detected.kind === 'file') {
    const sand = extractSandboxVerdicts(attrs, 5);
    if (sand.length) {
      payload.sandboxVerdicts = sand;
    }
  }
  if (attrs) {
    payload.extendedThreatLabels = scanFlags.engineBreakdown === true;
    payload.threatContext = extractThreatContext(attrs, {
      maxDistinctLabels: scanFlags.engineBreakdown ? 20 : 8
    });
    if (scanFlags.engineBreakdown) {
      payload.engineBreakdown = extractEngineBreakdown(attrs, { onlyFlagging: true });
    }
    payload.hero = buildHeroSummary(
      detected.kind,
      detected,
      attrs,
      payload.threatContext,
      rep,
      threatSeverity
    );
  }
  return payload;
}

// scanIoc: Tarama kuyruğu, geçmiş veya toplu özet depolama.
async function scanIoc(detected, opts) {
  opts = opts || {};
  if (detected.kind === 'url') {
    const data = await chrome.storage.local.get(['vtScanFullUrls']);
    detected = {
      kind: detected.kind,
      value: utils.prepareUrlForExternalScan(detected.value, data.vtScanFullUrls === true)
    };
  }
  const skipExtras = !!opts.skipExtras;
  /* Preset profili türü başına tek kez okunur; IP taramasında hem VT hem Abuse
     bayrakları aynı profilden türetilir (çift storage okuması önlenir). */
  let presetProfile = null;
  let scanFlags;
  if (skipExtras) {
    scanFlags = {
      relPreview: false,
      relSecondary: false,
      engineBreakdown: false,
      mitre: false
    };
  } else {
    presetProfile = await loadScanPresetProfile(detected.kind);
    scanFlags = utils.presetToRuntimeFlags(presetProfile);
  }
  let data;
  let abuseEnrichment = null;
  const fetchOpts = { skipPolling: skipExtras || opts.skipPolling === true };
  switch (detected.kind) {
    case 'ip': {
      const ipProviders = await gatherIpProviderData(detected, opts, presetProfile);
      data = ipProviders.vtData;
      abuseEnrichment = ipProviders.abuseEnrichment;
      /* VirusTotal absent/failed but AbuseIPDB answered → return an Abuse-only card. */
      if (!data) {
        return buildAbuseOnlyIpPayload(detected, abuseEnrichment, ipProviders.vtError);
      }
      break;
    }
    case 'domain':
      data = await fetchDomain(detected.value);
      break;
    case 'file':
      data = await fetchFile(detected.value);
      break;
    case 'url':
      data = await fetchUrlObject(detected.value, fetchOpts);
      break;
    default:
      throw new Error('Unsupported IoC kind');
  }
  const stats = extractStats(data);
  const level = threatLevel(stats);
  const link = guiPermalink(detected.kind, data, detected.value);
  const details = extractIocDetails(detected.kind, data);
  const attrs = data && data.data && data.data.attributes;
  const payload = {
    ok: true,
    ioc: detected.value,
    iocKind: detected.kind,
    stats: stats,
    threatLevel: level,
    permalink: link,
    rawType: data && data.data && data.data.type,
    details: details
  };
  const vtObjectId = data && data.data && data.data.id ? String(data.data.id).trim() : '';
  if (vtObjectId) {
    payload.vtObjectId = vtObjectId;
  }
  enrichScanPayload(payload, detected, data, attrs, scanFlags);
  if (detected.kind === 'ip') {
    mergeAbuseIntoIpPayload(payload, abuseEnrichment);
  }
  if (skipExtras) {
    return payload;
  }
  if (scanFlags.relPreview) {
    const cfg = VT_REL_PREVIEW_BY_KIND[detected.kind];
    await attachRelationshipPreview(payload, detected, data, cfg, 'relationshipPreview');
    const secCfg = scanFlags.relSecondary ? VT_REL_SECONDARY_BY_KIND[detected.kind] : null;
    if (secCfg) {
      await attachRelationshipPreview(
        payload,
        detected,
        data,
        secCfg,
        'relationshipPreviewSecondary'
      );
    }
  }
  if (scanFlags.mitre && detected.kind === 'file') {
    const fromObj = extractMitreFromFileAttributes(attrs);
    if (fromObj.ids.length > 0) {
      payload.mitreTechniques = fromObj;
    } else {
      const fileId = data && data.data && data.data.id;
      if (fileId) {
        try {
          const behJson = await vtFetch(
            '/files/' + encodeURIComponent(fileId) + '/behaviours?limit=5',
            { method: 'GET' },
            { iocKind: 'file' }
          );
          const beh = extractMitreFromBehavioursJson(behJson);
          beh.source = 'sandbox';
          payload.mitreTechniques = beh;
        } catch (e) {
          payload.mitreTechniques = {
            error: e && e.message ? String(e.message) : 'Request failed'
          };
        }
      }
    }
  }
  return payload;
}
