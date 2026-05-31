'use strict';

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
  return {
    ok: true,
    iocKind: iocKind,
    ioc: ioc,
    vtObjectId: objectId,
    analysisId: analysisId
  };
}

// fetchUrlObject: Önce GET (cache); yoksa POST + GET.
async function fetchUrlObject(urlStr) {
  const meta = { iocKind: 'url' };
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
  const newId = posted.data && posted.data.id;
  if (!newId) {
    const err = new Error('Unexpected VirusTotal response for URL submit');
    err.errorKey = 'errorVtUrlSubmit';
    err.errorVars = {};
    throw err;
  }
  return vtFetch('/urls/' + encodeURIComponent(newId), { method: 'GET' }, meta);
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
    payload[key] = {
      relationship: cfg.relationship,
      error: e && e.message ? String(e.message) : 'Request failed'
    };
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

// scanIoc: Tarama kuyruğu, geçmiş veya toplu özet depolama.
async function scanIoc(detected, opts) {
  opts = opts || {};
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
  switch (detected.kind) {
    case 'ip': {
      if (opts.includeAbuse === false) {
        data = await fetchIp(detected.value);
      } else {
        const abuseFlags = await resolveAbuseFlagsForIp(presetProfile);
        const ipResults = await Promise.all([
          fetchIp(detected.value),
          enrichAbuseForIp(detected.value, { abuseFlags: abuseFlags })
        ]);
        data = ipResults[0];
        abuseEnrichment = ipResults[1];
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
      data = await fetchUrlObject(detected.value);
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
  const rep = extractReputation(attrs);
  if (rep !== null) {
    payload.reputation = rep;
  }
  if (attrs) {
    payload.extendedThreatLabels = scanFlags.engineBreakdown === true;
    payload.threatContext = extractThreatContext(attrs, {
      maxDistinctLabels: scanFlags.engineBreakdown ? 20 : 8
    });
    payload.hero = buildHeroSummary(
      detected.kind,
      detected,
      attrs,
      payload.threatContext,
      rep
    );
  }
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

