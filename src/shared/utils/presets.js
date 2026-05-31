'use strict';

/**
 * Shared utilities — scan presets: defaults, migration, normalization, runtime/abuse flags, call estimates.
 */
(function (global) {
  const U = (global.VtSocUtils = global.VtSocUtils || {});

  const SCAN_PRESETS_VERSION = 3;
  const SCAN_PRESET_IDS = ['quick', 'detailed', 'analyst'];
  const IOC_KINDS = ['ip', 'domain', 'url', 'file'];

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

  // estimateVtCallsForPreset: Tahmini VT HTTP çağrısı (üst sınır); profile = tek IoC satırı.
  function estimateVtCallsForPreset(profile, iocKind) {
    const kind = IOC_KINDS.indexOf(iocKind) >= 0 ? iocKind : 'file';
    const p = normalizeScanPresetKind(profile, DEFAULT_SCAN_PRESETS.quick[kind]);
    let max = 2;
    if (iocKind === 'url') {
      max = 4;
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

  Object.assign(U, {
    SCAN_PRESETS_VERSION: SCAN_PRESETS_VERSION,
    SCAN_PRESET_IDS: SCAN_PRESET_IDS,
    IOC_KINDS: IOC_KINDS,
    DEFAULT_SCAN_PRESETS: DEFAULT_SCAN_PRESETS,
    ABUSE_WINDOW_DAY_CHOICES: ABUSE_WINDOW_DAY_CHOICES,
    ABUSE_OVERALL_DAY_CHOICES: ABUSE_OVERALL_DAY_CHOICES,
    getDefaultScanPresetsMap: getDefaultScanPresetsMap,
    migrateScanPresetsStorage: migrateScanPresetsStorage,
    normalizeScanPresetsMap: normalizeScanPresetsMap,
    normalizeScanPresetKind: normalizeScanPresetKind,
    normalizeScanPresetProfile: normalizeScanPresetProfile,
    resolvePresetForKind: resolvePresetForKind,
    presetToRuntimeFlags: presetToRuntimeFlags,
    presetToAbuseFlags: presetToAbuseFlags,
    abusePresetSummaryCode: abusePresetSummaryCode,
    estimateAbuseCallsForPreset: estimateAbuseCallsForPreset,
    storagePayloadFromPresets: storagePayloadFromPresets,
    estimateVtCallsForPreset: estimateVtCallsForPreset
  });
})(typeof globalThis !== 'undefined' ? globalThis : this);
