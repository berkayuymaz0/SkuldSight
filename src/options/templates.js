// Builds the repetitive options markup (scan-preset cards + copy-summary matrix)
// from data so the HTML stays small. Runs before state.js so every id/selector
// the other modules look up already exists. Generated nodes carry the same ids
// and data-i18n keys as the original hand-written markup.
(function () {
  const PRESET_CARDS = [
    {
      name: 'quick',
      tier: 'Ⅰ',
      titleKey: 'scanPresetQuick',
      titleText: 'Quick mode',
      leadKey: 'optPresetRowQuickDesc',
      leadText: 'Fast path — core verdicts, minimal enrichment.',
      matrixLabel: 'Quick preset by IoC type'
    },
    {
      name: 'detailed',
      tier: 'Ⅱ',
      titleKey: 'scanPresetDetailed',
      titleText: 'Detailed mode',
      leadKey: 'optPresetRowDetailedDesc',
      leadText: 'Adds relationship context and file behaviour (MITRE).',
      matrixLabel: 'Detailed preset by IoC type'
    },
    {
      name: 'analyst',
      tier: 'Ⅲ',
      titleKey: 'scanPresetAnalyst',
      titleText: 'Analyst mode',
      leadKey: 'optPresetRowAnalystDesc',
      leadText: 'Full enrichment including per-engine detection text.',
      matrixLabel: 'Analyst preset by IoC type'
    }
  ];

  const PRESET_LINES = [
    { suffix: 'rel', nameKey: 'optExtraRelPrimary', nameText: 'Related IOCs (primary)', hintKey: 'optPresetColRelHint', hintText: 'Resolutions, contacted IPs/domains' },
    { suffix: 'relsec', nameKey: 'optExtraRelSecondary', nameText: 'Secondary pivots', hintKey: 'optPresetColRelSecHint', hintText: 'communicating_files, extra domains' },
    { suffix: 'engine', nameKey: 'optExtraEngineBreakdown', nameText: 'Threat labels', hintKey: 'optPresetColEngineHint', hintText: 'Consensus labels' },
    { suffix: 'mitre', nameKey: 'optExtraMitre', nameText: 'MITRE (files)', hintKey: 'optPresetColMitreHint', hintText: 'Sandbox tactics' }
  ];

  const ABUSE_FIELDS = [
    { suffix: 'abuse-window', labelKey: 'optPresetAbuseWindow', labelText: 'Report window (days)', hintKey: 'optPresetAbuseWindowHintShort', hintText: 'Reports API lookback', options: ['30', '90'] },
    { suffix: 'abuse-overall', labelKey: 'optPresetAbuseOverall', labelText: 'Check overview (days)', hintKey: 'optPresetAbuseOverallHintShort', hintText: 'Check API lookback', options: ['90', '180', '365'] }
  ];

  const COPY_KINDS = ['ip', 'domain', 'url', 'file'];

  // Mirrors copySummaryInputId() in settings.js so generated button ids stay in sync.
  const COPY_ID_SUFFIX = {
    threatLevel: 'threat',
    detectionRatio: 'ratio',
    reputation: 'rep',
    suggestedThreat: 'suggested',
    abuseScore: 'abuse-score',
    abuseReports: 'abuse-reports',
    distinctLabels: 'labels',
    reportLink: 'report'
  };

  const COPY_ROWS = [
    { field: 'ioc', i18n: 'optCopyFieldIoc', text: 'IOC' },
    { field: 'kind', i18n: 'optCopyFieldKind', text: 'Type' },
    { field: 'threatLevel', i18n: 'optCopyFieldThreatLevel', text: 'Threat level' },
    { field: 'vt', i18n: 'optCopyFieldVtDetections', text: 'VT detections' },
    { field: 'detectionRatio', i18n: 'optCopyFieldDetectionRatio', text: 'Detection ratio' },
    { field: 'reputation', i18n: 'optCopyFieldReputation', text: 'Risk score' },
    { field: 'suggestedThreat', i18n: 'optCopyFieldSuggestedThreat', text: 'Suggested threat' },
    { field: 'abuseScore', i18n: 'optCopyFieldAbuseScore', text: 'Abuse score', kinds: ['ip'] },
    { field: 'abuseReports', i18n: 'optCopyFieldAbuseReports', text: 'Abuse reports', kinds: ['ip'] },
    { field: 'tags', i18n: 'optCopyFieldTags', text: 'Tags' },
    { field: 'distinctLabels', i18n: 'optCopyFieldDistinctLabels', text: 'AV labels' },
    { field: 'mitre', i18n: 'optCopyFieldMitre', text: 'MITRE ATT&amp;CK', kinds: ['file'] },
    { field: 'time', i18n: 'optCopyFieldTime', text: 'Scanned time' },
    { field: 'reportLink', i18n: 'optCopyFieldReportLink', text: 'Report link' }
  ];

  function presetLineHtml(name, line) {
    const id = 'preset-' + name + '-' + line.suffix;
    return (
      '<label class="preset-line" for="' + id + '">' +
        '<span class="preset-line-copy">' +
          '<span class="preset-line-name" data-i18n="' + line.nameKey + '">' + line.nameText + '</span>' +
          '<span class="preset-line-hint" data-i18n="' + line.hintKey + '">' + line.hintText + '</span>' +
        '</span>' +
        '<input type="checkbox" id="' + id + '" class="preset-line-check" />' +
      '</label>'
    );
  }

  function abuseFieldHtml(name, field) {
    const id = 'preset-' + name + '-' + field.suffix;
    let options = '';
    field.options.forEach(function (val) {
      options += '<option value="' + val + '">' + val + '</option>';
    });
    return (
      '<div class="preset-abuse-field">' +
        '<label class="preset-abuse-field-label" for="' + id + '" data-i18n="' + field.labelKey + '">' + field.labelText + '</label>' +
        '<p class="preset-abuse-field-hint" data-i18n="' + field.hintKey + '">' + field.hintText + '</p>' +
        '<select id="' + id + '" class="preset-abuse-select">' + options + '</select>' +
      '</div>'
    );
  }

  function presetCardHtml(cfg) {
    const n = cfg.name;
    let lines = '';
    PRESET_LINES.forEach(function (line) {
      lines += presetLineHtml(n, line);
    });
    let abuseFields = '';
    ABUSE_FIELDS.forEach(function (field) {
      abuseFields += abuseFieldHtml(n, field);
    });
    return (
      '<article class="preset-card preset-card--' + n + '" aria-labelledby="preset-card-title-' + n + '">' +
        '<header class="preset-card-header">' +
          '<span class="preset-card-tier preset-card-tier--' + n + '" aria-hidden="true">' + cfg.tier + '</span>' +
          '<div class="preset-card-intro">' +
            '<h3 class="preset-card-title" id="preset-card-title-' + n + '" data-i18n="' + cfg.titleKey + '">' + cfg.titleText + '</h3>' +
            '<p class="preset-card-lead" data-i18n="' + cfg.leadKey + '">' + cfg.leadText + '</p>' +
          '</div>' +
        '</header>' +
        '<div class="preset-card-body">' +
          '<div class="preset-ioc-matrix" data-preset="' + n + '" role="table" aria-label="' + cfg.matrixLabel + '"></div>' +
          '<p class="preset-override-note" data-i18n="optPresetOverrideNote">Checkboxes below apply the same profile to all IoC types when saved.</p>' +
          lines +
          '<div class="preset-abuse-block">' +
            '<p class="preset-abuse-heading" data-i18n="optPresetAbuseHeading">AbuseIPDB (IP scans)</p>' +
            presetLineHtml(n, { suffix: 'abuse-reports', nameKey: 'optPresetAbuseReports', nameText: 'Category reports', hintKey: 'optPresetAbuseReportsHint', hintText: '+1 call: newest 100 reports, category breakdown' }) +
            '<div class="preset-abuse-fields">' + abuseFields + '</div>' +
          '</div>' +
        '</div>' +
      '</article>'
    );
  }

  function copyRowHtml(row) {
    let cells = '';
    COPY_KINDS.forEach(function (kind) {
      if (row.kinds && row.kinds.indexOf(kind) === -1) {
        cells += '<td><span class="copy-matrix-na">-</span></td>';
        return;
      }
      const suffix = COPY_ID_SUFFIX[row.field] || row.field;
      const id = 'copy-' + kind + '-' + suffix;
      cells +=
        '<td><button type="button" id="' + id + '" class="copy-matrix-toggle" data-kind="' + kind + '" data-field="' + row.field + '" aria-pressed="false"></button></td>';
    });
    return '<tr><th data-i18n="' + row.i18n + '">' + row.text + '</th>' + cells + '</tr>';
  }

  function build() {
    const presetHost = document.querySelector('.preset-cards');
    if (presetHost) {
      let html = '';
      PRESET_CARDS.forEach(function (cfg) {
        html += presetCardHtml(cfg);
      });
      presetHost.innerHTML = html;
    }

    const matrixBody = document.querySelector('.copy-matrix tbody');
    if (matrixBody) {
      let rows = '';
      COPY_ROWS.forEach(function (row) {
        rows += copyRowHtml(row);
      });
      matrixBody.innerHTML = rows;
    }
  }

  build();
})();
