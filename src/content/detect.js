'use strict';

  const socUtils = typeof window !== 'undefined' ? window.VtSocUtils : null;
  const DOMAIN_BTN_ATTR = 'data-vt-domain-badge';
  const DOMAIN_VALUE_ATTR = 'data-vt-domain-value';
  const DOMAIN_TOKEN_ATTR = 'data-vt-domain-token';
  const IP_BTN_ATTR = 'data-vt-ip-badge';
  const IP_VALUE_ATTR = 'data-vt-ip-value';
  const IP_TOKEN_ATTR = 'data-vt-ip-token';
  const URL_BTN_ATTR = 'data-vt-url-badge';
  const URL_VALUE_ATTR = 'data-vt-url-value';
  const URL_TOKEN_ATTR = 'data-vt-url-token';
  const HASH_BTN_ATTR = 'data-vt-hash-badge';
  const HASH_VALUE_ATTR = 'data-vt-hash-value';
  const HASH_TOKEN_ATTR = 'data-vt-hash-token';
  const BADGE_ATTR_BY_KIND = {
    domain: { btn: DOMAIN_BTN_ATTR, val: DOMAIN_VALUE_ATTR },
    ip: { btn: IP_BTN_ATTR, val: IP_VALUE_ATTR },
    url: { btn: URL_BTN_ATTR, val: URL_VALUE_ATTR },
    file: { btn: HASH_BTN_ATTR, val: HASH_VALUE_ATTR }
  };
  const TOKEN_ATTR_BY_KIND = {
    domain: DOMAIN_TOKEN_ATTR,
    ip: IP_TOKEN_ATTR,
    url: URL_TOKEN_ATTR,
    file: HASH_TOKEN_ATTR
  };
  const MAX_BADGES = 120;
  const DOMAIN_TEXT_RE = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi;
  const IPV4_OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';
  const COMBINED_IP_RE = new RegExp(
    '\\b' +
      IPV4_OCTET +
      '(?:\\.' +
      IPV4_OCTET +
      '){3}\\b|\\b(?:(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|[A-Fa-f0-9]{1,4}:(?:(?::[A-Fa-f0-9]{1,4}){1,6})|:(?:(?::[A-Fa-f0-9]{1,4}){1,7}|:))\\b',
    'g'
  );
  const DOMAIN_SCAN_DEBOUNCE_MS = 120;
  const MAX_MUTATION_ROOTS_PER_FLUSH = 60;
  const INLINE_SCAN_CACHE_MAX = 50;
  const inlineScanCache = new Map();
  let domainPanel = null;
  let observer = null;
  let blacklistRules = [];
  let badgeCount = 0;
  let domainScanDebounceTimer = null;
  let contentTheme = 'dark';
  let contentIocBadgesEnabled = true;
  let panelLastScanResult = null;
  const pendingMutationRoots = new Set();

  function applyContentTheme(theme) {
    contentTheme = theme === 'light' ? 'light' : 'dark';
    document
      .querySelectorAll('.vt-domain-badge, .vt-ip-badge, .vt-url-badge, .vt-hash-badge')
      .forEach(function (btn) {
      btn.setAttribute('data-vt-theme', contentTheme);
    });
    if (domainPanel) {
      domainPanel.setAttribute('data-vt-theme', contentTheme);
    }
  }

  // İçerik betiğinde VT_I18N dilini kullanıcı ayarına göre Türkçe veya İngilizce yapar.
  function syncContentLang(isTr) {
    const lang = isTr ? 'tr' : 'en';
    if (typeof VT_I18N !== 'undefined' && VT_I18N.setLang) {
      VT_I18N.setLang(lang);
    }
    if (document.documentElement) {
      document.documentElement.lang = lang;
    }
  }

  // VT_I18N yüklüyse çeviri anahtarını çözer; değilse anahtarı olduğu gibi döndürür.
  function ct(key, vars) {
    if (typeof VT_I18N !== 'undefined' && VT_I18N.t) {
      return VT_I18N.t(key, vars);
    }
    return key;
  }

  chrome.storage.local.get(
    ['vtUiLang', 'vtDomainBadgeBlacklist', 'vtPopupTheme', 'vtContentIocBadges'],
    function (d) {
      syncContentLang(d.vtUiLang === 'tr');
      applyContentTheme(d.vtPopupTheme === 'light' ? 'light' : 'dark');
      blacklistRules = parseBlacklistRules(d.vtDomainBadgeBlacklist);
      contentIocBadgesEnabled = d.vtContentIocBadges !== false;
      applyContentIocSettings();
    }
  );

  chrome.storage.onChanged.addListener(function (changes, area) {
    if (area !== 'local') {
      return;
    }
    if (changes.vtUiLang) {
      syncContentLang(changes.vtUiLang.newValue === 'tr');
    }
    if (changes.vtPopupTheme) {
      applyContentTheme(changes.vtPopupTheme.newValue === 'light' ? 'light' : 'dark');
    }
    if (changes.vtDomainBadgeBlacklist) {
      blacklistRules = parseBlacklistRules(changes.vtDomainBadgeBlacklist.newValue);
      applyContentIocSettings();
    }
    if (changes.vtContentIocBadges) {
      contentIocBadgesEnabled = changes.vtContentIocBadges.newValue !== false;
      applyContentIocSettings();
    }
  });

  // Kara liste metnini satırlara bölüp yorumları atarak küçük harf kural dizisi üretir.
  function parseBlacklistRules(raw) {
    return String(raw || '')
      .split(/\r?\n/)
      .map(function (line) {
        return line.trim().toLowerCase();
      })
      .filter(function (line) {
        return !!line && line.indexOf('#') !== 0;
      });
  }

  // Geçerli sayfa URL’si veya alan adı, kayıtlı kara liste kurallarından birine uyuyorsa true döner.
  function isCurrentPageBlacklisted() {
    if (!blacklistRules || blacklistRules.length === 0) {
      return false;
    }
    const href = String(location.href || '').toLowerCase();
    const host = String(location.hostname || '').toLowerCase();
    const path = String(location.pathname || '').toLowerCase();
    for (let i = 0; i < blacklistRules.length; i++) {
      const rule = blacklistRules[i];
      if (rule === '*') {
        return true;
      }
      if (rule.indexOf('://') >= 0) {
        if (href.indexOf(rule) === 0) {
          return true;
        }
        continue;
      }
      if (rule[0] === '/') {
        if (path.indexOf(rule) === 0) {
          return true;
        }
        continue;
      }
      if (rule.indexOf('*.') === 0) {
        const suffix = rule.slice(2);
        if (host === suffix || host.endsWith('.' + suffix)) {
          return true;
        }
        continue;
      }
      if (host === rule || host.endsWith('.' + rule)) {
        return true;
      }
    }
    return false;
  }

  // Metnin gerçek bir alan adı adayı olup olmadığını (localhost/IP hariç) doğrular.
  function isDomainCandidate(hostname) {
    const host = String(hostname || '').trim().toLowerCase();
    if (!host || host.length > 253) {
      return false;
    }
    if (host === 'localhost') {
      return false;
    }
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
      return false;
    }
    return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host);
  }

  function isIPv4(ip) {
    return new RegExp(
      '^(?:' + IPV4_OCTET + ')(?:\\.(?:' + IPV4_OCTET + ')){3}$'
    ).test(ip);
  }

  function isIPv6(ip) {
    return /^((?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,7}:|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}|[A-Fa-f0-9]{1,4}:(?:(?::[A-Fa-f0-9]{1,4}){1,6})|:(?:(?::[A-Fa-f0-9]{1,4}){1,7}|:))$/.test(
      ip
    );
  }

  function isPublicIPv4(ip) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(Number.isNaN)) {
      return false;
    }
    const a = parts[0];
    const b = parts[1];
    if (a === 10 || a === 127 || a === 0) {
      return false;
    }
    if (a === 169 && b === 254) {
      return false;
    }
    if (a === 192 && b === 168) {
      return false;
    }
    if (a === 172 && b >= 16 && b <= 31) {
      return false;
    }
    if (a >= 224) {
      return false;
    }
    return true;
  }

  function isPublicIPv6(ip) {
    const lower = ip.toLowerCase();
    if (lower === '::' || lower === '::1') {
      return false;
    }
    if (lower.startsWith('fc') || lower.startsWith('fd')) {
      return false;
    }
    if (
      lower.startsWith('fe8') ||
      lower.startsWith('fe9') ||
      lower.startsWith('fea') ||
      lower.startsWith('feb')
    ) {
      return false;
    }
    if (lower.startsWith('ff')) {
      return false;
    }
    return true;
  }

  function isSupportedPublicIP(ip) {
    if (isIPv4(ip)) {
      return isPublicIPv4(ip);
    }
    if (isIPv6(ip)) {
      return isPublicIPv6(ip);
    }
    return false;
  }

  function inlineCacheKey(kind, value) {
    return kind + ':' + String(value || '').toLowerCase();
  }

  function createBadgeIconSvg(kind) {
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('class', 'vt-badge-glyph');
    svg.setAttribute('viewBox', '0 0 16 16');
    svg.setAttribute('width', '11');
    svg.setAttribute('height', '11');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    if (kind === 'url') {
      const path = document.createElementNS(ns, 'path');
      path.setAttribute(
        'd',
        'M6.2 8.75H9.8M8 6.95v3.6M4.5 5.2a5.5 5.5 0 0 1 7 0M4.5 10.8a5.5 5.5 0 0 0 7 0'
      );
      path.setAttribute('fill', 'none');
      path.setAttribute('stroke', 'currentColor');
      path.setAttribute('stroke-width', '1.1');
      path.setAttribute('stroke-linecap', 'round');
      path.setAttribute('stroke-linejoin', 'round');
      svg.appendChild(path);
    } else if (kind === 'file') {
      const rect = document.createElementNS(ns, 'rect');
      rect.setAttribute('x', '3.25');
      rect.setAttribute('y', '2.75');
      rect.setAttribute('width', '9.5');
      rect.setAttribute('height', '10.5');
      rect.setAttribute('rx', '1.2');
      rect.setAttribute('fill', 'none');
      rect.setAttribute('stroke', 'currentColor');
      rect.setAttribute('stroke-width', '1.1');
      const line1 = document.createElementNS(ns, 'path');
      line1.setAttribute('d', 'M5.5 6.25h5M5.5 8.25h5M5.5 10.25h3.2');
      line1.setAttribute('fill', 'none');
      line1.setAttribute('stroke', 'currentColor');
      line1.setAttribute('stroke-width', '1');
      line1.setAttribute('stroke-linecap', 'round');
      svg.appendChild(rect);
      svg.appendChild(line1);
    } else if (kind === 'domain') {
      const circle = document.createElementNS(ns, 'circle');
      circle.setAttribute('cx', '8');
      circle.setAttribute('cy', '8');
      circle.setAttribute('r', '5.25');
      circle.setAttribute('fill', 'none');
      circle.setAttribute('stroke', 'currentColor');
      circle.setAttribute('stroke-width', '1.15');
      const meridian = document.createElementNS(ns, 'ellipse');
      meridian.setAttribute('cx', '8');
      meridian.setAttribute('cy', '8');
      meridian.setAttribute('rx', '2.15');
      meridian.setAttribute('ry', '5.25');
      meridian.setAttribute('fill', 'none');
      meridian.setAttribute('stroke', 'currentColor');
      meridian.setAttribute('stroke-width', '1');
      const parallel = document.createElementNS(ns, 'path');
      parallel.setAttribute('d', 'M2.75 8h10.5');
      parallel.setAttribute('fill', 'none');
      parallel.setAttribute('stroke', 'currentColor');
      parallel.setAttribute('stroke-width', '1');
      svg.appendChild(circle);
      svg.appendChild(meridian);
      svg.appendChild(parallel);
    } else {
      const paths = [
        'M3 3.25h3.25v3.25H3zM9.75 3.25H13v3.25H9.75zM3 9.5h3.25V12.75H3zM9.75 9.5H13V12.75H9.75z',
        'M5.1 8h1.35M9.55 8h1.35M8 5.1v1.35M8 9.55v1.35'
      ];
      paths.forEach(function (d, idx) {
        const el = document.createElementNS(ns, 'path');
        el.setAttribute('d', d);
        if (idx < 4) {
          el.setAttribute('fill', 'currentColor');
          el.setAttribute('stroke', 'none');
        } else {
          el.setAttribute('fill', 'none');
          el.setAttribute('stroke', 'currentColor');
          el.setAttribute('stroke-width', '1.05');
          el.setAttribute('stroke-linecap', 'round');
        }
        svg.appendChild(el);
      });
    }
    return svg;
  }

  function applyBadgeRiskState(btn, payload) {
    if (!btn || !payload || !payload.ok) {
      return;
    }
    const risk =
      socUtils && socUtils.payloadToBadgeRisk
        ? socUtils.payloadToBadgeRisk(payload)
        : payload.threatLevel || 'clean';
    btn.setAttribute('data-vt-risk', risk);
    btn.classList.remove('vt-badge-pending');
    if (btn.classList.contains('vt-ip-badge')) {
      let scoreEl = btn.querySelector('.vt-badge-score');
      const abuse = payload.abuseipdb;
      if (abuse && abuse.ok === true && abuse.score != null && isFinite(abuse.score)) {
        if (!scoreEl) {
          scoreEl = document.createElement('span');
          scoreEl.className = 'vt-badge-score';
          btn.appendChild(scoreEl);
        }
        scoreEl.textContent = String(Math.round(abuse.score));
        btn.classList.add('vt-badge-has-score');
      } else {
        if (scoreEl) {
          scoreEl.remove();
        }
        btn.classList.remove('vt-badge-has-score');
      }
    }
  }

  function applyBadgeRiskStateForAll(kind, value, payload) {
    const attrs = BADGE_ATTR_BY_KIND[kind];
    if (!attrs) {
      return;
    }
    const norm = String(value || '').toLowerCase();
    document.querySelectorAll('[' + attrs.btn + '="1"]').forEach(function (btn) {
      const v = String(btn.getAttribute(attrs.val) || '').toLowerCase();
      if (v === norm) {
        applyBadgeRiskState(btn, payload);
      }
    });
  }

  function createDomainBadge(hostname) {
    badgeCount += 1;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.setAttribute(DOMAIN_BTN_ATTR, '1');
    btn.setAttribute(DOMAIN_VALUE_ATTR, hostname);
    btn.title = ct('domainBadgeButtonTitle', { host: hostname });
    btn.className = 'vt-domain-badge vt-badge-pending';
    btn.appendChild(createBadgeIconSvg('domain'));
    btn.setAttribute('data-vt-theme', contentTheme);
    btn.addEventListener('click', onDomainBadgeClick, true);
    return btn;
  }

  function createIpBadge(ip) {
    badgeCount += 1;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.setAttribute(IP_BTN_ATTR, '1');
    btn.setAttribute(IP_VALUE_ATTR, ip);
    btn.title = ct('ipBadgeButtonTitle', { ip: ip });
    btn.className = 'vt-ip-badge vt-badge-pending';
    btn.setAttribute('data-vt-theme', contentTheme);
    btn.appendChild(createBadgeIconSvg('ip'));
    btn.addEventListener('click', onIpBadgeClick, true);
    return btn;
  }

  function createUrlBadge(url) {
    badgeCount += 1;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.setAttribute(URL_BTN_ATTR, '1');
    btn.setAttribute(URL_VALUE_ATTR, url);
    btn.title = ct('urlBadgeButtonTitle', { url: url });
    btn.className = 'vt-url-badge vt-badge-pending';
    btn.setAttribute('data-vt-theme', contentTheme);
    btn.appendChild(createBadgeIconSvg('url'));
    btn.addEventListener('click', onUrlBadgeClick, true);
    return btn;
  }

  function createHashBadge(hash) {
    badgeCount += 1;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.setAttribute(HASH_BTN_ATTR, '1');
    btn.setAttribute(HASH_VALUE_ATTR, hash);
    btn.title = ct('hashBadgeButtonTitle', { hash: hash });
    btn.className = 'vt-hash-badge vt-badge-pending';
    btn.setAttribute('data-vt-theme', contentTheme);
    btn.appendChild(createBadgeIconSvg('file'));
    btn.addEventListener('click', onHashBadgeClick, true);
    return btn;
  }

