# PixelPaw SOC

Chrome extension (Manifest V3) for IoC lookups via VirusTotal, optional AbuseIPDB enrichment for IPs, and local history/analytics. UI languages: English and Turkish.

## Features

- Single and batch IoC scans (IP, domain, URL, hash)
- Context-menu scan and in-page IoC badges (URL, IP, domain, file hash)
- Scan presets (Quick / Detailed / Analyst)
- VirusTotal **reanalyze** from the result card
- Settings: API keys, rate limit, notifications, analytics dashboard

## Installation

1. Open `chrome://extensions` and enable **Developer mode**
2. Click **Load unpacked** and select this project folder

## Project structure

No build step — the extension is loaded unpacked and all scripts run in a shared
global namespace (no ES modules / bundler).

```text
manifest.json            Entry point: paths, permissions, content scripts, CSP
assets/                  icons/ (toolbar + store) and pixel/ (mascot sprites)
styles/                  tokens.css + base.css (shared) and popup/, options/ parts
src/
  shared/                Cross-surface code
    utils/               VtSocUtils namespace, split by domain (core, analytics,
                         summary, presets, ioc)
    i18n.js
  background/            Service worker; background.js orchestrates importScripts
                         of config, settings-uimode, feeds, vt-client, vt-parse,
                         abuse, scan, analytics, messaging
  popup/                 popup.html + state/ui-helpers/feeds/result/scan parts
  options/               options.html + state/settings/analytics/init parts
  content/               content-utils.js + detect/panel/scan/observe parts
docs/                    SECURITY_HARDENING_CHECKLIST.md
```

### Load order matters

Because there is no module system, every file shares one global scope and the
**load order acts as the import graph**. Shared/namespace files must load before
their consumers:

- HTML pages: the `<script>` order in `popup.html` / `options.html`
  (`shared/utils/*` → `i18n.js` → page parts; page entry/init parts load last).
- Service worker: the `importScripts(...)` order in `background/background.js`
  (config/state first, `messaging.js` listeners last).
- Content scripts: the `content_scripts.js` array order in `manifest.json`.

When adding a file, register it in the correct place above and respect the order.

## Configuration

In **Settings**:

| Key | Required | Purpose |
|-----|----------|---------|
| VirusTotal API | Yes | All scans |
| AbuseIPDB API | No | IP enrichment only |

Keys are stored in `chrome.storage.local` only (14-day TTL). Rotate API keys periodically; expired keys are cleared automatically.

## Security

See [`docs/SECURITY_HARDENING_CHECKLIST.md`](docs/SECURITY_HARDENING_CHECKLIST.md) before release.

## Changelog

### [1.0.6] — 2026-06-05

**Security**
- AbuseIPDB API key is sent via the `Key` HTTP header instead of the URL query string.
- Background port/message validation tightened (payload size, batch line/count limits, plain-object checks).
- Batch scans stop when the popup/side-panel port disconnects.
- Private/reserved IP ranges are blocked before VirusTotal, AbuseIPDB, or VT reanalysis calls.
- Extension CSP tightened (`img-src`, `form-action`, `frame-src`, `frame-ancestors`).
- VirusTotal and AbuseIPDB outbound links validated with URL parsing and host allowlists.
- RSS/USOM feed data normalized and size-limited before storage; popup import capped at 1 MB / 250 lines.

### [1.0.5] — 2026-06-05

**Changed**
- IP lookups now query each provider (VirusTotal, AbuseIPDB) independently so one missing key or failure never blocks the other; new integrations can plug in the same way.
- Scans work with **AbuseIPDB alone** (IP-only) or **VirusTotal alone**: an IP can be scored from AbuseIPDB even when no VirusTotal key is set, and a VirusTotal failure no longer drops an available AbuseIPDB result.
- Result card shows an Abuse-only verdict when VirusTotal data is unavailable; the VT pill reads "No key" instead of a misleading "Clean".

**Fixed**
- Missing/expired VirusTotal key now returns i18n error keys (`errorVtNoKey`, `errorVtKeyExpired`); IPs with no configured provider return `errorNoProvider`.

### [1.0.4] — 2026-05-31

**Changed**
- Project layout under `src/`, `styles/`, `assets/`, and `docs/` with modular scripts and CSS (no build step); see [Project structure](#project-structure).
- Unified IoC classification (IPv6, URL validation) across background and popup; consolidated content badges, copy-summary field gating, and CSS cleanup.
- IP scans read scan preset once per request; news/USOM search debounced in the popup.

**Fixed**
- Background: job-queue race on worker shutdown; Abuse threat shown as `unknown` when lookup fails (not `clean`); unknown message types and context-menu errors return `errorKey`/`errorVars`.
- Content: IPv6 badge pre-filter; settings load race before first scan; inline scan timeout on port disconnect; IP badge SVG stroke; `characterData` mutations for SPAs.
- Popup: combined VT+Abuse threat after recent IP enrich; USOM detail race on slow fetch; DOM null guards on core controls.
- Options: i18n confirm dialogs; live preset matrix on checkbox changes; content panel copy respects “Copy summary fields”.
- Side panel / popup paths point to `src/popup/popup.html` after restructure (`ERR_FILE_NOT_FOUND`).

### [1.0.3] — 2026-05-30

**Added**
- `content-utils.js`: lightweight utils subset for content scripts (smaller page injection footprint)
- Shared design tokens in `tokens.css` injected into content pages (`--vt-bg`, badge/panel colors)
- i18n for batch CSV export headers, USOM copy template labels, popup `aria-label`s, and macOS `⌘+Enter` scan hint
- `data-i18n-aria-label` support in `applyI18n`; `document.documentElement.lang` synced with UI language

**Changed**
- Content panel: escape IOC labels/errors in HTML; sanitize VirusTotal permalinks before use in links
- Inline scan cache capped at 50 entries; storage keys centralized in `utils.STORAGE_KEYS`
- Popup/options background aligned via `--vt-bg`; content badge colors use CSS variables
- Mascot tab animation skipped when `prefers-reduced-motion: reduce`
- Removed unused Dark Reading news slug/CSS (feed not available)
- Options KPI fallback text aligned with i18n
- Version bump to `1.0.3`

**Fixed**
- Content panel close button and error text no longer vulnerable to HTML injection from page IOC text

### [1.0.2] — 2026-05-29

**Added**
- On-page badges for **URLs** and **file hashes** (MD5, SHA-1, SHA-256), alongside IP and domain
- Settings master switch: **Enable on-page IOC detection** (`vtContentIocBadges`, default on)
- Shared URL/hash text helpers in `utils.js` (`findUrlsInText`, `findFileHashesInText`, defang `hxxp`)

**Changed**
- Single-pass scan order (URL → IP → domain → hash) to prevent double badges (e.g. domain inside a URL)
- Behavior settings: colored icons beside each toggle and the rate slider (dark/light theme)
- Version bump to `1.0.2`

### [1.0.1] — 2026-05-29

**Added**
- VT **Reanalyze** for all IoC types (result card, top-right icon)
- Status banner above the chart (queue / error feedback)
- Background: `VT_REANALYZE` → VT v3 `POST .../analyse`

**Changed**
- Reanalyze feedback shown in the chart area instead of a toast
- Version bump to `1.0.1`

### [1.0.0] — 2026-05-28

- Initial release: popup scans, batch, content script, settings/analytics, security hardening baseline
