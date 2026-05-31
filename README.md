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

### [Unreleased] — 2026-05-31

**Changed**
- Project restructured into a professional layout (`src/{shared,background,popup,options,content}`, `styles/`, `assets/`, `docs/`) with no build step; see [Project structure](#project-structure).
- Large monoliths split into logical modules (behavior preserved, verified byte-for-byte):
  - `utils.js` → `src/shared/utils/{core,analytics,summary,presets,ioc}.js` (shared `VtSocUtils` namespace)
  - `background.js` → `src/background/{config,settings-uimode,feeds,vt-client,vt-parse,abuse,scan,analytics,messaging}.js` orchestrated via `importScripts`
  - `popup.js` / `options.js` / `content.js` → per-surface part files loaded in dependency order
  - `popup.css` / `options.css` → `styles/{popup,options}/*.css` parts

**Fixed**
- Side panel / popup opening after restructure: runtime `setPopup` / `sidePanel.setOptions` paths now point to `src/popup/popup.html` (was root-relative `popup.html`, causing `ERR_FILE_NOT_FOUND`).

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
