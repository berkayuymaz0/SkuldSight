# SkuldSight SOC

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

Release history and version notes: [`CHANGELOG.md`](CHANGELOG.md).
