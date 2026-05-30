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

## Configuration

In **Settings**:

| Key | Required | Purpose |
|-----|----------|---------|
| VirusTotal API | Yes | All scans |
| AbuseIPDB API | No | IP enrichment only |

Keys are stored in `chrome.storage.local` only (14-day TTL). Rotate API keys periodically; expired keys are cleared automatically.

## Security

See [`SECURITY_HARDENING_CHECKLIST.md`](SECURITY_HARDENING_CHECKLIST.md) before release.

## Changelog

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
