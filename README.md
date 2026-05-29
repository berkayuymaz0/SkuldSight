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

Keys are stored in `chrome.storage.local` only (14-day TTL).

## Security

See [`SECURITY_HARDENING_CHECKLIST.md`](SECURITY_HARDENING_CHECKLIST.md) before release.

## Changelog

### [1.0.2] — 2026-05-29

**Added**
- On-page badges for **URLs** and **file hashes** (MD5, SHA-1, SHA-256), alongside IP and domain
- Settings master switch: **Enable on-page IOC detection** (`vtContentIocBadges`, default on)
- Shared URL/hash text helpers in `utils.js` (`findUrlsInText`, `findFileHashesInText`, defang `hxxp`)

**Changed**
- Single-pass scan order (URL → IP → domain → hash) to prevent double badges (e.g. domain inside a URL)
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
