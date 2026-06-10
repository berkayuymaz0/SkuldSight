<div align="center">

<img src="assets/brand/skuldsight.png" alt="SkuldSight SOC logo" width="120" />

# SkuldSight SOC

**Threat intel, analyst-grade — right in your browser.**

Scan IPs, domains, URLs and file hashes via VirusTotal and AbuseIPDB, run batch triage, and get on-page IOC badges. Built for SOC workflows. No build step, no telemetry.

[![Chrome Web Store](https://img.shields.io/chrome-web-store/v/mjdpoecgbpenpkadhnkkogifbmmfkjnn?style=for-the-badge&logo=googlechrome&logoColor=white&label=Chrome%20Web%20Store&color=4285F4)](https://chromewebstore.google.com/detail/skuldsight-soc/mjdpoecgbpenpkadhnkkogifbmmfkjnn)
![Manifest V3](https://img.shields.io/badge/Manifest-V3-1f6feb?style=for-the-badge&logo=googlechrome&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-API%20v3-394EFF?style=for-the-badge&logo=virustotal&logoColor=white)
![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-enrichment-FF5252?style=for-the-badge)
![i18n](https://img.shields.io/badge/i18n-EN%20%7C%20TR-2ea043?style=for-the-badge)

<a href="https://chromewebstore.google.com/detail/skuldsight-soc/mjdpoecgbpenpkadhnkkogifbmmfkjnn">
  <img src="https://img.shields.io/badge/Add%20to%20Chrome-Install-34A853?style=for-the-badge&logo=googlechrome&logoColor=white" alt="Add to Chrome" height="40" />
</a>

[Features](#-features) · [Install](#-install) · [Configuration](#-configuration) · [Project structure](#-project-structure) · [Security](#-security)

</div>

<div align="center">

<img src="store/promo-marquee-1400x560.jpg" alt="SkuldSight SOC — analyst-grade threat intel in the browser" width="900" />

</div>

---

## 💡 Why SkuldSight

> SOC analysts validate dozens of indicators a day — copy a hash, open a tab, paste, repeat. SkuldSight collapses that loop into one place: lookups, batch triage, and on-page badges, with VirusTotal engine results and optional AbuseIPDB enrichment, all without leaving the page you're investigating.

- **One-click IoC lookup** from the toolbar popup or the side panel.
- **Direct-to-source** — scans go straight to VirusTotal / AbuseIPDB; API keys live in your browser only.
- **SOC-tuned** — Quick / Detailed / Analyst presets, reanalyze, scan history, and a local analytics dashboard.

---

## ✨ Features

### 🔍 Every IoC's verdict in seconds

<table>
<tr>
<td width="55%">

Look up any **IP, domain, URL, or file hash** from the popup or side panel and get the full picture in a single result card: reputation score, per-engine VirusTotal detections, and network intel (ASN, owner, country, last analysis).

- **VirusTotal API v3** engine breakdown — malicious / suspicious / undetected / clean.
- **AbuseIPDB enrichment** for IPs — confidence score, report counts, last-reported time.
- **🔄 Reanalyze** straight from the card to force a fresh VirusTotal run.
- One-click **Copy summary** for ticket-ready notes.

</td>
<td width="45%">

<img src="store/screenshot-1-single-scan-1280x800.jpg" alt="Single scan result panel showing VirusTotal and AbuseIPDB verdicts" width="100%" />

</td>
</tr>
</table>

### 📦 Triage a whole batch at once

<table>
<tr>
<td width="45%">

<img src="store/screenshot-2-batch-scan-1280x800.jpg" alt="Batch scan resolving indicators live with malicious/suspicious/clean labels" width="100%" />

</td>
<td width="55%">

Paste **hundreds of indicators** — one per line — and watch them resolve live. The queue is **rate-limit aware**, so you stay within VirusTotal / AbuseIPDB quotas while every line gets a clear **malicious / suspicious / clean** label.

- Mixed IPs, domains, URLs, and hashes in the same batch.
- Live progress counter and per-row status (`PENDING` → verdict).
- Export results to CSV for incident logs.

</td>
</tr>
</table>

### 🏷️ IOC badges, right on the page

<table>
<tr>
<td width="55%">

On-page detection highlights **IPs, domains, URLs, and hashes** as you browse HTTPS pages. Hover any badge for an instant reputation summary — no copy-paste, no tab switching.

- Auto-detects indicators in page text as you read.
- Inline hover panel with the same VT + AbuseIPDB summary.
- Toggle the whole feature off in Settings when you don't need it.

</td>
<td width="45%">

<img src="store/screenshot-5-page-badges-1280x800.jpg" alt="On-page IOC badges with inline reputation summary" width="100%" />

</td>
</tr>
</table>

### 📊 Know your threat landscape

<table>
<tr>
<td width="45%">

<img src="store/screenshot-3-analytics-1280x800.jpg" alt="Local analytics dashboard with activity, threat distribution, and IoC breakdown" width="100%" />

</td>
<td width="55%">

A **local-only** dashboard turns your scan history into insight — nothing leaves the browser.

- Totals for scans, malicious, and suspicious hits.
- **14-day activity** volume chart.
- Threat distribution (malicious / suspicious / clean) and a breakdown by IoC type.
- Latest-batch summary at a glance.

</td>
</tr>
</table>

### ⚙️ Tune the depth: Quick → Analyst

<table>
<tr>
<td width="55%">

Three presets control how deep each scan goes, balancing detail against API quota:

- **Quick** — report only, no extra VT relationship or MITRE calls.
- **Detailed** — full pivots (related IoCs, communicating files) plus file MITRE.
- **Analyst** — Detailed depth with extended AV labels and wider AbuseIPDB report/overview windows.

Checkboxes let you override individual pivots, threat labels, and AbuseIPDB lookback windows.

</td>
<td width="45%">

<img src="store/screenshot-4-scan-presets-1280x800.jpg" alt="Scan preset depth control from Quick to Analyst" width="100%" />

</td>
</tr>
</table>

> [!TIP]
> The UI is fully **bilingual (English / Turkish)** — switch languages from the header at any time.

---

## 🚀 Install

### From the Chrome Web Store (recommended)

**[Add to Chrome →](https://chromewebstore.google.com/detail/skuldsight-soc/mjdpoecgbpenpkadhnkkogifbmmfkjnn)**

### From source (development)

```text
1. Open chrome://extensions
2. Enable Developer mode
3. Click "Load unpacked" and select this project folder
```

> [!NOTE]
> This is a Manifest V3 extension with **no build step** — load the repo root directly. No npm install, no bundler.

---

## 🔧 Configuration

Open **Settings** and add your API keys:

| Key | Required | Purpose |
|-----|----------|---------|
| VirusTotal API | ✅ Yes | All scans |
| AbuseIPDB API | ⬜ No | IP enrichment only |

> [!IMPORTANT]
> Keys are stored in `chrome.storage.local` only (14-day TTL) and are never logged or transmitted anywhere except VirusTotal / AbuseIPDB. Private/reserved IPs are blocked before any outbound request. Rotate keys periodically — expired keys are cleared automatically.

---

## 🏗️ Project structure

No build step — the extension is loaded unpacked and all scripts run in a shared global namespace (no ES modules / bundler).

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

<details>
<summary><b>Load order matters</b></summary>

<br />

Because there is no module system, every file shares one global scope and the
**load order acts as the import graph**. Shared/namespace files must load before
their consumers:

- HTML pages: the `<script>` order in `popup.html` / `options.html`
  (`shared/utils/*` → `i18n.js` → page parts; page entry/init parts load last).
- Service worker: the `importScripts(...)` order in `background/background.js`
  (config/state first, `messaging.js` listeners last).
- Content scripts: the `content_scripts.js` array order in `manifest.json`.

When adding a file, register it in the correct place above and respect the order.

</details>

---

## 🔒 Security

API keys never leave local storage, private/reserved IPs are blocked before outbound calls, and the extension ships a tightened CSP. See [`docs/SECURITY_HARDENING_CHECKLIST.md`](docs/SECURITY_HARDENING_CHECKLIST.md) before release.

## 📜 Changelog

Release history and version notes: [`CHANGELOG.md`](CHANGELOG.md).
