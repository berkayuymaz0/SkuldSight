# Changelog

All notable changes to SkuldSight SOC are documented here.

## [1.1.0] — 2026-06-08

**Changed**
- Rebranded from PixelPaw SOC to **SkuldSight SOC** (name, UI strings, notifications).
- New extension logo/icons generated from the SkuldSight shield artwork.

## [1.0.6] — 2026-06-05

**Security**
- AbuseIPDB API key is sent via the `Key` HTTP header instead of the URL query string.
- Background port/message validation tightened (payload size, batch line/count limits, plain-object checks).
- Batch scans stop when the popup/side-panel port disconnects.
- Private/reserved IP ranges are blocked before VirusTotal, AbuseIPDB, or VT reanalysis calls.
- Extension CSP tightened (`img-src`, `form-action`, `frame-src`, `frame-ancestors`).
- VirusTotal and AbuseIPDB outbound links validated with URL parsing and host allowlists.
- RSS/USOM feed data normalized and size-limited before storage; popup import capped at 1 MB / 250 lines.
- `chrome.storage.local` restricted to trusted extension contexts (`setAccessLevel`); content scripts load settings via background messaging.
- Sender context matrix limits message types by origin (popup/options vs content); content scans rate-limited per tab.
- URL query/hash stripped before VirusTotal scans by default; full-URL scan is opt-in in Options.
- IANA special-use IPv6 ranges added to the private/reserved IP guard (IPv4-mapped, Teredo, 6to4, NAT64).
- Central `fetchWithRetry` helper adds 5xx/429 retry with `Retry-After` and exponential backoff for VT and AbuseIPDB.
- DOM badge scan capped per flush and scheduled with `requestIdleCallback`; inline cache keys namespaced as `vt:scan:{kind}:{value}`.
- External links in popup use a shared `applySafeExternalLink` helper (`noopener noreferrer`).
- Minimum Chrome version set to 102 (required for storage access level).

**Fixed**
- Popup API status check (`TEST_VT_CONNECTION`) works again after sender-context hardening.
- Content script `VtSocUtils` merge preserves IP/hash detection helpers after Phase 2 module load order change.
- Content badge bootstrap runs after all content modules load; settings fetch retries on cold service worker start.
- Scheduled DOM scans are cancelled when inline badges are disabled via settings.

## [1.0.5] — 2026-06-05

**Changed**
- IP lookups now query each provider (VirusTotal, AbuseIPDB) independently so one missing key or failure never blocks the other; new integrations can plug in the same way.
- Scans work with **AbuseIPDB alone** (IP-only) or **VirusTotal alone**: an IP can be scored from AbuseIPDB even when no VirusTotal key is set, and a VirusTotal failure no longer drops an available AbuseIPDB result.
- Result card shows an Abuse-only verdict when VirusTotal data is unavailable; the VT pill reads "No key" instead of a misleading "Clean".

**Fixed**
- Missing/expired VirusTotal key now returns i18n error keys (`errorVtNoKey`, `errorVtKeyExpired`); IPs with no configured provider return `errorNoProvider`.

## [1.0.4] — 2026-05-31

**Changed**
- Project layout under `src/`, `styles/`, `assets/`, and `docs/` with modular scripts and CSS (no build step); see [Project structure](README.md#project-structure) in the README.
- Unified IoC classification (IPv6, URL validation) across background and popup; consolidated content badges, copy-summary field gating, and CSS cleanup.
- IP scans read scan preset once per request; news/USOM search debounced in the popup.

**Fixed**
- Background: job-queue race on worker shutdown; Abuse threat shown as `unknown` when lookup fails (not `clean`); unknown message types and context-menu errors return `errorKey`/`errorVars`.
- Content: IPv6 badge pre-filter; settings load race before first scan; inline scan timeout on port disconnect; IP badge SVG stroke; `characterData` mutations for SPAs.
- Popup: combined VT+Abuse threat after recent IP enrich; USOM detail race on slow fetch; DOM null guards on core controls.
- Options: i18n confirm dialogs; live preset matrix on checkbox changes; content panel copy respects “Copy summary fields”.
- Side panel / popup paths point to `src/popup/popup.html` after restructure (`ERR_FILE_NOT_FOUND`).

## [1.0.3] — 2026-05-30

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

## [1.0.2] — 2026-05-29

**Added**
- On-page badges for **URLs** and **file hashes** (MD5, SHA-1, SHA-256), alongside IP and domain
- Settings master switch: **Enable on-page IOC detection** (`vtContentIocBadges`, default on)
- Shared URL/hash text helpers in `utils.js` (`findUrlsInText`, `findFileHashesInText`, defang `hxxp`)

**Changed**
- Single-pass scan order (URL → IP → domain → hash) to prevent double badges (e.g. domain inside a URL)
- Behavior settings: colored icons beside each toggle and the rate slider (dark/light theme)
- Version bump to `1.0.2`

## [1.0.1] — 2026-05-29

**Added**
- VT **Reanalyze** for all IoC types (result card, top-right icon)
- Status banner above the chart (queue / error feedback)
- Background: `VT_REANALYZE` → VT v3 `POST .../analyse`

**Changed**
- Reanalyze feedback shown in the chart area instead of a toast
- Version bump to `1.0.1`

## [1.0.0] — 2026-05-28

- Initial release: popup scans, batch, content script, settings/analytics, security hardening baseline
