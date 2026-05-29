# Changelog

All notable changes to this project are documented in this file.

## [1.0.1] - 2026-05-29

### Added
- VirusTotal **Reanalyze** action on scan result cards for all IoC types (IP, domain, URL, file).
- Background handler `VT_REANALYZE` calling VT v3 `POST .../analyse` endpoints.
- Inline status banner above the VT chart for queue feedback (success, pending, error).
- `vtObjectId` on scan payloads to improve URL/object targeting for reanalysis.

### Changed
- Reanalyze control is a minimal icon button in the top-right corner of the VirusTotal card.
- Reanalyze feedback is shown in the chart area instead of a toast on success.

### i18n
- English and Turkish strings for reanalyze labels, tooltips, status messages, and errors.
