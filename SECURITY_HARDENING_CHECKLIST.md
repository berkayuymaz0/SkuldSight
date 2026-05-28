# Security Hardening Checklist

## Pre-release
- Verify `manifest.json` keeps only minimum required permissions and hosts.
- Confirm `content_scripts.matches` is limited to required origins.
- Ensure all remote endpoints are `https://` only.
- Review `web_accessible_resources` for minimum exposure.
- Run `scripts/prepush-check.sh` and resolve any failure.

## Runtime messaging safety
- `chrome.runtime.onMessage` accepts trusted runtime sender only.
- `chrome.runtime.onConnect` accepts trusted runtime sender only.
- Port names are allowlisted (`vt-single`, `vt-batch`).
- Message payloads are validated per operation type.

## Key management
- API keys are never logged.
- Expired keys are cleared from storage automatically.
- Encourage periodic key rotation in release notes.

## Manual smoke tests
- Single IoC scan from popup works.
- Batch scan reports line-by-line results and completion.
- Content badge scan works on HTTPS page.
- Options page can save and test VT/Abuse keys.
