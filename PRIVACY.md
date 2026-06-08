# Privacy Policy — SkuldSight SOC

_Last updated: 8 June 2026_

SkuldSight SOC is a Chrome extension that lets security analysts look up the
reputation of indicators of compromise (IP addresses, domains, URLs and file
hashes) using the VirusTotal and AbuseIPDB APIs.

## What the extension handles

- **Indicators you scan** (IPs, domains, URLs, file hashes): sent to
  VirusTotal and/or AbuseIPDB **only when you initiate a scan** (manually, via
  the right-click menu, or by interacting with an on-page badge) so that their
  reputation can be returned to you.
- **Page content**: the on-page detection feature reads text on HTTPS pages
  locally in your browser to highlight indicators. This text is **not**
  transmitted anywhere unless you explicitly scan a highlighted indicator.
- **Your settings, API keys and local scan history**: stored only in
  `chrome.storage.local` on your own device to power the options and analytics
  dashboard.

## What we do NOT do

- We do **not** collect, receive, sell, or transfer your data to the developer
  or any third party beyond the VirusTotal/AbuseIPDB lookups described above.
- We do **not** track your browsing history, location, or personal information.
- We do **not** use your data for advertising, creditworthiness, or any purpose
  unrelated to IOC reputation lookups.

## Third-party services

When you scan an indicator, it is sent to the service(s) you have configured:

- VirusTotal — https://docs.virustotal.com/docs/privacy-policy
- AbuseIPDB — https://www.abuseipdb.com/legal

Your use of those services is governed by their own privacy policies.

## Data retention

All data (settings, API keys, scan history) lives only on your device and is
removed when you clear it in the extension or uninstall the extension.

## Contact

Questions or concerns: https://github.com/berkayuymaz0/PixelPaw-SOC/issues
