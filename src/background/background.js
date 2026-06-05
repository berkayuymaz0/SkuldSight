'use strict';

importScripts('../shared/utils/core.js');
importScripts('../shared/utils/analytics.js');
importScripts('../shared/utils/summary.js');
importScripts('../shared/utils/presets.js');
importScripts('../shared/utils/ioc.js');
importScripts('background-guards.js');

function ensureTrustedStorageAccessLevel() {
  try {
    if (chrome.storage && chrome.storage.local && chrome.storage.local.setAccessLevel) {
      chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
    }
  } catch (_) {}
}
ensureTrustedStorageAccessLevel();

/**
 * Service worker: VirusTotal API v3 calls, client-side rate limiting, scan job queue,
 * context menu scans, and long-lived ports for popup/content batch and single scans.
 *
 * Implementation is split into thematic modules loaded below (shared worker scope).
 * Load order is significant: config/state first, listeners (messaging) last.
 */
importScripts('config.js');
importScripts('fetch-retry.js');
importScripts('settings-uimode.js');
importScripts('feeds.js');
importScripts('vt-client.js');
importScripts('vt-parse.js');
importScripts('abuse.js');
importScripts('scan.js');
importScripts('analytics.js');
importScripts('messaging.js');
