import assert from 'node:assert/strict';
import test from 'node:test';

import { STALE_AFTER_MS, connectivityState, describeConnectivity } from './connectivity.ts';

const LOADED = Date.parse('2026-10-18T10:00:00Z');

test('online and fresh is live and shows no banner', () => {
  const state = connectivityState({ online: true, loadedAtMs: LOADED, nowMs: LOADED + 1000 });
  assert.equal(state, 'live');
  assert.equal(describeConnectivity(state, LOADED), null);
});

test('offline is reported as offline however fresh the page is', () => {
  assert.equal(connectivityState({ online: false, loadedAtMs: LOADED, nowMs: LOADED + 1 }), 'offline');
});

test('an online page older than the stale threshold is stale', () => {
  assert.equal(connectivityState({ online: true, loadedAtMs: LOADED, nowMs: LOADED + STALE_AFTER_MS - 1 }), 'live');
  assert.equal(connectivityState({ online: true, loadedAtMs: LOADED, nowMs: LOADED + STALE_AFTER_MS }), 'stale');
});

test('offline wins over stale', () => {
  assert.equal(connectivityState({ online: false, loadedAtMs: LOADED, nowMs: LOADED + STALE_AFTER_MS * 5 }), 'offline');
});

test('a clock that went backwards is treated as live, not as a negative age', () => {
  assert.equal(connectivityState({ online: true, loadedAtMs: LOADED, nowMs: LOADED - 10_000 }), 'live');
});

test('offline and stale messages say the data is not live and give the load time', () => {
  const offline = describeConnectivity('offline', LOADED);
  const stale = describeConnectivity('stale', LOADED);
  assert.ok(offline !== null && stale !== null);
  assert.match(offline.message, /offline/i);
  assert.match(offline.message, /not live/i);
  assert.match(offline.detail, /2026-10-18 10:00 UTC/);
  assert.match(stale.message, /may be out of date/i);
  assert.match(stale.detail, /Reload/i);
});
