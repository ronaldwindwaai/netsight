import assert from 'node:assert/strict';
import test from 'node:test';

import { isActiveMobileTab, mobileNavItemsFor } from './mobile-nav.ts';

const labels = (permissions: readonly string[] | null) => mobileNavItemsFor(permissions).map((item) => item.label);

test('every session sees Overview and Incidents on the mobile bar', () => {
  assert.deepEqual(labels([]), ['Overview', 'Incidents']);
  assert.deepEqual(labels(null), ['Overview', 'Incidents']);
});

test('Diagnostics and Internet appear only with their permissions, like the sidebar', () => {
  assert.deepEqual(labels(['diagnostics:read']), ['Overview', 'Incidents', 'Diagnostics']);
  assert.deepEqual(labels(['internet:read']), ['Overview', 'Incidents', 'Internet']);
  assert.deepEqual(labels(['internet:read', 'diagnostics:read']), ['Overview', 'Incidents', 'Diagnostics', 'Internet']);
});

test('a tab is active for its own path and children, not for a similarly named prefix', () => {
  assert.equal(isActiveMobileTab('/incidents', '/incidents'), true);
  assert.equal(isActiveMobileTab('/incidents/abc', '/incidents'), true);
  assert.equal(isActiveMobileTab('/incidents-archive', '/incidents'), false);
  assert.equal(isActiveMobileTab('/overview', '/incidents'), false);
  assert.equal(isActiveMobileTab(null, '/incidents'), false);
});
