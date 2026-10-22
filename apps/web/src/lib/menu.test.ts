import assert from 'node:assert/strict';
import test from 'node:test';

import type { MenuNode } from '@adminlte/react';

import { menuItemsFor } from './menu.ts';

/** The header an item sits under, or null when it is absent. */
function groupOf(items: readonly MenuNode[], text: string): string | null {
  let current: string | null = null;
  for (const item of items) {
    if (item.type === 'header') current = item.text;
    else if (item.type === 'item' && item.text === text) return current;
  }
  return null;
}

function headers(items: readonly MenuNode[]): string[] {
  return items.flatMap((item) => (item.type === 'header' ? [item.text] : []));
}

function labels(items: readonly MenuNode[]): string[] {
  return items.flatMap((item) => (item.type === 'item' ? [item.text] : []));
}

test('the menu offers Diagnostics only to a session holding diagnostics:read', () => {
  assert.ok(labels(menuItemsFor(['diagnostics:read', 'incidents:read'])).includes('Diagnostics'));
  assert.ok(!labels(menuItemsFor(['incidents:read-summary', 'audit:read'])).includes('Diagnostics'));
  assert.ok(!labels(menuItemsFor([])).includes('Diagnostics'));
});

test('without a session the menu fails closed and hides Diagnostics', () => {
  assert.ok(!labels(menuItemsFor(null)).includes('Diagnostics'));
});

test('every other entry is unaffected by the diagnostics permission', () => {
  const without = labels(menuItemsFor([])).filter((text) => text !== 'Diagnostics');
  const withIt = labels(menuItemsFor(['diagnostics:read'])).filter((text) => text !== 'Diagnostics');
  assert.deepEqual(without, withIt);
  assert.ok(without.includes('Incidents') && without.includes('Overview'));
});

test('the menu offers Internet only to a session holding internet:read, and fails closed without one', () => {
  assert.ok(labels(menuItemsFor(['internet:read'])).includes('Internet'));
  assert.ok(!labels(menuItemsFor(['incidents:read', 'diagnostics:read'])).includes('Internet'));
  assert.ok(!labels(menuItemsFor([])).includes('Internet'));
  assert.ok(!labels(menuItemsFor(null)).includes('Internet'));
});

test('the Internet entry points at /internet, under Network', () => {
  const items = menuItemsFor(['internet:read', 'traffic:read']);
  const entry = items.find((item) => item.type === 'item' && item.text === 'Internet');
  assert.ok(entry && entry.type === 'item' && entry.href === '/internet');
  assert.equal(groupOf(items, 'Internet'), 'Network');
});

test('the menu offers Users only to a session holding a users permission, and fails closed without one', () => {
  assert.ok(labels(menuItemsFor(['users:read-summary'])).includes('Users'));
  assert.ok(labels(menuItemsFor(['users:read', 'users:read-limited', 'users:read-summary'])).includes('Users'));
  // Auditor holds none (an open decision), so the entry is absent rather than a page that refuses.
  assert.ok(!labels(menuItemsFor(['audit:read', 'incidents:read'])).includes('Users'));
  assert.ok(!labels(menuItemsFor([])).includes('Users'));
  assert.ok(!labels(menuItemsFor(null)).includes('Users'));
});

test('the Users entry points at /users, under Security (identity)', () => {
  const items = menuItemsFor(['users:read-summary']);
  const entry = items.find((item) => item.type === 'item' && item.text === 'Users');
  assert.ok(entry && entry.type === 'item' && entry.href === '/users');
  assert.equal(groupOf(items, 'Users'), 'Security');
});

test('the menu offers Traffic only to a session holding traffic:read, and fails closed without one', () => {
  assert.ok(labels(menuItemsFor(['traffic:read'])).includes('Traffic'));
  assert.ok(labels(menuItemsFor(['traffic:read', 'traffic:read-detail'])).includes('Traffic'));
  // Technician holds no traffic permission (an open decision), so the entry is absent.
  assert.ok(!labels(menuItemsFor(['incidents:read', 'diagnostics:read'])).includes('Traffic'));
  assert.ok(!labels(menuItemsFor([])).includes('Traffic'));
  assert.ok(!labels(menuItemsFor(null)).includes('Traffic'));
});

test('the menu offers Inventory, IPAM and Unknown devices only to a session holding their permission', () => {
  const held = labels(menuItemsFor(['inventory:read-summary', 'ipam:read-summary', 'unknown-devices:read-summary']));
  assert.ok(held.includes('Inventory') && held.includes('IPAM') && held.includes('Unknown devices'));
  for (const text of ['Inventory', 'IPAM', 'Unknown devices']) {
    assert.ok(!labels(menuItemsFor(['incidents:read', 'devices:read'])).includes(text));
    assert.ok(!labels(menuItemsFor([])).includes(text));
    assert.ok(!labels(menuItemsFor(null)).includes(text));
  }
});

test('each of the three entries is gated by its own permission', () => {
  const mine = (permission: string) =>
    labels(menuItemsFor([permission])).filter((t) => ['Inventory', 'IPAM', 'Unknown devices'].includes(t));
  assert.deepEqual(mine('inventory:read-summary'), ['Inventory']);
  assert.deepEqual(mine('ipam:read-summary'), ['IPAM']);
  assert.deepEqual(mine('unknown-devices:read-summary'), ['Unknown devices']);
});

test('the new entries point at their pages, after Devices', () => {
  const items = menuItemsFor(['inventory:read-summary', 'ipam:read-summary', 'unknown-devices:read-summary']);
  const href = (text: string) => {
    const entry = items.find((item) => item.type === 'item' && item.text === text);
    return entry && entry.type === 'item' ? entry.href : null;
  };
  assert.equal(href('Inventory'), '/inventory');
  assert.equal(href('IPAM'), '/ipam');
  assert.equal(href('Unknown devices'), '/unknown-devices');
  assert.equal(groupOf(items, 'Inventory'), 'Infrastructure');
  assert.equal(groupOf(items, 'IPAM'), 'Infrastructure');
  assert.equal(groupOf(items, 'Unknown devices'), 'Security');
});

test('configuration menu is visible only with its backend permission', () => {
  assert.ok(labels(menuItemsFor(['configuration:read'])).includes('Configuration'));
  assert.ok(!labels(menuItemsFor(null)).includes('Configuration'));
  assert.ok(!labels(menuItemsFor(['reports:read'])).includes('Configuration'));
});

test('reports navigation follows the reports:read permission', () => {
  assert.ok(labels(menuItemsFor(['reports:read'])).includes('Reports'));
  assert.ok(!labels(menuItemsFor(null)).includes('Reports'));
});

test('the menu offers Action requests only to a session holding actions:read, and fails closed without one', () => {
  const items = menuItemsFor(['actions:read']);
  const entry = items.find((item) => item.type === 'item' && item.text === 'Action requests');
  assert.ok(entry && entry.type === 'item' && entry.href === '/actions');
  assert.ok(!labels(menuItemsFor(['incidents:read', 'actions:propose'])).includes('Action requests'));
  assert.ok(!labels(menuItemsFor([])).includes('Action requests'));
  assert.ok(!labels(menuItemsFor(null)).includes('Action requests'));
});

test('the menu offers Capacity forecast only to a session holding forecast:read, and fails closed without one', () => {
  const items = menuItemsFor(['forecast:read']);
  const entry = items.find((item) => item.type === 'item' && item.text === 'Capacity forecast');
  assert.ok(entry && entry.type === 'item' && entry.href === '/forecast');
  assert.ok(!labels(menuItemsFor(['forecast:export', 'traffic:read'])).includes('Capacity forecast'));
  assert.ok(!labels(menuItemsFor([])).includes('Capacity forecast'));
  assert.ok(!labels(menuItemsFor(null)).includes('Capacity forecast'));
});

test('the menu follows the information-architecture groups, in order', () => {
  const everything = [
    'inventory:read-summary', 'ipam:read-summary', 'unknown-devices:read-summary', 'users:read-summary',
    'traffic:read', 'internet:read', 'forecast:read', 'diagnostics:read', 'copilot:ask', 'actions:read',
    'configuration:read', 'reports:read',
  ];
  assert.deepEqual(headers(menuItemsFor(everything)), [
    'Overview', 'Network', 'Security', 'Operations', 'Infrastructure', 'Intelligence', 'Analytics',
  ]);
});

test('a group with no visible entry shows no header (no empty sections)', () => {
  const none = headers(menuItemsFor(null));
  assert.ok(!none.includes('Intelligence') && !none.includes('Analytics') && !none.includes('Infrastructure'));
  assert.ok(none.includes('Overview') && none.includes('Network') && none.includes('Security') && none.includes('Operations'));
});

test('core entries sit under their group', () => {
  const items = menuItemsFor(['diagnostics:read', 'copilot:ask', 'traffic:read', 'configuration:read']);
  assert.equal(groupOf(items, 'Overview'), 'Overview');
  assert.equal(groupOf(items, 'Network Map'), 'Network');
  assert.equal(groupOf(items, 'Devices'), 'Network');
  assert.equal(groupOf(items, 'Security'), 'Security');
  assert.equal(groupOf(items, 'Incidents'), 'Operations');
  assert.equal(groupOf(items, 'Alerts'), 'Operations');
  assert.equal(groupOf(items, 'Diagnostics'), 'Operations');
  assert.equal(groupOf(items, 'Ask Netsight'), 'Intelligence');
  assert.equal(groupOf(items, 'Traffic'), 'Analytics');
  assert.equal(groupOf(items, 'Configuration'), 'Infrastructure');
});
