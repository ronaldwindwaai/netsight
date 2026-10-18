import assert from 'node:assert/strict';
import test from 'node:test';

import type { MenuNode } from '@adminlte/react';

import { menuItemsFor } from './menu.ts';

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

test('the Internet entry points at /internet, next to Traffic', () => {
  const items = menuItemsFor(['internet:read', 'traffic:read']);
  const entry = items.find((item) => item.type === 'item' && item.text === 'Internet');
  assert.ok(entry && entry.type === 'item' && entry.href === '/internet');
  const order = labels(items);
  assert.equal(order.indexOf('Internet'), order.indexOf('Traffic') + 1);
});

test('the menu offers Users only to a session holding a users permission, and fails closed without one', () => {
  assert.ok(labels(menuItemsFor(['users:read-summary'])).includes('Users'));
  assert.ok(labels(menuItemsFor(['users:read', 'users:read-limited', 'users:read-summary'])).includes('Users'));
  // Auditor holds none (an open decision), so the entry is absent rather than a page that refuses.
  assert.ok(!labels(menuItemsFor(['audit:read', 'incidents:read'])).includes('Users'));
  assert.ok(!labels(menuItemsFor([])).includes('Users'));
  assert.ok(!labels(menuItemsFor(null)).includes('Users'));
});

test('the Users entry points at /users, after Devices', () => {
  const items = menuItemsFor(['users:read-summary']);
  const entry = items.find((item) => item.type === 'item' && item.text === 'Users');
  assert.ok(entry && entry.type === 'item' && entry.href === '/users');
  const order = labels(items);
  assert.equal(order.indexOf('Users'), order.indexOf('Devices') + 1);
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
  const order = labels(items);
  assert.ok(order.indexOf('Inventory') > order.indexOf('Devices'));
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
