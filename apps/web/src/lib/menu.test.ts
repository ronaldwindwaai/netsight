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
  const items = menuItemsFor(['internet:read']);
  const entry = items.find((item) => item.type === 'item' && item.text === 'Internet');
  assert.ok(entry && entry.type === 'item' && entry.href === '/internet');
  const order = labels(items);
  assert.equal(order.indexOf('Internet'), order.indexOf('Traffic') + 1);
});
