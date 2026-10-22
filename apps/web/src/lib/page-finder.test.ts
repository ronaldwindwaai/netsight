import assert from 'node:assert/strict';
import test from 'node:test';

import type { MenuNode } from '@adminlte/react';

import { menuItemsFor } from './menu.ts';
import { findPages, pageTargetsFrom } from './page-finder.ts';
import type { PageTarget } from './page-finder.ts';

const MENU: MenuNode[] = [
  { type: 'header', text: 'Network' },
  { type: 'item', text: 'Devices', href: '/devices', icon: 'bi-x' },
  { type: 'item', text: 'Network Map', href: '/network/map', icon: 'bi-x' },
  { type: 'header', text: 'Operations' },
  { type: 'item', text: 'Incidents', href: '/incidents', icon: 'bi-x' },
];

const NOTHING = { items: [], total: 0 };

test('pages are flattened with the group they sit under', () => {
  assert.deepEqual(pageTargetsFrom(MENU).map((t) => [t.label, t.group]), [
    ['Devices', 'Network'],
    ['Network Map', 'Network'],
    ['Incidents', 'Operations'],
  ]);
});

test('an empty or blank query matches nothing rather than listing everything', () => {
  const targets = pageTargetsFrom(MENU);
  assert.deepEqual(findPages(targets, ''), NOTHING);
  assert.deepEqual(findPages(targets, '   '), NOTHING);
});

test('matching is case-insensitive and needs every word', () => {
  const targets = pageTargetsFrom(MENU);
  assert.deepEqual(findPages(targets, 'MAP').items.map((t) => t.href), ['/network/map']);
  assert.deepEqual(findPages(targets, 'network map').items.map((t) => t.href), ['/network/map']);
  assert.deepEqual(findPages(targets, 'network').items.map((t) => t.href), ['/devices', '/network/map']);
  assert.deepEqual(findPages(targets, 'map incidents'), NOTHING);
});

test('a query for something that is not a page returns no results (no invented entities)', () => {
  assert.deepEqual(findPages(pageTargetsFrom(MENU), '10.0.0.1'), NOTHING);
});

test('a truncated list still reports the true total', () => {
  const many: PageTarget[] = Array.from({ length: 20 }, (_, i) => ({ label: `Page ${i}`, href: `/p${i}`, group: 'G' }));
  const result = findPages(many, 'page');
  assert.equal(result.items.length, 8);
  assert.equal(result.total, 20);
});

test('pages hidden from a session are not offered by the finder', () => {
  const labels = pageTargetsFrom(menuItemsFor([])).map((t) => t.label);
  assert.ok(labels.includes('Incidents'));
  for (const hidden of ['Diagnostics', 'Configuration', 'Traffic']) assert.ok(!labels.includes(hidden));
  assert.deepEqual(findPages(pageTargetsFrom(menuItemsFor([])), 'diagnostics'), NOTHING);
  assert.ok(pageTargetsFrom(menuItemsFor(['diagnostics:read'])).some((t) => t.label === 'Diagnostics'));
});
