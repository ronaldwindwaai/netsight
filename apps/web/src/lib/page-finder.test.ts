import assert from 'node:assert/strict';
import test from 'node:test';

import type { MenuNode } from '@adminlte/react';

import { findPages, pageTargetsFrom } from './page-finder.ts';

const MENU: MenuNode[] = [
  { type: 'header', text: 'Network' },
  { type: 'item', text: 'Devices', href: '/devices', icon: 'bi-x' },
  { type: 'item', text: 'Network Map', href: '/network/map', icon: 'bi-x' },
  { type: 'header', text: 'Operations' },
  { type: 'item', text: 'Incidents', href: '/incidents', icon: 'bi-x' },
];

test('pages are flattened with the group they sit under', () => {
  assert.deepEqual(pageTargetsFrom(MENU).map((t) => [t.label, t.group]), [
    ['Devices', 'Network'],
    ['Network Map', 'Network'],
    ['Incidents', 'Operations'],
  ]);
});

test('an empty or blank query matches nothing rather than listing everything', () => {
  const targets = pageTargetsFrom(MENU);
  assert.deepEqual(findPages(targets, ''), []);
  assert.deepEqual(findPages(targets, '   '), []);
});

test('matching is case-insensitive and needs every word', () => {
  const targets = pageTargetsFrom(MENU);
  assert.deepEqual(findPages(targets, 'MAP').map((t) => t.href), ['/network/map']);
  assert.deepEqual(findPages(targets, 'network map').map((t) => t.href), ['/network/map']);
  assert.deepEqual(findPages(targets, 'network').map((t) => t.href), ['/devices', '/network/map']);
  assert.deepEqual(findPages(targets, 'map incidents'), []);
});

test('a query for something that is not a page returns no results (no invented entities)', () => {
  assert.deepEqual(findPages(pageTargetsFrom(MENU), '10.0.0.1'), []);
});
