import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { alertCsvRows, filterAlerts, sortAlerts } from './alert-list-view.ts';
import type { Alert } from './api-contracts.ts';

function alert(id: string, over: Partial<Alert> = {}): Alert {
  return {
    id,
    severity: 'low',
    state: 'open',
    title: `Alert ${id}`,
    observed_at: '2026-10-18T12:00:00Z',
    device_id: null,
    incident_id: null,
    ...over,
  };
}

const ALERTS = [
  alert('a', { severity: 'low', state: 'open', title: 'Port flap', observed_at: '2026-10-18T10:00:00Z' }),
  alert('b', { severity: 'critical', state: 'acknowledged', title: 'Link down', observed_at: '2026-10-18T12:00:00Z' }),
  alert('c', { severity: 'high', state: 'open', title: 'CPU high', device_id: 'device-1', observed_at: '2026-10-18T11:00:00Z' }),
];

const ids = (list: readonly Alert[]) => list.map((a) => a.id);

describe('filterAlerts', () => {
  it('returns everything for an empty filter', () => {
    assert.deepEqual(ids(filterAlerts(ALERTS, { q: '', severity: null, state: null })), ['a', 'b', 'c']);
  });

  it('filters by severity and state together', () => {
    assert.deepEqual(ids(filterAlerts(ALERTS, { q: '', severity: 'high', state: 'open' })), ['c']);
  });

  it('matches text on title and id, case-insensitively', () => {
    assert.deepEqual(ids(filterAlerts(ALERTS, { q: ' LINK ', severity: null, state: null })), ['b']);
    assert.deepEqual(ids(filterAlerts(ALERTS, { q: 'a', severity: null, state: 'open' })), ['a']);
  });

  it('does not mutate its input', () => {
    const copy = [...ALERTS];
    filterAlerts(ALERTS, { q: 'link', severity: null, state: null });
    assert.deepEqual(ALERTS, copy);
  });
});

describe('sortAlerts', () => {
  it('keeps the API order with no sort', () => {
    assert.deepEqual(ids(sortAlerts(ALERTS, null)), ['a', 'b', 'c']);
  });

  it('sorts severity with the most severe first when ascending', () => {
    assert.deepEqual(ids(sortAlerts(ALERTS, { key: 'severity', direction: 'asc' })), ['b', 'c', 'a']);
    assert.deepEqual(ids(sortAlerts(ALERTS, { key: 'severity', direction: 'desc' })), ['a', 'c', 'b']);
  });

  it('sorts by observed time', () => {
    assert.deepEqual(ids(sortAlerts(ALERTS, { key: 'observed', direction: 'desc' })), ['b', 'c', 'a']);
    assert.deepEqual(ids(sortAlerts(ALERTS, { key: 'observed', direction: 'asc' })), ['a', 'c', 'b']);
  });

  it('sorts by title', () => {
    assert.deepEqual(ids(sortAlerts(ALERTS, { key: 'title', direction: 'asc' })), ['c', 'b', 'a']);
  });

  it('is stable for ties', () => {
    const tied = [alert('x'), alert('y'), alert('z')];
    assert.deepEqual(ids(sortAlerts(tied, { key: 'state', direction: 'desc' })), ['x', 'y', 'z']);
  });
});

describe('alertCsvRows', () => {
  it('lists the fields an operator would paste into a ticket', () => {
    assert.deepEqual(alertCsvRows([ALERTS[2]]), [
      ['high', 'open', 'CPU high', 'device-1', 'c', '2026-10-18T11:00:00Z'],
    ]);
  });
});
