import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { countByStatus, nextSort, sortDevices } from './device-view.ts';
import type { Device } from './api-contracts.ts';

function device(over: Partial<Device> & { id: string }): Device {
  return {
    name: over.id,
    hostname: null,
    type: 'switch',
    status: 'healthy',
    ip_addresses: [],
    mac_addresses: [],
    site_id: null,
    owner_identity_id: null,
    source_aliases: [],
    freshness: { state: 'fresh', observed_at: null, source: null },
    ...over,
  };
}

describe('sortDevices', () => {
  it('puts the most urgent status first when ascending', () => {
    const rows = [
      device({ id: 'a', status: 'healthy' }),
      device({ id: 'b', status: 'critical' }),
      device({ id: 'c', status: 'unknown' }),
    ];
    assert.deepEqual(sortDevices(rows, 'status', 'asc').map((d) => d.id), ['b', 'c', 'a']);
  });

  it('sorts names naturally and does not mutate the input', () => {
    const rows = [device({ id: 'sw10' }), device({ id: 'sw2' })];
    assert.deepEqual(sortDevices(rows, 'name', 'asc').map((d) => d.id), ['sw2', 'sw10']);
    assert.deepEqual(rows.map((d) => d.id), ['sw10', 'sw2']);
  });

  it('keeps missing values last in both directions', () => {
    const rows = [
      device({ id: 'none' }),
      device({ id: 'low', ip_addresses: ['10.0.0.1'] }),
      device({ id: 'high', ip_addresses: ['10.0.0.9'] }),
    ];
    assert.deepEqual(sortDevices(rows, 'ip', 'asc').map((d) => d.id), ['low', 'high', 'none']);
    assert.deepEqual(sortDevices(rows, 'ip', 'desc').map((d) => d.id), ['high', 'low', 'none']);
  });

  it('is stable for equal keys', () => {
    const rows = [device({ id: 'x' }), device({ id: 'y' }), device({ id: 'z' })];
    assert.deepEqual(sortDevices(rows, 'type', 'desc').map((d) => d.id), ['x', 'y', 'z']);
  });

  it('sorts stale freshness first', () => {
    const rows = [
      device({ id: 'f' }),
      device({ id: 's', freshness: { state: 'stale', observed_at: null, source: null } }),
    ];
    assert.deepEqual(sortDevices(rows, 'freshness', 'asc').map((d) => d.id), ['s', 'f']);
  });
});

describe('countByStatus and nextSort', () => {
  it('reports every status including zeros', () => {
    const counts = countByStatus([device({ id: 'a', status: 'offline' })]);
    assert.equal(counts.offline, 1);
    assert.equal(counts.healthy, 0);
  });

  it('starts ascending from no sort at all', () => {
    assert.deepEqual(nextSort(null, 'site'), { key: 'site', direction: 'asc' });
  });

  it('treats an empty type as missing, last in both directions', () => {
    const rows = [device({ id: 'e', type: '' }), device({ id: 'a', type: 'ap' })];
    assert.deepEqual(sortDevices(rows, 'type', 'asc').map((d) => d.id), ['a', 'e']);
    assert.deepEqual(sortDevices(rows, 'type', 'desc').map((d) => d.id), ['a', 'e']);
  });

  it('toggles direction on the same column and resets on a new one', () => {
    assert.deepEqual(nextSort({ key: 'name', direction: 'asc' }, 'name'), { key: 'name', direction: 'desc' });
    assert.deepEqual(nextSort({ key: 'name', direction: 'desc' }, 'site'), { key: 'site', direction: 'asc' });
  });
});
