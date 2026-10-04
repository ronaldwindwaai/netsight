import assert from 'node:assert/strict';
import test from 'node:test';

import type { Device, DeviceListResponse, DeviceStatus } from './api-contracts.ts';
import {
  deviceHealthSummary,
  sourceProvenance,
  type OverviewFetchKind,
} from './overview-summary.ts';

function device(status: DeviceStatus, index = 1): Device {
  return {
    id: `device-00000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
    name: `Device ${index}`,
    hostname: null,
    type: 'network',
    status,
    ip_addresses: [],
    mac_addresses: [],
    site_id: null,
    owner_identity_id: null,
    source_aliases: [{ source: 'librenms', native_id: String(index) }],
    freshness: { state: 'fresh', observed_at: null, source: 'librenms' },
  };
}

function inventory(statuses: DeviceStatus[], total = statuses.length): DeviceListResponse {
  return {
    items: statuses.map(device),
    page: 1,
    page_size: 100,
    total,
    freshness: { state: 'fresh', observed_at: null, source: 'librenms' },
  };
}

test('uses success only for a complete all-healthy inventory', () => {
  assert.deepEqual(deviceHealthSummary(inventory(['healthy', 'healthy'])), {
    title: '100%',
    detail: '0 need attention · 0 unscored',
    progress: 100,
    theme: 'success',
  });
});

test('treats every attention status as warning evidence', () => {
  for (const status of ['warning', 'degraded', 'critical', 'offline'] as const) {
    const summary = deviceHealthSummary(inventory(['healthy', status]));
    assert.equal(summary.theme, 'warning', status);
    assert.equal(summary.detail, '1 need attention · 0 unscored', status);
    assert.equal(summary.progress, 50, status);
  }
});

test('keeps unknown and maintenance devices neutral and explicitly unscored', () => {
  for (const status of ['unknown', 'maintenance'] as const) {
    const summary = deviceHealthSummary(inventory(['healthy', status]));
    assert.equal(summary.theme, 'secondary', status);
    assert.equal(summary.title, '1 healthy', status);
    assert.equal(summary.detail, '0 need attention · 1 unscored', status);
    assert.equal(summary.progress, undefined, status);
  }
});

test('never presents a partial healthy page as complete success', () => {
  assert.deepEqual(deviceHealthSummary(inventory(['healthy', 'healthy'], 250)), {
    title: '2 healthy',
    detail: '2 of 250 devices sampled',
    progress: undefined,
    theme: 'secondary',
  });
});

test('distinguishes unavailable, empty, and non-empty inventory states', () => {
  assert.equal(deviceHealthSummary(null).title, 'Unknown');
  assert.deepEqual(deviceHealthSummary(inventory([])), {
    title: 'No devices',
    detail: 'Valid empty inventory',
    progress: 0,
    theme: 'secondary',
  });
});

test('does not infer a LibreNMS outage from auth or API failures', () => {
  const unknownKinds: OverviewFetchKind[] = [
    'unauthenticated',
    'forbidden',
    'not_found',
    'invalid_response',
    'error',
  ];
  for (const kind of unknownKinds) {
    assert.match(sourceProvenance(kind).label, /^Source status unknown/, kind);
    assert.equal(sourceProvenance(kind).tone, '', kind);
  }

  assert.equal(sourceProvenance('source_unavailable').label, 'LibreNMS unavailable');
  assert.equal(sourceProvenance('maintenance').label, 'LibreNMS maintenance');
  assert.equal(sourceProvenance('invalid_source_data').label, 'LibreNMS data rejected');
  assert.deepEqual(sourceProvenance('ok', 'fresh'), {
    label: 'LibreNMS fresh',
    tone: 'is-connected',
  });
  assert.deepEqual(sourceProvenance('ok', 'unknown'), {
    label: 'LibreNMS unknown',
    tone: 'is-caution',
  });
});
