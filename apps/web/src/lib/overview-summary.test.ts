import assert from 'node:assert/strict';
import test from 'node:test';

import { parseOverviewResponse, type DeviceHealthSummary, type DeviceStatus } from './api-contracts.ts';
import {
  deviceHealthSummary,
  sourceProvenance,
  type OverviewFetchKind,
} from './overview-summary.ts';

function summary(statuses: DeviceStatus[]): DeviceHealthSummary {
  const counts = new Map<DeviceStatus, number>();
  for (const status of statuses) {
    counts.set(status, (counts.get(status) ?? 0) + 1);
  }
  const order: DeviceStatus[] = [
    'healthy',
    'warning',
    'degraded',
    'critical',
    'offline',
    'unknown',
    'maintenance',
  ];
  return {
    total: statuses.length,
    by_status: order
      .filter((status) => counts.has(status))
      .map((status) => ({ status, count: counts.get(status) ?? 0 })),
    freshness: { state: 'fresh', observed_at: null, source: 'librenms' },
  };
}

test('uses success only for a complete all-healthy inventory', () => {
  assert.deepEqual(deviceHealthSummary(summary(['healthy', 'healthy'])), {
    title: '100%',
    detail: '0 need attention · 0 unscored',
    progress: 100,
    theme: 'success',
  });
});

test('treats every attention status as warning evidence', () => {
  for (const status of ['warning', 'degraded', 'critical', 'offline'] as const) {
    const result = deviceHealthSummary(summary(['healthy', status]));
    assert.equal(result.theme, 'warning', status);
    assert.equal(result.detail, '1 need attention · 0 unscored', status);
    assert.equal(result.progress, 50, status);
  }
});

test('keeps unknown and maintenance devices neutral and explicitly unscored', () => {
  for (const status of ['unknown', 'maintenance'] as const) {
    const result = deviceHealthSummary(summary(['healthy', status]));
    assert.equal(result.theme, 'secondary', status);
    assert.equal(result.title, '1 healthy', status);
    assert.equal(result.detail, '0 need attention · 1 unscored', status);
    assert.equal(result.progress, undefined, status);
  }
});

test('computes progress from the aggregate counts', () => {
  assert.deepEqual(deviceHealthSummary(summary(['healthy', 'healthy', 'healthy', 'warning'])), {
    title: '75%',
    detail: '1 need attention · 0 unscored',
    progress: 75,
    theme: 'warning',
  });
});

test('parseOverviewResponse accepts a canonical overview aggregate', () => {
  assert.deepEqual(
    parseOverviewResponse({
      devices: {
        total: 2,
        by_status: [
          { status: 'healthy', count: 1 },
          { status: 'offline', count: 1 },
        ],
        freshness: { state: 'fresh', observed_at: '2026-10-04T12:00:00Z', source: 'librenms' },
      },
      sources: { librenms: { configured: true, status: 'success' } },
    }),
    {
      devices: {
        total: 2,
        by_status: [
          { status: 'healthy', count: 1 },
          { status: 'offline', count: 1 },
        ],
        freshness: { state: 'fresh', observed_at: '2026-10-04T12:00:00Z', source: 'librenms' },
      },
      sources: { librenms: { configured: true, status: 'success' } },
    },
  );
});

test('parseOverviewResponse rejects malformed aggregates', () => {
  assert.equal(parseOverviewResponse(null), null);
  assert.equal(parseOverviewResponse({}), null);
  assert.equal(
    parseOverviewResponse({
      devices: { total: -1, by_status: [], freshness: null },
      sources: { librenms: { configured: true, status: 'success' } },
    }),
    null,
  );
  assert.equal(
    parseOverviewResponse({
      devices: {
        total: 1,
        by_status: [{ status: 'healthy', count: -1 }],
        freshness: { state: 'fresh', observed_at: null, source: 'librenms' },
      },
      sources: { librenms: { configured: true, status: 'success' } },
    }),
    null,
  );
  assert.equal(
    parseOverviewResponse({
      devices: {
        total: 1,
        by_status: [{ status: 'nonsense', count: 1 }],
        freshness: { state: 'fresh', observed_at: null, source: 'librenms' },
      },
      sources: { librenms: { configured: true, status: 'success' } },
    }),
    null,
  );
  assert.equal(
    parseOverviewResponse({
      devices: {
        total: 1,
        by_status: [],
        freshness: { state: 'fresh', observed_at: null, source: 'librenms' },
      },
      sources: { librenms: { configured: 'yes', status: 'success' } },
    }),
    null,
  );
  assert.equal(
    parseOverviewResponse({
      devices: {
        total: 1,
        by_status: [],
        freshness: { state: 'fresh', observed_at: null, source: 'librenms' },
      },
      sources: { librenms: { configured: true, status: 'made-up' } },
    }),
    null,
  );
});

test('distinguishes unavailable, empty, and non-empty inventory states', () => {
  assert.equal(deviceHealthSummary(null).title, 'Unknown');
  assert.deepEqual(deviceHealthSummary(summary([])), {
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
    'rate_limited',
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
