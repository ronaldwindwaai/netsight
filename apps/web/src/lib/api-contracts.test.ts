import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseAlert,
  parseAlertList,
  parseApiError,
  parseAuthProviders,
  parseDevice,
  parseDeviceDetail,
  parseDeviceList,
  parseSessionInfo,
  parseSourceHealth,
} from './api-contracts.ts';

const DEVICE = {
  id: 'device-dc425b99-786e-50f0-82dc-ebe2d0aa0e38',
  name: 'core-sw-01',
  hostname: 'core-sw-01.example.test',
  type: 'network',
  status: 'healthy',
  ip_addresses: ['192.0.2.10'],
  mac_addresses: [],
  site_id: null,
  owner_identity_id: null,
  source_aliases: [{ source: 'librenms', native_id: '1' }],
  freshness: {
    state: 'fresh',
    observed_at: '2026-10-03T02:00:00Z',
    source: 'librenms',
  },
};

const LIST = {
  items: [DEVICE],
  page: 1,
  page_size: 50,
  total: 1,
  freshness: DEVICE.freshness,
};

const SOURCE_HEALTH = {
  source: 'librenms',
  status: 'success',
  reachable: true,
  latency_ms: 12.4,
  checked_at: '2026-10-04T12:30:00Z',
  detail: 'ok',
};

const ALERT = {
  id: 'librenms:7',
  severity: 'critical',
  state: 'open',
  title: 'Link down on port 12',
  observed_at: '2026-10-04T10:02:00Z',
  device_id: DEVICE.id,
  incident_id: null,
};

const ALERT_LIST = {
  items: [ALERT],
  page: 1,
  page_size: 50,
  total: 1,
  freshness: DEVICE.freshness,
};

test('parses canonical alerts and normalises optional references', () => {
  assert.deepEqual(parseAlert(ALERT), ALERT);
  assert.deepEqual(
    parseAlert({
      id: ALERT.id,
      severity: ALERT.severity,
      state: ALERT.state,
      title: ALERT.title,
      observed_at: ALERT.observed_at,
    }),
    { ...ALERT, device_id: null, incident_id: null },
  );
  assert.deepEqual(parseAlertList(ALERT_LIST), ALERT_LIST);
});

test('rejects malformed canonical alerts and alert envelopes', () => {
  assert.equal(parseAlert({ ...ALERT, severity: 'urgent' }), null);
  assert.equal(parseAlert({ ...ALERT, state: 'new' }), null);
  assert.equal(parseAlert({ ...ALERT, observed_at: '2026-02-31T10:02:00Z' }), null);
  assert.equal(parseAlert({ ...ALERT, device_id: 7 }), null);
  assert.equal(parseAlert({ ...ALERT, vendor_rule: 9 }), null);
  assert.equal(parseAlertList({ ...ALERT_LIST, items: [{ ...ALERT, title: 7 }] }), null);
  assert.equal(parseAlertList({ ...ALERT_LIST, page: 0 }), null);
  assert.equal(parseAlertList({ ...ALERT_LIST, page_size: 101 }), null);
  assert.equal(parseAlertList({ ...ALERT_LIST, total: -1 }), null);
  assert.equal(parseAlertList({ ...ALERT_LIST, vendor_page: 1 }), null);
});

test('parses the documented LibreNMS source health response', () => {
  assert.deepEqual(parseSourceHealth(SOURCE_HEALTH), SOURCE_HEALTH);
});

test('accepts every internally consistent source health failure state', () => {
  for (const status of ['unavailable', 'forbidden', 'invalid-source-data'] as const) {
    assert.deepEqual(
      parseSourceHealth({
        ...SOURCE_HEALTH,
        status,
        reachable: false,
        latency_ms: null,
        detail: status,
      }),
      {
        ...SOURCE_HEALTH,
        status,
        reachable: false,
        latency_ms: null,
        detail: status,
      },
    );
  }
});

test('rejects malformed and extended source health responses', () => {
  assert.equal(parseSourceHealth({ ...SOURCE_HEALTH, source: 'other' }), null);
  assert.equal(parseSourceHealth({ ...SOURCE_HEALTH, status: 'healthy' }), null);
  assert.equal(parseSourceHealth({ ...SOURCE_HEALTH, reachable: 1 }), null);
  assert.equal(parseSourceHealth({ ...SOURCE_HEALTH, latency_ms: -0.1 }), null);
  assert.equal(parseSourceHealth({ ...SOURCE_HEALTH, latency_ms: Number.NaN }), null);
  assert.equal(parseSourceHealth({ ...SOURCE_HEALTH, latency_ms: Number.POSITIVE_INFINITY }), null);
  assert.equal(parseSourceHealth({ ...SOURCE_HEALTH, checked_at: 'just now' }), null);
  assert.equal(
    parseSourceHealth({ ...SOURCE_HEALTH, checked_at: '2026-02-31T12:30:00Z' }),
    null,
  );
  assert.equal(parseSourceHealth({ ...SOURCE_HEALTH, detail: 'healthy' }), null);
  assert.equal(parseSourceHealth({ ...SOURCE_HEALTH, debug: true }), null);

  const missingDetail: Partial<typeof SOURCE_HEALTH> = { ...SOURCE_HEALTH };
  delete missingDetail.detail;
  assert.equal(parseSourceHealth(missingDetail), null);
});

test('rejects internally inconsistent source health combinations', () => {
  assert.equal(parseSourceHealth({ ...SOURCE_HEALTH, reachable: false }), null);
  assert.equal(parseSourceHealth({ ...SOURCE_HEALTH, latency_ms: null }), null);
  assert.equal(parseSourceHealth({ ...SOURCE_HEALTH, detail: 'unavailable' }), null);
  assert.equal(
    parseSourceHealth({
      ...SOURCE_HEALTH,
      status: 'unavailable',
      reachable: false,
      latency_ms: null,
      detail: 'forbidden',
    }),
    null,
  );
  assert.equal(
    parseSourceHealth({
      ...SOURCE_HEALTH,
      status: 'forbidden',
      reachable: true,
      latency_ms: 5,
      detail: 'forbidden',
    }),
    null,
  );
  assert.equal(
    parseSourceHealth({
      ...SOURCE_HEALTH,
      status: 'invalid-source-data',
      reachable: false,
      latency_ms: 5,
      detail: 'invalid-source-data',
    }),
    null,
  );
});

test('parses a canonical device list into a clean browser model', () => {
  assert.deepEqual(parseDeviceList(LIST), LIST);
});

test('normalises optional JSON Schema properties without retaining unknown fields', () => {
  const parsed = parseDeviceList({
    items: [
      {
        id: DEVICE.id,
        name: DEVICE.name,
        status: DEVICE.status,
        source_aliases: DEVICE.source_aliases,
        freshness: DEVICE.freshness,
      },
    ],
    page: 1,
    page_size: 50,
    total: 1,
    freshness: DEVICE.freshness,
  });

  assert.ok(parsed);
  assert.deepEqual(parsed.items[0], {
    id: DEVICE.id,
    name: DEVICE.name,
    hostname: null,
    type: 'unknown',
    status: DEVICE.status,
    ip_addresses: [],
    mac_addresses: [],
    site_id: null,
    owner_identity_id: null,
    source_aliases: DEVICE.source_aliases,
    freshness: DEVICE.freshness,
  });
});

test('rejects unexpected properties at every canonical object boundary', () => {
  assert.equal(parseDevice({ ...DEVICE, vendor_private: true }), null);
  assert.equal(
    parseDevice({
      ...DEVICE,
      freshness: { ...DEVICE.freshness, vendor_timestamp: 'ignored' },
    }),
    null,
  );
  assert.equal(
    parseDevice({
      ...DEVICE,
      source_aliases: [{ ...DEVICE.source_aliases[0], vendor_id: 'ignored' }],
    }),
    null,
  );
  assert.equal(parseDeviceList({ ...LIST, vendor_page: 1 }), null);
  assert.equal(parseDeviceDetail({ item: DEVICE, vendor_detail: true }), null);
});

test('rejects invalid canonical IDs, statuses, and missing required properties', () => {
  assert.equal(parseDevice({ ...DEVICE, id: 'device:librenms:1' }), null);
  assert.equal(
    parseDevice({ ...DEVICE, id: 'device-DC425B99-786E-50F0-82DC-EBE2D0AA0E38' }),
    null,
  );
  assert.equal(parseDevice({ ...DEVICE, status: 'up-ish' }), null);
  assert.equal(parseDevice({ ...DEVICE, source_aliases: [{ source: 'librenms' }] }), null);

  const withoutFreshness: Partial<typeof DEVICE> = { ...DEVICE };
  const withoutAliases: Partial<typeof DEVICE> = { ...DEVICE };
  delete withoutFreshness.freshness;
  delete withoutAliases.source_aliases;
  assert.equal(parseDevice(withoutFreshness), null);
  assert.equal(parseDevice(withoutAliases), null);
});

test('rejects list and detail envelopes with invalid devices', () => {
  assert.equal(
    parseDeviceList({
      items: [{ ...DEVICE, freshness: { state: 'fresh', observed_at: 123 } }],
      page: 1,
      page_size: 50,
      total: 1,
      freshness: DEVICE.freshness,
    }),
    null,
  );
  assert.equal(parseDeviceDetail({ item: { ...DEVICE, id: 42 } }), null);
});

test('accepts nullable provenance for every freshness state and validates present timestamps', () => {
  assert.ok(
    parseDevice({
      ...DEVICE,
      freshness: { state: 'fresh', observed_at: null, source: null },
    }),
  );
  assert.ok(
    parseDevice({
      ...DEVICE,
      freshness: { state: 'stale', observed_at: null, source: null },
    }),
  );
  assert.equal(
    parseDevice({
      ...DEVICE,
      freshness: { state: ['fresh'], observed_at: null, source: null },
    }),
    null,
  );
  assert.equal(
    parseDevice({
      ...DEVICE,
      freshness: { state: 'fresh', observed_at: 'yesterday', source: 'librenms' },
    }),
    null,
  );
  assert.equal(
    parseDevice({
      ...DEVICE,
      freshness: { state: 'unknown', observed_at: '2026-02-31T02:00:00Z', source: null },
    }),
    null,
  );
  assert.ok(
    parseDevice({
      ...DEVICE,
      freshness: { state: 'unknown', observed_at: null, source: null },
    }),
  );
});

test('accepts unbounded canonical strings and arrays while retaining their documented types', () => {
  assert.ok(parseDevice({ ...DEVICE, name: '' }));
  assert.ok(parseDevice({ ...DEVICE, name: 'n'.repeat(256) }));
  assert.ok(parseDevice({ ...DEVICE, type: '' }));
  assert.ok(parseDevice({ ...DEVICE, type: 't'.repeat(129) }));
  assert.ok(parseDevice({ ...DEVICE, hostname: 'h'.repeat(256) }));
  assert.equal(parseDevice({ ...DEVICE, ip_addresses: null }), null);
  assert.ok(parseDevice({ ...DEVICE, ip_addresses: Array(257).fill('192.0.2.1') }));
  assert.ok(parseDevice({ ...DEVICE, mac_addresses: Array(257).fill('00:00:00:00:00:00') }));
  assert.equal(parseDevice({ ...DEVICE, source_aliases: [] }), null);
  assert.equal(
    parseDevice({
      ...DEVICE,
      source_aliases: [{ source: 's'.repeat(65), native_id: '1' }],
    }),
    null,
  );
  assert.equal(
    parseDevice({
      ...DEVICE,
      source_aliases: [{ source: 'librenms', native_id: 'n'.repeat(256) }],
    }),
    null,
  );
  assert.ok(
    parseDevice({
      ...DEVICE,
      freshness: {
        ...DEVICE.freshness,
        source: 's'.repeat(65),
      },
    }),
  );
});

test('requires bounded unique source and native ID alias pairs', () => {
  const duplicate = { source: 'librenms', native_id: '1' };
  assert.equal(parseDevice({ ...DEVICE, source_aliases: [duplicate, { ...duplicate }] }), null);
  assert.equal(
    parseDevice({
      ...DEVICE,
      source_aliases: Array.from({ length: 33 }, (_, index) => ({
        source: 'librenms',
        native_id: String(index),
      })),
    }),
    null,
  );
  assert.ok(
    parseDevice({
      ...DEVICE,
      source_aliases: [duplicate, { source: 'netbox', native_id: '1' }],
    }),
  );
});

test('enforces the published pagination bounds without inventing page fullness rules', () => {
  assert.equal(parseDeviceList({ ...LIST, page: 0 }), null);
  assert.equal(parseDeviceList({ ...LIST, page_size: 0 }), null);
  assert.equal(parseDeviceList({ ...LIST, page_size: 101 }), null);
  assert.equal(parseDeviceList({ ...LIST, total: -1 }), null);
  assert.ok(parseDeviceList({ ...LIST, page_size: 1, items: [DEVICE, DEVICE], total: 2 }));
  assert.ok(parseDeviceList({ ...LIST, total: 0 }));
  assert.ok(parseDeviceList({ ...LIST, page: 2, page_size: 50, total: 1 }));
  assert.ok(parseDeviceList({ ...LIST, items: [], page: 2, page_size: 50, total: 1 }));
});

test('parses only the documented error envelope', () => {
  assert.deepEqual(
    parseApiError({
      error: {
        code: 'SOURCE_UNAVAILABLE',
        message: 'Monitoring source is unavailable',
        correlation_id: 'corr-1',
      },
    }),
    {
      code: 'SOURCE_UNAVAILABLE',
      message: 'Monitoring source is unavailable',
      correlationId: 'corr-1',
    },
  );
  assert.equal(parseApiError({ detail: 'raw framework error' }), null);
  assert.equal(
    parseApiError({
      error: {
        code: 'source-unavailable',
        message: 'Monitoring source is unavailable',
        correlation_id: 'corr-1',
      },
    }),
    null,
  );
  assert.deepEqual(
    parseApiError({
      error: {
        code: 'SOURCE_UNAVAILABLE',
        message: '',
        correlation_id: 'corr-1',
      },
    }),
    {
      code: 'SOURCE_UNAVAILABLE',
      message: '',
      correlationId: 'corr-1',
    },
  );
  assert.equal(
    parseApiError({
      error: {
        code: 'SOURCE_UNAVAILABLE',
        message: 'Monitoring source is unavailable',
        correlation_id: 'c'.repeat(65),
        debug: 'must not cross the API boundary',
      },
    }),
    null,
  );
  assert.equal(
    parseApiError({
      error: {
        code: 'SOURCE_UNAVAILABLE',
        message: 'Monitoring source is unavailable',
        correlation_id: 'corr-1',
      },
      debug: true,
    }),
    null,
  );
});

test('parseAuthProviders accepts a valid provider state response', () => {
  assert.deepEqual(
    parseAuthProviders({
      providers: {
        microsoft: { configured: true },
        google: { configured: false },
      },
    }),
    {
      providers: {
        microsoft: { configured: true },
        google: { configured: false },
      },
    },
  );
});

test('parseAuthProviders rejects malformed provider state', () => {
  assert.equal(parseAuthProviders(null), null);
  assert.equal(parseAuthProviders({}), null);
  assert.equal(parseAuthProviders({ providers: {} }), null);
  assert.equal(
    parseAuthProviders({
      providers: {
        microsoft: { configured: true },
      },
    }),
    null,
  );
  assert.equal(
    parseAuthProviders({
      providers: {
        microsoft: { configured: 'yes' },
        google: { configured: false },
      },
    }),
    null,
  );
  assert.equal(
    parseAuthProviders({
      providers: {
        microsoft: { configured: true },
        google: { configured: false },
        extra: { configured: true },
      },
    }),
    null,
  );
});

test('parseSessionInfo accepts a valid session response', () => {
  assert.deepEqual(
    parseSessionInfo({
      authenticated: true,
      identity_id: 'microsoft:subject-1',
      provider: 'microsoft',
      email: 'ops@example.test',
      roles: ['operator'],
    }),
    {
      authenticated: true,
      identity_id: 'microsoft:subject-1',
      provider: 'microsoft',
      email: 'ops@example.test',
      roles: ['operator'],
    },
  );
});

test('parseSessionInfo rejects malformed session responses', () => {
  assert.equal(parseSessionInfo(null), null);
  assert.equal(parseSessionInfo({}), null);
  assert.equal(
    parseSessionInfo({
      authenticated: false,
      identity_id: 'microsoft:subject-1',
      provider: 'microsoft',
      email: null,
      roles: [],
    }),
    null,
  );
  assert.equal(
    parseSessionInfo({
      authenticated: true,
      identity_id: 'microsoft:subject-1',
      provider: 'microsoft',
      email: null,
      roles: 'operator',
    }),
    null,
  );
  assert.equal(
    parseSessionInfo({
      authenticated: true,
      identity_id: 'microsoft:subject-1',
      provider: 'microsoft',
      email: null,
      roles: [],
      extra: true,
    }),
    null,
  );
});
