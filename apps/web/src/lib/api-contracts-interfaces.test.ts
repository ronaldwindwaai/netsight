import assert from 'node:assert/strict';
import test from 'node:test';

import { parseInterface, parseInterfaceList } from './api-contracts.ts';

const INTERFACE = {
  id: 'interface-3f2b1a90-5c4d-4e6f-8a1b-2c3d4e5f6a7b',
  device_id: 'device-dc425b99-786e-50f0-82dc-ebe2d0aa0e38',
  index: 24,
  name: 'GigabitEthernet0/1',
  description: 'Uplink to core',
  alias: 'uplink-core',
  hardware_type: 'ethernetCsmacd',
  mac_address: null,
  admin_status: 'up',
  oper_status: 'up',
  status: 'healthy',
  speed_bps: 1000000000,
  source_aliases: [{ source: 'librenms', native_id: '2' }],
  freshness: { state: 'fresh', observed_at: '2026-10-05T08:00:00Z', source: 'librenms' },
};

test('parseInterface accepts a canonical interface', () => {
  assert.deepEqual(parseInterface(INTERFACE), INTERFACE);
});

test('parseInterface accepts the minimal required shape', () => {
  const minimal = {
    id: INTERFACE.id,
    device_id: INTERFACE.device_id,
    name: 'Gi0/2',
    admin_status: 'down',
    oper_status: 'down',
    status: 'maintenance',
    source_aliases: [{ source: 'librenms', native_id: '3' }],
    freshness: { state: 'fresh', observed_at: null, source: 'librenms' },
  };

  assert.deepEqual(parseInterface(minimal), {
    ...minimal,
    index: null,
    description: null,
    alias: null,
    hardware_type: null,
    mac_address: null,
    speed_bps: null,
  });
});

test('parseInterface rejects an unknown link state instead of guessing', () => {
  assert.equal(parseInterface({ ...INTERFACE, oper_status: 'probably-up' }), null);
  assert.equal(parseInterface({ ...INTERFACE, admin_status: 'enabled' }), null);
});

test('parseInterface rejects malformed identifiers and bounds', () => {
  assert.equal(parseInterface({ ...INTERFACE, id: 'port-2' }), null);
  assert.equal(parseInterface({ ...INTERFACE, device_id: 'not-a-device' }), null);
  assert.equal(parseInterface({ ...INTERFACE, name: '' }), null);
  assert.equal(parseInterface({ ...INTERFACE, index: -1 }), null);
  assert.equal(parseInterface({ ...INTERFACE, index: 1.5 }), null);
  assert.equal(parseInterface({ ...INTERFACE, speed_bps: -1 }), null);
  assert.equal(parseInterface({ ...INTERFACE, description: 'x'.repeat(256) }), null);
  assert.equal(parseInterface({ ...INTERFACE, status: 'invented' }), null);
});

test('parseInterface rejects unknown fields and non-string text', () => {
  assert.equal(parseInterface({ ...INTERFACE, extra: true }), null);
  assert.equal(parseInterface({ ...INTERFACE, alias: 42 }), null);
  assert.equal(parseInterface({ ...INTERFACE, hardware_type: {} }), null);
  assert.equal(parseInterface({ ...INTERFACE, source_aliases: [] }), null);
});

test('parseInterfaceList validates the envelope and every row', () => {
  const list = { items: [INTERFACE], total: 1, freshness: INTERFACE.freshness };
  assert.deepEqual(parseInterfaceList(list), list);

  // An empty inventory is a valid result, not an error.
  assert.deepEqual(parseInterfaceList({ items: [], total: 0, freshness: INTERFACE.freshness }), {
    items: [],
    total: 0,
    freshness: INTERFACE.freshness,
  });

  assert.equal(parseInterfaceList({ items: [INTERFACE], total: -1, freshness: INTERFACE.freshness }), null);
  assert.equal(parseInterfaceList({ items: [INTERFACE], total: 1 }), null);
  assert.equal(
    parseInterfaceList({ items: [{ ...INTERFACE, status: 'nope' }], total: 1, freshness: INTERFACE.freshness }),
    null,
  );
});