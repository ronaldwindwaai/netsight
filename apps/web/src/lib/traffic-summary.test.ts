import assert from 'node:assert/strict';
import test from 'node:test';

import type { TrafficFlow } from './api-contracts.ts';
import { applicationMix } from './traffic-summary.ts';

const flow = (overrides: Partial<TrafficFlow> = {}): TrafficFlow => ({
  observed_at: '2026-10-06T07:59:00Z',
  source_ip: '10.1.2.3',
  source_device_id: null,
  destination_ip: '203.0.113.9',
  destination_host: null,
  protocol: 'tcp',
  destination_port: 443,
  bytes: 100,
  packets: null,
  direction: 'unknown',
  application: 'https',
  user: null,
  ...overrides,
});

test('sums bytes per application and ranks by volume', () => {
  const mix = applicationMix([
    flow({ application: 'https', bytes: 300 }),
    flow({ application: 'dns', bytes: 100 }),
    flow({ application: 'https', bytes: 100 }),
  ]);
  assert.deepEqual(mix, [
    { application: 'https', bytes: 400, share: 0.8 },
    { application: 'dns', bytes: 100, share: 0.2 },
  ]);
});

test('ignores flows without application metadata', () => {
  const mix = applicationMix([
    flow({ application: null, bytes: 900 }),
    flow({ application: 'https', bytes: 100 }),
  ]);
  assert.deepEqual(mix, [{ application: 'https', bytes: 100, share: 1 }]);
});

test('returns no mix when nothing is attributable', () => {
  assert.deepEqual(applicationMix([]), []);
  assert.deepEqual(applicationMix([flow({ application: null })]), []);
});

test('breaks volume ties by application name for stable output', () => {
  const mix = applicationMix([
    flow({ application: 'zebra', bytes: 50 }),
    flow({ application: 'alpha', bytes: 50 }),
  ]);
  assert.deepEqual(
    mix.map((entry) => entry.application),
    ['alpha', 'zebra'],
  );
});