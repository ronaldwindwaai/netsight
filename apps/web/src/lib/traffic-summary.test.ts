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

test('buckets flows without application metadata as unattributed', () => {
  const mix = applicationMix([
    flow({ application: null, bytes: 300 }),
    flow({ application: 'https', bytes: 100 }),
  ]);
  assert.deepEqual(mix, [
    { application: null, bytes: 300, share: 0.75 },
    { application: 'https', bytes: 100, share: 0.25 },
  ]);
});

test('shares are computed across every listed flow, not just attributed ones', () => {
  const mix = applicationMix([
    flow({ application: 'https', bytes: 100 }),
    flow({ application: null, bytes: 300 }),
  ]);
  const httpsShare = mix.find((entry) => entry.application === 'https')?.share;
  assert.equal(httpsShare, 0.25);
});

test('returns no mix when nothing carries bytes', () => {
  assert.deepEqual(applicationMix([]), []);
  assert.deepEqual(applicationMix([flow({ bytes: 0 })]), []);
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