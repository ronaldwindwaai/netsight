import assert from 'node:assert/strict';
import test from 'node:test';

import type { SecurityEvent } from './api-contracts-security.ts';
import { severityCounts } from './security-summary.ts';

const event = (severity: SecurityEvent['severity']): SecurityEvent => ({
  id: `e-${severity}`,
  observed_at: '2026-10-06T07:55:00Z',
  source: 'wazuh',
  severity,
  category: null,
  signature: 'sig',
  source_ip: null,
  destination_ip: null,
  device_id: null,
});

test('returns zero for every severity when there are no events', () => {
  assert.deepEqual(severityCounts([]), { info: 0, low: 0, medium: 0, high: 0, critical: 0 });
});

test('counts events per severity', () => {
  const counts = severityCounts([
    event('critical'),
    event('high'),
    event('high'),
    event('info'),
  ]);
  assert.deepEqual(counts, { info: 1, low: 0, medium: 0, high: 2, critical: 1 });
});
