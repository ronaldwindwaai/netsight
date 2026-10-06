import assert from 'node:assert/strict';
import test from 'node:test';

import { parseTopologyResponse } from './api-contracts.ts';

const DEVICE_A = 'device-a7f3d9e1-1c2b-4a8e-9f0d-5b6c7d8e9f01';
const DEVICE_B = 'device-b1c2d3e4-5f6a-4b7c-8d9e-0a1b2c3d4e56';

const UNKNOWN_FRESHNESS = {
  state: 'unknown',
  observed_at: null,
  source: null,
};

const NOT_CONNECTED = {
  state: 'not-connected',
  nodes: [],
  edges: [],
  freshness: UNKNOWN_FRESHNESS,
};

test('parseTopologyResponse accepts explicit not-connected state', () => {
  assert.deepEqual(parseTopologyResponse(NOT_CONNECTED), NOT_CONNECTED);
});

test('parseTopologyResponse accepts explicit unknown state', () => {
  const payload = { ...NOT_CONNECTED, state: 'unknown' };
  assert.deepEqual(parseTopologyResponse(payload), payload);
});

test('parseTopologyResponse accepts a valid graph', () => {
  const payload = {
    state: 'ok',
    nodes: [
      { device_id: DEVICE_A, name: 'core-sw-01' },
      { device_id: DEVICE_B, name: 'edge-sw-02' },
    ],
    edges: [
      {
        source_device_id: DEVICE_A,
        target_device_id: DEVICE_B,
        source: 'lldp',
        observed_at: '2026-10-06T08:00:00Z',
      },
    ],
    freshness: {
      state: 'fresh',
      observed_at: '2026-10-06T08:00:00Z',
      source: 'netbox',
    },
  };
  assert.deepEqual(parseTopologyResponse(payload), payload);
});

test('parseTopologyResponse accepts edge without observed_at', () => {
  const payload = {
    state: 'ok',
    nodes: [{ device_id: DEVICE_A, name: 'core-sw-01' }],
    edges: [],
    freshness: {
      state: 'stale',
      observed_at: '2026-10-06T08:00:00Z',
      source: 'manual',
    },
  };
  const parsed = parseTopologyResponse(payload);
  assert.ok(parsed);
  assert.equal(parsed.state, 'ok');
});

test('parseTopologyResponse rejects unknown keys', () => {
  assert.equal(parseTopologyResponse({ ...NOT_CONNECTED, extra: 1 }), null);
});

test('parseTopologyResponse accepts an explicitly empty connected graph', () => {
  // A configured source with zero cables: ok + empty is honest, not a failure.
  const payload = {
    ...NOT_CONNECTED,
    state: 'ok',
    freshness: {
      state: 'fresh',
      observed_at: '2026-10-06T08:00:00Z',
      source: 'netbox',
    },
  };
  assert.deepEqual(parseTopologyResponse(payload), payload);
});

test('parseTopologyResponse rejects not-connected state carrying data', () => {
  assert.equal(
    parseTopologyResponse({
      ...NOT_CONNECTED,
      nodes: [{ device_id: DEVICE_A, name: 'core-sw-01' }],
    }),
    null,
  );
});

test('parseTopologyResponse rejects a node without an explicit name key', () => {
  // name is required (nullable) so a missing key never renders as blank.
  assert.equal(
    parseTopologyResponse({
      ...NOT_CONNECTED,
      state: 'ok',
      nodes: [{ device_id: DEVICE_A }],
    }),
    null,
  );
});

test('parseTopologyResponse rejects non-canonical node ids', () => {
  assert.equal(
    parseTopologyResponse({
      ...NOT_CONNECTED,
      state: 'ok',
      nodes: [{ device_id: 'librenms:1', name: null }],
    }),
    null,
  );
});

test('parseTopologyResponse rejects edges referencing unknown nodes', () => {
  assert.equal(
    parseTopologyResponse({
      state: 'ok',
      nodes: [{ device_id: DEVICE_A, name: 'core-sw-01' }],
      edges: [
        {
          source_device_id: DEVICE_A,
          target_device_id: DEVICE_B,
          source: 'lldp',
          observed_at: null,
        },
      ],
      freshness: {
        state: 'fresh',
        observed_at: '2026-10-06T08:00:00Z',
        source: 'lldp',
      },
    }),
    null,
  );
});

test('parseTopologyResponse rejects unknown edge sources', () => {
  assert.equal(
    parseTopologyResponse({
      state: 'ok',
      nodes: [{ device_id: DEVICE_A, name: 'core-sw-01' }],
      edges: [
        {
          source_device_id: DEVICE_A,
          target_device_id: DEVICE_A,
          source: 'guess',
          observed_at: null,
        },
      ],
      freshness: {
        state: 'fresh',
        observed_at: '2026-10-06T08:00:00Z',
        source: 'lldp',
      },
    }),
    null,
  );
});
