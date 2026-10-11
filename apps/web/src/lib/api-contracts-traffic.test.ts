import assert from 'node:assert/strict';
import test from 'node:test';

import { parseTrafficTopResponse } from './api-contracts.ts';


const UNKNOWN_FRESHNESS = {
  state: 'unknown',
  observed_at: null,
  source: null,
};

const FRESH_FRESHNESS = {
  state: 'fresh',
  observed_at: '2026-10-06T08:00:00Z',
  source: 'clickhouse',
};

const TIME_RANGE = {
  from: '2026-10-05T08:00:00Z',
  to: '2026-10-06T08:00:00Z',
  preset: '24h',
};

/** Canonical aggregate row: always carries every contract key. */
const item = (overrides: Record<string, unknown> = {}) => ({
  rank: 1,
  subject_kind: 'ip',
  subject_id: null,
  label: '10.1.2.3',
  bytes: 104857600,
  packets: 820000,
  share: 0.42,
  ...overrides,
});

const NOT_CONNECTED_TOP = {
  state: 'not-connected',
  dimension: 'talkers',
  time_range: TIME_RANGE,
  items: [],
  freshness: UNKNOWN_FRESHNESS,
};

test('parseTrafficTopResponse accepts explicit not-connected state', () => {
  assert.deepEqual(parseTrafficTopResponse(NOT_CONNECTED_TOP), NOT_CONNECTED_TOP);
});

test('parseTrafficTopResponse accepts a valid ok payload', () => {
  const payload = {
    state: 'ok',
    dimension: 'destinations',
    time_range: TIME_RANGE,
    items: [
      item(),
      item({ rank: 2, subject_kind: 'domain', label: 'cdn.example.net', packets: null }),
      item({ rank: 3, subject_kind: 'user', label: 'alice', share: null }),
    ],
    freshness: FRESH_FRESHNESS,
  };
  assert.deepEqual(parseTrafficTopResponse(payload), payload);
});

test('parseTrafficTopResponse passes source labels through as untrusted data', () => {
  const xssLabel = "<script>alert('xss')</script>";
  const payload = {
    ...NOT_CONNECTED_TOP,
    state: 'ok',
    items: [item({ subject_kind: 'user', label: xssLabel })],
    freshness: FRESH_FRESHNESS,
  };
  const parsed = parseTrafficTopResponse(payload);
  assert.ok(parsed);
  assert.equal(parsed.items[0].label, xssLabel);
});

test('parseTrafficTopResponse rejects items on a non-ok state', () => {
  for (const state of ['not-connected', 'unknown']) {
    const payload = { ...NOT_CONNECTED_TOP, state, items: [item()] };
    assert.equal(parseTrafficTopResponse(payload), null, state);
  }
});

test('parseTrafficTopResponse rejects an unknown state or dimension', () => {
  assert.equal(parseTrafficTopResponse({ ...NOT_CONNECTED_TOP, state: 'degraded' }), null);
  assert.equal(
    parseTrafficTopResponse({ ...NOT_CONNECTED_TOP, dimension: 'applications' }),
    null,
  );
});

test('parseTrafficTopResponse rejects an unknown preset', () => {
  const payload = {
    ...NOT_CONNECTED_TOP,
    time_range: { ...TIME_RANGE, preset: '12h' },
  };
  assert.equal(parseTrafficTopResponse(payload), null);
});

test('parseTrafficTopResponse rejects a non-RFC3339 window bound', () => {
  const payload = {
    ...NOT_CONNECTED_TOP,
    time_range: { ...TIME_RANGE, from: '05/10/2026' },
  };
  assert.equal(parseTrafficTopResponse(payload), null);
});

test('parseTrafficTopResponse rejects out-of-bounds item fields', () => {
  const rejects: Array<Record<string, unknown>> = [
    { rank: 0 },
    { rank: 1001 },
    { rank: 1.5 },
    { subject_kind: 'process' },
    { label: '' },
    { label: 42 },
    { subject_id: 17 },
    { bytes: -1 },
    { bytes: 1.5 },
    { packets: -1 },
    { share: 1.5 },
    { share: -0.1 },
  ];
  for (const overrides of rejects) {
    const payload = { ...NOT_CONNECTED_TOP, state: 'ok', items: [item(overrides)] };
    assert.equal(parseTrafficTopResponse(payload), null, JSON.stringify(overrides));
  }
});

test('parseTrafficTopResponse rejects missing or extra keys', () => {
  const missing = item();
  delete (missing as Record<string, unknown>).label;
  assert.equal(
    parseTrafficTopResponse({ ...NOT_CONNECTED_TOP, state: 'ok', items: [missing] }),
    null,
  );

  const extra = { ...NOT_CONNECTED_TOP, fabricated: true } as Record<string, unknown>;
  assert.equal(parseTrafficTopResponse(extra), null);
});
