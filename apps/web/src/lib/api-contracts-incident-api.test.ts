import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseIncidentDetailResponse,
  parseIncidentListResponse,
  parseIncidentSummaryListResponse,
  parseIncidentTimelineResponse,
} from './api-contracts-incident-api.ts';
import { buildInstance, loadVectors } from './contract-vectors.ts';

const VECTORS = loadVectors();
const PARSERS = {
  incident_list_response: parseIncidentListResponse,
  incident_summary_list_response: parseIncidentSummaryListResponse,
  incident_detail_response: parseIncidentDetailResponse,
  incident_timeline_response: parseIncidentTimelineResponse,
} as const;

// The same vectors drive JSON Schema, OpenAPI and pydantic in
// apps/api/tests/test_incident_alert_contracts.py: all four must agree.
for (const [entity, parse] of Object.entries(PARSERS)) {
  const block = VECTORS[entity];
  for (const vector of block.cases) {
    test(`${entity}: ${vector.name}`, () => {
      const instance = buildInstance(block, vector);
      const parsed = parse(instance);
      if (vector.valid) {
        assert.notEqual(parsed, null);
        assert.deepEqual(parsed, instance);
      } else {
        assert.equal(parsed, null);
      }
    });
  }
}

test('incident envelope parsers fail closed on non-objects', () => {
  for (const parse of Object.values(PARSERS)) {
    for (const bad of [null, undefined, 'x', 1, [], true]) {
      assert.equal(parse(bad), null);
    }
  }
});

test('list parser rejects more rows than the server page cap', () => {
  const block = VECTORS.incident_list_response;
  const instance = buildInstance(block, block.cases[0]) as { incidents: unknown[] };
  instance.incidents = Array.from({ length: 101 }, () => structuredClone(block.base.incidents));
  assert.equal(parseIncidentListResponse(instance), null);
});

test('timeline parser rejects more rows than the server page cap', () => {
  const block = VECTORS.incident_timeline_response;
  const instance = buildInstance(block, block.cases[0]) as { events: unknown[] };
  const [event] = (block.base as { events: unknown[] }).events;
  instance.events = Array.from({ length: 501 }, () => structuredClone(event));
  assert.equal(parseIncidentTimelineResponse(instance), null);
});

test('parsed envelopes are detached from the input object', () => {
  const block = VECTORS.incident_detail_response;
  const input = buildInstance(block, block.cases[0]) as { incident: { title: string } };
  const parsed = parseIncidentDetailResponse(input);
  assert.notEqual(parsed, null);
  input.incident.title = 'mutated';
  assert.equal(parsed?.incident?.title, 'Perimeter outage');
});

test('untrusted text is returned verbatim as data', () => {
  const block = VECTORS.incident_detail_response;
  const input = buildInstance(block, block.cases[0]) as { incident: { title: string } };
  input.incident.title = `<img src=x onerror=alert(1)> ‮`;
  assert.equal(parseIncidentDetailResponse(input)?.incident?.title, input.incident.title);
});

test('summary rows carry no evidence, resolution or assignee identity', () => {
  const block = VECTORS.incident_summary_list_response;
  const instance = buildInstance(block, block.cases[1]) as { incidents: Record<string, unknown>[] };
  const parsed = parseIncidentSummaryListResponse(instance);
  assert.notEqual(parsed, null);
  const [row] = parsed?.incidents ?? [];
  assert.deepEqual(Object.keys(row).sort(), [
    'assigned',
    'created_at',
    'id',
    'resolved_at',
    'severity',
    'state',
    'title',
    'updated_at',
  ]);
  assert.equal(row.assigned, true);
});

test('summary parser never lets a full incident through as a summary', () => {
  const full = VECTORS.incident_list_response;
  const instance = buildInstance(full, full.cases[0]);
  assert.equal(parseIncidentSummaryListResponse(instance), null);
});
