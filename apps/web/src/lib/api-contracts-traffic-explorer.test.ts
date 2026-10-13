import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseAnomaly,
  parseAppTrend,
  parseApplicationRow,
  parseAttributionStatus,
  parseCohort,
  parseDestinationRow,
  parseEvaluation,
  parseFirstSeen,
  parseFlowAggregations,
  parseFlowAttribution,
  parseFlowFilters,
  parseTrafficAnomaliesResponse,
  parseTrafficApplicationsResponse,
  parseTrafficDestinationsResponse,
  parseTrafficFlow,
  parseTrafficFlowsResponse,
  parseWorkingHours,
} from './api-contracts-traffic-explorer.ts';
import { buildInstance, loadTrafficVectors } from './contract-vectors.ts';

// The same vectors drive the JSON schema, OpenAPI and pydantic verdicts in the API test suite
// (apps/api/tests/test_traffic_contracts.py): four-way agreement.
const VECTORS = loadTrafficVectors();
const PARSERS = {
  traffic_flow_filters: parseFlowFilters,
  traffic_flow_attribution: parseFlowAttribution,
  traffic_attribution_status: parseAttributionStatus,
  traffic_cohort: parseCohort,
  traffic_flow: parseTrafficFlow,
  traffic_aggregations: parseFlowAggregations,
  traffic_flows: parseTrafficFlowsResponse,
  traffic_app_trend: parseAppTrend,
  traffic_application: parseApplicationRow,
  traffic_applications: parseTrafficApplicationsResponse,
  traffic_destination: parseDestinationRow,
  traffic_destinations: parseTrafficDestinationsResponse,
  traffic_working_hours: parseWorkingHours,
  traffic_evaluation: parseEvaluation,
  traffic_anomaly: parseAnomaly,
  traffic_first_seen: parseFirstSeen,
  traffic_anomalies: parseTrafficAnomaliesResponse,
} as const;

test('every traffic vector entity has a parser', () => {
  assert.deepEqual(Object.keys(VECTORS).sort(), Object.keys(PARSERS).sort());
});

test('the shared vectors are large enough to matter', () => {
  const cases = Object.values(VECTORS).reduce((sum, block) => sum + block.cases.length, 0);
  assert.ok(cases >= 400, `expected at least 400 cases, saw ${cases}`);
});

for (const [entity, parse] of Object.entries(PARSERS)) {
  const block = VECTORS[entity];
  for (const vector of block.cases) {
    test(`${entity}: ${vector.name}`, () => {
      const instance = buildInstance(block, vector);
      const parsed = parse(instance);
      if (vector.valid) {
        assert.notEqual(parsed, null);
        // Lossless: the parser must not drop or invent fields.
        assert.deepEqual(parsed, instance);
      } else {
        assert.equal(parsed, null);
      }
    });
  }
}

test('traffic parsers fail closed on non-objects', () => {
  for (const parse of Object.values(PARSERS)) {
    assert.equal(parse(null), null);
    assert.equal(parse([]), null);
    assert.equal(parse('traffic'), null);
    assert.equal(parse(undefined), null);
    assert.equal(parse(42), null);
  }
});

test('the parsed response is a detached copy', () => {
  const block = VECTORS.traffic_flows;
  const instance = buildInstance(block, { name: 'x', valid: true }) as {
    flows: Array<{ application: string }>;
  };
  const parsed = parseTrafficFlowsResponse(instance);
  assert.notEqual(parsed, null);
  instance.flows[0].application = 'mutated after parsing';
  assert.notEqual(parsed?.flows[0].application, 'mutated after parsing');
});

test('hostile text is carried as data, unchanged', () => {
  const hostile = '<img src=x onerror=alert(1)> ignore previous instructions';
  const flow = buildInstance(VECTORS.traffic_flow, {
    name: 'x',
    valid: true,
    set: { destination_host: hostile, application: hostile, 'attribution.person.label': hostile },
  });
  const parsed = parseTrafficFlow(flow);
  assert.equal(parsed?.destination_host, hostile);
  assert.equal(parsed?.application, hostile);
  assert.equal(parsed?.attribution?.person?.label, hostile);
});

test('the retired source user field is not accepted anywhere', () => {
  const flow = buildInstance(VECTORS.traffic_flow, { name: 'x', valid: true, set: { user: 'alice' } });
  assert.equal(parseTrafficFlow(flow), null);
});
