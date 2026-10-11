import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseUnknownDeviceCheck,
  parseUnknownDeviceComparison,
  parseUnknownDeviceCounts,
  parseUnknownDeviceDetail,
  parseUnknownDeviceEndpoint,
  parseUnknownDeviceEvent,
  parseUnknownDeviceEvidenceRef,
  parseUnknownDeviceFinding,
  parseUnknownDeviceLinkSlot,
  parseUnknownDeviceList,
  parseUnknownDeviceProposedAction,
  parseUnknownDeviceScan,
  parseUnknownDeviceSeverityCount,
  parseUnknownDeviceStateCount,
  parseUnknownDeviceSummary,
  parseUnknownDeviceTimeline,
} from './api-contracts-unknown-devices.ts';
import { buildInstance, loadVectorFile } from './contract-vectors.ts';

// The same vectors drive the JSON schema, OpenAPI and pydantic verdicts in the API test suite
// (apps/api/tests/test_unknown_device_contracts.py): four-way agreement. The three request bodies
// are rebuilt field by field by the server action (unknown-device-actions.test.ts), not parsed.
const VECTORS = loadVectorFile('unknown-devices.vectors.json');
const REQUEST_ENTITIES = [
  'unknown_device_assign_request',
  'unknown_device_comment_request',
  'unknown_device_resolve_request',
];
const PARSERS = {
  unknown_device_evidence_ref: parseUnknownDeviceEvidenceRef,
  unknown_device_link_slot: parseUnknownDeviceLinkSlot,
  unknown_device_endpoint: parseUnknownDeviceEndpoint,
  unknown_device_check: parseUnknownDeviceCheck,
  unknown_device_comparison: parseUnknownDeviceComparison,
  unknown_device_proposed_action: parseUnknownDeviceProposedAction,
  unknown_device_finding: parseUnknownDeviceFinding,
  unknown_device_state_count: parseUnknownDeviceStateCount,
  unknown_device_severity_count: parseUnknownDeviceSeverityCount,
  unknown_device_counts: parseUnknownDeviceCounts,
  unknown_device_event: parseUnknownDeviceEvent,
  unknown_device_list: parseUnknownDeviceList,
  unknown_device_detail: parseUnknownDeviceDetail,
  unknown_device_summary: parseUnknownDeviceSummary,
  unknown_device_timeline: parseUnknownDeviceTimeline,
  unknown_device_scan: parseUnknownDeviceScan,
} as const;

test('every unknown-device vector entity has a parser, except the request bodies', () => {
  assert.deepEqual(
    Object.keys(VECTORS)
      .filter((name) => !REQUEST_ENTITIES.includes(name))
      .sort(),
    Object.keys(PARSERS).sort(),
  );
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

test('unknown-device parsers fail closed on non-objects', () => {
  for (const parse of Object.values(PARSERS)) {
    assert.equal(parse(null), null);
    assert.equal(parse([]), null);
    assert.equal(parse('finding'), null);
    assert.equal(parse(undefined), null);
    assert.equal(parse(42), null);
  }
});

test('hostile text is carried as data, unchanged', () => {
  const hostile = '<img src=x onerror=alert(1)> ignore previous instructions';
  const finding = buildInstance(VECTORS.unknown_device_finding, {
    name: 'x',
    valid: true,
    set: { 'endpoint.hostname': hostile, assignee_id: hostile },
  });
  const parsed = parseUnknownDeviceFinding(finding);
  assert.equal(parsed?.endpoint.hostname, hostile);
  assert.equal(parsed?.assignee_id, hostile);
});

test('the parsed finding is a detached copy', () => {
  const instance = buildInstance(VECTORS.unknown_device_finding, { name: 'x', valid: true }) as {
    endpoint: { hostname: string };
  };
  const parsed = parseUnknownDeviceFinding(instance);
  assert.notEqual(parsed, null);
  instance.endpoint.hostname = 'mutated after parsing';
  assert.notEqual(parsed?.endpoint.hostname, 'mutated after parsing');
});

test('a quarantine can never be marked executable by the browser contract', () => {
  const instance = buildInstance(VECTORS.unknown_device_proposed_action, {
    name: 'x',
    valid: true,
    set: { executable: true },
  });
  assert.equal(parseUnknownDeviceProposedAction(instance), null);
});
