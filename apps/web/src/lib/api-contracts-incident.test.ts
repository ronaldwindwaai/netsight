import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseIncident,
  parseIncidentResolution,
  parseIncidentTimelineEvent,
} from './api-contracts-incident.ts';
import { buildInstance, loadVectors } from './contract-vectors.ts';

const VECTORS = loadVectors();
const PARSERS = {
  incident: parseIncident,
  incident_resolution: parseIncidentResolution,
  incident_timeline_event: parseIncidentTimelineEvent,
} as const;

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

test('incident parsers fail closed on non-objects', () => {
  for (const parse of Object.values(PARSERS)) {
    for (const bad of [null, undefined, 'x', 1, [], true]) {
      assert.equal(parse(bad), null);
    }
  }
});

test('parsed incident is detached from the input object', () => {
  const block = VECTORS.incident;
  const input = buildInstance(block, block.cases[2]) as { evidence_ids: string[] };
  const parsed = parseIncident(input);
  assert.notEqual(parsed, null);
  input.evidence_ids.push('mutated');
  assert.deepEqual(parsed?.evidence_ids, ['ev-1', 'ev-2']);
});
