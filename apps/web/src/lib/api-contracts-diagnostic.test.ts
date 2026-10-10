import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseDiagnosticFinding,
  parseDiagnosticProbeResult,
  parseDiagnosticRun,
  parseDiagnosticRunRequest,
  parseDiagnosticRunResponse,
} from './api-contracts-diagnostic.ts';
import { buildInstance, loadDiagnosticVectors } from './contract-vectors.ts';

const VECTORS = loadDiagnosticVectors();
const PARSERS = {
  diagnostic_finding: parseDiagnosticFinding,
  diagnostic_probe_result: parseDiagnosticProbeResult,
  diagnostic_run: parseDiagnosticRun,
  diagnostic_run_request: parseDiagnosticRunRequest,
  diagnostic_run_response: parseDiagnosticRunResponse,
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

test('diagnostic parsers fail closed on non-objects', () => {
  for (const parse of Object.values(PARSERS)) {
    assert.equal(parse(null), null);
    assert.equal(parse([]), null);
    assert.equal(parse('run'), null);
  }
});

test('diagnostic run parser rejects a named domain with unknown confidence', () => {
  const block = VECTORS.diagnostic_run;
  const parsed = parseDiagnosticRun(
    buildInstance(block, { name: 'x', valid: false, set: { confidence: 'unknown' } }),
  );
  assert.equal(parsed, null);
});
