import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseDiagnosticLocationResult,
  parseDiagnosticPath,
  parseDiagnosticProbableCause,
  parseDiagnosticRecentChanges,
  parseDiagnosticSession,
  parseDiagnosticSessionListResponse,
  parseDiagnosticSessionResponse,
} from './api-contracts-diagnostic-session.ts';
import { buildInstance, loadDiagnosticSessionVectors } from './contract-vectors.ts';

// The same vectors drive the JSON schema, OpenAPI and pydantic verdicts in the API test suite.
const VECTORS = loadDiagnosticSessionVectors();
const PARSERS = {
  diagnostic_location_result: parseDiagnosticLocationResult,
  diagnostic_probable_cause: parseDiagnosticProbableCause,
  diagnostic_recent_changes: parseDiagnosticRecentChanges,
  diagnostic_path: parseDiagnosticPath,
  diagnostic_session: parseDiagnosticSession,
  diagnostic_session_response: parseDiagnosticSessionResponse,
  diagnostic_session_list_response: parseDiagnosticSessionListResponse,
} as const;

test('every session vector entity has a parser', () => {
  assert.deepEqual(Object.keys(VECTORS).sort(), Object.keys(PARSERS).sort());
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

test('session parsers fail closed on non-objects', () => {
  for (const parse of Object.values(PARSERS)) {
    assert.equal(parse(null), null);
    assert.equal(parse([]), null);
    assert.equal(parse('session'), null);
    assert.equal(parse(undefined), null);
  }
});

test('the parsed session is a detached copy', () => {
  const block = VECTORS.diagnostic_session;
  const instance = buildInstance(block, { name: 'x', valid: true }) as {
    probable_cause: { summary: string };
  };
  const parsed = parseDiagnosticSession(instance);
  assert.notEqual(parsed, null);
  instance.probable_cause.summary = 'mutated after parsing';
  assert.notEqual(parsed?.probable_cause.summary, 'mutated after parsing');
});
