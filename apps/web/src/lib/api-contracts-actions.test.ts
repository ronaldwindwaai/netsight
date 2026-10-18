import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseActionCheck,
  parseActionCreateRequest,
  parseActionDecisionRequest,
  parseActionDefinition,
  parseActionDetail,
  parseActionEvent,
  parseActionExecution,
  parseActionFromFindingRequest,
  parseActionList,
  parseActionReasonRequest,
  parseActionRequest,
  parseActionStatus,
  parseKillSwitchRequest,
} from './api-contracts-actions.ts';
import { buildInstance, loadVectorFile } from './contract-vectors.ts';

// The same vectors drive the JSON schema, OpenAPI and pydantic verdicts in the API test suite
// (apps/api/tests/test_actions_contracts.py): four-way agreement.
const VECTORS = loadVectorFile('actions.vectors.json');
const PARSERS = {
  action_check: parseActionCheck,
  action_execution: parseActionExecution,
  action_event: parseActionEvent,
  action_definition: parseActionDefinition,
  action_request: parseActionRequest,
  action_status: parseActionStatus,
  action_list: parseActionList,
  action_detail: parseActionDetail,
  action_create_request: parseActionCreateRequest,
  action_from_finding_request: parseActionFromFindingRequest,
  action_decision_request: parseActionDecisionRequest,
  action_reason_request: parseActionReasonRequest,
  action_kill_switch_request: parseKillSwitchRequest,
} as const;

test('every action vector entity has a parser', () => {
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

test('a request that carries a command-like field is refused, not trimmed', () => {
  const base = buildInstance(VECTORS.action_request, { name: 'base', valid: true }) as Record<string, unknown>;
  assert.equal(parseActionRequest({ ...base, command: 'reload' }), null);
  assert.equal(parseActionRequest({ ...base, params: { duration_minutes: 60, cmd: { run: 'ls' } } }), null);
});
