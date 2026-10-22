import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseCopilotAnswer,
  parseCopilotAsk,
  parseCopilotAskRequest,
  parseCopilotClaim,
  parseCopilotEvidence,
  parseCopilotStatus,
  parseCopilotToolCall,
} from './api-contracts-copilot.ts';
import { buildInstance, loadVectorFile } from './contract-vectors.ts';

// The same vectors drive the JSON schema, OpenAPI and pydantic verdicts in the API test suite
// (apps/api/tests/test_copilot_contracts.py): four-way agreement.
const VECTORS = loadVectorFile('copilot.vectors.json');
const PARSERS = {
  copilot_evidence: parseCopilotEvidence,
  copilot_tool_call: parseCopilotToolCall,
  copilot_claim: parseCopilotClaim,
  copilot_answer: parseCopilotAnswer,
  copilot_ask_request: parseCopilotAskRequest,
  copilot_ask: parseCopilotAsk,
  copilot_status: parseCopilotStatus,
} as const;

test('every copilot vector entity has a parser', () => {
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
