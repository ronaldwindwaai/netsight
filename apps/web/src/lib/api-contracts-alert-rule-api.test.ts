import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseAlertRuleApproveRequest,
  parseAlertRuleDetailResponse,
  parseAlertRuleEvaluateRequest,
  parseAlertRuleEvaluateResponse,
  parseAlertRuleListResponse,
  parseAlertRuleUpdateRequest,
  parseMaintenanceWindowCreateRequest,
  parseMaintenanceWindowDetailResponse,
  parseMaintenanceWindowListResponse,
} from './api-contracts-alert-rule-api.ts';
import { parseAlertRuleDefinition } from './api-contracts-alert-rule.ts';
import { buildInstance, loadVectors } from './contract-vectors.ts';

const VECTORS = loadVectors();
const PARSERS = {
  alert_rule_definition: parseAlertRuleDefinition,
  alert_rule_list_response: parseAlertRuleListResponse,
  alert_rule_detail_response: parseAlertRuleDetailResponse,
  maintenance_window_list_response: parseMaintenanceWindowListResponse,
  maintenance_window_detail_response: parseMaintenanceWindowDetailResponse,
  alert_rule_update_request: parseAlertRuleUpdateRequest,
  alert_rule_approve_request: parseAlertRuleApproveRequest,
  maintenance_window_create_request: parseMaintenanceWindowCreateRequest,
  alert_rule_evaluate_request: parseAlertRuleEvaluateRequest,
  alert_rule_evaluate_response: parseAlertRuleEvaluateResponse,
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

test('every alert-rule API entity in the shared vectors has a parser', () => {
  const entities = Object.keys(VECTORS).filter((name) =>
    /^(alert_rule_(definition|list|detail|update|approve|evaluate)|maintenance_window_(list|detail|create))/.test(
      name,
    ),
  );
  assert.deepEqual(entities.sort(), Object.keys(PARSERS).sort());
});

test('alert-rule API parsers fail closed on non-objects', () => {
  for (const parse of Object.values(PARSERS)) {
    for (const bad of [null, undefined, 'x', 1, [], true]) {
      assert.equal(parse(bad), null);
    }
  }
});

test('list parsers reject more rows than the server page cap', () => {
  const rules = VECTORS.alert_rule_list_response;
  const ruleInstance = buildInstance(rules, rules.cases[0]) as { rules: unknown[] };
  ruleInstance.rules = Array.from({ length: 101 }, () =>
    structuredClone((rules.base as { rules: unknown[] }).rules[0]),
  );
  assert.equal(parseAlertRuleListResponse(ruleInstance), null);
  const windows = VECTORS.maintenance_window_list_response;
  const windowInstance = buildInstance(windows, windows.cases[0]) as { windows: unknown[] };
  windowInstance.windows = Array.from({ length: 101 }, () =>
    structuredClone((windows.base as { windows: unknown[] }).windows[0]),
  );
  assert.equal(parseMaintenanceWindowListResponse(windowInstance), null);
});

test('a non-ok state never yields rows even if the payload carries them', () => {
  const block = VECTORS.alert_rule_list_response;
  for (const state of ['not-connected', 'unknown']) {
    const instance = buildInstance(block, block.cases[0]) as { state: string };
    instance.state = state;
    assert.equal(parseAlertRuleListResponse(instance), null);
  }
});

test('untrusted text is returned verbatim as data', () => {
  const block = VECTORS.alert_rule_detail_response;
  const input = buildInstance(block, block.cases[0]) as { rule: { name: string } };
  input.rule.name = `<img src=x onerror=alert(1)> ‮`;
  assert.equal(parseAlertRuleDetailResponse(input)?.rule?.name, input.rule.name);
});

test('parsed responses are detached from the input object', () => {
  const block = VECTORS.alert_rule_detail_response;
  const input = buildInstance(block, block.cases[0]) as { rule: { name: string } };
  const parsed = parseAlertRuleDetailResponse(input);
  assert.notEqual(parsed, null);
  input.rule.name = 'mutated';
  assert.equal(parsed?.rule?.name, 'After-hours large upload');
});

test('definition parser refuses lifecycle fields smuggled into a request', () => {
  const block = VECTORS.alert_rule_definition;
  const instance = buildInstance(block, block.cases[0]) as Record<string, unknown>;
  for (const [key, value] of [
    ['status', 'active'],
    ['approved_by', 'someone'],
    ['version', 9],
    ['id', 'alert-rule-5a6b7c8d-1e2f-4a3b-9c4d-5e6f7a8b9c0d'],
  ] as const) {
    assert.equal(parseAlertRuleDefinition({ ...instance, [key]: value }), null);
  }
});

test('definition labels cannot smuggle prototype keys', () => {
  const block = VECTORS.alert_rule_definition;
  const instance = buildInstance(block, block.cases[0]) as Record<string, unknown>;
  instance.labels = JSON.parse('{"__proto__": "x"}');
  assert.equal(parseAlertRuleDefinition(instance), null);
});
