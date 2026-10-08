import assert from 'node:assert/strict';
import test from 'node:test';

import { parseAlertRule, parseMaintenanceWindow } from './api-contracts-alert-rule.ts';
import { buildInstance, loadVectors } from './contract-vectors.ts';

const VECTORS = loadVectors();
const PARSERS = {
  alert_rule: parseAlertRule,
  maintenance_window: parseMaintenanceWindow,
} as const;

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

test('alert rule and window parsers fail closed on non-objects', () => {
  for (const parse of Object.values(PARSERS)) {
    for (const bad of [null, undefined, 'x', 1, [], true]) {
      assert.equal(parse(bad), null);
    }
  }
});

test('labels cannot smuggle prototype keys', () => {
  const block = VECTORS.alert_rule;
  const instance = buildInstance(block, block.cases[0]) as Record<string, unknown>;
  instance.labels = JSON.parse('{"__proto__": "x"}');
  assert.equal(parseAlertRule(instance), null);
});
