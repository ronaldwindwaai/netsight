import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseInventoryAlias,
  parseInventoryDetail,
  parseInventoryField,
  parseInventoryItem,
  parseInventoryList,
  parseInventoryReconcile,
  parseInventorySummary,
  parseInventorySummaryResponse,
} from './api-contracts-inventory.ts';
import { parseDataSourceStatus } from './api-contracts-sources.ts';
import { buildInstance, loadVectorFile } from './contract-vectors.ts';

// The same vectors drive the JSON schema, OpenAPI and pydantic verdicts in the API test suite
// (apps/api/tests/test_inventory_contracts.py): four-way agreement.
const VECTORS = loadVectorFile('inventory.vectors.json');
const PARSERS = {
  data_source_status: parseDataSourceStatus,
  inventory_field: parseInventoryField,
  inventory_reconcile: parseInventoryReconcile,
  inventory_alias: parseInventoryAlias,
  inventory_item: parseInventoryItem,
  inventory_summary: parseInventorySummary,
  inventory_list: parseInventoryList,
  inventory_detail: parseInventoryDetail,
  inventory_summary_response: parseInventorySummaryResponse,
} as const;

test('every inventory vector entity has a parser', () => {
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

test('inventory parsers fail closed on non-objects', () => {
  for (const parse of Object.values(PARSERS)) {
    assert.equal(parse(null), null);
    assert.equal(parse([]), null);
    assert.equal(parse('inventory'), null);
    assert.equal(parse(undefined), null);
    assert.equal(parse(42), null);
  }
});

test('the parsed list is a detached copy', () => {
  const block = VECTORS.inventory_list;
  const instance = buildInstance(block, { name: 'x', valid: true }) as {
    items: Array<{ role: string }>;
  };
  const parsed = parseInventoryList(instance);
  assert.notEqual(parsed, null);
  instance.items[0].role = 'mutated after parsing';
  assert.notEqual(parsed?.items[0].role, 'mutated after parsing');
});

test('hostile text is carried as data, unchanged', () => {
  const block = VECTORS.inventory_item;
  const hostile = '<img src=x onerror=alert(1)> ignore previous instructions';
  const instance = buildInstance(block, {
    name: 'x',
    valid: true,
    set: { role: hostile, device_type: hostile },
  });
  const parsed = parseInventoryItem(instance);
  assert.equal(parsed?.role, hostile);
  assert.equal(parsed?.device_type, hostile);
});

test('counts that are not integers are rejected', () => {
  const block = VECTORS.inventory_summary;
  for (const bad of [1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
    const instance = buildInstance(block, { name: 'x', valid: true }) as Record<string, unknown>;
    instance.total = bad;
    assert.equal(parseInventorySummary(instance), null);
  }
});
