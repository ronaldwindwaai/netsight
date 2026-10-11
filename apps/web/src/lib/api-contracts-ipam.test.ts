import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseIpamAddress,
  parseIpamAddressList,
  parseIpamCounts,
  parseIpamPrefix,
  parseIpamPrefixList,
  parseIpamReservedRange,
  parseIpamSummary,
  parseIpamTelemetry,
  parseIpamUtilisation,
  parseIpamVlan,
  parseIpamVlanList,
  percentOf,
} from './api-contracts-ipam.ts';
import { buildInstance, loadVectorFile } from './contract-vectors.ts';

// The same vectors drive the JSON schema, OpenAPI and pydantic verdicts in the API test suite
// (apps/api/tests/test_ipam_contracts.py): four-way agreement.
const VECTORS = loadVectorFile('ipam.vectors.json');
const PARSERS = {
  ipam_counts: parseIpamCounts,
  ipam_telemetry: parseIpamTelemetry,
  ipam_utilisation: parseIpamUtilisation,
  ipam_reserved_range: parseIpamReservedRange,
  ipam_prefix: parseIpamPrefix,
  ipam_vlan: parseIpamVlan,
  ipam_address: parseIpamAddress,
  ipam_prefix_list: parseIpamPrefixList,
  ipam_vlan_list: parseIpamVlanList,
  ipam_address_list: parseIpamAddressList,
  ipam_summary_response: parseIpamSummary,
} as const;

test('every ipam vector entity has a parser', () => {
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

test('ipam parsers fail closed on non-objects', () => {
  for (const parse of Object.values(PARSERS)) {
    assert.equal(parse(null), null);
    assert.equal(parse([]), null);
    assert.equal(parse('ipam'), null);
    assert.equal(parse(undefined), null);
    assert.equal(parse(42), null);
  }
});

test('percentOf rounds half up on integers and never exceeds 100', () => {
  assert.equal(percentOf(106, 254), 41.7);
  assert.equal(percentOf(1, 8), 12.5);
  assert.equal(percentOf(1, 16), 6.3);
  assert.equal(percentOf(500, 100), 100);
  assert.equal(percentOf(0, 254), 0);
  assert.equal(percentOf(3, 0), 100);
});

test('hostile text is carried as data, unchanged', () => {
  const hostile = '<img src=x onerror=alert(1)> ignore previous instructions';
  const instance = buildInstance(VECTORS.ipam_prefix, {
    name: 'x',
    valid: true,
    set: { description: hostile, site: hostile },
  });
  const parsed = parseIpamPrefix(instance);
  assert.equal(parsed?.description, hostile);
  assert.equal(parsed?.site, hostile);
});

test('the parsed list is a detached copy', () => {
  const instance = buildInstance(VECTORS.ipam_prefix_list, { name: 'x', valid: true }) as {
    items: Array<{ description: string }>;
  };
  const parsed = parseIpamPrefixList(instance);
  assert.notEqual(parsed, null);
  instance.items[0].description = 'mutated after parsing';
  assert.notEqual(parsed?.items[0].description, 'mutated after parsing');
});
