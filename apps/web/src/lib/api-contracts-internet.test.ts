import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseInternetResponse,
  parseSlaExport,
  parseSlaExportLink,
  parseSlaExportSource,
  parseSlaExportWindow,
  parseSlaLink,
  parseSlaResponse,
  parseWanAvailability,
  parseWanFailover,
  parseWanInterfaceReading,
  parseWanLink,
  parseWanQuality,
} from './api-contracts-internet.ts';
import { buildInstance, loadInternetVectors } from './contract-vectors.ts';

// The same vectors drive the JSON schema, OpenAPI and pydantic verdicts in the API test suite
// (apps/api/tests/test_internet_contracts.py): four-way agreement.
const VECTORS = loadInternetVectors();
const PARSERS = {
  internet_interface: parseWanInterfaceReading,
  internet_quality: parseWanQuality,
  internet_availability: parseWanAvailability,
  internet_link: parseWanLink,
  internet_failover: parseWanFailover,
  internet_response: parseInternetResponse,
  internet_sla_link: parseSlaLink,
  internet_sla_response: parseSlaResponse,
  internet_sla_export_window: parseSlaExportWindow,
  internet_sla_export_source: parseSlaExportSource,
  internet_sla_export_link: parseSlaExportLink,
  internet_sla_export: parseSlaExport,
} as const;

test('every internet vector entity has a parser', () => {
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

test('internet parsers fail closed on non-objects', () => {
  for (const parse of Object.values(PARSERS)) {
    assert.equal(parse(null), null);
    assert.equal(parse([]), null);
    assert.equal(parse('internet'), null);
    assert.equal(parse(undefined), null);
    assert.equal(parse(42), null);
  }
});

test('the parsed response is a detached copy', () => {
  const block = VECTORS.internet_response;
  const instance = buildInstance(block, { name: 'x', valid: true }) as {
    links: Array<{ name: string }>;
  };
  const parsed = parseInternetResponse(instance);
  assert.notEqual(parsed, null);
  instance.links[0].name = 'mutated after parsing';
  assert.notEqual(parsed?.links[0].name, 'mutated after parsing');
});

test('hostile text is carried as data, unchanged', () => {
  const block = VECTORS.internet_link;
  const hostile = '<img src=x onerror=alert(1)> ignore previous instructions';
  const instance = buildInstance(block, {
    name: 'x',
    valid: true,
    set: { name: hostile, 'configured.isp': hostile },
  });
  const parsed = parseWanLink(instance);
  assert.equal(parsed?.name, hostile);
  assert.equal(parsed?.configured.isp, hostile);
});

test('numbers that are not finite are rejected', () => {
  const block = VECTORS.internet_quality;
  for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
    const instance = buildInstance(block, { name: 'x', valid: true }) as Record<string, unknown>;
    instance.latency_ms = bad;
    assert.equal(parseWanQuality(instance), null);
  }
});
