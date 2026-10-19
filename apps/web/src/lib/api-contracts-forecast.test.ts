import assert from 'node:assert/strict';
import test from 'node:test';

import {
  NOTICE,
  dayNumber,
  overallState,
  parseForecastCrossing,
  parseForecastMethod,
  parseForecastPoint,
  parseForecastRecommendation,
  parseForecastResponse,
  parseForecastSeries,
  parseForecastThreshold,
  parseHistoryPoint,
} from './api-contracts-forecast.ts';
import { buildInstance, loadVectorFile } from './contract-vectors.ts';

// The same vectors drive the JSON schema, OpenAPI and pydantic verdicts in the API test suite
// (apps/api/tests/test_forecast_contracts.py): four-way agreement.
const VECTORS = loadVectorFile('forecast.vectors.json');
const PARSERS = {
  forecast_history_point: parseHistoryPoint,
  forecast_point: parseForecastPoint,
  forecast_method: parseForecastMethod,
  forecast_threshold: parseForecastThreshold,
  forecast_crossing: parseForecastCrossing,
  forecast_series: parseForecastSeries,
  forecast_recommendation: parseForecastRecommendation,
  forecast_response: parseForecastResponse,
} as const;

test('every forecast vector entity has a parser', () => {
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

test('the notice text is the one the API sends', () => {
  const base = VECTORS.forecast_response.base as { notice: string };
  assert.equal(base.notice, NOTICE);
});

test('a calendar day must exist', () => {
  assert.notEqual(dayNumber('2026-02-28'), null);
  assert.equal(dayNumber('2026-02-30'), null);
  assert.equal(dayNumber('2026-2-3'), null);
  assert.equal(dayNumber(20260228), null);
});

test('the overall state follows the series states', () => {
  assert.equal(overallState(['not-connected', 'ok']), 'ok');
  assert.equal(overallState(['not-connected', 'insufficient-data', 'unknown']), 'insufficient-data');
  assert.equal(overallState(['not-connected', 'unknown']), 'unknown');
  assert.equal(overallState(['not-connected', 'not-connected']), 'not-connected');
});
