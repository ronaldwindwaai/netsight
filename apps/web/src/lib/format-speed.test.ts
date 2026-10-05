import assert from 'node:assert/strict';
import test from 'node:test';

import { formatSpeed, SPEED_UNREPORTED } from './format-speed.ts';

test('an unreported speed is never shown as zero', () => {
  assert.equal(formatSpeed(null), SPEED_UNREPORTED);
  assert.equal(formatSpeed(undefined), SPEED_UNREPORTED);
  assert.equal(formatSpeed(-1), SPEED_UNREPORTED);
  assert.equal(formatSpeed(Number.NaN), SPEED_UNREPORTED);
  assert.notEqual(formatSpeed(null), '0 bps');
});

test('scales through the standard units', () => {
  assert.equal(formatSpeed(0), '0 bps');
  assert.equal(formatSpeed(999), '999 bps');
  assert.equal(formatSpeed(1000), '1 Kbps');
  assert.equal(formatSpeed(1_000_000), '1 Mbps');
  assert.equal(formatSpeed(1_000_000_000), '1 Gbps');
  assert.equal(formatSpeed(10_000_000_000), '10 Gbps');
  assert.equal(formatSpeed(100_000_000_000), '100 Gbps');
  assert.equal(formatSpeed(1_000_000_000_000), '1 Tbps');
});

test('rounds sub-100 values to one decimal for readability', () => {
  assert.equal(formatSpeed(1_234), '1.2 Kbps');
  assert.equal(formatSpeed(12_345), '12.3 Kbps');
  assert.equal(formatSpeed(123_456), '123 Kbps');
});

test('does not run past the largest unit', () => {
  assert.equal(formatSpeed(1e15), '1000 Tbps');
});