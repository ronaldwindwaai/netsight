import assert from 'node:assert/strict';
import test from 'node:test';

import { BYTES_UNREPORTED, formatBytes, formatShare } from './format-bytes.ts';

test('an unreported volume is never shown as zero', () => {
  assert.equal(formatBytes(null), BYTES_UNREPORTED);
  assert.equal(formatBytes(undefined), BYTES_UNREPORTED);
  assert.equal(formatBytes(-1), BYTES_UNREPORTED);
  assert.equal(formatBytes(Number.NaN), BYTES_UNREPORTED);
  assert.notEqual(formatBytes(null), '0 B');
});

test('scales through the standard units', () => {
  assert.equal(formatBytes(0), '0 B');
  assert.equal(formatBytes(999), '999 B');
  assert.equal(formatBytes(1000), '1 KB');
  assert.equal(formatBytes(1_000_000), '1 MB');
  assert.equal(formatBytes(1_000_000_000), '1 GB');
  assert.equal(formatBytes(1_000_000_000_000), '1 TB');
});

test('rounds sub-100 values to one decimal for readability', () => {
  assert.equal(formatBytes(1234), '1.2 KB');
  assert.equal(formatBytes(12_345), '12.3 KB');
  assert.equal(formatBytes(123_456), '123 KB');
});

test('an unreported share is never shown as zero', () => {
  assert.equal(formatShare(null), 'share not reported');
  assert.equal(formatShare(undefined), 'share not reported');
  assert.equal(formatShare(Number.NaN), 'share not reported');
});

test('formats a share as a bounded percentage', () => {
  assert.equal(formatShare(0), '0%');
  assert.equal(formatShare(0.425), '42.5%');
  assert.equal(formatShare(1), '100%');
});