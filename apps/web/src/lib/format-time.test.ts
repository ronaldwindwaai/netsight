import assert from 'node:assert/strict';
import test from 'node:test';

import { formatUtcTimestamp } from './format-time.ts';

test('formats an RFC 3339 instant as a fixed UTC string', () => {
  assert.equal(formatUtcTimestamp('2026-10-06T07:55:09Z'), '2026-10-06 07:55:09 UTC');
});

test('normalises offsets to UTC', () => {
  assert.equal(formatUtcTimestamp('2026-10-06T09:55:09+02:00'), '2026-10-06 07:55:09 UTC');
});

test('drops fractional seconds', () => {
  assert.equal(formatUtcTimestamp('2026-10-06T07:55:09.987Z'), '2026-10-06 07:55:09 UTC');
});

test('never echoes an unparseable value', () => {
  assert.equal(formatUtcTimestamp('<img src=x onerror=alert(1)>'), 'Unknown time');
  assert.equal(formatUtcTimestamp(''), 'Unknown time');
});
