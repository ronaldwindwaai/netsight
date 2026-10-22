import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { formatRelativeTime } from './relative-time.ts';

const NOW = Date.parse('2026-10-21T12:00:00Z');
const ago = (seconds: number) => new Date(NOW - seconds * 1000).toISOString();

describe('formatRelativeTime', () => {
  it('says "just now" under a minute', () => {
    assert.equal(formatRelativeTime(ago(5), NOW), 'just now');
    assert.equal(formatRelativeTime(ago(59), NOW), 'just now');
  });

  it('uses minutes, hours and days', () => {
    assert.equal(formatRelativeTime(ago(60), NOW), '1 min ago');
    assert.equal(formatRelativeTime(ago(59 * 60), NOW), '59 min ago');
    assert.equal(formatRelativeTime(ago(3600), NOW), '1 h ago');
    assert.equal(formatRelativeTime(ago(23 * 3600 + 1800), NOW), '23 h ago');
    assert.equal(formatRelativeTime(ago(2 * 86400), NOW), '2 d ago');
  });

  it('falls back to the date after 30 days', () => {
    assert.equal(formatRelativeTime(ago(40 * 86400), NOW), '2026-09-11');
  });

  it('treats a small future skew as now and a large one as in the future', () => {
    assert.equal(formatRelativeTime(ago(-20), NOW), 'just now');
    assert.equal(formatRelativeTime(ago(-3600), NOW), 'in 1 h');
  });

  it('never echoes an unparseable value', () => {
    assert.equal(formatRelativeTime('garbage', NOW), 'Unknown time');
  });
});
