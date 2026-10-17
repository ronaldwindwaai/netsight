import assert from 'node:assert/strict';
import test from 'node:test';
import { parseConfigurationNodes, parseConfigurationVersions } from './api-contracts-configuration.ts';
const node = { id: 'config-node-11111111-1111-1111-1111-111111111111', name: '<script>alert(1)</script>', group: 'hq', model: 'ios', backup_status: 'success', last_attempt_at: '2026-10-17T10:00:00Z', backup_freshness: 'fresh' };
const read = { source: 'oxidized', state: 'ok', observed_at: '2026-10-17T10:00:00Z', items: [node], skipped: 0, truncated: false, page: 1, page_size: 50, total: 1, has_more: false };
test('configuration nodes preserve source text as data and accept the canonical response', () => {
  assert.equal(parseConfigurationNodes(read)?.items[0].name, node.name);
});
test('unknown is not an empty successful source read', () => {
  assert.ok(parseConfigurationNodes({ ...read, state: 'unknown', items: [], observed_at: null, total: null }));
  assert.equal(parseConfigurationNodes({ ...read, state: 'unknown' }), null);
  assert.equal(parseConfigurationNodes({ ...read, observed_at: null }), null);
});
test('extra secrets, duplicate IDs, inconsistent partial state and invalid freshness are refused', () => {
  for (const invalid of [
    { ...read, password: 'never-shipped' }, { ...read, items: [{ ...node, password: 'never-shipped' }] },
    { ...read, items: [node, node] }, { ...read, state: 'partial' },
    { ...read, items: [{ ...node, backup_status: 'failed' }] },
    { ...read, page: 0 }, { ...read, page_size: 0 }, { ...read, items: [{ ...node, last_attempt_at: 'never' }] },
  ]) assert.equal(parseConfigurationNodes(invalid), null);
});
test('version metadata accepts no author emails or messages', () => {
  const version = { id: 'a'.repeat(40), saved_at: '2026-10-17T10:00:00Z' };
  assert.ok(parseConfigurationVersions({ ...read, items: [version] }));
  assert.equal(parseConfigurationVersions({ ...read, items: [{ ...version, author: 'private' }] }), null);
});

import { readFileSync } from 'node:fs';
const vectors = JSON.parse(readFileSync(new URL('../../../../contracts/test-vectors/configuration.vectors.json', import.meta.url), 'utf8')) as {name: string; target: string; data: unknown; valid: boolean}[];
for (const vector of vectors) test(`shared configuration vector: ${vector.name}`, () => {
  const parse = vector.target === 'nodes' ? parseConfigurationNodes : parseConfigurationVersions;
  assert.equal(parse(vector.data) !== null, vector.valid);
});
