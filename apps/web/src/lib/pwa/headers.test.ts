import assert from 'node:assert/strict';
import test from 'node:test';

import config from '../../../next.config.mjs';

async function headersFor(source: string): Promise<Record<string, string>> {
  const rules = (await config.headers?.()) ?? [];
  const rule = rules.find((candidate: { source: string }) => candidate.source === source);
  assert.ok(rule, `no header rule for ${source}`);
  return Object.fromEntries(rule.headers.map((h: { key: string; value: string }) => [h.key.toLowerCase(), h.value]));
}

test('the service worker script is never HTTP-cached and is locked to its own origin', async () => {
  const h = await headersFor('/sw.js');
  assert.match(h['cache-control'], /no-cache|max-age=0/);
  assert.match(h['content-type'], /javascript/);
  assert.equal(h['x-content-type-options'], 'nosniff');
  assert.match(h['content-security-policy'], /default-src 'self'/);
  assert.equal(h['service-worker-allowed'], '/');
});

test('the offline page is revalidated and sandboxed from scripts and remote content', async () => {
  const h = await headersFor('/offline.html');
  assert.match(h['cache-control'], /no-cache|max-age=0/);
  assert.match(h['content-security-policy'], /default-src 'none'/);
  assert.doesNotMatch(h['content-security-policy'], /script-src/);
});

test('every route gets baseline anti-framing, sniffing, referrer and permission headers', async () => {
  const h = await headersFor('/:path*');
  assert.equal(h['x-frame-options'], 'DENY');
  assert.equal(h['x-content-type-options'], 'nosniff');
  assert.equal(h['referrer-policy'], 'strict-origin-when-cross-origin');
  assert.match(h['permissions-policy'], /camera=\(\)/);
  assert.equal(h['content-security-policy'], undefined, 'a CSP here would collide with the per-file CSPs');
});
