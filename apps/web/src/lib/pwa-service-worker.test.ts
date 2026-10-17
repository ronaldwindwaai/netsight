import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';
const origin = 'https://netsight.test';
function worker(online = true) {
  const callbacks = new Map<string, (value: unknown) => void>();
  const stored: Request[] = [];
  const removed: string[] = [];
  const fetches: unknown[] = [];
  vm.runInNewContext(readFileSync(new URL('../../public/sw.js', import.meta.url), 'utf8'), {
    self: {location: {origin}, addEventListener: (name: string, callback: (e: unknown) => void) => callbacks.set(name, callback), skipWaiting: async () => {}, clients: {claim: async () => {}}},
    caches: {
      open: async () => ({addAll: async (requests: Request[]) => { stored.push(...requests); }, match: async () => new Response('Current health is unknown.')}),
      keys: async () => ['netsight-offline-v0', 'netsight-offline-v1', 'unrelated-app'],
      delete: async (key: string) => {removed.push(key); return true;},
    },
    Request: class extends Request {
      constructor(value: string, init: RequestInit) {super(new URL(value, origin), init);}
    },
    Response, URL,
    fetch: async (request: unknown) => {fetches.push(request); if (!online) throw new Error('offline'); return new Response('Live response');},
  });
  async function lifecycle(name: string) {
    const promises: Promise<void>[] = [];
    callbacks.get(name)!({waitUntil: (p: Promise<void>) => promises.push(p)});
    await Promise.all(promises);
  }
  async function navigate(path: string, mode = 'navigate', method = 'GET') {
    const promises: Promise<Response>[] = [];
    callbacks.get('fetch')!({request: {url: new URL(path, origin).href, mode, method}, respondWith: (p: Promise<Response>) => promises.push(p)});
    return promises.length ? await promises[0] : null;
  }
  return {stored, removed, fetches, lifecycle, navigate};
}
test('installation caches only public offline assets, without credentials', async () => {
  const sw = worker(); await sw.lifecycle('install');
  assert.deepEqual(sw.stored.map(r => new URL(r.url).pathname), ['/offline.html', '/icons/netsight-192.png', '/icons/netsight-512.png']);
  assert.ok(sw.stored.every(r => r.credentials === 'omit'));
});
test('activation only removes obsolete caches owned by this feature', async () => {
  const sw = worker(); await sw.lifecycle('activate');
  assert.deepEqual(sw.removed, ['netsight-offline-v0']);
});
test('API, auth, login, writes, subresource and external requests are never intercepted', async () => {
  const sw = worker(false);
  for (const path of ['/api/v1/auth/session', '/auth/callback?code=private', '/login', 'https://elsewhere.test/overview']) assert.equal(await sw.navigate(path), null);
  assert.equal(await sw.navigate('/overview', 'cors'), null);
  assert.equal(await sw.navigate('/incidents', 'navigate', 'POST'), null);
  assert.equal(sw.fetches.length, 0);
});
test('online protected navigation stays on the network and is never cached', async () => {
  const sw = worker(); const response = await sw.navigate('/config');
  assert.equal(await response?.text(), 'Live response');
  assert.equal(sw.stored.length, 0);
});
test('offline protected navigation returns generic unknown state with failure status and no-store', async () => {
  const sw = worker(false); const response = await sw.navigate('/incidents/private-id');
  assert.equal(response?.status, 503);
  assert.equal(response?.headers.get('Cache-Control'), 'no-store');
  assert.equal(await response?.text(), 'Current health is unknown.');
  assert.equal(sw.stored.length, 0);
});
