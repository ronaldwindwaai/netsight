/* Public offline document only. Never cache authenticated routes or API responses. */
const OFFLINE_CACHE = 'netsight-offline-v1';
const OFFLINE_URL = '/offline.html';
const PUBLIC_FILES = [OFFLINE_URL, '/icons/netsight-192.png', '/icons/netsight-512.png'];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(OFFLINE_CACHE);
    await cache.addAll(PUBLIC_FILES.map(url => new Request(url, {credentials: 'omit', cache: 'reload'})));
    await self.skipWaiting();
  })());
});
self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) {
      if (key.startsWith('netsight-offline-') && key !== OFFLINE_CACHE) await caches.delete(key);
    }
    await self.clients.claim();
  })());
});
self.addEventListener('fetch', (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== 'GET' || request.mode !== 'navigate' || url.origin !== self.location.origin
      || /^\/(api|auth|login)(\/|$)/.test(url.pathname)) return;
  event.respondWith((async () => {
    try { return await fetch(request); }
    catch {
      const offline = await (await caches.open(OFFLINE_CACHE)).match(OFFLINE_URL);
      const body = offline ? offline.body : 'Netsight cannot be reached. Current health is unknown.';
      return new Response(body, {status: 503, headers: {
        'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store',
      }});
    }
  })());
});
