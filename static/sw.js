
const CACHE = 'david-connect-v2';
const SHELL = [
  '/',
  '/static/style.css',
  '/static/app.js',
  '/static/manifest.json',
  '/static/icon-192.png',
  '/static/icon-512.png'
];

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE).then(cache => cache.addAll(SHELL)));
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
  );
  self.clients.claim();
});

self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  if (url.pathname.startsWith('/69c3de35-f164-832e-ae50-fdf6bc0939f9') || url.pathname.startsWith('/admin')) {
    return;
  }

  if (request.method !== 'GET') return;

  const isNavigation = request.mode === 'navigate';
  const isStatic = url.pathname.startsWith('/static/');

  event.respondWith((async () => {
    const cache = await caches.open(CACHE);
    if (isStatic) {
      const cached = await cache.match(request);
      if (cached) return cached;
      try {
        const response = await fetch(request);
        if (response.ok) cache.put(request, response.clone());
        return response;
      } catch (_) {
        return cached || caches.match('/').then(r => r);
      }
    }

    if (isNavigation) {
      try {
        const response = await fetch(request);
        if (response.ok) cache.put(request, response.clone());
        return response;
      } catch (_) {
        return (await cache.match(request)) || (await cache.match('/'));
      }
    }

    try {
      const response = await fetch(request);
      if (response.ok) cache.put(request, response.clone());
      return response;
    } catch (_) {
      return (await cache.match(request)) || Response.error();
    }
  })());
});
