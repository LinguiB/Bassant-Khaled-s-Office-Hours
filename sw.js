const CACHE_NAME = 'dr-bassant-office-hours-v2';
const APP_SHELL = ['./', './index.html', './manifest.webmanifest', './icons/icon-192.png', './icons/icon-512.png'];
self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(APP_SHELL)));
  self.skipWaiting();
});
self.addEventListener('activate', event => {
  event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key)))));
  self.clients.claim();
});
self.addEventListener('fetch', event => {
  const request = event.request;
  if (request.method !== 'GET' || new URL(request.url).origin !== self.location.origin) return;
  if (request.mode === 'navigate') {
    event.respondWith(fetch(request).then(response => {
      const copy = response.clone();
      caches.open(CACHE_NAME).then(cache => cache.put('./index.html', copy));
      return response;
    }).catch(() => caches.match('./index.html')));
  }
});
self.addEventListener('push', event => {
  let msg = {};
  try { msg = event.data ? event.data.json() : {}; }
  catch { msg = { body: event.data ? event.data.text() : 'A student has sent a message.' }; }
  event.waitUntil(self.registration.showNotification(msg.title || 'New student message', {
    body: msg.body || 'A student has sent you a message. Open your inbox to view it.',
    icon: './icons/icon-192.png', badge: './icons/icon-192.png', tag: 'student-message', renotify: true,
    data: { url: msg.url || './#teacher' }
  }));
});
self.addEventListener('notificationclick', event => {
  event.notification.close();
  const target = new URL(event.notification.data?.url || './#teacher', self.location.href).href;
  event.waitUntil((async () => {
    const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    for (const client of clients) {
      if ('focus' in client) { await client.focus(); if ('navigate' in client) await client.navigate(target); return; }
    }
    await self.clients.openWindow(target);
  })());
});
