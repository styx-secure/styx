// sw.js — Styx Chat service worker (vite-plugin-pwa injectManifest strategy).
// Precaches the app shell + OpenMLS WASM so the app opens offline. The push /
// notificationclick listeners are the stable skeleton Phase 2 (Web Push) fills in.
import { precacheAndRoute } from 'workbox-precaching';

precacheAndRoute(self.__WB_MANIFEST);

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

// Show the single generic notification on a Web Push wake-up. The payload is
// empty by design (content stays E2E); we never read event.data.
self.addEventListener('push', (event) => {
  event.waitUntil(
    self.registration.showNotification('Styx Chat', { body: 'Hai un nuovo messaggio', tag: 'styx-new' }),
  );
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil((async () => {
    const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    if (clients.length) return clients[0].focus();
    return self.clients.openWindow('/');
  })());
});
