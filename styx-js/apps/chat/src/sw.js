// sw.js — Styx Chat service worker (vite-plugin-pwa injectManifest strategy).
// Precaches the app shell + OpenMLS WASM so the app opens offline. The push /
// notificationclick listeners are the stable skeleton Phase 2 (Web Push) fills in.
import { precacheAndRoute } from 'workbox-precaching';

precacheAndRoute(self.__WB_MANIFEST);

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

// Phase 2 fills this in: show a generic notification on a Web Push. No-op for now.
self.addEventListener('push', () => {});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil((async () => {
    const clients = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    if (clients.length) return clients[0].focus();
    return self.clients.openWindow('/');
  })());
});
