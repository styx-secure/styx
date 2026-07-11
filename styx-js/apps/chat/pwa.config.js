// pwa.config.js — the web app manifest, shared by vite.config.js (build) and
// the unit test. Kept free of vite imports so Jest can import it directly.
export const manifest = {
  name: 'Styx Chat',
  short_name: 'Styx',
  description: 'Messaggistica cifrata end-to-end, distribuita tramite relay federati.',
  id: '/',
  start_url: '/',
  scope: '/',
  display: 'standalone',
  orientation: 'portrait',
  lang: 'it',
  theme_color: '#0d9f6e',
  background_color: '#04070a',
  icons: [
    { src: 'pwa-192.png', sizes: '192x192', type: 'image/png' },
    { src: 'pwa-512.png', sizes: '512x512', type: 'image/png' },
    { src: 'pwa-maskable-512.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
  ],
};
