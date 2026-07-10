import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { VitePWA } from 'vite-plugin-pwa';
import { fileURLToPath } from 'node:url';
import { manifest } from './pwa.config.js';

// Resolve `styx-js` to the library source in the parent package, so the app
// consumes the real StyxChat (MLS/OpenMLS) instead of the mock.
const styxJsEntry = fileURLToPath(new URL('../../src/index.js', import.meta.url));
const styxJsRoot = fileURLToPath(new URL('../../', import.meta.url));

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      strategies: 'injectManifest',
      srcDir: 'src',
      filename: 'sw.js',
      registerType: 'autoUpdate',
      injectRegister: 'auto',
      includeAssets: ['apple-touch-icon.png', 'icon.svg'],
      manifest,
      injectManifest: {
        // The OpenMLS WASM is ~1.8 MB — raise the precache size ceiling.
        maximumFileSizeToCacheInBytes: 3_000_000,
        globPatterns: ['**/*.{js,css,html,wasm,png,svg,woff2}'],
      },
      // Keep the SW out of the dev server so the existing dev-based e2e is
      // unaffected; the PWA e2e runs against a production build + preview.
      devOptions: { enabled: false },
    }),
  ],
  resolve: {
    alias: { 'styx-js': styxJsEntry },
  },
  server: {
    port: 5175,
    fs: { allow: [styxJsRoot] },
  },
  preview: {
    port: 8090,
    host: '127.0.0.1',
    allowedHosts: true,
  },
  assetsInclude: ['**/*.wasm'],
  optimizeDeps: {
    exclude: ['styx-js'],
  },
});
