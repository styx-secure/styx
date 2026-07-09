import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

// Resolve `styx-js` to the library source in the parent package, so the app
// consumes the real StyxChat (MLS/OpenMLS) instead of the mock.
const styxJsEntry = fileURLToPath(new URL('../../src/index.js', import.meta.url));
const styxJsRoot = fileURLToPath(new URL('../../', import.meta.url));

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { 'styx-js': styxJsEntry },
  },
  server: {
    port: 5175,
    // Allow serving the library source and the vendored WASM (outside app root).
    fs: { allow: [styxJsRoot] },
  },
  // The OpenMLS wasm is loaded via `new URL(..., import.meta.url)` in the glue.
  assetsInclude: ['**/*.wasm'],
  optimizeDeps: {
    // The glue + wasm shouldn't be pre-bundled (it uses import.meta.url asset URL).
    exclude: ['styx-js'],
  },
});
