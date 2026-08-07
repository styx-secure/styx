import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { VitePWA } from 'vite-plugin-pwa';
import { fileURLToPath } from 'node:url';
import { readFileSync, readdirSync, unlinkSync } from 'node:fs';
import { resolve } from 'node:path';
import { manifest } from './pwa.config.js';

// Resolve `styx-js` to the library source in the parent package, so the app
// consumes the real StyxChat (MLS/OpenMLS) instead of the mock.
const styxJsEntry = fileURLToPath(new URL('../../src/index.js', import.meta.url));
const styxJsRoot = fileURLToPath(new URL('../../', import.meta.url));
const vaultKdfSource = fileURLToPath(new URL(
  '../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm', import.meta.url,
));
const vaultWorkerSource = fileURLToPath(new URL(
  '../../src/crypto/vault-worker-product.js', import.meta.url,
));
const vaultKdfOutput = 'vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm';

// The frozen loader accepts only this canonical path. Emit the already-pinned
// bytes for explicitly enabled developer/test builds; ordinary builds contain
// neither this asset nor a vault worker chunk.
function vaultKdfAssetPlugin() {
  const stage = process.env.VITE_VAULT_STAGE;
  const enabled = stage === 'developer-only' || stage === 'test-profile';
  let outputAssets;
  return {
    name: 'styx-vault-kdf-asset',
    apply: 'build',
    configResolved(config) {
      outputAssets = resolve(config.root, config.build.outDir, 'assets');
    },
    buildStart() {
      if (!enabled) return;
      this.emitFile({ type: 'asset', fileName: vaultKdfOutput, source: readFileSync(vaultKdfSource) });
    },
    generateBundle(_options, bundle) {
      if (enabled) return;
      // Vite discovers `new Worker(new URL(...))` before Rollup removes the
      // disabled dynamic-import branch. Remove only those two now-unreachable
      // artifacts from the final off bundle; no application chunk references
      // them after tree-shaking.
      for (const [fileName, output] of Object.entries(bundle)) {
        const isWorker = output.type === 'chunk'
          && (output.facadeModuleId === vaultWorkerSource
            || /^assets\/vault-worker-product-[A-Za-z0-9_-]+\.js$/.test(fileName));
        const isWorkerKdf = output.type === 'asset'
          && /^assets\/styx_kdf_wasm_bg-[A-Za-z0-9_-]+\.wasm$/.test(fileName);
        if (isWorker || isWorkerKdf) delete bundle[fileName];
      }
    },
    closeBundle() {
      if (enabled || outputAssets === undefined) return;
      // Worker sub-builds are written independently of the main Rollup
      // bundle, so remove their exact unreachable outputs after that sub-build.
      for (const name of readdirSync(outputAssets, { withFileTypes: true })) {
        if (!name.isFile()) continue;
        if (/^(vault-worker-product-|styx_kdf_wasm_bg-)[A-Za-z0-9_-]+\.(js|wasm)$/.test(name.name)) {
          unlinkSync(resolve(outputAssets, name.name));
        }
      }
    },
  };
}

export default defineConfig({
  plugins: [
    react(),
    vaultKdfAssetPlugin(),
    VitePWA({
      strategies: 'injectManifest',
      srcDir: 'src',
      filename: 'sw.js',
      registerType: 'autoUpdate',
      injectRegister: 'auto',
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
    // Loopback only, stated explicitly: the dev server must never listen on a
    // public interface by default (accepted-risk register: GHSA-fx2h-pf6j-xcff
    // is dev-server-only). Opting out requires an explicit --host on the CLI.
    host: '127.0.0.1',
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
