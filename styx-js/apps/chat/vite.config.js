import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { VitePWA } from 'vite-plugin-pwa';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { manifest } from './pwa.config.js';

// Resolve `styx-js` to the library source in the parent package, so the app
// consumes the real StyxChat (MLS/OpenMLS) instead of the mock.
const styxJsEntry = fileURLToPath(new URL('../../src/index.js', import.meta.url));
const styxJsRoot = fileURLToPath(new URL('../../', import.meta.url));
const vaultKdfSource = fileURLToPath(new URL(
  '../../vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm', import.meta.url,
));
const vaultKdfOutput = 'vendor/styx-kdf-wasm/pkg/styx_kdf_wasm_bg.wasm';
const disabledVaultSupervisorId = '\0styx-vault-supervisor-disabled';

// The frozen loader accepts only this canonical path. Emit the already-pinned
// bytes for explicitly enabled developer/test builds; ordinary builds contain
// neither this asset nor a vault worker chunk.
function vaultKdfAssetPlugin() {
  const stage = process.env.VITE_VAULT_STAGE;
  const enabled = stage === 'developer-only' || stage === 'test-profile';
  return {
    name: 'styx-vault-kdf-asset',
    enforce: 'pre',
    apply: 'build',
    resolveId(source, importer) {
      // Replace the only vault lifecycle edge with a virtual off-stage module.
      // This prevents Vite's worker scanner from ever entering the product
      // worker graph in ordinary builds; no post-build deletion is needed.
      if (!enabled && source.endsWith('/crypto/vault-worker-supervisor.js')
        && importer?.includes('/src/config/vault-stage.js')) {
        return disabledVaultSupervisorId;
      }
      return null;
    },
    load(id) {
      if (id === disabledVaultSupervisorId) {
        return 'export const createProductVaultWorkerSupervisor = undefined;';
      }
      return null;
    },
    buildStart() {
      if (!enabled) return;
      this.emitFile({ type: 'asset', fileName: vaultKdfOutput, source: readFileSync(vaultKdfSource) });
    },
    generateBundle(_options, bundle) {
      if (enabled) return;
      for (const [fileName, output] of Object.entries(bundle)) {
        if (/vault-worker-product|styx_kdf_wasm_bg/.test(fileName)) {
          this.error(`stage-off bundle contains forbidden vault artifact: ${fileName}`);
        }
        if (output.type === 'chunk' && /vault-worker-product|styx_kdf_wasm_bg/.test(output.code)) {
          this.error(`stage-off bundle references forbidden vault artifact from ${fileName}`);
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
