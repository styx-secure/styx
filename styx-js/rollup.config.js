// Default ESM library build for `npm run build` (Issue #139 amendment).
// Declared runtime dependencies stay external. No plugin is used, and no
// vendored WASM artifact is rebuilt, re-verified, or committed. Generated
// dist output is gitignored and is never committed.
//
// Artifact limitation: src/index.js re-exports MlsEngine, so ordinary relative
// import resolution inlines the pinned vendor/openmls-wasm/openmls_wasm.js
// glue. Its default new URL('openmls_wasm_bg.wasm', import.meta.url) lookup
// consequently resolves next to dist/styx.esm.js; Rollup does not emit or copy
// that WASM binary. Consumers must pre-initialize MlsEngine with supported
// wasmBytes or host the binary beside the emitted bundle. Changing this
// resolution or excluding the glue is outside Issue #139.
const RUNTIME_DEPENDENCIES = [
  '@noble/ciphers',
  '@noble/curves',
  '@noble/ed25519',
  '@noble/hashes',
];

export default {
  input: 'src/index.js',
  external: (id) =>
    RUNTIME_DEPENDENCIES.some((dependency) =>
      id === dependency || id.startsWith(`${dependency}/`)
    ),
  output: {
    file: 'dist/styx.esm.js',
    format: 'es',
    sourcemap: false,
  },
};
