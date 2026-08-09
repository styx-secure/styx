// Default ESM library build for `npm run build` (Issue #139 amendment).
// Runtime dependencies stay external, and generated dist output is not
// committed. No plugin or vendored-WASM rebuild is performed.
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
