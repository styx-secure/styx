// mls-build-info.js — what the *current* vendored MLS runtime is, declared once.
//
// The state envelope (src/storage/mls-state-envelope.js) stamps these values into
// every persisted MLS state and refuses to load state written by a runtime it cannot
// prove compatible. They MUST match the vendored artifact:
//   - openMlsRevision   ↔ OPENMLS_COMMIT in vendor/openmls-wasm/build.sh
//   - wasmArtifactSha256 ↔ sha256 of vendor/openmls-wasm/openmls_wasm_bg.wasm
//   - ciphersuite        ↔ the suite compiled in vendor/openmls-wasm/patch/lib.rs
// A test (test/storage/mls-state-envelope.test.js) reads those files and fails the
// suite on any drift, so a pin bump cannot silently leave these constants stale.

export const MLS_BUILD_INFO = Object.freeze({
  openMlsRevision: '09e92777dba0528d3d29e2e5e681b7e91637c7be',
  wasmArtifactSha256: 'f1596c27c90f71e50998bfae1be212e6b016944e18fe3c3fecee1eb44e64f869',
  ciphersuite: 'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519',
});

export const B3_2_MLS_BUILD_INFO = Object.freeze({
  openMlsRevision: '09e92777dba0528d3d29e2e5e681b7e91637c7be',
  wasmArtifactSha256: 'd281d4a4c3c72999e966c1e70bff68b0ddc5eda23653295adbf620bad723f62c',
  ciphersuite: 'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519',
});

export const B3_1_MLS_BUILD_INFO = Object.freeze({
  openMlsRevision: '09e92777dba0528d3d29e2e5e681b7e91637c7be',
  wasmArtifactSha256: '26a41d86d7fd2c9ab4184344e4ff00f5eebb5bc7609ba22e98b12ce903d4a4dd',
  ciphersuite: 'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519',
});

export const B2_7_MLS_BUILD_INFO = Object.freeze({
  openMlsRevision: '09e92777dba0528d3d29e2e5e681b7e91637c7be',
  wasmArtifactSha256: 'ed5e740d9c93aa46aa1afb7b6065e4b5b92be972a8a080ddd0a35091260691bb',
  ciphersuite: 'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519',
});

export const B2_2_MLS_BUILD_INFO = Object.freeze({
  openMlsRevision: '09e92777dba0528d3d29e2e5e681b7e91637c7be',
  wasmArtifactSha256: '60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a',
  ciphersuite: 'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519',
});

export const B2_1_MLS_BUILD_INFO = Object.freeze({
  openMlsRevision: '09e92777dba0528d3d29e2e5e681b7e91637c7be',
  wasmArtifactSha256: 'd0399fddc2ed5f030927f9786d295c394bcdfa133a1c69feeb9514edf2cd6f01',
  ciphersuite: 'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519',
});

export const B1_MLS_BUILD_INFO = Object.freeze({
  openMlsRevision: '09e92777dba0528d3d29e2e5e681b7e91637c7be',
  wasmArtifactSha256: '61cce676c81366fc9c62752a09ea1547a4998ede7f144013ac5ade088e70a863',
  ciphersuite: 'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519',
});

export const PRE_B1_MLS_BUILD_INFO = Object.freeze({
  openMlsRevision: '09e92777dba0528d3d29e2e5e681b7e91637c7be',
  wasmArtifactSha256: 'b56e3ea095c3be3dc9a589e27ad2092bcc6de663cc788db30853e89c02ff386a',
  ciphersuite: 'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519',
});

// Exact, fixture-proven state-writer identities. These are tuples rather than
// independent allowlists so hashes, revisions and suites cannot be mixed.
export const COMPATIBLE_MLS_STATE_TUPLES = Object.freeze([
  PRE_B1_MLS_BUILD_INFO,
  B1_MLS_BUILD_INFO,
  B2_1_MLS_BUILD_INFO,
  B2_2_MLS_BUILD_INFO,
  B2_7_MLS_BUILD_INFO,
  B3_1_MLS_BUILD_INFO,
  B3_2_MLS_BUILD_INFO,
  MLS_BUILD_INFO,
]);

// Revisions whose serialize_state format is PROVEN loadable by the current runtime
// (a real fixture from that revision restored under this one — never assumed from
// upstream release notes). See docs/architecture/mls-state-migration-policy.md §4.1.
export const COMPATIBLE_OPENMLS_REVISIONS = Object.freeze([
  MLS_BUILD_INFO.openMlsRevision,
]);
