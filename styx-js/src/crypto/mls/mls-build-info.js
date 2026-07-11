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
  wasmArtifactSha256: 'b56e3ea095c3be3dc9a589e27ad2092bcc6de663cc788db30853e89c02ff386a',
  ciphersuite: 'MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519',
});

// Revisions whose serialize_state format is PROVEN loadable by the current runtime
// (a real fixture from that revision restored under this one — never assumed from
// upstream release notes). See docs/architecture/mls-state-migration-policy.md §4.1.
export const COMPATIBLE_OPENMLS_REVISIONS = Object.freeze([
  MLS_BUILD_INFO.openMlsRevision,
]);
