// Known-answer vectors for styx-kdf-wasm (Argon2id v0x13).
//
// Provenance: every output was computed by TWO independent implementations
// (this project's RustCrypto crate and hash-wasm 4.12.0) with byte-identical
// results, and the first three inputs are the cross-vectors of the Argon2id
// spike (docs/superpowers/spikes/2026-07-12-argon2id.md), stable across
// Chromium and Firefox. RFC 9106 §5.3 literal vectors are NOT API-compatible
// (they require secret-key and associated-data inputs the minimal surface
// deliberately does not expose); these anchors serve the same regression
// purpose. The same anchors are asserted by the crate's native cargo tests.
//
// Synthetic passwords only — never real credentials.

const utf8 = (s) => new TextEncoder().encode(s);

export const KDF_KAT_VECTORS = [
  {
    name: 'spike-1',
    password: utf8('synthetic-test-password'),
    salt: Uint8Array.from({ length: 16 }, (_, i) => i * 7 + 3),
    mKib: 19456,
    t: 2,
    p: 1,
    outLen: 32,
    hex: '743669d50cc2010f3ac408895f013d176b7e53a4f114cf6c12f42981e1837a7e',
  },
  {
    name: 'spike-2-unicode',
    password: utf8('another synthetic pw €🔑'),
    salt: Uint8Array.from({ length: 16 }, (_, i) => i * 7 + 3),
    mKib: 65536,
    t: 3,
    p: 1,
    outLen: 32,
    hex: 'b0e838c99930e1d511bc38fa05d6b435354e7c4a66a4c64ec20712cd73f49857',
  },
  {
    name: 'spike-3-lanes',
    password: utf8('parallel-lanes'),
    salt: Uint8Array.from({ length: 16 }, (_, i) => i * 7 + 3),
    mKib: 32768,
    t: 3,
    p: 4,
    outLen: 64,
    hex: 'fe175848b6c78398ed7e0db89042d21b384e9cce995400f0b4eb27891ddb9f1b'
      + '58a43b6c1bc50e14379c5dcaa75e8928d134836f6062100e0ca4c8c07843ee8e',
  },
  {
    name: 'zero-salt',
    password: utf8('styx-kdf-wasm-kat'),
    salt: new Uint8Array(16),
    mKib: 19456,
    t: 2,
    p: 1,
    outLen: 32,
    hex: 'b3a27916fb1e0e5ff9f461b7721cf2d5cc5fb50dab51b68f0f8ca2b25818bc7a',
  },
  {
    name: 'absolute-min-bounds',
    password: utf8('k'),
    salt: Uint8Array.from({ length: 8 }, (_, i) => i),
    mKib: 1024,
    t: 1,
    p: 1,
    outLen: 16,
    hex: '7a6ebb2e8257e4c8ea88b5d3bf7c5a95',
  },
];

export const toHex = (u8) => [...u8].map((x) => x.toString(16).padStart(2, '0')).join('');
