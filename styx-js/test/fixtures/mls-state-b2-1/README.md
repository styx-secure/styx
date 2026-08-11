# mls-state-b2-1 fixture

This directory is a fixed, synthetic persisted-state regression fixture created
with the exact committed B2.1 OpenMLS-WASM artifact before the B2.2 artifact
replacement. It contains no browser export, real identity, real conversation or
reusable user secret.

## Bound provenance

- Source head: `d878ed75c11d5459c4361b425c5b48724ca91406`
- OpenMLS revision: `09e92777dba0528d3d29e2e5e681b7e91637c7be`
- B2.1 WASM SHA-256:
  `d0399fddc2ed5f030927f9786d295c394bcdfa133a1c69feeb9514edf2cd6f01`
- Ciphersuite:
  `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
- Envelope version: 1
- Storage schema version: 1
- Creator identity: 32 bytes of `0x55`, represented as 64 hexadecimal `5`
  characters.
- Peer identity: 32 bytes of `0x66`, represented as 64 hexadecimal `6`
  characters.
- `context.json`: 884 bytes; SHA-256
  `179b6a2ab89f6d1f129ac62599d6de2a2c4c9450b4fade00c9712bd2adbf017d`.
- `envelope.json`: 16,598 bytes; SHA-256
  `03e2edfc9ca1b8c3f60a66ded7d13f79f4d1351fad738aed8b2012a02c4c242e`.
- External generation-evidence SHA-256:
  `95c1e95229dd3627ac5cab7c398f2a5e620bf1d2ecd0097298123e951da94b65`.

## Exact generation procedure

From the clean source head above, the executor generated the fixture outside the
repository with the committed B2.1 files and performed these ordered operations:

1. SHA-256-verify `vendor/openmls-wasm/openmls_wasm_bg.wasm` against the exact
   B2.1 digest above, then initialize `MlsEngine` with those bytes.
2. Create engines named `55…55` and `66…66`; start a session from creator to
   peer with `peer.keyPackageBytes()`, then join the peer with the exact returned
   Welcome and ratchet tree.
3. Encrypt/decrypt UTF-8 `synthetic B2.1 creator→peer`, then encrypt/decrypt
   UTF-8 `synthetic B2.1 peer→creator`, in that order.
4. Serialize the creator with `creator.serializeState()` and wrap the bytes with
   `encodeMlsStateEnvelope()` from that same source head.
5. After the snapshot, have the peer encrypt the exact UTF-8 text
   `mls-state-b2-1 reference message — only a compatible restored session decrypts this`.
6. Write `envelope.json` and `context.json` as `JSON.stringify(value, null, 2)`
   followed by one LF byte. `context.json` contains exactly `name`, `peer`,
   `groupId`, `idpk`, `groups`, `refCiphertext`, and `refPlaintext`, in that
   insertion order.
7. Restore the creator from the just-written envelope and identity public key,
   load the exact peer/group pair, decrypt the post-snapshot ciphertext to the
   exact reference text, and require a non-empty encrypted reply for UTF-8
   `B2.1 fixture restored response`.
8. Record the source head, B2.1 WASM digest, both file byte lengths and digests,
   and the literal self-check result `restore-reference-decrypt-and-reply-pass`
   in the external generation evidence whose digest is frozen above.

The CSPRNG makes the serialized bytes intentionally non-reproducible. These
exact files are therefore the compatibility contract and must not be
regenerated in place. A future replacement requires a separately authorized
fixture and must preserve this one while its tuple remains a supported writer.

Stage B2.2 tests load this exact B2.1 tuple under the new artifact and prove
identity, group, membership, reference-message decryption and reply liveness.
The older pre-B1 and B1 fixtures remain separate unchanged contracts.
