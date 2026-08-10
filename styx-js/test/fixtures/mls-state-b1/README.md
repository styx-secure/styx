# mls-state-b1 fixture

This directory is a fixed, synthetic persisted-state regression fixture created
with the exact committed Phase B1 OpenMLS-WASM artifact before the B2.1 artifact
replacement. It contains no browser export, real identity, real conversation or
reusable user secret.

## Bound provenance

- Source head: `57bc9d4d17b7eb1ad380fb10c501efbacd3f3f42`
- OpenMLS revision: `09e92777dba0528d3d29e2e5e681b7e91637c7be`
- B1 WASM SHA-256:
  `61cce676c81366fc9c62752a09ea1547a4998ede7f144013ac5ade088e70a863`
- Ciphersuite:
  `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`
- Envelope version: 1
- Storage schema version: 1
- `context.json` SHA-256:
  `932b3e25916d889a98f9ba3e03a8f60f45c3c08a6c7f6b51275cca90d33e34a8`
- `envelope.json` SHA-256:
  `f63487b424c9dd0ade6302c488262d6c58129f1289e708cfe5a2fdb9285356d6`

The fixture was generated outside the repository by the executor from the
Styx-authored `mls-state-v1` fixture pattern. The generator first verified the
committed WASM digest, paired two test-only identities (`33…33` and `44…44`),
advanced both message ratchets, serialized the creator provider, produced a
post-snapshot reference ciphertext, restored the serialized bytes through the
real runtime, decrypted that ciphertext and produced a non-empty reply.

The CSPRNG makes the serialized bytes intentionally non-reproducible. These
exact files are therefore the compatibility contract and must not be
regenerated in place. A future replacement requires a separately authorized
fixture and must preserve this one while its tuple remains a supported writer.

Stage B2.1 tests load this exact B1 tuple under the new artifact and prove
identity, group, membership, reference-message decryption and reply liveness.
The older `mls-state-v1` pre-B1 fixture remains a separate unchanged contract.
