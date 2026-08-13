# mls-state-b2-2 writer fixture

This directory freezes one synthetic Phase B2 provider snapshot written by the
exact OpenMLS-WASM artifact committed at the B2.7 Stage 1 base. It was generated
before changing `patch/lib.rs`. It contains no browser export, real identity,
real conversation or user data.

## Bound provenance

- Source head: `097fc88f05e8fc740ba67ef13ff07906d6999006`
- OpenMLS revision: `09e92777dba0528d3d29e2e5e681b7e91637c7be`
- Writer WASM SHA-256:
  `60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a`
- Writer WASM byte length: `2074265`
- Ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
- Group id: UTF-8 `styx-b2-2-writer-fixture-v1`
- Stable epoch: `1`
- Synthetic account private-key inputs: 31 zero bytes followed by `0x01` for
  Alice and `0x02` for Bob. These are test values and must never be reused.
- Account-identity-proof timestamp: `1786572000`
- Generator: `spikes/marmot-phase-b2-7/generate-b2-2-fixture.mjs`, 7,551 bytes,
  SHA-256 `28b203f136dcac524e44cdb8a05c57823135e9448f18f881ac1100c61cb593dd`.
- `context.json`: 1,894 bytes, SHA-256
  `7347133bdfc94ce9d44eb437f13a14cbd243a6db87dfee9f2b22b900ccbcb839`.
- `envelope.json`: 19,465 bytes, SHA-256
  `384f51bad7813524554127d145b5fe4c1a10087f5607d44f8eff87a7578c3208`.
- Provider payload: 14,209 bytes, SHA-256
  `813a5d5c0fcdc18cb8da016c0f5e0164d90b472a3fa8deb8712a55ba15fa90eb`.

## Ordered generation and self-check

From the exact clean base above, the generator:

1. refuses to run unless the committed writer has the exact SHA-256 above and
   both output files are absent;
2. creates fixed synthetic Marmot account inputs and fresh MLS leaf/key-package
   material under that writer;
3. creates a two-member Phase B2 group, confirms the Add and exchanges one
   application message in each direction;
4. snapshots Alice's provider at epoch 1;
5. creates a Bob-to-Alice reference ciphertext after the snapshot;
6. restores Alice's provider, identity and group from the snapshot;
7. decrypts the exact reference plaintext and creates a non-empty encrypted
   reply; and
8. writes both JSON files once with two-space indentation and one final LF.

The recorded self-check is
`restore-reference-decrypt-and-reply-pass`. OpenMLS uses a CSPRNG, so the
fixture bytes are intentionally not reproducible from the fixed semantic
inputs. These exact files are immutable and must not be regenerated in place.

Stage 1 does not add this writer tuple to any compatibility allowlist. Stage 2
may do so only after its separately authorized candidate artifact restores this
exact payload, decrypts the stored post-snapshot reference ciphertext and
creates a reply.
