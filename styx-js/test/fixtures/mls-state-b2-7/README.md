# mls-state-b2-7 writer fixture

This directory freezes one synthetic Phase B2 provider snapshot written by the
exact OpenMLS-WASM artifact committed at the B3.1 Stage 1 base. It was generated
before changing `patch/lib.rs`. It contains no browser export, real identity,
real conversation or user data.

## Bound provenance

- Source head: `a69df78c720bc679840172f68a68327ef603636c`
- OpenMLS revision: `09e92777dba0528d3d29e2e5e681b7e91637c7be`
- Writer WASM SHA-256:
  `ed5e740d9c93aa46aa1afb7b6065e4b5b92be972a8a080ddd0a35091260691bb`
- Writer WASM byte length: `2081600`
- Ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
- Group id: UTF-8 `styx-b2-7-writer-fixture-v1`
- Stable epoch: `1`
- Synthetic account private-key inputs: 31 zero bytes followed by `0x01` for
  Alice and `0x02` for Bob. These are test values and must never be reused.
- Account-identity-proof timestamp: `1786572000`
- Generator: `spikes/marmot-phase-b3-1/generate-b2-7-legacy-fixture.mjs`,
  7,551 bytes, SHA-256
  `88c92ae2103b36ccc65b07ab6abd1512ee68b30cf97583766d69fcc1b02ad20c`.
- `context.json`: 1,894 bytes, SHA-256
  `bce0e4f5e1bafbbf0239145161557a748db4c2792a8aa5bd33c6ea7bb2fc047d`.
- `envelope.json`: 19,497 bytes, SHA-256
  `fe33df74090d6d792b2715c468d5e6c19b87ad6bb0aeab335ee2180c331d20ad`.
- Provider payload: 14,233 bytes, SHA-256
  `809e339a3679798baf382c3be09db12f3980e79b704d36d1b281a91a5c105685`.

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
