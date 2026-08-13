# Phase B2.7 Stage 1: authenticated sender-attribution boundary

`STYX_SPIKE_PROTOTYPE` — isolated, non-product source and executable evidence
for the Stage 1 contract in Issue #163.

This spike proves that the pinned OpenMLS engine can return current-epoch MLS
application plaintext together with the authenticated member leaf, BasicCredential
identity and leaf signature key that produced it. Application payload bytes are
never treated as sender authority.

Stage 1 deliberately leaves the five generated OpenMLS-WASM files committed in
`vendor/openmls-wasm/` unchanged. The candidate bindings are built into two
disposable external directories and loaded only by `source-probe.mjs`. Installing
that candidate, admitting the old writer as compatible and persisting a B2.7
delivery record require a separately amended and approved Stage 2 contract.

## Boundary under test

The additive Rust method `PhaseB2Group.receive_application_message`:

1. validates the Provider bound to the group;
2. exact-decodes one TLS-framed `MlsMessageIn`;
3. accepts only a `PrivateMessage` for the loaded group and current epoch;
4. processes it once with OpenMLS;
5. rejects own echo and every non-member or non-application result;
6. resolves the authenticated member from the same current group instance;
7. compares the processed credential identity byte-for-byte with that member;
   and
8. returns a closed getter-only result containing group id, epoch, member leaf,
   credential identity, leaf signature key and plaintext.

The existing sender-discarding `process_application_message` remains present
and behaviorally unchanged.

## Current-writer fixture

`generate-b2-2-fixture.mjs` was executed before changing the Rust patch. It
refuses any writer except the exact committed B2.2 WASM digest and refuses to
overwrite its outputs. The synthetic snapshot, reference ciphertext and full
provenance live under `test/fixtures/mls-state-b2-2/`.

The fixture is compatibility input for a future Stage 2 probe. It is not yet a
compatibility allowlist entry and does not authorize an artifact transition.

## External source probe

From `styx-js/`, after producing an external candidate with `build.sh`:

```bash
node spikes/marmot-phase-b2-7/source-probe.mjs \
  vendor/openmls-wasm /absolute/path/to/external/candidate
```

The probe refuses the committed artifact as the candidate, discovers the full
generated surface and exercises:

- exact three-member interleaved attribution;
- equality of group, epoch, leaf, credential identity and signature key;
- an application payload that falsely claims a different identity;
- own echo, public Commit and different-group rejection;
- stale-to-current and current-to-stale epoch refusal;
- tampered ciphertext failure without plaintext release;
- continued liveness at the next sender-ratchet generation;
- accepted-message replay refusal; and
- malformed framing rejection.

Early rejects are also checked for byte-identical Provider state. A tampered
current-generation ciphertext is not an early reject: the pinned engine may
consume that receiver-ratchet generation before authentication fails. The
candidate releases no plaintext or sender result for it, rejects the original
generation afterward and accepts the next generation. This is bounded
fail-closed behavior with a residual denial-of-service/liveness cost, not proof
that rejected AEAD input is state-neutral.

## Non-claims

This evidence does not implement the B2.7 durable record, install a new WASM
artifact, activate product code, authenticate a human or device, provide legal
non-repudiation, prove delivery, hide metadata, implement Marmot transport or
make any anonymity claim. It is not covered by an independent cryptographic
audit and must never be used with real sensitive data.

See
`docs/architecture/spikes/2026-08-13-marmot-openmls-phase-b2-7-stage-1.md`
for exact hashes, measurements, tests and residual risks.
