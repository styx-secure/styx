# Phase B2.7: authenticated sender-attribution boundary

`STYX_SPIKE_PROTOTYPE` — isolated, non-product source and executable evidence
for the two-stage contract in Issue #163.

This spike proves that the pinned OpenMLS engine can return current-epoch MLS
application plaintext together with the authenticated member leaf, BasicCredential
identity and leaf signature key that produced it. Application payload bytes are
never treated as sender authority.

Stage 1 deliberately left the five generated OpenMLS-WASM files committed in
`vendor/openmls-wasm/` unchanged. The separately amended and approved Stage 2
contract installs that exact candidate, admits the exact B2.2 writer tuple only
after fixture evidence, and exercises sender-bound durable receive semantics in
a fresh disposable database namespace.

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

## Stage 2 durable machine

The Stage 2 files are a mechanical fork of the isolated B2.6 machine under the
fresh `styx-b2-7-poc-v1-` namespace and `STYX-B2-7-...-V1` digest domains. They
do not open, migrate or reinterpret B2.6 or product databases.

For each inbound application message, the adapter restores a disposable exact
provider/group instance and calls only `receive_application_message`. Before
any journal write or plaintext release, it requires the authenticated result to
match the restored group and epoch, uniquely resolves the returned leaf in the
same BIP-340-validated parent projection, checks the credential identity and
leaf signature key byte-for-byte, and recomputes the exact B2.4 verified-leaf
digest. The complete 104-byte account proof comes only from that projection.

One IndexedDB transaction CAS-commits the successor provider snapshot and a
strict ACCEPTED record whose content digest covers the ciphertext, plaintext,
instance, group, epoch, GroupContext, verified roster and full sender tuple.
The caller receives plaintext and attribution only after re-reading that exact
durable record. Duplicate delivery returns only its stored result. A failed
transaction or CAS loser returns neither plaintext nor sender authority.

Every non-ACCEPTED disposition structurally rejects plaintext and sender
fields. DEFERRED ciphertext can gain sender attribution only after a later exact
historical-instance receive authenticates it. No current roster is used to
interpret a past epoch.

## Stage 2 executable evidence

The Jest evidence covers three-member interleaving, per-sender out-of-order
delivery, payload false identity, restart and duplicate delivery, corrupted
records, out-of-roster and mismatched sender results, epoch/GroupContext/roster
refusal, retained historical receive, and remove/re-add reuse of a leaf index
with a new signature key and proof. Tampered ciphertext creates no durable
success; because the failed disposable provider is discarded, the original
ciphertext can be accepted in a later fresh transaction, followed by the next
generation.

The browser harness executes 100 two-connection inbound CAS races in both
Chromium and Firefox without Web Locks. Every race has exactly one durable
attributed winner; the typed loser exposes no plaintext or sender fields.

The committed five-file WASM set is byte-identical to two clean external builds
and matches the approved artifact table. The exact B2.2 writer tuple is a named
compatibility entry only because the immutable fixture restores under the new
reader, decrypts its reference message and creates a reply.

## Non-claims

This evidence does not activate product code, authenticate a human or device,
provide legal non-repudiation, prove delivery, hide metadata, implement Marmot
transport or make any anonymity claim. It is not covered by an independent
cryptographic audit and must never be used with real sensitive data.

See the Stage 1 and Stage 2 reports under `docs/architecture/spikes/` for exact
hashes, measurements, tests and residual risks.
