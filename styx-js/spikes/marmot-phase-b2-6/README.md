# Phase B2.6: crash-safe MLS application-message ratchet

STYX_SPIKE_PROTOTYPE — isolated, non-product executable evidence for Issue
#161.

B2.6 extends the frozen B2.5c retained convergence machine with a bounded
application-message journal. Outbound encryption happens only in a disposable
OpenMLS provider. The post-encryption provider snapshot and the exact
ciphertext outbox record then win or lose one atomic CAS transaction. The
adapter returns only a durable ordinal; ciphertext bytes are readable solely
from the committed outbox.

Inbound decryption follows the symmetric rule: exact-ciphertext deduplication
precedes OpenMLS, while the post-decryption provider snapshot and accepted
delivery record commit atomically before plaintext is returned. A transaction
loser exposes neither its mutated provider nor computed output.

The pinned wrapper authenticates an inbound message as originating from a
member of the MLS group but returns plaintext without the processed sender
credential. Therefore the durable inbound record deliberately contains no
per-member sender field. Inner payload identity, member-count inference and
provider diffs are not substitutes for authenticated sender evidence.

This proof does **not** activate any product send path or implement Marmot
transport, application payload conformance, identity-sensitive business rules,
real delivery proof, metadata privacy, multi-device recovery, secure erasure,
external rollback anchoring or audit coverage.

## Frozen identity

- Styx base: acafff1fe71ba1621483fc52830b27415262ab53
- Base tree: 7ece9baaa874295a9ed7397602a6525e5353b7a3
- OpenMLS: 09e92777dba0528d3d29e2e5e681b7e91637c7be
- Marmot specification: 4ad4ae21479c3f3fa9950c6fc4556a76941a62e1
- WASM SHA-256:
  60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a
- Ciphersuite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
- Database prefix: styx-b2-6-poc-v1-

## Durable boundary

Each transcript-derived epoch instance owns one monotonic message state and one
current provider snapshot. The instance identity binds group id, canonical tip
Commit, epoch, GroupContext and authenticated local member.

The producing tip Commit remains stable when settlement later advances the
canonical anchor. The journal resolves it from mutually consistent durable
edge, transition and local-generation evidence, including the first transition
that adopts a snapshot as its anchor. Conflicting evidence fails closed. This
preserves the frozen transcript-derived identity instead of replacing it with a
storage id or snapshot digest.

Outbound ordering is:

    restore durable state
    -> encrypt in disposable provider
    -> serialize post-state
    -> CAS(post-state + exact immutable outbox)
    -> expose durable ordinal
    -> read/retry exact committed bytes

Opaque request ids are bounded and idempotent. Reusing one with the same payload
digest and immutable recipient scope recovers the existing ordinal; conflicting
reuse fails closed. Publication attempts and outcomes are bounded attestations
and never ratchet authority.

The inherited B2.5c liveness probe keeps its one-use write-ahead reservation,
but its MLS application ciphertext now advances through this same durable
message-state transaction. Its internal request namespace is reserved from
application callers. A probe and an ordinary send from one predecessor can
therefore produce only one committed, releasable ciphertext; inbound probe
processing likewise persists the receiver successor before returning
plaintext. The probe ledger remains evidence, not a second ratchet authority.

Inbound ordering is:

    deduplicate exact ciphertext
    -> decrypt in disposable provider
    -> serialize post-state
    -> CAS(post-state + exact ciphertext + bounded plaintext)
    -> read durable delivery
    -> expose plaintext

The B2.5c settlement transaction shares the message stores for serialization.
It may suspend displaced-instance outboxes, re-enable a retained instance after
re-adoption, or terminally invalidate and tombstone an instance that leaves the
retained horizon. Message activity is excluded from the convergence selection
read set. Release also invalidates bounded deferred-only input when no primary
message-state record was ever created, and local-generation replacement or
eviction uses the same atomic release path. Every message commit revalidates
its retained base inside that transaction, so a local-generation release that
does not change the canonical head still wins fail-closed.

## Bounds

- retained epoch instances and message states: 17, enforced before the first
  message-state mutation;
- non-terminal outbox obligations per instance: 16, with no eviction;
- total outbox history per instance: 128, fail-closed with no eviction;
- inbound records per instance: 64;
- publication evidence records per outbox: 64;
- opaque request id: 128 UTF-8 bytes;
- plaintext: 4 KiB;
- ciphertext: 8 KiB;
- provider snapshot: 8 MiB.

## Files

- b2-6-canonical.mjs: identity tuple, domains, limits, errors and keys.
- b2-6-record.mjs: strict durable record codecs.
- b2-6-journal.mjs: isolated IndexedDB journal and private atomic CAS hooks.
- b2-6-engine-adapter.mjs: disposable-provider message and convergence logic.
- b2-6-coordinator.mjs: action-only scheduling surface.
- harness.html, journal.browser.spec.js, playwright.config.js: real IndexedDB
  multi-connection races on Chromium and Firefox.
- ../../test/crypto/mls-phase-b2-6-message-ratchet.test.js: real-WASM crash,
  restart, deduplication, convergence and bound evidence.

## Run

    cd styx-js
    npm test -- --runInBand \
      test/crypto/mls-phase-b2-6-message-ratchet.test.js --testTimeout=20000
    npx playwright test -c spikes/marmot-phase-b2-6/playwright.config.js

See
docs/architecture/spikes/2026-08-12-marmot-openmls-phase-b2-6-message-ratchet.md
for the complete evidence boundary, measurements, non-claims and residual
risks.
