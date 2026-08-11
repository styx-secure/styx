# Phase B2.5a: same-parent branch-selection kernel

`STYX_SPIKE_PROTOTYPE` — isolated, non-product executable evidence for Issue
#155.

This directory proves one bounded property: given the same authenticated MLS
parent and the same frozen set of depth-one Commit branches, clients select and
durably apply the same eligible child independently of insertion order,
transport order, and candidate-completion order.

It does **not** implement full Marmot convergence, a collection scheduler,
retained-history rewind, local-publisher admission, witnesses, transport, a
vault, or a product runtime.

## Frozen runtime tuple

- OpenMLS: `09e92777dba0528d3d29e2e5e681b7e91637c7be`
- Marmot specification: `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1`
- WASM SHA-256:
  `60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a`
- Ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
- Database prefix: `styx-b2-5a-poc-v1-`
- Maximum frozen batch: 16 exact Commit inputs

## Algorithm

1. Retain and digest exact MLS Commit bytes before evaluation.
2. Freeze the sorted unique digest set against the current stable parent.
3. Restore the exact retained provider snapshot independently for every input.
4. Stage the Commit through the pinned OpenMLS engine. Failure becomes
   `NOT_CANDIDATE`, not a policy rejection.
5. Reproduce and bind the complete B2.4 authorization decision.
6. Admit only authorized direct children of the retained parent.
7. Select the lexicographically minimum tuple:

   ```text
   (priority, authenticated_account_identity, sha256(exact_commit_bytes))
   ```

   `Add` and `Remove` have priority 0; `self-update` has priority 1.
8. Restore the retained parent again, restage and reauthorize the winner, then
   merge only that Commit.
9. Re-read the complete six-store decision set inside one read-write
   transaction and publish the result using compare-and-swap on the base head.

An all-invalid frozen batch resolves terminally with a null winner and leaves
the canonical head byte-identical. A missing retained parent moves the local
head to typed `UNRECOVERABLE` while preserving the last epoch, GroupContext,
snapshot reference, and all MLS bytes.

## Files

- `b2-5a-canonical.mjs`: limits, runtime identity, strict helpers, protocol
  batch identity, ordering tuple, and provider-map semantic comparison.
- `b2-5a-record.mjs`: closed codecs and domain-separated digests for all
  durable records.
- `b2-5a-journal.mjs`: isolated six-store atomic journal, freeze, CAS resolve,
  terminal null-winner and unrecoverable recovery paths.
- `b2-5a-convergence.mjs`: pure priority derivation and total-order selection.
- `b2-5a-engine-adapter.mjs`: fresh-restore OpenMLS replay and B2.4 policy
  binding.
- `../../test/crypto/mls-phase-b2-5a-convergence.test.js`: real-WASM hostile
  and convergence evidence.

## Durable states

```text
stable head + collected inputs
             |
             v
      immutable FROZEN batch
          /             \
         v               v
RESOLVED + winner   RESOLVED + null winner
  successor head       unchanged head

missing retained parent -> UNRECOVERABLE local head
```

There is no durable `RESOLVING` state. An aborted transaction leaves the exact
frozen predecessor. A committed transaction contains the complete result.

## Cross-client evidence

Cross-client convergence identity is limited to:

- group id;
- protocol batch digest;
- selected exact Commit digest;
- successor epoch; and
- successor GroupContext digest.

Local head and provider snapshot digests are deliberately excluded. Distinct
members necessarily retain different secrets and identities. Same-member
replicas are compared by sorted provider key/value semantics; only OpenMLS's
local `MessageSecrets.message_secrets.added_at` retention timestamp is excluded
from that diagnostic comparison. Original provider snapshot bytes are always
retained exactly and are never normalized or rewritten.

## Run the focused evidence

```bash
cd styx-js
npm test -- --runInBand \
  test/crypto/mls-phase-b2-5a-convergence.test.js --testTimeout=20000
```

See
`docs/architecture/spikes/2026-08-12-marmot-openmls-phase-b2-5a-branch-selection.md`
for schema, threat boundaries, evidence, specification mapping, and deferred
work.
