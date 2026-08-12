# Phase B2.5c: bounded retained-history convergence

`STYX_SPIKE_PROTOTYPE` — isolated, non-product executable evidence for Issue
#159.

B2.5c replaces B2.5b's one-cutoff arbitration with a five-Commit retained
history. Exact Commit parentage is discovered by replay against retained
OpenMLS states, every successful replay is freshly projected and B2.4-
authorized, and branches are selected by depth followed by the unchanged
B2.5a authenticated tip tuple. The result can supersede a prior branch without
depending on relay order or local cutoff partitions.

The spike also demonstrates one-use application-message liveness. It commits a
durable reservation before encryption, permits only the selected tip to emit,
and permanently refuses a second emission from the same local epoch instance.
This is deliberately not production sender-ratchet persistence.

It does **not** implement Marmot transport, business effects, real delivery
acknowledgements, a product runtime, multi-device recovery, secure erasure,
metadata privacy, rollback-resistant external anchoring or audit coverage.

## Frozen identity

- Styx base: `838e09898f889299963820018368f331611ee439`
- Base tree: `12707bb365bf7663029993a6c21efb5ad4700a56`
- OpenMLS: `09e92777dba0528d3d29e2e5e681b7e91637c7be`
- Marmot specification: `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1`
- WASM SHA-256:
  `60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a`
- Ciphersuite: `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`
- Database prefix: `styx-b2-5c-poc-v1-`

## Selection and recovery

Every pass freezes the exact eligible input closure. Disposable providers
replay each exact Commit against retained, non-pending states until the graph
reaches a fixed point. Zero matching parents remain deferred (or become stale
beyond the anchor), one matching parent creates an edge after B2.4 validation,
and more than one matching parent fails closed as ambiguous.

Branches begin at one retained anchor and sort by:

```text
(-depth, priority, authenticated account identity, SHA-256(exact Commit bytes))
```

The selected successor, invalidation evidence, released-state tombstones,
input dispositions, replay graph, local-generation dispositions, transition
and head are one CAS transaction. A changed read set forces a complete retry.
Missing required material or contradictory local publication evidence records
an `UNRECOVERABLE` transition while preserving epoch, snapshot, anchor and
canonical path.

The anchor advances only when a sixth edge is selected. States and edges no
longer reachable from the new anchor are logically released or removed;
selection-relevant alternative branches and active or eligible local pending states stay
retained. Historical state reads distinguish a release tombstone from absent
or corrupt storage.

## Local history and probe boundary

Local Commit evidence is generation-scoped. A stable generation-authority
digest binds immutable preparation fields even while the mutable generation
record moves through publication and selection states. At the 16-generation
limit, only a safely terminal, non-edge generation may be evicted; its evidence
and private pending state are removed together. The latest truncation marker
digest-links its predecessor and preserves the evicted authority digest; older
marker records are not retained by this bounded PoC. Historical operations then
return typed `UNKNOWN_GENERATION`.

The liveness probe is an intentionally narrow write-ahead ledger:

```text
reserve selected epoch instance -> persist -> encrypt once -> optional completion
```

A crash after reservation leaves a permanent refusal and no false completion.
Supersession never removes a reservation. A strictly deeper re-adopted tip has
a different instance identity and may be probed once. No post-send provider
state is persisted or exposed, so this mechanism must not be reused as a
production sender ratchet.

## Files

- `b2-5c-canonical.mjs`: identity tuple, domains, limits, errors and keys.
- `b2-5c-record.mjs`: strict codecs for every durable record family.
- `b2-5c-journal.mjs`: isolated IndexedDB journal and atomic CAS capabilities.
- `b2-5c-engine-adapter.mjs`: real-WASM replay, policy, selection and probe.
- `b2-5c-coordinator.mjs`: action-only scheduling surface.
- `harness.html`, `journal.browser.spec.js`, `playwright.config.js`: real
  IndexedDB multi-connection races on Chromium and Firefox.
- `../../test/crypto/mls-phase-b2-5c-retained-convergence.test.js`: real-WASM
  convergence, recovery, bounds, rollback and liveness evidence.

## Run

```bash
cd styx-js
npm test -- --runInBand \
  test/crypto/mls-phase-b2-5c-retained-convergence.test.js --testTimeout=20000
npx playwright test -c spikes/marmot-phase-b2-5c/playwright.config.js
```

See
`docs/architecture/spikes/2026-08-12-marmot-openmls-phase-b2-5c-retained-convergence.md`
for the complete evidence boundary, durable model, non-claims and residual
risks.
