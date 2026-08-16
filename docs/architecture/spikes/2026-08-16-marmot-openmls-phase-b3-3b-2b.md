# Phase B3.3b-2b: bounded concurrent-fork convergence

Date: 2026-08-16

Issue: #194

Pull request: #195

Disposition: **implementation evidence is a bounded GO; exact-final-HEAD review,
CI and human gates remain required**

## Question and bounded claim

B3.3b-2b asks whether the exact pinned Styx OpenMLS wrapper and MDK can converge
after both members have independently published, confirmed and durably restored
different ordinary self-update Commits from the same authenticated parent.

The answer is `B33B2B=BOUNDED_GO` for exactly two authenticated, proposal-free,
depth-one candidates with no application witnesses. This is not a general
convergence engine or a product persistence claim.

## Frozen inputs

The proof reuses without modification:

- OpenMLS `09e92777dba0528d3d29e2e5e681b7e91637c7be`, tree
  `fde242458abe5594fbebf2556dca0a135367a817`;
- Marmot `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1`, tree
  `10d941f358de5d9fe4ee1db75581f3e5363f5e92`;
- MDK `9396adb6aa6b95b521a7979facd5ea7040c07288`, tree
  `a1145de604e616634dae9a1ef6bf5033c9c9e879`;
- the B3.3b-1 five-file WASM artifact tuple and generated bindings;
- ciphersuite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`);
- member profiles `STYX_B32A` and `MDK_PIN_9396ADB`;
- the exact five-past-epoch retained-history horizon.

No dependency, manifest, lockfile, vendor artifact, ciphersuite, profile or
earlier persisted format changes in this increment.

## Observed pinned-engine behavior

The Stage-0 probe froze behavior before the durable adapter was implemented.
For rival delivery after restart, MDK stores the rival as `buffered`, exposes
exactly two eligible ordinary depth-one candidates, and reports zero proposals,
application payloads and witnesses. All ordering inputs tie until
`tip_committer`; the lower raw authenticated 32-byte account identity wins.
The losing valid candidate is `deferred` and a replayed convergence pass is
empty.

For delivery before restart, pinned MDK exposes an asymmetric pairwise result:

- when the received Styx Commit wins, it reports `processed`, followed by
  `fork_recovered`, `group_state_invalidated` with the upstream
  `supersededbybranchselection` reason, and `epoch_changed`;
- when MDK's already-confirmed branch wins, it reports `stale` with the typed
  `AlreadyAtEpoch` reason and no event.

The Styx settlement record does not rename either upstream result. Its own
bounded losing-candidate disposition is `deferred` while the retained parent is
available.

## Selection algorithm

Both exact Commits are staged against the retained authenticated parent. The
wrapper-derived projections bind group, source and target epoch, committer
account and signature key, authority digest, Commit digest, parent state and
GroupContext digests, candidate GroupContext and verified roster.

The immutable selection trace contains exactly two candidates and records:

```text
effective depth = 1
priority = ordinary
witness quorum = false
application witness score = 0
proposal count = 0
application payload count = 0
witness count = 0
decisive rule = tip_committer
```

The trace is derived internally from authenticated projections. There is no API
for a caller to supply a winner, ordering hint, third candidate or witness. The
winner is the lower raw authenticated account identity under unsigned
lexicographic byte ordering. Commit SHA-256 is validated for the exact
TLS-serialized bytes but is not the decisive rule in this bounded case.

## Durable state machine

The new phase-only journal uses content-addressed private blobs, canonical JSON,
an append-only transition history and one compare-and-swap head:

```text
ACTIVATED
  -> LOCAL_BRANCH_DURABLE
  -> RIVAL_RECORDED
  -> RACE_FROZEN
  -> SETTLEMENT_PREPARED
  -> STABLE
  \-> UNRECOVERABLE
```

Every head binds the fork epoch, canonical authority, retained parent, roster,
candidate projections, immutable frozen-set digest, selected Commit, successor,
settlement record and stable effect identifier. The successor and settlement
blobs are durable before the canonical-head CAS. A failed verification records
`UNRECOVERABLE` without replacing the last verified canonical authority or
emitting a success effect.

The pre-settlement canonical branch must remain the exact durable local branch.
If it wins, it is reloaded and preserved. If it loses, a fresh OpenMLS instance
reloads the retained parent, stages and re-authenticates the rival exact Commit,
checks the repeated projection and released bytes, applies the Commit, verifies
the rebuilt successor, persists settlement evidence and then performs one CAS.

Fresh Node processes, not only new JavaScript wrapper objects, perform the
retry, rival admission, freeze, settlement preparation and stable-head commit.
This exposed and corrected a harness lifetime bug where an un-awaited async
operation could outlive and lose its cleared binding. The corrected worker
awaits every operation before clearing private material.

## Crash and hostile-input evidence

The dedicated tests cover:

| Boundary | Result |
| --- | --- |
| no head / empty or foreign journal | typed fail closed |
| local branch durable, before rival | exact recovery |
| rival durable, before freeze | exact recovery |
| race frozen, before preparation | exact recovery |
| successor and settlement blobs durable, before head CAS | exact recovery |
| stable-head CAS, before effect acknowledgement | stable-ID retry, one effect |
| local Commit handed to delivery before durable acceptance | byte-identical retry |
| two settlement writers on one expected head | exactly one CAS succeeds |

Missing, empty, truncated, substituted or digest-mismatched retained authority
fails closed. The same holds for missing or corrupt local/rival Commit,
successor and settlement blobs. Tests also reject mutation of the authenticated
group, parent, epoch, account, signature key, authority, Commit, GroupContext,
priority, frozen set, candidate roles, candidate omission, third-candidate
extension and non-zero witness input. None of these failures changes canonical
authority.

The journal head is limited to 1 MiB, every provider blob to 8 MiB, every Commit
to 1 MiB and the complete private content-addressed blob store to 64 MiB per
peer. The store limit is checked before mutation. Candidate count is fixed at
two and the experiment permits at most two convergence passes per peer.

## Cross-engine result

The durable proof executes four scenarios:

- Styx wins, rival delivered after restart;
- Styx wins, rival delivered before restart;
- MDK wins, rival delivered after restart;
- MDK wins, rival delivered before restart.

In all four, both engines select the same exact Commit and final GroupContext,
the Styx journal reaches `STABLE`, the losing candidate remains `deferred`, and
one stable settlement effect is accepted. An injected crash after effect-sink
acceptance but before journal acknowledgement is retried with the same effect
identifier and does not duplicate the effect.

Two clean paired executions use disjoint groups and participant material. The
verifier compares their normalized ordered outcomes, not private or random
digests. Synthetic provider states, account material, full Commits and database
files are removed after each execution.

## Evidence and provenance

The public verdict records exact pins and artifact identity plus safe digests
and synthetic role labels. It does not record raw group IDs, account identities,
signature keys, roster members, MLS state, Commit bytes, plaintext or secrets.

The Rust MDK peer gained additive operations for this isolated experiment.
Existing B3.3b-1 operations and the one-candidate convergence assertion remain
unchanged. The Rust suite independently checks both identity assignments,
stored and pairwise paths, zero witnesses, replay behavior and the typed
winner-side stale classification.

## Non-claims and residual risk

- No three-candidate, deeper-branch, witness-scored or multi-pass convergence.
- No membership change, external Commit, PSK, ReInit, account rotation,
  multi-device, rejoin, missing-parent acquisition, pruning or compaction.
- No product, application-core, PWA, vault, worker, Nostr, relay, notification,
  media or reference-chat integration.
- No anonymity, metadata privacy, network convergence, production suitability,
  certification, audit inheritance or general Marmot conformance.
- The wrapper, journal and harness remain unaudited; `extensions-draft` remains
  experimental.
- Content digests detect corruption and provide CAS identity. They are not keyed
  authentication against a same-origin adversary and do not detect complete
  profile rollback.
- Retaining the parent and losing branch increases private-material lifetime.
  This bounded GO does not choose a production retention or compaction policy.
- The pinned Marmot revision has no normative durability contract. Fresh-process
  equivalence here is Styx engineering evidence at exact pins.

Exact-final-HEAD CI, independent agent review and the independent human security
review remain mandatory before this evidence can be merged. Rollback is deletion
of the isolated branch before merge or one atomic revert after merge; no product
database or migration exists.
