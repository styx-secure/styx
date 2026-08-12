# Phase B2.5c — bounded retained-history convergence

Date: 2026-08-12

Status: experimental, isolated, non-product proof

Authority: Issue #159 and its approved one-use write-ahead liveness amendment;
Phase B Epic #128

Base: `838e09898f889299963820018368f331611ee439`

## 1. Result

B2.5c demonstrates that Styx can retain a bounded OpenMLS history, discover
exact Commit parentage by replay, and deterministically reconsider branches
after later input arrives. Clients receiving the same admissible Commit set in
different orders and cutoff partitions converge on the same Commit path,
epoch and GroupContext. A deeper branch wins before the frozen B2.5a tip order;
a late same-depth higher-ranked sibling supersedes the earlier choice.

The proof records explicit invalidation, retained-state release and canonical
transition evidence. It also retains bounded local publication generations so
own echoes and late acknowledgements remain tied to the exact historical
Commit. Contradictory publication evidence and missing in-horizon material
terminalize the group as `UNRECOVERABLE` without changing its canonical MLS
epoch, snapshot, anchor or path.

A separate write-ahead ledger proves one bidirectional application-message
exchange at each client's selected fresh epoch instance. Reservation is durable
before encryption. The same instance can never encrypt twice, including after
restart, crash, supersession or re-adoption. This is a liveness probe, not the
production sender-ratchet persistence required for normal messaging.

## 2. Exact dependencies and provenance

| Component | Exact identity |
|---|---|
| Styx base | `838e09898f889299963820018368f331611ee439` |
| Base tree | `12707bb365bf7663029993a6c21efb5ad4700a56` |
| OpenMLS | `09e92777dba0528d3d29e2e5e681b7e91637c7be` |
| Marmot specification | `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1` |
| Installed WASM SHA-256 | `60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a` |
| Ciphersuite | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` |
| Database namespace | `styx-b2-5c-poc-v1-` |

The implementation is independently Styx-authored from public protocol facts.
No MDK/Darkmatter source, audit material, fixture, vector, example or prose was
copied or adapted. No upstream audit coverage transfers to Styx, its WASM
wrapper, this journal or this configuration.

## 3. Authority boundary

The journal factory accepts only the isolated B2.5c namespace. Public methods
admit exact Commit bytes, create explicit cutoffs, record generation-scoped
publication facts and read state. Initialization, settlement, preparation,
generation replacement and publication append are journal-private closures
captured only by its bound adapter.

No public method accepts a claimed parent, priority, committer, projection,
authorization verdict, selected digest, successor snapshot, invalidation
result, acknowledgement boolean or liveness result. Parentage comes only from
real replay; projection and B2.4 authorization are recomputed against that
exact parent. Transport metadata, origin, arrival order, timestamps and cutoff
identity never enter branch comparison.

The pinned WASM implementation and caller-attested publication evidence remain
trusted inputs. A real transport acknowledgement and recipient delivery proof
are outside this increment.

## 4. Retained graph and deterministic order

The durable anchor is the oldest complete provider state inside the five-edge
rewind horizon. A pass freezes all retained raw inputs and eligible local
generation Commit digests. Replay uses disposable providers and excludes local
pending snapshots from the parent candidate set.

For each exact Commit:

1. zero successful parents yields `DEFERRED`, or `STALE` once its only possible
   parent is older than the retained anchor;
2. one successful parent creates an edge only after fresh projection, exact
   candidate epoch binding and complete B2.4 authorization;
3. more than one successful parent produces `AMBIGUOUS` and no edge; and
4. a closed engine or policy rejection produces `REJECTED`.

Fixed-point discovery permits child-before-parent arrival. A defensive second
pass retests newly reachable states so an edge cannot remain accepted after a
second parent becomes available.

All branches start at the anchor and sort by maximum depth first. Equal-depth
tips use the unchanged B2.5a tuple:

```text
(priority, authenticated account identity, SHA-256(exact MLS Commit bytes))
```

An empty branch is valid when no input attaches. Selection never lowers the
canonical epoch.

## 5. Supersession, invalidation and release

Settlement restores the winning retained state rather than transplanting any
application ciphertext or side effect. The invalidation record binds the prior
head, common ancestor, displaced path, selected path and successor. The
transition binds that invalidation, the frozen pass, release set, new anchor,
epoch and GroupContext.

When the selected path reaches six edges, the first edge becomes the new anchor
and the canonical suffix remains exactly five edges. The transaction retains
all states and edges reachable from that anchor, including alternate branches,
plus pending snapshots required by active or eligible local generations. Only
unreachable snapshots that were already durable at the start of settlement
receive content-bound release tombstones; newly replayed but unselected
successors are simply not persisted. Unreachable edges are deleted and their
inputs become `STALE`. Released private bytes are no longer returned, but
this logical deletion is not claimed to be physical secure erasure or an
independently measured forward-secrecy improvement.

A state required by the canonical suffix, a deferred reachable branch, an
active or eligible local generation or recovery is never silently evicted.
Missing required state produces an atomic `MARK_UNRECOVERABLE` head transition. The
transition changes only terminal status and sequence; canonical MLS state does
not move.

## 6. Local generations

Local preparation preserves the clean parent, pending provider snapshot, exact
Commit, projection, verified-leaf digest and B2.4 decision. Eligible local
replay restores the pending provider and invokes `confirm_pending_commit`; it
never stages the member's own Commit through the inbound API.

A stable generation-authority digest covers immutable preparation identity:
group, monotonic ordinal, parent head/state, pending state and exact Commit.
Replay edges bind that stable authority even though the generation record's
content digest changes with attempts, acknowledgements and final disposition.
Publication evidence itself binds the exact record version against which it was
appended.

History holds at most 16 live generation records. When full, preparation may
evict only the oldest `CANCELLED`, `DISCARDED` or `REJECTED` generation that is
not referenced by an eligible replay edge. Its publication evidence and
unneeded pending private state are removed atomically. The latest bounded
truncation marker records the evicted generation authority and final digest and
digest-links its predecessor; older marker records are not retained by this PoC.
Later historical requests fail as `UNKNOWN_GENERATION` and expose the current
marker as diagnostic evidence. If no safe terminal record exists, preparation
fails before mutation with `RESOURCE_LIMIT`.

## 7. Write-ahead liveness probe

The one-use probe key binds group, selected tip, epoch, GroupContext and local
member identity. Its flow is:

1. read and verify the selected retained tip;
2. add-if-absent the reservation in its own durable transaction;
3. only after commit, restore a disposable provider and encrypt once;
4. optionally append completion evidence after the ciphertext exists; and
5. discard the post-send provider without serializing it.

Reservation survives restart and supersession. Recovery of an already probed
tip relies on prior evidence and refuses another encryption. A crash after step
2 is deliberately unavailable rather than risking key/nonce reuse, and does
not become false liveness evidence. A strictly deeper re-adopted tip has a new
epoch instance and may reserve exactly once.

The ledger holds at most 16 reservations and performs no eviction in this
proof. It is selection-inert and must not be inherited as production sender
state. Normal multi-message operation requires a separate write-ahead sender-
ratchet persistence design.

## 8. Durable schema and atomicity

The isolated database contains:

| Store | Purpose |
|---|---|
| `canonical-head` | sequence, terminal state and canonical MLS binding |
| `retained-state` | complete replayable provider states |
| `released-state` | logical-release tombstones |
| `commit-input` | exact inbound bytes and disposition |
| `replay-edge` | parent/successor and fresh policy evidence |
| `settlement-pass` | immutable cutoff and result |
| `canonical-transition` | predecessor/successor, path and release authority |
| `invalidation-evidence` | displaced and selected branch binding |
| `local-generation` | exact local preparation and lifecycle |
| `generation-truncation` | bounded latest marker with predecessor-digest linkage |
| `active-local` | single active generation pointer |
| `publication-evidence` | exact generation-scoped facts |
| `probe-reservation` | one-use emitted-epoch reservation |
| `probe-completion` | optional completed liveness evidence |

All durable families use closed direct objects, exact fields, bounded values,
domain-separated canonical encodings and content digests. Provider states bind
exact bytes, length, epoch, GroupContext, account and MLS signing key.

The settlement transaction CAS-protects the complete read set: head, anchor,
retained/released states, frozen closure, all input and edge records,
transitions, invalidations, local generations, truncation marker, active pointer
and publication evidence. Newly admitted input or discovered durable evidence
changes the read-set digest and forces a complete retry. State, edge, input,
generation, pass, invalidation, transition, release and head writes are atomic.

## 9. Executable evidence

The focused Jest suite covers real-WASM evidence for:

- child-before-parent delivery and zero/one/ambiguous parent classification;
- three cutoff partitions and multiple arrival orders converging to the same
  path, epoch and GroupContext;
- depth-first selection, sibling supersession and deeper branch re-adoption;
- exact five-edge anchor advancement, stale beyond-anchor input, bounded graph
  counts and `RELEASED` reads;
- historical own echo and late acknowledgement across newer generations;
- contradiction and missing-anchor `UNRECOVERABLE` terminalization without MLS
  state movement;
- rollback and deterministic retry when every settlement store write fails;
- complete read-set CAS when input arrives during replay;
- 16-generation truncation, evidence eviction and typed unknown generation;
- strict unknown-field rejection and exact raw-input overflow rollback;
- bidirectional application-message liveness, one-use restart refusal, crash
  after reservation, and deeper-tip re-adoption; and
- unchanged canonical selection under probe activity.

Playwright opens separate connections from separate pages and races both final
settlement and one probe reservation. Chromium and Firefox each produce one
winner and one typed CAS/refusal outcome, with no skipped test.

Exact candidate-head full-suite, CI, independent-agent and human-review results
belong on the PR. This pre-merge report does not claim they passed before they
do.

## 10. Rejected alternatives

- **Caller-supplied parent or verdict:** rejected as untrusted authority.
- **Relay order, timestamp or cutoff as branch order:** rejected because peers
  do not share those local observations.
- **Unbounded history:** rejected as a private-material and resource risk.
- **Delete old state without tombstones:** rejected because release must remain
  distinguishable from corruption.
- **Replay local Commit inbound:** rejected because own Commit confirmation uses
  the retained pending handle.
- **Encrypt, then reserve:** rejected because a crash could repeat a sender
  generation.
- **Persist the post-probe provider as normal sender state:** rejected because
  B2.5c does not specify production ratchet recovery, migration or concurrency.
- **Treat an interrupted reservation as liveness:** rejected because no
  ciphertext completion is durable.

## 11. Residual risks and non-claims

B2.5c does not provide:

- real Nostr/Marmot transport, recipient-authenticated delivery, Welcome flow,
  push, anonymity or metadata privacy;
- business-rule authorization, application-ledger effects, payload merge or
  product invalidation;
- production sender-ratchet persistence or general application messaging;
- full Marmot/MDK interoperability, fork witnesses, quorum or multi-device
  reconciliation;
- journal authentication against malicious same-origin code, an external
  rollback anchor, secure erasure or storage-eviction protection;
- defense against XSS, hostile extensions, compromised origin/browser/OS or
  injected dependencies;
- automatic repair from `UNRECOVERABLE`; or
- audit coverage, production readiness or suitability for real sensitive data.

Provider serialization may produce byte-distinct snapshots for the same
logical epoch and GroupContext. Fresh replay therefore compares logical and
security evidence and reuses an already durable edge when those bindings are
identical; byte identity is not treated as a protocol identity. The explicit
ambiguous-parent guard remains fail closed when one Commit attaches to two
retained parents.

## 12. Next increment

Production work must keep this proof isolated. The next security decision is a
separate sender-ratchet persistence contract: write-ahead generation state,
crash recovery, multi-context exclusion, migration, bounds and rollback
behavior for normal multi-message operation. B2.5c's reservation ledger is
evidence for the ordering requirement, not its implementation.
