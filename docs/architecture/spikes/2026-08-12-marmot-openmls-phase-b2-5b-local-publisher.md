# Phase B2.5b — publish-before-apply local Commit arbitration

Date: 2026-08-12

Status: experimental, isolated, non-product proof

Authority: Issue #157 and its approved narrow security/evidence amendment;
Phase B Epic #128
Base: `44f953e79e8f61632b528a0a2b1ffbe5fe965cb7`

## 1. Result

B2.5b proves that an authorized local MLS Commit can be prepared and retried
without changing the canonical MLS head, becomes arbitration-eligible only
after exact typed acknowledgement evidence is durable, and then competes under
the same authenticated B2.5a order as inbound one-Commit children of the exact
retained parent.

When local wins, the adapter confirms the exact pending Commit. When inbound
wins, it merges only the selected sibling from the separately retained clean
parent and atomically terminalizes the losing pending annex. Cross-admission
evidence shows that clients receiving exact Commit C through acknowledged local
state or inbound replay derive the same batch identity, candidate tuple, winner,
successor epoch and GroupContext and retain bidirectional MLS message liveness.

This is not full convergence. In particular, different cutoff partitions may
select different same-parent branches; B2.5b detects the later earlier-parent
input but cannot rewind. B2.5c must add retained-history supersession.

## 2. Exact dependencies and provenance

| Component | Exact identity |
|---|---|
| Styx base | `44f953e79e8f61632b528a0a2b1ffbe5fe965cb7` |
| Base tree | `bc4d0c697d0d6a9f3f1c53cbd4ee5d3fb3c4d22f` |
| OpenMLS | `09e92777dba0528d3d29e2e5e681b7e91637c7be` |
| Marmot specification | `4ad4ae21479c3f3fa9950c6fc4556a76941a62e1` |
| Installed WASM SHA-256 | `60dbbc1127fbfb0e7e479cf7e2f7e6e20183c60d0559268f039d8db58bf60a3a` |
| Ciphersuite | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` |
| Database namespace | `styx-b2-5b-poc-v1-` |

The implementation is independently Styx-authored from public protocol facts.
No MDK/Darkmatter source, audit material, fixture, vector, example or prose was
copied or adapted. No upstream audit coverage transfers to Styx, the wrapper,
this journal or its configuration.

## 3. Trust and authority boundary

The journal factory rejects databases outside the isolated namespace. The
public journal can queue one bounded intent, retain exact inbound bytes and read
state. Initialization, pending-state publication mutation and final resolution
are private closures captured only by the journal-created adapter. The public
coordinator exposes actions, not verdict inputs: no caller can supply priority,
committer, projection, parent metadata, candidate validity, selected digest,
successor snapshot, acknowledgement boolean or arbitrary artifact bytes.

The initialized pinned WASM object and caller-attested publication evidence are
trusted inputs to this proof. The ACK binds a prior durable attempt, exact
Commit digest and bytes, recipient-scope digest, and one authenticated prior
member. It does **not** cryptographically prove recipient delivery or a real
relay/HTTP/Nostr outcome. A hostile injected engine or lying evidence source is
outside the modeled boundary.

## 4. Publish-before-apply lifecycle

The canonical head has only `STABLE` and `UNRECOVERABLE`. Local lifecycle is a
separate record:

| Local state | Canonical effect | Permitted next action |
|---|---|---|
| `QUEUED` | none | one preparation opportunity |
| `PREPARED` | none | attempt or pre-attempt cancel |
| `PUBLISHING` without ACK | none | exact retry; failure evidence; explicit discard after failure |
| `ACKNOWLEDGED` | none | admission at a later explicit cutoff |
| `CANCELLED` / `DISCARDED` | none | terminal; late ACK retained as contradiction |
| active frozen local | none until atomic resolution | deterministic evaluation |
| `CONFIRMED` | selected successor | historical terminal state |
| `CLEARED_LOST` / `CLEARED_REJECTED` | inbound/null outcome | historical terminal state |

Preparation persists both an exact clean-parent retained state and an exact
pending provider snapshot. Publication attempts always read the stored Commit;
there is no API for replacement bytes. Duplicate outcomes are idempotent by
attempt, recipient and semantic kind even if caller payload bytes differ. Every
terminal local state is immutable: later ACK/failure evidence cannot change its
state, disposition or counters. ACK dominates all failure evidence and
permanently disables discard. A remote ACK that is never recorded locally is
deliberately modeled as ambiguous: restart keeps the head unchanged and permits
only exact retry.

Freeze-time eligibility is immutable. An ACK arriving after cutoff does not
enter that batch. An inbound-only batch may freeze while the same-parent local
record is `PREPARED` or `PUBLISHING`; if that batch advances the head, the
excluded local record is atomically terminalized as
`CLEARED_LOST / LOSING_OUTSIDE_BATCH`. A later ACK is retained as
`LATE_ACK`, never silently applied. An ACK already durable at cutoff always
admits the local Commit to that same batch.

## 5. Candidate derivation and application

For a local candidate the adapter restores the exact pending snapshot, loads
the bound identity/group, obtains the pending projection, independently restores
the clean parent, and re-runs the full B2.4 authorization and decision binding.
It checks exact Commit, parent epoch/GroupContext, candidate epoch/GroupContext,
verified-leaf digest, operation, authenticated committer and recipient scope.

Inbound candidates use fresh clean-parent replay as in B2.5a. Local and inbound
evidence share the same byte shape; origin is excluded from comparison identity.
The only order is:

```text
(0 for authorized Add/Remove or 1 for self-update,
 authenticated 32-byte account identity,
 SHA-256(exact Commit bytes))
```

The local winner is re-derived and confirmed from pending. The inbound winner
is re-staged, re-projected, reauthorized and merged from a disposable clean
parent restore. Clearing pending is never used to reconstruct that parent.

The pinned group constructor establishes one founder administrator and exposes
no administrator-policy mutation surface. Real-WASM evidence therefore proves
contested local Add and Remove wins over authorized inbound self-updates, plus
both winning and losing contested local self-updates under authenticated
identity order. It also proves the losing-local path with an authorized
self-update against a lower-priority administrator Add. It cannot construct two
distinct authorized priority-0 administrators, so it makes no general
Add/Remove-loss claim and does not fake that unsupported topology.

## 6. Durable schema and atomicity

The database has exactly eight stores:

| Store | Authority |
|---|---|
| `head` | local canonical sequence, epoch, GroupContext and retained snapshot |
| `retained-state` | exact clean, pending and successor provider states |
| `input` | exact inbound Commit bytes and disposition |
| `frozen-batch` | immutable cutoff identity and closed result |
| `candidate-evidence` | B2.4 decision and B2.5a tuple bindings |
| `transition` | predecessor, winner, outcomes and successor |
| `local-pending` | intent, pending annex, obligation and terminal disposition |
| `publication-evidence` | exact attempt/ACK/failure/late-ACK facts |

B2.5b-local records use closed direct objects, exact field sets, bounded counts
and byte lengths, closed terminal-disposition/counter bindings,
domain-separated canonical encoding and SHA-256 digests. Publication records
recheck their artifact digest against their exact bytes, and a new attempt is
rejected before the 64-record evidence cap would strand it without outcome
capacity. Failure evidence cannot consume the final slot reserved for a later
acknowledgement. The
cross-member protocol-batch and comparison-tuple identities deliberately retain
the frozen B2.5a domains. Unknown fields/states, duplicate sorted identities,
unsafe counters, corrupt digests and incoherent nullable bindings fail closed.

Engine work occurs on disposable providers outside the transaction. The final
transaction re-reads the full head, transition, retained parent, local pending,
publication evidence, batch, every input and every candidate placeholder. It
also treats the observed absence of local pending state as part of the CAS
read-set, so a concurrently appearing local operation forces a retry. It
then atomically writes candidate outcomes, input dispositions, local terminal
state, selected retained state, transition and head. Injected failure at every
logical store written by preparation, freeze, publication and finalization
leaves the exact durable predecessor and permits deterministic retry.

## 7. Executable evidence

The focused Jest suite covers:

- exact eight-store/namespace and absent public finalizer boundaries;
- non-canonical local preparation, attempt and ambiguous retry;
- real authorized local self-update, Add and Remove, including contested
  Add/Remove wins and self-update win/loss;
- local winner, inbound winner and clean-parent losing-pending path;
- exact local/inbound cross-admission equivalence and bidirectional liveness;
- active and terminal `own_echo` before input creation;
- success, failure, two-step discard, payload-independent duplicate ACK, ACK
  dominance, immutable post-terminal ACK/failure evidence, wrong
  attempt/recipient and ACK-before-attempt;
- byte-identical retry and restart from queued, prepared, ambiguous
  publication, acknowledged and frozen states;
- two successive attempted and acknowledged local generations with outcome
  lookup bound to each generation's exact Commit digest;
- freeze-time ACK eligibility and post-cutoff durable input;
- strict codec corruption/unknown/overflow/duplicate rejection for all eight
  record families, plus negative cross-record binding evidence;
- rollback during preparation, freeze, publication and every logical-store
  final write;
- an inbound-only resolution racing a newly prepared local operation, proving
  that local absence is CAS-protected and the retry closes the loser safely;
- the 64-record boundary, including outcome capacity before an attempt and a
  final acknowledgement slot that failure evidence cannot consume;
- idempotent historical resolution and no double application;
- a sequential pass against the selected head, terminal closure of failed
  preparation, and reservation of one local slot within the 16-candidate cap;
  and
- explicit cross-partition divergence plus no-rewind `NOT_CANDIDATE` closure.

The Playwright suite runs with no skips on Chromium and Firefox. Separate pages
open separate connections to the same IndexedDB and race (a) publication of one
exact attempt and (b) final arbitration after both evaluators have crossed a
barrier. Exactly one CAS write succeeds in each race; the durable record contains
one attempt and one successor.

Exact candidate-head test, CI, independent-agent and human-review results belong
on PR #158. This pre-merge document does not claim they passed before they do.

## 8. Rejected alternatives

- **Confirm after send invocation:** rejected because invocation is not durable
  acknowledgement and crash ambiguity could apply an unpublished branch.
- **Accept a caller success boolean:** rejected because it would be an authority
  finalizer with no evidence binding.
- **Stage the local Commit inbound:** rejected by the pinned engine as
  `OwnCommit` and semantically wrong for pending confirmation.
- **Clear pending, then reconstruct parent:** rejected because own path state is
  irreversibly consumed; the clean parent is retained independently.
- **Order by ACK time, attempt id or origin:** rejected because local transport
  facts are not shared protocol authority.
- **Let a late ACK mutate a frozen set:** rejected because selection would depend
  on evaluation timing rather than explicit cutoff.
- **Claim convergence across cutoff partitions:** rejected because B2.5b has no
  retained-history rewind or supersession.

## 9. Residual risks and non-claims

B2.5b does not provide:

- real transport acknowledgement, recipient delivery, NIP-59/kind-445,
  metadata privacy, anonymity or push;
- full Marmot/MDK interoperability or convergence;
- cutoff closure, fair production scheduling, background execution or liveness;
- retained-history rewind, multi-Commit branches, witnesses, quorum or scoring;
- Welcome delivery, group creation, multi-device, rejoin or key rotation;
- journal MAC, external anchor, rollback detection, secure erasure or storage
  persistence/eviction protection;
- defense against malicious same-origin code, XSS/extensions, compromised
  browser/OS or hostile injected dependencies;
- pruning or forward-secrecy material-release guarantees; or
- audit coverage or readiness for real sensitive data.

Whole provider snapshots intentionally retain private MLS material. Primitive
bounds reused from B2.3 may retain `B23_*` error codes even though all B2.5b
record identities and domains are new; they still fail closed and grant no
authority.

## 10. Next increment

B2.5c must add a bounded retained-history index, explicit rewind/supersession,
late same-parent reconsideration, material-retention/release rules and tests that
make branch selection independent of admissible cutoff partitioning. Nothing in
B2.5b silently supplies those properties.
