# APP-CORE evidence-update result candidate

Status: pre-ratification working analysis. This corrects a discovered
cross-operation conflation; it is not repository authority.

## Why candidate-event results cannot be reused literally

`EVALUATE_CANDIDATE` evaluates one new signed event, so its three axes include
whether that candidate is newly retained as K evidence. An evidence-only update
adds content/opening material for records already in the revalidated closure.
It may change several record outcomes at once and retains no new K event.

Therefore the 25-row candidate-event relation and its single
`primaryOnCommit` cannot be copied onto an evidence-update result. Doing so
would falsely claim `RETAIN_NEW` for an existing event or select one primary for
a potentially multi-record replay.

## Closed candidate result

```text
EvidenceUpdateResultV0 =
  { kind: TERMINAL_REJECTED,
    reason: EvidenceUpdateRejectionV0 }
| { kind: IDEMPOTENT_NO_CHANGE }
| { kind: PROPOSAL_READY,
    evidenceEffect: ADD_MONOTONE,
    proposal: ProposedApplicationDeltaV0 }
```

Candidate closed rejection registry:

```text
PRIOR_REVALIDATION_FAILED
EMPTY_ADDITION_SET
UNKNOWN_EVENT_REFERENCE
DELETION_FORBIDDEN
REPLACEMENT_FORBIDDEN
PARTIAL_OVERLAP
CONFLICTING_DUPLICATE
NONCANONICAL_MATERIAL
EVIDENCE_COMMITMENT_MISMATCH
RESOURCE_LIMIT
FULL_REPLAY_MISMATCH
```

These are conformance-plane operation reasons, not automatically SDK/wire
errors and not replacements for per-record O-10 outcomes. Review may merge a
reason only by providing an exact total mapping that preserves the distinct
hostile constructions.

Rejection-registry tokens are disjoint by construction from the closed O-10
primary registry, so both registries stay fail-closed under O-10's
unknown-token rule.

Rules:

- `IDEMPOTENT_NO_CHANGE` is legal only when every supplied item is byte-exact
  material already present under the same event/purpose relation.
- Any new valid non-overlapping item selects `ADD_MONOTONE`, even if the same
  call also contains exact duplicates.
- The proposal contains the only complete successor; there is no changed-item,
  affected-record or selected-primary sibling field.
- Full replay recomputes every per-record O-10 outcome in that successor. No
  single outcome is promoted as the update operation result.
- A terminal rejection and an idempotent no-change never enter O-11/RS.

## Adapter finalization

```text
FinalizeEvidenceUpdateV0 =
  { kind: EVIDENCE_UPDATE_FINALIZED,
    successor: locally applied exact complete successor }
| { kind: CAPACITY_REJECTED,
    reason: UPDATE_CAPACITY_EXHAUSTED }
| { kind: RS_NOT_COMMITTED }
| { kind: RS_INDETERMINATE }
```

Only exact-bound `COMMITTED` yields `EVIDENCE_UPDATE_FINALIZED`. It releases the
committed APP-facing projection selected by the later SDK contract, not a
synthetic single O-10 primary. `NOT_COMMITTED` preserves the prior;
`INDETERMINATE` releases nothing and halts.

`CAPACITY_REJECTED` reuses the deterministic O-08 durable-capacity accounting
unchanged, but its reason is an operation-scoped conformance token, never an
O-10 primary; an evidence-only update emits no operation-level O-10 primary. A
deferred-dependency arm may be added only with an exact deterministic
definition; none exists at this increment.

The pure evidence-update relation is extensional only: it proves the relation
against the exact supplied prior and authorizes no online update. A future
supported adapter must source that prior from authenticated local acceptance
state, bind it into the same abstract RS mutation, and revalidate it immediately
before commit. Prior omission, substitution, staleness and cross-context reuse
must all fail closed.

Every `FinalizeEvidenceUpdateV0` kind is trusted-boundary information only. A
future profile exposing it to an untrusted peer must collapse every
non-`EVIDENCE_UPDATE_FINALIZED` kind into `OPAQUE_REMOTE_FAILURE`.

## Required hostile evidence

In addition to the sixteen `OPEN-F16` cases, kill distinct mutants that:

1. emit candidate `KRetentionEffectV0` for evidence-only material;
2. choose one changed record's primary as the whole update outcome;
3. include an affected-record/changed-subset list beside the complete successor;
4. treat a mixed duplicate-plus-new set as idempotent;
5. treat an exact duplicate as a new proposal;
6. release a recomputed record outcome before RS commit;
7. commit the APP projection without its O-04 custody changes; and
8. emit `EVIDENCE_UPDATE_FINALIZED` on `NOT_COMMITTED` or `INDETERMINATE`;
9. omit, substitute, stale or cross-bind the authoritative prior;
10. use an O-10 primary as an evidence-update rejection or capacity token; and
11. release any lifecycle distinction across an untrusted boundary.

Independent review and the human gate must ratify or replace this exact
operation-specific relation before APP-CORE-IFACE-0 execution.
