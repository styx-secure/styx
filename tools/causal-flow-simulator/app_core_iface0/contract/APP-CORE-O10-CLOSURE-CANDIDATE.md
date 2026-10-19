# APP-CORE O-10 three-axis and S6 closure candidate

Status: pre-ratification candidate. This file is not repository authority and
authorizes no implementation or normative edit. It is the finite proposed
resolution of `OPEN-F13` and `OPEN-F14` for independent falsification and a
human decision.

## Selected interpretation proposed for review

1. O-10 `mutation` is clarified as **AP transition effect**, not whole-context
   retention authority.
2. K-evidence retention is a separate closed axis.
3. Every newly retained candidate or evidence update produces exactly one
   complete successor proposal. A would-be `APPLIED` candidate must
   additionally pass the already-ratified deterministic O-08 S6 checks inside
   the pure evaluation. Every successor proposal, regardless of primary, must
   then pass the same adapter/RS commit lifecycle. O-08 S6 capacity accounting
   and the RS commit result are distinct gates owned by different layers;
   neither substitutes for the other.
4. A pure core never emits a final `APPLIED` and never claims that any
   successor has been durably accepted.
5. A final O-10 primary for a successor-bearing evaluation is released only
   after the local authenticated RS boundary has returned `COMMITTED` for the
   exact proposal. Deterministic S6 checks run, and may replace the primary,
   only on the would-be `APPLIED` path fixed by O-10; no S6 result is computed
   or fabricated for any other `RETAIN_NEW` primary.
6. `NOT_COMMITTED` produces no final O-10 primary and preserves the prior.
   `INDETERMINATE` produces no final O-10 primary, releases nothing and halts
   the context. These are adapter/RS lifecycle results, not new O-10 primaries.

No O-10 classification, stage or precedence is amended: the existing
event-local/S5/stale classification of a `RETAIN_NEW` row is exact and never
provisional, and S6 remains reachable only for a candidate that would otherwise
be `APPLIED`. Only the release of the final primary and the installation of the
successor await finalization: an adapter/RS refusal withholds publication and
preserves the prior without creating, replacing or reordering any O-10 primary.
This publication gate is adapter-owned behavior outside O-10; it still requires
independent review and the human gate before use, but reopens neither O-10 nor
O-08.

## Closed axis tokens

```text
ApTransitionEffectV0 = APPLY | DO_NOT_APPLY
KRetentionEffectV0 = RETAIN_NEW | ALREADY_RETAINED | DO_NOT_RETAIN
CoreResultKindV0 = TERMINAL_NO_SUCCESSOR | PROPOSAL_READY
```

`ALREADY_RETAINED` is legal only for exact `DUPLICATE` and produces no new
successor. An evidence-only exact duplicate is handled by
`EVALUATE_EVIDENCE_UPDATE` as an idempotent no-successor result and does not
change this candidate-event table.

## Literal 25-row relation

The machine-readable relation also carries `existingO10Stage` for every row.
That field is copied from, and must remain exactly equal to, the pinned O-10
taxonomy; it is not inferred from owner, mutation or core-result kind.

| Primary | Existing O-10 mutation | AP effect | K retention | Core result | Same-bytes rule after finalization | Scenario | Mutant |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `APPLIED` | `APPLIED` | `APPLY` | `RETAIN_NEW` | `PROPOSAL_READY` | `NONE` | `F13-APPLIED` | `M-F13-APPLIED-WITHOUT-RETENTION` |
| `AUTHENTIC_BUT_UNAUTHORIZED` | `NOT_APPLIED` | `DO_NOT_APPLY` | `RETAIN_NEW` | `PROPOSAL_READY` | `DIFFERENT_CANDIDATE_BYTES` | `F13-AUTHENTIC-BUT-UNAUTHORIZED` | `M-F13-DISCARD-UNAUTHORIZED-K-EVIDENCE` |
| `AUTHORITY_PROJECTION_UNAVAILABLE` | `NOT_APPLIED` | `DO_NOT_APPLY` | `RETAIN_NEW` | `PROPOSAL_READY` | `AUTHORITY_CAPABILITY_RESTORED` | `F13-AUTHORITY-UNAVAILABLE` | `M-F13-DROP-K-EVIDENCE-WHEN-AUTHORITY-UNAVAILABLE` |
| `COMMITMENT_MISMATCH` | `NOT_APPLIED` | `DO_NOT_APPLY` | `DO_NOT_RETAIN` | `TERMINAL_NO_SUCCESSOR` | `DIFFERENT_CANDIDATE_BYTES` | `F13-COMMITMENT-MISMATCH` | `M-F13-RETAIN-COMMITMENT-MISMATCH` |
| `CONTEXT_CAPACITY_EXHAUSTED` | `NOT_APPLIED` | `DO_NOT_APPLY` | `DO_NOT_RETAIN` | `TERMINAL_NO_SUCCESSOR` | `NEW_CONTEXT_OR_RATIFIED_PROFILE` | `F13-CONTEXT-CAPACITY` | `M-F13-RETAIN-OVER-CAPACITY` |
| `CREDENTIAL_BINDING_MISMATCH` | `NOT_APPLIED` | `DO_NOT_APPLY` | `DO_NOT_RETAIN` | `TERMINAL_NO_SUCCESSOR` | `DIFFERENT_CANDIDATE_BYTES` | `F13-CREDENTIAL-BINDING-MISMATCH` | `M-F13-RETAIN-BINDING-MISMATCH` |
| `CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED` | `NOT_APPLIED` | `DO_NOT_APPLY` | `DO_NOT_RETAIN` | `TERMINAL_NO_SUCCESSOR` | `DIFFERENT_CANDIDATE_BYTES` | `F13-CREDENTIAL-ID-COLLISION` | `M-F13-RETAIN-CREDENTIAL-ID-COLLISION` |
| `CURRENT_OBJECT_OUT_OF_PROFILE` | `NOT_APPLIED` | `DO_NOT_APPLY` | `DO_NOT_RETAIN` | `TERMINAL_NO_SUCCESSOR` | `NEW_CONTEXT_OR_RATIFIED_PROFILE` | `F13-OUT-OF-PROFILE` | `M-F13-RETAIN-OUT-OF-PROFILE` |
| `DEPENDENCY_DEFERRED` | `NOT_APPLIED` | `DO_NOT_APPLY` | `DO_NOT_RETAIN` | `TERMINAL_NO_SUCCESSOR` | `AUTHENTICATED_DEPENDENCY_STATE_CHANGED` | `F13-DEPENDENCY-DEFERRED` | `M-F13-RETAIN-DEFERRED-CANDIDATE` |
| `DUPLICATE` | `NOT_APPLIED` | `DO_NOT_APPLY` | `ALREADY_RETAINED` | `TERMINAL_NO_SUCCESSOR` | `NONE` | `F13-DUPLICATE` | `M-F13-DUPLICATE-CREATES-SUCCESSOR` |
| `FORK_EVIDENCE` | `NOT_APPLIED` | `DO_NOT_APPLY` | `RETAIN_NEW` | `PROPOSAL_READY` | `RATIFIED_LINEAGE_STATE_CHANGED` | `F13-FORK-EVIDENCE` | `M-F13-DISCARD-FORK-EVIDENCE` |
| `INVALID` | `NOT_APPLIED` | `DO_NOT_APPLY` | `DO_NOT_RETAIN` | `TERMINAL_NO_SUCCESSOR` | `DIFFERENT_CANDIDATE_BYTES` | `F13-INVALID` | `M-F13-RETAIN-INVALID` |
| `LENGTH_MISMATCH` | `NOT_APPLIED` | `DO_NOT_APPLY` | `DO_NOT_RETAIN` | `TERMINAL_NO_SUCCESSOR` | `DIFFERENT_CANDIDATE_BYTES` | `F13-LENGTH-MISMATCH` | `M-F13-RETAIN-LENGTH-MISMATCH` |
| `LINEAGE_QUARANTINED` | `NOT_APPLIED` | `DO_NOT_APPLY` | `RETAIN_NEW` | `PROPOSAL_READY` | `RATIFIED_LINEAGE_STATE_CHANGED` | `F13-LINEAGE-QUARANTINED` | `M-F13-DISCARD-QUARANTINED-EVIDENCE` |
| `OPENING_MISSING` | `NOT_APPLIED` | `DO_NOT_APPLY` | `DO_NOT_RETAIN` | `TERMINAL_NO_SUCCESSOR` | `VERIFIED_OPENING_PRESENT` | `F13-DETACHABLE-OPENING-MISSING` | `M-F13-RETAIN-DETACHABLE-WITHOUT-OPENING` |
| `PENDING_ANCESTOR` | `NOT_APPLIED` | `DO_NOT_APPLY` | `RETAIN_NEW` | `PROPOSAL_READY` | `AUTHENTICATED_DEPENDENCY_STATE_CHANGED` | `F13-PENDING-ANCESTOR` | `M-F13-DISCARD-PENDING-DESCENDANT` |
| `PENDING_OPENING` | `NOT_APPLIED` | `DO_NOT_APPLY` | `RETAIN_NEW` | `PROPOSAL_READY` | `VERIFIED_OPENING_PRESENT` | `F13-REQUIRED-PENDING-OPENING` | `M-F13-DISCARD-REQUIRED-PENDING-ROOT` |
| `POST_REVOCATION` | `NOT_APPLIED` | `DO_NOT_APPLY` | `RETAIN_NEW` | `PROPOSAL_READY` | `DIFFERENT_CANDIDATE_BYTES` | `F13-POST-REVOCATION` | `M-F13-DISCARD-POST-REVOCATION-EVIDENCE` |
| `PROFILE_ACTIVATION_UNSUPPORTED` | `NOT_APPLIED` | `DO_NOT_APPLY` | `DO_NOT_RETAIN` | `TERMINAL_NO_SUCCESSOR` | `NEW_CONTEXT_OR_RATIFIED_PROFILE` | `F13-PROFILE-UNSUPPORTED` | `M-F13-RETAIN-UNSUPPORTED-PROFILE` |
| `REFERENCE_COLLISION_UNSUPPORTED` | `NOT_APPLIED` | `DO_NOT_APPLY` | `DO_NOT_RETAIN` | `TERMINAL_NO_SUCCESSOR` | `DIFFERENT_CANDIDATE_BYTES` | `F13-REFERENCE-COLLISION` | `M-F13-SELECT-COLLISION-WINNER` |
| `REMOVAL_INAPPLICABLE` | `NOT_APPLIED` | `DO_NOT_APPLY` | `RETAIN_NEW` | `PROPOSAL_READY` | `DIFFERENT_CANDIDATE_BYTES` | `F13-REMOVAL-INAPPLICABLE` | `M-F13-DISCARD-INAPPLICABLE-REMOVAL` |
| `STALE_EVIDENCE` | `NOT_APPLIED` | `DO_NOT_APPLY` | `RETAIN_NEW` | `PROPOSAL_READY` | `FRESH_LIVE_EVIDENCE_PRESENT` | `F13-STALE-LIVE-EVIDENCE` | `M-F13-CHECKPOINT-SUBSTITUTES-OR-DROPS-LIVE-EVIDENCE` |
| `STRUCTURAL_REJECTION` | `NOT_APPLIED` | `DO_NOT_APPLY` | `DO_NOT_RETAIN` | `TERMINAL_NO_SUCCESSOR` | `DIFFERENT_CANDIDATE_BYTES` | `F13-STRUCTURAL-REJECTION` | `M-F13-RETAIN-STRUCTURAL-REJECTION` |
| `UNRESOLVABLE_CREDENTIAL` | `NOT_APPLIED` | `DO_NOT_APPLY` | `DO_NOT_RETAIN` | `TERMINAL_NO_SUCCESSOR` | `DIFFERENT_CANDIDATE_BYTES` | `F13-UNRESOLVABLE-CREDENTIAL` | `M-F13-RETAIN-UNRESOLVABLE-CREDENTIAL` |
| `UNRESOLVED_CREDENTIAL_BINDING` | `NOT_APPLIED` | `DO_NOT_APPLY` | `DO_NOT_RETAIN` | `TERMINAL_NO_SUCCESSOR` | `DIFFERENT_CANDIDATE_BYTES` | `F13-UNRESOLVED-BINDING` | `M-F13-RETAIN-UNRESOLVED-BINDING` |

The ten `RETAIN_NEW` rows are exact: `APPLIED`,
`AUTHENTIC_BUT_UNAUTHORIZED`, `AUTHORITY_PROJECTION_UNAVAILABLE`,
`FORK_EVIDENCE`, `LINEAGE_QUARANTINED`, `PENDING_ANCESTOR`,
`PENDING_OPENING`, `POST_REVOCATION`, `REMOVAL_INAPPLICABLE` and
`STALE_EVIDENCE`. The ratified model must compare this literal set, the
25-primary set and every row tuple for exact equality.

Exact existing-stage partition:

```text
FINAL_AFTER_S6:
  APPLIED
S0_PROFILE_ACTIVATION:
  PROFILE_ACTIVATION_UNSUPPORTED
S3_KERNEL_STRUCTURAL:
  COMMITMENT_MISMATCH, CREDENTIAL_BINDING_MISMATCH,
  CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED, CURRENT_OBJECT_OUT_OF_PROFILE,
  DUPLICATE, INVALID, LENGTH_MISMATCH, OPENING_MISSING,
  REFERENCE_COLLISION_UNSUPPORTED, STRUCTURAL_REJECTION,
  UNRESOLVABLE_CREDENTIAL, UNRESOLVED_CREDENTIAL_BINDING
S4_GRAPH_ADMISSION|S6_DURABLE_COMMIT:
  CONTEXT_CAPACITY_EXHAUSTED, DEPENDENCY_DEFERRED
S5_AUTHORITY_PROJECTION:
  AUTHORITY_PROJECTION_UNAVAILABLE
POST_S3_REPLAY_EVIDENCE:
  STALE_EVIDENCE
EVENT_LOCAL:
  AUTHENTIC_BUT_UNAUTHORIZED, FORK_EVIDENCE, LINEAGE_QUARANTINED,
  PENDING_ANCESTOR, PENDING_OPENING, POST_REVOCATION,
  REMOVAL_INAPPLICABLE
```

`STALE_EVIDENCE` is structurally unreachable in v0: O-07 fixes checkpoint
evidence as structurally empty and O-08 selects `CHECKPOINT_REFERENCES=0`. Its
`RETAIN_NEW` classification is a reserved, unexercised candidate row pending
human ratification. `POST_S3_REPLAY_EVIDENCE` precedes `S4_GRAPH_ADMISSION` in
the pinned selection order, so no S4 graph-admission capacity gate currently
supports this retention. Any decision that makes checkpoint evidence reachable
already reopens O-07 and its dependents and must re-falsify this row, including
an explicit deterministic capacity bound for evidence retained under a stale
projection, before the row may be exercised.

## Closed precommit result

The serializable evaluator returns one of:

```text
CandidateEvaluationResultV0 =
  { kind: TERMINAL_NO_SUCCESSOR,
    primary: one exact no-successor primary,
    stage: exact O-10 stage }
| { kind: PROPOSAL_READY,
    primaryOnCommit: one exact RETAIN_NEW primary,
    proposal: ProposedApplicationDeltaV0 }
```

`primaryOnCommit` is a deterministic prediction, not a current/final outcome
or capability. The field name and schema must make that distinction explicit.
It is never accepted back as input and is recomputed during finalization.

## Adapter-owned finalization relation

```text
FinalizeResultV0 =
  { kind: FINALIZED,
    primary: recomputed primaryOnCommit,
    successor: locally applied exact successor }
| { kind: S6_REJECTED,
    primary: CONTEXT_CAPACITY_EXHAUSTED | DEPENDENCY_DEFERRED }
| { kind: RS_NOT_COMMITTED }
| { kind: RS_INDETERMINATE }
```

- `FINALIZED` requires an authenticated `COMMITTED` capability bound to the
  exact prior, successor, profile, namespace, purpose and operation. No O-11
  wire/storage mutation container exists at this increment; the binding is
  abstract, and any later O-11 container must bind at least this same tuple
  without weakening it.
- `S6_REJECTED` exists only for a proposal whose `primaryOnCommit` is `APPLIED`,
  arises from deterministic S6 revalidation before the RS commit attempt and
  preserves the prior; it is unreachable for every other `RETAIN_NEW` primary.
- `RS_NOT_COMMITTED` preserves the prior and releases no final O-10 primary,
  successor or escrowed output. Because no O-10 primary was finalized, no O-10
  same-bytes recovery class attaches; the adapter alone owns retry, and any
  retry re-enters the complete pure evaluation from the current prior.
- `RS_INDETERMINATE` preserves no guessed truth, releases nothing and moves the
  adapter context to `HALTED`. Only an RS-owned recovery procedure that resolves
  the exact transaction to `COMMITTED` or `NOT_COMMITTED` may clear `HALTED`;
  the APP adapter never guesses, retries automatically or continues from
  ambiguous advanced state.
- The same core proposal is revalidated immediately before finalization. A
  caller-supplied primary, S6 result, RS enum, boolean, digest or structural
  lookalike is never authority. If revalidation does not reproduce the exact
  proposal and predicted `primaryOnCommit` against the exact prior,
  finalization aborts fail-closed: no RS commit is attempted, no final primary,
  successor or escrowed output is released, and the prior is preserved.
- Every `FinalizeResultV0` kind is trusted-boundary information only. This
  increment selects no remote projection for it; any later profile exposing an
  adapter lifecycle result to an untrusted peer must collapse every
  non-`FINALIZED` kind into the existing `OPAQUE_REMOTE_FAILURE` boundary owned
  by O-10 and its future acknowledgement profile.

## Mandatory cross-axis and finality mutants

In addition to the 25 row mutants, the ratified inventory must kill distinct
mutants for:

1. infer K retention from O-10 `mutation`;
2. infer AP effect from K retention;
3. retain every authenticated candidate;
4. discard every non-`APPLIED` candidate;
5. create two independently mutable K/AP deltas;
6. emit final `APPLIED` from the pure core;
7. expose `primaryOnCommit` as a final/current result;
8. fabricate, require or consume an O-10 S6 result for a non-AP-transition
   retained candidate, or skip S6 on the would-be `APPLIED` path;
9. commit K evidence without its recomputed AP projection;
10. commit AP transition without all required K evidence;
11. mutate authoritative APP state and authoritative SS state in one operation
    at this increment, or apply an APP successor whose invariant requires a
    jointly committed SS mutation without that mutation in the same OB-RS03
    atomic mutation set;
12. apply an SS successor through this contract, which owns no SS mutation; the
    concrete one-container APP/SS composition is selected only at the
    supported-adapter increment;
13. treat `NOT_COMMITTED` as a final O-10 result;
14. continue or retry automatically after `INDETERMINATE`;
15. release plaintext/ciphertext/Commit/Welcome before `COMMITTED`;
16. substitute proposal, prior, profile, namespace, purpose or operation at
    finalization;
17. let auxiliary evidence upgrade any axis or primary;
18. retry same bytes after a finalized outcome without its exact O-10
    precondition.
19. emit a primary at a different stage while preserving every other row
    field.

## Review questions that must be answered explicitly

1. Does retaining K-admitted evidence in the ten listed rows match the already
   ratified O-01/O-02 semantics, especially whole-projection unavailable and
   stale states?
2. Is the proposed S6 refinement the minimal coherent repair, or should the
   owning O-10 decision instead define a separate evidence-retention outcome
   plane?
3. Does withholding a final O-10 primary on `NOT_COMMITTED`/`INDETERMINATE`
   preserve O-10 without creating an unreported application result?
4. Does the separate evidence-update relation correctly avoid fabricating K
   retention or one synthetic primary while using the same adapter/RS lifecycle
   without conflating its operation-scoped capacity result with O-10 S6?

Any answer that changes a row, stage, precedence or retry rule requires a
literal amended table, new hostile scenarios, independent re-falsification and
the human gate. The executor may not choose among interpretations.
