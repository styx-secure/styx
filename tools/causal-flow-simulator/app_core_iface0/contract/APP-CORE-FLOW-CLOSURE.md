# APP-CORE normative flow closure

Status: pre-ratification working analysis. This file is not repository
authority and authorizes no implementation or normative change.

## Purpose

The review model and C0.3 corpus enumerate exactly twelve flows. An interface
contract is incomplete unless every flow is either mapped to a closed
operation/scenario or rejected as an owned layer boundary. Merely listing the
flow as “covered” is insufficient.

## Exact flow relation

| Review-model flow | APP-CORE operation/scenario | APP-CORE claim | Boundary/non-claim |
| --- | --- | --- | --- |
| `author_application_event` | negative boundary in APP-CORE; future `APP-AUTHORING-IFACE-0`; the resulting signed transcript is accepted by `VALIDATE_TRANSCRIPT` | validates only already-produced canonical bytes | no signer, signing capability, random source, author intent or outbound state change |
| `authority_evidence_replay` | `REPLAY_CONTEXT`; equivalence witnesses through `EVALUATE_CANDIDATE` and `EVALUATE_EVIDENCE_UPDATE` | recomputes authority from the complete admitted closure | no cached authority verdict or caller-supplied authorization |
| `checkpoint_restore` | `REPLAY_CONTEXT/checkpoint-only-replay-dependency` negative scenario | non-empty checkpoint substitution is rejected/stale exactly as v0 requires | no checkpoint grant-side or restore authority |
| `credential_succession` | `EVALUATE_CANDIDATE` plus full `REPLAY_CONTEXT` equivalence | evaluates the complete control-event lineage | no possession/signature-to-AP-authority substitution |
| `fork_quarantine` | `EVALUATE_CANDIDATE` plus full `REPLAY_CONTEXT` equivalence | retains and replays authenticated fork evidence under the ratified lineage rules | no arrival-order winner or automatic recovery |
| `logical_removal` | `EVALUATE_CANDIDATE` plus full `REPLAY_CONTEXT` equivalence | evaluates authenticated logical removal only | no physical delete, erasure, custody or compliance claim |
| `missing_required_opening` | `EVALUATE_CANDIDATE` plus full `REPLAY_CONTEXT` equivalence | keeps REQUIRED content K-admitted and pending under the ratified rule | no timeout, fabricated opening or AP application |
| `receive_late_opening` | `EVALUATE_EVIDENCE_UPDATE` plus full `REPLAY_CONTEXT` equivalence | adds bounded raw evidence and recomputes the complete successor | no arbitrary evidence replacement/removal and no RS custody inference |
| `secure_session_receive` | negative boundary; after SS authentication/decryption the opaque plaintext is supplied as ordinary transcript/evidence input | APP-CORE independently validates K/AP bytes | SS membership, decryption or sender identity never proves K/AP validity |
| `secure_session_send` | negative boundary owned by future authoring plus SS adapter contracts | none | no protect/send/publish operation in APP-CORE |
| `transport_publish` | negative boundary owned by TR | none | relay acceptance, order or acknowledgement never changes K/AP state |
| `validate_and_fold` | `VALIDATE_TRANSCRIPT`, `EVALUATE_GENESIS`, `REPLAY_CONTEXT`, `EVALUATE_CANDIDATE`, and `EVALUATE_EVIDENCE_UPDATE`, according to the exact input class | deterministic bounded validation and one complete proposed successor | no durable commit or product/public-view authority |

The final hostile inventory must contain one positive or negative scenario for
every row above and must compare the literal twelve-element flow set for exact
equality. A wildcard, prose category or aggregate suite pass cannot satisfy a
flow.

## `F16-CANDIDATE` — prior-bound evidence-only updates

The original five-operation candidate is insufficient for the ratified
`receive_late_opening` flow. `REPLAY_CONTEXT` can recompute a full closure from
different evidence, but it does not bind that closure to the currently
authoritative prior. A caller could omit records or evidence and present the
result as an online update. `EVALUATE_CANDIDATE` cannot be reused because the
flow has no new application event; passing a duplicate event would conflate
idempotent event admission with new content/opening material.

The recommended sixth evaluator-only operation is:

```text
EVALUATE_EVIDENCE_UPDATE
```

with the following closed input relation:

```text
EvaluateEvidenceUpdateInputV0 {
  prior: ProposedContextSnapshotV0
  additions: EvidenceAdditionSetV0
}

EvidenceAdditionSetV0 {
  contentMaterial: [ContentMaterialEvidenceV0]
  openingMaterial: [OpeningEvidenceV0]
}
```

Both arrays are bounded, canonical and non-empty as a set. They contain raw
material only for event references already present in the revalidated prior.
The operation revalidates the complete prior first and then permits only this
monotone relation:

- a previously absent content object may be added;
- a previously absent opening may be added;
- an exact already-present object is idempotent;
- a new non-overlapping content segment may be added;
- any removal, replacement, partial overlap, conflicting duplicate,
  cross-event substitution or evidence for an unknown event fails closed.

The result uses the same adapter/RS commit lifecycle as candidate evaluation
but not its K-retention/single-primary result. Its operation-scoped deterministic
capacity rejection is not an O-10 S6 primary, and O-08 accounting is never
treated as RS commit. It has a distinct closed rejected/idempotent/additive
union and contains at most one complete successor.
Full replay over the prior record closure plus the resulting complete evidence
set must be byte-identical to that successor. Evidence presence, completeness
and commitment verification remain independent axes; the operation cannot
accept `available`, `verified`, `complete`, `committed` or equivalent caller
oracles. `APP-CORE-EVIDENCE-UPDATE-CANDIDATE.md` records the finite candidate.

This pure relation proves only an extensional update against the exact supplied
prior; it authorizes no online mutation. The future supported adapter must
source the authoritative prior from authenticated local acceptance state and
revalidate it inside the same abstract RS lifecycle. Omission, substitution,
staleness and cross-context reuse of that prior fail closed.

## Required hostile atoms for `F16-CANDIDATE`

At minimum the ratified inventory must name distinct scenarios and source
mutants for:

1. omit one prior record while adding a valid opening;
2. delete one prior content segment;
3. replace one prior opening;
4. add an opening under the wrong event reference;
5. add content under an unknown reference;
6. conflicting exact-offset segment;
7. partially overlapping segment;
8. duplicate exact segment (idempotent);
9. duplicate exact opening (idempotent);
10. complete late opening changes `PENDING_OPENING` only after recomputation;
11. late content without opening remains non-applied where required;
12. opening without complete content remains non-applied;
13. zero-length content is distinct from absent content;
14. caller-supplied availability/verification/commit fields are rejected;
15. precommit successor is never exposed as durably applied;
16. RS `NOT_COMMITTED` and `INDETERMINATE` never release the successor.
17. prior omission, stale-prior, cross-context prior and caller-substituted prior
    are each rejected before commit.

## Ratification effect

Selecting this relation changes the candidate registry from five to six pure
evaluator operations. It does not add authoring, signing, SS, RS, TR, storage,
wire, SDK or product behavior. Rejecting it requires another explicit
prior-bound mechanism for `receive_late_opening`; leaving the flow to
`REPLAY_CONTEXT` plus caller discipline is not an acceptable alternative.
