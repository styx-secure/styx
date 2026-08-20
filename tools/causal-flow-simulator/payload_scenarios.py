"""Required payload-state hostile families for the C0.2f bounded gate."""

from __future__ import annotations

from dataclasses import replace
from itertools import product

from model import (
    CausalModel,
    CheckpointEvidence,
    Context,
    CredentialAuthority,
    Event,
    ModelInputError,
    Profile,
    evaluation_json,
)
from payload_model import (
    Availability,
    BindingObservation,
    CheckpointDisposition,
    ChunkGeometry,
    CommitmentShape,
    ContentClass,
    ContentDescriptor,
    DirectiveOutcome,
    PayloadCheckpoint,
    PayloadModel,
    PayloadObservation,
    PayloadProfile,
    PayloadRecord,
    PresentationState,
    ReplayReadiness,
    RemovalClaim,
    RetentionState,
    SymbolicCommitmentVector,
    payload_evaluation_json,
    symbolic_chunk_terms,
    symbolic_commitment_term,
)


CTX = Context("example.app", "payload-bounded-v0", "case-1", b"g")
GRANT_A = b"ga"
GRANT_B = b"gb"
GRANT_C = b"gc"
NONE_OBSERVATION = PayloadObservation(
    Availability.ABSENT, BindingObservation.NOT_APPLICABLE
)
VERIFIED = PayloadObservation(Availability.PRESENT, BindingObservation.VERIFIED)
MISSING = PayloadObservation(Availability.ABSENT, BindingObservation.NOT_CHECKED)


def causal_model(
    *,
    b_revocations: tuple[bytes, ...] = (),
    proven_extra: tuple[bytes, ...] = (),
    heads: tuple[tuple[bytes, int, bytes], ...] = (),
) -> CausalModel:
    return CausalModel(
        context=CTX,
        authorities=(
            CredentialAuthority(b"a", CTX, GRANT_A),
            CredentialAuthority(b"b", CTX, GRANT_B, b_revocations),
            CredentialAuthority(b"c", CTX, GRANT_C),
        ),
        checkpoint=CheckpointEvidence(
            CTX,
            frozenset((GRANT_A, GRANT_B, GRANT_C, *proven_extra)),
            author_heads=heads,
        ),
        profile=Profile(),
    )


def first(
    reference: bytes,
    credential: bytes,
    grant: bytes,
    *,
    parents: tuple[bytes, ...] = (),
    kind: str = "action",
) -> Event:
    return Event(
        reference,
        CTX,
        credential,
        0,
        None,
        tuple(sorted((grant, *parents))),
        kind,
    )


def next_event(
    reference: bytes,
    credential: bytes,
    sequence: int,
    predecessor: bytes,
    *,
    parents: tuple[bytes, ...] = (),
    kind: str = "action",
) -> Event:
    return Event(
        reference,
        CTX,
        credential,
        sequence,
        predecessor,
        tuple(sorted(parents)),
        kind,
    )


def descriptor(
    content_class: ContentClass,
    token: bytes,
    *,
    length: int = 3,
    shape: CommitmentShape = CommitmentShape.SINGLE,
    geometry: ChunkGeometry | None = None,
) -> ContentDescriptor:
    if content_class is ContentClass.NONE:
        return ContentDescriptor.none()
    return ContentDescriptor(
        content_class,
        "example.content",
        length,
        "abstract-v0",
        shape,
        token,
        geometry,
    )


def record(
    reference: bytes, content_class: ContentClass, token: bytes
) -> PayloadRecord:
    return PayloadRecord(reference, descriptor(content_class, token))


def removal_fixture(
    target_class: ContentClass = ContentClass.DETACHABLE,
) -> tuple[
    Event,
    Event,
    object,
    tuple[PayloadRecord, PayloadRecord],
    dict[bytes, PayloadObservation],
]:
    target = first(b"a0", b"a", GRANT_A)
    directive = first(
        b"r0", b"b", GRANT_B, parents=(target.reference,), kind="remove"
    )
    causal = causal_model().evaluate((directive, target))
    target_record = record(target.reference, target_class, b"target")
    directive_record = PayloadRecord(
        directive.reference,
        ContentDescriptor.none(),
        RemovalClaim(target.reference, b"target"),
    )
    target_observation = (
        NONE_OBSERVATION if target_class is ContentClass.NONE else VERIFIED
    )
    return (
        target,
        directive,
        causal,
        (target_record, directive_record),
        {target.reference: target_observation, directive.reference: NONE_OBSERVATION},
    )


def extend_required_suite(suite: object) -> None:
    """Append the sixteen C0.2f obligations to the existing suite object."""

    payload = PayloadModel()

    # 1 and 13: availability changes projection observations, never causal facts.
    detachable = first(b"d0", b"a", GRANT_A)
    causal = causal_model().evaluate((detachable,))
    causal_fingerprint = evaluation_json(causal)
    records = (record(detachable.reference, ContentClass.DETACHABLE, b"det"),)
    absent = payload.evaluate(causal, records, {detachable.reference: MISSING}, {})
    present = payload.evaluate(causal, records, {detachable.reference: VERIFIED}, {})
    suite.check(
        "payload availability leaves graph order and AP application invariant",
        absent.applied_order == present.applied_order == causal.order
        and evaluation_json(causal) == causal_fingerprint
        and absent.halted_at == present.halted_at
        and absent.states[detachable.reference].presentation
        is PresentationState.ACTIVE_UNAVAILABLE
        and present.states[detachable.reference].presentation
        is PresentationState.ACTIVE_VERIFIED,
        family="payload-availability-invariance",
        trace=(detachable,),
        obligation="C0.2f-01",
    )
    suite.check(
        "availability-divergent replicas do not create event forks",
        causal.decisions[detachable.reference].status.value == "admitted"
        and causal.decisions[detachable.reference].fork_peers == (),
        family="availability-not-fork",
        trace=(detachable,),
        obligation="C0.2f-13",
    )

    # 2: checkpoint contents are availability-independent; eligibility is not.
    required = first(b"q0", b"a", GRANT_A)
    causal_required = causal_model().evaluate((required,))
    required_records = (record(required.reference, ContentClass.REQUIRED, b"req"),)
    horizon = PayloadCheckpoint((required.reference,))
    checkpoint_missing = payload.evaluate(
        causal_required, required_records, {required.reference: MISSING}, {}, horizon
    )
    checkpoint_present = payload.evaluate(
        causal_required, required_records, {required.reference: VERIFIED}, {}, horizon
    )
    missing_without_checkpoint = payload.evaluate(
        causal_required, required_records, {required.reference: MISSING}, {}
    )
    present_without_checkpoint = payload.evaluate(
        causal_required, required_records, {required.reference: VERIFIED}, {}
    )
    blocking_required = first(b"p0", b"a", GRANT_A)
    deferred_horizon_member = first(b"z0", b"b", GRANT_B)
    causal_deferred_horizon = causal_model().evaluate(
        (deferred_horizon_member, blocking_required)
    )
    deferred_horizon_records = (
        record(blocking_required.reference, ContentClass.REQUIRED, b"blocking"),
        record(
            deferred_horizon_member.reference,
            ContentClass.REQUIRED,
            b"horizon",
        ),
    )
    deferred_horizon_observations = {
        blocking_required.reference: MISSING,
        deferred_horizon_member.reference: VERIFIED,
    }
    emittable_deferred_horizon = payload.evaluate(
        causal_deferred_horizon,
        deferred_horizon_records,
        deferred_horizon_observations,
        {},
        PayloadCheckpoint((deferred_horizon_member.reference,)),
    )
    deferred_horizon_without_checkpoint = payload.evaluate(
        causal_deferred_horizon,
        deferred_horizon_records,
        deferred_horizon_observations,
        {},
    )
    suite.check(
        "checkpoint contents ignore producer availability while eligibility changes",
        checkpoint_missing.checkpoint.contents == checkpoint_present.checkpoint.contents
        and checkpoint_missing.checkpoint.disposition
        is CheckpointDisposition.PRODUCER_INELIGIBLE
        and checkpoint_present.checkpoint.disposition
        is CheckpointDisposition.EMITTABLE,
        family="checkpoint-availability",
        trace=(required,),
        obligation="C0.2f-02",
    )
    availability_projection_equal = (
        checkpoint_missing.checkpoint is not None
        and checkpoint_present.checkpoint is not None
        and not checkpoint_missing.checkpoint.consumer_substitution
        and not checkpoint_present.checkpoint.consumer_substitution
        and replace(checkpoint_missing, checkpoint=None)
        == missing_without_checkpoint
        and replace(checkpoint_present, checkpoint=None)
        == present_without_checkpoint
    )
    emittable_deferred_projection_equal = (
        emittable_deferred_horizon.checkpoint is not None
        and emittable_deferred_horizon.checkpoint.disposition
        is CheckpointDisposition.EMITTABLE
        and emittable_deferred_horizon.halted_at == blocking_required.reference
        and emittable_deferred_horizon.states[
            deferred_horizon_member.reference
        ].readiness
        is ReplayReadiness.CONTENT_DEFERRED
        and emittable_deferred_horizon.states[
            deferred_horizon_member.reference
        ].presentation
        is PresentationState.DEFERRED
        and replace(emittable_deferred_horizon, checkpoint=None)
        == deferred_horizon_without_checkpoint
    )
    suite.check(
        "availability-divergent checkpoint production never substitutes consumer state",
        availability_projection_equal and emittable_deferred_projection_equal,
        family="checkpoint-non-substitution",
        trace=(
            (required,)
            if not availability_projection_equal
            else (blocking_required, deferred_horizon_member)
        ),
        obligation="C0.2f-12",
    )
    checkpoint_child = first(
        b"q1", b"b", GRANT_B, parents=(required.reference,)
    )
    checkpoint_grandchild = first(
        b"q2", b"c", GRANT_C, parents=(checkpoint_child.reference,)
    )
    checkpoint_chain = causal_model().evaluate(
        (checkpoint_grandchild, checkpoint_child, required)
    )
    checkpoint_chain_records = (
        required_records[0],
        record(checkpoint_child.reference, ContentClass.DETACHABLE, b"child"),
        record(
            checkpoint_grandchild.reference,
            ContentClass.DETACHABLE,
            b"grandchild",
        ),
    )
    proper_subset_horizon = payload.evaluate(
        checkpoint_chain,
        checkpoint_chain_records,
        {
            required.reference: MISSING,
            checkpoint_child.reference: VERIFIED,
            checkpoint_grandchild.reference: VERIFIED,
        },
        {},
        PayloadCheckpoint((checkpoint_grandchild.reference,)),
    )
    suite.check(
        "checkpoint eligibility covers the causal closure of its horizon",
        proper_subset_horizon.checkpoint is not None
        and proper_subset_horizon.checkpoint.disposition
        is CheckpointDisposition.PRODUCER_INELIGIBLE
        and not proper_subset_horizon.checkpoint.producer_eligible
        and {
            item[0] for item in proper_subset_horizon.checkpoint.contents
        }
        == {
            required.reference.hex(),
            checkpoint_child.reference.hex(),
            checkpoint_grandchild.reference.hex(),
        },
        family="checkpoint-availability",
        trace=(required, checkpoint_child, checkpoint_grandchild),
        obligation="C0.2f-02",
    )

    # 3 and 4: a REQUIRED hole defers the complete suffix and resumes exactly.
    later = first(b"z0", b"b", GRANT_B, parents=(required.reference,))
    causal_chain = causal_model().evaluate((later, required))
    chain_records = (
        required_records[0],
        record(later.reference, ContentClass.DETACHABLE, b"later"),
    )
    old_observations = {required.reference: MISSING, later.reference: VERIFIED}
    new_observations = {required.reference: VERIFIED, later.reference: VERIFIED}
    blocked = payload.evaluate(causal_chain, chain_records, old_observations, {})
    resumed = payload.evaluate(causal_chain, chain_records, new_observations, {})
    boundary, incremental = payload.incremental(
        causal_chain,
        causal_chain,
        blocked,
        chain_records,
        chain_records,
        old_observations,
        new_observations,
        {},
        {},
    )
    suite.check(
        "unavailable REQUIRED content defers the whole canonical suffix",
        blocked.halted_at == required.reference
        and blocked.applied_order == ()
        and blocked.states[later.reference].presentation is PresentationState.DEFERRED,
        family="required-deferral",
        trace=(required, later),
        obligation="C0.2f-04",
    )
    suite.check(
        "availability recovery incremental replay equals fresh full replay",
        boundary == 0 and incremental == resumed and resumed.applied_order == causal_chain.order,
        family="payload-replay-equivalence",
        trace=(required, later),
        obligation="C0.2f-03",
    )
    detachable_prefix_records = (
        record(required.reference, ContentClass.DETACHABLE, b"required"),
        chain_records[1],
    )
    detachable_prefix = payload.evaluate(
        causal_chain,
        detachable_prefix_records,
        old_observations,
        {},
    )
    record_boundary, record_incremental = payload.incremental(
        causal_chain,
        causal_chain,
        detachable_prefix,
        detachable_prefix_records,
        chain_records,
        old_observations,
        old_observations,
        {},
        {},
    )
    suite.check(
        "prefix record changes force incremental replay to the fresh full result",
        record_boundary == 0
        and record_incremental == blocked
        and detachable_prefix.applied_order == causal_chain.order
        and blocked.halted_at == required.reference,
        family="payload-replay-equivalence",
        trace=(required, later),
        obligation="C0.2f-03",
    )
    final_snapshot = resumed.snapshots[-1]
    forged_snapshot = replace(
        final_snapshot,
        states=tuple(
            (
                reference,
                replace(state, retention=RetentionState.LOGICALLY_REMOVED),
            )
            if reference == required.reference
            else (reference, state)
            for reference, state in final_snapshot.states
        ),
    )
    forged_resumed = replace(
        resumed,
        snapshots=(*resumed.snapshots[:-1], forged_snapshot),
    )
    suite.check_raises(
        "incremental replay rejects a count-preserving forged old evaluation",
        lambda: payload.incremental(
            causal_chain,
            causal_chain,
            forged_resumed,
            chain_records,
            chain_records,
            new_observations,
            new_observations,
            {},
            {},
        ),
        family="payload-replay-equivalence",
        trace=(required, later),
        obligation="C0.2f-03",
    )
    halt_target = first(b"h0", b"a", GRANT_A)
    halt_required = first(
        b"h1", b"b", GRANT_B, parents=(halt_target.reference,)
    )
    halt_directive = first(
        b"h2",
        b"c",
        GRANT_C,
        parents=(halt_required.reference,),
        kind="remove",
    )
    halt_causal = causal_model().evaluate(
        (halt_directive, halt_required, halt_target)
    )
    halt_records = (
        record(halt_target.reference, ContentClass.DETACHABLE, b"halt-target"),
        record(halt_required.reference, ContentClass.REQUIRED, b"halt-required"),
        PayloadRecord(
            halt_directive.reference,
            ContentDescriptor.none(),
            RemovalClaim(halt_target.reference, b"halt-target"),
        ),
    )
    halted_directive = payload.evaluate(
        halt_causal,
        halt_records,
        {
            halt_target.reference: VERIFIED,
            halt_required.reference: MISSING,
            halt_directive.reference: NONE_OBSERVATION,
        },
        {halt_directive.reference: True},
    )
    suite.check(
        "removal in a REQUIRED-deferred suffix cannot affect an earlier target",
        halted_directive.halted_at == halt_required.reference
        and halted_directive.directive_outcomes[halt_directive.reference]
        is DirectiveOutcome.DEFERRED_BY_REQUIRED_SUFFIX
        and halted_directive.states[halt_target.reference].retention
        is RetentionState.ACTIVE
        and halt_directive.reference not in halted_directive.applied_order,
        family="required-bypass",
        trace=(halt_target, halt_required, halt_directive),
        obligation="C0.2f-11",
    )

    # 5: exercise the complete local product of minimum observation axes.
    content_bearing_legal = {
        (Availability.ABSENT, BindingObservation.NOT_CHECKED),
        (Availability.PARTIAL, BindingObservation.NOT_CHECKED),
        (Availability.PRESENT, BindingObservation.NOT_CHECKED),
        (Availability.PRESENT, BindingObservation.VERIFIED),
        (Availability.PRESENT, BindingObservation.OPENING_MISSING),
        (Availability.PRESENT, BindingObservation.LENGTH_MISMATCH),
        (Availability.PRESENT, BindingObservation.COMMITMENT_MISMATCH),
    }
    none_legal = {
        (Availability.ABSENT, BindingObservation.NOT_APPLICABLE),
        (Availability.PRESENT, BindingObservation.NOT_APPLICABLE),
    }
    classification_matches = True
    for content_class in ContentClass:
        axis_records = (
            record(detachable.reference, content_class, b"axis"),
        )
        expected_legal = (
            none_legal
            if content_class is ContentClass.NONE
            else content_bearing_legal
        )
        for availability, binding in product(Availability, BindingObservation):
            suite.payload_explored()
            try:
                evaluated_axis = payload.evaluate(
                    causal,
                    axis_records,
                    {
                        detachable.reference: PayloadObservation(
                            availability, binding
                        )
                    },
                    {},
                )
                accepted = True
            except ModelInputError:
                accepted = False
            expected_acceptance = (availability, binding) in expected_legal
            classification_matches &= accepted == expected_acceptance
            if accepted:
                if content_class is ContentClass.NONE:
                    expected_presentation = (
                        PresentationState.NO_CONTENT
                        if availability is Availability.ABSENT
                        else PresentationState.UNEXPECTED_CONTENT_REJECTED
                    )
                elif (
                    content_class is ContentClass.REQUIRED
                    and binding is not BindingObservation.VERIFIED
                ):
                    expected_presentation = PresentationState.DEFERRED
                elif binding is BindingObservation.VERIFIED:
                    expected_presentation = PresentationState.ACTIVE_VERIFIED
                elif availability in (Availability.ABSENT, Availability.PARTIAL):
                    expected_presentation = PresentationState.ACTIVE_UNAVAILABLE
                elif binding in (
                    BindingObservation.LENGTH_MISMATCH,
                    BindingObservation.COMMITMENT_MISMATCH,
                ):
                    expected_presentation = (
                        PresentationState.ACTIVE_SUBSTITUTED_REJECTED
                    )
                else:
                    expected_presentation = PresentationState.ACTIVE_UNVERIFIABLE
                classification_matches &= (
                    evaluated_axis.states[detachable.reference].presentation
                    is expected_presentation
                )
    suite.check(
        "closed payload observation axes reject every unlisted combination",
        classification_matches,
        family="typed-axis-closure",
        trace=(detachable,),
        obligation="C0.2f-05",
    )
    none_supplied = payload.evaluate(
        causal_model().evaluate((detachable,)),
        (PayloadRecord(detachable.reference, ContentDescriptor.none()),),
        {
            detachable.reference: PayloadObservation(
                Availability.PRESENT, BindingObservation.NOT_APPLICABLE
            )
        },
        {},
    )
    suite.check(
        "bytes supplied for NONE are rejected as a typed non-content presentation",
        none_supplied.states[detachable.reference].presentation
        is PresentationState.UNEXPECTED_CONTENT_REJECTED
        and none_supplied.applied_order == causal.order,
        family="typed-axis-closure",
        trace=(detachable,),
        obligation="C0.2f-05",
    )
    noncanonical_none_record = PayloadRecord(
        detachable.reference,
        replace(ContentDescriptor.none(), content_type_id="unexpected"),
    )
    suite.check_raises(
        "non-canonical NONE descriptors fail closed before payload projection",
        lambda: payload.evaluate(
            causal_model().evaluate((detachable,)),
            (noncanonical_none_record,),
            {detachable.reference: NONE_OBSERVATION},
            {},
        ),
        family="typed-axis-closure",
        trace=(detachable,),
        obligation="C0.2f-05",
    )

    # 6 and 7: policy cannot remove REQUIRED and unauthorized directives do nothing.
    target, directive, causal_removal, required_removal_records, removal_observations = (
        removal_fixture(ContentClass.REQUIRED)
    )
    required_removal = payload.evaluate(
        causal_removal,
        required_removal_records,
        removal_observations,
        {directive.reference: True},
    )
    target_d, directive_d, causal_d, detachable_records, detachable_observations = (
        removal_fixture()
    )
    unauthorized = payload.evaluate(
        causal_d,
        detachable_records,
        detachable_observations,
        {directive_d.reference: False},
    )
    mismatched_records = (
        detachable_records[0],
        replace(
            detachable_records[1],
            removal=RemovalClaim(target_d.reference, b"wrong-commitment"),
        ),
    )
    commitment_mismatch = payload.evaluate(
        causal_d,
        mismatched_records,
        detachable_observations,
        {directive_d.reference: True},
    )
    authorized_without_checkpoint = payload.evaluate(
        causal_d,
        detachable_records,
        detachable_observations,
        {directive_d.reference: True},
    )
    checkpoint_with_directive = payload.evaluate(
        causal_d,
        detachable_records,
        detachable_observations,
        {directive_d.reference: True},
        PayloadCheckpoint(tuple(sorted(causal_d.order))),
    )
    suite.check(
        "authenticated directive cannot mutate or remove REQUIRED content",
        required_removal.directive_outcomes[directive.reference]
        is DirectiveOutcome.INAPPLICABLE_CLASS
        and required_removal.states[target.reference].retention is RetentionState.ACTIVE
        and required_removal_records[0].descriptor
        == record(target.reference, ContentClass.REQUIRED, b"target").descriptor,
        family="removal-policy",
        trace=(target, directive),
        obligation="C0.2f-06",
    )
    before_removal_state = unauthorized.states[target_d.reference]
    after_removal_state = authorized_without_checkpoint.states[target_d.reference]
    suite.check(
        "applied removal preserves every projected axis except retention and presentation",
        replace(
            after_removal_state,
            retention=before_removal_state.retention,
            presentation=before_removal_state.presentation,
        )
        == before_removal_state,
        family="removal-policy",
        trace=(target_d, directive_d),
        obligation="C0.2f-06",
    )
    suite.check(
        "unauthorized directive never produces logical removal",
        unauthorized.directive_outcomes[directive_d.reference]
        is DirectiveOutcome.UNAUTHORIZED
        and unauthorized.states[target_d.reference].retention is RetentionState.ACTIVE,
        family="removal-policy",
        trace=(target_d, directive_d),
        obligation="C0.2f-07",
    )
    suite.check(
        "removal target commitment mismatch cannot change retention",
        commitment_mismatch.directive_outcomes[directive_d.reference]
        is DirectiveOutcome.TARGET_COMMITMENT_MISMATCH
        and commitment_mismatch.states[target_d.reference].retention
        is RetentionState.ACTIVE,
        family="removal-policy",
        trace=(target_d, directive_d),
        obligation="C0.2f-06",
    )
    directive_checkpoint_term = next(
        item
        for item in checkpoint_with_directive.checkpoint.contents
        if item[0] == directive_d.reference.hex()
    )
    suite.check(
        "checkpoint contents commit to retained removal directives",
        directive_checkpoint_term[-1]
        == (
            "removal",
            target_d.reference.hex(),
            b"target".hex(),
        ),
        family="checkpoint-proof",
        trace=(target_d, directive_d),
        obligation="C0.2f-02",
    )
    suite.check(
        "emittable checkpoint never substitutes for consumer replay",
        checkpoint_with_directive.checkpoint is not None
        and checkpoint_with_directive.checkpoint.disposition
        is CheckpointDisposition.EMITTABLE
        and replace(checkpoint_with_directive, checkpoint=None)
        == authorized_without_checkpoint,
        family="checkpoint-non-substitution",
        trace=(target_d, directive_d),
        obligation="C0.2f-12",
    )

    # 8: removed presentations remain removed and distinguish binding evidence.
    presentation_cases = {
        MISSING: PresentationState.REMOVED,
        VERIFIED: PresentationState.REMOVED_PRESENTED_VERIFIED,
        PayloadObservation(
            Availability.PRESENT, BindingObservation.OPENING_MISSING
        ): PresentationState.REMOVED_PRESENTED_UNVERIFIABLE,
        PayloadObservation(
            Availability.PRESENT, BindingObservation.LENGTH_MISMATCH
        ): PresentationState.REMOVED_SUBSTITUTED_REJECTED,
    }
    presentations = set()
    remained_removed = True
    for observation, expected in presentation_cases.items():
        current = dict(detachable_observations)
        current[target_d.reference] = observation
        evaluated = payload.evaluate(
            causal_d,
            detachable_records,
            current,
            {directive_d.reference: True},
        )
        state = evaluated.states[target_d.reference]
        presentations.add(state.presentation)
        remained_removed &= (
            state.retention is RetentionState.LOGICALLY_REMOVED
            and state.presentation is expected
        )
    suite.check(
        "post-removal verified unverifiable and substituted presentations stay distinct",
        remained_removed and len(presentations) == len(presentation_cases),
        family="post-removal-presentation",
        trace=(target_d, directive_d),
        obligation="C0.2f-08",
    )

    # 9: causal compaction never substitutes for absent payload replay state.
    compacted = first(b"c0", b"a", GRANT_A)
    compacted_child = next_event(
        b"c1", b"a", 1, compacted.reference
    )
    compacted_causal = causal_model(
        proven_extra=(compacted.reference,),
        heads=((b"a", 0, compacted.reference),),
    ).evaluate((compacted_child,))
    compacted_records = (
        record(compacted_child.reference, ContentClass.DETACHABLE, b"child"),
    )
    compacted_observations = {compacted_child.reference: VERIFIED}
    without_checkpoint = payload.evaluate(
        compacted_causal,
        compacted_records,
        compacted_observations,
        {},
    )
    with_checkpoint = payload.evaluate(
        compacted_causal,
        compacted_records,
        compacted_observations,
        {},
        PayloadCheckpoint((compacted_child.reference,)),
    )
    compacted_boundary, compacted_incremental = payload.incremental(
        compacted_causal,
        compacted_causal,
        with_checkpoint,
        compacted_records,
        compacted_records,
        compacted_observations,
        compacted_observations,
        {},
        {},
        PayloadCheckpoint((compacted_child.reference,)),
    )
    suite.check(
        "fresh replica halts on compacted payload dependency with or without checkpoint",
        without_checkpoint.stale_dependencies == (compacted.reference,)
        and with_checkpoint.stale_dependencies == (compacted.reference,)
        and without_checkpoint.applied_order == with_checkpoint.applied_order == ()
        and without_checkpoint.states[compacted_child.reference].readiness
        is ReplayReadiness.STALE_EVIDENCE
        and with_checkpoint.states[compacted_child.reference]
        == without_checkpoint.states[compacted_child.reference]
        and with_checkpoint.checkpoint is not None
        and with_checkpoint.checkpoint.disposition
        is CheckpointDisposition.STALE_EVIDENCE
        and not with_checkpoint.checkpoint.producer_eligible
        and not with_checkpoint.checkpoint.consumer_substitution
        and compacted_boundary == 0
        and compacted_incremental == with_checkpoint,
        family="fresh-reconstruction",
        trace=(compacted, compacted_child),
        obligation="C0.2f-09",
    )
    stale_target = first(b"s2", b"b", GRANT_B)
    stale_directive = first(
        b"s3",
        b"c",
        GRANT_C,
        parents=(compacted_child.reference, stale_target.reference),
        kind="remove",
    )
    stale_causal = causal_model(
        proven_extra=(compacted.reference,),
        heads=((b"a", 0, compacted.reference),),
    ).evaluate((stale_directive, stale_target, compacted_child))
    stale_records = (
        compacted_records[0],
        record(stale_target.reference, ContentClass.DETACHABLE, b"stale-target"),
        PayloadRecord(
            stale_directive.reference,
            ContentDescriptor.none(),
            RemovalClaim(stale_target.reference, b"stale-target"),
        ),
    )
    stale_result = payload.evaluate(
        stale_causal,
        stale_records,
        {
            compacted_child.reference: VERIFIED,
            stale_target.reference: VERIFIED,
            stale_directive.reference: NONE_OBSERVATION,
        },
        {stale_directive.reference: True},
    )
    suite.check(
        "removal under stale causal evidence is deferred without changing retention",
        stale_result.directive_outcomes[stale_directive.reference]
        is DirectiveOutcome.DEFERRED_BY_STALE_EVIDENCE
        and stale_result.states[stale_target.reference].retention
        is RetentionState.ACTIVE
        and stale_result.applied_order == (),
        family="fresh-reconstruction",
        trace=(compacted, compacted_child, stale_target, stale_directive),
        obligation="C0.2f-09",
    )
    colliding_compacted = GRANT_C
    collision_consumer = first(
        b"k1", b"b", GRANT_B, parents=(colliding_compacted,)
    )
    collision_owner = first(b"k2", b"c", GRANT_C)
    collision_causal = causal_model(
        proven_extra=(colliding_compacted,)
    ).evaluate((collision_consumer, collision_owner))
    collision_records = tuple(
        record(reference, ContentClass.DETACHABLE, b"collision")
        for reference in collision_causal.order
    )
    collision_result = payload.evaluate(
        collision_causal,
        collision_records,
        {reference: VERIFIED for reference in collision_causal.order},
        {},
    )
    suite.check(
        "compacted dependency remains stale when its reference equals another authority grant",
        collision_result.stale_dependencies == (colliding_compacted,)
        and collision_result.halted_at == colliding_compacted
        and collision_result.applied_order == ()
        and all(
            state.readiness is ReplayReadiness.STALE_EVIDENCE
            for state in collision_result.states.values()
        ),
        family="compacted-reference-collision",
        trace=(collision_consumer, collision_owner),
        obligation="C0.2f-09",
    )
    predecessor_collision = next_event(b"k3", b"b", 1, GRANT_B)
    predecessor_collision_causal = causal_model(
        heads=((b"b", 0, GRANT_B),)
    ).evaluate((predecessor_collision,))
    predecessor_collision_result = payload.evaluate(
        predecessor_collision_causal,
        (
            record(
                predecessor_collision.reference,
                ContentClass.DETACHABLE,
                b"predecessor-collision",
            ),
        ),
        {predecessor_collision.reference: VERIFIED},
        {},
    )
    suite.check(
        "compacted author predecessor remains stale when it equals the event authority grant",
        predecessor_collision_result.stale_dependencies == (GRANT_B,)
        and predecessor_collision_result.halted_at == GRANT_B
        and predecessor_collision_result.applied_order == ()
        and predecessor_collision_result.states[
            predecessor_collision.reference
        ].readiness
        is ReplayReadiness.STALE_EVIDENCE,
        family="compacted-reference-collision",
        trace=(predecessor_collision,),
        obligation="C0.2f-09",
    )

    # 10: late authority evidence revokes a removal and incremental replay restores.
    old_auth = {directive_d.reference: True}
    old_payload = payload.evaluate(
        causal_d, detachable_records, detachable_observations, old_auth
    )
    authority_change = first(b"z0", b"c", GRANT_C, kind="revoke-b")
    new_causal = causal_model(b_revocations=(authority_change.reference,)).evaluate(
        (authority_change, directive_d, target_d)
    )
    new_records = (
        *detachable_records,
        PayloadRecord(authority_change.reference, ContentDescriptor.none()),
    )
    new_observations = dict(detachable_observations)
    new_observations[authority_change.reference] = NONE_OBSERVATION
    new_auth = {directive_d.reference: False}
    full_after_change = payload.evaluate(
        new_causal, new_records, new_observations, new_auth
    )
    changed_boundary, incremental_after_change = payload.incremental(
        causal_d,
        new_causal,
        old_payload,
        detachable_records,
        new_records,
        detachable_observations,
        new_observations,
        old_auth,
        new_auth,
    )
    suite.check(
        "late authority invalidation restores retention and incremental equals full",
        changed_boundary == new_causal.order.index(directive_d.reference)
        and incremental_after_change == full_after_change
        and full_after_change.states[target_d.reference].retention
        is RetentionState.ACTIVE
        and new_causal.handoffs[-1].kind == "revoke-b"
        and (directive_d.reference, "concurrent")
        in new_causal.handoffs[-1].causal_relations,
        family="late-removal-invalidation",
        trace=(target_d, directive_d, authority_change),
        obligation="C0.2f-10",
    )
    fork_directive = first(
        b"r1",
        b"b",
        GRANT_B,
        parents=(target_d.reference,),
        kind="remove",
    )
    fork_causal_removal = causal_model().evaluate(
        (fork_directive, directive_d, target_d)
    )
    fork_records_removal = (
        *detachable_records,
        PayloadRecord(
            fork_directive.reference,
            ContentDescriptor.none(),
            RemovalClaim(target_d.reference, b"target"),
        ),
    )
    fork_observations_removal = dict(detachable_observations)
    fork_observations_removal[fork_directive.reference] = NONE_OBSERVATION
    fork_authorizations = {
        directive_d.reference: False,
        fork_directive.reference: False,
    }
    fork_full = payload.evaluate(
        fork_causal_removal,
        fork_records_removal,
        fork_observations_removal,
        fork_authorizations,
    )
    fork_boundary, fork_incremental = payload.incremental(
        causal_d,
        fork_causal_removal,
        old_payload,
        detachable_records,
        fork_records_removal,
        detachable_observations,
        fork_observations_removal,
        old_auth,
        fork_authorizations,
    )
    suite.check(
        "late fork invalidates removal authority and incremental equals full",
        fork_incremental == fork_full
        and fork_boundary
        <= fork_causal_removal.order.index(directive_d.reference)
        and fork_causal_removal.decisions[directive_d.reference].status.value == "fork"
        and fork_causal_removal.decisions[fork_directive.reference].status.value
        == "fork"
        and fork_full.states[target_d.reference].retention is RetentionState.ACTIVE
        and fork_full.directive_outcomes[directive_d.reference]
        is DirectiveOutcome.UNAUTHORIZED
        and fork_full.directive_outcomes[fork_directive.reference]
        is DirectiveOutcome.UNAUTHORIZED,
        family="late-removal-invalidation",
        trace=(target_d, directive_d, fork_directive),
        obligation="C0.2f-10",
    )

    # 11: a forked REQUIRED event halts before independent later work.
    root = first(b"f0", b"a", GRANT_A)
    fork_left = next_event(b"f1", b"a", 1, root.reference)
    fork_right = next_event(b"f2", b"a", 1, root.reference)
    independent = first(b"x0", b"b", GRANT_B)
    fork_causal = causal_model().evaluate((independent, fork_right, root, fork_left))
    fork_records = (
        PayloadRecord(root.reference, ContentDescriptor.none()),
        record(fork_left.reference, ContentClass.REQUIRED, b"left"),
        record(fork_right.reference, ContentClass.REQUIRED, b"right"),
        record(independent.reference, ContentClass.DETACHABLE, b"independent"),
    )
    fork_observations = {
        root.reference: NONE_OBSERVATION,
        fork_left.reference: MISSING,
        fork_right.reference: VERIFIED,
        independent.reference: VERIFIED,
    }
    fork_payload = payload.evaluate(
        fork_causal,
        fork_records,
        fork_observations,
        {},
        PayloadCheckpoint(tuple(sorted(fork_causal.order))),
    )
    suite.check(
        "fork-classified REQUIRED hole and checkpoint cannot permit selective bypass",
        fork_causal.decisions[fork_left.reference].status.value == "fork"
        and fork_payload.halted_at == fork_left.reference
        and independent.reference not in fork_payload.applied_order
        and not fork_payload.checkpoint.consumer_substitution,
        family="required-bypass",
        trace=(root, fork_left, fork_right, independent),
        obligation="C0.2f-11",
    )

    # 12: bad checkpoint evidence is typed but never consumed as AP state.
    checkpoint_cases = (
        (PayloadCheckpoint((detachable.reference,), available=False), CheckpointDisposition.UNAVAILABLE),
        (PayloadCheckpoint((detachable.reference,), authenticated=False), CheckpointDisposition.UNAUTHENTICATED),
        (PayloadCheckpoint((detachable.reference,), conflicting=True), CheckpointDisposition.CONFLICTING),
        (PayloadCheckpoint((b"unknown",)), CheckpointDisposition.STALE_EVIDENCE),
    )
    checkpoint_typed_active = True
    for checkpoint, expected in checkpoint_cases:
        evaluated = payload.evaluate(
            causal, records, {detachable.reference: VERIFIED}, {}, checkpoint
        )
        checkpoint_typed_active &= (
            evaluated.checkpoint is not None
            and evaluated.checkpoint.disposition is expected
            and not evaluated.checkpoint.consumer_substitution
            and (
                expected is not CheckpointDisposition.STALE_EVIDENCE
                or not evaluated.checkpoint.producer_eligible
            )
            and replace(evaluated, checkpoint=None) == present
        )
    halted_checkpoint_cases = (
        (
            PayloadCheckpoint(
                (deferred_horizon_member.reference,), available=False
            ),
            CheckpointDisposition.UNAVAILABLE,
        ),
        (
            PayloadCheckpoint(
                (deferred_horizon_member.reference,), authenticated=False
            ),
            CheckpointDisposition.UNAUTHENTICATED,
        ),
        (
            PayloadCheckpoint(
                (deferred_horizon_member.reference,), conflicting=True
            ),
            CheckpointDisposition.CONFLICTING,
        ),
        (PayloadCheckpoint((b"unknown",)), CheckpointDisposition.STALE_EVIDENCE),
    )
    checkpoint_typed_halted = True
    for checkpoint, expected in halted_checkpoint_cases:
        evaluated = payload.evaluate(
            causal_deferred_horizon,
            deferred_horizon_records,
            deferred_horizon_observations,
            {},
            checkpoint,
        )
        checkpoint_typed_halted &= (
            evaluated.checkpoint is not None
            and evaluated.checkpoint.disposition is expected
            and not evaluated.checkpoint.consumer_substitution
            and (
                expected is not CheckpointDisposition.STALE_EVIDENCE
                or not evaluated.checkpoint.producer_eligible
            )
            and replace(evaluated, checkpoint=None)
            == deferred_horizon_without_checkpoint
        )
    suite.check(
        "unavailable unauthenticated conflicting and stale checkpoints never substitute",
        checkpoint_typed_active and checkpoint_typed_halted,
        family="checkpoint-non-substitution",
        trace=(
            (detachable,)
            if not checkpoint_typed_active
            else (blocking_required, deferred_horizon_member)
        ),
        obligation="C0.2f-12",
    )

    # 14: NONE, late target and repeated removal each have deterministic outcomes.
    none_target, none_directive, none_causal, none_records, none_observations = (
        removal_fixture(ContentClass.NONE)
    )
    none_result = payload.evaluate(
        none_causal,
        none_records,
        none_observations,
        {none_directive.reference: True},
    )
    late_target = first(b"l0", b"a", GRANT_A)
    late_directive = first(
        b"l1", b"b", GRANT_B, parents=(late_target.reference,), kind="remove"
    )
    before_target = causal_model().evaluate((late_directive,))
    before_payload = payload.evaluate(before_target, (), {}, {})
    after_target = causal_model().evaluate((late_directive, late_target))
    late_records = (
        record(late_target.reference, ContentClass.DETACHABLE, b"late"),
        PayloadRecord(
            late_directive.reference,
            ContentDescriptor.none(),
            RemovalClaim(late_target.reference, b"late"),
        ),
    )
    late_observations = {
        late_target.reference: VERIFIED,
        late_directive.reference: NONE_OBSERVATION,
    }
    after_payload = payload.evaluate(
        after_target,
        late_records,
        late_observations,
        {late_directive.reference: True},
    )
    repeat = next_event(b"r1", b"b", 1, directive_d.reference, kind="remove")
    repeat_causal = causal_model().evaluate((repeat, directive_d, target_d))
    repeat_records = (
        *detachable_records,
        PayloadRecord(
            repeat.reference,
            ContentDescriptor.none(),
            RemovalClaim(target_d.reference, b"target"),
        ),
    )
    repeat_observations = dict(detachable_observations)
    repeat_observations[repeat.reference] = NONE_OBSERVATION
    repeated = payload.evaluate(
        repeat_causal,
        repeat_records,
        repeat_observations,
        {directive_d.reference: True, repeat.reference: True},
    )
    concurrent_target = first(b"n0", b"a", GRANT_A)
    concurrent_directive = first(b"n1", b"b", GRANT_B, kind="remove")
    concurrent_causal = causal_model().evaluate(
        (concurrent_directive, concurrent_target)
    )
    concurrent_records = (
        record(
            concurrent_target.reference,
            ContentClass.DETACHABLE,
            b"concurrent",
        ),
        PayloadRecord(
            concurrent_directive.reference,
            ContentDescriptor.none(),
            RemovalClaim(concurrent_target.reference, b"concurrent"),
        ),
    )
    suite.check_raises(
        "removal cannot target a concurrent non-ancestor event",
        lambda: payload.evaluate(
            concurrent_causal,
            concurrent_records,
            {
                concurrent_target.reference: VERIFIED,
                concurrent_directive.reference: NONE_OBSERVATION,
            },
            {concurrent_directive.reference: True},
        ),
        family="removal-target-cases",
        trace=(concurrent_target, concurrent_directive),
        obligation="C0.2f-14",
    )
    unrelated_target_records = (
        concurrent_records[0],
        replace(
            concurrent_records[1],
            removal=RemovalClaim(b"unrelated-missing", b"concurrent"),
        ),
    )
    suite.check_raises(
        "unrelated unavailable removal target fails closed before projection",
        lambda: payload.evaluate(
            concurrent_causal,
            unrelated_target_records,
            {
                concurrent_target.reference: VERIFIED,
                concurrent_directive.reference: NONE_OBSERVATION,
            },
            {concurrent_directive.reference: True},
        ),
        family="removal-target-cases",
        trace=(concurrent_target, concurrent_directive),
        obligation="C0.2f-14",
    )
    compacted_target = first(b"n2", b"a", GRANT_A)
    compacted_directive = next_event(
        b"n3",
        b"a",
        1,
        compacted_target.reference,
        kind="remove",
    )
    compacted_target_causal = causal_model(
        proven_extra=(compacted_target.reference,),
        heads=((b"a", 0, compacted_target.reference),),
    ).evaluate((compacted_directive,))
    compacted_target_record = PayloadRecord(
        compacted_directive.reference,
        ContentDescriptor.none(),
        RemovalClaim(compacted_target.reference, b"compacted"),
    )
    compacted_target_result = payload.evaluate(
        compacted_target_causal,
        (compacted_target_record,),
        {compacted_directive.reference: NONE_OBSERVATION},
        {compacted_directive.reference: True},
    )
    suite.check(
        "removal targeting compacted evidence defers without applying an effect",
        compacted_target_result.stale_dependencies == (compacted_target.reference,)
        and compacted_target_result.halted_at == compacted_target.reference
        and compacted_target_result.applied_order == ()
        and compacted_target_result.directive_outcomes[compacted_directive.reference]
        is DirectiveOutcome.DEFERRED_BY_STALE_EVIDENCE
        and compacted_target_result.states[compacted_directive.reference].readiness
        is ReplayReadiness.STALE_EVIDENCE,
        family="removal-target-cases",
        trace=(compacted_target, compacted_directive),
        obligation="C0.2f-14",
    )
    suite.check(
        "NONE late-admitted and already-removed targets are deterministic",
        none_result.directive_outcomes[none_directive.reference]
        is DirectiveOutcome.INAPPLICABLE_CLASS
        and before_payload.applied_order == ()
        and after_payload.directive_outcomes[late_directive.reference]
        is DirectiveOutcome.APPLIED
        and repeated.directive_outcomes[repeat.reference]
        is DirectiveOutcome.ALREADY_REMOVED,
        family="removal-target-cases",
        trace=(late_directive, late_target),
        obligation="C0.2f-14",
    )

    # 15: injected randomizers separate identical chunks; bad geometry fails first.
    vector = SymbolicCommitmentVector(
        (CTX.application, CTX.profile, CTX.instance, CTX.genesis_ref),
        "abstract-v0",
        "example.attachment",
        6,
        CommitmentShape.CHUNKED,
        ChunkGeometry(3, 2, 3),
        (b"same", b"tail"),
        (3, 3),
        b"r1",
    )
    other_vector = replace(vector, randomizer=b"r2")
    terms_separated = (
        symbolic_commitment_term(vector) != symbolic_commitment_term(other_vector)
        and all(
            left != right
            for left, right in zip(
                symbolic_chunk_terms(vector),
                symbolic_chunk_terms(other_vector),
                strict=True,
            )
        )
    )
    suite.check(
        "identical chunks with different injected randomizers have distinct symbolic terms",
        terms_separated,
        family="chunk-privacy",
        obligation="C0.2f-15",
    )
    suite.check_raises(
        "inconsistent chunk geometry rejects before symbolic expansion",
        lambda: symbolic_commitment_term(
            replace(vector, chunk_geometry=ChunkGeometry(4, 2, 3))
        ),
        family="chunk-privacy",
        obligation="C0.2f-15",
    )
    invalid_descriptor_geometry = PayloadRecord(
        detachable.reference,
        descriptor(
            ContentClass.DETACHABLE,
            b"geometry",
            length=6,
            shape=CommitmentShape.CHUNKED,
            geometry=ChunkGeometry(4, 2, 3),
        ),
    )
    suite.check_raises(
        "inconsistent descriptor geometry rejects before payload projection",
        lambda: payload.evaluate(
            causal,
            (invalid_descriptor_geometry,),
            {detachable.reference: VERIFIED},
            {},
        ),
        family="chunk-privacy",
        trace=(detachable,),
        obligation="C0.2f-15",
    )

    # 16: attacker-controlled declarations are rejected at scalar bounds.
    oversized_record = PayloadRecord(
        detachable.reference,
        descriptor(ContentClass.DETACHABLE, b"x", length=10_000_000),
    )
    suite.check_raises(
        "attacker-declared content length rejects at profile bound",
        lambda: PayloadModel(PayloadProfile(max_content_length=16)).evaluate(
            causal, (oversized_record,), {detachable.reference: VERIFIED}, {}
        ),
        family="payload-resource-bound",
        obligation="C0.2f-16",
    )
    oversized_text_record = PayloadRecord(
        detachable.reference,
        replace(
            descriptor(ContentClass.DETACHABLE, b"x"),
            content_type_id="x" * 65,
        ),
    )
    suite.check_raises(
        "attacker-declared payload text rejects at profile bound",
        lambda: PayloadModel(PayloadProfile(max_text_bytes=64)).evaluate(
            causal,
            (oversized_text_record,),
            {detachable.reference: VERIFIED},
            {},
        ),
        family="payload-resource-bound",
        obligation="C0.2f-16",
    )
    too_many_parts = replace(
        vector,
        exact_content_length=9,
        chunk_geometry=ChunkGeometry(1, 9, 1),
        part_symbols=(b"x",) * 9,
        part_lengths=(1,) * 9,
    )
    suite.check_raises(
        "attacker-declared chunk count rejects at profile bound",
        lambda: symbolic_commitment_term(too_many_parts),
        family="payload-resource-bound",
        obligation="C0.2f-16",
    )
    oversized_chunk_size = replace(
        vector,
        chunk_geometry=ChunkGeometry(257, 1, 6),
        part_symbols=(b"x",),
        part_lengths=(6,),
    )
    suite.check_raises(
        "attacker-declared chunk size rejects at profile bound",
        lambda: symbolic_commitment_term(oversized_chunk_size),
        family="payload-resource-bound",
        obligation="C0.2f-16",
    )
    suite.check_raises(
        "attacker-declared directive count rejects at profile bound",
        lambda: PayloadModel(PayloadProfile(max_directives=1)).evaluate(
            repeat_causal,
            repeat_records,
            repeat_observations,
            {directive_d.reference: True, repeat.reference: True},
        ),
        family="payload-resource-bound",
        obligation="C0.2f-16",
    )
    suite.check_raises(
        "attacker-declared record count rejects at profile bound",
        lambda: PayloadModel(PayloadProfile(max_records=1)).evaluate(
            repeat_causal,
            repeat_records,
            repeat_observations,
            {directive_d.reference: True, repeat.reference: True},
        ),
        family="payload-resource-bound",
        obligation="C0.2f-16",
    )
    suite.check_raises(
        "aggregate payload input rejects at profile bound",
        lambda: PayloadModel(PayloadProfile(max_input_bytes=8)).evaluate(
            causal_d,
            detachable_records,
            detachable_observations,
            {directive_d.reference: True},
        ),
        family="payload-resource-bound",
        obligation="C0.2f-16",
    )
    suite.check_raises(
        "attacker-declared checkpoint reference count rejects at profile bound",
        lambda: PayloadModel(PayloadProfile(max_checkpoint_refs=1)).evaluate(
            causal,
            (record(detachable.reference, ContentClass.DETACHABLE, b"det"),),
            {detachable.reference: VERIFIED},
            {},
            PayloadCheckpoint((b"a", b"b")),
        ),
        family="payload-resource-bound",
        obligation="C0.2f-16",
    )

    suite.samples["payload_required_halt"] = payload_evaluation_json(blocked)
    suite.samples["payload_removed_presentations"] = {
        "states": sorted(item.value for item in presentations),
        "retention": RetentionState.LOGICALLY_REMOVED.value,
    }
    suite.samples["payload_checkpoint"] = {
        "contents_availability_invariant": checkpoint_missing.checkpoint.contents
        == checkpoint_present.checkpoint.contents,
        "missing_disposition": checkpoint_missing.checkpoint.disposition.value,
        "present_disposition": checkpoint_present.checkpoint.disposition.value,
        "consumer_substitution": False,
    }
