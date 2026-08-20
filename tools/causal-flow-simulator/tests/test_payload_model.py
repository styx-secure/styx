from __future__ import annotations

from dataclasses import replace
from itertools import product
import unittest

import support

from model import ModelInputError
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
    RemovalClaim,
    ReplayReadiness,
    RetentionState,
    SymbolicCommitmentVector,
    symbolic_chunk_terms,
    symbolic_commitment_term,
)
from scenarios import (
    CTX,
    GRANT_A,
    GRANT_B,
    GRANT_C,
    checkpoint,
    first,
    model,
    next_event,
)


NONE_OBSERVATION = PayloadObservation(
    Availability.ABSENT, BindingObservation.NOT_APPLICABLE
)
VERIFIED = PayloadObservation(Availability.PRESENT, BindingObservation.VERIFIED)
MISSING = PayloadObservation(Availability.ABSENT, BindingObservation.NOT_CHECKED)


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
        "example.text",
        length,
        "abstract-v0",
        shape,
        token,
        geometry,
    )


def record(reference: bytes, content_class: ContentClass, token: bytes) -> PayloadRecord:
    return PayloadRecord(reference, descriptor(content_class, token))


class DescriptorAndAxisTest(unittest.TestCase):
    def test_none_descriptor_is_canonical(self):
        event = first(b"a0", b"a", GRANT_A)
        causal = model().evaluate((event,))
        valid = PayloadRecord(event.reference, ContentDescriptor.none())
        result = PayloadModel().evaluate(
            causal, (valid,), {event.reference: NONE_OBSERVATION}, {}
        )
        self.assertEqual(
            result.states[event.reference].presentation, PresentationState.NO_CONTENT
        )

        invalid = replace(valid, descriptor=replace(ContentDescriptor.none(), content_type_id="x"))
        with self.assertRaises(ModelInputError):
            PayloadModel().evaluate(
                causal, (invalid,), {event.reference: NONE_OBSERVATION}, {}
            )

    def test_none_event_rejects_unexpected_supplied_bytes_as_typed_state(self):
        event = first(b"a0", b"a", GRANT_A)
        causal = model().evaluate((event,))
        supplied = PayloadObservation(
            Availability.PRESENT, BindingObservation.NOT_APPLICABLE
        )
        result = PayloadModel().evaluate(
            causal,
            (PayloadRecord(event.reference, ContentDescriptor.none()),),
            {event.reference: supplied},
            {},
        )
        self.assertEqual(result.applied_order, causal.order)
        self.assertEqual(
            result.states[event.reference].presentation,
            PresentationState.UNEXPECTED_CONTENT_REJECTED,
        )

    def test_closed_axis_set_accepts_only_legal_combinations(self):
        event = first(b"a0", b"a", GRANT_A)
        causal = model().evaluate((event,))
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
        for content_class in ContentClass:
            payload_record = record(event.reference, content_class, b"ct")
            legal = (
                none_legal
                if content_class is ContentClass.NONE
                else content_bearing_legal
            )
            for availability, binding in product(Availability, BindingObservation):
                operation = lambda: PayloadModel().evaluate(
                    causal,
                    (payload_record,),
                    {event.reference: PayloadObservation(availability, binding)},
                    {},
                )
                with self.subTest(
                    content_class=content_class,
                    availability=availability,
                    binding=binding,
                ):
                    if (availability, binding) in legal:
                        operation()
                    else:
                        with self.assertRaises(ModelInputError):
                            operation()

    def test_active_presentations_distinguish_unavailable_unverifiable_and_substituted(self):
        event = first(b"a0", b"a", GRANT_A)
        causal = model().evaluate((event,))
        records = (record(event.reference, ContentClass.DETACHABLE, b"ct"),)
        cases = {
            PayloadObservation(
                Availability.ABSENT, BindingObservation.NOT_CHECKED
            ): PresentationState.ACTIVE_UNAVAILABLE,
            PayloadObservation(
                Availability.PRESENT, BindingObservation.OPENING_MISSING
            ): PresentationState.ACTIVE_UNVERIFIABLE,
            PayloadObservation(
                Availability.PRESENT, BindingObservation.LENGTH_MISMATCH
            ): PresentationState.ACTIVE_SUBSTITUTED_REJECTED,
        }
        observed = set()
        for observation, expected in cases.items():
            result = PayloadModel().evaluate(
                causal, records, {event.reference: observation}, {}
            )
            self.assertEqual(result.states[event.reference].presentation, expected)
            observed.add(result.states[event.reference].presentation)
        self.assertEqual(observed, set(cases.values()))

    def test_zero_length_content_is_not_none(self):
        event = first(b"a0", b"a", GRANT_A)
        causal = model().evaluate((event,))
        zero = PayloadRecord(
            event.reference,
            descriptor(ContentClass.REQUIRED, b"zero", length=0),
        )
        result = PayloadModel().evaluate(
            causal, (zero,), {event.reference: VERIFIED}, {}
        )
        self.assertEqual(result.states[event.reference].content_class, ContentClass.REQUIRED)
        self.assertEqual(result.states[event.reference].readiness, ReplayReadiness.READY)


class SymbolicCommitmentTest(unittest.TestCase):
    def vector(self, randomizer: bytes) -> SymbolicCommitmentVector:
        return SymbolicCommitmentVector(
            (CTX.application, CTX.profile, CTX.instance, CTX.genesis_ref),
            "abstract-v0",
            "example.attachment",
            6,
            CommitmentShape.CHUNKED,
            ChunkGeometry(3, 2, 3),
            (b"same", b"tail"),
            (3, 3),
            randomizer,
        )

    def test_randomizer_changes_commitment_and_every_leaf_term(self):
        left = self.vector(b"r1")
        right = self.vector(b"r2")
        self.assertNotEqual(symbolic_commitment_term(left), symbolic_commitment_term(right))
        self.assertTrue(
            all(a != b for a, b in zip(symbolic_chunk_terms(left), symbolic_chunk_terms(right)))
        )

    def test_chunk_terms_bind_ordinal_length_and_geometry(self):
        vector = self.vector(b"r1")
        leaves = symbolic_chunk_terms(vector)
        self.assertNotEqual(leaves[0], leaves[1])
        self.assertEqual(leaves[0][4:6], (0, 3))
        bad = replace(vector, chunk_geometry=ChunkGeometry(4, 2, 2))
        with self.assertRaises(ModelInputError):
            symbolic_commitment_term(bad)

    def test_geometry_and_declared_bounds_fail_before_expansion(self):
        oversized = replace(self.vector(b"r1"), exact_content_length=10_000_000)
        with self.assertRaises(ModelInputError):
            symbolic_commitment_term(oversized, PayloadProfile(max_content_length=8))
        too_many = replace(
            self.vector(b"r1"),
            chunk_geometry=ChunkGeometry(1, 9, 1),
            exact_content_length=9,
            part_symbols=(b"x",) * 9,
            part_lengths=(1,) * 9,
        )
        with self.assertRaises(ModelInputError):
            symbolic_commitment_term(too_many)
        oversized_chunk_size = replace(
            self.vector(b"r1"),
            chunk_geometry=ChunkGeometry(257, 1, 6),
            part_symbols=(b"x",),
            part_lengths=(6,),
        )
        with self.assertRaisesRegex(ModelInputError, "chunk size exceeds profile"):
            symbolic_commitment_term(oversized_chunk_size)


class ReplayAvailabilityTest(unittest.TestCase):
    def test_required_halts_whole_suffix_and_resumes_deterministically(self):
        required = first(b"a0", b"a", GRANT_A)
        later = first(b"b0", b"b", GRANT_B, parents=(required.reference,))
        causal = model().evaluate((later, required))
        records = (
            record(required.reference, ContentClass.REQUIRED, b"req"),
            record(later.reference, ContentClass.DETACHABLE, b"det"),
        )
        unavailable = {
            required.reference: MISSING,
            later.reference: VERIFIED,
        }
        blocked = PayloadModel().evaluate(causal, records, unavailable, {})
        self.assertEqual(blocked.halted_at, required.reference)
        self.assertEqual(blocked.applied_order, ())
        self.assertEqual(
            blocked.states[later.reference].presentation, PresentationState.DEFERRED
        )
        available = dict(unavailable)
        available[required.reference] = VERIFIED
        resumed = PayloadModel().evaluate(causal, records, available, {})
        self.assertIsNone(resumed.halted_at)
        self.assertEqual(resumed.applied_order, causal.order)
        boundary, incremental = PayloadModel().incremental(
            causal,
            causal,
            blocked,
            records,
            records,
            unavailable,
            available,
            {},
            {},
        )
        self.assertEqual(boundary, 0)
        self.assertEqual(incremental, resumed)

    def test_incremental_replays_when_prefix_record_changes(self):
        required = first(b"a0", b"a", GRANT_A)
        later = first(b"b0", b"b", GRANT_B, parents=(required.reference,))
        causal = model().evaluate((later, required))
        old_records = (
            record(required.reference, ContentClass.DETACHABLE, b"required"),
            record(later.reference, ContentClass.DETACHABLE, b"later"),
        )
        new_records = (
            record(required.reference, ContentClass.REQUIRED, b"required"),
            old_records[1],
        )
        observations = {required.reference: MISSING, later.reference: VERIFIED}
        old_payload = PayloadModel().evaluate(causal, old_records, observations, {})
        fresh = PayloadModel().evaluate(causal, new_records, observations, {})
        boundary, incremental = PayloadModel().incremental(
            causal,
            causal,
            old_payload,
            old_records,
            new_records,
            observations,
            observations,
            {},
            {},
        )
        self.assertEqual(boundary, 0)
        self.assertEqual(incremental, fresh)
        self.assertEqual(old_payload.applied_order, causal.order)
        self.assertEqual(fresh.halted_at, required.reference)

    def test_removal_in_required_deferred_suffix_does_not_apply(self):
        target = first(b"a0", b"a", GRANT_A)
        required = first(b"b0", b"b", GRANT_B, parents=(target.reference,))
        directive = first(
            b"c0",
            b"c",
            b"gc",
            parents=(required.reference,),
            kind="remove",
        )
        causal = model().evaluate((directive, required, target))
        records = (
            record(target.reference, ContentClass.DETACHABLE, b"target"),
            record(required.reference, ContentClass.REQUIRED, b"required"),
            PayloadRecord(
                directive.reference,
                ContentDescriptor.none(),
                RemovalClaim(target.reference, b"target"),
            ),
        )
        result = PayloadModel().evaluate(
            causal,
            records,
            {
                target.reference: VERIFIED,
                required.reference: MISSING,
                directive.reference: NONE_OBSERVATION,
            },
            {directive.reference: True},
        )
        self.assertEqual(result.halted_at, required.reference)
        self.assertEqual(
            result.directive_outcomes[directive.reference],
            DirectiveOutcome.DEFERRED_BY_REQUIRED_SUFFIX,
        )
        self.assertEqual(
            result.states[target.reference].retention, RetentionState.ACTIVE
        )

    def test_stale_causal_evidence_defers_removal(self):
        compacted = b"a0"
        child = next_event(b"a1", b"a", 1, compacted)
        target = first(b"b0", b"b", GRANT_B)
        directive = first(
            b"c0",
            b"c",
            b"gc",
            parents=(child.reference, target.reference),
            kind="remove",
        )
        evidence = checkpoint(
            proven=frozenset((GRANT_A, GRANT_B, b"gc", compacted)),
            heads=((b"a", 0, compacted),),
        )
        causal = model(evidence=evidence).evaluate((directive, target, child))
        records = (
            record(child.reference, ContentClass.DETACHABLE, b"child"),
            record(target.reference, ContentClass.DETACHABLE, b"target"),
            PayloadRecord(
                directive.reference,
                ContentDescriptor.none(),
                RemovalClaim(target.reference, b"target"),
            ),
        )
        result = PayloadModel().evaluate(
            causal,
            records,
            {
                child.reference: VERIFIED,
                target.reference: VERIFIED,
                directive.reference: NONE_OBSERVATION,
            },
            {directive.reference: True},
        )
        self.assertEqual(
            result.directive_outcomes[directive.reference],
            DirectiveOutcome.DEFERRED_BY_STALE_EVIDENCE,
        )
        self.assertEqual(
            result.states[target.reference].retention, RetentionState.ACTIVE
        )

    def test_incremental_rejects_unvalidated_old_payload_state(self):
        event = first(b"a0", b"a", GRANT_A)
        causal = model().evaluate((event,))
        records = (record(event.reference, ContentClass.REQUIRED, b"req"),)
        observations = {event.reference: VERIFIED}
        old = PayloadModel().evaluate(causal, records, observations, {})
        snapshot = old.snapshots[0]
        reference, state = snapshot.states[0]
        forged_snapshot = replace(
            snapshot,
            states=((reference, replace(state, retention=RetentionState.LOGICALLY_REMOVED)),),
        )
        forged = replace(old, snapshots=(forged_snapshot,))
        with self.assertRaisesRegex(
            ModelInputError, "old payload evaluation does not match validated inputs"
        ):
            PayloadModel().incremental(
                causal,
                causal,
                forged,
                records,
                records,
                observations,
                observations,
                {},
                {},
            )

    def test_detachable_availability_changes_presentation_not_authoritative_order(self):
        event = first(b"a0", b"a", GRANT_A)
        causal = model().evaluate((event,))
        records = (record(event.reference, ContentClass.DETACHABLE, b"det"),)
        absent = PayloadModel().evaluate(causal, records, {event.reference: MISSING}, {})
        present = PayloadModel().evaluate(causal, records, {event.reference: VERIFIED}, {})
        self.assertEqual(absent.applied_order, present.applied_order)
        self.assertEqual(absent.halted_at, present.halted_at)
        self.assertNotEqual(
            absent.states[event.reference].presentation,
            present.states[event.reference].presentation,
        )

    def test_availability_divergence_does_not_create_event_fork(self):
        event = first(b"a0", b"a", GRANT_A)
        causal = model().evaluate((event,))
        records = (record(event.reference, ContentClass.DETACHABLE, b"det"),)
        PayloadModel().evaluate(causal, records, {event.reference: MISSING}, {})
        PayloadModel().evaluate(causal, records, {event.reference: VERIFIED}, {})
        self.assertEqual(causal.decisions[event.reference].status.value, "admitted")
        self.assertEqual(causal.decisions[event.reference].fork_peers, ())

    def test_compacted_dependency_never_substitutes_for_payload_replay(self):
        compacted = b"a0"
        current = next_event(b"a1", b"a", 1, compacted)
        evidence = checkpoint(
            proven=frozenset((GRANT_A, compacted)),
            heads=((b"a", 0, compacted),),
        )
        causal = model(evidence=evidence).evaluate((current,))
        records = (record(current.reference, ContentClass.DETACHABLE, b"current"),)
        result = PayloadModel().evaluate(
            causal,
            records,
            {current.reference: VERIFIED},
            {},
            PayloadCheckpoint((current.reference,)),
        )
        self.assertEqual(result.stale_dependencies, (compacted,))
        self.assertEqual(result.halted_at, compacted)
        self.assertEqual(result.applied_order, ())
        self.assertEqual(
            result.states[current.reference].readiness,
            ReplayReadiness.STALE_EVIDENCE,
        )
        self.assertEqual(
            result.checkpoint.disposition, CheckpointDisposition.STALE_EVIDENCE
        )
        self.assertFalse(result.checkpoint.producer_eligible)
        self.assertFalse(result.checkpoint.consumer_substitution)
        boundary, incremental = PayloadModel().incremental(
            causal,
            causal,
            result,
            records,
            records,
            {current.reference: VERIFIED},
            {current.reference: VERIFIED},
            {},
            {},
            PayloadCheckpoint((current.reference,)),
        )
        self.assertEqual(boundary, 0)
        self.assertEqual(incremental, result)

    def test_compacted_reference_collision_with_another_grant_stays_stale(self):
        consumer = first(b"k1", b"b", GRANT_B, parents=(GRANT_C,))
        grant_owner = first(b"k2", b"c", GRANT_C)
        causal = model().evaluate((consumer, grant_owner))
        records = tuple(
            record(reference, ContentClass.DETACHABLE, b"collision")
            for reference in causal.order
        )
        result = PayloadModel().evaluate(
            causal,
            records,
            {reference: VERIFIED for reference in causal.order},
            {},
        )
        self.assertEqual(result.stale_dependencies, (GRANT_C,))
        self.assertEqual(result.halted_at, GRANT_C)
        self.assertEqual(result.applied_order, ())
        self.assertTrue(
            all(
                state.readiness is ReplayReadiness.STALE_EVIDENCE
                for state in result.states.values()
            )
        )

    def test_author_predecessor_grant_collision_stays_stale(self):
        event = next_event(b"k3", b"b", 1, GRANT_B)
        evidence = checkpoint(
            proven=frozenset((GRANT_A, GRANT_B, GRANT_C)),
            heads=((b"b", 0, GRANT_B),),
        )
        causal = model(evidence=evidence).evaluate((event,))
        result = PayloadModel().evaluate(
            causal,
            (record(event.reference, ContentClass.DETACHABLE, b"collision"),),
            {event.reference: VERIFIED},
            {},
        )
        self.assertEqual(result.stale_dependencies, (GRANT_B,))
        self.assertEqual(result.halted_at, GRANT_B)
        self.assertEqual(result.applied_order, ())
        self.assertEqual(
            result.states[event.reference].readiness,
            ReplayReadiness.STALE_EVIDENCE,
        )


class RemovalTest(unittest.TestCase):
    def fixture(self, target_class: ContentClass = ContentClass.DETACHABLE):
        target = first(b"a0", b"a", GRANT_A)
        directive = first(
            b"r0", b"b", GRANT_B, parents=(target.reference,), kind="remove"
        )
        causal = model().evaluate((directive, target))
        target_record = record(target.reference, target_class, b"target")
        directive_record = PayloadRecord(
            directive.reference,
            ContentDescriptor.none(),
            RemovalClaim(target.reference, b"target"),
        )
        observations = {
            target.reference: VERIFIED if target_class is not ContentClass.NONE else NONE_OBSERVATION,
            directive.reference: NONE_OBSERVATION,
        }
        return target, directive, causal, (target_record, directive_record), observations

    def test_removal_target_must_be_causal_and_compacted_target_defers(self):
        concurrent_target = first(b"a0", b"a", GRANT_A)
        concurrent_directive = first(b"b0", b"b", GRANT_B, kind="remove")
        concurrent_causal = model().evaluate(
            (concurrent_directive, concurrent_target)
        )
        concurrent_records = (
            record(
                concurrent_target.reference,
                ContentClass.DETACHABLE,
                b"target",
            ),
            PayloadRecord(
                concurrent_directive.reference,
                ContentDescriptor.none(),
                RemovalClaim(concurrent_target.reference, b"target"),
            ),
        )
        with self.assertRaisesRegex(ModelInputError, "causal ancestor"):
            PayloadModel().evaluate(
                concurrent_causal,
                concurrent_records,
                {
                    concurrent_target.reference: VERIFIED,
                    concurrent_directive.reference: NONE_OBSERVATION,
                },
                {concurrent_directive.reference: True},
            )

        compacted_target = b"a0"
        compacted_directive = next_event(
            b"a1", b"a", 1, compacted_target, kind="remove"
        )
        evidence = checkpoint(
            proven=frozenset((GRANT_A, compacted_target)),
            heads=((b"a", 0, compacted_target),),
        )
        compacted_causal = model(evidence=evidence).evaluate((compacted_directive,))
        compacted_record = PayloadRecord(
            compacted_directive.reference,
            ContentDescriptor.none(),
            RemovalClaim(compacted_target, b"target"),
        )
        compacted_result = PayloadModel().evaluate(
            compacted_causal,
            (compacted_record,),
            {compacted_directive.reference: NONE_OBSERVATION},
            {compacted_directive.reference: True},
        )
        self.assertEqual(compacted_result.stale_dependencies, (compacted_target,))
        self.assertEqual(compacted_result.applied_order, ())
        self.assertEqual(
            compacted_result.directive_outcomes[compacted_directive.reference],
            DirectiveOutcome.DEFERRED_BY_STALE_EVIDENCE,
        )

    def test_unrelated_missing_removal_target_fails_closed(self):
        target, directive, causal, records, observations = self.fixture()
        unrelated = (
            records[0],
            replace(
                records[1],
                removal=RemovalClaim(b"unrelated-missing", b"target"),
            ),
        )
        with self.assertRaisesRegex(
            ModelInputError, "retained removal target is unavailable"
        ):
            PayloadModel().evaluate(
                causal,
                unrelated,
                observations,
                {directive.reference: True},
            )

    def test_only_authorized_detachable_removal_applies(self):
        target, directive, causal, records, observations = self.fixture()
        denied = PayloadModel().evaluate(
            causal, records, observations, {directive.reference: False}
        )
        self.assertEqual(
            denied.directive_outcomes[directive.reference], DirectiveOutcome.UNAUTHORIZED
        )
        self.assertEqual(denied.states[target.reference].retention, RetentionState.ACTIVE)
        allowed = PayloadModel().evaluate(
            causal, records, observations, {directive.reference: True}
        )
        self.assertEqual(
            allowed.directive_outcomes[directive.reference], DirectiveOutcome.APPLIED
        )
        self.assertEqual(
            allowed.states[target.reference].retention, RetentionState.LOGICALLY_REMOVED
        )
        self.assertEqual(
            replace(
                allowed.states[target.reference],
                retention=denied.states[target.reference].retention,
                presentation=denied.states[target.reference].presentation,
            ),
            denied.states[target.reference],
        )

    def test_none_required_and_commitment_mismatch_are_inapplicable(self):
        for target_class in (ContentClass.NONE, ContentClass.REQUIRED):
            target, directive, causal, records, observations = self.fixture(target_class)
            result = PayloadModel().evaluate(
                causal, records, observations, {directive.reference: True}
            )
            self.assertEqual(
                result.directive_outcomes[directive.reference],
                DirectiveOutcome.INAPPLICABLE_CLASS,
            )
            self.assertEqual(result.states[target.reference].retention, RetentionState.ACTIVE)
        target, directive, causal, records, observations = self.fixture()
        bad = (records[0], replace(records[1], removal=RemovalClaim(target.reference, b"wrong")))
        result = PayloadModel().evaluate(
            causal, bad, observations, {directive.reference: True}
        )
        self.assertEqual(
            result.directive_outcomes[directive.reference],
            DirectiveOutcome.TARGET_COMMITMENT_MISMATCH,
        )

    def test_post_removal_presentations_remain_removed_and_distinct(self):
        target, directive, causal, records, observations = self.fixture()
        cases = {
            MISSING: PresentationState.REMOVED,
            VERIFIED: PresentationState.REMOVED_PRESENTED_VERIFIED,
            PayloadObservation(
                Availability.PRESENT, BindingObservation.OPENING_MISSING
            ): PresentationState.REMOVED_PRESENTED_UNVERIFIABLE,
            PayloadObservation(
                Availability.PRESENT, BindingObservation.LENGTH_MISMATCH
            ): PresentationState.REMOVED_SUBSTITUTED_REJECTED,
            PayloadObservation(
                Availability.PRESENT, BindingObservation.COMMITMENT_MISMATCH
            ): PresentationState.REMOVED_SUBSTITUTED_REJECTED,
        }
        observed_presentations = set()
        for observation, expected in cases.items():
            current = dict(observations)
            current[target.reference] = observation
            result = PayloadModel().evaluate(
                causal, records, current, {directive.reference: True}
            )
            state = result.states[target.reference]
            self.assertEqual(state.retention, RetentionState.LOGICALLY_REMOVED)
            self.assertEqual(state.presentation, expected)
            observed_presentations.add(state.presentation)
        self.assertGreaterEqual(len(observed_presentations), 4)

    def test_second_removal_is_idempotently_classified(self):
        target = first(b"a0", b"a", GRANT_A)
        first_remove = first(b"r0", b"b", GRANT_B, parents=(target.reference,), kind="remove")
        second_remove = next_event(b"r1", b"b", 1, first_remove.reference, kind="remove")
        causal = model().evaluate((second_remove, first_remove, target))
        records = (
            record(target.reference, ContentClass.DETACHABLE, b"target"),
            PayloadRecord(first_remove.reference, ContentDescriptor.none(), RemovalClaim(target.reference, b"target")),
            PayloadRecord(second_remove.reference, ContentDescriptor.none(), RemovalClaim(target.reference, b"target")),
        )
        observations = {reference: NONE_OBSERVATION for reference in (first_remove.reference, second_remove.reference)}
        observations[target.reference] = VERIFIED
        result = PayloadModel().evaluate(
            causal,
            records,
            observations,
            {first_remove.reference: True, second_remove.reference: True},
        )
        self.assertEqual(
            result.directive_outcomes[second_remove.reference], DirectiveOutcome.ALREADY_REMOVED
        )

    def test_late_authority_evidence_restores_active_state_under_incremental_replay(self):
        target, directive, old_causal, old_records, old_observations = self.fixture()
        old_auth = {directive.reference: True}
        old_payload = PayloadModel().evaluate(
            old_causal, old_records, old_observations, old_auth
        )
        late_evidence = first(b"z0", b"a", GRANT_A, kind="revoke-removal-authority")
        new_causal = model().evaluate((late_evidence, directive, target))
        new_records = (*old_records, PayloadRecord(late_evidence.reference, ContentDescriptor.none()))
        new_observations = dict(old_observations)
        new_observations[late_evidence.reference] = NONE_OBSERVATION
        new_auth = {directive.reference: False}
        full = PayloadModel().evaluate(new_causal, new_records, new_observations, new_auth)
        boundary, incremental = PayloadModel().incremental(
            old_causal,
            new_causal,
            old_payload,
            old_records,
            new_records,
            old_observations,
            new_observations,
            old_auth,
            new_auth,
        )
        self.assertEqual(boundary, new_causal.order.index(directive.reference))
        self.assertEqual(incremental, full)
        self.assertEqual(full.states[target.reference].retention, RetentionState.ACTIVE)

    def test_late_fork_invalidation_restores_active_state(self):
        target, directive, old_causal, old_records, old_observations = self.fixture()
        old_authorizations = {directive.reference: True}
        old_payload = PayloadModel().evaluate(
            old_causal, old_records, old_observations, old_authorizations
        )
        fork = first(
            b"r1",
            b"b",
            GRANT_B,
            parents=(target.reference,),
            kind="remove",
        )
        new_causal = model().evaluate((fork, directive, target))
        new_records = (
            *old_records,
            PayloadRecord(
                fork.reference,
                ContentDescriptor.none(),
                RemovalClaim(target.reference, b"target"),
            ),
        )
        new_observations = dict(old_observations)
        new_observations[fork.reference] = NONE_OBSERVATION
        new_authorizations = {directive.reference: False, fork.reference: False}
        full = PayloadModel().evaluate(
            new_causal,
            new_records,
            new_observations,
            new_authorizations,
        )
        boundary, incremental = PayloadModel().incremental(
            old_causal,
            new_causal,
            old_payload,
            old_records,
            new_records,
            old_observations,
            new_observations,
            old_authorizations,
            new_authorizations,
        )
        self.assertEqual(incremental, full)
        self.assertLessEqual(boundary, new_causal.order.index(directive.reference))
        self.assertEqual(
            new_causal.decisions[directive.reference].status.value, "fork"
        )
        self.assertEqual(
            new_causal.decisions[fork.reference].status.value, "fork"
        )
        self.assertEqual(full.states[target.reference].retention, RetentionState.ACTIVE)
        self.assertEqual(
            full.directive_outcomes[directive.reference], DirectiveOutcome.UNAUTHORIZED
        )
        self.assertEqual(
            full.directive_outcomes[fork.reference], DirectiveOutcome.UNAUTHORIZED
        )


class CheckpointTest(unittest.TestCase):
    def test_checkpoint_contents_ignore_availability_but_eligibility_does_not(self):
        required = first(b"a0", b"a", GRANT_A)
        causal = model().evaluate((required,))
        records = (record(required.reference, ContentClass.REQUIRED, b"required"),)
        checkpoint = PayloadCheckpoint((required.reference,))
        missing = PayloadModel().evaluate(
            causal, records, {required.reference: MISSING}, {}, checkpoint
        )
        present = PayloadModel().evaluate(
            causal, records, {required.reference: VERIFIED}, {}, checkpoint
        )
        self.assertEqual(missing.checkpoint.contents, present.checkpoint.contents)
        self.assertEqual(
            missing.checkpoint.disposition, CheckpointDisposition.PRODUCER_INELIGIBLE
        )
        self.assertEqual(present.checkpoint.disposition, CheckpointDisposition.EMITTABLE)

    def test_checkpoint_never_substitutes_for_required_content(self):
        required = first(b"a0", b"a", GRANT_A)
        later = first(b"b0", b"b", GRANT_B, parents=(required.reference,))
        causal = model().evaluate((required, later))
        records = (
            record(required.reference, ContentClass.REQUIRED, b"required"),
            record(later.reference, ContentClass.DETACHABLE, b"later"),
        )
        observations = {required.reference: MISSING, later.reference: VERIFIED}
        checkpoint = PayloadCheckpoint(tuple(sorted(causal.order)))
        result = PayloadModel().evaluate(causal, records, observations, {}, checkpoint)
        baseline = PayloadModel().evaluate(causal, records, observations, {})
        self.assertEqual(result.halted_at, required.reference)
        self.assertFalse(result.checkpoint.consumer_substitution)
        self.assertEqual(result.applied_order, ())
        self.assertEqual(replace(result, checkpoint=None), baseline)

        blocking_required = first(b"p0", b"a", GRANT_A)
        deferred_horizon_member = first(b"z0", b"b", GRANT_B)
        deferred_causal = model().evaluate(
            (deferred_horizon_member, blocking_required)
        )
        deferred_records = (
            record(blocking_required.reference, ContentClass.REQUIRED, b"blocking"),
            record(
                deferred_horizon_member.reference,
                ContentClass.REQUIRED,
                b"horizon",
            ),
        )
        deferred_observations = {
            blocking_required.reference: MISSING,
            deferred_horizon_member.reference: VERIFIED,
        }
        deferred_checkpoint = PayloadCheckpoint(
            (deferred_horizon_member.reference,)
        )
        deferred_result = PayloadModel().evaluate(
            deferred_causal,
            deferred_records,
            deferred_observations,
            {},
            deferred_checkpoint,
        )
        deferred_baseline = PayloadModel().evaluate(
            deferred_causal,
            deferred_records,
            deferred_observations,
            {},
        )
        self.assertEqual(
            deferred_result.checkpoint.disposition,
            CheckpointDisposition.EMITTABLE,
        )
        self.assertEqual(deferred_result.halted_at, blocking_required.reference)
        self.assertEqual(
            deferred_result.states[deferred_horizon_member.reference].readiness,
            ReplayReadiness.CONTENT_DEFERRED,
        )
        self.assertEqual(
            deferred_result.states[deferred_horizon_member.reference].presentation,
            PresentationState.DEFERRED,
        )
        self.assertEqual(replace(deferred_result, checkpoint=None), deferred_baseline)

    def test_checkpoint_eligibility_covers_horizon_ancestor_closure(self):
        required = first(b"f0", b"a", GRANT_A)
        child = first(b"a0", b"b", GRANT_B, parents=(required.reference,))
        grandchild = first(b"c0", b"c", GRANT_C, parents=(child.reference,))
        causal = model().evaluate((grandchild, child, required))
        records = (
            record(required.reference, ContentClass.REQUIRED, b"required"),
            record(child.reference, ContentClass.DETACHABLE, b"child"),
            record(grandchild.reference, ContentClass.DETACHABLE, b"grandchild"),
        )
        result = PayloadModel().evaluate(
            causal,
            records,
            {
                required.reference: MISSING,
                child.reference: VERIFIED,
                grandchild.reference: VERIFIED,
            },
            {},
            PayloadCheckpoint((grandchild.reference,)),
        )
        self.assertEqual(
            result.checkpoint.disposition,
            CheckpointDisposition.PRODUCER_INELIGIBLE,
        )
        self.assertFalse(result.checkpoint.producer_eligible)
        self.assertEqual(
            {item[0] for item in result.checkpoint.contents},
            {
                required.reference.hex(),
                child.reference.hex(),
                grandchild.reference.hex(),
            },
        )

    def test_bad_checkpoint_evidence_is_typed_and_non_substituting(self):
        event = first(b"a0", b"a", GRANT_A)
        causal = model().evaluate((event,))
        records = (record(event.reference, ContentClass.DETACHABLE, b"det"),)
        observations = {event.reference: VERIFIED}
        baseline = PayloadModel().evaluate(causal, records, observations, {})
        cases = (
            (PayloadCheckpoint((event.reference,), available=False), CheckpointDisposition.UNAVAILABLE),
            (PayloadCheckpoint((event.reference,), authenticated=False), CheckpointDisposition.UNAUTHENTICATED),
            (PayloadCheckpoint((event.reference,), conflicting=True), CheckpointDisposition.CONFLICTING),
            (PayloadCheckpoint((b"unknown",)), CheckpointDisposition.STALE_EVIDENCE),
        )
        contents = None
        for checkpoint, expected in cases:
            result = PayloadModel().evaluate(causal, records, observations, {}, checkpoint)
            self.assertEqual(result.checkpoint.disposition, expected)
            self.assertFalse(result.checkpoint.consumer_substitution)
            self.assertEqual(replace(result, checkpoint=None), baseline)
            if expected is CheckpointDisposition.STALE_EVIDENCE:
                self.assertFalse(result.checkpoint.producer_eligible)
            if checkpoint.horizon_refs == (event.reference,):
                if contents is None:
                    contents = result.checkpoint.contents
                else:
                    self.assertEqual(contents, result.checkpoint.contents)

        blocking_required = first(b"p0", b"a", GRANT_A)
        deferred_horizon_member = first(b"z0", b"b", GRANT_B)
        halted_causal = model().evaluate(
            (deferred_horizon_member, blocking_required)
        )
        halted_records = (
            record(blocking_required.reference, ContentClass.REQUIRED, b"blocking"),
            record(
                deferred_horizon_member.reference,
                ContentClass.REQUIRED,
                b"horizon",
            ),
        )
        halted_observations = {
            blocking_required.reference: MISSING,
            deferred_horizon_member.reference: VERIFIED,
        }
        halted_baseline = PayloadModel().evaluate(
            halted_causal, halted_records, halted_observations, {}
        )
        halted_cases = (
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
            (
                PayloadCheckpoint((b"unknown",)),
                CheckpointDisposition.STALE_EVIDENCE,
            ),
        )
        for checkpoint, expected in halted_cases:
            result = PayloadModel().evaluate(
                halted_causal,
                halted_records,
                halted_observations,
                {},
                checkpoint,
            )
            self.assertEqual(result.checkpoint.disposition, expected)
            self.assertFalse(result.checkpoint.consumer_substitution)
            self.assertEqual(replace(result, checkpoint=None), halted_baseline)

    def test_checkpoint_contents_bind_removal_claims(self):
        target = first(b"a0", b"a", GRANT_A)
        directive = first(
            b"r0", b"b", GRANT_B, parents=(target.reference,), kind="remove"
        )
        causal = model().evaluate((directive, target))
        target_record = record(target.reference, ContentClass.DETACHABLE, b"target")
        directive_record = PayloadRecord(
            directive.reference,
            ContentDescriptor.none(),
            RemovalClaim(target.reference, b"target"),
        )
        result = PayloadModel().evaluate(
            causal,
            (target_record, directive_record),
            {target.reference: VERIFIED, directive.reference: NONE_OBSERVATION},
            {directive.reference: True},
            PayloadCheckpoint(tuple(sorted(causal.order))),
        )
        baseline = PayloadModel().evaluate(
            causal,
            (target_record, directive_record),
            {target.reference: VERIFIED, directive.reference: NONE_OBSERVATION},
            {directive.reference: True},
        )
        self.assertEqual(
            result.checkpoint.disposition, CheckpointDisposition.EMITTABLE
        )
        self.assertEqual(result.states, baseline.states)
        self.assertEqual(result.directive_outcomes, baseline.directive_outcomes)
        self.assertEqual(result.applied_order, baseline.applied_order)
        self.assertEqual(result.halted_at, baseline.halted_at)
        directive_term = next(
            term for term in result.checkpoint.contents if term[0] == directive.reference.hex()
        )
        self.assertEqual(
            directive_term[-1],
            ("removal", target.reference.hex(), b"target".hex()),
        )


class PayloadBoundsTest(unittest.TestCase):
    def test_record_directive_checkpoint_and_input_bounds_fail_closed(self):
        event = first(b"a0", b"a", GRANT_A)
        causal = model().evaluate((event,))
        records = (record(event.reference, ContentClass.DETACHABLE, b"det"),)
        other = first(b"b0", b"b", GRANT_B)
        two_event_causal = model().evaluate((event, other))
        two_records = (
            records[0],
            record(other.reference, ContentClass.DETACHABLE, b"other"),
        )
        with self.assertRaises(ModelInputError):
            PayloadModel(PayloadProfile(max_records=1)).evaluate(
                two_event_causal,
                two_records,
                {event.reference: VERIFIED, other.reference: VERIFIED},
                {},
            )
        with self.assertRaises(ModelInputError):
            PayloadModel(PayloadProfile(max_checkpoint_refs=1)).evaluate(
                causal,
                records,
                {event.reference: VERIFIED},
                {},
                PayloadCheckpoint((b"a", b"b")),
            )
        with self.assertRaisesRegex(ModelInputError, "horizon is not canonical"):
            PayloadModel().evaluate(
                causal,
                records,
                {event.reference: VERIFIED},
                {},
                PayloadCheckpoint((event.reference, event.reference)),
            )
        with self.assertRaisesRegex(ModelInputError, "horizon is not canonical"):
            PayloadModel().evaluate(
                causal,
                records,
                {event.reference: VERIFIED},
                {},
                PayloadCheckpoint((b"b", b"a")),
            )
        with self.assertRaises(ModelInputError):
            PayloadModel(PayloadProfile(max_input_bytes=8)).evaluate(
                causal, records, {event.reference: VERIFIED}, {}
            )

    def test_duplicate_records_and_non_boolean_authorization_fail_closed(self):
        target = first(b"t0", b"a", GRANT_A)
        directive = next_event(
            b"d0", b"a", 1, target.reference, kind="remove"
        )
        causal = model().evaluate((directive, target))
        target_record = record(target.reference, ContentClass.DETACHABLE, b"target")
        directive_record = PayloadRecord(
            directive.reference,
            ContentDescriptor.none(),
            RemovalClaim(target.reference, b"target"),
        )
        observations = {
            target.reference: VERIFIED,
            directive.reference: NONE_OBSERVATION,
        }

        with self.assertRaisesRegex(ModelInputError, "duplicate payload record"):
            PayloadModel().evaluate(
                causal,
                (target_record, target_record, directive_record),
                observations,
                {directive.reference: True},
            )
        with self.assertRaisesRegex(
            ModelInputError, "removal authorization must be boolean"
        ):
            PayloadModel().evaluate(
                causal,
                (target_record, directive_record),
                observations,
                {directive.reference: 1},
            )

    def test_declared_content_and_geometry_bounds_fail_closed(self):
        event = first(b"a0", b"a", GRANT_A)
        causal = model().evaluate((event,))
        huge = PayloadRecord(
            event.reference,
            descriptor(ContentClass.DETACHABLE, b"x", length=10_000_000),
        )
        with self.assertRaises(ModelInputError):
            PayloadModel(PayloadProfile(max_content_length=16)).evaluate(
                causal, (huge,), {event.reference: VERIFIED}, {}
            )
        oversized_text = PayloadRecord(
            event.reference,
            replace(
                descriptor(ContentClass.DETACHABLE, b"x"),
                content_type_id="x" * 65,
            ),
        )
        with self.assertRaisesRegex(
            ModelInputError, "content type identifier is invalid"
        ):
            PayloadModel(PayloadProfile(max_text_bytes=64)).evaluate(
                causal,
                (oversized_text,),
                {event.reference: VERIFIED},
                {},
            )
        bad_geometry = PayloadRecord(
            event.reference,
            descriptor(
                ContentClass.DETACHABLE,
                b"x",
                length=6,
                shape=CommitmentShape.CHUNKED,
                geometry=ChunkGeometry(4, 2, 3),
            ),
        )
        with self.assertRaises(ModelInputError):
            PayloadModel().evaluate(
                causal, (bad_geometry,), {event.reference: VERIFIED}, {}
            )

    def test_directive_count_bound_fails_before_projection(self):
        target = first(b"a0", b"a", GRANT_A)
        first_remove = first(
            b"r0", b"b", GRANT_B, parents=(target.reference,), kind="remove"
        )
        second_remove = next_event(
            b"r1", b"b", 1, first_remove.reference, kind="remove"
        )
        causal = model().evaluate((second_remove, first_remove, target))
        records = (
            record(target.reference, ContentClass.DETACHABLE, b"target"),
            PayloadRecord(
                first_remove.reference,
                ContentDescriptor.none(),
                RemovalClaim(target.reference, b"target"),
            ),
            PayloadRecord(
                second_remove.reference,
                ContentDescriptor.none(),
                RemovalClaim(target.reference, b"target"),
            ),
        )
        observations = {
            target.reference: VERIFIED,
            first_remove.reference: NONE_OBSERVATION,
            second_remove.reference: NONE_OBSERVATION,
        }
        with self.assertRaises(ModelInputError):
            PayloadModel(PayloadProfile(max_directives=1)).evaluate(
                causal,
                records,
                observations,
                {first_remove.reference: True, second_remove.reference: True},
            )


if __name__ == "__main__":
    unittest.main()
