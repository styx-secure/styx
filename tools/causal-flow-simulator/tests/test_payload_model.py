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
from scenarios import CTX, GRANT_A, GRANT_B, first, model, next_event


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

    def test_closed_axis_set_accepts_only_legal_combinations(self):
        event = first(b"a0", b"a", GRANT_A)
        causal = model().evaluate((event,))
        legal = {
            (Availability.ABSENT, BindingObservation.NOT_CHECKED),
            (Availability.PARTIAL, BindingObservation.NOT_CHECKED),
            (Availability.PRESENT, BindingObservation.NOT_CHECKED),
            (Availability.PRESENT, BindingObservation.VERIFIED),
            (Availability.PRESENT, BindingObservation.OPENING_MISSING),
            (Availability.PRESENT, BindingObservation.LENGTH_MISMATCH),
            (Availability.PRESENT, BindingObservation.COMMITMENT_MISMATCH),
        }
        payload_record = record(event.reference, ContentClass.DETACHABLE, b"ct")
        for availability, binding in product(Availability, BindingObservation):
            operation = lambda: PayloadModel().evaluate(
                causal,
                (payload_record,),
                {event.reference: PayloadObservation(availability, binding)},
                {},
            )
            with self.subTest(availability=availability, binding=binding):
                if (availability, binding) in legal:
                    operation()
                else:
                    with self.assertRaises(ModelInputError):
                        operation()

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

    def test_incremental_rejects_unvalidated_old_payload_state(self):
        event = first(b"a0", b"a", GRANT_A)
        causal = model().evaluate((event,))
        records = (record(event.reference, ContentClass.REQUIRED, b"req"),)
        observations = {event.reference: VERIFIED}
        old = PayloadModel().evaluate(causal, records, observations, {})
        forged = replace(old, snapshots=())
        with self.assertRaises(ModelInputError):
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
        checkpoint = PayloadCheckpoint(causal.order)
        result = PayloadModel().evaluate(causal, records, observations, {}, checkpoint)
        self.assertEqual(result.halted_at, required.reference)
        self.assertFalse(result.checkpoint.consumer_substitution)
        self.assertEqual(result.applied_order, ())

    def test_bad_checkpoint_evidence_is_typed_and_non_substituting(self):
        event = first(b"a0", b"a", GRANT_A)
        causal = model().evaluate((event,))
        records = (record(event.reference, ContentClass.DETACHABLE, b"det"),)
        observations = {event.reference: VERIFIED}
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
            if checkpoint.horizon_refs == (event.reference,):
                if contents is None:
                    contents = result.checkpoint.contents
                else:
                    self.assertEqual(contents, result.checkpoint.contents)


class PayloadBoundsTest(unittest.TestCase):
    def test_record_directive_checkpoint_and_input_bounds_fail_closed(self):
        event = first(b"a0", b"a", GRANT_A)
        causal = model().evaluate((event,))
        records = (record(event.reference, ContentClass.DETACHABLE, b"det"),)
        with self.assertRaises(ModelInputError):
            PayloadModel(PayloadProfile(max_records=1)).evaluate(
                causal, records * 2, {event.reference: VERIFIED}, {}
            )
        with self.assertRaises(ModelInputError):
            PayloadModel(PayloadProfile(max_checkpoint_refs=1)).evaluate(
                causal,
                records,
                {event.reference: VERIFIED},
                {},
                PayloadCheckpoint((b"a", b"b")),
            )
        with self.assertRaises(ModelInputError):
            PayloadModel(PayloadProfile(max_input_bytes=8)).evaluate(
                causal, records, {event.reference: VERIFIED}, {}
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
