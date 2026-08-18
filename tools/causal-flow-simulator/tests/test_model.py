from __future__ import annotations

from dataclasses import replace
import unittest

import support

from model import (
    CausalModel,
    CheckpointEvidence,
    Context,
    CredentialAuthority,
    Event,
    ModelInputError,
    Profile,
    Status,
    affected_replay_boundary,
    evaluation_json,
    incremental_handoffs,
)
from scenarios import CTX, GRANT_A, GRANT_B, checkpoint, first, model, next_event


class StructuralValidationTest(unittest.TestCase):
    def test_profile_rejects_non_integer_and_zero_limits(self):
        for profile in (Profile(max_events=0), Profile(max_parents=True)):
            with self.subTest(profile=profile):
                with self.assertRaises(ModelInputError):
                    profile.validate()

    def test_observation_budget_fails_closed(self):
        evaluator = model(profile=Profile(max_events=1))
        with self.assertRaises(ModelInputError):
            evaluator.evaluate((first(b"a0", b"a", GRANT_A), first(b"b0", b"b", GRANT_B)))

    def test_credential_checkpoint_and_text_budgets_fail_closed(self):
        with self.assertRaises(ModelInputError):
            model(profile=Profile(max_credentials=3))
        with self.assertRaises(ModelInputError):
            model(profile=Profile(max_checkpoint_refs=3))
        with self.assertRaises(ModelInputError):
            CausalModel(
                context=Context("too-long", "p", "i", b"g"),
                authorities=(),
                checkpoint=CheckpointEvidence(Context("too-long", "p", "i", b"g")),
                profile=Profile(max_text_bytes=2),
            )

    def test_total_input_byte_budget_counts_duplicate_observations(self):
        context = Context("a", "p", "i", b"g")
        authority = CredentialAuthority(b"a", context, b"q")
        evidence = CheckpointEvidence(context, frozenset((b"q",)))
        evaluator = CausalModel(
            context=context,
            authorities=(authority,),
            checkpoint=evidence,
            profile=Profile(max_input_bytes=55),
        )
        event = Event(b"e", context, b"a", 0, None, (b"q",))
        self.assertEqual(evaluator.evaluate((event,)).order, (b"e",))
        with self.assertRaises(ModelInputError):
            evaluator.evaluate((event, event))

    def test_kind_has_a_utf8_byte_bound(self):
        event = first(b"a0", b"a", GRANT_A, kind="ééééééé")
        result = model(profile=Profile(max_text_bytes=12)).evaluate((event,))
        self.assertEqual(result.decisions[event.reference].status, Status.INVALID)
        self.assertIn("KIND_INVALID", result.decisions[event.reference].reasons)

    def test_wrong_runtime_field_types_fail_closed_before_graph_work(self):
        malformed = Event(b"a0", CTX, b"a", 0, None, ("not-bytes",))  # type: ignore[arg-type]
        with self.assertRaises(ModelInputError):
            model().evaluate((malformed,))

    def test_duplicate_observation_does_not_duplicate_effect(self):
        event = first(b"a0", b"a", GRANT_A)
        result = model().evaluate((event, event))
        self.assertEqual(result.duplicate_refs, (event.reference,))
        self.assertEqual(result.decisions[event.reference].duplicate_observations, 1)
        self.assertEqual(result.order, (event.reference,))
        self.assertEqual(len(result.handoffs), 1)

    def test_same_reference_with_different_content_is_invalid(self):
        event = first(b"a0", b"a", GRANT_A)
        collision = replace(event, kind="different")
        result = model().evaluate((event, collision))
        self.assertEqual(result.decisions[event.reference].status, Status.INVALID)
        self.assertIn("REFERENCE_COLLISION", result.decisions[event.reference].reasons)

    def test_parent_list_must_be_sorted_unique_and_bounded(self):
        duplicate = Event(b"a0", CTX, b"a", 0, None, (GRANT_A, GRANT_A))
        result = model().evaluate((duplicate,))
        self.assertEqual(result.decisions[duplicate.reference].status, Status.INVALID)
        self.assertIn("PARENTS_NOT_CANONICAL", result.decisions[duplicate.reference].reasons)

        fanout = Event(b"a1", CTX, b"a", 0, None, (b"1", b"2", GRANT_A))
        result = model(profile=Profile(max_parents=2)).evaluate((fanout,))
        self.assertIn("PARENT_COUNT_BOUNDS", result.decisions[fanout.reference].reasons)

    def test_context_separation_is_fail_closed(self):
        other = Context("example.app", "bounded-v0", "other", b"z")
        foreign = Event(b"f0", other, b"b", 0, None, (GRANT_B,))
        local = first(b"a0", b"a", GRANT_A, parents=(foreign.reference,))
        result = model().evaluate((foreign, local))
        self.assertEqual(result.decisions[local.reference].status, Status.INVALID)
        self.assertIn("CROSS_CONTEXT_PARENT", result.decisions[local.reference].reasons)


class AuthorChainAndEvidenceTest(unittest.TestCase):
    def test_child_before_parent_is_deferred_then_admitted(self):
        parent = first(b"a0", b"a", GRANT_A)
        child = next_event(b"a1", b"a", 1, parent.reference)
        deferred = model().evaluate((child,))
        self.assertEqual(deferred.decisions[child.reference].status, Status.DEFERRED)
        self.assertEqual(deferred.handoffs, ())
        admitted = model().evaluate((child, parent))
        self.assertEqual(admitted.order, (parent.reference, child.reference))

    def test_wrong_sequence_is_gap_not_deferred(self):
        parent = first(b"a0", b"a", GRANT_A)
        child = next_event(b"a2", b"a", 2, parent.reference)
        result = model().evaluate((parent, child))
        self.assertEqual(result.decisions[child.reference].status, Status.GAP)
        self.assertEqual(result.decisions[child.reference].reasons, ("AUTHOR_SEQUENCE_GAP",))

    def test_checkpoint_head_must_match_author_predecessor(self):
        evidence = checkpoint(
            proven=frozenset((GRANT_A, GRANT_B, b"old")),
            heads=((b"a", 7, b"old"),),
        )
        continued = next_event(b"a8", b"a", 8, b"old")
        result = model(evidence=evidence).evaluate((continued,))
        self.assertEqual(result.decisions[continued.reference].status, Status.ADMITTED)

        wrong = next_event(b"a9", b"a", 9, b"old")
        result = model(evidence=evidence).evaluate((wrong,))
        self.assertEqual(result.decisions[wrong.reference].status, Status.GAP)

    def test_missing_stale_and_proven_are_distinct(self):
        event = next_event(b"a1", b"a", 1, b"old")
        missing = model().evaluate((event,))
        self.assertEqual(missing.decisions[event.reference].status, Status.DEFERRED)

        stale_checkpoint = checkpoint(stale=frozenset((b"old",)))
        stale = model(evidence=stale_checkpoint).evaluate((event,))
        self.assertEqual(stale.decisions[event.reference].status, Status.STALE)

        proven_checkpoint = checkpoint(
            proven=frozenset((GRANT_A, GRANT_B, b"old")),
            heads=((b"a", 0, b"old"),),
        )
        proven = model(evidence=proven_checkpoint).evaluate((event,))
        self.assertEqual(proven.decisions[event.reference].status, Status.ADMITTED)

    def test_checkpoint_evidence_cannot_be_both_proven_and_stale(self):
        evidence = CheckpointEvidence(CTX, frozenset((b"x",)), frozenset((b"x",)))
        with self.assertRaises(ModelInputError):
            CausalModel(
                context=CTX,
                authorities=(CredentialAuthority(b"a", CTX, GRANT_A),),
                checkpoint=evidence,
                profile=Profile(),
            )


class CausalityAndForkTest(unittest.TestCase):
    def test_topological_order_exposes_ready_sets(self):
        a0 = first(b"\x10", b"a", GRANT_A)
        b0 = first(b"\x20", b"b", GRANT_B)
        a1 = next_event(b"\x30", b"a", 1, a0.reference, parents=(b0.reference,))
        result = model().evaluate((a1, b0, a0))
        self.assertEqual(result.ready_sets[0], (a0.reference, b0.reference))
        self.assertEqual(result.order, (a0.reference, b0.reference, a1.reference))

    def test_redundant_frontier_is_invalid(self):
        a0 = first(b"a0", b"a", GRANT_A)
        a1 = next_event(b"a1", b"a", 1, a0.reference)
        b0 = first(b"b0", b"b", GRANT_B, parents=(a0.reference, a1.reference))
        result = model().evaluate((a0, a1, b0))
        self.assertEqual(result.decisions[b0.reference].status, Status.INVALID)
        self.assertIn("PARENT_FRONTIER_NOT_ANTICHAIN", result.decisions[b0.reference].reasons)

    def test_same_sequence_fork_is_retained_not_resolved(self):
        a0 = first(b"a0", b"a", GRANT_A)
        left = next_event(b"a1", b"a", 1, a0.reference)
        right = next_event(b"a2", b"a", 1, a0.reference)
        result = model().evaluate((right, a0, left))
        self.assertEqual(result.decisions[left.reference].status, Status.FORK)
        self.assertEqual(result.decisions[right.reference].status, Status.FORK)
        self.assertEqual(result.decisions[left.reference].fork_peers, (right.reference,))
        self.assertIn(left.reference, result.order)
        self.assertIn(right.reference, result.order)

    def test_cycle_is_rejected(self):
        left = first(b"a0", b"a", GRANT_A, parents=(b"b0",))
        right = first(b"b0", b"b", GRANT_B, parents=(b"a0",))
        result = model().evaluate((left, right))
        self.assertIn("CYCLE", result.decisions[left.reference].reasons)
        self.assertIn("CYCLE", result.decisions[right.reference].reasons)
        self.assertEqual(result.order, ())

    def test_checkpoint_proven_revocation_ancestor_rejects_action(self):
        revoke_ref = b"rv"
        evidence = CheckpointEvidence(
            CTX,
            frozenset((GRANT_A, GRANT_B, revoke_ref)),
            frozenset(),
        )
        evaluator = CausalModel(
            context=CTX,
            authorities=(
                CredentialAuthority(b"a", CTX, GRANT_A, (revoke_ref,)),
                CredentialAuthority(b"b", CTX, GRANT_B),
            ),
            checkpoint=evidence,
            profile=Profile(),
        )
        event = first(b"a0", b"a", GRANT_A, parents=(revoke_ref,))
        result = evaluator.evaluate((event,))
        self.assertEqual(result.decisions[event.reference].status, Status.INVALID)
        self.assertEqual(result.decisions[event.reference].reasons, ("POST_REVOCATION",))


class ReplayTest(unittest.TestCase):
    def test_boundary_moves_to_first_changed_position(self):
        self.assertEqual(affected_replay_boundary((b"a", b"c"), (b"a", b"b", b"c")), 1)
        self.assertEqual(affected_replay_boundary((b"a", b"b"), (b"a", b"b", b"c")), 2)

    def test_incremental_suffix_is_full_replay_equivalent(self):
        a0 = first(b"\x10", b"a", GRANT_A)
        c0 = first(b"\x40", b"b", GRANT_B, parents=(a0.reference,))
        late = first(b"\x20", b"b", GRANT_B)
        old = model().evaluate((a0, c0))
        new = model().evaluate((a0, c0, late))
        boundary, handoffs = incremental_handoffs(old, new)
        self.assertEqual(boundary, 1)
        self.assertEqual(handoffs, new.handoffs)

    def test_handoff_is_prefix_scoped_while_graph_decisions_are_set_scoped(self):
        a0 = first(b"a0", b"a", GRANT_A)
        left = next_event(b"a1", b"a", 1, a0.reference)
        right = next_event(b"a2", b"a", 1, a0.reference)
        old = model().evaluate((a0, left))
        new = model().evaluate((a0, left, right))
        boundary, incremental = incremental_handoffs(old, new)

        self.assertEqual(new.decisions[left.reference].status, Status.FORK)
        self.assertEqual(new.handoffs[1].classification, Status.ADMITTED)
        self.assertEqual(new.handoffs[1].fork_peers, ())
        self.assertEqual(new.handoffs[2].classification, Status.FORK)
        self.assertEqual(new.handoffs[2].fork_peers, (left.reference,))
        self.assertEqual(boundary, len(old.order))
        self.assertEqual(incremental, new.handoffs)

    def test_handoff_does_not_contain_business_verdict(self):
        result = evaluation_json(model().evaluate((first(b"a0", b"a", GRANT_A),)))
        keys = set(result["handoffs"][0])
        self.assertEqual(result["handoffs"][0]["classification"], "admitted")
        self.assertEqual(result["handoffs"][0]["grant_ref"], GRANT_A.hex())
        self.assertTrue(
            keys.isdisjoint({"accept", "reject", "authorized", "delivered", "final", "effect"})
        )


if __name__ == "__main__":
    unittest.main()
