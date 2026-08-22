from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

V2_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(V2_ROOT))

from kernel_model_v2 import (  # noqa: E402
    Availability,
    AxisPresentation,
    BindingObservation,
    ContentClass,
    EventKind,
    EventRole,
    MAX_TEXT_BYTES,
    ModelInputError,
    OpeningObservation,
    Outcome,
    classify_payload_axis,
    frontier_is_producible,
    incremental_replay,
    project,
)
import kernel_model_v2  # noqa: E402
from scenarios_v2 import _scenario, event  # noqa: E402


class PendingSubtreeTests(unittest.TestCase):
    def test_payload_axis_preserves_detachable_substitution_state(self) -> None:
        self.assertIs(
            classify_payload_axis(
                ContentClass.DETACHABLE,
                Availability.PRESENT,
                BindingObservation.COMMITMENT_MISMATCH,
            ),
            AxisPresentation.ACTIVE_SUBSTITUTED_REJECTED,
        )

    def test_payload_axis_rejects_unlisted_combination(self) -> None:
        with self.assertRaisesRegex(
            ModelInputError, "ILLEGAL_AXIS_COMBINATION"
        ):
            classify_payload_axis(
                ContentClass.REQUIRED,
                Availability.ABSENT,
                BindingObservation.VERIFIED,
            )

    def test_opening_observation_type_fails_closed(self) -> None:
        root = event("root", 0, content=ContentClass.REQUIRED)
        with self.assertRaisesRegex(
            ModelInputError, "ILLEGAL_AXIS_COMBINATION"
        ):
            project(_scenario((root,), {"root": "VERIFIED"}))

    def test_independent_event_applies_while_descendant_waits(self) -> None:
        root = event("root", 0, content=ContentClass.REQUIRED)
        child = event("child", 1, predecessor="root")
        independent = event("independent", 0, credential="peer")
        result = project(_scenario((root, child, independent), genesis=("admin", "peer")))
        self.assertEqual(result.pending_roots, {"root"})
        self.assertEqual(result.pending, {"root", "child"})
        self.assertEqual(result.applied_order, ("independent",))
        self.assertIs(result.outcomes["root"], Outcome.PENDING_OPENING)
        self.assertIs(result.outcomes["child"], Outcome.PENDING_ANCESTOR)

    def test_opening_does_not_change_k_graph(self) -> None:
        root = event("root", 0, content=ContentClass.REQUIRED)
        child = event("child", 1, predecessor="root")
        absent = _scenario((root, child))
        present = replace(
            absent, opening_observations={"root": OpeningObservation.VERIFIED}
        )
        before = project(absent)
        after = project(present)
        self.assertEqual(before.graph, after.graph)
        self.assertFalse(after.pending)

    def test_incremental_equals_full_and_reports_boundary(self) -> None:
        first = event("first", 0)
        root = event("root", 0, credential="peer", content=ContentClass.REQUIRED)
        child = event("child", 1, credential="peer", predecessor="root")
        prior = _scenario((first, root, child), genesis=("admin", "peer"))
        updated = replace(
            prior, opening_observations={"root": OpeningObservation.VERIFIED}
        )
        incremental = incremental_replay(prior, updated)
        full = project(updated)
        self.assertEqual(incremental.semantic_view(), full.semantic_view())
        self.assertEqual(incremental.metrics.earliest_replay_boundary, 1)
        self.assertEqual(incremental.metrics.replayed_event_work, 2)

    def test_incremental_replays_when_only_nested_root_status_changes(self) -> None:
        outer = event("outer", 0, content=ContentClass.REQUIRED)
        inner = event(
            "inner",
            1,
            predecessor="outer",
            content=ContentClass.REQUIRED,
        )
        prior = _scenario((outer, inner))
        updated = replace(
            prior,
            opening_observations={"inner": OpeningObservation.VERIFIED},
        )
        before = project(prior)
        incremental = incremental_replay(prior, updated)
        full = project(updated)
        self.assertEqual(before.pending, full.pending)
        self.assertNotEqual(before.pending_roots, full.pending_roots)
        self.assertEqual(incremental.semantic_view(), full.semantic_view())
        self.assertIs(incremental.outcomes["inner"], Outcome.PENDING_ANCESTOR)
        self.assertEqual(incremental.metrics.earliest_replay_boundary, 1)

    def test_incremental_uses_prior_cache_not_updated_full_projection(self) -> None:
        root = event("root", 0, content=ContentClass.REQUIRED)
        child = event("child", 1, predecessor="root")
        prior = _scenario((root, child))
        updated = replace(
            prior, opening_observations={"root": OpeningObservation.VERIFIED}
        )
        real_project = kernel_model_v2.project
        calls = []

        def guarded_project(candidate):
            calls.append(candidate)
            if candidate is updated:
                self.fail("incremental replay called the updated full oracle")
            return real_project(candidate)

        with patch.object(kernel_model_v2, "project", side_effect=guarded_project):
            incremental = incremental_replay(prior, updated)

        self.assertEqual(calls, [prior])
        self.assertEqual(incremental.semantic_view(), real_project(updated).semantic_view())
        self.assertEqual(
            len(real_project(prior).replay_prefix_states),
            len(real_project(prior).graph.canonical_order) + 1,
        )

    def test_verified_opening_cannot_be_removed(self) -> None:
        root = event("root", 0, content=ContentClass.REQUIRED)
        verified = _scenario(
            (root,), {"root": OpeningObservation.VERIFIED}
        )
        absent = _scenario((root,))
        with self.assertRaisesRegex(ModelInputError, "NON_MONOTONE_OPENING_SET"):
            incremental_replay(verified, absent)

    def test_checkpoint_only_dependency_precedes_pending_fold(self) -> None:
        root = event("root", 0, content=ContentClass.REQUIRED)
        result = project(
            _scenario((root,), checkpoint_only=("revocation-in-checkpoint",))
        )
        self.assertIs(result.outcomes["root"], Outcome.STALE_EVIDENCE)
        self.assertEqual(result.applied_order, ())
        self.assertEqual(result.authorized_credentials, frozenset())
        self.assertTrue(result.stale_evidence)

    def test_incremental_replay_preserves_fork_quarantine_under_staleness(self) -> None:
        left = event("fork-left", 0, content=ContentClass.REQUIRED)
        right = event("fork-right", 0)
        prior = _scenario(
            (left, right),
            checkpoint_only=("withheld-transcript",),
        )
        updated = replace(
            prior,
            opening_observations={"fork-left": OpeningObservation.VERIFIED},
        )
        incremental = incremental_replay(prior, updated)
        full = project(updated)
        self.assertEqual(incremental.semantic_view(), full.semantic_view())
        self.assertTrue(incremental.stale_evidence)
        self.assertTrue(incremental.fork_quarantined)
        self.assertEqual(incremental.applied_order, ())
        self.assertEqual(incremental.authorized_credentials, frozenset())

    def test_live_admitted_reference_is_not_checkpoint_only(self) -> None:
        root = event("root", 0, content=ContentClass.REQUIRED)
        scenario = _scenario((root,), checkpoint_only=("root",))
        result = project(scenario)
        self.assertFalse(result.stale_evidence)
        self.assertIs(result.outcomes["root"], Outcome.PENDING_OPENING)
        self.assertFalse(frontier_is_producible(scenario, ("root",)))

    def test_checkpoint_evidence_unrelated_to_replay_is_not_stale(self) -> None:
        root = event("root", 0)
        result = project(
            _scenario(
                (root,),
                checkpoint_evidence=("unrelated",),
                replay_dependencies=(),
            )
        )
        self.assertIs(result.outcomes["root"], Outcome.APPLIED)

    def test_incremental_accepts_equal_transcript_sets_in_different_order(self) -> None:
        root = event("root", 0, content=ContentClass.REQUIRED)
        side = event("side", 0, credential="peer")
        prior = _scenario((root, side), genesis=("admin", "peer"))
        updated = _scenario(
            (side, root),
            {"root": OpeningObservation.VERIFIED},
            genesis=("admin", "peer"),
        )
        self.assertEqual(
            incremental_replay(prior, updated).semantic_view(),
            project(updated).semantic_view(),
        )

    def test_ready_concurrent_events_use_reference_tiebreak(self) -> None:
        high = event("z-reference", 0, credential="admin")
        low = event("a-reference", 0, credential="peer")
        result = project(
            _scenario((high, low), genesis=("admin", "peer"))
        )
        self.assertEqual(result.graph.canonical_order, ("a-reference", "z-reference"))

    def test_author_gap_is_structural_not_graph_evidence(self) -> None:
        root = event("root", 0)
        gap = event("gap", 2, predecessor="root")
        result = project(_scenario((root, gap)))
        self.assertEqual(result.graph.structurally_rejected, ("gap",))
        self.assertNotIn("gap", result.graph.admitted)
        self.assertIs(result.outcomes["gap"], Outcome.STRUCTURAL_REJECTION)

    def test_self_parent_is_structural_not_a_model_abort(self) -> None:
        invalid = event("self", 0, parents=("self",))
        result = project(_scenario((invalid,)))
        self.assertEqual(result.graph.structurally_rejected, ("self",))
        self.assertIs(result.outcomes["self"], Outcome.STRUCTURAL_REJECTION)

    def test_parent_descending_from_direct_predecessor_is_valid(self) -> None:
        admin_zero = event("a0", 0)
        peer_zero = event(
            "p0", 0, credential="peer", parents=("a0",)
        )
        admin_one = event("a1", 1, predecessor="a0", parents=("p0",))
        result = project(
            _scenario((admin_zero, peer_zero, admin_one), genesis=("admin", "peer"))
        )
        self.assertIn("a1", result.graph.admitted)
        self.assertIs(result.outcomes["a1"], Outcome.APPLIED)

    def test_parent_ancestor_of_direct_predecessor_is_redundant(self) -> None:
        peer_zero = event("p0", 0, credential="peer")
        admin_zero = event("a0", 0, parents=("p0",))
        admin_one = event("a1", 1, predecessor="a0", parents=("p0",))
        result = project(
            _scenario((peer_zero, admin_zero, admin_one), genesis=("admin", "peer"))
        )
        self.assertIs(result.outcomes["a1"], Outcome.STRUCTURAL_REJECTION)

    def test_non_ancestral_binding_is_invalid_not_deferred(self) -> None:
        grant = event("a-grant", 0, kind=EventKind.GRANT, subject="bob")
        invalid = event(
            "z-bob", 0, credential="bob", binding_ref="a-grant"
        )
        child = event(
            "bob-child",
            1,
            credential="bob",
            predecessor="z-bob",
            binding_ref="a-grant",
        )
        result = project(_scenario((grant, invalid, child)))
        self.assertIn("a-grant", result.graph.admitted)
        self.assertEqual(set(result.graph.invalid), {"z-bob", "bob-child"})
        self.assertIs(result.outcomes["z-bob"], Outcome.INVALID)
        self.assertIs(result.outcomes["bob-child"], Outcome.INVALID)

    def test_subjectless_grant_is_structurally_rejected(self) -> None:
        result = project(_scenario((event("grant", 0, kind=EventKind.GRANT),)))
        self.assertIs(result.outcomes["grant"], Outcome.STRUCTURAL_REJECTION)

    def test_scalar_bounds_fail_before_graph_expansion(self) -> None:
        oversized = "x" * (MAX_TEXT_BYTES + 1)
        with self.assertRaisesRegex(ModelInputError, "MODEL_BOUND_EXCEEDED"):
            project(_scenario((event("root", 0),), context=oversized))

    def test_binding_observations_remain_distinct(self) -> None:
        root = event("root", 0, content=ContentClass.REQUIRED)
        observed = {
            value: project(_scenario((root,), {"root": value}))
            .binding_observations["root"]
            for value in (
                OpeningObservation.OPENING_MISSING,
                OpeningObservation.LENGTH_MISMATCH,
                OpeningObservation.COMMITMENT_MISMATCH,
            )
        }
        self.assertEqual(set(observed), set(observed.values()))


class AuthorityBoundaryTests(unittest.TestCase):
    def test_bound_grantee_requires_ap_authority(self) -> None:
        grant = event("grant", 0, kind=EventKind.GRANT, subject="bob")
        bob_action = event(
            "bob-action",
            0,
            credential="bob",
            parents=("grant",),
            binding_ref="grant",
        )
        result = project(_scenario((grant, bob_action)))
        self.assertIs(result.outcomes["bob-action"], Outcome.APPLIED)

    def test_revoked_key_event_is_graph_evidence_not_ap_effect(self) -> None:
        grant = event("grant", 0, kind=EventKind.GRANT, subject="bob")
        bob_action = event(
            "bob-action",
            0,
            credential="bob",
            parents=("grant",),
            binding_ref="grant",
        )
        revoke = event(
            "revoke", 1, predecessor="grant", kind=EventKind.REVOKE, subject="bob"
        )
        old = event(
            "old",
            1,
            credential="bob",
            predecessor="bob-action",
            parents=("revoke",),
            binding_ref="grant",
        )
        result = project(_scenario((grant, bob_action, revoke, old)))
        self.assertIn("old", result.graph.admitted)
        self.assertIs(result.outcomes["old"], Outcome.POST_REVOCATION)

    def test_content_bearing_control_rejects_before_opening(self) -> None:
        invalid = event(
            "invalid",
            0,
            kind=EventKind.POLICY,
            content=ContentClass.REQUIRED,
        )
        result = project(_scenario((invalid,)))
        self.assertFalse(result.pending)
        self.assertNotIn("invalid", result.graph.admitted)
        self.assertIs(result.outcomes["invalid"], Outcome.STRUCTURAL_REJECTION)

    def test_control_role_on_ordinary_kind_is_structural(self) -> None:
        invalid = event(
            "invalid-role",
            0,
            kind=EventKind.ACTION,
            role=EventRole.CONTROL,
            content=ContentClass.REQUIRED,
        )
        result = project(_scenario((invalid,)))
        self.assertIs(
            result.outcomes["invalid-role"], Outcome.STRUCTURAL_REJECTION
        )
        self.assertFalse(result.pending)

    def test_duplicate_genesis_identifier_rejects_before_projection(self) -> None:
        with self.assertRaisesRegex(
            ModelInputError, "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED"
        ):
            project(_scenario((), genesis=("admin", "admin")))

    def test_independent_closure_applies_outside_pending_subtree(self) -> None:
        hole = event("hole", 0, content=ContentClass.REQUIRED)
        closure = event(
            "closure", 0, credential="recovery", kind=EventKind.CLOSURE
        )
        result = project(
            _scenario((hole, closure), genesis=("admin", "recovery"))
        )
        self.assertIs(result.outcomes["hole"], Outcome.PENDING_OPENING)
        self.assertIs(result.outcomes["closure"], Outcome.APPLIED)

    def test_stale_outcomes_do_not_hide_terminal_fork_quarantine(self) -> None:
        left = event("left", 0)
        right = event("right", 0)
        independent = event("independent", 0, credential="recovery")
        scenario = _scenario(
            (left, right, independent),
            genesis=("admin", "recovery"),
            checkpoint_only=("withheld",),
        )
        result = project(scenario)
        self.assertTrue(result.stale_evidence)
        self.assertTrue(result.fork_quarantined)
        self.assertEqual(
            {result.outcomes[reference] for reference in result.graph.admitted},
            {Outcome.STALE_EVIDENCE},
        )
        self.assertFalse(frontier_is_producible(scenario, ("independent",)))

    def test_conflicting_grants_reject_independent_of_arrival(self) -> None:
        left = event("left", 0, kind=EventKind.GRANT, subject="bob")
        right = event("right", 0, kind=EventKind.GRANT, subject="bob")
        for events in ((left, right), (right, left)):
            with self.assertRaisesRegex(
                ModelInputError, "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED"
            ):
                project(_scenario(events))

    def test_all_causal_revocations_are_retained(self) -> None:
        grant = event("grant", 0, kind=EventKind.GRANT, subject="bob")
        first = event(
            "revoke-a", 1, predecessor="grant", kind=EventKind.REVOKE, subject="bob"
        )
        second = event(
            "a-revoke-b",
            2,
            predecessor="revoke-a",
            kind=EventKind.REVOKE,
            subject="bob",
        )
        action = event(
            "z-bob",
            0,
            credential="bob",
            parents=("revoke-a",),
            binding_ref="grant",
        )
        result = project(_scenario((grant, first, second, action)))
        self.assertIs(result.outcomes["z-bob"], Outcome.POST_REVOCATION)

    def test_rotation_or_recovery_does_not_resurrect_identifier(self) -> None:
        grant = event("grant", 0, kind=EventKind.GRANT, subject="bob")
        revoke = event(
            "a-revoke", 1, predecessor="grant", kind=EventKind.REVOKE, subject="bob"
        )
        recover = event(
            "z-recover",
            0,
            credential="recovery",
            parents=("grant",),
            kind=EventKind.RECOVER,
            subject="bob",
        )
        action = event(
            "zz-bob",
            0,
            credential="bob",
            parents=("z-recover",),
            binding_ref="grant",
        )
        result = project(
            _scenario((grant, revoke, recover, action), genesis=("admin", "recovery"))
        )
        self.assertIs(result.outcomes["z-recover"], Outcome.APPLIED)
        self.assertIs(
            result.outcomes["zz-bob"], Outcome.AUTHENTIC_BUT_UNAUTHORIZED
        )

    def test_any_same_author_fork_quarantines_the_whole_ap_projection(self) -> None:
        left = event("left", 0)
        right = event("right", 0)
        independent = event("independent", 0, credential="recovery")
        scenario = _scenario(
            (left, right, independent),
            genesis=("admin", "recovery"),
        )
        result = project(scenario)
        self.assertTrue(result.fork_quarantined)
        self.assertEqual(result.graph.forks, {"left", "right"})
        self.assertIs(result.outcomes["left"], Outcome.FORK_EVIDENCE)
        self.assertIs(result.outcomes["right"], Outcome.FORK_EVIDENCE)
        self.assertIs(
            result.outcomes["independent"], Outcome.FORK_QUARANTINED
        )
        self.assertEqual(result.applied_order, ())
        self.assertEqual(result.authorized_credentials, frozenset())
        self.assertEqual(result.removed_targets, frozenset())
        self.assertFalse(frontier_is_producible(scenario, ("independent",)))

    def test_concurrent_grant_can_survive_revocation_in_v0_nonclaim(self) -> None:
        grant = event(
            "a-grant", 0, kind=EventKind.GRANT, subject="evil"
        )
        revoke = event(
            "z-revoke",
            0,
            credential="recovery",
            kind=EventKind.REVOKE,
            subject="admin",
        )
        action = event(
            "b-action",
            0,
            credential="evil",
            parents=("a-grant",),
            binding_ref="a-grant",
        )
        unsafe_order = project(
            _scenario((grant, revoke, action), genesis=("admin", "recovery"))
        )
        self.assertFalse(unsafe_order.graph.forks)
        self.assertIs(unsafe_order.outcomes["b-action"], Outcome.APPLIED)
        self.assertEqual(
            unsafe_order.authorized_credentials, {"evil", "recovery"}
        )

        revoke_first = replace(revoke, reference="a-revoke")
        grant_last = replace(grant, reference="z-grant")
        action_last = replace(
            action,
            reference="zz-action",
            parents=("z-grant",),
            binding_ref="z-grant",
        )
        safe_order = project(
            _scenario(
                (revoke_first, grant_last, action_last),
                genesis=("admin", "recovery"),
            )
        )
        self.assertIs(
            safe_order.outcomes["z-grant"],
            Outcome.AUTHENTIC_BUT_UNAUTHORIZED,
        )
        self.assertIs(
            safe_order.outcomes["zz-action"],
            Outcome.AUTHENTIC_BUT_UNAUTHORIZED,
        )
        self.assertEqual(safe_order.authorized_credentials, {"recovery"})


if __name__ == "__main__":
    unittest.main()
