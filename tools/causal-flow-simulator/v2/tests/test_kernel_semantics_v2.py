from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path

V2_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(V2_ROOT))

from kernel_model_v2 import (  # noqa: E402
    ContentClass,
    EventKind,
    MAX_TEXT_BYTES,
    ModelInputError,
    OpeningObservation,
    Outcome,
    incremental_replay,
    project,
)
from scenarios_v2 import _scenario, event  # noqa: E402


class PendingSubtreeTests(unittest.TestCase):
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

    def test_conflicting_grants_reject_independent_of_arrival(self) -> None:
        left = event("left", 0, kind=EventKind.GRANT, subject="bob")
        right = event("right", 0, kind=EventKind.GRANT, subject="bob")
        for events in ((left, right), (right, left)):
            with self.assertRaisesRegex(
                ModelInputError, "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED"
            ):
                project(_scenario(events))


if __name__ == "__main__":
    unittest.main()
