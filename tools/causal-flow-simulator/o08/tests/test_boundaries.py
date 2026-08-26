from __future__ import annotations

import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from envelope_model import evaluate_observation, materialize_candidate, validate_candidate_set
from scenario_generator import (
    AuthorityItem, boundary_scenarios, evaluate_contention_bound,
    static_trace_bound,
)
from semantic_registry import CANDIDATES_PATH, ROLE_CAPABILITY, load_json, load_source_registry


class BoundaryTests(unittest.TestCase):
    def test_published_static_tuple_bounds_are_exact(self):
        candidates = validate_candidate_set(load_json(CANDIDATES_PATH))
        observed = [
            static_trace_bound(
                candidate["values"]["AUTHORITY_CONCURRENT_CONTROLS"],
                candidate["values"]["CONTROL_EVENTS"],
                candidate["values"]["FORK_SLOTS"],
            )
            for candidate in candidates
        ]
        self.assertEqual(observed, [14_336, 2_359_296, 406_061_056])

    def test_exact_contention_bound_distinguishes_contention_from_ordering(self):
        policy = AuthorityItem(
            reference="policy", item_type="CONTROL", predecessors=frozenset(),
            actor_id="actor-a", control_kind="POLICY",
        )
        revoke = AuthorityItem(
            reference="revoke", item_type="CONTROL", predecessors=frozenset(),
            actor_id="actor-b", control_kind="REVOKE", target_id="actor-a",
        )
        contended = evaluate_contention_bound(
            (policy, revoke), {"actor-a": None, "actor-b": None}
        )
        self.assertEqual(contended.value, 6)
        self.assertEqual(contended.ideal_count, 4)
        self.assertEqual(contended.width, 2)
        self.assertEqual(contended.contended_controls, ("policy",))
        self.assertEqual(contended.static_trace_bound, 16)

        ordered_revoke = AuthorityItem(
            reference="revoke", item_type="CONTROL",
            predecessors=frozenset({"policy"}), actor_id="actor-b",
            control_kind="REVOKE", target_id="actor-a",
        )
        ordered = evaluate_contention_bound(
            (policy, ordered_revoke), {"actor-a": None, "actor-b": None}
        )
        self.assertEqual(ordered.value, 3)
        self.assertEqual(ordered.contended_controls, ())

    def test_fork_join_is_a_lineage_killer(self):
        policy = AuthorityItem(
            reference="policy", item_type="CONTROL", predecessors=frozenset(),
            actor_id="child", control_kind="POLICY",
        )
        join = AuthorityItem(
            reference="join", item_type="FORK_JOIN", predecessors=frozenset(),
            credential_id="root",
        )
        result = evaluate_contention_bound(
            (policy, join), {"root": None, "child": "root"}
        )
        self.assertEqual(result.value, 6)
        self.assertEqual(result.contended_controls, ("policy",))

    def test_every_entry_has_required_adjacent_observations(self):
        registry = load_source_registry()
        candidate = validate_candidate_set(load_json(CANDIDATES_PATH))[1]
        envelope = materialize_candidate(candidate, registry)
        rows = boundary_scenarios(envelope, registry)
        expected_count = 3 * (len(registry.entry_dimensions) - 1) + 3 * len(
            envelope["entries"]["CHUNK_OCTETS"]["closed_values"]
        )
        self.assertEqual(len(rows), expected_count)
        for row in rows:
            stage = registry.stages[row["dimension"]][0]
            result = evaluate_observation(envelope, row["dimension"], row["observed"], stage=stage)
            selected = envelope["entries"][row["dimension"]]["selected_value"]
            entry = envelope["entries"][row["dimension"]]
            capability = entry["role"] == ROLE_CAPABILITY
            if entry["comparison"] == "EXACT_CLOSED_SET":
                expected = row["observed"] in entry["closed_values"]
            elif entry["comparison"] == "EXACT_CLOSED_KEY_SET":
                expected = row["observed"] == selected
            else:
                expected = row["observed"] >= 0 and (
                    row["observed"] >= selected if capability else row["observed"] <= selected
                )
            self.assertEqual(result.disposition == "ACCEPT", expected)
            self.assertEqual(
                result.authoritative_state_mutated,
                result.authoritative_state_before != result.authoritative_state_after,
            )
            if result.disposition != "ACCEPT":
                self.assertEqual(result.authoritative_state_before, result.authoritative_state_after)


if __name__ == "__main__":
    unittest.main()
