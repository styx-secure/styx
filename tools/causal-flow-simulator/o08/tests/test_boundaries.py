from __future__ import annotations

import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from envelope_model import evaluate_observation, materialize_candidate, validate_candidate_set
from scenario_generator import boundary_scenarios
from semantic_registry import CANDIDATES_PATH, ROLE_CAPABILITY, load_json, load_source_registry


class BoundaryTests(unittest.TestCase):
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
