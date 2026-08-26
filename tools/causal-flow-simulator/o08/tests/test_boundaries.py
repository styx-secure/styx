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
    def test_every_entry_has_three_adjacent_observations(self):
        registry = load_source_registry()
        candidate = validate_candidate_set(load_json(CANDIDATES_PATH))[1]
        envelope = materialize_candidate(candidate, registry)
        rows = boundary_scenarios(envelope, registry)
        self.assertEqual(len(rows), 53 * 3)
        for row in rows:
            stage = registry.stages[row["dimension"]][0]
            result = evaluate_observation(envelope, row["dimension"], row["observed"], stage=stage)
            selected = envelope["entries"][row["dimension"]]["selected_value"]
            capability = envelope["entries"][row["dimension"]]["role"] == ROLE_CAPABILITY
            expected = row["observed"] >= 0 and (
                row["observed"] >= selected if capability else row["observed"] <= selected
            )
            self.assertEqual(result.disposition == "ACCEPT", expected)


if __name__ == "__main__":
    unittest.main()
