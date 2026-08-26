from __future__ import annotations

import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from envelope_model import evaluate_observation, materialize_candidate, validate_candidate_set
from semantic_registry import CANDIDATES_PATH, load_json


class FailureSemanticTests(unittest.TestCase):
    def setUp(self):
        self.envelope = materialize_candidate(validate_candidate_set(load_json(CANDIDATES_PATH))[1])

    def test_excess_is_not_absence_or_empty_authority(self):
        selected = self.envelope["entries"]["AUTHORITY_TRANSITIONS"]["selected_value"]
        result = evaluate_observation(
            self.envelope, "AUTHORITY_TRANSITIONS", selected + 1,
            stage="S5_AUTHORITY_PROJECTION",
        )
        self.assertEqual(result.disposition, "AUTHORITY_PROJECTION_UNAVAILABLE")
        self.assertFalse(result.authoritative_state_mutated)

    def test_pending_excess_defers_dependency(self):
        selected = self.envelope["entries"]["PENDING_ROOTS"]["selected_value"]
        result = evaluate_observation(self.envelope, "PENDING_ROOTS", selected + 1, stage="S4_GRAPH_ADMISSION")
        self.assertEqual(result.disposition, "DEPENDENCY_DEFERRED")

    def test_gate_skip_mutant_is_executed_and_exposes_the_hostile_transition(self):
        selected = self.envelope["entries"]["EVENTS_ADMITTED"]["selected_value"]
        baseline = evaluate_observation(
            self.envelope, "EVENTS_ADMITTED", selected + 1, stage="S4_GRAPH_ADMISSION"
        )
        mutant = evaluate_observation(
            self.envelope, "EVENTS_ADMITTED", selected + 1,
            stage="S4_GRAPH_ADMISSION", mutant="SKIP_GATE",
        )
        self.assertNotEqual(baseline.disposition, "ACCEPT")
        self.assertEqual(mutant.disposition, "ACCEPT")
        self.assertFalse(baseline.authoritative_state_mutated)
        self.assertTrue(mutant.authoritative_state_mutated)


if __name__ == "__main__":
    unittest.main()
