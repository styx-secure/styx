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


if __name__ == "__main__":
    unittest.main()
