from __future__ import annotations

import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from envelope_model import materialize_candidate, validate_candidate_set
from scenario_generator import combined_scenarios
from semantic_registry import CANDIDATES_PATH, load_json, load_source_registry


class CombinedTests(unittest.TestCase):
    def test_exact_sixteen_row_matrix(self):
        registry = load_source_registry()
        envelope = materialize_candidate(validate_candidate_set(load_json(CANDIDATES_PATH))[1], registry)
        rows = combined_scenarios(envelope, registry)
        self.assertEqual(len(rows), 16)
        post = {row["scenario_id"] for row in rows if row["disposition"] == "POST_C03_NOT_EXECUTED"}
        self.assertEqual(post, {"POST_TRANSPORT", "POST_SESSION", "POST_DELIVERY"})


if __name__ == "__main__":
    unittest.main()
