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
        for candidate in validate_candidate_set(load_json(CANDIDATES_PATH)):
            with self.subTest(candidate=candidate["id"]):
                envelope = materialize_candidate(candidate, registry)
                rows = combined_scenarios(envelope, registry)
                self.assertEqual(len(rows), 16)
                post = {row["scenario_id"] for row in rows if row["disposition"] == "POST_C03_NOT_EXECUTED"}
                self.assertEqual(post, {"POST_TRANSPORT", "POST_SESSION", "POST_DELIVERY"})
                executable = [row for row in rows if row["disposition"] == "EXECUTE"]
                self.assertTrue(all(row["predicates"] for row in executable))
                self.assertTrue(all(predicate["passed"] for row in executable for predicate in row["predicates"]))
                names = {predicate["observation"] for row in executable for predicate in row["predicates"]}
                self.assertTrue({
                    "DIRECT_EDGE_CAPACITY", "CONTENT_CHUNK_GEOMETRY",
                    "AGGREGATE_TRANSIENT_WORKING_SET", "DURABLE_REFERENCE_ENVELOPE",
                }.issubset(names))


if __name__ == "__main__":
    unittest.main()
