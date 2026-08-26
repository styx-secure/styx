from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from envelope_model import materialize_candidate, validate_candidate_set
from semantic_registry import CANDIDATES_PATH, load_json


class CrossRuntimeTests(unittest.TestCase):
    def test_node_oracle_rejects_above_maximum(self):
        envelope = materialize_candidate(validate_candidate_set(load_json(CANDIDATES_PATH))[1])
        selected = envelope["entries"]["EVENTS_ADMITTED"]["selected_value"]
        request = {
            "schema": "styx-o08-oracle-request/v1", "envelope": envelope,
            "cases": [{"dimension": "EVENTS_ADMITTED", "stage": "S4_GRAPH_ADMISSION", "observed": selected + 1}],
        }
        completed = subprocess.run(
            ["node", str(ROOT / "independent_oracle.mjs")], input=json.dumps(request),
            text=True, capture_output=True, check=True,
        )
        response = json.loads(completed.stdout)
        self.assertEqual(response["results"][0]["disposition"], "CONTEXT_CAPACITY_EXHAUSTED")
        self.assertFalse(response["results"][0]["authoritative_state_mutated"])

    def test_node_oracle_preserves_max_safe_plus_one_as_decimal(self):
        envelope = materialize_candidate(validate_candidate_set(load_json(CANDIDATES_PATH))[1])
        request = {
            "schema": "styx-o08-oracle-request/v1", "envelope": envelope,
            "cases": [{
                "dimension": "SEQUENCE_VALUE", "stage": "S3_KERNEL_STRUCTURAL",
                "observed": "9007199254740992",
            }],
        }
        completed = subprocess.run(
            ["node", str(ROOT / "independent_oracle.mjs")], input=json.dumps(request),
            text=True, capture_output=True, check=True,
        )
        response = json.loads(completed.stdout)
        self.assertEqual(response["results"][0]["observed"], "9007199254740992")
        self.assertEqual(response["results"][0]["disposition"], "CURRENT_OBJECT_OUT_OF_PROFILE")


if __name__ == "__main__":
    unittest.main()
