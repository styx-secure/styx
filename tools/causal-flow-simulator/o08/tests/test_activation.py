from __future__ import annotations

import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from envelope_model import evaluate_observation, materialize_candidate, validate_candidate_set
from semantic_registry import CANDIDATES_PATH, load_json
from run_measurements import _activation_outcome


class ActivationTests(unittest.TestCase):
    def setUp(self):
        candidates = validate_candidate_set(load_json(CANDIDATES_PATH))
        self.envelope = materialize_candidate(candidates[1])

    def test_missing_abstract_capability_fails_activation(self):
        result = evaluate_observation(
            self.envelope, "TRANSIENT_MEMORY_CAPABILITY", 0,
            stage="S0_PROFILE_ACTIVATION",
        )
        self.assertEqual(result.disposition, "PROFILE_ACTIVATION_UNSUPPORTED")
        self.assertFalse(result.authoritative_state_mutated)

    def test_post_c03_budget_cannot_become_authority(self):
        result = evaluate_observation(
            self.envelope, "OPERATIONAL_EVENT_RATE", 10**9,
            stage="S1_TRANSPORT_ADMISSION",
        )
        self.assertEqual(result.disposition, "POST_C03_NOT_EXECUTED")

    def test_capability_declaration_is_an_exact_four_key_map_not_a_scalar(self):
        payload = load_json(CANDIDATES_PATH)
        candidate = validate_candidate_set(payload)[1]
        profile = payload["capability_profiles"]["balanced"]
        self.assertNotIn("activation_capability_set", profile)
        self.assertEqual(_activation_outcome(candidate, profile), "PASS")
        hostile = dict(profile); hostile["unknown_capability"] = 1
        self.assertEqual(_activation_outcome(candidate, hostile), "PROFILE_ACTIVATION_UNSUPPORTED")


if __name__ == "__main__":
    unittest.main()
