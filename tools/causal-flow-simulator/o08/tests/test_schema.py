from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from envelope_model import EnvelopeError, load_selected_envelope, materialize_candidate, validate_candidate_set, validate_selected
from semantic_registry import CANDIDATES_PATH, RegistryError, canonical_bytes, load_json


class SchemaTests(unittest.TestCase):
    def test_candidate_and_selected_schema_are_exact(self):
        payload = load_json(CANDIDATES_PATH)
        candidates = validate_candidate_set(payload)
        selected = materialize_candidate(candidates[1])
        self.assertEqual(validate_selected(selected, payload), selected)

    def test_unknown_field_fails_closed(self):
        payload = copy.deepcopy(load_json(CANDIDATES_PATH))
        payload["ambient_limit"] = 1
        with self.assertRaisesRegex(EnvelopeError, "schema mismatch"):
            validate_candidate_set(payload)

    def test_profile_downgrade_and_missing_dimension_fail(self):
        for mutation in ("profile", "dimension"):
            payload = copy.deepcopy(load_json(CANDIDATES_PATH))
            if mutation == "profile":
                payload["profile"] = "STYX_APP_KERNEL_V0_DOWNGRADE"
            else:
                payload["candidates"][0]["values"].pop("EVENTS_ADMITTED")
            with self.assertRaises(EnvelopeError):
                validate_candidate_set(payload)

    def test_selected_gate_and_role_are_not_ambient(self):
        payload = load_json(CANDIDATES_PATH)
        selected = materialize_candidate(validate_candidate_set(payload)[1])
        for mutation in ("gate", "role"):
            hostile = copy.deepcopy(selected)
            entry = hostile["entries"]["EVENTS_ADMITTED"]
            if mutation == "gate":
                entry["enforcement_points"] = []
            else:
                entry["role"] = "C03_ACTIVATION_CAPABILITY_INPUT"
            with self.assertRaises(EnvelopeError):
                validate_selected(hostile, payload)

    def test_duplicate_member_and_noncanonical_selected_fail(self):
        with tempfile.TemporaryDirectory() as temporary:
            duplicate = Path(temporary) / "duplicate.json"
            duplicate.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
            with self.assertRaises(RegistryError):
                load_json(duplicate)
            payload = load_json(CANDIDATES_PATH)
            selected = materialize_candidate(validate_candidate_set(payload)[1])
            noncanonical = Path(temporary) / "selected.json"
            noncanonical.write_text(json.dumps(selected, indent=2), encoding="utf-8")
            with self.assertRaises(EnvelopeError):
                load_selected_envelope(noncanonical)
            noncanonical.write_bytes(canonical_bytes(selected))
            self.assertEqual(load_selected_envelope(noncanonical), selected)


if __name__ == "__main__":
    unittest.main()
