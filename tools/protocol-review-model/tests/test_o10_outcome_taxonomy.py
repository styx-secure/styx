"""Fail-closed registration and exact-AST tests for O-10."""

from __future__ import annotations

import copy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from support import MODEL_PATH, REPO_ROOT, SCHEMA_PATH, load_validator


validator = load_validator()
O10_ROOT = REPO_ROOT / "tools/causal-flow-simulator/o10"
sys.path.insert(0, str(O10_ROOT))

from scope_guard import (  # noqa: E402
    BASE_SHA,
    MAIN_ADDITION,
    ScopeError,
    validate_historical_validator_delta,
    validate_validator_delta,
)


class O10OutcomeTaxonomyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.model = validator.load_json_unique(MODEL_PATH)
        cls.schema = validator.load_json_unique(SCHEMA_PATH)
        cls.base_validator = subprocess.check_output(
            ["git", "-C", str(REPO_ROOT), "show", f"{BASE_SHA}:tools/protocol-review-model/validate.py"],
            text=True,
        )
        cls.actual_validator = (REPO_ROOT / "tools/protocol-review-model/validate.py").read_text(
            encoding="utf-8"
        )
        cls.historical_validator = subprocess.check_output(
            [
                "git",
                "-C",
                str(REPO_ROOT),
                "show",
                "25be9abc0d8c1bce8821a750616e13d245abc356:tools/protocol-review-model/validate.py",
            ],
            text=True,
        )

    def test_positive_registration_has_no_o10_findings(self) -> None:
        self.assertEqual(
            validator.validate_o10_outcome_taxonomy(self.model, REPO_ROOT), []
        )
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                validator.validate_o10_outcome_taxonomy(
                    self.model, Path(directory)
                ),
                [],
            )

    def test_o10_status_drift_fails_closed(self) -> None:
        model = copy.deepcopy(self.model)
        next(item for item in model["blockers"] if item["id"] == "O-10")["status"] = "OPEN"
        codes = {
            finding.code
            for finding in validator.validate_o10_outcome_taxonomy(model, REPO_ROOT)
        }
        self.assertIn("O10_STATUS", codes)
        with tempfile.TemporaryDirectory() as directory:
            source_only = Path(directory)
            codes = {
                finding.code
                for finding in validator.validate_o10_outcome_taxonomy(
                    model, source_only
                )
            }
        self.assertIn("O10_STATUS", codes)

    def test_o14_removal_is_still_rejected_by_core_validator(self) -> None:
        model = copy.deepcopy(self.model)
        model["blockers"] = [item for item in model["blockers"] if item["id"] != "O-14"]
        self.assertTrue(validator.validate(model, self.schema, REPO_ROOT))

    def test_dependency_or_assignment_drift_is_rejected(self) -> None:
        drift = self.actual_validator.replace(
            '        "O-14": "DECIDED",', '        "O-14": "OPEN",', 1
        )
        with self.assertRaises(ScopeError):
            validate_validator_delta(self.base_validator, drift)

    def test_o14_assignment_removal_is_rejected(self) -> None:
        drift = self.actual_validator.replace('        "O-14": "DECIDED",\n', "", 1)
        with self.assertRaises(ScopeError):
            validate_validator_delta(self.base_validator, drift)

    def test_adjacent_assignment_coordinate_is_rejected(self) -> None:
        drift = self.actual_validator.replace(
            '        "O-12": "OPEN",', '        "O-12": "DECIDED",', 1
        )
        with self.assertRaises(ScopeError):
            validate_validator_delta(self.base_validator, drift)

    def test_o10_function_body_drift_is_rejected(self) -> None:
        drift = self.actual_validator.replace("len(ids) != 25", "len(ids) != 24", 1)
        with self.assertRaises(ScopeError):
            validate_validator_delta(self.base_validator, drift)

    def test_inside_try_main_call_placement_is_exact(self) -> None:
        without = self.actual_validator.replace(MAIN_ADDITION, "", 1)
        anchor = "        findings.extend(validate_model_bytes(model, args.model))\n"
        drift = without.replace(anchor, anchor + MAIN_ADDITION, 1)
        with self.assertRaises(ScopeError):
            validate_validator_delta(self.base_validator, drift)

    def test_main_call_argument_is_exact(self) -> None:
        drift = self.actual_validator.replace(
            "validate_o10_outcome_taxonomy(model, args.repo_root)",
            "validate_o10_outcome_taxonomy(model, Path('.'))",
            1,
        )
        with self.assertRaises(ScopeError):
            validate_validator_delta(self.base_validator, drift)

    def test_unrelated_main_body_drift_is_rejected(self) -> None:
        drift = self.actual_validator.replace(
            "findings.sort(key=lambda item: (item.code, item.path, item.message))",
            "findings.sort(key=lambda item: item.code)",
            1,
        )
        with self.assertRaises(ScopeError):
            validate_validator_delta(self.base_validator, drift)

    def test_c03_authorization_assignment_drift_is_rejected(self) -> None:
        drift = self.actual_validator.replace(
            'AUTHORIZED_UNBLOCKED_CAPABILITIES = {"corpus"}',
            'AUTHORIZED_UNBLOCKED_CAPABILITIES = {"corpus", "demo"}',
            1,
        )
        with self.assertRaises(ScopeError):
            validate_validator_delta(self.base_validator, drift)

    def test_c03_blocker_edge_digest_drift_is_rejected(self) -> None:
        drift = self.actual_validator.replace(
            '"C0.3": "8c825da422bcc2fe6c330353dcbb1952346ebfdc07f7df9ee65e73d5781931f5"',
            '"C0.3": "294c90766317a495004a86e300e1c1b6b81de66b377cefe47676b9e67c1f6d14"',
            1,
        )
        with self.assertRaises(ScopeError):
            validate_validator_delta(self.base_validator, drift)

    def test_c03_authorization_function_drift_is_rejected(self) -> None:
        drift = self.actual_validator.replace(
            "and capability not in AUTHORIZED_UNBLOCKED_CAPABILITIES",
            "or capability not in AUTHORIZED_UNBLOCKED_CAPABILITIES",
            1,
        )
        with self.assertRaises(ScopeError):
            validate_validator_delta(self.base_validator, drift)

    def test_exact_main_and_function_registration_pass(self) -> None:
        hashes = validate_validator_delta(self.base_validator, self.actual_validator)
        self.assertEqual(len(hashes), 3)

    def test_historical_o10_relation_remains_exact(self) -> None:
        hashes = validate_historical_validator_delta(
            self.base_validator, self.historical_validator
        )
        self.assertEqual(
            "a77067d559270c1779353d870c4663705951cea8ce19150c325014726d59629d",
            hashes["complete_source_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
