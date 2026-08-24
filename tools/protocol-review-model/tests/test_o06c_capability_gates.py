"""Fail-closed coverage for the O-06c to C0.3 capability-gate transfer."""

from __future__ import annotations

import copy
import json
import unittest

from support import FIXTURE_ROOT, MODEL_PATH, REPO_ROOT, SCHEMA_PATH, load_validator


validator = load_validator()


class O06cCapabilityGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.model = validator.load_json_unique(MODEL_PATH)
        cls.schema = validator.load_json_unique(SCHEMA_PATH)
        cls.cases = json.loads(
            (FIXTURE_ROOT / "o06c-capability-gates.json").read_text(
                encoding="utf-8"
            )
        )

    @staticmethod
    def _blocker(model: dict, blocker_id: str) -> dict:
        matches = [item for item in model["blockers"] if item["id"] == blocker_id]
        if len(matches) != 1:
            raise AssertionError(f"expected one blocker {blocker_id!r}")
        return matches[0]

    def test_selected_gate_transfer_is_present(self) -> None:
        c03 = self._blocker(self.model, "C0.3")
        o06c = self._blocker(self.model, "O-06c")
        self.assertEqual("NO_GO", c03["status"])
        self.assertEqual(
            ["corpus", "demo", "implementation_alignment", "product", "sensitive_use"],
            c03["blocks"],
        )
        self.assertEqual("DECIDED", o06c["status"])
        self.assertEqual(["C0.3"], o06c["blocks"])

    def test_every_negative_fixture_reaches_its_declared_detector(self) -> None:
        self.assertEqual(5, len(self.cases))
        self.assertEqual(len(self.cases), len({case["id"] for case in self.cases}))
        for case in self.cases:
            with self.subTest(case=case["id"]):
                model = copy.deepcopy(self.model)
                blocker = self._blocker(model, case["blocker_id"])
                if case["operation"] == "remove-block":
                    blocker["blocks"].remove(case["value"])
                elif case["operation"] == "append-block":
                    blocker["blocks"].append(case["value"])
                elif case["operation"] == "set-status":
                    blocker["status"] = case["value"]
                else:
                    self.fail(f"unknown operation {case['operation']!r}")
                codes = {
                    finding.code
                    for finding in validator.validate(model, self.schema, REPO_ROOT)
                }
                self.assertIn(case["expected_code"], codes)


if __name__ == "__main__":
    unittest.main()
