"""Positive and fail-closed tests for the protocol review model."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from support import FIXTURE_ROOT, MODEL_PATH, REPO_ROOT, SCHEMA_PATH, load_validator


validator = load_validator()


def _resolve_pointer(document: object, pointer: str) -> tuple[object, str]:
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/")[1:]]
    current = document
    for part in parts[:-1]:
        current = current[int(part)] if isinstance(current, list) else current[part]
    return current, parts[-1]


def _apply_mutation(document: dict, mutation: dict) -> None:
    parent, key = _resolve_pointer(document, mutation["path"])
    operation = mutation["operation"]
    if operation == "set":
        if isinstance(parent, list):
            parent[int(key)] = mutation["value"]
        else:
            parent[key] = mutation["value"]
    elif operation == "delete":
        if isinstance(parent, list):
            del parent[int(key)]
        else:
            del parent[key]
    elif operation == "append-copy":
        target = parent[int(key)] if isinstance(parent, list) else parent[key]
        target.append(copy.deepcopy(target[mutation["index"]]))
    elif operation == "remove-value":
        target = parent[int(key)] if isinstance(parent, list) else parent[key]
        target.remove(mutation["value"])
    elif operation == "swap":
        target = parent[int(key)] if isinstance(parent, list) else parent[key]
        left, right = mutation["indices"]
        target[left], target[right] = target[right], target[left]
    else:
        raise AssertionError(f"unknown fixture operation: {operation}")


class ProtocolReviewModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.model = validator.load_json_unique(MODEL_PATH)
        cls.schema = validator.load_json_unique(SCHEMA_PATH)
        cls.negative_cases = json.loads(
            (FIXTURE_ROOT / "negative-cases.json").read_text(encoding="utf-8")
        )

    def test_current_model_passes(self) -> None:
        self.assertEqual([], validator.validate(self.model, self.schema, REPO_ROOT))

    def test_validation_report_is_byte_deterministic(self) -> None:
        report = validator.build_report(MODEL_PATH, SCHEMA_PATH, self.model)
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            validator.write_canonical_json(first, report)
            validator.write_canonical_json(second, report)
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_malformed_json_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validator.load_json_unique(FIXTURE_ROOT / "malformed.json")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaises(validator.DuplicateKeyError):
            validator.load_json_unique(FIXTURE_ROOT / "duplicate-keys.json")

    def test_each_declared_negative_case_fails_closed(self) -> None:
        seen_expected_codes: set[str] = set()
        for case in self.negative_cases:
            with self.subTest(case=case["id"]):
                mutated = copy.deepcopy(self.model)
                _apply_mutation(mutated, case["mutation"])
                codes = {
                    finding.code
                    for finding in validator.validate(mutated, self.schema, REPO_ROOT)
                }
                self.assertIn(case["expected_code"], codes)
                seen_expected_codes.add(case["expected_code"])
        self.assertEqual(
            {
                "BLOCKER_CYCLE",
                "C03_GATE_MISSING",
                "DANGLING_REFERENCE",
                "DUPLICATE_ID",
                "FORBIDDEN_STATUS_PROMOTION",
                "MISSING_NORMATIVE_CITATION",
                "MISSING_PROTECTION_METADATA",
                "NONDETERMINISTIC_ORDER",
                "SCHEMA_MISMATCH",
                "SOURCE_DIGEST_MISMATCH",
                "UNKNOWN_REGISTRY_VALUE",
            },
            seen_expected_codes,
        )


if __name__ == "__main__":
    unittest.main()
