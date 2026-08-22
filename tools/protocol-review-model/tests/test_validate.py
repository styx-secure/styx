"""Positive and fail-closed tests for the protocol review model."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
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
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            command = [
                sys.executable,
                str(REPO_ROOT / "tools/protocol-review-model/validate.py"),
                "--repo-root",
                str(REPO_ROOT),
                "--schema",
                str(SCHEMA_PATH),
                "--model",
                str(MODEL_PATH),
            ]
            subprocess.run(
                [*command, "--output", str(first)],
                check=True,
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [*command, "--output", str(second)],
                check=True,
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_model_bytes_are_canonical(self) -> None:
        expected = (
            json.dumps(self.model, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        self.assertEqual(expected, MODEL_PATH.read_bytes())

    def test_cli_rejects_noncanonical_model_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            model_path = Path(directory) / "model.json"
            output_path = Path(directory) / "report.json"
            model_path.write_text(json.dumps(self.model), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "tools/protocol-review-model/validate.py"),
                    "--repo-root",
                    str(REPO_ROOT),
                    "--schema",
                    str(SCHEMA_PATH),
                    "--model",
                    str(model_path),
                    "--output",
                    str(output_path),
                ],
                check=False,
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("NONDETERMINISTIC_ORDER", result.stderr)

    def test_schema_definition_mutations_fail_closed(self) -> None:
        mutations = [
            lambda schema: schema.__setitem__(
                "$schema", "https://json-schema.org/draft/2019-09/schema"
            ),
            lambda schema: schema["properties"]["actors"].__setitem__(
                "uniqueItems", True
            ),
            lambda schema: schema["$defs"]["actor"].__delitem__(
                "additionalProperties"
            ),
            lambda schema: schema["properties"]["actors"]["items"].__setitem__(
                "$ref", "#/$defs/doesNotExist"
            ),
            lambda schema: schema["$defs"]["actor"].__setitem__(
                "required", "id"
            ),
            lambda schema: schema["$defs"]["nonEmptyString"].__setitem__(
                "minLength", "1"
            ),
            lambda schema: schema["$defs"]["status"].__setitem__(
                "enum", "DECIDED"
            ),
            lambda schema: schema["properties"]["actors"].__setitem__(
                "items", []
            ),
            lambda schema: (
                schema["$defs"]["actor"].pop("type"),
                schema["$defs"]["actor"].pop("additionalProperties"),
            ),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                schema = copy.deepcopy(self.schema)
                mutate(schema)
                codes = {
                    finding.code
                    for finding in validator.validate(self.model, schema, REPO_ROOT)
                }
                self.assertIn("SCHEMA_DEFINITION", codes)

    def test_malformed_json_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validator.load_json_unique(FIXTURE_ROOT / "malformed.json")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaises(validator.DuplicateKeyError):
            validator.load_json_unique(FIXTURE_ROOT / "duplicate-keys.json")

    def test_schema_invalid_nested_records_fail_without_validator_crash(self) -> None:
        mutations = [
            ("actors", 0),
            ("flows", 0),
            ("objects", 0),
            ("outcomes", 0),
            ("review_queries", 0),
            ("state_models", 0),
        ]
        for collection, index in mutations:
            with self.subTest(collection=collection):
                model = copy.deepcopy(self.model)
                model[collection][index] = "not-an-object"
                findings = validator.validate(model, self.schema, REPO_ROOT)
                self.assertTrue(findings)
                self.assertIn("SCHEMA_MISMATCH", {item.code for item in findings})

    def test_cli_rejects_malformed_and_duplicate_json(self) -> None:
        command = [
            sys.executable,
            str(REPO_ROOT / "tools/protocol-review-model/validate.py"),
            "--repo-root",
            str(REPO_ROOT),
            "--schema",
            str(SCHEMA_PATH),
        ]
        for fixture in ("malformed.json", "duplicate-keys.json"):
            with self.subTest(fixture=fixture):
                result = subprocess.run(
                    [*command, "--model", str(FIXTURE_ROOT / fixture)],
                    check=False,
                    cwd=REPO_ROOT,
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(0, result.returncode)

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
                "BLOCKER_EDGE_MISMATCH",
                "C03_GATE_MISSING",
                "CITATION_ANCHOR_INVALID",
                "CITATION_ANCHOR_MISSING",
                "DANGLING_REFERENCE",
                "DUPLICATE_ID",
                "FORBIDDEN_STATUS_PROMOTION",
                "MISSING_CITATION",
                "MISSING_NORMATIVE_CITATION",
                "MISSING_PROTECTION_METADATA",
                "NONDETERMINISTIC_ORDER",
                "REQUIRED_RECORD_MISSING",
                "SCHEMA_MISMATCH",
                "SOURCE_DIGEST_MISMATCH",
                "SOURCE_BOUNDARY",
                "SOURCE_MISSING",
                "UNKNOWN_REGISTRY_VALUE",
                "VISIBILITY_MUTABILITY_MISMATCH",
            },
            seen_expected_codes,
        )


if __name__ == "__main__":
    unittest.main()
