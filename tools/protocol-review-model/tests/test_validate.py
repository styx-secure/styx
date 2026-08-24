"""Positive and fail-closed tests for the protocol review model."""

from __future__ import annotations

import copy
import contextlib
import io
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
    elif operation == "append-copy-set":
        target = parent[int(key)] if isinstance(parent, list) else parent[key]
        item = copy.deepcopy(target[mutation["index"]])
        item[mutation["field"]] = mutation["value"]
        target.append(item)
    elif operation == "append-value":
        target = parent[int(key)] if isinstance(parent, list) else parent[key]
        target.append(copy.deepcopy(mutation["value"]))
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

    def _copy_validation_repo(self, destination: Path) -> tuple[Path, Path, Path]:
        repo = destination / "repo"
        model_path = repo / MODEL_PATH.relative_to(REPO_ROOT)
        schema_path = repo / SCHEMA_PATH.relative_to(REPO_ROOT)
        model_path.parent.mkdir(parents=True)
        shutil.copy2(MODEL_PATH, model_path)
        shutil.copy2(SCHEMA_PATH, schema_path)
        for source in self.model["sources"]:
            source_path = Path(source["path"])
            target = repo / source_path
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO_ROOT / source_path, target)
        return repo, model_path, schema_path

    def _run_cli(
        self,
        repo: Path,
        model_path: Path,
        schema_path: Path,
        output_path: Path,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools/protocol-review-model/validate.py"),
                "--repo-root",
                str(repo),
                "--schema",
                str(schema_path),
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
            self.assertEqual([], list(Path(directory).glob(".*.tmp")))

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
            lambda schema: schema["$defs"]["actor"].__setitem__(
                "items", {"type": "string"}
            ),
            lambda schema: schema["properties"]["actors"].pop("items"),
            lambda schema: schema["$defs"].__setitem__("actor", {}),
            lambda schema: schema["$defs"]["actor"].__setitem__("type", ["object"]),
            lambda schema: schema["$defs"]["actor"].__setitem__("properties", []),
            lambda schema: schema["$defs"]["actor"].__setitem__("properties", {}),
            lambda schema: schema["$defs"]["actor"].__setitem__(
                "additionalProperties", True
            ),
            lambda schema: schema.__setitem__("$defs", []),
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

    def test_schema_walk_continues_below_malformed_parent(self) -> None:
        schema = copy.deepcopy(self.schema)
        schema["$defs"]["actor"]["type"] = "unsupported"
        schema["$defs"]["actor"]["properties"]["id"] = {}
        findings = validator.validate(self.model, schema, REPO_ROOT)
        paths = {finding.path for finding in findings}
        self.assertIn("$schema.$defs.actor.type", paths)
        self.assertIn("$schema.$defs.actor.properties.id", paths)

    def test_schema_digest_drift_is_additive_at_cli_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, model_path, schema_path = self._copy_validation_repo(root)
            model = copy.deepcopy(self.model)
            model["artifact"]["normative"] = True
            model_path.write_text(
                json.dumps(model, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            schema = copy.deepcopy(self.schema)
            schema["$defs"]["actor"]["required"].remove("id")
            schema["$defs"]["status"]["enum"].append("WIDENED")
            schema_path.write_text(
                json.dumps(schema, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            result = self._run_cli(
                repo, model_path, schema_path, root / "report.json"
            )
            self.assertEqual(2, result.returncode)
            self.assertIn("SCHEMA_SNAPSHOT_DRIFT", result.stderr)
            self.assertIn("FORBIDDEN_STATUS_PROMOTION", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_exact_pin_tables_cover_the_base_inventory(self) -> None:
        field_keys = {
            (obj["id"], field["id"])
            for obj in self.model["objects"]
            for field in obj["fields"]
        }
        transition_keys = {
            (state_model["id"], transition["id"])
            for state_model in self.model["state_models"]
            for transition in state_model["transitions"]
        }
        self.assertEqual(field_keys, set(validator.EXPECTED_FIELD_SECURITY_DIGEST))
        self.assertEqual(
            transition_keys,
            {
                (state_model_id, transition_id)
                for state_model_id, transition_ids in validator.EXPECTED_TRANSITION_IDS.items()
                for transition_id in transition_ids
            },
        )
        self.assertEqual(transition_keys, set(validator.EXPECTED_TRANSITION_STATUS))
        self.assertEqual(
            transition_keys, set(validator.EXPECTED_TRANSITION_STRUCTURE_DIGEST)
        )
        for collection, table in (
            ("state_models", validator.EXPECTED_STATE_MODEL_STRUCTURE_DIGEST),
            ("invariants", validator.EXPECTED_INVARIANT_REFS_DIGEST),
            ("blockers", validator.EXPECTED_BLOCKER_EDGES_DIGEST),
            ("outcomes", validator.EXPECTED_OUTCOME_TRANSITION),
            ("counterexamples", validator.EXPECTED_COUNTEREXAMPLE_BLOCKS),
        ):
            self.assertEqual({item["id"] for item in self.model[collection]}, set(table))

    def test_every_transition_rejects_every_alternative_status(self) -> None:
        statuses = self.model["registries"]["statuses"]
        for state_index, state_model in enumerate(self.model["state_models"]):
            for transition_index, transition in enumerate(state_model["transitions"]):
                for status in statuses:
                    if status == transition["status"]:
                        continue
                    with self.subTest(transition=transition["id"], status=status):
                        model = copy.deepcopy(self.model)
                        model["state_models"][state_index]["transitions"][transition_index][
                            "status"
                        ] = status
                        codes = {
                            item.code
                            for item in validator.validate(model, self.schema, REPO_ROOT)
                        }
                        self.assertIn("FORBIDDEN_STATUS_PROMOTION", codes)

    def test_malformed_nested_matrix_is_additive_and_never_crashes(self) -> None:
        mutations = [
            ("/objects/0/fields/0/integrity", [None]),
            ("/objects/0/fields/0/mutable_by", 7),
            ("/objects/0/fields/0/visible_to", {"actor": "kernel"}),
            ("/flows/0/consumers", None),
            ("/flows/0/object_refs", [1, {}, [], [[]]]),
            ("/flows/0/actor_actions/0", None),
            ("/invariants/0/evidence_refs", [["nested"]]),
            ("/state_models/0/states", ["ACTIVE", {}]),
            ("/state_models/0/transitions/0/from", [["PARTIALLY_PENDING"]]),
            ("/blockers/0/depends_on", {"not": "an array"}),
            ("/review_queries/0/record_refs", [None, 1, {}, []]),
            ("/actors/0/id", []),
        ]
        for pointer, value in mutations:
            with self.subTest(pointer=pointer, value=value):
                model = copy.deepcopy(self.model)
                _apply_mutation(
                    model, {"operation": "set", "path": pointer, "value": value}
                )
                findings = validator.validate(model, self.schema, REPO_ROOT)
                self.assertIn("SCHEMA_MISMATCH", {item.code for item in findings})

    def test_non_hashable_dictionary_key_is_typed_and_never_crashes(self) -> None:
        model = copy.deepcopy(self.model)
        _apply_mutation(
            model,
            {
                "operation": "set",
                "path": "/actors/0/citations/0/source_id",
                "value": {"id": "not-hashable"},
            },
        )
        findings = validator.validate(model, self.schema, REPO_ROOT)
        self.assertIn("SCHEMA_MISMATCH", {item.code for item in findings})

    def test_domain_findings_survive_additive_schema_findings(self) -> None:
        for pointer, expected_code in (
            ("/objects/0/fields/0/confidentiality", "MISSING_PROTECTION_METADATA"),
            ("/actors/0/citations", "MISSING_CITATION"),
        ):
            with self.subTest(pointer=pointer):
                model = copy.deepcopy(self.model)
                _apply_mutation(model, {"operation": "delete", "path": pointer})
                codes = {
                    item.code for item in validator.validate(model, self.schema, REPO_ROOT)
                }
                self.assertIn("SCHEMA_MISMATCH", codes)
                self.assertIn(expected_code, codes)

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
        hostile_inputs = {
            "malformed": "{\"broken\":",
            "duplicate": "{\"duplicate\":1,\"duplicate\":2}",
            "nan": "{\"value\":NaN}",
            "infinity": "{\"value\":Infinity}",
            "recursion": "[" * 2000 + "0" + "]" * 2000,
        }
        for name, payload in hostile_inputs.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                repo, _, schema_path = self._copy_validation_repo(root)
                model_path = root / f"{name}.json"
                model_path.write_text(payload, encoding="utf-8")
                output_path = root / "report.json"
                output_path.write_bytes(b"sentinel\n")
                result = self._run_cli(repo, model_path, schema_path, output_path)
                self.assertEqual(2, result.returncode)
                self.assertIn("INPUT_INVALID", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(b"sentinel\n", output_path.read_bytes())
                self.assertEqual([], list(root.glob(".report.json.*.tmp")))

    def test_cli_rejects_every_output_alias_inside_temporary_repo(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, model_path, schema_path = self._copy_validation_repo(root)
            source_path = repo / self.model["sources"][0]["path"]
            for output_path in (model_path, schema_path, source_path):
                with self.subTest(output=output_path):
                    before = output_path.read_bytes()
                    result = self._run_cli(
                        repo, model_path, schema_path, output_path
                    )
                    self.assertEqual(2, result.returncode)
                    self.assertIn("INPUT_INVALID", result.stderr)
                    self.assertNotIn("Traceback", result.stderr)
                    self.assertEqual(before, output_path.read_bytes())
            symlink = root / "repo-link"
            symlink.symlink_to(repo / "docs", target_is_directory=True)
            linked_output = symlink / "aliased-report.json"
            result = self._run_cli(repo, model_path, schema_path, linked_output)
            self.assertEqual(2, result.returncode)
            self.assertIn("INPUT_INVALID", result.stderr)
            self.assertFalse((repo / "docs/aliased-report.json").exists())

    def test_cli_output_failure_is_typed_and_leaves_no_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo, model_path, schema_path = self._copy_validation_repo(root)
            not_a_directory = root / "not-a-directory"
            not_a_directory.write_text("sentinel", encoding="utf-8")
            output_path = not_a_directory / "report.json"
            result = self._run_cli(repo, model_path, schema_path, output_path)
            self.assertEqual(2, result.returncode)
            self.assertIn("INPUT_INVALID", result.stderr)
            self.assertNotIn("Traceback", result.stderr)
            self.assertEqual("sentinel", not_a_directory.read_text(encoding="utf-8"))
            self.assertEqual([], list(root.rglob(".report.json.*.tmp")))

    def test_last_resort_internal_error_is_typed_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "report.json"
            stderr = io.StringIO()
            with mock.patch.object(validator, "validate", side_effect=RuntimeError("boom")):
                with contextlib.redirect_stderr(stderr):
                    result = validator.main(
                        [
                            "--repo-root",
                            str(REPO_ROOT),
                            "--schema",
                            str(SCHEMA_PATH),
                            "--model",
                            str(MODEL_PATH),
                            "--output",
                            str(output_path),
                        ]
                    )
            self.assertEqual(2, result)
            self.assertIn("INTERNAL_ERROR: RuntimeError", stderr.getvalue())
            self.assertNotIn("Traceback", stderr.getvalue())
            self.assertFalse(output_path.exists())

    def test_cli_argument_error_is_typed_and_fail_closed(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = validator.main(["--repo-root", str(REPO_ROOT)])
        self.assertEqual(2, result)
        self.assertIn("INPUT_INVALID", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

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
                "GATED_CAPABILITY_UNBLOCKED",
                "MISSING_CITATION",
                "MISSING_NORMATIVE_CITATION",
                "MISSING_PROTECTION_METADATA",
                "NONDETERMINISTIC_ORDER",
                "PINNED_VALUE_DRIFT",
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

    def test_negative_fixture_corpus_is_canonical_and_preserves_base_cases(self) -> None:
        fixture_path = FIXTURE_ROOT / "negative-cases.json"
        expected = (
            json.dumps(
                self.negative_cases,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        self.assertEqual(expected, fixture_path.read_bytes())
        self.assertEqual(71, len(self.negative_cases))
        self.assertEqual(71, len({case["id"] for case in self.negative_cases}))

    def test_additive_inventory_cases_fail_only_the_pinned_equality(self) -> None:
        additive_ids = {
            "unexpected-record-set-entry",
            "unexpected-object-field",
            "unexpected-state-transition",
            "unexpected-closed-registry-entry",
        }
        cases = {case["id"]: case for case in self.negative_cases}
        self.assertEqual(additive_ids, additive_ids & cases.keys())
        for case_id in sorted(additive_ids):
            with self.subTest(case=case_id):
                case = cases[case_id]
                mutated = copy.deepcopy(self.model)
                _apply_mutation(mutated, case["mutation"])
                codes = {
                    finding.code
                    for finding in validator.validate(mutated, self.schema, REPO_ROOT)
                }
                self.assertEqual({case["expected_code"]}, codes)


if __name__ == "__main__":
    unittest.main()
