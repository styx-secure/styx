"""Closed derived-model checks for the Gate-A-frozen SS-0 profile."""

from __future__ import annotations

import ast
import copy
import hashlib
import importlib.util
import os
import subprocess
import sys
import unittest
from pathlib import Path

from support import MODEL_PATH, REPO_ROOT, SCHEMA_PATH, load_validator


validator = load_validator()

BASE_SHA = "bd13fac2df51e8585db6487fff7217fb68fb6242"
VALIDATOR_SHA256 = "e79caecde38c457ed79036d339c67b7aa7a394e37708ba76f0aa715ce0092f3b"
VALIDATE_DOMAIN_SHA256 = "f31ebaa85d6a5247772a38ee7fbb1ea3addcf4bae55ec6db86259e31913786c5"


def _base_validator_source() -> str:
    environment = {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    completed = subprocess.run(
        [
            "/usr/bin/git",
            "show",
            f"{BASE_SHA}:tools/protocol-review-model/validate.py",
        ],
        cwd=REPO_ROOT,
        env=environment,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return completed.stdout


def _top_level(tree: ast.Module) -> dict[tuple[str, str], ast.AST]:
    result: dict[tuple[str, str], ast.AST] = {}
    for node in tree.body:
        coordinate: tuple[str, str] | None = None
        if isinstance(node, ast.FunctionDef):
            coordinate = ("function", node.name)
        elif isinstance(node, ast.ClassDef):
            coordinate = ("class", node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if len(targets) == 1 and isinstance(targets[0], ast.Name):
                coordinate = ("assignment", targets[0].id)
        if coordinate is not None:
            if coordinate in result:
                raise AssertionError(f"duplicate validator coordinate: {coordinate}")
            result[coordinate] = node
    return result


def _function_segment(source: str, name: str) -> str:
    matches = [
        node
        for node in ast.parse(source).body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    if len(matches) != 1:
        raise AssertionError(f"validator function cardinality drift: {name}")
    node = matches[0]
    lines = source.splitlines(keepends=True)
    segment = "".join(lines[node.lineno - 1 : node.end_lineno])
    if node.end_lineno < len(lines) and not segment.endswith("\n\n"):
        segment += "\n"
    return segment


def _registry_decisions(node: ast.AST) -> list[str]:
    value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
    if not isinstance(value, ast.Dict):
        raise AssertionError("registry assignment is not a dictionary")
    for key, child in zip(value.keys, value.values, strict=True):
        if isinstance(key, ast.Constant) and key.value == "decisions":
            decisions = ast.literal_eval(child)
            if not isinstance(decisions, list) or not all(
                isinstance(item, str) for item in decisions
            ):
                raise AssertionError("decision registry is not a literal string list")
            return decisions
    raise AssertionError("decision registry is absent")


def _load_frozen_o07_guard():
    path = REPO_ROOT / "tools/causal-flow-simulator/o07/scope_guard_o07.py"
    sys.path.insert(0, str(path.parent))
    try:
        specification = importlib.util.spec_from_file_location(
            "_styx_ss0_test_frozen_o07_guard", path
        )
        if specification is None or specification.loader is None:
            raise AssertionError("cannot load frozen O-07 guard")
        module = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


class SecureSessionProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.model = validator.load_json_unique(MODEL_PATH)
        cls.schema = validator.load_json_unique(SCHEMA_PATH)

    def codes(self, model: dict) -> set[str]:
        return {
            finding.code
            for finding in validator.validate(model, self.schema, REPO_ROOT)
        }

    def test_gate_a_source_and_scope_are_exact(self) -> None:
        sources = {source["id"]: source for source in self.model["sources"]}
        self.assertEqual(
            {
                "authority": "normative",
                "id": "secure_session_decisions",
                "path": "docs/protocol/styx-secure-session-v0-decisions.md",
                "sha256": "235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07",
            },
            sources["secure_session_decisions"],
        )
        self.assertEqual(validator.EXPECTED_MODELED_SCOPE, self.model["modeled_scope"])
        self.assertFalse(self.model["artifact"]["implementation_claim"])
        self.assertEqual("NO_GO", self.model["artifact"]["c03_verdict"])

    def test_every_decision_has_one_normative_source(self) -> None:
        actual = {
            record["decision_id"]: record["source_id"]
            for record in self.model["decision_sources"]
        }
        self.assertEqual(validator.EXPECTED_DECISION_SOURCES, actual)
        self.assertEqual(len(actual), len(self.model["decision_sources"]))

    def test_ss_boundary_is_closed(self) -> None:
        actors = {record["id"]: record for record in self.model["actors"]}
        layers = {record["id"]: record for record in self.model["layers"]}
        for record in (actors["secure_session_adapter"], layers["SS"]):
            self.assertEqual(
                validator.EXPECTED_SS_DECISION_REFS, record["decision_refs"]
            )
            self.assertEqual(
                validator.EXPECTED_SS_OBLIGATION_REFS, record["obligation_refs"]
            )
        self.assertEqual(
            validator.EXPECTED_SS_FORBIDDEN_INFERENCES,
            layers["SS"]["forbidden_inferences"],
        )

    def test_missing_duplicate_unknown_and_misattributed_decisions_fail_closed(self) -> None:
        mutations = []

        missing = copy.deepcopy(self.model)
        missing["decision_sources"] = missing["decision_sources"][1:]
        mutations.append((missing, "REQUIRED_RECORD_MISSING"))

        duplicate = copy.deepcopy(self.model)
        duplicate["decision_sources"].append(
            copy.deepcopy(duplicate["decision_sources"][0])
        )
        mutations.append((duplicate, "DUPLICATE_ID"))

        unknown = copy.deepcopy(self.model)
        unknown["decision_sources"][0]["decision_id"] = "SSD-99"
        mutations.append((unknown, "UNKNOWN_REGISTRY_VALUE"))

        misattributed = copy.deepcopy(self.model)
        index = next(
            index
            for index, record in enumerate(misattributed["decision_sources"])
            if record["decision_id"] == "SSD-01"
        )
        misattributed["decision_sources"][index]["source_id"] = "decisions"
        mutations.append((misattributed, "PINNED_VALUE_DRIFT"))

        inconsistent = copy.deepcopy(self.model)
        inconsistent["modeled_scope"]["supported_adapter"] = True
        mutations.append((inconsistent, "PINNED_VALUE_DRIFT"))

        for model, expected in mutations:
            with self.subTest(expected=expected):
                self.assertIn(expected, self.codes(model))

    def test_ss_registry_drift_fails_closed(self) -> None:
        model = copy.deepcopy(self.model)
        model["registries"]["decisions"].remove("SSD-11")
        self.assertIn("UNKNOWN_REGISTRY_VALUE", self.codes(model))

    def test_validator_ast_delta_matches_the_ratified_ss0_projection(self) -> None:
        path = REPO_ROOT / "tools/protocol-review-model/validate.py"
        actual_source = path.read_text(encoding="utf-8")
        self.assertEqual(
            VALIDATOR_SHA256,
            hashlib.sha256(actual_source.encode("utf-8")).hexdigest(),
        )
        before_source = _base_validator_source()
        before_tree = ast.parse(before_source)
        actual_tree = ast.parse(actual_source)
        before = _top_level(before_tree)
        actual = _top_level(actual_tree)
        assignments = {
            "APPLICATION_KERNEL_DECISIONS",
            "EXPECTED_DECISION_SOURCES",
            "EXPECTED_MODELED_SCOPE",
            "EXPECTED_REGISTRIES",
            "EXPECTED_SCHEMA_SHA256",
            "EXPECTED_SOURCE_RECORDS",
            "EXPECTED_SS_DECISION_REFS",
            "EXPECTED_SS_FORBIDDEN_INFERENCES",
            "EXPECTED_SS_OBLIGATION_REFS",
            "SECURE_SESSION_EVIDENCE_DECISIONS",
        }
        changed = {
            coordinate
            for coordinate in set(before) | set(actual)
            if coordinate not in before
            or coordinate not in actual
            or ast.dump(before[coordinate], include_attributes=False)
            != ast.dump(actual[coordinate], include_attributes=False)
        }
        self.assertEqual(
            {("assignment", name) for name in assignments}
            | {("function", "validate_domain")},
            changed,
        )
        self.assertEqual(
            [
                *_registry_decisions(before[("assignment", "EXPECTED_REGISTRIES")]),
                *(f"SSD-{index:02d}" for index in range(1, 12)),
            ],
            _registry_decisions(actual[("assignment", "EXPECTED_REGISTRIES")]),
        )
        self.assertEqual(
            VALIDATE_DOMAIN_SHA256,
            hashlib.sha256(
                _function_segment(actual_source, "validate_domain").encode("utf-8")
            ).hexdigest(),
        )

        projected = copy.deepcopy(actual_tree)
        projected_records = _top_level(projected)
        for coordinate in (
            ("assignment", "EXPECTED_REGISTRIES"),
            ("function", "validate_domain"),
        ):
            target = projected_records[coordinate]
            projected.body[projected.body.index(target)] = copy.deepcopy(
                before[coordinate]
            )
        projected_source = ast.unparse(ast.fix_missing_locations(projected))
        guard = _load_frozen_o07_guard()
        guard.enforce_declared_validator_ast_delta(
            before_source,
            projected_source,
            projected_source,
            allowed_assignments=assignments - {"EXPECTED_REGISTRIES"},
            allowed_functions=frozenset(),
            allowed_literal_changes={
                ("APPLICATION_KERNEL_DECISIONS",),
                ("EXPECTED_DECISION_SOURCES",),
                ("EXPECTED_MODELED_SCOPE",),
                ("EXPECTED_SCHEMA_SHA256",),
                ("EXPECTED_SOURCE_RECORDS", "secure_session_decisions"),
                ("EXPECTED_SS_DECISION_REFS",),
                ("EXPECTED_SS_FORBIDDEN_INFERENCES",),
                ("EXPECTED_SS_OBLIGATION_REFS",),
                ("SECURE_SESSION_EVIDENCE_DECISIONS",),
            },
            allowed_function_call_additions={},
            protected_literal_paths=frozenset(),
        )


if __name__ == "__main__":
    unittest.main()
