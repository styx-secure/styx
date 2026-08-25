from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


O07_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = O07_ROOT.parents[2]
if str(O07_ROOT) not in sys.path:
    sys.path.insert(0, str(O07_ROOT))

from report_schema import (  # noqa: E402
    CROSS_RUNTIME_SCHEMA,
    MUTATION_SCHEMA,
    PROBE_SCHEMA,
    SCOPE_SCHEMA,
    ReportHygieneContext,
    repository_hygiene_context,
    validate_canonical_report,
)
from verify_final_evidence_hygiene import validate_final_reports  # noqa: E402


IDENTITY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
RUNTIME_VALUES = ("/tmp/styx-o07-runtime", "review-host.invalid", "review-user")


def _context(*identities: str) -> ReportHygieneContext:
    return ReportHygieneContext(identities or (IDENTITY,), RUNTIME_VALUES)


def _reports() -> list[dict[str, object]]:
    return [
        {
            "schema": PROBE_SCHEMA,
            "inventory_relation_count": 1,
            "semantic_atom_count": 0,
            "external_gate_count": 1,
            "semantic_cases": [],
            "external_gates": [
                {
                    "atom_instance_id": "A-EVD-001",
                    "gate_instance_id": "G-EVD-001",
                    "requirement": "closed external requirement",
                    "state": "REQUIRED_SEPARATE_GATE",
                }
            ],
            "failed_semantic_atoms": [],
            "semantic_verdict": "PASS",
            "final_o07_gate": "NOT_EVALUATED_BY_THIS_PROBE",
        },
        {
            "schema": CROSS_RUNTIME_SCHEMA,
            "adapter_count": 2,
            "semantic_atom_count": 0,
            "comparisons": [],
            "failed": [],
            "verdict": "PASS",
        },
        {
            "schema": MUTATION_SCHEMA,
            "registered_mutant_count": 0,
            "semantic_relation_count": 0,
            "mutants": [],
            "relations": [],
            "survived": [],
            "uncovered_atoms": [],
            "verdict": "ALL_REGISTERED_MUTANTS_KILLED",
        },
        {
            "schema": SCOPE_SCHEMA,
            "copy_threshold_percent": 25,
            "changed_relation": [{"status": "M", "paths": ["docs/protocol/a.md"]}],
            "changed_endpoint_count": 1,
            "validator_assignments_changed": ["EXPECTED_SOURCE_RECORDS"],
            "approved_artifact_count": 1,
            "predecessor_review_test_count": 9,
            "byte_identical_o07_base_blob_count": 0,
            "predecessor_import_count": 0,
            "verdict": "PASS",
        },
    ]


def _string_paths(value: object, prefix: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
    result: list[tuple[object, ...]] = []
    if isinstance(value, str):
        result.append(prefix)
    elif isinstance(value, dict):
        for key, item in value.items():
            result.extend(_string_paths(item, prefix + (key,)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            result.extend(_string_paths(item, prefix + (index,)))
    return result


def _replace(value: object, path: tuple[object, ...], replacement: str) -> object:
    changed = copy.deepcopy(value)
    cursor = changed
    for part in path[:-1]:
        cursor = cursor[part]  # type: ignore[index]
    cursor[path[-1]] = replacement  # type: ignore[index]
    return changed


class ReportHygieneTests(unittest.TestCase):
    def test_context_is_mandatory_and_non_empty(self) -> None:
        with self.assertRaises(TypeError):
            validate_canonical_report(_reports()[0])  # type: ignore[call-arg]
        with self.assertRaises(ValueError):
            ReportHygieneContext((), RUNTIME_VALUES)
        with self.assertRaises(ValueError):
            ReportHygieneContext((IDENTITY,), ())

    def test_full_and_abbreviated_identity_rejected_in_every_string_field(self) -> None:
        for report in _reports():
            for path in _string_paths(report):
                for needle in (IDENTITY, IDENTITY[:7], IDENTITY.upper()[:7]):
                    with self.subTest(schema=report["schema"], path=path, needle=needle):
                        with self.assertRaises(ValueError):
                            validate_canonical_report(
                                _replace(report, path, needle),
                                hygiene_context=_context(),
                            )

    def test_runtime_values_rejected_in_every_string_field(self) -> None:
        for report in _reports():
            for path in _string_paths(report):
                for needle in (*RUNTIME_VALUES, "pid=731", "2026-08-25T20:37"):
                    with self.subTest(schema=report["schema"], path=path, needle=needle):
                        with self.assertRaises(ValueError):
                            validate_canonical_report(
                                _replace(report, path, needle),
                                hygiene_context=_context(),
                            )

    def test_repository_context_contains_base_head_trees_and_diff(self) -> None:
        base = "86c3f2dbd630e445d737a25c09889de2777ee185"
        context = repository_hygiene_context(REPO_ROOT, base, "HEAD")
        self.assertEqual(len(context.repository_identities), 5)
        self.assertIn(str(REPO_ROOT.resolve()), context.runtime_values)

    def test_final_gate_requires_two_equal_reports_per_schema_and_bundle_identity(self) -> None:
        base = "86c3f2dbd630e445d737a25c09889de2777ee185"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "candidate.bundle"
            bundle.write_bytes(b"bounded final bundle bytes")
            paths: list[Path] = []
            for index, report in enumerate(_reports()):
                raw = (
                    json.dumps(report, separators=(",", ":"), sort_keys=True) + "\n"
                ).encode()
                for copy_index in range(2):
                    path = root / f"report-{index}-{copy_index}.json"
                    path.write_bytes(raw)
                    paths.append(path)
            bundle_identity = validate_final_reports(
                repo=REPO_ROOT,
                base=base,
                candidate="HEAD",
                bundle=bundle,
                report_paths=paths,
            )
            leaked = json.loads(paths[0].read_text())
            leaked["external_gates"][0]["requirement"] = bundle_identity[:7]
            paths[0].write_text(json.dumps(leaked, separators=(",", ":"), sort_keys=True) + "\n")
            paths[1].write_bytes(paths[0].read_bytes())
            with self.assertRaisesRegex(ValueError, "repository identity"):
                validate_final_reports(
                    repo=REPO_ROOT,
                    base=base,
                    candidate="HEAD",
                    bundle=bundle,
                    report_paths=paths,
                )


if __name__ == "__main__":
    unittest.main()
