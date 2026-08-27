"""Focused fail-closed tests for the Issue #260 final gate."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


O06C = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(O06C))

from integrated_final_gate import (
    FinalGateError,
    _selected_envelope_digest,
    _validate_integrated_test_module_inventory,
    validate_integrated_reports,
    write_manifest,
)
from integrated_mutation_harness import build_report as build_mutations
from integrated_probe import build_report as build_probe


def _encoded(value: dict[str, object]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class IntegratedFinalGateTest(unittest.TestCase):
    def test_each_exact_integrated_module_collects_tests(self) -> None:
        _validate_integrated_test_module_inventory(O06C / "tests")

    def test_zero_test_module_fails_closed_without_assert(self) -> None:
        names = {
            "test_integrated_cross_runtime.py",
            "test_integrated_final_gate.py",
            "test_integrated_model.py",
            "test_integrated_mutation_harness.py",
            "test_integrated_probe.py",
            "test_integrated_registry.py",
            "test_integrated_scope_guard.py",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in names:
                (root / name).write_text(
                    "import unittest\nclass T(unittest.TestCase):\n    def test_one(self): pass\n",
                    encoding="utf-8",
                )
            (root / "test_integrated_probe.py").write_text(
                "# deliberately contains no tests\n", encoding="utf-8"
            )
            with self.assertRaises(FinalGateError):
                _validate_integrated_test_module_inventory(root)

    def test_frozen_envelope_uses_provider_selected_candidate_identity(self) -> None:
        repo = O06C.parents[2]
        payload = json.loads(
            (repo / "tools/causal-flow-simulator/o08/resource-envelope.candidate.json").read_bytes()
        )
        self.assertEqual(_selected_envelope_digest(repo), payload["candidate_digest"])

    def test_substantive_integrated_counts_are_accepted(self) -> None:
        reports = {
            "probe": _encoded(build_probe()),
            "mutations": _encoded(build_mutations()),
            "runtime": _encoded({"verdict": "PASS", "interchange": "TEST_ONLY_NOT_O11"}),
            "scope": _encoded({"verdict": "PASS"}),
        }
        validate_integrated_reports(reports)

    def test_synthetic_empty_probe_fails_closed(self) -> None:
        reports = {
            "probe": _encoded({"verdict": "PASS", "disposition_count": 69, "handoff_count": 66}),
            "mutations": _encoded(build_mutations()),
            "runtime": _encoded({"verdict": "PASS", "interchange": "TEST_ONLY_NOT_O11"}),
            "scope": _encoded({"verdict": "PASS"}),
        }
        with self.assertRaises(FinalGateError):
            validate_integrated_reports(reports)

    def test_manifest_covers_exact_regular_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one.json").write_text("{}\n", encoding="utf-8")
            (root / "two.log").write_text("PASS\n", encoding="utf-8")
            write_manifest(root)
            lines = (root / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            self.assertTrue(lines[0].endswith("  one.json"))
            self.assertTrue(lines[1].endswith("  two.log"))


if __name__ == "__main__":
    unittest.main()
