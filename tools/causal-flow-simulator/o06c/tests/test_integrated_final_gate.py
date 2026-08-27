"""Focused fail-closed tests for the Issue #260 final gate."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest


O06C = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(O06C))

from integrated_final_gate import FinalGateError, validate_integrated_reports, write_manifest
from integrated_mutation_harness import build_report as build_mutations
from integrated_probe import build_report as build_probe


def _encoded(value: dict[str, object]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


class IntegratedFinalGateTest(unittest.TestCase):
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
