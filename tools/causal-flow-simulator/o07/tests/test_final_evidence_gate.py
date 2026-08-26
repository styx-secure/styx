from __future__ import annotations

import copy
from pathlib import Path
import sys
import tempfile
import unittest


O07_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = O07_ROOT.parents[2]
if str(O07_ROOT) not in sys.path:
    sys.path.insert(0, str(O07_ROOT))

from inventory import validate_inventory  # noqa: E402
from run_cross_runtime import build_report as build_runtime  # noqa: E402
from run_genesis_checkpoint_probe import build_report as build_probe  # noqa: E402
from run_mutations import build_report as build_mutations  # noqa: E402
from verify_final_evidence_hygiene import (  # noqa: E402
    _contained_regular_file,
    _validate_mutation_content,
    _validate_probe_content,
    _validate_runtime_content,
)


class FinalEvidenceGateTests(unittest.TestCase):
    def test_probe_rejects_zero_count_and_falsified_disposition(self) -> None:
        inventory = validate_inventory()
        report, passed = build_probe()
        self.assertTrue(passed)
        _validate_probe_content(report, inventory)

        zero = copy.deepcopy(report)
        zero["inventory_relation_count"] = 0
        zero["semantic_atom_count"] = 0
        zero["external_gate_count"] = 0
        zero["semantic_cases"] = []
        zero["external_gates"] = []
        with self.assertRaisesRegex(ValueError, "relation is not exact"):
            _validate_probe_content(zero, inventory)

        falsified = copy.deepcopy(report)
        expected = falsified["semantic_cases"][0]["expected_disposition"]
        falsified["semantic_cases"][0]["observed_disposition"] = (
            "REJECT" if expected != "REJECT" else "ACCEPT"
        )
        with self.assertRaisesRegex(ValueError, "falsified"):
            _validate_probe_content(falsified, inventory)

    def test_runtime_and_mutation_results_are_substantive(self) -> None:
        inventory = validate_inventory()
        with tempfile.TemporaryDirectory() as temporary:
            runtime, passed = build_runtime(
                REPO_ROOT, Path(temporary) / "runtime", "node"
            )
        self.assertTrue(passed)
        _validate_runtime_content(runtime, inventory)
        runtime["comparisons"][0]["exact"] = False
        with self.assertRaisesRegex(ValueError, "not exact"):
            _validate_runtime_content(runtime, inventory)

        mutations, passed = build_mutations(REPO_ROOT)
        self.assertTrue(passed)
        _validate_mutation_content(mutations, inventory)
        mutations["mutants"][0]["killed"] = False
        with self.assertRaisesRegex(ValueError, "falsified"):
            _validate_mutation_content(mutations, inventory)

    def test_report_must_be_regular_contained_and_not_symlinked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            report = evidence / "report.json"
            report.write_text("{}\n")
            self.assertEqual(_contained_regular_file(report, evidence), report.resolve())

            outside = root / "outside.json"
            outside.write_text("{}\n")
            with self.assertRaisesRegex(ValueError, "outside"):
                _contained_regular_file(outside, evidence)

            link = evidence / "link.json"
            link.symlink_to(report)
            with self.assertRaisesRegex(ValueError, "symlink"):
                _contained_regular_file(link, evidence)


if __name__ == "__main__":
    unittest.main()
