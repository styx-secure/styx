from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mutation_harness_o14 import build_report
from scenarios import DECLARED_DETECTORS, REQUIRED_MUTANTS


class MutationHarnessTest(unittest.TestCase):
    def test_closed_registry_and_exact_detector_equality(self) -> None:
        self.assertEqual(set(DECLARED_DETECTORS), set(REQUIRED_MUTANTS))
        self.assertTrue(all(DECLARED_DETECTORS.values()))
        report, passed = build_report()
        self.assertTrue(passed)
        self.assertEqual(report["survived"], [])
        for result in report["results"]:
            self.assertTrue(result["mutated_branch_executed"])
            self.assertEqual(
                result["declared_detectors"], result["observed_detectors"]
            )


if __name__ == "__main__":
    unittest.main()
