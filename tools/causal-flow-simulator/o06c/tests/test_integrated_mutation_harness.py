from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest


O06C = Path(__file__).resolve().parents[1]
if str(O06C) not in sys.path:
    sys.path.insert(0, str(O06C))

from integrated_mutation_harness import REPORT_FIELDS, build_report, evaluate_mutant
from integrated_registry import required_mutants
from o10.canonical_report import canonical_bytes


class IntegratedMutationHarnessTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = build_report()

    def test_all_required_mutants_are_killed_exactly(self):
        self.assertEqual(self.report["verdict"], "ALL_REQUIRED_MUTANTS_KILLED")
        self.assertEqual(self.report["mutant_count"], len(required_mutants()))
        self.assertEqual(self.report["killed_count"], len(required_mutants()))
        self.assertEqual(self.report["survivor_count"], 0)
        for row in self.report["results"]:
            self.assertTrue(row["declared_detectors"])
            self.assertEqual(row["observed_detectors"], row["declared_detectors"])

    def test_missing_or_extra_detector_fails_closed(self):
        original = required_mutants()[0]
        changed = replace(original, detectors=original.detectors + ("I-K-MISSING",))
        self.assertFalse(evaluate_mutant(changed)["killed"])

    def test_report_is_canonical(self):
        canonical_bytes(self.report, allowed_fields=REPORT_FIELDS)


if __name__ == "__main__":
    unittest.main()
