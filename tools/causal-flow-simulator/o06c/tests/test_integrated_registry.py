from __future__ import annotations

from pathlib import Path
import sys
import unittest


O06C = Path(__file__).resolve().parents[1]
if str(O06C) not in sys.path:
    sys.path.insert(0, str(O06C))

from integrated_registry import (
    REGISTRY_VERSION,
    registry_record,
    required_mutants,
    required_witnesses,
)


class IntegratedRegistryTest(unittest.TestCase):
    def test_registry_is_closed_and_nonempty(self):
        witnesses = required_witnesses()
        mutants = required_mutants()
        self.assertGreater(len(witnesses), 150)
        self.assertEqual(len(mutants), 7)
        self.assertEqual(len({item.identifier for item in witnesses}), len(witnesses))
        self.assertEqual(len({item.identifier for item in mutants}), len(mutants))

    def test_every_mutant_has_exact_known_detectors(self):
        witnesses = {item.identifier for item in required_witnesses()}
        for mutant in required_mutants():
            self.assertTrue(mutant.detectors)
            self.assertLessEqual(set(mutant.detectors), witnesses)

    def test_record_count_is_derived(self):
        report = registry_record()
        self.assertEqual(report["schema"], REGISTRY_VERSION)
        self.assertEqual(report["witness_count"], len(report["witnesses"]))
        self.assertEqual(report["mutant_count"], len(report["mutants"]))


if __name__ == "__main__":
    unittest.main()
