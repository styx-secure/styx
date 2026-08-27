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

    def test_integration_specific_hostile_families_are_literal(self):
        identifiers = {item.identifier for item in required_witnesses()}
        required = {
            "I-POS-AUTHORITY-GENESIS",
            "I-POS-AUTHORITY-GRANT",
            "I-POS-ROTATION-SUCCESSOR",
            "I-POS-RECOVERY-SUCCESSOR",
            "I-POS-SAME-KEY-DISTINCT-CREDENTIAL",
            "I-STATE-FRESH-REPLAY",
            "I-POS-CONTENT-REQUIRED-SINGLE",
            "I-POS-CONTENT-REQUIRED-TREE",
            "I-POS-CONTENT-DETACHABLE-SINGLE",
            "I-POS-CONTENT-DETACHABLE-TREE",
            "I-K-PROVENANCE-INVALID",
            "I-K-SEQUENCE-ROLLBACK",
            "I-K-SEQUENCE-GAP",
            "I-K-SAME-KEY-WRONG-CREDENTIAL",
            "I-K-ZERO-SUITE",
            "I-K-MAX-SUITE",
            "I-K-KEY-EMPTY",
            "I-K-KEY-DECLARED-MAX",
            "I-K-SIG-EMPTY",
            "I-K-SIG-DECLARED-MAX",
            "I-K-SCALAR-L",
            "I-K-SCALAR-GREATER-L",
            "I-K-SCALAR-PLUS-L",
            "I-K-KEY-NONCANONICAL",
            "I-K-KEY-OFF-CURVE",
            "I-K-KEY-MIXED-ORDER",
            "I-K-KEY-MIXED-ORDER-COFACTORLESS",
            "I-K-R-NONCANONICAL",
            "I-K-R-OFF-CURVE",
            "I-K-R-SMALL-ORDER",
            "I-K-R-MIXED-ORDER",
            "I-K-EVENT-REFERENCE-SIGNATURE",
            "I-SUB-NOSTR",
            "I-SUB-MLS",
        }
        self.assertLessEqual(required, identifiers)


if __name__ == "__main__":
    unittest.main()
