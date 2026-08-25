from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scenarios import (
    EXPECTED_RUNTIME_VECTOR_COUNT,
    EXPECTED_WITNESS_COUNT,
    execute_suite,
    required_witnesses,
)
from semantic_registry import SELECTED_SUITE


class SemanticRegistryTest(unittest.TestCase):
    def test_registry_is_closed_and_complete(self) -> None:
        self.assertEqual(SELECTED_SUITE.identifier, 1)
        self.assertEqual(SELECTED_SUITE.public_key_octets, 32)
        self.assertEqual(SELECTED_SUITE.signature_octets, 64)
        self.assertIn("prime-order", SELECTED_SUITE.verification_equation)
        self.assertIn("O-06b-1", SELECTED_SUITE.transcript_input)

    def test_required_suite_passes(self) -> None:
        results = execute_suite()
        self.assertEqual(len(required_witnesses()), EXPECTED_WITNESS_COUNT)
        self.assertFalse([item for item in results if not item["passed"]])

    def test_runtime_inventory_has_required_equation_witnesses(self) -> None:
        identifiers = {item.identifier for item in required_witnesses() if item.runtime}
        self.assertEqual(len(identifiers), EXPECTED_RUNTIME_VECTOR_COUNT)
        self.assertIn("mixed-order-key", identifiers)
        self.assertIn("mixed-order-cofactorless-valid", identifiers)
        self.assertIn("small-order-r", identifiers)
        self.assertIn("noncanonical-key", identifiers)
        self.assertIn("noncanonical-r", identifiers)
        self.assertIn("zero-length-key", identifiers)
        self.assertIn("zero-length-signature", identifiers)

    def test_succession_and_alias_boundaries_are_directed(self) -> None:
        identifiers = {item.identifier for item in required_witnesses()}
        self.assertTrue(
            {
                "revoked",
                "rotated-predecessor",
                "recovered-predecessor",
                "historical-revoked",
                "historical-rotated",
                "rotation-successor",
                "recovery-successor",
                "same-key-distinct-credential",
                "same-key-distinct-credential-positive",
            }.issubset(identifiers)
        )


if __name__ == "__main__":
    unittest.main()
