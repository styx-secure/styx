from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from pathlib import Path


PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parents[2]
sys.path.insert(0, str(PACKAGE))

from inventory import (  # noqa: E402
    load_unique,
    validate_anchor,
    validate_inventory,
    validate_public_reader_inputs,
)


class InventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = load_unique(PACKAGE / "source-inventory.json")

    def test_closed_inventory_and_anchor_pass(self) -> None:
        self.assertEqual(67, len(validate_inventory(self.inventory)))
        validate_anchor(ROOT, load_unique(PACKAGE / "phase-b-anchor.json"))
        self.assertEqual(5, validate_public_reader_inputs(ROOT))

    def test_missing_case_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.inventory)
        mutated["cases"].pop()
        with self.assertRaises(ValueError):
            validate_inventory(mutated)

    def test_anchor_registry_qualification_fails_closed(self) -> None:
        anchor = load_unique(PACKAGE / "phase-b-anchor.json")
        anchor["profile"]["ciphersuite_registry"] = "STYX_SIGNATURE"
        with self.assertRaisesRegex(ValueError, "profile mismatch"):
            validate_anchor(ROOT, anchor)

    def test_oracle_in_adapter_input_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.inventory)
        mutated["cases"][0]["input"]["expected"] = "PASS"
        with self.assertRaises(ValueError):
            validate_inventory(mutated)

    def test_reused_candidate_input_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.inventory)
        mutated["cases"][1]["input"] = copy.deepcopy(mutated["cases"][0]["input"])
        with self.assertRaisesRegex(ValueError, "distinct atoms"):
            validate_inventory(mutated)

    def test_public_derivation_drift_fails_closed(self) -> None:
        path = PACKAGE / "public-candidate-projections.json"
        original = path.read_text(encoding="utf-8")
        mutated = original.replace(
            "LOWER_UNSIGNED_LEXICOGRAPHIC_ACCOUNT_AFTER_FIXED_INPUT_CHECKS",
            "APPLICATION_WITNESS_SELECTOR",
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "tools/causal-flow-simulator/ss0"
            target.mkdir(parents=True)
            for name in (
                "oracle-reader-task.json",
                "phase-b-anchor.json",
                "public-candidate-projections.json",
            ):
                (target / name).write_bytes((PACKAGE / name).read_bytes())
            (target / path.name).write_text(mutated, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "derivation mismatch"):
                validate_public_reader_inputs(root)


if __name__ == "__main__":
    unittest.main()
