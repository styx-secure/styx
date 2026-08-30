from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parents[2]
sys.path.insert(0, str(PACKAGE))

from inventory import load_unique, validate_anchor, validate_inventory  # noqa: E402


class InventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = load_unique(PACKAGE / "source-inventory.json")

    def test_closed_inventory_and_anchor_pass(self) -> None:
        self.assertEqual(66, len(validate_inventory(self.inventory)))
        validate_anchor(ROOT, load_unique(PACKAGE / "phase-b-anchor.json"))

    def test_missing_case_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.inventory)
        mutated["cases"].pop()
        with self.assertRaises(ValueError):
            validate_inventory(mutated)

    def test_oracle_in_adapter_input_fails_closed(self) -> None:
        mutated = copy.deepcopy(self.inventory)
        mutated["cases"][0]["input"]["expected"] = "PASS"
        with self.assertRaises(ValueError):
            validate_inventory(mutated)


if __name__ == "__main__":
    unittest.main()
