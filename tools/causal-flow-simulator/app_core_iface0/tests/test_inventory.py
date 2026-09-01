from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from inventory import (
    SEMANTIC_COUNT,
    STRUCTURAL_COUNT,
    TOTAL_COUNT,
    expand_semantic_instances,
    expand_structural_instances,
)


class InventoryTests(unittest.TestCase):
    def test_structural_relation_is_exact_and_unique(self) -> None:
        rows = expand_structural_instances(ROOT / "contract")
        self.assertEqual(len(rows), STRUCTURAL_COUNT)
        self.assertEqual(len({row.instance_id for row in rows}), STRUCTURAL_COUNT)
        self.assertEqual(rows[0].instance_id, "STR-REQUIRED-PROPERTY-OMISSION--0001")

    def test_semantic_relation_is_exact_and_unique(self) -> None:
        rows = expand_semantic_instances(ROOT / "contract")
        self.assertEqual(len(rows), SEMANTIC_COUNT)
        self.assertEqual(len({row.instance_id for row in rows}), SEMANTIC_COUNT)
        self.assertEqual(len(rows) + STRUCTURAL_COUNT, TOTAL_COUNT)


if __name__ == "__main__":
    unittest.main()

