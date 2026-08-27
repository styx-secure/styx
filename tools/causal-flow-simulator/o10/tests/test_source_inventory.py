from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tools/causal-flow-simulator/o10"))

from inventory import validate_literal  # noqa: E402


class SourceInventoryTests(unittest.TestCase):
    def test_literal_inventory_matches_frozen_inputs(self) -> None:
        inventory = validate_literal(ROOT)
        kinds = [row["kind"] for row in inventory["rows"]]
        self.assertEqual((len(kinds), kinds.count("positive"), kinds.count("negative")), (102, 99, 3))


if __name__ == "__main__":
    unittest.main()
