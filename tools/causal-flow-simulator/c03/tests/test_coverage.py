from __future__ import annotations

import sys
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
sys.path.insert(0, str(ROOT))

from corpus_model import BASE_SHA, validate_base_inputs  # noqa: E402


class ClosedInputTests(unittest.TestCase):
    def test_source_map_and_inventory_match_exact_base(self) -> None:
        source_map, inventory = validate_base_inputs(REPO)
        self.assertEqual(source_map["base"], BASE_SHA)
        self.assertEqual(inventory["o07_relation_count"], 287)
        self.assertEqual(len(inventory["o10_primaries"]), 25)
        self.assertEqual(
            sum(
                len(inventory["o08_roles"][role])
                for role in (
                    "C03_SEMANTIC_LIMIT",
                    "C03_ACTIVATION_CAPABILITY_INPUT",
                    "C03_EXPLICIT_ZERO_OR_UNSUPPORTED",
                )
            ),
            53,
        )


if __name__ == "__main__":
    unittest.main()
