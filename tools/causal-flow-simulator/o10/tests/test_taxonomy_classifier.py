from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tools/causal-flow-simulator/o10"))

from fixtures import primary_scenario  # noqa: E402
from taxonomy import PRIMARY_ROWS, TaxonomyError, evaluate  # noqa: E402


class TaxonomyClassifierTests(unittest.TestCase):
    def test_every_primary_is_reachable_exactly(self) -> None:
        for primary in PRIMARY_ROWS:
            with self.subTest(primary=primary):
                self.assertEqual(evaluate(primary_scenario(primary)).primary, primary)

    def test_unknown_fields_fail_closed(self) -> None:
        scenario = primary_scenario("APPLIED")
        scenario["invented"] = True
        with self.assertRaises(TaxonomyError):
            evaluate(scenario)


if __name__ == "__main__":
    unittest.main()
