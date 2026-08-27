from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tools/causal-flow-simulator/o10"))

from fixtures import _combine  # noqa: E402
from taxonomy import EVENT_PRECEDENCE, K_PRECEDENCE, evaluate  # noqa: E402


class PrecedenceTests(unittest.TestCase):
    def test_adjacent_edges_ignore_presentation_order(self) -> None:
        for order in (K_PRECEDENCE, EVENT_PRECEDENCE):
            for index, (higher, lower) in enumerate(zip(order, order[1:])):
                for reverse in (False, True):
                    scenario = _combine(
                        f"test-edge-{index}-{reverse}", higher, lower, reverse=reverse
                    )
                    self.assertEqual(evaluate(scenario).primary, higher)


if __name__ == "__main__":
    unittest.main()
