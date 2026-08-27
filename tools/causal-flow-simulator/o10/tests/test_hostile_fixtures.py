from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
O10 = ROOT / "tools/causal-flow-simulator/o10"
sys.path.insert(0, str(O10))

from fixtures import cases  # noqa: E402


class HostileFixtureTests(unittest.TestCase):
    def test_checked_in_fixture_corpus_is_literal_and_complete(self) -> None:
        literal = json.loads((O10 / "hostile-scenarios.json").read_bytes())
        self.assertEqual(literal, {"cases": cases(), "schema": "styx.o10-hostile-fixtures.v1"})
        self.assertEqual(len(literal["cases"]), 79)


if __name__ == "__main__":
    unittest.main()
