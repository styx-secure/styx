from __future__ import annotations

import shutil
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tools/causal-flow-simulator/o10"))

from run_mutations import build_report  # noqa: E402


class MutationTests(unittest.TestCase):
    def test_every_required_mutant_is_killed(self) -> None:
        node = shutil.which("node")
        self.assertIsNotNone(node)
        report = build_report(ROOT, node or "node")
        self.assertEqual(report["killed_count"], 64)
        self.assertEqual(report["survivor_count"], 0)


if __name__ == "__main__":
    unittest.main()
