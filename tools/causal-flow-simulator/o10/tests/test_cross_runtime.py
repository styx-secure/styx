from __future__ import annotations

import shutil
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tools/causal-flow-simulator/o10"))

from run_cross_runtime import build_report  # noqa: E402


class CrossRuntimeTests(unittest.TestCase):
    def test_python_and_javascript_are_byte_identical(self) -> None:
        node = shutil.which("node")
        self.assertIsNotNone(node)
        report = build_report(ROOT, node or "node")
        self.assertEqual(report["case_count"], 79)
        self.assertEqual(report["verdict"], "PASS")


if __name__ == "__main__":
    unittest.main()
