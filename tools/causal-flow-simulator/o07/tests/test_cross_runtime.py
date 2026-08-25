from __future__ import annotations

from pathlib import Path
import shutil
import sys
import tempfile
import unittest


O07_ROOT = Path(__file__).resolve().parents[1]
if str(O07_ROOT) not in sys.path:
    sys.path.insert(0, str(O07_ROOT))

from run_cross_runtime import build_report


class CrossRuntimeTest(unittest.TestCase):
    def test_python_and_node_agree(self) -> None:
        node = shutil.which("node")
        self.assertIsNotNone(node)
        repo = Path(__file__).resolve().parents[4]
        with tempfile.TemporaryDirectory() as root:
            report, passed = build_report(repo, Path(root) / "runtime", "node")
        self.assertTrue(passed)
        self.assertEqual(report["adapter_count"], 2)
        self.assertEqual(report["semantic_atom_count"], 229)
        self.assertEqual(report["failed"], [])


if __name__ == "__main__":
    unittest.main()
