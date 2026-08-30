from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parents[2]


class CrossRuntimeTests(unittest.TestCase):
    def test_javascript_matches_python(self) -> None:
        node = shutil.which("node")
        self.assertIsNotNone(node)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "cross.json"
            completed = subprocess.run(
                [sys.executable, "-B", str(PACKAGE / "run_cross_runtime.py"), "--root", str(ROOT), "--node", node, "--output", str(output)],
                cwd=ROOT,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual("PASS", report["result"])
            self.assertEqual(66, len(report["observations"]))


if __name__ == "__main__":
    unittest.main()
