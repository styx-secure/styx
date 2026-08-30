from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parents[2]


class MutationTests(unittest.TestCase):
    def test_every_declared_mutant_is_killed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "mutations.json"
            completed = subprocess.run(
                [sys.executable, "-B", str(PACKAGE / "run_mutations.py"), "--root", str(ROOT), "--output", str(output)],
                cwd=ROOT,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(33, report["killed"])
            self.assertTrue(all(row["killed"] is True for row in report["mutants"]))
            signatures = [
                row["behavioral_signature_sha256"] for row in report["mutants"]
            ]
            self.assertEqual(33, len(set(signatures)))
            self.assertTrue(
                all(row["affected_witness_count"] > 0 for row in report["mutants"])
            )


if __name__ == "__main__":
    unittest.main()
