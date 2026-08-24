from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


O06C_ROOT = Path(__file__).resolve().parents[1]
GATE = O06C_ROOT / "cross_language_gate.py"


class CrossLanguageTests(unittest.TestCase):
    def environment(self) -> dict[str, str]:
        value = dict(os.environ)
        value["O06C_MODEL_SEED"] = "o06c-v1-deterministic-test-seed"
        value["PYTHONDONTWRITEBYTECODE"] = "1"
        value.pop("PYTHONPATH", None)
        return value

    def test_independent_derivations_match_and_bind_grant(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            frozen = root / "frozen.json"
            frozen.write_text(
                json.dumps(
                    {
                        "schema": "styx-o06c-frozen-section-report/v1",
                        "verdict": "PASS",
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            output = root / "report.json"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(GATE),
                    "--suite",
                    "required",
                    "--javascript",
                    "node",
                    "--frozen-report",
                    str(frozen),
                    "--workspace",
                    str(root / "workspace"),
                    "--output",
                    str(output),
                ],
                env=self.environment(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(output.read_bytes())
            self.assertEqual(report["verdict"], "PASS")
            self.assertEqual(report["event_count"], 9)
            self.assertEqual(
                report["python_derivation_sha256"],
                report["javascript_derivation_sha256"],
            )
            self.assertEqual(
                report["changed_python_derivation_sha256"],
                report["changed_javascript_derivation_sha256"],
            )
            self.assertTrue(report["grant_non_circular"])
            self.assertEqual(report["grant_rooted_case_count"], 8)
            self.assertTrue(
                all(
                    all(item["checks"].values())
                    for item in report["genesis_propagation"]
                )
            )

    def test_seed_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            frozen = root / "frozen.json"
            frozen.write_text(
                '{"schema":"styx-o06c-frozen-section-report/v1","verdict":"PASS"}\n',
                encoding="utf-8",
            )
            environment = self.environment()
            environment["O06C_MODEL_SEED"] = "wrong"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(GATE),
                    "--suite",
                    "required",
                    "--javascript",
                    "node",
                    "--frozen-report",
                    str(frozen),
                    "--workspace",
                    str(root / "workspace"),
                    "--output",
                    str(root / "report.json"),
                ],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 2)
            self.assertIn("O06C_MODEL_SEED mismatch", completed.stderr)


if __name__ == "__main__":
    unittest.main()
