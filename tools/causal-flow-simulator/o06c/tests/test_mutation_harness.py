from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


O06C_ROOT = Path(__file__).resolve().parents[1]
HARNESS = O06C_ROOT / "mutation_harness_o06c.py"


class MutationHarnessTests(unittest.TestCase):
    def test_closed_registry_has_exact_kills_and_is_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            frozen = root / "frozen.json"
            frozen.write_text(
                '{"schema":"styx-o06c-frozen-section-report/v1","verdict":"PASS"}\n',
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            outputs = (root / "first.json", root / "second.json")
            for output in outputs:
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(HARNESS),
                        "--suite",
                        "required",
                        "--frozen-report",
                        str(frozen),
                        "--output",
                        str(output),
                    ],
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())
            report = json.loads(outputs[0].read_bytes())
            self.assertEqual(report["registry_size"], 16)
            self.assertEqual(report["killed_count"], 16)
            self.assertEqual(report["verdict"], "ALL_REQUIRED_MUTANTS_KILLED")
            self.assertFalse(report["survived"])
            for mutant in report["mutants"]:
                self.assertTrue(mutant["mutated_path_executed"])
                self.assertEqual(mutant["observed_detectors"], mutant["declared_detectors"])
                self.assertEqual(mutant["disposition"], "EXACT_DECLARED_SET")
            self.assertTrue(report["witness_coverage"])
            self.assertTrue(
                all(
                    coverage["directed_assertions"]
                    for coverage in report["witness_coverage"].values()
                )
            )
            self.assertEqual(
                set(report["mutant_to_detectors"]),
                {mutant["id"] for mutant in report["mutants"]},
            )
            for mutant in report["mutants"]:
                self.assertEqual(
                    report["mutant_to_detectors"][mutant["id"]],
                    mutant["declared_detectors"],
                )


if __name__ == "__main__":
    unittest.main()
