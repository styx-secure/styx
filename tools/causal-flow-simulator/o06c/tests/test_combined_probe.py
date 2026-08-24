from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


O06C_ROOT = Path(__file__).resolve().parents[1]
PROBE = O06C_ROOT / "combined_falsification_probe.py"
sys.path.insert(0, str(O06C_ROOT))

from combined_falsification_probe import ProbeError, reject_digest_alias  # noqa: E402


class CombinedProbeTests(unittest.TestCase):
    def test_required_probe_is_canonical_and_exercises_all_stages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            frozen = root / "frozen.json"
            frozen.write_text(
                '{"schema":"styx-o06c-frozen-section-report/v1","verdict":"PASS"}\n',
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment["O06C_MODEL_SEED"] = "o06c-v1-deterministic-test-seed"
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            outputs = (root / "first.json", root / "second.json")
            for output in outputs:
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(PROBE),
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
            self.assertEqual(report["verdict"], "NO_COUNTEREXAMPLE_WITHIN_BOUNDS")
            self.assertGreaterEqual(report["witness_count"], 23)
            self.assertFalse(report["failed_witnesses"])
            counters = report["evidence"]["aggregate_stage_counters"]
            self.assertTrue(all(value > 0 for value in counters.values()))

    def test_injected_digest_alias_is_a_blocking_finding(self) -> None:
        with self.assertRaisesRegex(ProbeError, "HASH_COLLISION_FINDING"):
            reject_digest_alias(b"distinct-a", b"distinct-b", bytes(32), bytes(32))


if __name__ == "__main__":
    unittest.main()
