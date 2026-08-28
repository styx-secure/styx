from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
CORPUS = REPO / "conformance/application-protocol/c03"
sys.path.insert(0, str(ROOT))

from canonical_json import dumps  # noqa: E402
from run_cross_runtime import run  # noqa: E402


class CrossRuntimeTests(unittest.TestCase):
    def test_python_and_javascript_reports_are_identical(self) -> None:
        report = run(REPO, CORPUS)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["runtimes"], ["javascript", "python"])
        self.assertEqual(report["scenarios"], 46)
        self.assertEqual(report["vectors"], 27)
        self.assertRegex(report["reportDigest"], r"^[0-9a-f]{64}$")

    def test_cross_report_has_closed_canonical_shape(self) -> None:
        report = run(REPO, CORPUS)
        self.assertEqual(
            set(report),
            {"reportDigest", "result", "runtimes", "scenarios", "vectors"},
        )
        encoded = dumps(report)
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertNotIn(str(REPO).encode(), encoded)
        self.assertNotIn(b"elapsed", encoded)


if __name__ == "__main__":
    unittest.main()
