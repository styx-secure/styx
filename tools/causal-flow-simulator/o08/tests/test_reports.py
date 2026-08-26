from __future__ import annotations

import sys
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from canonical_report import ReportError, load_report, store_report


class ReportTests(unittest.TestCase):
    def test_canonical_round_trip(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            report = {"schema": "example/v1", "value": "docs/protocol/root-authority.md", "verdict": "PASS"}
            store_report(path, report, "example/v1")
            self.assertEqual(load_report(path, "example/v1"), report)

    def test_runtime_provenance_and_measurement_are_rejected(self):
        bad = ("provenance=/tmp/styx", "path=C:\\review", "elapsed=1.2s", "2026-08-26T12:00")
        with tempfile.TemporaryDirectory() as temporary:
            for index, value in enumerate(bad):
                with self.assertRaises(ReportError):
                    store_report(Path(temporary) / f"{index}.json", {"schema": "x/v1", "value": value}, "x/v1")


if __name__ == "__main__":
    unittest.main()
