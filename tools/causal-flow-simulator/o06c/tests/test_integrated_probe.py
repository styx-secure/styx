from __future__ import annotations

from pathlib import Path
import sys
import unittest


O06C = Path(__file__).resolve().parents[1]
if str(O06C) not in sys.path:
    sys.path.insert(0, str(O06C))

from integrated_probe import REPORT_FIELDS, build_report
from integrated_registry import required_witnesses
from o10.canonical_report import canonical_bytes


class IntegratedProbeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = build_report()

    def test_complete_probe_passes(self):
        self.assertEqual(self.report["verdict"], "PASS")
        executed = {
            row["id"]
            for name in (
                "witness_results",
                "dispositions",
                "handoff_results",
                "boundary_results",
            )
            for row in self.report[name]
        }
        self.assertEqual(executed, {item.identifier for item in required_witnesses()})

    def test_exact_envelope_counts_are_executed(self):
        self.assertEqual(self.report["disposition_count"], 69)
        self.assertEqual(self.report["handoff_count"], 66)
        self.assertGreater(self.report["boundary_count"], 100)

    def test_report_is_canonical_and_has_no_runtime_identity(self):
        payload = canonical_bytes(self.report, allowed_fields=REPORT_FIELDS)
        self.assertTrue(payload.endswith(b"\n"))
        self.assertNotIn(str(Path.cwd()).encode(), payload)


if __name__ == "__main__":
    unittest.main()
