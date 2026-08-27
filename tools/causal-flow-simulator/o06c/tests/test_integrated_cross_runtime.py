from __future__ import annotations

from pathlib import Path
import shutil
import sys
import unittest


O06C = Path(__file__).resolve().parents[1]
REPO = O06C.parents[2]
if str(O06C) not in sys.path:
    sys.path.insert(0, str(O06C))

from integrated_cross_runtime import REPORT_FIELDS, build_report
from o10.canonical_report import canonical_bytes


class IntegratedCrossRuntimeTest(unittest.TestCase):
    def test_python_and_javascript_regenerate_the_claimed_surface(self):
        node = shutil.which("node")
        self.assertIsNotNone(node)
        report = build_report(REPO, node)
        self.assertEqual(report["verdict"], "PASS")
        self.assertGreater(report["derived_event_count"], 0)
        self.assertEqual(report["interchange"], "TEST_ONLY_NOT_O11")
        canonical_bytes(report, allowed_fields=REPORT_FIELDS)


if __name__ == "__main__":
    unittest.main()
