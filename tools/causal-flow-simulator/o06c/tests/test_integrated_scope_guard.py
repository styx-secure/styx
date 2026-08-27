from __future__ import annotations

from pathlib import Path
import sys
import unittest


O06C = Path(__file__).resolve().parents[1]
REPO = O06C.parents[2]
if str(O06C) not in sys.path:
    sys.path.insert(0, str(O06C))

from integrated_scope_guard import ALLOWED_EXACT, BASE_SHA, REPORT_FIELDS, ScopeError, build_report
from o10.canonical_report import canonical_bytes


HISTORICAL_CANDIDATE_SHA = "490689f0d81980cf942d448c76a54192913b7cde"


class IntegratedScopeGuardTest(unittest.TestCase):
    def test_historical_committed_candidate_is_in_scope(self):
        report = build_report(REPO, BASE_SHA, HISTORICAL_CANDIDATE_SHA)
        self.assertEqual(report["verdict"], "PASS")
        self.assertGreater(report["record_count"], 0)
        canonical_bytes(report, allowed_fields=REPORT_FIELDS)

    def test_allowed_set_is_exact_and_excludes_frozen_trees(self):
        self.assertIn("tools/causal-flow-simulator/o06c/integrated_scope_guard.py", ALLOWED_EXACT)
        self.assertNotIn("tools/causal-flow-simulator/o14/semantic_registry.py", ALLOWED_EXACT)

    def test_wrong_base_fails_closed(self):
        with self.assertRaises(ScopeError):
            build_report(REPO, "0" * 40, "HEAD")


if __name__ == "__main__":
    unittest.main()
