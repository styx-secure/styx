from __future__ import annotations

from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[3]
O14_ROOT = REPO_ROOT / "tools" / "causal-flow-simulator" / "o14"
HISTORICAL_CANDIDATE_SHA = "86c3f2dbd630e445d737a25c09889de2777ee185"
sys.path.insert(0, str(O14_ROOT))

from scope_guard_o14 import (  # noqa: E402
    BASE_SHA,
    NORMATIVE_BOUNDED,
    allowed,
    blob,
    build_report,
    forbidden,
    normalize_normative,
)


class O14ScopeTests(unittest.TestCase):
    def test_historical_committed_relation_is_in_scope(self) -> None:
        report = build_report(REPO_ROOT, BASE_SHA, HISTORICAL_CANDIDATE_SHA)
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(
            report["validator_assignments_changed"],
            ["EXPECTED_SOURCE_RECORDS", "EXPECTED_STATUS_BY_COLLECTION"],
        )
        self.assertEqual(
            report["new_review_tests"],
            ["tools/protocol-review-model/tests/test_o14_scope.py"],
        )

    def test_forbidden_paths_win(self) -> None:
        self.assertTrue(forbidden("styx-js/src/product.js"))
        self.assertTrue(forbidden("tools/causal-flow-simulator/o14/report.json"))
        self.assertTrue(forbidden("nested/package-lock.json"))
        self.assertFalse(forbidden("tools/causal-flow-simulator/o14/evidence_io.py"))
        self.assertTrue(allowed("tools/causal-flow-simulator/o14/evidence_io.py"))

    def test_every_bounded_document_has_a_stable_normalizer(self) -> None:
        for path in sorted(NORMATIVE_BOUNDED):
            data = blob(REPO_ROOT, HISTORICAL_CANDIDATE_SHA, path)
            self.assertEqual(normalize_normative(data, path), normalize_normative(data, path))


if __name__ == "__main__":
    unittest.main()
