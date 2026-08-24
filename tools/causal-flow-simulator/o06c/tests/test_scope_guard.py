from __future__ import annotations

from pathlib import Path
import sys
import unittest


O06C_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = O06C_ROOT.parents[2]
sys.path.insert(0, str(O06C_ROOT))

from scope_guard import (  # noqa: E402
    BASE_SHA,
    REGIONS,
    allowed,
    build_report,
    changed_records,
    enforce_named_regions,
    enforce_validator_ast,
    forbidden,
    normalize_regions,
)


class ScopeGuardTests(unittest.TestCase):
    def test_current_committed_relation_is_in_scope(self) -> None:
        records = changed_records(REPO_ROOT, BASE_SHA, "HEAD")
        self.assertTrue(records)
        self.assertTrue(
            all(
                allowed(path) and not forbidden(path)
                for record in records
                for path in record["paths"]
            )
        )
        self.assertEqual(
            enforce_validator_ast(REPO_ROOT, BASE_SHA, "HEAD"),
            [
                "CONTRACT_BASE_COMMIT",
                "EXPECTED_BLOCKER_EDGES_DIGEST",
                "EXPECTED_INVARIANT_REFS_DIGEST",
                "EXPECTED_SOURCE_RECORDS",
                "EXPECTED_STATUS_BY_COLLECTION",
            ],
        )
        self.assertEqual(len(enforce_named_regions(REPO_ROOT, BASE_SHA, "HEAD")), 2)

    def test_canonical_report_defers_candidate_identity_to_pr_evidence(self) -> None:
        report = build_report(REPO_ROOT, BASE_SHA, "HEAD")
        self.assertEqual(report["candidate_identity_location"], "immutable_pr_evidence")
        self.assertNotIn("candidate_commit", report)
        self.assertNotIn("candidate_tree", report)

    def test_forbidden_paths_always_win(self) -> None:
        self.assertTrue(forbidden("styx-js/src/product.js"))
        self.assertTrue(forbidden("tools/causal-flow-simulator/o06c/generated.json"))
        self.assertTrue(forbidden("nested/package-lock.json"))
        self.assertFalse(forbidden("tools/causal-flow-simulator/o06c/model.py"))

    def test_named_region_masks_only_the_selected_row(self) -> None:
        path = "example.md"
        selectors = (("row", "| selected |"),)
        baseline = b"# title\n| selected | old |\noutside\n"
        allowed_change = b"# title\n| selected | new |\noutside\n"
        unrelated_change = b"# title\n| selected | new |\nchanged\n"
        self.assertEqual(
            normalize_regions(baseline, path, selectors),
            normalize_regions(allowed_change, path, selectors),
        )
        self.assertNotEqual(
            normalize_regions(baseline, path, selectors),
            normalize_regions(unrelated_change, path, selectors),
        )


if __name__ == "__main__":
    unittest.main()
