"""Finding canonical identity, lifecycle, missing-test and path hardening."""

from __future__ import annotations

import unittest

import support
from support import evidence_pair, finding_dict, review_request_dict

from evidence import load_evidence
from model import LIFECYCLE_STATES, PathError, ReviewInputError
from review import build_review_report, validate_review_request


def _build(request_dict):
    scope, test = evidence_pair()
    request = validate_review_request(request_dict)
    evidence = load_evidence(scope, test)
    return build_review_report(request, evidence)


class FindingIdentityTest(unittest.TestCase):
    def test_stable_across_builds(self):
        finding = finding_dict(severity="HIGH")
        a = _build(review_request_dict(verdict="CHANGES_REQUESTED",
                                       findings=[dict(finding, required_fix=True)]))
        b = _build(review_request_dict(verdict="CHANGES_REQUESTED",
                                       findings=[dict(finding, required_fix=True)]))
        self.assertEqual(a["findings"][0]["finding_id"], b["findings"][0]["finding_id"])

    def test_stable_across_lifecycle_change(self):
        base = finding_dict(severity="HIGH", required_fix=True)
        open_report = _build(review_request_dict(verdict="CHANGES_REQUESTED", findings=[dict(base, lifecycle="OPEN")]))
        resolved_report = _build(review_request_dict(verdict="GO", findings=[dict(base, lifecycle="RESOLVED")]))
        self.assertEqual(open_report["findings"][0]["finding_id"], resolved_report["findings"][0]["finding_id"])

    def test_changes_when_problem_changes(self):
        a = _build(review_request_dict(verdict="CHANGES_REQUESTED",
                                       findings=[finding_dict(severity="HIGH", required_fix=True, problem="Problem A")]))
        b = _build(review_request_dict(verdict="CHANGES_REQUESTED",
                                       findings=[finding_dict(severity="HIGH", required_fix=True, problem="Problem B")]))
        self.assertNotEqual(a["findings"][0]["finding_id"], b["findings"][0]["finding_id"])

    def test_duplicate_canonical_identity_rejected(self):
        dup = finding_dict(severity="HIGH", required_fix=True)
        with self.assertRaises(ReviewInputError):
            _build(review_request_dict(verdict="CHANGES_REQUESTED", findings=[dict(dup), dict(dup)]))

    def test_findings_sorted_by_id(self):
        report = _build(review_request_dict(
            verdict="CHANGES_REQUESTED",
            findings=[
                finding_dict(severity="HIGH", required_fix=True, problem="Alpha", component_path="tools/review-gate/a.py"),
                finding_dict(severity="HIGH", required_fix=True, problem="Beta", component_path="tools/review-gate/b.py"),
            ],
        ))
        ids = [f["finding_id"] for f in report["findings"]]
        self.assertEqual(ids, sorted(ids))


class LifecycleTest(unittest.TestCase):
    def test_all_lifecycle_states_accepted(self):
        for state in LIFECYCLE_STATES:
            verdict = "GO" if state in ("RESOLVED", "WAIVED_BY_HUMAN") else "CHANGES_REQUESTED"
            report = _build(review_request_dict(
                verdict=verdict,
                findings=[finding_dict(severity="MEDIUM", lifecycle=state)],
            ))
            self.assertEqual(report["findings"][0]["lifecycle"], state)


class MissingTestFindingTest(unittest.TestCase):
    def test_missing_test_finding_preserved(self):
        report = _build(review_request_dict(
            verdict="CHANGES_REQUESTED",
            findings=[finding_dict(
                severity="HIGH",
                required_fix=True,
                required_test="MISSING: no test exercises the atomic write failure path.",
                problem="The atomic write failure path is untested.",
            )],
        ))
        self.assertIn("MISSING", report["findings"][0]["required_test"])


class PathHardeningTest(unittest.TestCase):
    def test_parent_traversal_rejected(self):
        with self.assertRaises(PathError):
            validate_review_request(review_request_dict(
                verdict="CHANGES_REQUESTED",
                findings=[finding_dict(severity="HIGH", required_fix=True, component_path="../etc/passwd")],
            ))

    def test_absolute_path_rejected(self):
        with self.assertRaises(PathError):
            validate_review_request(review_request_dict(
                verdict="CHANGES_REQUESTED",
                findings=[finding_dict(severity="HIGH", required_fix=True, component_path="/etc/passwd")],
            ))

    def test_backslash_rejected(self):
        with self.assertRaises(PathError):
            validate_review_request(review_request_dict(
                verdict="CHANGES_REQUESTED",
                findings=[finding_dict(severity="HIGH", required_fix=True, component_path="tools\\review-gate\\x.py")],
            ))

    def test_home_relative_rejected(self):
        with self.assertRaises(PathError):
            validate_review_request(review_request_dict(
                verdict="CHANGES_REQUESTED",
                findings=[finding_dict(severity="HIGH", required_fix=True, component_path="~/secret")],
            ))


if __name__ == "__main__":
    unittest.main()
