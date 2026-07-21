"""Verdict rules, reviewer classes and GO invalidation."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import support
from support import evidence_pair, finding_dict, review_request_dict

from evidence import load_evidence
from model import EXIT_CHANGES, EXIT_PASS, PreconditionError, ReviewInputError
from review import build_review_report, review_report_bytes, validate_review_request


def _build(request_dict):
    scope, test = evidence_pair()
    request = validate_review_request(request_dict)
    evidence = load_evidence(scope, test)
    return build_review_report(request, evidence)


class VerdictTest(unittest.TestCase):
    def test_go_clean(self):
        report = _build(review_request_dict(verdict="GO"))
        self.assertEqual(report["verdict"], "GO")
        self.assertFalse(report["remediation_required"])

    def test_go_with_conditions_open_low_finding(self):
        report = _build(review_request_dict(
            verdict="GO_WITH_CONDITIONS",
            findings=[finding_dict(severity="LOW", lifecycle="OPEN")],
        ))
        self.assertEqual(report["verdict"], "GO_WITH_CONDITIONS")

    def test_changes_requested_sets_remediation_required(self):
        report = _build(review_request_dict(
            verdict="CHANGES_REQUESTED",
            findings=[finding_dict(severity="HIGH", lifecycle="OPEN", required_fix=True)],
        ))
        self.assertTrue(report["remediation_required"])

    def test_blocked_with_open_blocker(self):
        report = _build(review_request_dict(
            verdict="BLOCKED",
            findings=[finding_dict(severity="BLOCKER", lifecycle="OPEN", required_fix=True)],
        ))
        self.assertEqual(report["verdict"], "BLOCKED")
        self.assertFalse(report["remediation_required"])

    def test_go_with_open_blocker_is_invalid(self):
        with self.assertRaises(PreconditionError):
            _build(review_request_dict(
                verdict="GO",
                findings=[finding_dict(severity="BLOCKER", lifecycle="OPEN")],
            ))

    def test_go_with_open_high_is_invalid(self):
        with self.assertRaises(PreconditionError):
            _build(review_request_dict(
                verdict="GO",
                findings=[finding_dict(severity="HIGH", lifecycle="OPEN")],
            ))

    def test_go_with_open_required_fix_is_invalid(self):
        with self.assertRaises(PreconditionError):
            _build(review_request_dict(
                verdict="GO",
                findings=[finding_dict(severity="LOW", lifecycle="OPEN", required_fix=True)],
            ))

    def test_go_with_conditions_and_open_blocker_is_invalid(self):
        with self.assertRaises(PreconditionError):
            _build(review_request_dict(
                verdict="GO_WITH_CONDITIONS",
                findings=[finding_dict(severity="BLOCKER", lifecycle="OPEN")],
            ))

    def test_go_valid_when_blocker_resolved(self):
        report = _build(review_request_dict(
            verdict="GO",
            findings=[finding_dict(severity="BLOCKER", lifecycle="RESOLVED", required_fix=True)],
        ))
        self.assertEqual(report["verdict"], "GO")

    def test_changes_requested_requires_open_finding(self):
        with self.assertRaises(ReviewInputError):
            _build(review_request_dict(verdict="CHANGES_REQUESTED", findings=[]))

    def test_blocked_requires_open_finding(self):
        with self.assertRaises(ReviewInputError):
            _build(review_request_dict(
                verdict="BLOCKED",
                findings=[finding_dict(severity="BLOCKER", lifecycle="RESOLVED")],
            ))


class ReviewerClassTest(unittest.TestCase):
    def test_human_reviewer_recorded(self):
        report = _build(review_request_dict(verdict="GO"))
        self.assertEqual(report["reviewer_class"], "HUMAN")

    def test_delegated_agent_reviewer_recorded(self):
        reviewer = support.reviewer_dict(reviewer_class="DELEGATED_AGENT")
        report = _build(review_request_dict(verdict="GO", reviewer=reviewer))
        self.assertEqual(report["reviewer_class"], "DELEGATED_AGENT")
        self.assertTrue(report["independent"])


class ExitCodeTest(unittest.TestCase):
    def test_changes_requested_exit_is_changes(self):
        scope, test = evidence_pair()
        request = review_request_dict(
            verdict="CHANGES_REQUESTED",
            findings=[finding_dict(severity="HIGH", lifecycle="OPEN", required_fix=True)],
        )
        with tempfile.TemporaryDirectory() as raw:
            code, output = support.run_review(Path(raw), request=request, scope_bytes=scope, test_bytes=test)
            self.assertEqual(code, EXIT_CHANGES)
            self.assertTrue(output.exists())

    def test_blocked_exit_is_changes(self):
        scope, test = evidence_pair()
        request = review_request_dict(
            verdict="BLOCKED",
            findings=[finding_dict(severity="BLOCKER", lifecycle="OPEN")],
        )
        with tempfile.TemporaryDirectory() as raw:
            code, output = support.run_review(Path(raw), request=request, scope_bytes=scope, test_bytes=test)
        self.assertEqual(code, EXIT_CHANGES)


class CanonicalStabilityTest(unittest.TestCase):
    def test_identical_inputs_hash_identically(self):
        first = review_report_bytes(_build(review_request_dict(verdict="GO")))
        second = review_report_bytes(_build(review_request_dict(verdict="GO")))
        self.assertEqual(first, second)

    def test_report_is_canonical(self):
        from model import canonical_json_bytes
        report = _build(review_request_dict(verdict="GO"))
        raw = review_report_bytes(report)
        import json
        reparsed = json.loads(raw.decode("utf-8"))
        self.assertEqual(canonical_json_bytes(reparsed), raw)


if __name__ == "__main__":
    unittest.main()
