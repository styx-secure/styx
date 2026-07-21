"""F2: a delegated agent cannot clear a severe finding by asserting RESOLVED.

A bare ``RESOLVED`` lifecycle is an assertion, not evidence. Because RESOLVED
findings are excluded from the open/severe evaluation, a delegated agent could
otherwise record a BLOCKER, mark it RESOLVED and take GO on the same HEAD, with
no fix, no new evidence and no re-verification -- the waiver denial defeated in
all but name.

The frozen v1 shapes carry nothing that could *prove* a cross-round
re-verification, so this version fails closed on the strict rule rather than
inventing a weak binding: final resolution of a severe or required-fix finding
is reserved to a human reviewer.
"""

from __future__ import annotations

import unittest

import support
from support import evidence_pair, finding_dict, review_request_dict

from evidence import load_evidence
from model import IdentityError
from review import CANDIDATE_FIELDS, REVIEW_REQUEST_FIELDS, build_review_report, validate_review_request

DELEGATED = {"reviewer_class": "DELEGATED_AGENT"}


def _build(request_dict):
    scope, test = evidence_pair()
    request = validate_review_request(request_dict)
    evidence = load_evidence(scope, test)
    return build_review_report(request, evidence)


def _delegated(verdict, findings):
    return review_request_dict(
        verdict=verdict,
        reviewer=support.reviewer_dict(**DELEGATED),
        findings=findings,
    )


class DelegatedSevereResolutionTest(unittest.TestCase):
    def test_blocker_resolved_go_fails_closed(self):
        with self.assertRaises(IdentityError):
            _build(_delegated("GO", [finding_dict(severity="BLOCKER", lifecycle="RESOLVED")]))

    def test_high_resolved_go_fails_closed(self):
        with self.assertRaises(IdentityError):
            _build(_delegated("GO", [finding_dict(severity="HIGH", lifecycle="RESOLVED")]))

    def test_blocker_resolved_go_with_conditions_fails_closed(self):
        with self.assertRaises(IdentityError):
            _build(_delegated("GO_WITH_CONDITIONS", [finding_dict(severity="BLOCKER", lifecycle="RESOLVED")]))

    def test_high_resolved_go_with_conditions_fails_closed(self):
        with self.assertRaises(IdentityError):
            _build(_delegated("GO_WITH_CONDITIONS", [finding_dict(severity="HIGH", lifecycle="RESOLVED")]))

    def test_required_fix_resolved_go_fails_closed(self):
        # required_fix must block acceptance until validly resolved, whatever
        # the severity.
        with self.assertRaises(IdentityError):
            _build(_delegated("GO", [finding_dict(severity="LOW", lifecycle="RESOLVED", required_fix=True)]))

    def test_required_fix_resolved_go_with_conditions_fails_closed(self):
        with self.assertRaises(IdentityError):
            _build(_delegated(
                "GO_WITH_CONDITIONS",
                [finding_dict(severity="INFO", lifecycle="RESOLVED", required_fix=True)],
            ))

    def test_blocker_resolved_fails_closed_on_unchanged_head(self):
        # The candidate HEAD is exactly the HEAD the evidence was produced for:
        # nothing has been re-implemented, so nothing can have been fixed.
        scope, test = evidence_pair(head_sha=support.HEAD_SHA)
        request = validate_review_request(_delegated(
            "GO", [finding_dict(severity="BLOCKER", lifecycle="RESOLVED", required_fix=True)],
        ))
        evidence = load_evidence(scope, test)
        self.assertEqual(request["candidate"]["head_sha"], evidence.head_sha)
        with self.assertRaises(IdentityError):
            build_review_report(request, evidence)

    def test_one_severe_resolved_taints_an_otherwise_clean_acceptance(self):
        with self.assertRaises(IdentityError):
            _build(_delegated("GO", [
                finding_dict(severity="LOW", lifecycle="RESOLVED", problem="A cosmetic nit."),
                finding_dict(severity="BLOCKER", lifecycle="RESOLVED", problem="A real blocker."),
            ]))

    def test_open_severe_finding_still_blocks_acceptance(self):
        # OPEN must keep blocking GO, independently of the new rule.
        from model import PreconditionError

        with self.assertRaises(PreconditionError):
            _build(_delegated("GO", [finding_dict(severity="BLOCKER", lifecycle="OPEN")]))

    def test_addressed_pending_reverify_still_blocks_acceptance(self):
        from model import PreconditionError

        with self.assertRaises(PreconditionError):
            _build(_delegated("GO", [finding_dict(severity="HIGH", lifecycle="ADDRESSED_PENDING_REVERIFY")]))

    def test_waived_by_human_remains_impossible_for_a_delegated_agent(self):
        with self.assertRaises(IdentityError):
            _build(_delegated("GO", [finding_dict(severity="BLOCKER", lifecycle="WAIVED_BY_HUMAN")]))


class NoFreshEvidenceBindingTest(unittest.TestCase):
    """No weak cross-round binding was invented to justify a resolution."""

    def test_review_request_cannot_carry_a_prior_review_report_hash(self):
        # There is nowhere in the v1 shape to state "this was verified against
        # review report X", so a delegated RESOLVED can never be evidenced. The
        # closed shape also rejects a forged attempt to supply one.
        self.assertNotIn("previous_review_report_sha256", CANDIDATE_FIELDS)
        self.assertNotIn("previous_review_report_sha256", REVIEW_REQUEST_FIELDS)
        candidate = support.candidate_dict()
        candidate["previous_review_report_sha256"] = "0" * 64
        from model import ReviewInputError

        with self.assertRaises(ReviewInputError):
            validate_review_request(review_request_dict(verdict="GO", candidate=candidate))

    def test_review_request_cannot_carry_a_prior_head(self):
        self.assertNotIn("previous_head_sha", CANDIDATE_FIELDS)
        candidate = support.candidate_dict()
        candidate["previous_head_sha"] = "1" * 40
        from model import ReviewInputError

        with self.assertRaises(ReviewInputError):
            validate_review_request(review_request_dict(verdict="GO", candidate=candidate))

    def test_finding_cannot_carry_fix_evidence(self):
        from model import ReviewInputError

        finding = finding_dict(severity="BLOCKER", lifecycle="RESOLVED")
        finding["fix_evidence_sha256"] = "0" * 64
        with self.assertRaises(ReviewInputError):
            validate_review_request(_delegated("GO", [finding]))


class DelegatedPermittedTest(unittest.TestCase):
    """The rule is scoped: it denies severe self-clearing, nothing else."""

    def test_delegated_clean_go_still_allowed(self):
        report = _build(_delegated("GO", []))
        self.assertEqual(report["verdict"], "GO")

    def test_delegated_resolved_medium_without_required_fix_allowed(self):
        report = _build(_delegated("GO", [finding_dict(severity="MEDIUM", lifecycle="RESOLVED")]))
        self.assertEqual(report["verdict"], "GO")

    def test_delegated_may_record_severe_resolved_under_changes_requested(self):
        # Recording history is fine; only *accepting* on it is not.
        report = _build(_delegated("CHANGES_REQUESTED", [
            finding_dict(severity="BLOCKER", lifecycle="RESOLVED", problem="Fixed last round."),
            finding_dict(severity="HIGH", lifecycle="OPEN", required_fix=True, problem="Still broken."),
        ]))
        self.assertEqual(report["verdict"], "CHANGES_REQUESTED")
        self.assertTrue(report["remediation_required"])

    def test_delegated_may_record_severe_resolved_under_blocked(self):
        report = _build(_delegated("BLOCKED", [
            finding_dict(severity="BLOCKER", lifecycle="RESOLVED", problem="Fixed last round."),
            finding_dict(severity="BLOCKER", lifecycle="OPEN", problem="A fresh blocker."),
        ]))
        self.assertEqual(report["verdict"], "BLOCKED")


class HumanResolutionTest(unittest.TestCase):
    """Explicit positive cases for the authorized human reviewer."""

    def test_human_can_resolve_blocker_and_go(self):
        report = _build(review_request_dict(
            verdict="GO",
            findings=[finding_dict(severity="BLOCKER", lifecycle="RESOLVED", required_fix=True)],
        ))
        self.assertEqual(report["verdict"], "GO")
        self.assertEqual(report["reviewer_class"], "HUMAN")

    def test_human_can_resolve_high_and_go_with_conditions(self):
        report = _build(review_request_dict(
            verdict="GO_WITH_CONDITIONS",
            findings=[finding_dict(severity="HIGH", lifecycle="RESOLVED", required_fix=True)],
        ))
        self.assertEqual(report["verdict"], "GO_WITH_CONDITIONS")

    def test_human_can_resolve_required_fix_and_go(self):
        report = _build(review_request_dict(
            verdict="GO",
            findings=[finding_dict(severity="LOW", lifecycle="RESOLVED", required_fix=True)],
        ))
        self.assertEqual(report["verdict"], "GO")

    def test_human_can_waive_blocker_and_go(self):
        report = _build(review_request_dict(
            verdict="GO",
            findings=[finding_dict(severity="BLOCKER", lifecycle="WAIVED_BY_HUMAN", required_fix=True)],
        ))
        self.assertEqual(report["verdict"], "GO")


if __name__ == "__main__":
    unittest.main()
