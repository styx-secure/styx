"""Independence, self-review rejection and delegated-agent waiver denial."""

from __future__ import annotations

import unittest

import support
from support import evidence_pair, finding_dict, review_request_dict

from evidence import load_evidence
from model import IdentityError
from review import build_review_report, validate_review_request


def _build(request_dict):
    scope, test = evidence_pair()
    request = validate_review_request(request_dict)
    evidence = load_evidence(scope, test)
    return build_review_report(request, evidence)


class IndependenceTest(unittest.TestCase):
    def test_self_review_reused_execution_id(self):
        reviewer = support.reviewer_dict(execution_id=support.IMPLEMENTER_EXECUTION_ID)
        with self.assertRaises(IdentityError):
            _build(review_request_dict(verdict="GO", reviewer=reviewer))

    def test_reused_implementer_context_id(self):
        reviewer = support.reviewer_dict(context_id=support.IMPLEMENTER_CONTEXT_ID)
        with self.assertRaises(IdentityError):
            _build(review_request_dict(verdict="GO", reviewer=reviewer))

    def test_delegated_agent_reused_execution_id(self):
        reviewer = support.reviewer_dict(
            reviewer_class="DELEGATED_AGENT",
            execution_id=support.IMPLEMENTER_EXECUTION_ID,
        )
        with self.assertRaises(IdentityError):
            _build(review_request_dict(verdict="GO", reviewer=reviewer))

    def test_delegated_agent_reused_context_id(self):
        reviewer = support.reviewer_dict(
            reviewer_class="DELEGATED_AGENT",
            context_id=support.IMPLEMENTER_CONTEXT_ID,
        )
        with self.assertRaises(IdentityError):
            _build(review_request_dict(verdict="GO", reviewer=reviewer))

    def test_distinct_identities_pass(self):
        report = _build(review_request_dict(verdict="GO"))
        self.assertNotEqual(report["reviewer_execution_id"], report["implementer_execution_id"])
        self.assertNotEqual(report["reviewer_context_id"], report["implementer_context_id"])


class WaiverTest(unittest.TestCase):
    def test_human_can_waive_blocker(self):
        report = _build(review_request_dict(
            verdict="GO",
            findings=[finding_dict(severity="BLOCKER", lifecycle="WAIVED_BY_HUMAN", required_fix=True)],
        ))
        self.assertEqual(report["verdict"], "GO")

    def test_delegated_agent_cannot_waive_blocker(self):
        reviewer = support.reviewer_dict(reviewer_class="DELEGATED_AGENT")
        with self.assertRaises(IdentityError):
            _build(review_request_dict(
                verdict="GO",
                reviewer=reviewer,
                findings=[finding_dict(severity="BLOCKER", lifecycle="WAIVED_BY_HUMAN", required_fix=True)],
            ))

    def test_delegated_agent_cannot_waive_high(self):
        reviewer = support.reviewer_dict(reviewer_class="DELEGATED_AGENT")
        with self.assertRaises(IdentityError):
            _build(review_request_dict(
                verdict="GO",
                reviewer=reviewer,
                findings=[finding_dict(severity="HIGH", lifecycle="WAIVED_BY_HUMAN", required_fix=True)],
            ))

    def test_delegated_agent_cannot_waive_even_low(self):
        reviewer = support.reviewer_dict(reviewer_class="DELEGATED_AGENT")
        with self.assertRaises(IdentityError):
            _build(review_request_dict(
                verdict="GO",
                reviewer=reviewer,
                findings=[finding_dict(severity="LOW", lifecycle="WAIVED_BY_HUMAN")],
            ))


if __name__ == "__main__":
    unittest.main()
