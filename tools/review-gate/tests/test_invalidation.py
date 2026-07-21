"""A new candidate HEAD or diff invalidates any prior acceptance."""

from __future__ import annotations

import unittest

import support
from support import evidence_pair, review_request_dict

from evidence import load_evidence
from review import acceptance_still_valid, build_review_report, validate_review_request


def _go_report(candidate=None):
    scope, test = evidence_pair(head_sha=(candidate or support.candidate_dict())["head_sha"],
                                base_sha=(candidate or support.candidate_dict())["base_sha"])
    request = validate_review_request(review_request_dict(verdict="GO", candidate=candidate))
    evidence = load_evidence(scope, test)
    return build_review_report(request, evidence)


class InvalidationTest(unittest.TestCase):
    def test_same_candidate_still_valid(self):
        report = _go_report()
        self.assertTrue(acceptance_still_valid(report, support.candidate_dict()))

    def test_new_head_invalidates(self):
        report = _go_report()
        moved = support.candidate_dict(head_sha=support.OTHER_HEAD_SHA)
        self.assertFalse(acceptance_still_valid(report, moved))

    def test_new_diff_invalidates(self):
        report = _go_report()
        moved = support.candidate_dict(diff_sha256=support.OTHER_DIFF_SHA256)
        self.assertFalse(acceptance_still_valid(report, moved))

    def test_new_body_hash_invalidates(self):
        report = _go_report()
        moved = support.candidate_dict(issue_body_sha256="0" * 64)
        self.assertFalse(acceptance_still_valid(report, moved))

    def test_new_base_invalidates(self):
        report = _go_report()
        moved = support.candidate_dict(base_sha="0" * 40)
        self.assertFalse(acceptance_still_valid(report, moved))

    def test_non_acceptance_verdict_never_valid(self):
        scope, test = evidence_pair()
        request = validate_review_request(review_request_dict(
            verdict="CHANGES_REQUESTED",
            findings=[support.finding_dict(severity="HIGH", lifecycle="OPEN", required_fix=True)],
        ))
        evidence = load_evidence(scope, test)
        report = build_review_report(request, evidence)
        self.assertFalse(acceptance_still_valid(report, support.candidate_dict()))


if __name__ == "__main__":
    unittest.main()
