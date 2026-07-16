"""Review preconditions: exact-HEAD PASS binding and evidence rejection."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import support
from support import evidence_pair, review_request_dict

from evidence import load_evidence
from model import EXIT_CHANGES, EXIT_ERROR, EXIT_PASS, EvidenceError, PreconditionError
from review import build_review_report, validate_review_request


class ExactHeadPreconditionTest(unittest.TestCase):
    def test_green_pass_evidence_accepts_review(self):
        scope, test = evidence_pair()
        request = validate_review_request(review_request_dict(verdict="GO"))
        evidence = load_evidence(scope, test)
        report = build_review_report(request, evidence)
        self.assertEqual(report["verdict"], "GO")
        self.assertEqual(report["head_sha"], support.HEAD_SHA)
        self.assertEqual(report["scope_verdict"], "PASS")
        self.assertEqual(report["test_verdict"], "PASS")

    def test_cli_go_exit_code_is_pass(self):
        scope, test = evidence_pair()
        with tempfile.TemporaryDirectory() as raw:
            code, output = support.run_review(Path(raw), request=review_request_dict(verdict="GO"),
                                              scope_bytes=scope, test_bytes=test)
        self.assertEqual(code, EXIT_PASS)

    def test_scope_fail_blocks_review(self):
        scope, test = evidence_pair(scope_verdict="FAIL")
        request = validate_review_request(review_request_dict(verdict="GO"))
        evidence = load_evidence(scope, test)
        with self.assertRaises(PreconditionError):
            build_review_report(request, evidence)

    def test_test_fail_blocks_review(self):
        scope, test = evidence_pair(test_verdict="FAIL")
        request = validate_review_request(review_request_dict(verdict="GO"))
        evidence = load_evidence(scope, test)
        with self.assertRaises(PreconditionError):
            build_review_report(request, evidence)

    def test_test_error_blocks_review(self):
        scope, test = evidence_pair(test_verdict="ERROR")
        request = validate_review_request(review_request_dict(verdict="GO"))
        evidence = load_evidence(scope, test)
        with self.assertRaises(PreconditionError):
            build_review_report(request, evidence)

    def test_cli_scope_fail_is_error(self):
        scope, test = evidence_pair(scope_verdict="FAIL")
        with tempfile.TemporaryDirectory() as raw:
            code, output = support.run_review(Path(raw), request=review_request_dict(verdict="GO"),
                                              scope_bytes=scope, test_bytes=test)
        self.assertEqual(code, EXIT_ERROR)
        self.assertFalse(output.exists())


class EvidenceRejectionTest(unittest.TestCase):
    def test_missing_evidence_field(self):
        scope, test = evidence_pair()
        import json
        broken = json.loads(scope.decode())
        del broken["head_sha"]
        from model import canonical_json_bytes
        with self.assertRaises(EvidenceError):
            load_evidence(canonical_json_bytes(broken), test)

    def test_cross_linked_evidence(self):
        # A test report bound to a foreign scope report.
        scope, _ = evidence_pair()
        _, foreign_test = evidence_pair(issue_body_sha256="0" * 64)
        with self.assertRaises(PreconditionError):
            load_evidence(scope, foreign_test)

    def test_stale_head_drift(self):
        # Evidence at OTHER_HEAD, candidate at HEAD -> stale.
        scope, test = evidence_pair(head_sha=support.OTHER_HEAD_SHA)
        request = validate_review_request(review_request_dict(verdict="GO"))
        evidence = load_evidence(scope, test)
        with self.assertRaises(PreconditionError):
            build_review_report(request, evidence)

    def test_base_drift(self):
        scope, test = evidence_pair()
        candidate = support.candidate_dict(base_sha="0" * 40)
        request = validate_review_request(review_request_dict(verdict="GO", candidate=candidate))
        evidence = load_evidence(scope, test)
        with self.assertRaises(PreconditionError):
            build_review_report(request, evidence)

    def test_body_hash_drift(self):
        scope, test = evidence_pair()
        candidate = support.candidate_dict(issue_body_sha256="0" * 64)
        request = validate_review_request(review_request_dict(verdict="GO", candidate=candidate))
        evidence = load_evidence(scope, test)
        with self.assertRaises(PreconditionError):
            build_review_report(request, evidence)

    def test_issue_drift(self):
        scope, test = evidence_pair()
        candidate = support.candidate_dict(issue_number=999)
        request = validate_review_request(review_request_dict(verdict="GO", candidate=candidate))
        evidence = load_evidence(scope, test)
        with self.assertRaises(PreconditionError):
            build_review_report(request, evidence)

    def test_issue_body_file_mismatch_via_cli(self):
        scope, test = evidence_pair()
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            body = support.write_bytes(tmp / "body.txt", b"the wrong body")
            code, output = support.run_review(tmp, request=review_request_dict(verdict="GO"),
                                              scope_bytes=scope, test_bytes=test,
                                              extra_args=["--issue-body-file", str(body)])
        self.assertEqual(code, EXIT_ERROR)

    def test_issue_body_file_match_via_cli(self):
        scope, test = evidence_pair()
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            body = support.write_bytes(tmp / "body.txt", support.ISSUE_BODY)
            code, output = support.run_review(tmp, request=review_request_dict(verdict="GO"),
                                              scope_bytes=scope, test_bytes=test,
                                              extra_args=["--issue-body-file", str(body)])
        self.assertEqual(code, EXIT_PASS)


if __name__ == "__main__":
    unittest.main()
