"""Structured remediation and multi-round binding."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import support
from support import evidence_pair, finding_dict, review_request_dict

from evidence import load_evidence
from model import EXIT_ERROR, EXIT_PASS, ReviewInputError, sha256_hex
from remediation import build_remediation_request, remediation_request_bytes
from review import build_review_report, review_report_bytes, validate_review_request


def _changes_report_bytes(findings=None):
    scope, test = evidence_pair()
    if findings is None:
        findings = [finding_dict(severity="HIGH", lifecycle="OPEN", required_fix=True)]
    request = validate_review_request(review_request_dict(verdict="CHANGES_REQUESTED", findings=findings))
    evidence = load_evidence(scope, test)
    report = build_review_report(request, evidence)
    return review_report_bytes(report)


class RemediationTest(unittest.TestCase):
    def test_items_derived_from_open_findings(self):
        report_bytes = _changes_report_bytes(findings=[
            finding_dict(severity="HIGH", lifecycle="OPEN", required_fix=True, problem="A"),
            finding_dict(severity="MEDIUM", lifecycle="RESOLVED", problem="B"),
        ])
        request = build_remediation_request(report_bytes, 1)
        self.assertEqual(len(request["items"]), 1)
        self.assertEqual(request["remediation_round_id"], 1)

    def test_items_bound_to_review_report_hash(self):
        report_bytes = _changes_report_bytes()
        request = build_remediation_request(report_bytes, 1)
        expected = sha256_hex(report_bytes)
        self.assertEqual(request["review_report_sha256"], expected)
        for item in request["items"]:
            self.assertEqual(item["review_report_sha256"], expected)
            self.assertEqual(item["remediation_round_id"], 1)

    def test_exact_head_binding_carried(self):
        report_bytes = _changes_report_bytes()
        request = build_remediation_request(report_bytes, 1)
        self.assertEqual(request["head_sha"], support.HEAD_SHA)
        self.assertEqual(request["base_sha"], support.BASE_SHA)
        self.assertEqual(request["diff_sha256"], support.DIFF_SHA256)
        self.assertEqual(request["issue_body_sha256"], support.ISSUE_BODY_SHA256)

    def test_required_fields_present(self):
        from remediation import REMEDIATION_ITEM_FIELDS, REMEDIATION_REQUEST_FIELDS
        request = build_remediation_request(_changes_report_bytes(), 1)
        self.assertEqual(set(request), set(REMEDIATION_REQUEST_FIELDS))
        for item in request["items"]:
            self.assertEqual(set(item), set(REMEDIATION_ITEM_FIELDS))

    def test_multi_round_same_finding_new_round(self):
        report_bytes = _changes_report_bytes()
        round1 = build_remediation_request(report_bytes, 1)
        round2 = build_remediation_request(report_bytes, 2)
        self.assertEqual(round1["items"][0]["finding_id"], round2["items"][0]["finding_id"])
        self.assertNotEqual(round1["remediation_round_id"], round2["remediation_round_id"])

    def test_remediation_from_go_rejected(self):
        scope, test = evidence_pair()
        request = validate_review_request(review_request_dict(verdict="GO"))
        evidence = load_evidence(scope, test)
        report_bytes = review_report_bytes(build_review_report(request, evidence))
        with self.assertRaises(ReviewInputError):
            build_remediation_request(report_bytes, 1)

    def test_remediation_no_open_finding_rejected(self):
        report_bytes = _changes_report_bytes(findings=[
            finding_dict(severity="HIGH", lifecycle="OPEN", required_fix=True),
        ])
        # Now craft a BLOCKED report whose findings are all resolved -> none open.
        scope, test = evidence_pair()
        request = validate_review_request(review_request_dict(
            verdict="GO",
            findings=[finding_dict(severity="LOW", lifecycle="RESOLVED")],
        ))
        evidence = load_evidence(scope, test)
        report = build_review_report(request, evidence)
        with self.assertRaises(ReviewInputError):
            build_remediation_request(review_report_bytes(report), 1)

    def test_bad_round_rejected(self):
        with self.assertRaises(ReviewInputError):
            build_remediation_request(_changes_report_bytes(), 0)

    def test_addressed_pending_reverify_is_remediated(self):
        report_bytes = _changes_report_bytes(findings=[
            finding_dict(severity="HIGH", lifecycle="ADDRESSED_PENDING_REVERIFY", required_fix=True),
        ])
        request = build_remediation_request(report_bytes, 3)
        self.assertEqual(len(request["items"]), 1)
        self.assertEqual(request["items"][0]["lifecycle"], "ADDRESSED_PENDING_REVERIFY")

    def test_cli_remediate_roundtrip(self):
        report_bytes = _changes_report_bytes()
        with tempfile.TemporaryDirectory() as raw:
            code, output = support.run_remediate(Path(raw), review_report_bytes=report_bytes, round_id=1)
            self.assertEqual(code, EXIT_PASS)
            self.assertTrue(output.exists())


if __name__ == "__main__":
    unittest.main()
