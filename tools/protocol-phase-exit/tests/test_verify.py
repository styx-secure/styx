from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tools/protocol-phase-exit/verify.py"
SPEC = importlib.util.spec_from_file_location("phase_exit_verify", MODULE_PATH)
verify = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)


class VerifyTests(unittest.TestCase):
    def test_first_parent_identity_is_exact(self):
        commits = verify.first_parent_commits(ROOT)
        self.assertEqual(24, len(commits))
        self.assertEqual(verify.FREEZE_SHA, commits[0])
        self.assertEqual(verify.BASE_SHA, commits[-1])

    def test_base_pins_and_frozen_manifest(self):
        verify.verify_base_pins(ROOT)
        digest, mapping = verify.frozen_manifest(ROOT)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertGreater(len(mapping), 100)

    def test_registry_is_closed(self):
        registry = verify.load_registry(ROOT)
        self.assertEqual([f"EXIT-{index:02d}" for index in range(1, 12)], [item["id"] for item in registry["conditions"]])
        registered = {
            evidence_id
            for item in registry["conditions"]
            for evidence_id in item["required_evidence_ids"]
        }
        self.assertEqual(set(verify.EVIDENCE_PATHS) | {"frozen_manifest", "first_parent_audit"}, registered)

    def test_report_is_bounded_and_deterministic(self):
        first = verify.canonical_bytes(verify.build_report(ROOT))
        second = verify.canonical_bytes(verify.build_report(ROOT))
        self.assertEqual(first, second)
        report = json.loads(first)
        self.assertEqual("ELIGIBLE_FOR_BOUNDED_GO", report["eligibility"])
        self.assertEqual("HUMAN_GATE_PENDING", report["conditions"][7]["disposition"])
        self.assertEqual("HUMAN_GATE_PENDING", report["conditions"][8]["disposition"])
        self.assertIn("adapter", report["non_authorizations"])
        self.assertEqual(verify.MINIMUM_CONDITIONAL_STATEMENTS, report["conditional_exclusions"])
        self.assertEqual(3, len(report["conditions"][0]["excluded_claims"]))

    def test_fail_dominates_eligibility(self):
        self.assertEqual("REQUIRES_NO_GO", verify.mechanical_eligibility(["PASS", "FAIL"]))
        self.assertEqual("ELIGIBLE_FOR_BOUNDED_GO", verify.mechanical_eligibility(["PASS", "CONDITIONAL_EXCLUSION"]))
        self.assertEqual("ELIGIBLE_FOR_GO", verify.mechanical_eligibility(["PASS"]))

    def test_digest_substitution_and_duplicate_evidence_fail_closed(self):
        registry = verify.load_registry(ROOT)
        record = copy.deepcopy(registry["conditions"][2])
        observed = dict(record["expected_evidence_sha256"])
        observed["protocol_plan"] = "0" * 64
        with self.assertRaises(verify.ExitError):
            verify.disposition_for(record, observed)
        record["required_evidence_ids"].append(record["required_evidence_ids"][0])
        with self.assertRaises(verify.ExitError):
            verify.validate_evidence_declaration(record)

    def test_missing_registered_input_fails_closed(self):
        with mock.patch.dict(verify.EVIDENCE_PATHS, {"missing_fixture": ("not/present",)}):
            with self.assertRaises(verify.ExitError):
                verify.evidence_digest(ROOT, "missing_fixture", "0" * 64, "1" * 64)

    def test_committed_report_substitution_fails_closed(self):
        report = {"schema": "test", "eligibility": "ELIGIBLE_FOR_BOUNDED_GO"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / verify.CANONICAL_REPORT_PATH
            path.parent.mkdir(parents=True)
            path.write_bytes(verify.canonical_bytes(report))
            verify.verify_committed_report(root, report)
            path.write_text('{"eligibility":"ELIGIBLE_FOR_GO"}\n', encoding="utf-8")
            with self.assertRaises(verify.ExitError):
                verify.verify_committed_report(root, report)

    def test_report_hygiene_and_scope_are_fail_closed(self):
        verify.validate_report_strings({"value": "docs/protocol/root-authority.md"}, {"deadbeef"})
        for value in ("/tmp/leak", "path=C:\\review", "2026-08-31T12:00", "candidate-deadbeef"):
            with self.subTest(value=value), self.assertRaises(verify.ExitError):
                verify.validate_report_strings({"value": value}, {"deadbeef"})
        self.assertTrue(verify.is_allowed_changed_path("tools/protocol-phase-exit/verify.py"))
        self.assertFalse(verify.is_allowed_changed_path("tools/causal-flow-simulator/ss0/model.py"))

    def test_unknown_evidence_fails_closed(self):
        with self.assertRaises(verify.ExitError):
            verify.evidence_digest(ROOT, "unknown", "0" * 64, "1" * 64)

    def test_verdict_monotonicity(self):
        self.assertTrue(verify.monotone_verdict("ELIGIBLE_FOR_GO", "GO"))
        self.assertTrue(verify.monotone_verdict("ELIGIBLE_FOR_GO", "BOUNDED_GO"))
        self.assertTrue(verify.monotone_verdict("ELIGIBLE_FOR_BOUNDED_GO", "BOUNDED_GO"))
        self.assertFalse(verify.monotone_verdict("ELIGIBLE_FOR_BOUNDED_GO", "GO"))
        self.assertFalse(verify.monotone_verdict("REQUIRES_NO_GO", "BOUNDED_GO"))
        self.assertTrue(verify.monotone_verdict("REQUIRES_NO_GO", "NO_GO"))

    def test_verdict_provider_identity_and_payload(self):
        comment_id = "5476501347"
        url = verify.verdict_url(comment_id)
        payload = {
            "schema": "styx-protocol-phase-exit-verdict/v1",
            "issue_number": 287,
            "issue_body_sha256": verify.ISSUE_BODY_SHA256,
            "operator": "maverde73",
            "base_sha": verify.BASE_SHA,
            "phase_a_head": "a" * 40,
            "phase_exit_report_sha256": "b" * 64,
            "frozen_manifest_sha256": "c" * 64,
            "first_parent_audit_sha256": "d" * 64,
            "mechanical_eligibility": "ELIGIBLE_FOR_BOUNDED_GO",
            "verdict": "BOUNDED_GO",
        }
        comment = {
            "id": int(comment_id), "url": url, "issue_url": verify.ISSUE_API_URL,
            "user": {"id": verify.MAVERDE_ID, "login": "maverde73"},
            "created_at": "2026-08-31T12:00:00Z", "updated_at": "2026-08-31T12:00:00Z",
            "body": json.dumps(payload, sort_keys=True, separators=(",", ":")),
        }
        result = verify.validate_verdict_comment(
            comment, comment_id=comment_id, phase_a_head="a" * 40,
            report_sha="b" * 64, frozen_sha="c" * 64, audit_sha="d" * 64,
            eligibility="ELIGIBLE_FOR_BOUNDED_GO",
        )
        self.assertEqual("BOUNDED_GO", result["verdict"])
        hostile = copy.deepcopy(comment)
        hostile["updated_at"] = "2026-08-31T12:00:01Z"
        with self.assertRaises(verify.ExitError):
            verify.validate_verdict_comment(
                hostile, comment_id=comment_id, phase_a_head="a" * 40,
                report_sha="b" * 64, frozen_sha="c" * 64, audit_sha="d" * 64,
                eligibility="ELIGIBLE_FOR_BOUNDED_GO",
            )

    def test_approval_provider_identity_and_head(self):
        review_id = "5065807842"
        review = {
            "id": int(review_id),
            "url": verify.approval_url(review_id),
            "pull_request_url": f"https://api.github.com/repos/styx-secure/styx/pulls/{verify.PR_NUMBER}",
            "user": {"id": verify.MANEXADA_ID, "login": "manexada"},
            "state": "APPROVED",
            "commit_id": "a" * 40,
            "submitted_at": "2026-08-31T12:00:00Z",
        }
        result = verify.validate_approval_review(review, review_id=review_id, final_head="a" * 40)
        self.assertEqual("a" * 40, result["approved_head"])
        hostile = copy.deepcopy(review)
        hostile["commit_id"] = "b" * 40
        with self.assertRaises(verify.ExitError):
            verify.validate_approval_review(hostile, review_id=review_id, final_head="a" * 40)

    def test_canonical_json_has_no_insignificant_whitespace(self):
        self.assertEqual(b'{"a":2,"z":1}\n', verify.canonical_bytes({"z": 1, "a": 2}))


if __name__ == "__main__":
    unittest.main()
