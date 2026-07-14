"""The frozen review-eligibility rule and its CLI adapter."""

from __future__ import annotations

import json

import support
from support import OrchestratorCase

HEAD = "a" * 40
OTHER = "b" * 40


def test_report(**overrides) -> dict:
    document = {
        "schema": "styx.test-report/v1",
        "verdict": "PASS",
        "head_sha": HEAD,
    }
    document.update(overrides)
    return document


def scope_report(**overrides) -> dict:
    document = {
        "schema": "styx.task-scope-report/v1",
        "verdict": "PASS",
        "head_sha": HEAD,
    }
    document.update(overrides)
    return document


class EligibilityRuleTest(OrchestratorCase):
    def test_pass_on_exact_head_is_eligible(self):
        self.assertTrue(support.executor.review_eligible(test_report(), scope_report(), HEAD))

    def test_any_non_pass_or_head_drift_is_ineligible(self):
        cases = [
            (test_report(verdict="FAIL"), scope_report(), HEAD),
            (test_report(verdict="ERROR"), scope_report(), HEAD),
            (test_report(head_sha=OTHER), scope_report(), HEAD),
            (test_report(), scope_report(verdict="FAIL"), HEAD),
            (test_report(), scope_report(verdict="ERROR"), HEAD),
            (test_report(), scope_report(head_sha=OTHER), HEAD),
            (test_report(), scope_report(), OTHER),
            (test_report(schema="styx.test-report/v0"), scope_report(), HEAD),
            (test_report(), scope_report(schema="styx.task-scope-report/v0"), HEAD),
        ]
        for index, (report, scope, candidate) in enumerate(cases):
            with self.subTest(case=index):
                self.assertFalse(support.executor.review_eligible(report, scope, candidate))

    def test_minimal_documents_are_no_longer_accepted_by_the_cli(self):
        report_path = self.workdir / "test-report.json"
        scope_path = self.workdir / "scope-report.json"
        report_path.write_bytes(support.model.canonical_json_bytes(test_report()))
        scope_path.write_bytes(support.model.canonical_json_bytes(scope_report()))
        code, stderr = self.invoke(
            ["eligibility", "--test-report", str(report_path),
             "--scope-report", str(scope_path), "--head-sha", HEAD]
        )
        self.assertEqual(3, code)
        self.assertIn("missing or unknown fields", stderr)


class EligibilityValidationTest(OrchestratorCase):
    """Runtime validation of the evidence pair consumed by eligibility."""

    def evidence(self, *, failing_mandatory: bool = False):
        fixture = self.fixture(failing_mandatory=failing_mandatory)
        plan_path, _ = self.build_plan(fixture)
        report_path = self.workdir / "test-report.json"
        self.invoke(fixture.execute_args(plan_path, report_path))
        return fixture, report_path

    def eligibility(self, report_path, scope_path, head_sha) -> tuple[int, str]:
        return self.invoke(
            ["eligibility", "--test-report", str(report_path),
             "--scope-report", str(scope_path), "--head-sha", head_sha]
        )

    def rewrite_report(self, report_path, mutate) -> None:
        report = json.loads(report_path.read_text(encoding="utf-8"))
        mutate(report)
        report_path.write_bytes(support.model.canonical_json_bytes(report))

    def test_valid_pass_evidence_is_eligible(self):
        fixture, report_path = self.evidence()
        code, stderr = self.eligibility(report_path, fixture.scope_report_path, fixture.head_sha)
        self.assertEqual(0, code, stderr)

    def test_head_drift_is_not_eligible(self):
        fixture, report_path = self.evidence()
        code, _ = self.eligibility(report_path, fixture.scope_report_path, fixture.base_sha)
        self.assertEqual(2, code)

    def test_fail_report_is_not_eligible(self):
        fixture, report_path = self.evidence(failing_mandatory=True)
        code, _ = self.eligibility(report_path, fixture.scope_report_path, fixture.head_sha)
        self.assertEqual(2, code)

    def test_missing_field_is_rejected(self):
        fixture, report_path = self.evidence()
        self.rewrite_report(report_path, lambda report: report.pop("verdict"))
        code, stderr = self.eligibility(report_path, fixture.scope_report_path, fixture.head_sha)
        self.assertEqual(3, code)
        self.assertIn("missing or unknown fields", stderr)

    def test_extra_field_is_rejected(self):
        fixture, report_path = self.evidence()
        self.rewrite_report(report_path, lambda report: report.update({"note": "extra"}))
        code, stderr = self.eligibility(report_path, fixture.scope_report_path, fixture.head_sha)
        self.assertEqual(3, code)
        self.assertIn("missing or unknown fields", stderr)

    def test_non_canonical_report_is_rejected(self):
        fixture, report_path = self.evidence()
        report = json.loads(report_path.read_text(encoding="utf-8"))
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        code, stderr = self.eligibility(report_path, fixture.scope_report_path, fixture.head_sha)
        self.assertEqual(3, code)
        self.assertIn("canonical", stderr)

    def test_wrong_scope_hash_is_rejected(self):
        fixture, report_path = self.evidence()
        self.rewrite_report(
            report_path, lambda report: report.update({"scope_report_sha256": "0" * 64})
        )
        code, stderr = self.eligibility(report_path, fixture.scope_report_path, fixture.head_sha)
        self.assertEqual(3, code)
        self.assertIn("does not match", stderr)

    def test_policy_hash_drift_is_rejected(self):
        fixture, report_path = self.evidence()
        self.rewrite_report(
            report_path, lambda report: report.update({"command_policy_sha256": "e" * 64})
        )
        code, stderr = self.eligibility(report_path, fixture.scope_report_path, fixture.head_sha)
        self.assertEqual(3, code)
        self.assertIn("different command policy", stderr)

    def test_malformed_failure_entry_is_rejected(self):
        fixture, report_path = self.evidence(failing_mandatory=True)
        self.rewrite_report(report_path, lambda report: report["failures"][0].pop("reproduction"))
        code, stderr = self.eligibility(report_path, fixture.scope_report_path, fixture.head_sha)
        self.assertEqual(3, code)
        self.assertIn("failure entry", stderr)

    def test_bad_verdict_type_is_rejected(self):
        fixture, report_path = self.evidence()
        self.rewrite_report(report_path, lambda report: report.update({"mandatory_verdict": True}))
        code, stderr = self.eligibility(report_path, fixture.scope_report_path, fixture.head_sha)
        self.assertEqual(3, code)
        self.assertIn("class verdict", stderr)

    def test_malformed_candidate_head_is_rejected(self):
        fixture, report_path = self.evidence()
        code, stderr = self.eligibility(report_path, fixture.scope_report_path, "HEAD")
        self.assertEqual(3, code)
        self.assertIn("candidate head", stderr)


if __name__ == "__main__":
    import unittest

    unittest.main()
