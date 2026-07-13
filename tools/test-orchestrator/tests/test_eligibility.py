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

    def test_cli_eligibility_exit_codes(self):
        report_path = self.workdir / "test-report.json"
        scope_path = self.workdir / "scope-report.json"
        scope_path.write_text(json.dumps(scope_report()), encoding="utf-8")

        report_path.write_text(json.dumps(test_report()), encoding="utf-8")
        code, _ = self.invoke(
            ["eligibility", "--test-report", str(report_path),
             "--scope-report", str(scope_path), "--head-sha", HEAD]
        )
        self.assertEqual(0, code)

        report_path.write_text(json.dumps(test_report(verdict="FAIL")), encoding="utf-8")
        code, _ = self.invoke(
            ["eligibility", "--test-report", str(report_path),
             "--scope-report", str(scope_path), "--head-sha", HEAD]
        )
        self.assertEqual(2, code)

        code, _ = self.invoke(
            ["eligibility", "--test-report", str(report_path),
             "--scope-report", str(scope_path), "--head-sha", OTHER]
        )
        self.assertEqual(2, code)


if __name__ == "__main__":
    import unittest

    unittest.main()
