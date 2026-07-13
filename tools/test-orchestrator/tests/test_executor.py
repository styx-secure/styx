"""Executor behaviour: validation, classification, isolation, invalidation."""

from __future__ import annotations

import json
import os
from unittest import mock

import support
from support import FAKE_TOKEN, MiniSchemaValidator, OrchestratorCase, load_schema


class ExecutorPassTest(OrchestratorCase):
    def test_passing_plan_produces_pass_report(self):
        fixture = self.fixture()
        plan_path, plan = self.build_plan(fixture)
        code, report = self.execute_plan(fixture, plan_path)
        self.assertEqual(0, code)
        self.assertEqual("PASS", report["verdict"])
        self.assertEqual("PASS", report["mandatory_verdict"])
        self.assertEqual("PASS", report["regression_verdict"])
        self.assertEqual("PASS", report["adversarial_verdict"])
        self.assertEqual("PASS", report["static_verdict"])
        self.assertEqual("PASS", report["rollback_verdict"])
        self.assertEqual("NOT_RUN", report["generated_verdict"])
        self.assertEqual([], report["failures"])
        self.assertEqual(fixture.head_sha, report["head_sha"])
        self.assertEqual(support.sha256_hex(plan_path.read_bytes()), report["plan_sha256"])
        MiniSchemaValidator(load_schema(support.REPORT_SCHEMA)).validate(report)

    def test_generated_check_runs_isolated_from_the_worktree(self):
        fixture = self.fixture()
        proposals = [
            {"purpose": "compile in isolation",
             "command": ["python3", "-m", "py_compile", "tools/sample/newfile.py"]},
        ]
        plan_path, _ = self.build_plan(fixture, proposals=proposals)
        code, report = self.execute_plan(fixture, plan_path)
        self.assertEqual(0, code)
        self.assertEqual("PASS", report["generated_verdict"])
        self.assertEqual("", fixture.repo.status())
        self.assertFalse((fixture.repo.root / "tools/sample/__pycache__").exists())


class ExecutorClassificationTest(OrchestratorCase):
    def test_failing_mandatory_test_is_fail_and_output_stays_bounded(self):
        fixture = self.fixture(failing_mandatory=True)
        plan_path, _ = self.build_plan(fixture)
        code, report = self.execute_plan(fixture, plan_path)
        self.assertEqual(2, code)
        self.assertEqual("FAIL", report["verdict"])
        self.assertEqual("FAIL", report["mandatory_verdict"])
        failures = [item for item in report["failures"] if item["category"] == "MANDATORY"]
        self.assertEqual(1, len(failures))
        failure = failures[0]
        self.assertEqual("nonzero_exit", failure["observed_class"])
        self.assertEqual("FAIL", failure["verdict"])
        self.assertEqual("PASS", failure["expected_outcome"])
        MiniSchemaValidator(load_schema(support.FAILURE_SCHEMA)).validate(failure)
        report_bytes = json.dumps(report)
        self.assertNotIn("ghp_" + FAKE_TOKEN, report_bytes)
        self.assertNotIn("leaked credential", report_bytes)

    def test_timeout_is_error_and_never_pass(self):
        fixture = self.fixture()
        proposals = [
            {"purpose": "slow suite must be stopped",
             "command": ["python3", "-m", "unittest", "discover", "-s", "tools/sample/slow",
                          "-p", "test_*.py"],
             "timeout_seconds": 1},
        ]
        plan_path, _ = self.build_plan(fixture, proposals=proposals)
        code, report = self.execute_plan(fixture, plan_path)
        self.assertEqual(3, code)
        self.assertEqual("ERROR", report["verdict"])
        self.assertEqual("ERROR", report["generated_verdict"])
        observed = {item["observed_class"] for item in report["failures"]}
        self.assertEqual({"timeout"}, observed)

    def test_output_limit_is_error_with_truncated_hashes(self):
        fixture = self.fixture()
        proposals = [
            {"purpose": "noisy suite must be bounded",
             "command": ["python3", "-m", "unittest", "discover", "-s", "tools/sample/noisy",
                          "-p", "test_*.py"],
             "max_output_bytes": 64},
        ]
        plan_path, _ = self.build_plan(fixture, proposals=proposals)
        code, report = self.execute_plan(fixture, plan_path)
        self.assertEqual(3, code)
        failures = [item for item in report["failures"] if item["category"] == "GENERATED"]
        self.assertEqual(1, len(failures))
        self.assertEqual("output_limit_exceeded", failures[0]["observed_class"])
        self.assertTrue(failures[0]["output_truncated"])
        self.assertGreater(failures[0]["stdout_bytes"] + failures[0]["stderr_bytes"], 64)

    def test_missing_tool_is_error(self):
        fixture = self.fixture()
        environment = support.executor.ExecutionEnvironment(fixture.repo.root, fixture.head_sha)
        self.addCleanup(environment.cleanup)
        check = {
            "command": ["python3", "-m", "json.tool", "docs/governance/schemas/sample.schema.json"],
            "discard_stdout": False,
            "timeout_seconds": 5,
            "max_output_bytes": 1024,
            "isolation": "worktree",
        }
        empty = self.workdir / "empty-path"
        empty.mkdir()
        with mock.patch.dict(os.environ, {"PATH": str(empty)}):
            outcome = support.executor.run_check(check, environment)
        self.assertEqual("ERROR", outcome["verdict"])
        self.assertEqual("missing_tool", outcome["observed_class"])


class ExecutorPlanValidationTest(OrchestratorCase):
    def tampered(self, fixture, mutate) -> tuple[int, str]:
        plan_path, plan = self.build_plan(fixture)
        mutate(plan)
        self.rewrite_plan(plan_path, plan)
        report_path = self.workdir / "report.json"
        code, stderr = self.invoke(fixture.execute_args(plan_path, report_path))
        self.assertFalse(report_path.exists())
        return code, stderr

    def test_unknown_field_is_rejected(self):
        fixture = self.fixture()
        code, stderr = self.tampered(fixture, lambda plan: plan.update({"note": "extra"}))
        self.assertEqual(3, code)
        self.assertIn("unknown fields", stderr)

    def test_duplicate_keys_are_rejected(self):
        fixture = self.fixture()
        plan_path, _ = self.build_plan(fixture)
        raw = plan_path.read_text(encoding="utf-8")
        tampered = raw.replace('"schema":', '"schema":"styx.test-plan/v1","schema":', 1)
        plan_path.write_text(tampered, encoding="utf-8")
        code, stderr = self.invoke(fixture.execute_args(plan_path, self.workdir / "report.json"))
        self.assertEqual(3, code)
        self.assertIn("duplicate JSON key", stderr)

    def test_non_canonical_plan_is_rejected(self):
        fixture = self.fixture()
        plan_path, plan = self.build_plan(fixture)
        plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
        code, stderr = self.invoke(fixture.execute_args(plan_path, self.workdir / "report.json"))
        self.assertEqual(3, code)
        self.assertIn("canonical", stderr)

    def test_tampered_check_identifier_is_rejected(self):
        fixture = self.fixture()

        def mutate(plan):
            plan["checks"][0]["id"] = "0" * 64

        code, stderr = self.tampered(fixture, mutate)
        self.assertEqual(3, code)
        self.assertIn("identifier", stderr)

    def test_unsafe_command_is_rejected_even_with_valid_identifier(self):
        fixture = self.fixture()

        def mutate(plan):
            check = plan["checks"][0]
            check["command"] = ["curl", "https://evil.example"]
            check["id"] = support.executor._check_identifier(check)

        code, stderr = self.tampered(fixture, mutate)
        self.assertEqual(3, code)
        self.assertIn("command policy", stderr)

    def test_plan_without_mandatory_checks_is_rejected(self):
        fixture = self.fixture()

        def mutate(plan):
            plan["checks"] = [
                check for check in plan["checks"] if check["execution_class"] != "MANDATORY"
            ]

        code, stderr = self.tampered(fixture, mutate)
        self.assertEqual(3, code)
        self.assertIn("MANDATORY", stderr)


class ExecutorInvalidationTest(OrchestratorCase):
    def assert_invalidated(self, fixture, plan_path) -> dict:
        report_path = self.workdir / "report.json"
        code, _ = self.invoke(fixture.execute_args(plan_path, report_path))
        self.assertEqual(3, code)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual("ERROR", report["verdict"])
        self.assertEqual("NOT_RUN", report["mandatory_verdict"])
        observed = {item["observed_class"] for item in report["failures"]}
        self.assertEqual({"plan_invalidated"}, observed)
        MiniSchemaValidator(load_schema(support.REPORT_SCHEMA)).validate(report)
        return report

    def test_new_commit_invalidates_the_plan(self):
        fixture = self.fixture()
        plan_path, _ = self.build_plan(fixture)
        fixture.repo.write("tools/sample/later.py", "LATER = 1\n")
        fixture.repo.commit("later")
        self.assert_invalidated(fixture, plan_path)

    def test_dirty_worktree_invalidates_the_plan(self):
        fixture = self.fixture()
        plan_path, _ = self.build_plan(fixture)
        fixture.repo.write("tools/sample/dirty.txt", "dirty\n")
        self.assert_invalidated(fixture, plan_path)

    def test_changed_issue_body_invalidates_the_plan(self):
        fixture = self.fixture()
        plan_path, _ = self.build_plan(fixture)
        fixture.issue_body.write_text(
            fixture.issue_body.read_text(encoding="utf-8") + "\nEdited.\n", encoding="utf-8"
        )
        self.assert_invalidated(fixture, plan_path)

    def test_changed_scope_report_invalidates_the_plan(self):
        fixture = self.fixture()
        plan_path, _ = self.build_plan(fixture)
        document = json.loads(fixture.scope_report_path.read_text(encoding="utf-8"))
        document["execution_id"] = "different-execution"
        fixture.scope_report_path.write_bytes(support.model.canonical_json_bytes(document))
        self.assert_invalidated(fixture, plan_path)


if __name__ == "__main__":
    import unittest

    unittest.main()
