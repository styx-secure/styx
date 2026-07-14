"""Executor behaviour: validation, classification, isolation, invalidation."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import tarfile
import unittest
from unittest import mock

import support
from support import FAKE_TOKEN, Fixture, MiniSchemaValidator, OrchestratorCase, load_schema

NETWORK_PROBE_TEST_TEMPLATE = """import socket
import unittest


class NetworkDenialTest(unittest.TestCase):
    def test_host_loopback_listener_is_unreachable(self):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.settimeout(2)
            with self.assertRaises(OSError):
                client.connect(("127.0.0.1", {port}))
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
"""


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


class ExecutorOutputBoundingTest(OrchestratorCase):
    def test_unbounded_output_stream_is_killed_and_classified(self):
        fixture = self.fixture()
        proposals = [
            {"purpose": "endless output must be stopped at the cap",
             "command": ["python3", "-m", "unittest", "discover", "-s", "tools/sample/infinite",
                          "-p", "test_*.py"],
             "timeout_seconds": 60,
             "max_output_bytes": 4096},
        ]
        plan_path, _ = self.build_plan(fixture, proposals=proposals)
        code, report = self.execute_plan(fixture, plan_path)
        self.assertEqual(3, code)
        self.assertEqual("ERROR", report["generated_verdict"])
        failures = [item for item in report["failures"] if item["category"] == "GENERATED"]
        self.assertEqual(1, len(failures))
        self.assertEqual("output_limit_exceeded", failures[0]["observed_class"])
        self.assertTrue(failures[0]["output_truncated"])
        self.assertGreater(failures[0]["stdout_bytes"], 4096)

    def test_child_process_that_keeps_writing_is_killed(self):
        fixture = self.fixture()
        proposals = [
            {"purpose": "a lingering child writer must be terminated with the group",
             "command": ["python3", "-m", "unittest", "discover", "-s", "tools/sample/childwriter",
                          "-p", "test_*.py"],
             "timeout_seconds": 60,
             "max_output_bytes": 4096},
        ]
        plan_path, _ = self.build_plan(fixture, proposals=proposals)
        code, report = self.execute_plan(fixture, plan_path)
        self.assertEqual(3, code)
        failures = [item for item in report["failures"] if item["category"] == "GENERATED"]
        self.assertEqual(1, len(failures))
        self.assertEqual("output_limit_exceeded", failures[0]["observed_class"])
        self.assertTrue(failures[0]["output_truncated"])


class SandboxFailClosedTest(OrchestratorCase):
    def assert_sandbox_blocked(self, fixture, plan_path) -> dict:
        report_path = self.workdir / "report.json"
        code, _ = self.invoke(fixture.execute_args(plan_path, report_path))
        self.assertEqual(3, code)
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual("ERROR", report["verdict"])
        for name in ("mandatory", "regression", "generated", "adversarial", "static", "rollback"):
            self.assertEqual("NOT_RUN", report[f"{name}_verdict"])
        observed = {item["observed_class"] for item in report["failures"]}
        self.assertEqual({"sandbox_unavailable"}, observed)
        MiniSchemaValidator(load_schema(support.REPORT_SCHEMA)).validate(report)
        return report

    def test_missing_bwrap_runs_no_check_and_reports_error(self):
        fixture = self.fixture()
        plan_path, _ = self.build_plan(fixture)
        self.use_missing_bwrap()
        self.assert_sandbox_blocked(fixture, plan_path)

    def test_broken_bwrap_runs_no_check_and_reports_error(self):
        fixture = self.fixture()
        plan_path, _ = self.build_plan(fixture)
        self.use_broken_bwrap()
        self.assert_sandbox_blocked(fixture, plan_path)

    def test_non_startable_bwrap_fails_the_probe_closed(self):
        stub = self._write_sandbox_stub("non-executable-bwrap", "#!/bin/sh\nexit 0\n")
        stub.chmod(0o644)
        support.executor.locate_bwrap = lambda: str(stub)
        environment = support.executor.ExecutionEnvironment(self.workdir, "0" * 40)
        self.addCleanup(environment.cleanup)
        with self.assertRaises(support.model.SandboxError):
            environment.ensure_sandbox()

    def test_run_check_never_executes_without_a_sandbox(self):
        fixture = self.fixture()
        self.use_missing_bwrap()
        environment = support.executor.ExecutionEnvironment(fixture.repo.root, fixture.head_sha)
        self.addCleanup(environment.cleanup)
        check = {
            "command": ["python3", "-m", "json.tool", "docs/governance/schemas/sample.schema.json"],
            "discard_stdout": False,
            "timeout_seconds": 5,
            "max_output_bytes": 1024,
            "isolation": "worktree",
        }
        outcome = support.executor.run_check(check, environment)
        self.assertEqual("ERROR", outcome["verdict"])
        self.assertEqual("sandbox_unavailable", outcome["observed_class"])


class GeneratedPreparationFailureTest(OrchestratorCase):
    ARCHIVE_CHECK = {
        "command": ["python3", "-m", "py_compile", "tools/sample/newfile.py"],
        "discard_stdout": False,
        "timeout_seconds": 5,
        "max_output_bytes": 1024,
        "isolation": "archive",
    }

    def test_git_archive_failure_is_a_structured_error_and_is_not_retried(self):
        fixture = self.fixture()
        environment = support.executor.ExecutionEnvironment(fixture.repo.root, "0" * 40)
        self.addCleanup(environment.cleanup)
        first = support.executor.run_check(self.ARCHIVE_CHECK, environment)
        self.assertEqual("ERROR", first["verdict"])
        self.assertEqual("preparation_error", first["observed_class"])
        with mock.patch.object(support.executor.subprocess, "run") as never_called:
            second = support.executor.run_check(self.ARCHIVE_CHECK, environment)
        self.assertEqual("preparation_error", second["observed_class"])
        never_called.assert_not_called()

    def test_tar_extraction_failure_is_a_structured_error(self):
        fixture = self.fixture()
        environment = support.executor.ExecutionEnvironment(fixture.repo.root, fixture.head_sha)
        self.addCleanup(environment.cleanup)
        with mock.patch.object(
            support.executor.tarfile, "open", side_effect=tarfile.TarError("corrupt")
        ):
            outcome = support.executor.run_check(self.ARCHIVE_CHECK, environment)
        self.assertEqual("ERROR", outcome["verdict"])
        self.assertEqual("preparation_error", outcome["observed_class"])

    def test_archive_timeout_is_a_structured_error(self):
        fixture = self.fixture()
        environment = support.executor.ExecutionEnvironment(fixture.repo.root, fixture.head_sha)
        self.addCleanup(environment.cleanup)
        with mock.patch.object(
            support.executor.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired(cmd="git", timeout=1),
        ):
            with self.assertRaises(support.model.RepositoryStateError):
                environment.archive_workdir()

    def test_preparation_failure_blocks_generated_tests_and_reports_error(self):
        fixture = self.fixture()
        proposals = [
            {"purpose": "first generated check",
             "command": ["python3", "-m", "py_compile", "tools/sample/newfile.py"]},
            {"purpose": "second generated check",
             "command": ["python3", "-m", "compileall", "tools/sample"]},
        ]
        plan_path, _ = self.build_plan(fixture, proposals=proposals)
        with mock.patch.object(
            support.executor.ExecutionEnvironment,
            "archive_workdir",
            side_effect=support.model.RepositoryStateError("preparation failed"),
        ):
            code, report = self.execute_plan(fixture, plan_path)
        self.assertEqual(3, code)
        self.assertEqual("ERROR", report["verdict"])
        self.assertEqual("ERROR", report["generated_verdict"])
        generated = [item for item in report["failures"] if item["category"] == "GENERATED"]
        self.assertEqual(2, len(generated))
        self.assertEqual({"preparation_error"}, {item["observed_class"] for item in generated})
        for entry in generated:
            MiniSchemaValidator(load_schema(support.FAILURE_SCHEMA)).validate(entry)
        MiniSchemaValidator(load_schema(support.REPORT_SCHEMA)).validate(report)


class GitDiffHardeningTest(OrchestratorCase):
    def test_hardened_command_injects_read_only_diff_flags(self):
        sha_a, sha_b = "a" * 40, "b" * 40
        hardened = support.executor.hardened_command(["git", "diff", "--check", sha_a, sha_b])
        self.assertEqual(
            ["git", "-c", "diff.external=", "diff", "--no-ext-diff", "--no-textconv",
             "--check", sha_a, sha_b],
            hardened,
        )
        untouched = ["git", "cat-file", "-e", f"{sha_a}^{{commit}}"]
        self.assertEqual(untouched, support.executor.hardened_command(untouched))
        python_command = ["python3", "-m", "unittest"]
        self.assertEqual(python_command, support.executor.hardened_command(python_command))

    def test_local_diff_external_sentinel_is_never_executed(self):
        fixture = self.fixture()
        marker = self.workdir / "external-diff-executed"
        sentinel = self.workdir / "sentinel-diff.sh"
        sentinel.write_text(f"#!/bin/sh\ntouch {marker}\nexit 0\n", encoding="utf-8")
        sentinel.chmod(0o755)
        support.run(
            ["git", "config", "diff.external", str(sentinel)], fixture.repo.root
        )
        plan_path, plan = self.build_plan(fixture)
        self.assertTrue(
            any(check["command"][:2] == ["git", "diff"] for check in plan["checks"])
        )
        code, report = self.execute_plan(fixture, plan_path)
        self.assertEqual(0, code)
        self.assertEqual("PASS", report["verdict"])
        self.assertFalse(marker.exists())


@unittest.skipUnless(support.real_bwrap_usable(), "real bubblewrap is unavailable on this host")
class RealSandboxIntegrationTest(OrchestratorCase):
    def test_real_bwrap_denies_network_and_runs_the_pipeline(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(listener.close)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        # The listener must be reachable from the host, otherwise the
        # in-sandbox failure would not demonstrate isolation.
        probe = socket.create_connection(("127.0.0.1", port), timeout=2)
        probe.close()

        fixture = Fixture(
            self.workdir / "real-sandbox",
            extra_files={
                "tools/sample/netprobe/test_netprobe.py":
                    NETWORK_PROBE_TEST_TEMPLATE.format(port=port),
            },
        )
        self.use_real_bwrap()
        proposals = [
            {"purpose": "the host loopback listener must be unreachable inside the sandbox",
             "command": ["python3", "-m", "unittest", "discover", "-s", "tools/sample/netprobe",
                          "-p", "test_*.py"]},
        ]
        plan_path, _ = self.build_plan(fixture, proposals=proposals)
        code, report = self.execute_plan(fixture, plan_path)
        self.assertEqual(0, code)
        self.assertEqual("PASS", report["verdict"])
        self.assertEqual("PASS", report["generated_verdict"])
        self.assertEqual("PASS", report["mandatory_verdict"])


class RuntimePathContainmentTest(OrchestratorCase):
    def run_crafted_check(self, fixture, command: list[str]) -> dict:
        environment = support.executor.ExecutionEnvironment(fixture.repo.root, fixture.head_sha)
        self.addCleanup(environment.cleanup)
        check = {
            "command": command,
            "discard_stdout": False,
            "timeout_seconds": 5,
            "max_output_bytes": 1024,
            "isolation": "worktree",
        }
        return support.executor.run_check(check, environment)

    def test_symlink_escape_is_rejected_before_execution(self):
        fixture = self.fixture()
        outside = self.workdir / "outside.py"
        outside.write_text("VALUE = 2\n", encoding="utf-8")
        link = fixture.repo.root / "tools" / "sample" / "escape_link.py"
        link.symlink_to(outside)
        outcome = self.run_crafted_check(
            fixture, ["python3", "-m", "py_compile", "tools/sample/escape_link.py"]
        )
        self.assertEqual("ERROR", outcome["verdict"])
        self.assertEqual("rejected_command", outcome["observed_class"])

    def test_relative_traversal_is_rejected_before_execution(self):
        fixture = self.fixture()
        outcome = self.run_crafted_check(
            fixture, ["python3", "-m", "py_compile", "../../outside.py"]
        )
        self.assertEqual("ERROR", outcome["verdict"])
        self.assertEqual("rejected_command", outcome["observed_class"])


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

    def test_tampered_policy_hash_invalidates_the_plan(self):
        fixture = self.fixture()
        plan_path, plan = self.build_plan(fixture)
        plan["command_policy_sha256"] = "0" * 64
        self.rewrite_plan(plan_path, plan)
        self.assert_invalidated(fixture, plan_path)

    def test_changed_command_policy_invalidates_the_plan(self):
        fixture = self.fixture()
        plan_path, _ = self.build_plan(fixture)
        with mock.patch.object(support.executor, "command_policy_sha256", return_value="f" * 64):
            self.assert_invalidated(fixture, plan_path)

    def test_non_pass_scope_report_can_never_yield_a_pass_report(self):
        for verdict in ("FAIL", "ERROR"):
            with self.subTest(verdict=verdict):
                fixture = Fixture(self.workdir / f"scope-{verdict.lower()}")
                plan_path, plan = self.build_plan(fixture)
                document = json.loads(fixture.scope_report_path.read_text(encoding="utf-8"))
                document["verdict"] = verdict
                raw = support.model.canonical_json_bytes(document)
                fixture.scope_report_path.write_bytes(raw)
                plan["scope_report_sha256"] = support.sha256_hex(raw)
                self.rewrite_plan(plan_path, plan)
                report = self.assert_invalidated(fixture, plan_path)
                self.assertNotEqual("PASS", report["verdict"])


class FailureSanitizationTest(OrchestratorCase):
    def test_reproduction_command_in_failure_report_is_redacted(self):
        fixture = self.fixture()
        secret = "hunter2-super-secret"
        proposals = [
            {"purpose": "failing check whose argv carries secret material",
             "command": ["python3", "-m", "py_compile", f"token={secret}", "missing_file.py"]},
        ]
        plan_path, _ = self.build_plan(fixture, proposals=proposals)
        code, report = self.execute_plan(fixture, plan_path)
        self.assertEqual(2, code)
        failures = [item for item in report["failures"] if item["category"] == "GENERATED"]
        self.assertEqual(1, len(failures))
        command = failures[0]["reproduction"]["command"]
        self.assertIn("token=[REDACTED]", command)
        self.assertNotIn(f"token={secret}", command)
        self.assertNotIn(secret, json.dumps(report))


if __name__ == "__main__":
    import unittest

    unittest.main()
