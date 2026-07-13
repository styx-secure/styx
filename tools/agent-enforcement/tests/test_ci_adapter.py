from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import urllib.error

from support import GuardIntegrationCase, ROOT, Repo, contract_body, run

import ci_adapter
from model import Diagnostic, EXIT_ERROR, EXIT_FAIL, EXIT_PASS
from report import build_report, write_report

BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40
WORKFLOW = ROOT / ".github" / "workflows" / "agent-scope-evidence.yml"


def synthetic_event(
    body: str = "Styx-Task: #48",
    *,
    base_sha: str = BASE_SHA,
    head_sha: str = HEAD_SHA,
    action: str = "opened",
    repository: str = "styx-secure/styx",
    base_repository: str = "styx-secure/styx",
    head_repository: str = "example-fork/styx",
) -> dict[str, object]:
    return {
        "action": action,
        "number": 7,
        "repository": {"full_name": repository},
        "pull_request": {
            "number": 7,
            "body": body,
            "base": {"sha": base_sha, "repo": {"full_name": base_repository}},
            "head": {"sha": head_sha, "repo": {"full_name": head_repository}},
        },
    }


class FakeResponse:
    def __init__(
        self,
        payload: bytes,
        *,
        status: int = 200,
        content_type: str = "application/json; charset=utf-8",
        content_length: str | None = None,
    ):
        self.payload = payload
        self.status = status
        self.headers = {"Content-Type": content_type}
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def read(self, limit: int = -1) -> bytes:
        return self.payload if limit < 0 else self.payload[:limit]

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class FakeOpener:
    def __init__(self, result):
        self.result = result

    def open(self, _request, timeout: int = 0):
        del timeout
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result


class CiAdapterUnitTests(unittest.TestCase):
    maxDiff = None

    def context(self) -> ci_adapter.ObservationContext:
        return ci_adapter.validate_event(
            synthetic_event(),
            repository="styx-secure/styx",
            run_id="123",
            run_attempt="2",
        )

    def test_issue_reference_is_strict_and_local(self) -> None:
        self.assertEqual(48, ci_adapter.parse_issue_reference("intro\nStyx-Task: #48\n"))
        cases = (
            ("", "E_CI_ISSUE_REFERENCE_MISSING"),
            ("Styx-Task: #48\nStyx-Task: #49", "E_CI_ISSUE_REFERENCE_AMBIGUOUS"),
            ("Styx-Task: issue-48", "E_CI_ISSUE_REFERENCE_MALFORMED"),
            ("Styx-Task: other/repo#48", "E_CI_ISSUE_REFERENCE_CROSS_REPOSITORY"),
        )
        for body, expected_code in cases:
            with self.subTest(body=body):
                with self.assertRaises(ci_adapter.CiAdapterError) as caught:
                    ci_adapter.parse_issue_reference(body)
                self.assertEqual(expected_code, caught.exception.code)

    def test_event_validation_accepts_fork_metadata_but_not_invalid_envelopes(self) -> None:
        context = self.context()
        self.assertEqual(48, context.issue_number)
        self.assertEqual(7, context.pull_number)
        self.assertIn("run-123-attempt-2", context.execution_id)
        self.assertIn(HEAD_SHA, context.artifact_name)

        cases = (
            (synthetic_event(base_sha="main"), "E_CI_EVENT_SHA"),
            (synthetic_event(action="closed"), "E_CI_EVENT_ACTION"),
            (synthetic_event(repository="other/repo"), "E_CI_EVENT_REPOSITORY"),
            (synthetic_event(base_repository="other/repo"), "E_CI_EVENT_REPOSITORY"),
            (synthetic_event(head_repository="not a repo"), "E_CI_EVENT_REPOSITORY"),
        )
        for event, expected_code in cases:
            with self.subTest(expected_code=expected_code):
                with self.assertRaises(ci_adapter.CiAdapterError) as caught:
                    ci_adapter.validate_event(
                        event,
                        repository="styx-secure/styx",
                        run_id="123",
                        run_attempt="2",
                    )
                self.assertEqual(expected_code, caught.exception.code)

    def test_issue_api_success_preserves_utf8_body_bytes(self) -> None:
        payload = json.dumps(
            {"number": 48, "state": "open", "body": "Testo UTF-8: π"},
            ensure_ascii=False,
        ).encode("utf-8")
        body = ci_adapter.fetch_issue_body(
            self.context(),
            api_url="https://api.github.com",
            token="ephemeral-token",
            opener=FakeOpener(FakeResponse(payload)),
        )
        self.assertEqual("Testo UTF-8: π".encode("utf-8"), body)

    def test_issue_api_failures_are_deterministic_errors(self) -> None:
        http_404 = urllib.error.HTTPError(
            "https://api.github.com/example",
            404,
            "not found",
            {},
            None,
        )
        http_403 = urllib.error.HTTPError(
            "https://api.github.com/example",
            403,
            "forbidden",
            {},
            None,
        )
        http_302 = urllib.error.HTTPError(
            "https://api.github.com/example",
            302,
            "redirect",
            {},
            None,
        )
        oversized = b"x" * (ci_adapter.MAX_API_RESPONSE_BYTES + 1)
        cases = (
            (FakeOpener(http_404), "E_CI_ISSUE_NOT_FOUND"),
            (FakeOpener(http_403), "E_CI_ISSUE_FORBIDDEN"),
            (FakeOpener(http_302), "E_CI_ISSUE_REDIRECT"),
            (FakeOpener(FakeResponse(b"{")), "E_CI_ISSUE_RESPONSE"),
            (
                FakeOpener(FakeResponse(json.dumps({"number": 48, "state": "open", "body": None}).encode())),
                "E_CI_ISSUE_BODY",
            ),
            (
                FakeOpener(FakeResponse(json.dumps({"number": 48, "state": "closed", "body": "x"}).encode())),
                "E_CI_ISSUE_STATE",
            ),
            (
                FakeOpener(
                    FakeResponse(
                        json.dumps({"number": 48, "state": "open", "body": "x", "pull_request": {}}).encode()
                    )
                ),
                "E_CI_ISSUE_RESPONSE",
            ),
            (FakeOpener(FakeResponse(b"{}", content_type="text/plain")), "E_CI_ISSUE_RESPONSE"),
            (FakeOpener(FakeResponse(oversized)), "E_CI_ISSUE_RESPONSE"),
        )
        for opener, expected_code in cases:
            with self.subTest(expected_code=expected_code):
                with self.assertRaises(ci_adapter.CiAdapterError) as caught:
                    ci_adapter.fetch_issue_body(
                        self.context(),
                        api_url="https://api.github.com",
                        token="ephemeral-token",
                        opener=opener,
                    )
                self.assertEqual(expected_code, caught.exception.code)

    def test_observation_preserves_pass_fail_error_exit_classes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_directory:
            root = Path(temp_directory)
            repo = root / "repo"
            runner_temp = root / "runner-temp"
            repo.mkdir()
            runner_temp.mkdir()
            event_file = root / "event.json"
            event_file.write_text(json.dumps(synthetic_event()), encoding="utf-8")

            def issue_fetcher(_context, **_kwargs):
                return b"contract"

            def head_fetcher(_context, **_kwargs):
                return None

            for verdict, expected_exit in (("PASS", 0), ("FAIL", 2), ("ERROR", 3)):
                report_path = runner_temp / f"{verdict.lower()}.json"

                def guard_runner(context, **kwargs):
                    diagnostics = () if verdict == "PASS" else (Diagnostic("E_TEST" if verdict == "ERROR" else "P_TEST", "test", "error"),)
                    report = build_report(
                        issue_number=context.issue_number,
                        execution_id=context.execution_id,
                        base_sha=context.base_sha,
                        head_sha=context.head_sha,
                        issue_body_sha256="0" * 64,
                        contract=None,
                        entries=(),
                        evaluations={},
                        diagnostics=diagnostics,
                        verdict=verdict,
                    )
                    write_report(kwargs["report_path"], report)
                    return expected_exit

                with self.subTest(verdict=verdict):
                    exit_code = ci_adapter.run_observation(
                        event_file=event_file,
                        repo=repo,
                        runner_temp=runner_temp,
                        repository="styx-secure/styx",
                        api_url="https://api.github.com",
                        server_url="https://github.com",
                        run_id="123",
                        run_attempt="1",
                        report_path=report_path,
                        token="ephemeral-token",
                        issue_fetcher=issue_fetcher,
                        head_fetcher=head_fetcher,
                        guard_runner=guard_runner,
                    )
                    self.assertEqual(expected_exit, exit_code)
                    self.assertEqual(verdict, json.loads(report_path.read_text(encoding="utf-8"))["verdict"])

    def test_missing_report_and_output_outside_runner_temp_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_directory:
            root = Path(temp_directory)
            repo = root / "repo"
            runner_temp = root / "runner-temp"
            repo.mkdir()
            runner_temp.mkdir()
            event_file = root / "event.json"
            event_file.write_text(json.dumps(synthetic_event()), encoding="utf-8")

            common = dict(
                event_file=event_file,
                repo=repo,
                runner_temp=runner_temp,
                repository="styx-secure/styx",
                api_url="https://api.github.com",
                server_url="https://github.com",
                run_id="123",
                run_attempt="1",
                token="ephemeral-token",
                issue_fetcher=lambda *_args, **_kwargs: b"contract",
                head_fetcher=lambda *_args, **_kwargs: None,
                guard_runner=lambda *_args, **_kwargs: EXIT_PASS,
            )

            missing_report = runner_temp / "missing.json"
            self.assertEqual(
                EXIT_ERROR,
                ci_adapter.run_observation(report_path=missing_report, **common),
            )
            self.assertEqual("ERROR", json.loads(missing_report.read_text(encoding="utf-8"))["verdict"])

            outside_report = root / "outside.json"
            self.assertEqual(
                EXIT_ERROR,
                ci_adapter.run_observation(report_path=outside_report, **common),
            )
            self.assertFalse(outside_report.exists())

    def test_summary_omits_untrusted_markdown_html_paths_and_messages(self) -> None:
        with tempfile.TemporaryDirectory() as temp_directory:
            root = Path(temp_directory)
            report_path = root / "report.json"
            summary_path = root / "summary.md"
            report = build_report(
                issue_number=48,
                execution_id="test",
                base_sha=BASE_SHA,
                head_sha=HEAD_SHA,
                issue_body_sha256=None,
                contract=None,
                entries=(),
                evaluations={},
                diagnostics=(
                    Diagnostic(
                        "E_TEST",
                        "<script>alert(1)</script>",
                        "error",
                        "[click](javascript:alert(1))",
                    ),
                ),
                verdict="ERROR",
            )
            write_report(report_path, report)
            self.assertEqual(EXIT_ERROR, ci_adapter.write_safe_summary(report_path, summary_path))
            summary = summary_path.read_text(encoding="utf-8")
            self.assertIn("E_TEST", summary)
            self.assertNotIn("<script>", summary)
            self.assertNotIn("javascript:", summary)
            self.assertNotIn("alert(1)", summary)

    def test_head_fetch_uses_object_only_ref_free_command(self) -> None:
        context = self.context()
        calls: list[tuple[list[str], dict[str, str]]] = []

        def fake_run_git(_repo, arguments, *, check=True, env_extra=None):
            del check
            calls.append((list(arguments), dict(env_extra or {})))
            stdout = ""
            if arguments[:2] == ["rev-parse", "HEAD"]:
                stdout = BASE_SHA + "\n"
            elif arguments[:2] == ["rev-parse", "--is-shallow-repository"]:
                stdout = "false\n"
            return subprocess.CompletedProcess(arguments, 0, stdout, "")

        with tempfile.TemporaryDirectory() as temp_directory, mock.patch.object(
            ci_adapter, "_run_git", fake_run_git
        ):
            ci_adapter.fetch_pull_head_object(
                context,
                repo=Path(temp_directory),
                server_url="https://github.com",
                token="ephemeral-token",
            )

        fetch_arguments, fetch_environment = next(
            (arguments, environment)
            for arguments, environment in calls
            if arguments and arguments[0] == "fetch"
        )
        self.assertIn("--no-write-fetch-head", fetch_arguments)
        self.assertEqual("refs/pull/7/head", fetch_arguments[-1])
        self.assertNotIn(":", fetch_arguments[-1])
        self.assertFalse(any("ephemeral-token" in argument for argument in fetch_arguments))
        self.assertIn("AUTHORIZATION: basic", fetch_environment["GIT_CONFIG_VALUE_0"])
        self.assertFalse(
            any(arguments[0] in {"checkout", "worktree", "update-ref"} for arguments, _ in calls)
        )

    def test_workflow_is_read_only_trusted_base_and_fully_pinned(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("pull_request_target:", workflow)
        for event_type in (
            "opened",
            "reopened",
            "synchronize",
            "ready_for_review",
            "converted_to_draft",
            "edited",
        ):
            self.assertIn(f"- {event_type}", workflow)
        for permission in ("contents: read", "issues: read", "pull-requests: read", "actions: read"):
            self.assertIn(permission, workflow)
        self.assertNotIn(": write", workflow)
        self.assertIn("ref: ${{ github.event.pull_request.base.sha }}", workflow)
        self.assertNotIn("ref: ${{ github.event.pull_request.head.sha }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("--no-write-fetch-head", (ROOT / "tools" / "agent-enforcement" / "ci_adapter.py").read_text(encoding="utf-8"))

        uses_lines = [line.strip() for line in workflow.splitlines() if line.strip().startswith("uses:")]
        self.assertEqual(2, len(uses_lines))
        for line in uses_lines:
            action, sha = line.split("@", 1)
            sha = sha.split()[0]
            self.assertIn(action, {"uses: actions/checkout", "uses: actions/upload-artifact"})
            self.assertRegex(sha, r"^[0-9a-f]{40}$")
        self.assertNotIn("@v", workflow)


class CiAdapterIntegrationTests(GuardIntegrationCase):
    def test_guard_inspects_head_objects_while_worktree_remains_at_trusted_base(self) -> None:
        base, head = self.simple_history()
        run(["git", "checkout", "-q", base], self.repo.root)
        before = self.repo.snapshot()
        self.issue.write_text(contract_body(), encoding="utf-8")
        result = subprocess.run(
            [
                "python3",
                str(ROOT / "tools" / "agent-enforcement" / "scope_guard.py"),
                "--issue-number",
                "48",
                "--issue-body-file",
                str(self.issue),
                "--base-sha",
                base,
                "--head-sha",
                head,
                "--worktree-sha",
                base,
                "--execution-id",
                "trusted-base-test",
                "--output",
                str(self.output),
                "--repo",
                str(self.repo.root),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(EXIT_PASS, result.returncode, result.stderr)
        self.assertEqual("PASS", json.loads(self.output.read_text(encoding="utf-8"))["verdict"])
        self.assertEqual(before, self.repo.snapshot())

    def test_adapter_runs_real_guard_for_pass_and_fail_without_mutating_repository(self) -> None:
        for changed_path, expected_verdict, expected_exit in (
            ("tools/agent-enforcement/example.txt", "PASS", EXIT_PASS),
            ("README.md", "FAIL", EXIT_FAIL),
        ):
            with self.subTest(changed_path=changed_path):
                self.repo = Repo(self.root / f"repo-{expected_verdict.lower()}")
                self.repo.write(changed_path, "base\n")
                base = self.repo.commit("base")
                self.repo.write(changed_path, "base\nhead\n")
                head = self.repo.commit("head")
                run(["git", "checkout", "-q", base], self.repo.root)
                before = self.repo.snapshot()

                event_file = self.root / f"event-{expected_verdict.lower()}.json"
                event_file.write_text(
                    json.dumps(
                        synthetic_event(
                            base_sha=base,
                            head_sha=head,
                            head_repository="styx-secure/styx",
                        )
                    ),
                    encoding="utf-8",
                )
                runner_temp = self.root / f"runner-{expected_verdict.lower()}"
                runner_temp.mkdir()
                report_path = runner_temp / "report.json"
                def real_guard_runner(context, **kwargs):
                    result = subprocess.run(
                        [
                            "python3",
                            str(ROOT / "tools" / "agent-enforcement" / "scope_guard.py"),
                            "--issue-number",
                            str(context.issue_number),
                            "--issue-body-file",
                            str(kwargs["issue_body_path"]),
                            "--base-sha",
                            context.base_sha,
                            "--head-sha",
                            context.head_sha,
                            "--worktree-sha",
                            context.base_sha,
                            "--execution-id",
                            context.execution_id,
                            "--output",
                            str(kwargs["report_path"]),
                            "--repo",
                            str(kwargs["repo"]),
                        ],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    return result.returncode

                exit_code = ci_adapter.run_observation(
                    event_file=event_file,
                    repo=self.repo.root,
                    runner_temp=runner_temp,
                    repository="styx-secure/styx",
                    api_url="https://api.github.com",
                    server_url="https://github.com",
                    run_id="123",
                    run_attempt="1",
                    report_path=report_path,
                    token="ephemeral-token",
                    issue_fetcher=lambda *_args, **_kwargs: contract_body().encode("utf-8"),
                    head_fetcher=lambda *_args, **_kwargs: None,
                    guard_runner=real_guard_runner,
                )
                self.assertEqual(expected_exit, exit_code)
                self.assertEqual(
                    expected_verdict,
                    json.loads(report_path.read_text(encoding="utf-8"))["verdict"],
                )
                self.assertEqual(before, self.repo.snapshot())

    def test_non_ancestor_and_malformed_event_fail_closed(self) -> None:
        self.repo.write("tools/agent-enforcement/base.txt", "base\n")
        base = self.repo.commit("base")
        run(["git", "checkout", "--orphan", "unrelated"], self.repo.root)
        run(["git", "rm", "-rf", "."], self.repo.root)
        self.repo.write("tools/agent-enforcement/head.txt", "head\n")
        unrelated = self.repo.commit("unrelated")
        run(["git", "checkout", "-q", base], self.repo.root)

        runner_temp = self.root / "runner-error"
        runner_temp.mkdir()
        event_file = self.root / "event-error.json"
        event_file.write_text(
            json.dumps(synthetic_event(base_sha=base, head_sha=unrelated)),
            encoding="utf-8",
        )
        report_path = runner_temp / "report.json"

        def ancestry_failure(*_args, **_kwargs):
            raise ci_adapter.CiAdapterError("E_CI_GIT_ANCESTRY", "base is not ancestor")

        exit_code = ci_adapter.run_observation(
            event_file=event_file,
            repo=self.repo.root,
            runner_temp=runner_temp,
            repository="styx-secure/styx",
            api_url="https://api.github.com",
            server_url="https://github.com",
            run_id="123",
            run_attempt="1",
            report_path=report_path,
            token="ephemeral-token",
            issue_fetcher=lambda *_args, **_kwargs: contract_body().encode("utf-8"),
            head_fetcher=ancestry_failure,
        )
        self.assertEqual(EXIT_ERROR, exit_code)
        codes = {
            item["code"]
            for item in json.loads(report_path.read_text(encoding="utf-8"))["diagnostics"]
        }
        self.assertIn("E_CI_GIT_ANCESTRY", codes)


if __name__ == "__main__":
    unittest.main()
