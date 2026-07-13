from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve()
RUNNER_DIR = HERE.parents[1]
sys.path.insert(0, str(RUNNER_DIR))

import isolated_git  # noqa: E402
import styx_agent as runner  # noqa: E402

isolated_git.apply(runner)


VALID_BODY = b"""<!-- styx-task-contract:v1 -->

## Observable outcome

Test.

## Non-goals

None.

## Allowed paths

```text
tools/agent-runner/**
docs/governance/agent-runner.md
```

## Forbidden paths

```text
AGENTS.md
.github/**
```

## Native dependencies

- Required closed Issue: #46

## Frozen shared interfaces

Stable.

## Acceptance criteria

Pass.

## Required tests

```bash
python3 -m unittest
git diff --check
```

## Rollback

Delete files.

## Residual risks

Test only.

## Executor and reviewers

Agent and reviewer.

## Human gates

Human merge.

## Base

`main @ 1111111111111111111111111111111111111111`
"""


class Parsed:
    allowed_patterns = ("tools/agent-runner/**", "docs/governance/agent-runner.md")
    forbidden_patterns = ("AGENTS.md", ".github/**")


def fake_parser(body: bytes):
    if b"styx-task-contract:v1" not in body:
        raise ValueError("missing marker")
    return Parsed()


def init_repo(path: Path) -> str:
    subprocess.run(["git", "init", "-b", "main"], cwd=path, check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)
    subprocess.run(["git", "remote", "add", "origin", "https://github.com/styx-secure/styx.git"], cwd=path, check=True)
    (path / "seed.txt").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "add", "seed.txt"], cwd=path, check=True)
    subprocess.run(["git", "commit", "-m", "seed"], cwd=path, check=True, stdout=subprocess.DEVNULL)
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, text=True).strip()


class RunnerCoreTests(unittest.TestCase):
    def test_issue_reference_is_exact(self):
        self.assertEqual(runner.parse_issue_reference("#50"), 50)
        for value in ("50", "#0", "#50 #51", "styx-secure/styx#50", ""):
            with self.subTest(value=value), self.assertRaises(runner.ContractError):
                runner.parse_issue_reference(value)

    def test_contract_preserves_utf8_and_extracts_frozen_fields(self):
        body = VALID_BODY.replace(b"Test.", "Caffè 🐈.".encode("utf-8"))
        contract = runner.validate_issue_contract(Path("."), 50, "[Task] Demo", body, parser=fake_parser)
        self.assertEqual(contract.body_bytes, body)
        self.assertEqual(contract.body_sha256, hashlib.sha256(body).hexdigest())
        self.assertEqual(contract.base_branch, "main")
        self.assertEqual(contract.dependencies, (46,))
        self.assertEqual(contract.required_tests, ("python3 -m unittest", "git diff --check"))

    def test_contract_rejects_bad_base_missing_marker_and_dangerous_test(self):
        bad_base = VALID_BODY.replace(b"`main @ " + b"1" * 40 + b"`", b"`dev @ " + b"1" * 40 + b"`")
        with self.assertRaises(runner.ContractError):
            runner.validate_issue_contract(Path("."), 1, "x", bad_base, parser=fake_parser)
        with self.assertRaises(runner.ContractError):
            runner.validate_issue_contract(Path("."), 1, "x", VALID_BODY.replace(b"styx-task-contract:v1", b"missing"), parser=fake_parser)
        dangerous = VALID_BODY.replace(b"python3 -m unittest", b"sudo apt update")
        with self.assertRaises(runner.ContractError):
            runner.validate_issue_contract(Path("."), 1, "x", dangerous, parser=fake_parser)

    def test_fetch_issue_preserves_utf8_and_rejects_pr_or_closed_item(self):
        payload = {"state": "open", "title": "Titolo", "body": "caffè 🐈", "html_url": "x"}
        title, body, _ = runner.fetch_issue(Path("."), 7, lambda _: payload)
        self.assertEqual(title, "Titolo")
        self.assertEqual(body, "caffè 🐈".encode("utf-8"))
        with self.assertRaises(runner.ContractError):
            runner.fetch_issue(Path("."), 7, lambda _: {**payload, "pull_request": {}})
        with self.assertRaises(runner.ContractError):
            runner.fetch_issue(Path("."), 7, lambda _: {**payload, "state": "closed"})

    def test_dependencies_fail_closed(self):
        runner.verify_dependencies(Path("."), [46], lambda _: {"state": "closed"})
        with self.assertRaises(runner.ContractError):
            runner.verify_dependencies(Path("."), [46], lambda _: {"state": "open"})
        with self.assertRaises(runner.ContractError):
            runner.verify_dependencies(Path("."), [46], lambda _: {"state": "closed", "pull_request": {}})

    def test_remote_normalization(self):
        accepted = (
            "https://github.com/styx-secure/styx.git",
            "https://github.com/styx-secure/styx",
            "git@github.com:styx-secure/styx.git",
            "ssh://git@github.com/styx-secure/styx.git",
        )
        for value in accepted:
            self.assertEqual(runner.normalize_remote(value), "styx-secure/styx")
        self.assertIsNone(runner.normalize_remote("https://evil.example/styx-secure/styx"))

    def test_redaction_and_canonical_json(self):
        env = {"GITHUB_TOKEN": "super-secret-token"}
        value = "Authorization: Bearer abcdef ghp_12345678901234567890 https://u:p@example.com/x super-secret-token"
        redacted = runner.redact_text(value, env)
        for secret in ("abcdef", "ghp_", "u:p@", "super-secret-token"):
            self.assertNotIn(secret, redacted)
        self.assertEqual(
            runner.canonical_json_bytes({"b": 1, "a": "é"}),
            b'{"a":"\xc3\xa9","b":1}\n',
        )

    def test_user_space_provision_is_idempotent_and_refuses_tamper(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo = base / "repo"
            repo.mkdir()
            (repo / "tools/agent-runner").mkdir(parents=True)
            (repo / "tools/agent-runner/styx-agent").write_text("x", encoding="utf-8")
            env = {
                "HOME": str(base),
                "STYX_AGENT_DATA_DIR": str(base / "data"),
                "STYX_AGENT_CACHE_DIR": str(base / "cache"),
                "STYX_AGENT_STATE_DIR": str(base / "state"),
                "STYX_AGENT_WORKTREE_ROOT": str(base / "worktrees"),
            }
            paths = runner.Paths.from_repo(repo, env)
            first = runner.provision_launcher(paths, repo, "/usr/bin/python3")
            second = runner.provision_launcher(paths, repo, "/usr/bin/python3")
            self.assertEqual(first.disposition, "provisioned")
            self.assertEqual(second.disposition, "already-provisioned")
            target = paths.data / "bin/styx-agent"
            self.assertEqual(target.stat().st_mode & 0o777, 0o700)
            target.write_text("tampered", encoding="utf-8")
            with self.assertRaises(runner.EnvironmentError):
                runner.provision_launcher(paths, repo, "/usr/bin/python3")

    def test_environment_classifies_missing_admin_tools_and_unsupported_os(self):
        checks, problems = runner.check_environment(
            (),
            os_release={"ID": "ubuntu", "VERSION_ID": "26.04"},
            machine="x86_64",
            which=lambda _: None,
        )
        self.assertTrue(checks)
        self.assertTrue(any(isinstance(problem, runner.AdminProvisioningRequired) for problem in problems))
        _, unsupported = runner.check_environment(
            (),
            os_release={"ID": "debian", "VERSION_ID": "13"},
            machine="x86_64",
            which=lambda _: None,
        )
        self.assertTrue(any(isinstance(problem, runner.EnvironmentError) for problem in unsupported))

    def test_prepare_private_worktree_is_exact_idempotent_and_has_no_remote(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            repo = base / "repo"
            repo.mkdir()
            sha = init_repo(repo)
            body = VALID_BODY.replace(b"1" * 40, sha.encode("ascii"))
            contract = runner.validate_issue_contract(repo, 50, "[Task] Demo runner", body, parser=fake_parser)
            env = {
                "HOME": str(base),
                "STYX_AGENT_DATA_DIR": str(base / "data"),
                "STYX_AGENT_CACHE_DIR": str(base / "cache"),
                "STYX_AGENT_STATE_DIR": str(base / "state"),
                "STYX_AGENT_WORKTREE_ROOT": str(base / "worktrees"),
            }
            paths = runner.Paths.from_repo(repo, env)
            worktree, branch, head = runner.prepare_worktree(paths, contract)
            self.assertEqual((branch, head), ("task/50-demo-runner", sha))
            self.assertEqual(subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=worktree, text=True).strip(), sha)
            source_worktrees = subprocess.check_output(["git", "worktree", "list", "--porcelain"], cwd=repo, text=True)
            self.assertEqual(source_worktrees.count("worktree "), 1)
            store = isolated_git.object_store(paths)
            self.assertTrue(store.is_dir())
            remotes = subprocess.check_output(["git", f"--git-dir={store}", "remote"], cwd=paths.state, text=True)
            self.assertEqual(remotes.strip(), "")
            self.assertEqual(runner.prepare_worktree(paths, contract)[:2], (worktree, branch))

    def test_source_checkout_must_equal_declared_base(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            sha = init_repo(repo)
            body = VALID_BODY.replace(b"1" * 40, sha.encode("ascii"))
            contract = runner.validate_issue_contract(repo, 50, "[Task] Demo", body, parser=fake_parser)
            subprocess.run(["git", "checkout", "-b", "other"], cwd=repo, check=True, stdout=subprocess.DEVNULL)
            (repo / "other.txt").write_text("other\n", encoding="utf-8")
            subprocess.run(["git", "add", "other.txt"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-m", "other"], cwd=repo, check=True, stdout=subprocess.DEVNULL)
            with self.assertRaises(runner.RepositoryError):
                runner.verify_repository(repo, contract, require_clean=True)

    def test_status_shape_and_exit_classes(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = runner.Paths.from_repo(Path(tmp), {"HOME": tmp})
            status = runner.build_status(
                command="run",
                execution_id="issue-50",
                paths=paths,
                phase="implementation",
                terminal_status="READY_FOR_IMPLEMENTATION",
            )
            self.assertEqual(status["schema"], "styx.agent-runner-status/v1")
            self.assertEqual((runner.EXIT_OK, runner.EXIT_BLOCKED, runner.EXIT_ERROR), (0, 2, 3))
            self.assertEqual(json.loads(runner.canonical_json_bytes(status))["terminal_status"], "READY_FOR_IMPLEMENTATION")

    def test_broker_rejects_every_write(self):
        broker = runner.BrokerOperations()
        for operation in ("push_task_branch", "open_draft_pr", "merge", "comment"):
            with self.subTest(operation=operation), self.assertRaises(runner.BrokerUnavailable):
                broker.request(operation, {})

    def test_cli_rejects_nonpositive_issue(self):
        self.assertEqual(runner.main(["run", "--issue", "0"]), runner.EXIT_ERROR)
        parsed = runner.parser().parse_args(["run", "--issue", "50", "--execution-id", "issue-50"])
        self.assertIsInstance(parsed, argparse.Namespace)
        self.assertEqual(parsed.issue, 50)


if __name__ == "__main__":
    unittest.main()
