from __future__ import annotations

from email.message import Message
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve()
ROOT = HERE.parents[3]
RUNNER_DIR = HERE.parents[1]
sys.path.insert(0, str(RUNNER_DIR))

import security_hardening  # noqa: E402
import styx_agent as runner  # noqa: E402

HOOK_PATH = ROOT / ".claude" / "hooks" / "styx_guard.py"
HOOK_SPEC = importlib.util.spec_from_file_location("styx_no_go_hook", HOOK_PATH)
assert HOOK_SPEC and HOOK_SPEC.loader
HOOK = importlib.util.module_from_spec(HOOK_SPEC)
HOOK_SPEC.loader.exec_module(HOOK)


class FakeResponse:
    def __init__(self, body: bytes, content_type: str = "application/json", status: int = 200):
        self._body = body
        self.status = status
        self.headers = Message()
        self.headers["Content-Type"] = content_type

    def getcode(self):
        return self.status

    def read(self, amount: int):
        return self._body[:amount]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeOpener:
    def __init__(self, response: FakeResponse):
        self.response = response
        self.request = None

    def open(self, request, timeout=0):
        self.request = request
        return self.response


class NoGoFixTests(unittest.TestCase):
    def test_public_issue_reader_is_anonymous_and_endpoint_locked(self):
        opener = FakeOpener(FakeResponse(b'{"state":"open","title":"x","body":"y"}'))
        payload = security_hardening.anonymous_github_get(
            runner,
            "repos/styx-secure/styx/issues/50",
            opener=opener,
        )
        self.assertEqual(payload["state"], "open")
        self.assertIsNotNone(opener.request)
        headers = {key.lower(): value for key, value in opener.request.header_items()}
        self.assertNotIn("authorization", headers)
        self.assertEqual(opener.request.get_method(), "GET")
        self.assertEqual(opener.request.full_url, "https://api.github.com/repos/styx-secure/styx/issues/50")
        with self.assertRaises(runner.EnvironmentError):
            security_hardening.anonymous_github_get(runner, "repos/styx-secure/styx/pulls/50", opener=opener)

    def test_test_sandbox_unshares_network_and_masks_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            worktree = Path(tmp) / "worktree"
            (home / ".config/gh").mkdir(parents=True)
            (home / ".ssh").mkdir()
            (home / ".netrc").write_text("secret", encoding="utf-8")
            worktree.mkdir()
            environment = {
                "HOME": str(home),
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
            }
            command = security_hardening._bwrap_command("/usr/bin/bwrap", worktree, "python3 -m unittest", environment)
            self.assertIn("--unshare-net", command)
            self.assertIn(str(worktree), command)
            self.assertIn(str(home / ".config/gh"), command)
            self.assertIn(str(home / ".ssh"), command)
            self.assertIn(str(home / ".netrc"), command)
            self.assertEqual(command[-4:], ["/bin/bash", "--noprofile", "--norc", "-lc"] + ["python3 -m unittest"][-0:])

    def test_settings_are_noninteractive_and_runner_state_is_not_task_writable(self):
        settings = json.loads((ROOT / ".claude/settings.json").read_text(encoding="utf-8"))
        self.assertEqual(settings["permissions"]["defaultMode"], "dontAsk")
        self.assertTrue(settings["sandbox"]["autoAllowBashIfSandboxed"])
        self.assertFalse(settings["sandbox"]["allowUnsandboxedCommands"])
        self.assertIn("python3 tools/agent-runner/styx-agent run *", settings["sandbox"]["excludedCommands"])
        allow_write = set(settings["sandbox"]["filesystem"]["allowWrite"])
        deny_write = set(settings["sandbox"]["filesystem"]["denyWrite"])
        self.assertEqual(
            allow_write,
            {
                "~/.local/state/styx-agent-runner/worktrees",
                "~/.local/state/styx-agent-runner/git",
            },
        )
        self.assertIn("~/.local/state/styx-agent-runner/active.json", deny_write)
        self.assertIn("~/.local/state/styx-agent-runner/runs", deny_write)
        self.assertIn("~/.local/state/styx-agent-runner/evidence", deny_write)
        self.assertIn("*", settings["sandbox"]["network"]["deniedDomains"])
        self.assertIn("PostToolUse", settings["hooks"])
        self.assertIn("PostToolBatch", settings["hooks"])

    def test_attestation_detects_state_tampering_and_real_diff_violation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            state_root = home / ".local/state/styx-agent-runner"
            worktree = state_root / "worktrees/issue-50"
            runs = state_root / "runs"
            worktree.mkdir(parents=True)
            runs.mkdir(parents=True)
            subprocess.run(["git", "init", "-b", "main"], cwd=worktree, check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=worktree, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=worktree, check=True)
            (worktree / "seed.txt").write_text("seed\n", encoding="utf-8")
            subprocess.run(["git", "add", "seed.txt"], cwd=worktree, check=True)
            subprocess.run(["git", "commit", "-m", "seed"], cwd=worktree, check=True, stdout=subprocess.DEVNULL)
            base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=worktree, text=True).strip()
            subprocess.run(["git", "checkout", "-b", "task/50-demo"], cwd=worktree, check=True, stdout=subprocess.DEVNULL)
            status_path = runs / "issue-50.json"
            status = {
                "base": {"declared_sha": base},
                "issue": {"number": 50},
                "scope_guard": None,
                "terminal_status": "READY_FOR_IMPLEMENTATION",
                "tests": [],
                "worktree": {"branch": "task/50-demo", "path": str(worktree)},
            }
            status_path.write_text(json.dumps(status), encoding="utf-8")
            active_path = state_root / "active.json"
            active = {
                "allowed_patterns": ["docs/**"],
                "base_sha": base,
                "branch": "task/50-demo",
                "forbidden_patterns": ["docs/private/**"],
                "issue_number": 50,
                "status_report": str(status_path),
                "terminal_status": "READY_FOR_IMPLEMENTATION",
                "worktree": str(worktree),
            }
            active_path.write_text(json.dumps(active), encoding="utf-8")
            environment = {
                "HOME": str(home),
                "STYX_AGENT_STATE_DIR": str(home / ".local/state"),
                "STYX_AGENT_TRUST_DIR": str(root / "trust"),
                "STYX_AGENT_WORKTREE_ROOT": str(state_root / "worktrees"),
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                loaded = HOOK._load_state()
                self.assertIsNotNone(loaded)
                HOOK.write_attestation(*loaded)
                HOOK.verify_attestation(*loaded)
                active["allowed_patterns"] = ["other/**"]
                active_path.write_text(json.dumps(active), encoding="utf-8")
                tampered = HOOK._load_state()
                with self.assertRaises(HOOK.HookError):
                    HOOK.verify_attestation(*tampered)
                active["allowed_patterns"] = ["docs/**"]
                active_path.write_text(json.dumps(active), encoding="utf-8")
                restored = HOOK._load_state()
                HOOK.write_attestation(*restored)
                (worktree / "outside.txt").write_text("x\n", encoding="utf-8")
                violations = HOOK._scope_violations(active)
                self.assertTrue(any("outside the task allowlist" in item for item in violations))

    def test_runner_command_is_exact_and_rejects_shell_chaining(self):
        self.assertEqual(
            HOOK._runner_command("python3 tools/agent-runner/styx-agent run --issue 50 --execution-id issue-50"),
            50,
        )
        self.assertIsNone(
            HOOK._runner_command(
                "python3 tools/agent-runner/styx-agent run --issue 50 --execution-id issue-50; gh pr merge 51"
            )
        )


if __name__ == "__main__":
    unittest.main()
