from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve()
ROOT = HERE.parents[3]
HOOK_PATH = ROOT / ".claude" / "hooks" / "worktree_integrity.py"
SPEC = importlib.util.spec_from_file_location("styx_worktree_integrity", HOOK_PATH)
assert SPEC and SPEC.loader
INTEGRITY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INTEGRITY)


class WorktreeIntegrityTests(unittest.TestCase):
    def _git(self, cwd: Path, *args: str) -> str:
        return subprocess.check_output(["git", *args], cwd=cwd, text=True).strip()

    def test_private_linked_worktree_is_accepted_and_repointing_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            source = root / "source"
            state = home / ".local/state/styx-agent-runner"
            store = state / "git/styx.git"
            worktree = state / "worktrees/issue-50"
            source.mkdir(parents=True)
            state.mkdir(parents=True)

            subprocess.run(["git", "init", "-b", "main"], cwd=source, check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=source, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=source, check=True)
            (source / "seed.txt").write_text("seed\n", encoding="utf-8")
            subprocess.run(["git", "add", "seed.txt"], cwd=source, check=True)
            subprocess.run(["git", "commit", "-m", "seed"], cwd=source, check=True, stdout=subprocess.DEVNULL)
            base = self._git(source, "rev-parse", "HEAD")

            store.parent.mkdir(parents=True)
            subprocess.run(["git", "clone", "--bare", "--no-hardlinks", str(source), str(store)], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(
                ["git", f"--git-dir={store}", "worktree", "add", "-b", "task/50-demo", str(worktree), base],
                check=True,
                stdout=subprocess.DEVNULL,
            )
            active = {
                "issue_number": 50,
                "worktree": str(worktree),
            }
            (state / "active.json").write_text(json.dumps(active), encoding="utf-8")
            environment = {
                "HOME": str(home),
                "STYX_AGENT_STATE_DIR": str(home / ".local/state"),
                "STYX_AGENT_WORKTREE_ROOT": str(state / "worktrees"),
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                INTEGRITY.verify_active_worktree()
                outside = root / "outside.git"
                outside.mkdir()
                (worktree / ".git").write_text(f"gitdir: {outside}\n", encoding="utf-8")
                with self.assertRaises(INTEGRITY.IntegrityError):
                    INTEGRITY.verify_active_worktree()

    def test_symlinked_git_pointer_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            state = home / ".local/state/styx-agent-runner"
            worktree = state / "worktrees/issue-50"
            worktree.mkdir(parents=True)
            target = root / "git-pointer"
            target.write_text("gitdir: /tmp/not-private\n", encoding="utf-8")
            (worktree / ".git").symlink_to(target)
            (state / "active.json").write_text(json.dumps({"issue_number": 50, "worktree": str(worktree)}), encoding="utf-8")
            environment = {
                "HOME": str(home),
                "STYX_AGENT_STATE_DIR": str(home / ".local/state"),
                "STYX_AGENT_WORKTREE_ROOT": str(state / "worktrees"),
            }
            with mock.patch.dict(os.environ, environment, clear=False):
                with self.assertRaises(INTEGRITY.IntegrityError):
                    INTEGRITY.verify_active_worktree()


if __name__ == "__main__":
    unittest.main()
