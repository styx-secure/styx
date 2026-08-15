from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve()
ROOT = HERE.parents[3]
RUNNER_DIR = HERE.parents[1]
sys.path.insert(0, str(RUNNER_DIR))

import review_hardening  # noqa: E402
import security_hardening  # noqa: E402

READ_ONLY_GUARD_PATH = ROOT / ".claude" / "hooks" / "read_only_guard.py"
READ_ONLY_GUARD_SPEC = importlib.util.spec_from_file_location(
    "styx_read_only_guard",
    READ_ONLY_GUARD_PATH,
)
assert READ_ONLY_GUARD_SPEC and READ_ONLY_GUARD_SPEC.loader
READ_ONLY_GUARD = importlib.util.module_from_spec(READ_ONLY_GUARD_SPEC)
READ_ONLY_GUARD_SPEC.loader.exec_module(READ_ONLY_GUARD)


class ReviewHardeningTests(unittest.TestCase):
    def test_find_and_sed_are_denied_at_the_read_only_gate(self):
        for command in (
            "find . -print",
            "find . -delete",
            "sed -n 1,10p file.txt",
            "sed -i s/a/b/ file.txt",
        ):
            payload = {
                "tool_name": "Bash",
                "tool_input": {"command": command},
            }
            with self.subTest(command=command):
                self.assertIsNotNone(READ_ONLY_GUARD.inspect(payload))

        safe = {
            "tool_name": "Bash",
            "tool_input": {"command": "git status --short"},
        }
        self.assertIsNone(READ_ONLY_GUARD.inspect(safe))

    def test_settings_preserve_sensitive_denies_without_legacy_blocking_profile(self):
        settings = json.loads((ROOT / ".claude/settings.json").read_text(encoding="utf-8"))
        self.assertEqual(settings["disableBypassPermissionsMode"], "disable")
        permissions = settings["permissions"]
        self.assertEqual(permissions["defaultMode"], "default")
        self.assertNotIn("additionalDirectories", permissions)
        self.assertNotIn("allow", permissions)
        self.assertNotIn("sandbox", settings)
        self.assertNotIn("hooks", settings)

        denied = set(permissions["deny"])
        for command in (
            "Bash(curl *)",
            "Bash(wget *)",
            "Bash(ssh *)",
            "Bash(scp *)",
            "Bash(sftp *)",
            "Bash(nc *)",
            "Bash(ncat *)",
            "Bash(socat *)",
            "Bash(sudo *)",
        ):
            self.assertIn(command, denied)
        for path in (
            "Read(~/.aws/**)",
            "Read(~/.gnupg/**)",
            "Read(~/.docker/config.json)",
            "Read(~/.gitconfig)",
            "Read(~/.config/git/**)",
        ):
            self.assertIn(path, denied)
        for deprecated in (
            "Bash(git push *)",
            "Bash(gh *)",
            "Bash(find *)",
            "Bash(sed *)",
        ):
            self.assertNotIn(deprecated, denied)

    def test_nested_test_sandbox_masks_additional_credential_stores(self):
        review_hardening.apply(security_hardening)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            worktree = root / "worktree"
            for directory in (
                home / ".aws",
                home / ".gnupg",
                home / ".config/git",
                home / ".docker",
            ):
                directory.mkdir(parents=True, exist_ok=True)
            (home / ".docker/config.json").write_text("{}", encoding="utf-8")
            (home / ".gitconfig").write_text("[user]\n", encoding="utf-8")
            worktree.mkdir()

            command = security_hardening._bwrap_command(
                "/usr/bin/bwrap",
                worktree,
                "python3 -m unittest",
                {
                    "HOME": str(home),
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                },
            )
            for path in (
                home / ".aws",
                home / ".gnupg",
                home / ".config/git",
                home / ".docker/config.json",
                home / ".gitconfig",
            ):
                self.assertIn(str(path), command)

            for sensitive in (
                "cat $HOME/.aws/credentials",
                "cat ~/.gnupg/private-keys-v1.d/key",
                "cat ~/.docker/config.json",
                "cat ~/.gitconfig",
                "cat ~/.config/git/credentials",
            ):
                with self.subTest(sensitive=sensitive):
                    self.assertIsNotNone(security_hardening.PROHIBITED_TEST_RE.search(sensitive))


if __name__ == "__main__":
    unittest.main()
