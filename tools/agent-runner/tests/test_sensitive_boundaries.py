from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest import mock

HERE = Path(__file__).resolve()
ROOT = HERE.parents[3]
HOOK_PATH = ROOT / ".claude" / "hooks" / "styx_guard.py"
HOOK_SPEC = importlib.util.spec_from_file_location("styx_sensitive_hook", HOOK_PATH)
assert HOOK_SPEC and HOOK_SPEC.loader
HOOK = importlib.util.module_from_spec(HOOK_SPEC)
HOOK_SPEC.loader.exec_module(HOOK)


class SensitiveBoundaryTests(unittest.TestCase):
    def test_shell_commands_cannot_reference_common_credential_files(self):
        with mock.patch.dict(
            os.environ,
            {
                "HOME": "/home/tester",
                "XDG_CONFIG_HOME": "/home/tester/.config",
            },
            clear=False,
        ):
            for command in (
                "cat ~/.config/gh/hosts.yml",
                "cat $HOME/.ssh/id_ed25519",
                "cat ${HOME}/.netrc",
                "cat /home/tester/.git-credentials",
                "grep token /home/tester/.config/gh/hosts.yml",
            ):
                payload = {
                    "tool_name": "Bash",
                    "tool_input": {"command": command},
                    "cwd": "/tmp",
                }
                with self.subTest(command=command):
                    reason = HOOK.inspect_pre_tool(payload, None)
                    self.assertIsNotNone(reason)
                    self.assertIn("credential", reason)

    def test_settings_deny_direct_reads_of_credential_locations(self):
        settings = json.loads((ROOT / ".claude" / "settings.json").read_text(encoding="utf-8"))
        denied = set(settings["permissions"]["deny"])
        self.assertTrue(
            {
                "Read(~/.config/gh/**)",
                "Read(~/.ssh/**)",
                "Read(~/.git-credentials)",
                "Read(~/.netrc)",
            }.issubset(denied)
        )


if __name__ == "__main__":
    unittest.main()
