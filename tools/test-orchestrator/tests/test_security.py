"""Security posture: offline policy, credential masking, no network paths."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import unittest
from unittest import mock

import support
from support import DEFAULT_REQUIRED_TESTS, OrchestratorCase

MODULE_FILES = sorted(support.TOOL_DIR.glob("*.py"))
NETWORK_IMPORT_RE = re.compile(
    r"^\s*(?:import|from)\s+(urllib|socket|http|ssl|ftplib|smtplib|requests|httpx)\b", re.MULTILINE
)


class SourcePolicyTest(unittest.TestCase):
    def test_orchestrator_modules_import_no_network_stack(self):
        self.assertTrue(MODULE_FILES)
        for module in MODULE_FILES:
            source = module.read_text(encoding="utf-8")
            self.assertIsNone(NETWORK_IMPORT_RE.search(source), module.name)

    def test_orchestrator_modules_reference_no_github_or_model_endpoints(self):
        for module in MODULE_FILES:
            source = module.read_text(encoding="utf-8").lower()
            for marker in ("api.github.com", "githubusercontent", "anthropic", "openai.com"):
                self.assertNotIn(marker, source, module.name)


class CommandPolicyTest(unittest.TestCase):
    def assert_rejected(self, argv: list[str]):
        with self.assertRaises(support.safety.CommandPolicyError):
            support.safety.validate_command(argv)

    def test_contract_commands_are_accepted(self):
        for command in DEFAULT_REQUIRED_TESTS:
            argv, _ = support.safety.split_shell_command(command)
            support.safety.validate_command(argv)

    def test_network_tools_are_rejected(self):
        for tool in ("curl", "wget", "ssh", "scp", "nc", "gh", "pip", "npm"):
            self.assert_rejected([tool, "example"])

    def test_shell_control_tokens_are_rejected(self):
        self.assert_rejected(["python3", "-m", "unittest", ";", "curl", "evil"])
        self.assert_rejected(["python3", "-m", "unittest", "a|b"])
        self.assert_rejected(["python3", "-m", "unittest", "$(id)"])
        self.assert_rejected(["git", "diff", "a>b"])

    def test_arbitrary_python_execution_is_rejected(self):
        self.assert_rejected(["python3", "-c", "print(1)"])
        self.assert_rejected(["python3", "script.py"])
        self.assert_rejected(["python3", "-m", "pdb"])
        self.assert_rejected(["python3", "-m", "py_compile", "-c"])

    def test_git_write_and_config_operations_are_rejected(self):
        self.assert_rejected(["git", "push", "origin", "main"])
        self.assert_rejected(["git", "commit", "-m", "x"])
        self.assert_rejected(["git", "fetch"])
        self.assert_rejected(["git", "-c", "core.fsmonitor=x", "diff"])
        self.assert_rejected(["git", "diff", "--git-dir=/elsewhere"])
        self.assert_rejected(["git", "diff", "--exec-path=/elsewhere"])

    def test_git_diff_write_and_helper_options_are_rejected(self):
        sha_a, sha_b = "a" * 40, "b" * 40
        for option in (
            "--output=/tmp/x",
            "--output",
            "--ext-diff",
            "--no-ext-diff",
            "--textconv",
            "--no-textconv",
            "--src-prefix=x",
            "--dst-prefix=x",
            "--line-prefix=x",
            "--ita-invisible-in-index",
            "--ita-visible-in-index",
            "-G",
            "-Gpattern",
            "-S",
            "-Ssecret",
            "--find-object",
            "--find-object=deadbeef",
        ):
            with self.subTest(option=option):
                self.assert_rejected(["git", "diff", option, sha_a, sha_b])

    def test_git_options_follow_a_positive_allowlist(self):
        sha_a, sha_b = "a" * 40, "b" * 40
        support.safety.validate_command(["git", "diff", "--check", sha_a, sha_b])
        support.safety.validate_command(
            ["git", "diff", "--quiet", sha_a, sha_b, "--", ":(glob).github/**"]
        )
        support.safety.validate_command(["git", "cat-file", "-e", f"{sha_a}^{{commit}}"])
        support.safety.validate_command(["git", "merge-base", "--is-ancestor", sha_a, sha_b])
        self.assert_rejected(["git", "diff", "--stat", sha_a, sha_b])
        self.assert_rejected(["git", "cat-file", "--batch"])
        self.assert_rejected(["git", "rev-parse", "--show-toplevel"])

    def test_python_path_traversal_is_rejected(self):
        self.assert_rejected(["python3", "-m", "py_compile", "../../etc/passwd"])
        self.assert_rejected(["python3", "-m", "py_compile", "a/../../b.py"])
        self.assert_rejected(["python3", "-m", "compileall", ".."])
        self.assert_rejected(["python3", "-m", "unittest", "discover", "-s", "../outside"])
        self.assert_rejected(["python3", "-m", "unittest", "discover", "--start-directory=../outside"])
        self.assert_rejected(["python3", "-m", "py_compile", "~/x.py"])
        self.assert_rejected(["python3", "-m", "py_compile", "/etc/passwd"])

    def test_only_devnull_redirection_is_supported(self):
        argv, discard = support.safety.split_shell_command("python3 -m json.tool x.json >/dev/null")
        self.assertTrue(discard)
        self.assertEqual(["python3", "-m", "json.tool", "x.json"], list(argv))
        argv, discard = support.safety.split_shell_command("python3 -m json.tool x.json > /dev/null")
        self.assertTrue(discard)
        with self.assertRaises(support.safety.CommandPolicyError):
            support.safety.validate_command(
                support.safety.split_shell_command("python3 -m json.tool x.json > out.txt")[0]
            )


class EnvironmentMaskingTest(OrchestratorCase):
    def test_execution_environment_drops_credentials_and_masks_home(self):
        secrets = {
            "GH_TOKEN": "ghp_" + "c" * 24,
            "GITHUB_TOKEN": "ghp_" + "d" * 24,
            "AWS_SECRET_ACCESS_KEY": "e" * 32,
            "NPM_AUTH_TOKEN": "f" * 32,
        }
        with mock.patch.dict(os.environ, secrets):
            environment = support.executor.ExecutionEnvironment(self.workdir, "0" * 40)
            self.addCleanup(environment.cleanup)
            env = environment.environment()
        for key in secrets:
            self.assertNotIn(key, env)
        for value in secrets.values():
            self.assertNotIn(value, json.dumps(env))
        self.assertTrue(Path(env["HOME"]).is_relative_to(environment.root))
        self.assertEqual([], list(Path(env["HOME"]).iterdir()))
        self.assertEqual(os.devnull, env["GIT_CONFIG_GLOBAL"])
        self.assertEqual(os.devnull, env["GIT_CONFIG_SYSTEM"])
        self.assertEqual("0", env["GIT_TERMINAL_PROMPT"])
        self.assertEqual("", env["GIT_EXTERNAL_DIFF"])
        self.assertEqual("cat", env["GIT_PAGER"])

    def test_bwrap_prefix_denies_network_and_write_access(self):
        environment = support.executor.ExecutionEnvironment(self.workdir, "0" * 40)
        self.addCleanup(environment.cleanup)
        environment.bwrap = "/usr/bin/bwrap"
        prefix = environment.command_prefix(self.workdir)
        self.assertIn("--unshare-net", prefix)
        self.assertIn("--die-with-parent", prefix)
        repo_binding = prefix.index("--ro-bind", prefix.index("--tmpfs"))
        self.assertEqual(str(self.workdir), prefix[repo_binding + 1])

    def test_bwrap_prefix_uses_absolute_paths_for_relative_repo(self):
        cwd = Path.cwd()
        try:
            os.chdir(self.workdir)
            environment = support.executor.ExecutionEnvironment(Path("."), "0" * 40)
            self.addCleanup(environment.cleanup)
            environment.bwrap = "/usr/bin/bwrap"
            prefix = environment.command_prefix(environment.repo)
            for token in prefix[1:]:
                if not token.startswith("--"):
                    self.assertTrue(token.startswith("/"), token)
        finally:
            os.chdir(cwd)

    def test_redaction_removes_token_shapes(self):
        redacted = support.model.redact_text("ghp_" + "g" * 24 + " and Authorization: Bearer abcdef123456")
        self.assertNotIn("ghp_" + "g" * 24, redacted)
        self.assertIn("[REDACTED]", redacted)

    def test_command_redaction_masks_secret_material(self):
        secret = "hunter2-super-secret"
        argv = [
            "python3", "-m", "unittest",
            f"token={secret}",
            f"--api-key={secret}",
            "--password", secret,
            f"https://user:{secret}@relay.example/path",
            "ghp_" + "h" * 24,
            ".ssh/id_ed25519",
            "docs/schema.json",
        ]
        redacted = support.model.redact_command(argv, env={})
        joined = json.dumps(redacted)
        self.assertNotIn(secret, joined)
        self.assertNotIn("ghp_" + "h" * 24, joined)
        self.assertNotIn("id_ed25519", joined)
        self.assertEqual("token=[REDACTED]", redacted[3])
        self.assertEqual("--api-key=[REDACTED]", redacted[4])
        self.assertEqual(["--password", "[REDACTED]"], redacted[5:7])
        self.assertEqual("docs/schema.json", redacted[-1])
        self.assertEqual(["python3", "-m", "unittest"], redacted[:3])

    def test_command_redaction_keeps_ordinary_commands_intact(self):
        argv = ["python3", "-m", "unittest", "discover", "-s", "tools/sample/tests", "-p", "test_*.py"]
        self.assertEqual(argv, support.model.redact_command(argv, env={}))

    def test_explicit_secret_shapes_are_redacted(self):
        samples = (
            "AKIA" + "A" * 16,
            "ASIA" + "B" * 16,
            "xoxb-123456789012-abcdefghijkl",
            "xoxp-987654321098-zyxwvutsrqpo",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abc_DEF-4567890",
            "ghp_" + "x" * 24,
            "github_pat_" + "y" * 24,
        )
        for sample in samples:
            with self.subTest(sample=sample):
                text = support.model.redact_text(f"before {sample} after", env={})
                self.assertNotIn(sample, text)
                self.assertIn("[REDACTED]", text)
                command = support.model.redact_command(["python3", "-m", "unittest", sample], env={})
                self.assertNotIn(sample, json.dumps(command))

    def test_secret_key_value_forms_are_redacted(self):
        secret = "swordfish-0123456789"
        for token in (
            f"AWS_ACCESS_KEY_ID={secret}",
            f"CLIENT_SECRET={secret}",
            f"api_key={secret}",
            f"--client-secret={secret}",
            f"--access-key={secret}",
        ):
            with self.subTest(token=token):
                redacted = support.model.redact_command([token], env={})
                self.assertNotIn(secret, json.dumps(redacted))
                self.assertIn("[REDACTED]", redacted[0])
        self.assertEqual(
            ["--private-key", "[REDACTED]"],
            support.model.redact_command(["--private-key", secret], env={}),
        )

    def test_legitimate_identifiers_are_never_redacted(self):
        commit_sha = "48b1d6450b52c387993073977869dded42ed4588"
        digest = "a" * 64
        for value in (commit_sha, digest, "tools/sample/newfile.py", "1.2.3", "test_*.py"):
            with self.subTest(value=value):
                self.assertEqual(value, support.model.redact_text(value, env={}))
                self.assertEqual([value], support.model.redact_command([value], env={}))


class CommandPolicyBindingTest(unittest.TestCase):
    def test_policy_hash_is_a_stable_sha256(self):
        first = support.safety.command_policy_sha256()
        second = support.safety.command_policy_sha256()
        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertEqual(first, second)

    def test_policy_hash_tracks_the_descriptor(self):
        baseline = support.safety.command_policy_sha256()
        descriptor = support.safety.command_policy_descriptor()
        descriptor["python_module_allowlist"] = ["unittest"]
        with mock.patch.object(
            support.safety, "command_policy_descriptor", return_value=descriptor
        ):
            self.assertNotEqual(baseline, support.safety.command_policy_sha256())


class SchemaShapeTest(unittest.TestCase):
    def test_published_schemas_are_closed_and_versioned(self):
        for path, schema_id in (
            (support.PLAN_SCHEMA, "styx.test-plan/v1"),
            (support.REPORT_SCHEMA, "styx.test-report/v1"),
            (support.FAILURE_SCHEMA, "styx.test-failure/v1"),
        ):
            document = json.loads(path.read_text(encoding="utf-8"))
            self.assertIs(False, document["additionalProperties"], path.name)
            self.assertEqual(schema_id, document["properties"]["schema"]["const"], path.name)

    def test_report_schema_freezes_the_contract_interface(self):
        document = json.loads(support.REPORT_SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(
            [
                "schema",
                "issue_number",
                "execution_id",
                "base_sha",
                "head_sha",
                "issue_body_sha256",
                "plan_sha256",
                "scope_report_sha256",
                "command_policy_sha256",
                "mandatory_verdict",
                "regression_verdict",
                "generated_verdict",
                "adversarial_verdict",
                "static_verdict",
                "rollback_verdict",
                "failures",
                "generation",
                "verdict",
            ],
            document["required"],
        )
        self.assertEqual(["PASS", "FAIL", "ERROR"], document["properties"]["verdict"]["enum"])


if __name__ == "__main__":
    unittest.main()
