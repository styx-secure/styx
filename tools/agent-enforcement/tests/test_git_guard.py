from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest import mock

from support import GuardIntegrationCase, Repo, TOOL, contract_body, run, scope_guard

import git_inventory


class GitGuardTests(GuardIntegrationCase):
    def test_valid_in_scope_text_change_passes(self) -> None:
        base, head = self.simple_history()
        result, report, _ = self.invoke(base, head)
        self.assert_verdict(result, report, "PASS", 0)
        self.assertEqual("M", report["changed_entries"][0]["status"])

    def test_outside_allowlist_and_forbidden_override_fail(self) -> None:
        base, head = self.simple_history("README.md")
        result, report, _ = self.invoke(base, head)
        self.assert_verdict(result, report, "FAIL", 2)
        self.assertIn("P_PATH_NOT_ALLOWED", {item["code"] for item in report["diagnostics"]})

        self.repo = Repo(self.root / "overlap-repo")
        base, head = self.simple_history("tools/agent-enforcement/secret.txt")
        body = contract_body(
            allowed=("tools/agent-enforcement/**",),
            forbidden=("tools/agent-enforcement/secret.txt",),
        )
        result, report, _ = self.invoke(base, head, body=body, output=self.root / "overlap.json")
        self.assert_verdict(result, report, "FAIL", 2)
        evaluation = report["changed_entries"][0]["paths"][0]
        self.assertTrue(evaluation["allowed_matches"])
        self.assertTrue(evaluation["forbidden_matches"])

    def test_add_modify_delete_inventory(self) -> None:
        self.repo.write("tools/agent-enforcement/modify.txt", "one\n")
        self.repo.write("tools/agent-enforcement/delete.txt", "delete\n")
        base = self.repo.commit("base")
        self.repo.write("tools/agent-enforcement/modify.txt", "two\n")
        self.repo.remove("tools/agent-enforcement/delete.txt")
        self.repo.write("tools/agent-enforcement/add.txt", "add\n")
        head = self.repo.commit("head")
        result, report, _ = self.invoke(base, head)
        self.assert_verdict(result, report, "PASS", 0)
        self.assertEqual({"A", "M", "D"}, {item["status"] for item in report["changed_entries"]})

    def test_rename_and_copy_check_both_paths(self) -> None:
        self.repo.write("legacy.txt", "same content\n" * 20)
        base = self.repo.commit("base")
        destination = self.repo.root / "tools" / "agent-enforcement" / "renamed.txt"
        destination.parent.mkdir(parents=True)
        (self.repo.root / "legacy.txt").rename(destination)
        head = self.repo.commit("rename")
        result, report, _ = self.invoke(base, head)
        self.assert_verdict(result, report, "FAIL", 2)
        rename = next(item for item in report["changed_entries"] if item["status"] == "R")
        self.assertEqual(2, len(rename["paths"]))

        self.repo = Repo(self.root / "copy-repo")
        self.repo.write("tools/agent-enforcement/source.txt", "copy me\n" * 20)
        base = self.repo.commit("base")
        shutil.copy2(
            self.repo.root / "tools" / "agent-enforcement" / "source.txt",
            self.repo.root / "tools" / "agent-enforcement" / "copy.txt",
        )
        head = self.repo.commit("copy")
        result, report, _ = self.invoke(base, head, output=self.root / "copy.json")
        self.assert_verdict(result, report, "PASS", 0)
        copy = next(item for item in report["changed_entries"] if item["status"] == "C")
        self.assertEqual(2, len(copy["paths"]))

    def test_symlink_gitlink_and_binary_fail_closed(self) -> None:
        self.repo.write("tools/agent-enforcement/target.txt", "target\n")
        base = self.repo.commit("base")
        (self.repo.root / "tools" / "agent-enforcement" / "link.txt").symlink_to("target.txt")
        head = self.repo.commit("symlink")
        result, report, _ = self.invoke(base, head)
        self.assert_verdict(result, report, "FAIL", 2)
        self.assertIn("P_SYMLINK", {item["code"] for item in report["diagnostics"]})

        self.repo = Repo(self.root / "binary-repo")
        self.repo.write("tools/agent-enforcement/base.txt", "base\n")
        base = self.repo.commit("base")
        self.repo.write("tools/agent-enforcement/blob.bin", b"abc\x00def")
        head = self.repo.commit("binary")
        result, report, _ = self.invoke(base, head, output=self.root / "binary.json")
        self.assert_verdict(result, report, "FAIL", 2)
        codes = {item["code"] for item in report["diagnostics"]}
        self.assertTrue({"P_BINARY_GIT", "P_BINARY_NUL"} & codes)

        self.repo = Repo(self.root / "gitlink-repo")
        self.repo.write("tools/agent-enforcement/base.txt", "base\n")
        base = self.repo.commit("base")
        nested = Repo(self.repo.root / "tools" / "agent-enforcement" / "submodule")
        nested.write("nested.txt", "nested\n")
        nested_sha = nested.commit("nested")
        run(
            [
                "git",
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{nested_sha},tools/agent-enforcement/submodule",
            ],
            self.repo.root,
        )
        run(["git", "commit", "-qm", "gitlink"], self.repo.root)
        head = run(["git", "rev-parse", "HEAD"], self.repo.root).stdout.strip()
        result, report, _ = self.invoke(base, head, output=self.root / "gitlink.json")
        self.assert_verdict(result, report, "FAIL", 2)
        self.assertIn("P_GITLINK", {item["code"] for item in report["diagnostics"]})

    def test_invalid_sha_mismatch_dirty_and_output_inside_repo_error(self) -> None:
        base, head = self.simple_history()
        result, report, _ = self.invoke("main", head)
        self.assert_verdict(result, report, "ERROR", 3)

        run(["git", "checkout", "-q", base], self.repo.root)
        result, report, _ = self.invoke(base, head, output=self.root / "mismatch.json")
        self.assert_verdict(result, report, "ERROR", 3)

        run(["git", "checkout", "-q", head], self.repo.root)
        self.repo.write("dirty.txt", "dirty\n")
        result, report, _ = self.invoke(base, head, output=self.root / "dirty.json")
        self.assert_verdict(result, report, "ERROR", 3)
        run(["git", "clean", "-fd"], self.repo.root)

        destination = self.repo.root / "report.json"
        result, report, _ = self.invoke(base, head, output=destination)
        self.assertEqual(3, result.returncode)
        self.assertIsNone(report)
        self.assertFalse(destination.exists())

    def test_cli_usage_errors_exit_with_documented_error_code(self) -> None:
        cases = (
            [],
            ["--issue-number", "not-an-integer"],
            ["--unknown-flag"],
        )
        for extra in cases:
            with self.subTest(extra=extra):
                result = subprocess.run(
                    ["python3", str(TOOL), *extra],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                self.assertEqual(3, result.returncode, result.stderr)
                self.assertIn("usage:", result.stderr)

        result = subprocess.run(
            ["python3", str(TOOL), "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(0, result.returncode)

    def test_missing_commit_object_is_error(self) -> None:
        _, head = self.simple_history()
        absent = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        result, report, _ = self.invoke(absent, head)
        self.assert_verdict(result, report, "ERROR", 3)
        self.assertIn("E_GIT_INPUT", {item["code"] for item in report["diagnostics"]})
        self.assertEqual(absent, report["base_sha"])

    def test_invalid_execution_ids_are_errors(self) -> None:
        base, head = self.simple_history()
        for index, execution_id in enumerate(("", " padded ", "control\x01char")):
            with self.subTest(execution_id=execution_id):
                result, report, _ = self.invoke(
                    base,
                    head,
                    execution_id=execution_id,
                    output=self.root / f"execution-{index}.json",
                )
                self.assert_verdict(result, report, "ERROR", 3)

    def test_shallow_repository_is_error(self) -> None:
        base, head = self.simple_history()
        self.issue.write_text(contract_body(), encoding="utf-8")
        clone_root = self.root / "shallow-clone"
        run(
            ["git", "clone", "-q", "--depth", "1", f"file://{self.repo.root}", str(clone_root)],
            self.root,
        )
        result = subprocess.run(
            [
                "python3",
                str(TOOL),
                "--issue-number",
                "46",
                "--issue-body-file",
                str(self.issue),
                "--base-sha",
                base,
                "--head-sha",
                head,
                "--execution-id",
                "shallow-regression",
                "--output",
                str(self.root / "shallow.json"),
                "--repo",
                str(clone_root),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(3, result.returncode, result.stderr)

    def test_concurrent_mutation_is_repository_changed_error(self) -> None:
        base, head = self.simple_history()
        self.issue.write_text(contract_body(), encoding="utf-8")
        intruder = self.repo.root / "intruder.txt"
        original_inventory = scope_guard.inventory_changes

        def mutating_inventory(repo, base_sha, head_sha):
            intruder.write_text("raced\n", encoding="utf-8")
            return original_inventory(repo, base_sha, head_sha)

        argv = [
            "--issue-number",
            "46",
            "--issue-body-file",
            str(self.issue),
            "--base-sha",
            base,
            "--head-sha",
            head,
            "--execution-id",
            "race-regression",
            "--output",
            str(self.output),
            "--repo",
            str(self.repo.root),
        ]
        try:
            with mock.patch.object(scope_guard, "inventory_changes", mutating_inventory):
                exit_code = scope_guard.main(argv)
        finally:
            intruder.unlink()
        self.assertEqual(3, exit_code)
        report = json.loads(self.output.read_text(encoding="utf-8"))
        self.assertEqual("ERROR", report["verdict"])
        self.assertIn("E_REPOSITORY_CHANGED", {item["code"] for item in report["diagnostics"]})

    def test_output_inside_real_repository_is_refused_for_subdirectory_repo(self) -> None:
        base, head = self.simple_history()
        subdirectory = self.repo.root / "tools"
        destination = self.repo.root / "smuggled-report.json"
        self.issue.write_text(contract_body(), encoding="utf-8")
        result = subprocess.run(
            [
                "python3",
                str(TOOL),
                "--issue-number",
                "46",
                "--issue-body-file",
                str(self.issue),
                "--base-sha",
                base,
                "--head-sha",
                head,
                "--execution-id",
                "subdir-output-regression",
                "--output",
                str(destination),
                "--repo",
                str(subdirectory),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(3, result.returncode, result.stderr)
        self.assertIn("outside the tested repository", result.stderr)
        self.assertFalse(destination.exists())

    def test_leading_colon_file_name_uses_literal_pathspec(self) -> None:
        self.repo.write(":odd.txt", "base\n")
        base = self.repo.commit("base")
        self.repo.write(":odd.txt", "base\nhead\n")
        head = self.repo.commit("head")
        body = contract_body(allowed=("tools/agent-enforcement/**", ":odd.txt"))
        result, report, _ = self.invoke(base, head, body=body)
        self.assert_verdict(result, report, "PASS", 0)
        self.assertEqual(":odd.txt", report["changed_entries"][0]["paths"][0]["path"])

    def test_base_equal_head_is_empty_diff(self) -> None:
        _, head = self.simple_history()
        result, report, _ = self.invoke(head, head)
        self.assert_verdict(result, report, "PASS", 0)
        self.assertEqual([], report["changed_entries"])

    def test_adversarial_deep_diff_path_is_deterministic_error(self) -> None:
        deep = b"a/" * 5000 + b"a"
        with self.assertRaises(git_inventory.GitInputError):
            git_inventory.parse_changed_entries(b"M\0" + deep + b"\0")

    def test_self_host_execution_does_not_create_bytecode_or_dirty_repo(self) -> None:
        self.repo = Repo(self.root / "self-host-repo")
        run(["git", "commit", "--allow-empty", "-qm", "empty base"], self.repo.root)
        base = run(["git", "rev-parse", "HEAD"], self.repo.root).stdout.strip()

        destination = self.repo.root / "tools" / "agent-enforcement"
        destination.mkdir(parents=True)
        for name in ("model.py", "contract.py", "git_inventory.py", "report.py", "scope_guard.py"):
            shutil.copy2(TOOL.parent / name, destination / name)
        head = self.repo.commit("implementation")

        issue = self.root / "self-host-issue.md"
        report_path = self.root / "self-host-report.json"
        issue.write_text(contract_body(), encoding="utf-8")
        result = subprocess.run(
            [
                "python3",
                str(destination / "scope_guard.py"),
                "--issue-number",
                "46",
                "--issue-body-file",
                str(issue),
                "--base-sha",
                base,
                "--head-sha",
                head,
                "--execution-id",
                "self-host-regression",
                "--output",
                str(report_path),
                "--repo",
                str(self.repo.root),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertFalse((destination / "__pycache__").exists())
        self.assertEqual(
            b"",
            run(
                ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
                self.repo.root,
                text=False,
            ).stdout,
        )


if __name__ == "__main__":
    unittest.main()
