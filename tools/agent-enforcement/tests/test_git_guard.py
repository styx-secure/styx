from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import unittest

from support import GuardIntegrationCase, Repo, TOOL, contract_body, run


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
