from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import unittest
from unittest import mock

from support import GuardIntegrationCase, Repo, TOOL, contract_body, run, scope_guard

import git_inventory
from model import BinaryArtifactAuthorization, ChangedEntry, TreeObject


class GitGuardTests(GuardIntegrationCase):
    @staticmethod
    def binary_declaration(path: str, data: bytes, *, length: int | None = None) -> str:
        return f"{hashlib.sha256(data).hexdigest()} {len(data) if length is None else length} {path}"

    @staticmethod
    def copy_source_declaration(path: str, data: bytes, *, length: int | None = None) -> str:
        return f"{hashlib.sha256(data).hexdigest()} {len(data) if length is None else length} {path}"

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

    def test_exact_read_only_copy_source_authorization_preserves_audit_evidence(self) -> None:
        source = "legacy/source.mjs"
        destination = "new/copied.mjs"
        data = ("export const immutable = true;\n" * 24).encode()
        self.repo.write(source, data)
        base = self.repo.commit("base")
        self.repo.write(destination, data)
        head = self.repo.commit("copy")
        base_body = contract_body(allowed=("new/**",), forbidden=("legacy/**",))

        result, report, _ = self.invoke(base, head, body=base_body)
        self.assert_verdict(result, report, "FAIL", 2)

        declaration = self.copy_source_declaration(source, data)
        result, report, _ = self.invoke(
            base,
            head,
            body=contract_body(
                allowed=("new/**",),
                forbidden=("legacy/**",),
                copy_sources=(declaration,),
            ),
            output=self.root / "authorized-copy.json",
        )
        self.assert_verdict(result, report, "PASS", 0)
        copy = next(item for item in report["changed_entries"] if item["status"] == "C")
        source_evaluation = copy["paths"][0]
        self.assertEqual(source, source_evaluation["path"])
        self.assertEqual(
            [f"![styx-copy-source sha256={hashlib.sha256(data).hexdigest()}]"],
            source_evaluation["allowed_matches"],
        )
        self.assertEqual(["legacy/**"], source_evaluation["forbidden_matches"])
        self.assertEqual([], source_evaluation["violations"])

    def test_one_exact_source_can_authorize_multiple_copy_destinations(self) -> None:
        source = "legacy/source.mjs"
        data = ("shared immutable source\n" * 32).encode()
        self.repo.write(source, data)
        base = self.repo.commit("base")
        self.repo.write("new/first.mjs", data)
        self.repo.write("new/second.mjs", data)
        head = self.repo.commit("two copies")
        result, report, _ = self.invoke(
            base,
            head,
            body=contract_body(
                allowed=("new/**",),
                forbidden=("legacy/**",),
                copy_sources=(self.copy_source_declaration(source, data),),
            ),
        )
        self.assert_verdict(result, report, "PASS", 0)
        copies = [item for item in report["changed_entries"] if item["status"] == "C"]
        self.assertEqual(2, len(copies))
        self.assertEqual({"new/first.mjs", "new/second.mjs"}, {item["new_path"] for item in copies})

    def test_copy_source_wrong_hash_length_destination_and_destination_only_fail(self) -> None:
        source = "legacy/source.mjs"
        destination = "new/copied.mjs"
        data = ("copy source\n" * 32).encode()
        self.repo.write(source, data)
        base = self.repo.commit("base")
        self.repo.write(destination, data)
        head = self.repo.commit("copy")
        cases = {
            "wrong hash": self.copy_source_declaration(source, b"x" * len(data)),
            "wrong length": self.copy_source_declaration(source, data, length=len(data) + 1),
            "destination only": self.copy_source_declaration(destination, data),
        }
        for index, (name, declaration) in enumerate(cases.items()):
            with self.subTest(name=name):
                result, report, _ = self.invoke(
                    base,
                    head,
                    body=contract_body(
                        allowed=("new/**",),
                        forbidden=("legacy/**",),
                        copy_sources=(declaration,),
                    ),
                    output=self.root / f"copy-mismatch-{index}.json",
                )
                self.assert_verdict(result, report, "FAIL", 2)

        result, report, _ = self.invoke(
            base,
            head,
            body=contract_body(
                allowed=("unrelated/**",),
                forbidden=("legacy/**", "new/**"),
                copy_sources=(self.copy_source_declaration(source, data),),
            ),
            output=self.root / "copy-destination-forbidden.json",
        )
        self.assert_verdict(result, report, "FAIL", 2)
        destination_evaluation = next(
            path
            for entry in report["changed_entries"]
            for path in entry["paths"]
            if path["path"] == destination
        )
        self.assertIn("PATH_FORBIDDEN", destination_evaluation["violations"])

    def test_copy_source_changed_deleted_renamed_or_binary_fails(self) -> None:
        source = "legacy/source.mjs"
        destination = "new/copied.mjs"
        data = ("immutable source\n" * 32).encode()

        self.repo.write(source, data)
        base = self.repo.commit("base")
        self.repo.write(source, data + b"changed\n")
        self.repo.write(destination, data)
        head = self.repo.commit("source changed and copied")
        result, report, _ = self.invoke(
            base,
            head,
            body=contract_body(
                allowed=("new/**",),
                forbidden=("legacy/**",),
                copy_sources=(self.copy_source_declaration(source, data),),
            ),
        )
        self.assert_verdict(result, report, "FAIL", 2)
        self.assertIn("P_COPY_SOURCE_CHANGED_ROLE", {item["code"] for item in report["diagnostics"]})

        for operation in ("delete", "rename"):
            self.repo = Repo(self.root / f"copy-source-{operation}")
            self.repo.write(source, data)
            base = self.repo.commit("base")
            if operation == "delete":
                self.repo.remove(source)
            else:
                target = self.repo.root / destination
                target.parent.mkdir(parents=True)
                (self.repo.root / source).rename(target)
            head = self.repo.commit(operation)
            result, report, _ = self.invoke(
                base,
                head,
                body=contract_body(
                    allowed=("new/**",),
                    forbidden=("legacy/**",),
                    copy_sources=(self.copy_source_declaration(source, data),),
                ),
                output=self.root / f"copy-source-{operation}.json",
            )
            self.assert_verdict(result, report, "FAIL", 2)
            self.assertIn("P_COPY_SOURCE_UNUSED", {item["code"] for item in report["diagnostics"]})

        self.repo = Repo(self.root / "copy-source-binary")
        binary = b"binary\x00source" * 32
        self.repo.write(source, binary)
        base = self.repo.commit("base")
        self.repo.write(destination, binary)
        head = self.repo.commit("binary copy")
        result, report, _ = self.invoke(
            base,
            head,
            body=contract_body(
                allowed=("new/**",),
                forbidden=("legacy/**",),
                copy_sources=(self.copy_source_declaration(source, binary),),
            ),
            output=self.root / "copy-source-binary.json",
        )
        self.assert_verdict(result, report, "FAIL", 2)
        self.assertIn("P_COPY_SOURCE_BINARY", {item["code"] for item in report["diagnostics"]})

    def test_copy_source_symlink_gitlink_and_misleading_source_fail(self) -> None:
        entry = ChangedEntry("C", 100, "legacy/source", "new/copy")
        declaration = git_inventory.CopySourceAuthorization("1" * 64, 1, "legacy/source")
        for mode, object_type in (
            ("120000", "blob"),
            ("160000", "commit"),
            ("040000", "tree"),
            ("100000", "blob"),
        ):
            with self.subTest(mode=mode), mock.patch.object(
                git_inventory,
                "tree_object",
                return_value=TreeObject(mode, object_type, "1" * 40, "legacy/source"),
            ):
                authorized, diagnostics = git_inventory.authorize_copy_sources(
                    Path("."), "1" * 40, "2" * 40, (entry,), (declaration,)
                )
                self.assertEqual({}, authorized)
                self.assertIn("P_COPY_SOURCE_OBJECT", {item.code for item in diagnostics})

        source_a = "legacy/declared.mjs"
        source_b = "legacy/actual.mjs"
        destination = "new/copied.mjs"
        data_a = ("declared source\n" * 32).encode()
        data_b = ("actual source\n" * 32).encode()
        self.repo = Repo(self.root / "misleading-copy-source")
        self.repo.write(source_a, data_a)
        self.repo.write(source_b, data_b)
        base = self.repo.commit("base")
        self.repo.write(destination, data_b)
        head = self.repo.commit("copy other source")
        result, report, _ = self.invoke(
            base,
            head,
            body=contract_body(
                allowed=("new/**",),
                forbidden=("legacy/**",),
                copy_sources=(self.copy_source_declaration(source_a, data_a),),
            ),
            output=self.root / "misleading-copy-source.json",
        )
        self.assert_verdict(result, report, "FAIL", 2)
        self.assertIn("P_COPY_SOURCE_UNUSED", {item["code"] for item in report["diagnostics"]})

    def test_pr176_two_copy_source_regression_is_exact_and_fail_closed(self) -> None:
        def shaped(prefix: str, common_lines: int) -> tuple[bytes, bytes]:
            original = [f"{prefix}-stable-{index:03d}-payload-value\n" for index in range(100)]
            changed = original[:common_lines] + [
                f"replacement-{prefix}-{index:03d}-xxxxxxxx\n"
                for index in range(common_lines, 100)
            ]
            return "".join(original).encode(), "".join(changed).encode()

        old_a = "styx-js/spikes/marmot-phase-b3-2/b3-2-orchestrator.mjs"
        old_b = "styx-js/spikes/marmot-phase-b3-2/verify-pins.mjs"
        new_a = "styx-js/spikes/marmot-phase-b3-2a/b3-2a-orchestrator.mjs"
        new_b = "styx-js/spikes/marmot-phase-b3-2a/verify-pins.mjs"
        source_a, destination_a = shaped("orchestrator", 68)
        source_b, destination_b = shaped("pins", 60)
        self.repo.write(old_a, source_a)
        self.repo.write(old_b, source_b)
        base = self.repo.commit("base")
        self.repo.write(new_a, destination_a)
        self.repo.write(new_b, destination_b)
        head = self.repo.commit("candidate")
        common = {
            "allowed": ("styx-js/spikes/marmot-phase-b3-2a/**",),
            "forbidden": ("styx-js/spikes/marmot-phase-b3-2/**",),
        }

        result, report, _ = self.invoke(
            base,
            head,
            body=contract_body(**common),
        )
        self.assert_verdict(result, report, "FAIL", 2)
        copies = [item for item in report["changed_entries"] if item["status"] == "C"]
        self.assertEqual({old_a, old_b}, {item["old_path"] for item in copies})
        self.assertEqual({68, 60}, {item["score"] for item in copies})

        declarations = (
            self.copy_source_declaration(old_a, source_a),
            self.copy_source_declaration(old_b, source_b),
        )
        result, report, _ = self.invoke(
            base,
            head,
            body=contract_body(**common, copy_sources=declarations),
            output=self.root / "pr176-copy-regression.json",
        )
        self.assert_verdict(result, report, "PASS", 0)
        copies = [item for item in report["changed_entries"] if item["status"] == "C"]
        self.assertEqual({old_a, old_b}, {item["old_path"] for item in copies})
        self.assertEqual({68, 60}, {item["score"] for item in copies})

        wrong = (
            self.copy_source_declaration(old_a, source_a),
            self.copy_source_declaration(old_b, b"x" * len(source_b)),
        )
        result, report, _ = self.invoke(
            base,
            head,
            body=contract_body(**common, copy_sources=wrong),
            output=self.root / "pr176-copy-regression-wrong.json",
        )
        self.assert_verdict(result, report, "FAIL", 2)

    def test_symlink_gitlink_and_binary_fail_closed(self) -> None:
        self.repo.write("tools/agent-enforcement/target.txt", "target\n")
        base = self.repo.commit("base")
        (self.repo.root / "tools" / "agent-enforcement" / "link.txt").symlink_to("target.txt")
        head = self.repo.commit("symlink")
        symlink_path = "tools/agent-enforcement/link.txt"
        symlink_blob = b"target.txt"
        result, report, _ = self.invoke(
            base,
            head,
            body=contract_body(binary_artifacts=(self.binary_declaration(symlink_path, symlink_blob),)),
        )
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
        result, report, _ = self.invoke(
            base,
            head,
            body=contract_body(
                binary_artifacts=(
                    f"{'1' * 64} 1 tools/agent-enforcement/submodule",
                )
            ),
            output=self.root / "gitlink.json",
        )
        self.assert_verdict(result, report, "FAIL", 2)
        self.assertIn("P_GITLINK", {item["code"] for item in report["diagnostics"]})

    def test_exact_binary_add_and_modify_pass(self) -> None:
        path = "tools/agent-enforcement/blob.wasm"
        self.repo.write("tools/agent-enforcement/base.txt", "base\n")
        base = self.repo.commit("base")
        added = b"wasm\x00authorized-add"
        self.repo.write(path, added)
        head = self.repo.commit("add binary")
        body = contract_body(binary_artifacts=(self.binary_declaration(path, added),))
        result, report, _ = self.invoke(base, head, body=body)
        self.assert_verdict(result, report, "PASS", 0)
        self.assertEqual([], report["diagnostics"])

        modified = b"wasm\x00authorized-modification"
        previous = head
        self.repo.write(path, modified)
        head = self.repo.commit("modify binary")
        body = contract_body(binary_artifacts=(self.binary_declaration(path, modified),))
        result, report, _ = self.invoke(
            previous,
            head,
            body=body,
            output=self.root / "modified.json",
        )
        self.assert_verdict(result, report, "PASS", 0)
        self.assertEqual([], report["diagnostics"])

    def test_binary_digest_is_read_from_candidate_head_object_not_worktree(self) -> None:
        path = "tools/agent-enforcement/blob.bin"
        data = b"head-only\x00artifact"
        self.repo.write("tools/agent-enforcement/base.txt", "base\n")
        base = self.repo.commit("base")
        self.repo.write(path, data)
        head = self.repo.commit("head")
        run(["git", "checkout", "-q", base], self.repo.root)

        body = contract_body(
            binary_artifacts=(self.binary_declaration(path, data),),
            base_sha=base,
        )
        self.issue.write_text(body, encoding="utf-8")
        result = subprocess.run(
            [
                "python3",
                str(TOOL),
                "--issue-number",
                "131",
                "--issue-body-file",
                str(self.issue),
                "--base-sha",
                base,
                "--head-sha",
                head,
                "--worktree-sha",
                base,
                "--execution-id",
                "trusted-head-binary",
                "--output",
                str(self.output),
                "--repo",
                str(self.repo.root),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        report = json.loads(self.output.read_text(encoding="utf-8"))
        self.assert_verdict(result, report, "PASS", 0)
        self.assertFalse((self.repo.root / path).exists())

    def test_binary_authorization_hash_length_path_and_scope_mismatches_fail(self) -> None:
        path = "tools/agent-enforcement/blob.wasm"
        actual = b"abc\x00def"
        same_length_other_blob = b"abc\x00deg"
        self.repo.write("tools/agent-enforcement/base.txt", "base\n")
        base = self.repo.commit("base")
        self.repo.write(path, actual)
        head = self.repo.commit("binary")

        cases = {
            "hash": (
                contract_body(
                    binary_artifacts=(self.binary_declaration(path, same_length_other_blob),)
                ),
                "P_BINARY_AUTH_HASH_MISMATCH",
            ),
            "length": (
                contract_body(
                    binary_artifacts=(
                        self.binary_declaration(path, actual, length=len(actual) + 1),
                    )
                ),
                "P_BINARY_AUTH_LENGTH_MISMATCH",
            ),
            "path": (
                contract_body(
                    binary_artifacts=(
                        self.binary_declaration("tools/agent-enforcement/other.wasm", actual),
                    )
                ),
                "P_BINARY_GIT",
            ),
            "extension-only": (contract_body(), "P_BINARY_GIT"),
            "forbidden": (
                contract_body(
                    forbidden=(path,),
                    binary_artifacts=(self.binary_declaration(path, actual),),
                ),
                "P_PATH_FORBIDDEN",
            ),
        }
        for index, (name, (body, expected_code)) in enumerate(cases.items()):
            with self.subTest(name=name):
                result, report, _ = self.invoke(
                    base,
                    head,
                    body=body,
                    output=self.root / f"mismatch-{index}.json",
                )
                self.assert_verdict(result, report, "FAIL", 2)
                codes = {item["code"] for item in report["diagnostics"]}
                self.assertIn(expected_code, codes)
                if name == "hash":
                    self.assertNotIn("P_BINARY_AUTH_LENGTH_MISMATCH", codes)

    def test_binary_delete_rename_and_copy_remain_forbidden_when_declared(self) -> None:
        path = "tools/agent-enforcement/blob.bin"
        data = (b"binary\x00payload" * 32)

        self.repo.write(path, data)
        base = self.repo.commit("base")
        self.repo.remove(path)
        head = self.repo.commit("delete binary")
        result, report, _ = self.invoke(
            base,
            head,
            body=contract_body(binary_artifacts=(self.binary_declaration(path, data),)),
        )
        self.assert_verdict(result, report, "FAIL", 2)
        self.assertIn("P_BINARY_AUTH_STATUS", {item["code"] for item in report["diagnostics"]})

        self.repo = Repo(self.root / "binary-rename-repo")
        old_path = "tools/agent-enforcement/old.bin"
        new_path = "tools/agent-enforcement/new.bin"
        self.repo.write(old_path, data)
        base = self.repo.commit("base")
        (self.repo.root / old_path).rename(self.repo.root / new_path)
        head = self.repo.commit("rename binary")
        declarations = (
            self.binary_declaration(old_path, data),
            self.binary_declaration(new_path, data),
        )
        result, report, _ = self.invoke(
            base,
            head,
            body=contract_body(binary_artifacts=declarations),
            output=self.root / "binary-rename.json",
        )
        self.assert_verdict(result, report, "FAIL", 2)
        self.assertIn("P_BINARY_AUTH_STATUS", {item["code"] for item in report["diagnostics"]})

        self.repo = Repo(self.root / "binary-copy-repo")
        self.repo.write(old_path, data)
        base = self.repo.commit("base")
        shutil.copy2(self.repo.root / old_path, self.repo.root / new_path)
        head = self.repo.commit("copy binary")
        result, report, _ = self.invoke(
            base,
            head,
            body=contract_body(binary_artifacts=(self.binary_declaration(new_path, data),)),
            output=self.root / "binary-copy.json",
        )
        self.assert_verdict(result, report, "FAIL", 2)
        self.assertIn("P_BINARY_AUTH_STATUS", {item["code"] for item in report["diagnostics"]})

    @mock.patch.object(git_inventory, "_entry_is_binary", return_value=False)
    @mock.patch.object(
        git_inventory,
        "tree_object",
        return_value=TreeObject("040000", "tree", "1" * 40, "tools/tree"),
    )
    def test_declared_unsupported_object_mode_remains_forbidden(self, _tree, _binary) -> None:
        entry = ChangedEntry("A", None, None, "tools/tree")
        authorization = BinaryArtifactAuthorization("1" * 64, 1, "tools/tree")
        diagnostics = git_inventory.content_diagnostics(
            Path("."),
            "1" * 40,
            "2" * 40,
            (entry,),
            (authorization,),
        )
        self.assertIn("P_UNSUPPORTED_OBJECT", {item.code for item in diagnostics})

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

    def test_contract_base_sha_mismatch_is_typed_error(self) -> None:
        base, head = self.simple_history()
        result, report, _ = self.invoke(
            base,
            head,
            body=contract_body(base_sha="2" * 40),
        )
        self.assert_verdict(result, report, "ERROR", 3)
        self.assertIn(
            "E_CONTRACT_BASE_SHA",
            {item["code"] for item in report["diagnostics"]},
        )

    def test_shallow_repository_is_error(self) -> None:
        base, head = self.simple_history()
        self.issue.write_text(contract_body(base_sha=base), encoding="utf-8")
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
        self.issue.write_text(contract_body(base_sha=base), encoding="utf-8")
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
        self.issue.write_text(contract_body(base_sha=base), encoding="utf-8")
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
        issue.write_text(contract_body(base_sha=base), encoding="utf-8")
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



class AncestorContractBaseTests(GuardIntegrationCase):
    """Contract base older than the evaluated base (owner proposal, 2026-10)."""

    ALLOWED = "tools/agent-enforcement/example.txt"

    def drifted_history(self, drift_path: str, drift_data: str = "drift\n") -> tuple[str, str, str]:
        self.repo.write(self.ALLOWED, "base\n")
        contract_base = self.repo.commit("contract base")
        self.repo.write(drift_path, drift_data)
        evaluated_base = self.repo.commit("unrelated merge on main")
        self.repo.write(self.ALLOWED, "base\nhead\n")
        return contract_base, evaluated_base, self.repo.commit("task change")

    def codes(self, report) -> set[str]:
        return {item["code"] for item in report["diagnostics"]}

    def test_ancestor_base_with_unrelated_drift_passes(self) -> None:
        contract_base, base, head = self.drifted_history("README.md")
        result, report, _ = self.invoke(base, head, body=contract_body(base_sha=contract_base))
        self.assert_verdict(result, report, "PASS", 0)
        self.assertEqual(base, report["base_sha"])
        self.assertEqual([self.ALLOWED], [item["new_path"] for item in report["changed_entries"]])
        self.assertIn("accepted as first-parent ancestor", result.stderr)

    def test_drift_on_forbidden_path_outside_allowlist_passes(self) -> None:
        contract_base, base, head = self.drifted_history(".github/workflows/ci.yml")
        result, report, _ = self.invoke(base, head, body=contract_body(base_sha=contract_base))
        self.assert_verdict(result, report, "PASS", 0)

    def test_drift_on_allowed_path_is_base_error(self) -> None:
        contract_base, base, head = self.drifted_history("tools/agent-enforcement/other.txt")
        result, report, _ = self.invoke(base, head, body=contract_body(base_sha=contract_base))
        self.assert_verdict(result, report, "ERROR", 3)
        self.assertIn("E_CONTRACT_BASE_SHA", self.codes(report))
        paths = {item.get("path") for item in report["diagnostics"]}
        self.assertIn("tools/agent-enforcement/other.txt", paths)

    def test_rename_out_of_allowlist_in_drift_is_base_error(self) -> None:
        self.repo.write("tools/agent-enforcement/moved.txt", "keep\n" * 20)
        self.repo.write(self.ALLOWED, "base\n")
        contract_base = self.repo.commit("contract base")
        self.repo.remove("tools/agent-enforcement/moved.txt")
        self.repo.write("docs/moved.txt", "keep\n" * 20)
        base = self.repo.commit("rename out of scope")
        self.repo.write(self.ALLOWED, "base\nhead\n")
        head = self.repo.commit("task change")
        result, report, _ = self.invoke(base, head, body=contract_body(base_sha=contract_base))
        self.assert_verdict(result, report, "ERROR", 3)
        self.assertIn("E_CONTRACT_BASE_SHA", self.codes(report))

    def test_non_ancestor_contract_base_is_error(self) -> None:
        self.repo.write(self.ALLOWED, "base\n")
        root = self.repo.commit("root")
        run(["git", "checkout", "-q", "-b", "side"], self.repo.root)
        self.repo.write("README.md", "side\n")
        side = self.repo.commit("side commit")
        run(["git", "checkout", "-q", "-"], self.repo.root)
        self.repo.write("NOTES.md", "main\n")
        base = self.repo.commit("main commit")
        self.repo.write(self.ALLOWED, "base\nhead\n")
        head = self.repo.commit("task change")
        self.assertNotEqual(root, side)
        result, report, _ = self.invoke(base, head, body=contract_body(base_sha=side))
        self.assert_verdict(result, report, "ERROR", 3)
        self.assertIn("E_CONTRACT_BASE_SHA", self.codes(report))

    def test_descendant_contract_base_is_error(self) -> None:
        contract_base, base, head = self.drifted_history("README.md")
        result, report, _ = self.invoke(contract_base, head, body=contract_body(base_sha=base))
        self.assert_verdict(result, report, "ERROR", 3)
        self.assertIn("E_CONTRACT_BASE_SHA", self.codes(report))

    def test_change_later_restored_on_allowed_path_is_base_error(self) -> None:
        self.repo.write(self.ALLOWED, "base\n")
        contract_base = self.repo.commit("contract base")
        self.repo.write(self.ALLOWED, "someone else\n")
        self.repo.commit("other change")
        self.repo.write(self.ALLOWED, "base\n")
        base = self.repo.commit("restored")
        self.repo.write(self.ALLOWED, "base\nhead\n")
        head = self.repo.commit("task change")
        result, report, _ = self.invoke(base, head, body=contract_body(base_sha=contract_base))
        self.assert_verdict(result, report, "ERROR", 3)
        self.assertIn("E_CONTRACT_BASE_SHA", self.codes(report))

    def test_restored_change_through_merge_is_base_error(self) -> None:
        self.repo.write(self.ALLOWED, "base\n")
        contract_base = self.repo.commit("contract base")
        run(["git", "checkout", "-q", "-b", "side"], self.repo.root)
        self.repo.write(self.ALLOWED, "side edit\n")
        self.repo.commit("side edit")
        self.repo.write(self.ALLOWED, "base\n")
        self.repo.commit("side restore")
        run(["git", "checkout", "-q", "-"], self.repo.root)
        self.repo.write("README.md", "main\n")
        self.repo.commit("main moves")
        run(["git", "merge", "-q", "--no-ff", "-m", "merge side", "side"], self.repo.root)
        base = run(["git", "rev-parse", "HEAD"], self.repo.root).stdout.strip()
        self.repo.write(self.ALLOWED, "base\nhead\n")
        head = self.repo.commit("task change")
        result, report, _ = self.invoke(base, head, body=contract_body(base_sha=contract_base))
        self.assert_verdict(result, report, "ERROR", 3)
        self.assertIn("E_CONTRACT_BASE_SHA", self.codes(report))

    def test_side_branch_base_merged_into_target_is_error(self) -> None:
        self.repo.write(self.ALLOWED, "base\n")
        self.repo.commit("root")
        run(["git", "checkout", "-q", "-b", "side"], self.repo.root)
        self.repo.write("NOTES.md", "side\n")
        side = self.repo.commit("side commit")
        run(["git", "checkout", "-q", "-"], self.repo.root)
        self.repo.write("README.md", "main\n")
        self.repo.commit("main moves")
        run(["git", "merge", "-q", "--no-ff", "-m", "merge side", "side"], self.repo.root)
        base = run(["git", "rev-parse", "HEAD"], self.repo.root).stdout.strip()
        self.repo.write(self.ALLOWED, "base\nhead\n")
        head = self.repo.commit("task change")
        result, report, _ = self.invoke(base, head, body=contract_body(base_sha=side))
        self.assert_verdict(result, report, "ERROR", 3)
        self.assertIn("E_CONTRACT_BASE_SHA", self.codes(report))

    def test_former_tip_through_merge_commit_passes(self) -> None:
        self.repo.write(self.ALLOWED, "base\n")
        contract_base = self.repo.commit("contract base")
        run(["git", "checkout", "-q", "-b", "side"], self.repo.root)
        self.repo.write("NOTES.md", "side\n")
        self.repo.commit("side commit")
        run(["git", "checkout", "-q", "-"], self.repo.root)
        run(["git", "merge", "-q", "--no-ff", "-m", "merge side", "side"], self.repo.root)
        base = run(["git", "rev-parse", "HEAD"], self.repo.root).stdout.strip()
        self.repo.write(self.ALLOWED, "base\nhead\n")
        head = self.repo.commit("task change")
        result, report, _ = self.invoke(base, head, body=contract_body(base_sha=contract_base))
        self.assert_verdict(result, report, "PASS", 0)

    def test_deleted_allowed_file_in_drift_is_base_error(self) -> None:
        self.repo.write("tools/agent-enforcement/gone.txt", "x\n")
        self.repo.write(self.ALLOWED, "base\n")
        contract_base = self.repo.commit("contract base")
        self.repo.remove("tools/agent-enforcement/gone.txt")
        base = self.repo.commit("delete allowed file")
        self.repo.write(self.ALLOWED, "base\nhead\n")
        head = self.repo.commit("task change")
        result, report, _ = self.invoke(base, head, body=contract_body(base_sha=contract_base))
        self.assert_verdict(result, report, "ERROR", 3)

    def test_copy_source_changed_in_drift_still_fails(self) -> None:
        source, destination = "legacy/source.mjs", "new/copied.mjs"
        data = ("export const immutable = true;\n" * 24).encode()
        self.repo.write(source, data)
        contract_base = self.repo.commit("contract base")
        changed = data + b"// changed after the contract\n"
        self.repo.write(source, changed)
        base = self.repo.commit("source changed on main")
        self.repo.write(destination, changed)
        head = self.repo.commit("copy")
        declaration = f"{hashlib.sha256(data).hexdigest()} {len(data)} {source}"
        body = contract_body(
            allowed=("new/**",), forbidden=("legacy/**",), copy_sources=(declaration,), base_sha=contract_base
        )
        result, report, _ = self.invoke(base, head, body=body)
        self.assert_verdict(result, report, "FAIL", 2)
        self.assertIn("P_COPY_SOURCE_LENGTH_MISMATCH", {item["code"] for item in report["diagnostics"]})

    def test_binary_authorization_with_ancestor_base_passes(self) -> None:
        path = "tools/agent-enforcement/blob.wasm"
        self.repo.write(self.ALLOWED, "base\n")
        contract_base = self.repo.commit("contract base")
        self.repo.write("README.md", "drift\n")
        base = self.repo.commit("unrelated")
        data = b"wasm\x00authorized-add"
        self.repo.write(path, data)
        head = self.repo.commit("add binary")
        declaration = f"{hashlib.sha256(data).hexdigest()} {len(data)} {path}"
        body = contract_body(binary_artifacts=(declaration,), base_sha=contract_base)
        result, report, _ = self.invoke(base, head, body=body)
        self.assert_verdict(result, report, "PASS", 0)

    def test_trusted_ci_shape_worktree_at_base_passes(self) -> None:
        contract_base, base, head = self.drifted_history("README.md")
        run(["git", "checkout", "-q", base], self.repo.root)
        self.issue.write_text(contract_body(base_sha=contract_base), encoding="utf-8")
        result = subprocess.run(
            ["python3", str(TOOL), "--issue-number", "46", "--issue-body-file", str(self.issue),
             "--base-sha", base, "--head-sha", head, "--worktree-sha", base,
             "--execution-id", "trusted-ancestor", "--output", str(self.output), "--repo", str(self.repo.root)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        report = json.loads(self.output.read_text(encoding="utf-8"))
        self.assert_verdict(result, report, "PASS", 0)
        self.assertEqual(base, report["base_sha"])

    def test_shared_pre_fork_ancestor_is_accepted_graph_rule_only(self) -> None:
        # Documents the accepted limit: the rule is about the graph, not lanes.
        self.repo.write(self.ALLOWED, "base\n")
        shared = self.repo.commit("shared ancestor before a lane fork")
        run(["git", "checkout", "-q", "-b", "lane"], self.repo.root)
        self.repo.write("LANE.md", "lane root\n")
        base = self.repo.commit("lane root")
        self.repo.write(self.ALLOWED, "base\nhead\n")
        head = self.repo.commit("task change")
        result, report, _ = self.invoke(base, head, body=contract_body(base_sha=shared))
        self.assert_verdict(result, report, "PASS", 0)

    def test_shallow_repository_with_ancestor_base_is_error(self) -> None:
        contract_base, base, head = self.drifted_history("README.md")
        clone_root = self.root / "shallow-ancestor"
        run(["git", "clone", "-q", "--depth", "1", f"file://{self.repo.root}", str(clone_root)], self.root)
        self.issue.write_text(contract_body(base_sha=contract_base), encoding="utf-8")
        result = subprocess.run(
            ["python3", str(TOOL), "--issue-number", "46", "--issue-body-file", str(self.issue),
             "--base-sha", base, "--head-sha", head, "--execution-id", "shallow-ancestor",
             "--output", str(self.output), "--repo", str(clone_root)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        report = json.loads(self.output.read_text(encoding="utf-8"))
        self.assert_verdict(result, report, "ERROR", 3)
        self.assertNotIn("accepted as first-parent ancestor", result.stderr)

    def test_shared_rule_rejects_shallow_history_for_direct_callers(self) -> None:
        # The planner calls the shared rule directly, without verify_repository.
        contract_base, base, _head = self.drifted_history("README.md")
        clone_root = self.root / "shallow-direct"
        run(["git", "clone", "-q", "--depth", "3", f"file://{self.repo.root}", str(clone_root)], self.root)
        self.assertIsNone(git_inventory.ancestor_base_problem(self.repo.root, contract_base, base, (self.ALLOWED,)))
        problem = git_inventory.ancestor_base_problem(clone_root, contract_base, base, (self.ALLOWED,))
        self.assertIsNotNone(problem)
        self.assertIn("shallow", problem[0])

    def test_historical_filename_bytes_are_not_trimmed(self) -> None:
        # A drift path ending in a newline must reach validation unchanged:
        # trimming it to "item" would hide its match with "item?".
        contract_base, base, _head = self.drifted_history("tools/agent-enforcement/item\n")
        patterns = (self.ALLOWED, "tools/agent-enforcement/item?")
        try:
            problem = git_inventory.ancestor_base_problem(self.repo.root, contract_base, base, patterns)
        except Exception as exc:  # fail closed through path validation
            problem = (type(exc).__name__, None)
        self.assertIsNotNone(problem)
        self.assertEqual(
            ("tools/agent-enforcement/item\n",),
            tuple(path for path in git_inventory.paths_touched_in_history(self.repo.root, contract_base, base)),
        )

    def test_forbidden_change_in_pr_still_fails_with_ancestor_base(self) -> None:
        self.repo.write(self.ALLOWED, "base\n")
        contract_base = self.repo.commit("contract base")
        self.repo.write("README.md", "drift\n")
        base = self.repo.commit("unrelated")
        self.repo.write(self.ALLOWED, "base\nhead\n")
        self.repo.write(".github/workflows/evil.yml", "on: push\n")
        head = self.repo.commit("task change touching forbidden")
        result, report, _ = self.invoke(base, head, body=contract_body(base_sha=contract_base))
        self.assert_verdict(result, report, "FAIL", 2)
        self.assertIn("P_PATH_FORBIDDEN", self.codes(report))

if __name__ == "__main__":
    unittest.main()
