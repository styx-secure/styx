from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Callable
from unittest.mock import patch


PACKAGE = Path(__file__).resolve().parents[1]
ROOT = PACKAGE.parents[2]
sys.path.insert(0, str(PACKAGE))

from scope_guard import (  # noqa: E402
    BASE_SHA,
    FORBIDDEN_LOCKFILES,
    FORBIDDEN_RUNTIME_MANIFESTS,
    INTEGRATED_SHA,
    INTEGRATED_TREE_SHA,
    ScopeViolation,
    TEST_VALIDATE_SHA256,
    _changed_relation,
    _require_integrated_identity,
    _validate_candidate_ancestry,
    _validate_disposition_disjointness,
    _validate_frozen_bytes,
    _unmanaged_top_level,
    build_integrated_report,
)


class ScopeGuardTests(unittest.TestCase):
    def _git(self, repo: Path, *arguments: str) -> str:
        return subprocess.run(
            ["/usr/bin/git", *arguments],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        ).stdout.strip()

    def _repository(self, initial: dict[str, bytes]) -> tuple[tempfile.TemporaryDirectory[str], Path, str]:
        directory = tempfile.TemporaryDirectory()
        repo = Path(directory.name)
        self._git(repo, "init", "-q")
        self._git(repo, "config", "user.name", "SS-0 Scope Test")
        self._git(repo, "config", "user.email", "ss0-scope@example.invalid")
        initial = dict(initial)
        initial.setdefault("tools/causal-flow-simulator/ss0/.scope-base", b"base\n")
        for name, payload in initial.items():
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        self._git(repo, "add", "--all")
        self._git(repo, "commit", "-q", "-m", "base")
        return directory, repo, self._git(repo, "rev-parse", "HEAD")

    def _commit(self, repo: Path, message: str = "candidate") -> str:
        self._git(repo, "add", "--all")
        self._git(repo, "commit", "-q", "-m", message)
        return self._git(repo, "rev-parse", "HEAD")

    def _assert_changed_relation_rejected(
        self, initial: dict[str, bytes], mutate: Callable[[Path, str], None]
    ) -> None:
        directory, repo, base = self._repository(initial)
        with directory:
            mutate(repo, base)
            head = self._commit(repo)
            with self.assertRaises(ScopeViolation):
                _changed_relation(repo, base, head)

    def test_integrated_committed_projection_is_accepted(self) -> None:
        report = build_integrated_report(ROOT)
        self.assertEqual("PASS", report["result"])

    def test_candidate_ancestry_modes_are_distinct(self) -> None:
        directory, repo, base = self._repository({})
        with directory:
            marker = repo / "tools/causal-flow-simulator/ss0/model-sync.py"
            marker.write_text("SYNC = True\n", encoding="utf-8")
            model_sync = self._commit(repo, "model sync")
            marker.write_text("SYNC = False\n", encoding="utf-8")
            candidate = self._commit(repo, "candidate")
            _validate_candidate_ancestry(repo, base, candidate, model_sync)

            self._git(repo, "checkout", "-q", "-b", "sibling", base)
            marker.write_text("SIBLING = True\n", encoding="utf-8")
            sibling = self._commit(repo, "sibling")
            with self.assertRaises(ScopeViolation):
                _validate_candidate_ancestry(repo, base, sibling, model_sync)

    def test_integrated_identity_substitutions_are_rejected(self) -> None:
        valid_commit = f"{INTEGRATED_SHA} {BASE_SHA}\n".encode("ascii")
        valid_tree = f"{INTEGRATED_TREE_SHA}\n".encode("ascii")
        _require_integrated_identity(valid_commit, valid_tree)
        invalid = (
            (f"{'0' * 40} {BASE_SHA}\n".encode("ascii"), valid_tree),
            (f"{INTEGRATED_SHA} {BASE_SHA} {'1' * 40}\n".encode("ascii"), valid_tree),
            (f"{INTEGRATED_SHA} {'2' * 40}\n".encode("ascii"), valid_tree),
            (f"{INTEGRATED_SHA} {BASE_SHA}\n".encode("ascii"), f"{'3' * 40}\n".encode("ascii")),
        )
        for commit, tree in invalid:
            with self.subTest(commit=commit, tree=tree):
                with self.assertRaises(ScopeViolation):
                    _require_integrated_identity(commit, tree)

    def test_missing_integrated_object_fails_closed(self) -> None:
        with patch("scope_guard._git", side_effect=ScopeViolation("git operation failed")):
            with self.assertRaises(ScopeViolation):
                build_integrated_report(ROOT)

    def test_undeclared_top_level_statement_is_not_hidden(self) -> None:
        declared = frozenset({("assignment", "VALUE"), ("function", "validate")})
        before = ast.parse("VALUE = 1\n\ndef validate():\n    return True\n")
        after = ast.parse(
            "VALUE = 2\n\nif True:\n    UNDECLARED = 1\n\ndef validate():\n    return False\n"
        )
        self.assertNotEqual(
            _unmanaged_top_level(before, declared),
            _unmanaged_top_level(after, declared),
        )

    def test_ratified_test_validate_bytes_are_exact(self) -> None:
        payload = subprocess.run(
            [
                "/usr/bin/git",
                "show",
                f"{INTEGRATED_SHA}:tools/protocol-review-model/tests/test_validate.py",
            ],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
        ).stdout
        self.assertEqual(
            TEST_VALIDATE_SHA256,
            hashlib.sha256(payload).hexdigest(),
        )

    def test_allowed_path_deletion_is_rejected(self) -> None:
        path = "tools/causal-flow-simulator/ss0/deleted.py"
        self._assert_changed_relation_rejected(
            {path: b"value = 1\n"}, lambda repo, _base: (repo / path).unlink()
        )

    def test_copy_and_rename_are_rejected(self) -> None:
        source = "tools/causal-flow-simulator/ss0/source.py"
        for destination, rename in (
            ("tools/causal-flow-simulator/ss0/copied.py", False),
            ("tools/causal-flow-simulator/ss0/renamed.py", True),
        ):
            def mutate(repo: Path, _base: str, *, target: str = destination, move: bool = rename) -> None:
                payload = (repo / source).read_bytes()
                (repo / target).write_bytes(payload)
                if move:
                    (repo / source).unlink()

            self._assert_changed_relation_rejected({source: b"value = 1\n"}, mutate)

    def test_symlink_binary_and_submodule_are_rejected(self) -> None:
        def symlink(repo: Path, _base: str) -> None:
            os.symlink("model.py", repo / "tools/causal-flow-simulator/ss0/link.py")

        self._assert_changed_relation_rejected({}, symlink)

        def binary(repo: Path, _base: str) -> None:
            path = repo / "tools/causal-flow-simulator/ss0/binary.dat"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"binary\0payload")

        self._assert_changed_relation_rejected({}, binary)

        directory, repo, base = self._repository({})
        with directory:
            self._git(
                repo,
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{base},tools/causal-flow-simulator/ss0/submodule",
            )
            self._git(repo, "commit", "-q", "-m", "candidate")
            head = self._git(repo, "rev-parse", "HEAD")
            with self.assertRaises(ScopeViolation):
                _changed_relation(repo, base, head)

    def test_every_required_lockfile_classifier_is_rejected(self) -> None:
        names = sorted({"custom.lock", *FORBIDDEN_LOCKFILES})
        for leaf in names:
            with self.subTest(leaf=leaf):
                def add_lock(repo: Path, _base: str, *, name: str = leaf) -> None:
                    path = repo / "tools/causal-flow-simulator/ss0" / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("locked\n", encoding="utf-8")

                self._assert_changed_relation_rejected({}, add_lock)

    def test_runtime_manifests_are_rejected(self) -> None:
        for leaf in sorted(FORBIDDEN_RUNTIME_MANIFESTS):
            with self.subTest(leaf=leaf):
                def add_manifest(repo: Path, _base: str, *, name: str = leaf) -> None:
                    path = repo / "tools/causal-flow-simulator/ss0" / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("manifest\n", encoding="utf-8")

                self._assert_changed_relation_rejected({}, add_manifest)

    def test_out_of_scope_addition_is_rejected(self) -> None:
        def add_outside(repo: Path, _base: str) -> None:
            (repo / "outside.py").write_text("value = 1\n", encoding="utf-8")

        self._assert_changed_relation_rejected({}, add_outside)

    def test_frozen_byte_drift_is_rejected(self) -> None:
        path = "docs/protocol/protocol-hardening-plan.md"
        directory, repo, base = self._repository({path: b"frozen\n"})
        with directory:
            (repo / path).write_bytes(b"changed\n")
            head = self._commit(repo)
            with self.assertRaises(ScopeViolation):
                _validate_frozen_bytes(repo, base, head, frozenset({path}))

    def test_ss0_dispositions_must_be_disjoint_from_o10(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            ss0 = repo / "tools/causal-flow-simulator/ss0"
            o10 = repo / "tools/causal-flow-simulator/o10"
            ss0.mkdir(parents=True)
            o10.mkdir(parents=True)
            (ss0 / "source-inventory.json").write_text(
                json.dumps({"closed_dispositions": ["APPLIED"]}), encoding="utf-8"
            )
            (o10 / "outcome-taxonomy.json").write_text(
                json.dumps(
                    {
                        "alias": {"id": "FORK_QUARANTINED", "primary": "LINEAGE_QUARANTINED"},
                        "post_c03_markers": [],
                        "primaries": [{"id": "APPLIED"}],
                        "remote_collapse": "OPAQUE_REMOTE_FAILURE",
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ScopeViolation):
                _validate_disposition_disjointness(repo)

    def test_valid_in_scope_addition_and_modification_pass(self) -> None:
        existing = "tools/causal-flow-simulator/ss0/existing.py"
        added = "tools/causal-flow-simulator/ss0/added.py"
        directory, repo, base = self._repository({existing: b"value = 1\n"})
        with directory:
            (repo / existing).write_bytes(b"value = 2\n")
            (repo / added).write_bytes(b"added = True\n")
            head = self._commit(repo)
            relation = _changed_relation(repo, base, head)
            self.assertEqual(2, len(relation))


if __name__ == "__main__":
    unittest.main()
