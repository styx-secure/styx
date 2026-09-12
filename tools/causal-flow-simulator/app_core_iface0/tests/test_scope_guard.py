from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scope_guard import (
    BASE_SHA,
    EXACT_MUTABLE,
    IMPLEMENTATION_FILES,
    SUBTREE,
    TEST_FILES,
    ScopeError,
    _is_allowed,
    _verify_native_read_only,
    _verify_subtree,
)


class ScopeGuardTests(unittest.TestCase):
    def test_only_exact_shared_paths_and_closed_subtree_are_allowed(self) -> None:
        expected_implementation_files = {
            "README.md",
            "authority_projection.py",
            "authority_witness.py",
            "canonical_json.py",
            "canonical_report.py",
            "derive_interface_maxima.py",
            "final_gate.py",
            "generate_seed_registry.py",
            "generate_structural_witnesses.py",
            "interface_model.py",
            "inventory.py",
            "node_adapter.mjs",
            "run_cross_runtime.py",
            "run_mutations.py",
            "run_probe.py",
            "run_semantic_acv048.py",
            "run_semantic_acv049.py",
            "run_semantic_preflight.py",
            "run_structural_cross_runtime.py",
            "scope_guard.py",
            "validate_inventory.py",
        }
        expected_test_files = {
            "release-relation-requests.json",
            "test_authority_projection.py",
            "test_canonical_json.py",
            "test_contract_package.py",
            "test_cross_runtime.py",
            "test_final_gate.py",
            "test_interface_maxima.py",
            "test_interface_model.py",
            "test_inventory.py",
            "test_mutations.py",
            "test_release_relations.py",
            "test_report_hygiene.py",
            "test_scope_guard.py",
            "test_structural_isolation_relation.py",
        }
        for path in EXACT_MUTABLE:
            self.assertTrue(_is_allowed(path))
        self.assertTrue(_is_allowed("tools/causal-flow-simulator/app_core_iface0/README.md"))
        self.assertTrue(_is_allowed("tools/causal-flow-simulator/c03/corpus_model.py"))
        self.assertTrue(_is_allowed("tools/causal-flow-simulator/o07/genesis_model.py"))
        self.assertTrue(_is_allowed("tools/causal-flow-simulator/o08/envelope_model.py"))
        self.assertTrue(_is_allowed("conformance/application-protocol/c03/manifest.json"))
        self.assertTrue(_is_allowed("tools/protocol-review-model/tests/test_validate.py"))
        self.assertFalse(_is_allowed("docs/protocol/styx-app-core-interface-v0.md"))
        self.assertFalse(_is_allowed("tools/causal-flow-simulator/o10/taxonomy.py"))
        self.assertFalse(_is_allowed("styx-js/src/adapter.js"))
        self.assertEqual(IMPLEMENTATION_FILES, expected_implementation_files)
        self.assertEqual(TEST_FILES, expected_test_files)

    def test_real_git_tree_counts_python_modules_without_json_fixture(self) -> None:
        self.assertEqual(_verify_subtree(ROOT.parents[2], "HEAD"), (28, 21, 13))


class GitObjectScopeGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name) / "objects-repo"
        subprocess.run(
            ["git", "clone", "--bare", "--shared", "--quiet", str(ROOT.parents[2]), str(self.repo)],
            check=True,
            capture_output=True,
            timeout=60,
        )
        self._git("read-tree", "HEAD")
        name = "APP-CORE-IFACE-0-NATIVE-DEPENDENCIES-CANDIDATE.json"
        self.registry = json.loads((ROOT / "contract" / name).read_text())
        self.registry_path = self.repo / SUBTREE / "contract" / name
        self.registry_path.parent.mkdir(parents=True)
        self._write_registry()

    def _git(self, *arguments: str, input_text: str | None = None) -> str:
        return subprocess.run(
            ["git", *arguments],
            cwd=self.repo,
            input=input_text,
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        ).stdout.strip()

    def _write_registry(self) -> None:
        self.registry_path.write_text(json.dumps(self.registry) + "\n")

    def _replace_blob(self, path: str, content: str) -> str:
        oid = self._git("hash-object", "-w", "--stdin", input_text=content)
        self._git("update-index", "--add", "--cacheinfo", "100644", oid, path)
        return oid

    def test_omitting_either_ratified_leaf_fails(self) -> None:
        for leaf in ("release-relation-requests.json", "test_release_relations.py"):
            with self.subTest(leaf=leaf):
                self._git("read-tree", "HEAD")
                self._git(
                    "update-index", "--index-info",
                    input_text="0 " + "0" * 40 + "\t" + SUBTREE + "tests/" + leaf + "\n",
                )
                tree = self._git("write-tree")
                with self.assertRaisesRegex(ScopeError, "APP-core test-module set mismatch"):
                    _verify_subtree(self.repo, tree)

    def test_unexpected_extra_test_leaf_fails(self) -> None:
        self._replace_blob(SUBTREE + "tests/unexpected.json", "{}\n")
        tree = self._git("write-tree")
        with self.assertRaisesRegex(ScopeError, "APP-core test-module set mismatch"):
            _verify_subtree(self.repo, tree)

    def test_original_git_objects_preserve_exact_native_repin(self) -> None:
        self.assertEqual(_verify_native_read_only(self.repo, BASE_SHA, "HEAD"), 60)

    def test_second_native_repin_fails(self) -> None:
        row = next(
            row for row in self.registry["dependencies"]
            if row["mutationPolicy"] == "SEEDED_EXTENSION_ONLY_PRESERVE_BASE_SEMANTICS"
        )
        content = "scope-guard second-repin negative control\n"
        oid = self._replace_blob(row["path"], content)
        row["mutationPolicy"] = "RATIFIED_H12_H3_EXACT_REPIN"
        row["repin"] = {
            "oldSha256": row["sha256"],
            "newSha256": hashlib.sha256(content.encode()).hexdigest(),
            "newGitBlobOid": oid,
            "newByteSize": len(content.encode()),
            "reason": "negative control only",
        }
        self._write_registry()
        tree = self._git("write-tree")
        with self.assertRaisesRegex(ScopeError, "ratified exact native dependency repin set drift"):
            _verify_native_read_only(self.repo, BASE_SHA, tree)

    def test_changed_repin_blob_identity_fails(self) -> None:
        self._replace_blob(
            "tools/causal-flow-simulator/c03/corpus_model.py",
            "scope-guard changed-repin-identity negative control\n",
        )
        tree = self._git("write-tree")
        with self.assertRaisesRegex(ScopeError, "exact native dependency repin drift"):
            _verify_native_read_only(self.repo, BASE_SHA, tree)


if __name__ == "__main__":
    unittest.main()
