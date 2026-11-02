from __future__ import annotations

import copy
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
    NATIVE_BASE_SHA,
    SUBTREE,
    TEST_FILES,
    ScopeError,
    _is_allowed,
    _verify_native_read_only,
    _verify_subtree,
    build_report,
)
from inventory import (
    GOVERNANCE_STATE_PATHS,
    GOVERNANCE_STATE_POLICY,
    OWNER_MERGED_GOVERNANCE_STATES,
    governance_state_by_identity,
)

# APP-core's own ratified candidate for the PR-boundary guard: the tip of the M1
# post-merge scope-guard repair (#315). The guard's boundary is the fixed pair
# BASE_SHA..RATIFIED_CANDIDATE_SHA, so the candidate is pinned to APP-core's own
# commit instead of a moving "HEAD". The live integration head also carries
# later commits outside APP-core scope (for example the scope-evidence
# workflow), and diffing those against APP-core's own base makes this suite fail
# for changes APP-core never made.
RATIFIED_CANDIDATE_SHA = "e1538ef9c070e463a8256872a3fd0882c424e2ef"


class ScopeGuardTests(unittest.TestCase):
    def test_only_exact_shared_paths_and_closed_subtree_are_allowed(self) -> None:
        expected_implementation_files = {
            "FOLLOWUPS.md",
            "README.md",
            "RESIDUALS-DISPOSITION.md",
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
            "fixtures/acv049_historical_residual_mutants.json",
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
            "test_o04_evidence_mutants.py",
            "o04_evidence_mutants.json",
            "test_public_boundary_red.py",
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
        self.assertEqual(_verify_subtree(ROOT.parents[2], "HEAD"), (28, 23, 15))

    def test_strict_guard_accepts_actual_candidate_tree(self) -> None:
        report = build_report(
            ROOT.parents[2], BASE_SHA, RATIFIED_CANDIDATE_SHA, "strict"
        )
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["changed_path_count"], 2)
        self.assertEqual(report["implementation_file_count"], 23)
        self.assertEqual(report["test_module_count"], 15)


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
        self._git("read-tree", RATIFIED_CANDIDATE_SHA)
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
        self.assertEqual(
            _verify_native_read_only(
                self.repo,
                NATIVE_BASE_SHA,
                "HEAD",
            ),
            58,
        )

    def test_pr_candidate_with_out_of_scope_path_fails(self) -> None:
        self._replace_blob("styx-js/outside-scope.txt", "negative control\n")
        tree = self._git("write-tree")
        candidate = self._git(
            "-c",
            "user.name=Styx Test",
            "-c",
            "user.email=styx-test.invalid",
            "commit-tree",
            tree,
            "-p",
            BASE_SHA,
            input_text="out-of-scope PR candidate\n",
        )
        with self.assertRaisesRegex(
            ScopeError,
            "changed path is outside ratified scope: styx-js/outside-scope.txt",
        ):
            build_report(self.repo, BASE_SHA, candidate, "strict")

    def test_later_governance_path_is_still_out_of_scope(self) -> None:
        path = ".github/workflows/agent-scope-evidence.yml"
        self._replace_blob(path, "governance change outside APP-core scope\n")
        tree = self._git("write-tree")
        candidate = self._git(
            "-c",
            "user.name=Styx Test",
            "-c",
            "user.email=styx-test.invalid",
            "commit-tree",
            tree,
            "-p",
            BASE_SHA,
            input_text="out-of-scope governance PR candidate\n",
        )
        with self.assertRaisesRegex(
            ScopeError,
            r"changed path is outside ratified scope: "
            r"\.github/workflows/agent-scope-evidence\.yml",
        ):
            build_report(self.repo, BASE_SHA, candidate, "strict")
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
            _verify_native_read_only(self.repo, NATIVE_BASE_SHA, tree)

    def test_changed_repin_blob_identity_fails(self) -> None:
        self._replace_blob(
            "tools/causal-flow-simulator/c03/corpus_model.py",
            "scope-guard changed-repin-identity negative control\n",
        )
        tree = self._git("write-tree")
        with self.assertRaisesRegex(ScopeError, "exact native dependency repin drift"):
            _verify_native_read_only(self.repo, NATIVE_BASE_SHA, tree)

    # Owner-merged governance states: AGENTS.md and the hardening plan must
    # form exactly one listed joint state in the candidate's Git objects.

    def _governance_blob(self, state_id: str, path: str) -> str:
        state = next(
            state for state in OWNER_MERGED_GOVERNANCE_STATES
            if state["stateId"] == state_id
        )
        oid = state["files"][path]["gitBlobOid"]
        present = subprocess.run(
            ["git", "cat-file", "-e", f"{oid}^{{blob}}"],
            cwd=self.repo,
            capture_output=True,
            timeout=60,
        )
        if present.returncode != 0:
            self.skipTest(f"governance blob {oid} of {state_id} is not in this clone")
        return oid

    def _governance_tree(self, agents_state: str, plan_state: str) -> str:
        for path, state_id in zip(GOVERNANCE_STATE_PATHS, (agents_state, plan_state)):
            oid = self._governance_blob(state_id, path)
            self._git("update-index", "--add", "--cacheinfo", "100644", oid, path)
        return self._git("write-tree")

    def test_every_owner_merged_governance_state_passes(self) -> None:
        for state in OWNER_MERGED_GOVERNANCE_STATES:
            with self.subTest(state=state["stateId"]):
                tree = self._governance_tree(state["stateId"], state["stateId"])
                self.assertEqual(
                    _verify_native_read_only(self.repo, NATIVE_BASE_SHA, tree), 58
                )

    def test_mixed_governance_states_fail(self) -> None:
        for agents_state, plan_state in (
            ("BASE_E0AF4E1", "MAIN_PHASE_480_490"),
            ("M3_PROC_497", "MAIN_PHASE_480_490"),
            ("MAIN_PHASE_480_490", "BASE_E0AF4E1"),
        ):
            with self.subTest(agents=agents_state, plan=plan_state):
                tree = self._governance_tree(agents_state, plan_state)
                with self.assertRaisesRegex(ScopeError, "unratified governance state"):
                    _verify_native_read_only(self.repo, NATIVE_BASE_SHA, tree)

    def test_unlisted_governance_bytes_fail(self) -> None:
        for path in GOVERNANCE_STATE_PATHS:
            for label, edit in (
                ("one-byte", lambda data: data + b" "),
                ("normative", lambda data: data.replace(b"human", b"agent", 1)),
                (
                    "phase-exit-block",
                    lambda data: data.replace(
                        b"<!-- styx-protocol-phase-exit-status:v1:start -->", b"", 1
                    ),
                ),
            ):
                with self.subTest(path=path, edit=label):
                    self._git("read-tree", "HEAD")
                    current = subprocess.run(
                        ["git", "cat-file", "blob", f"HEAD:{path}"],
                        cwd=self.repo,
                        capture_output=True,
                        check=True,
                        timeout=60,
                    ).stdout
                    changed = edit(current)
                    self.assertNotEqual(changed, current)
                    oid = subprocess.run(
                        ["git", "hash-object", "-w", "--stdin"],
                        cwd=self.repo,
                        input=changed,
                        capture_output=True,
                        check=True,
                        timeout=60,
                    ).stdout.decode().strip()
                    self._git("update-index", "--add", "--cacheinfo", "100644", oid, path)
                    tree = self._git("write-tree")
                    with self.assertRaisesRegex(ScopeError, "unratified governance state"):
                        _verify_native_read_only(self.repo, NATIVE_BASE_SHA, tree)

    def test_governance_document_mode_drift_fails(self) -> None:
        oid = self._git("rev-parse", "HEAD:AGENTS.md")
        self._git("update-index", "--add", "--cacheinfo", "100755", oid, "AGENTS.md")
        tree = self._git("write-tree")
        with self.assertRaisesRegex(ScopeError, "governance document mode drift"):
            _verify_native_read_only(self.repo, NATIVE_BASE_SHA, tree)

    def test_governance_registry_tampering_fails(self) -> None:
        original = copy.deepcopy(self.registry)
        tamperings = {
            "fourth-state": lambda registry: registry["ownerMergedGovernanceStates"].append(
                copy.deepcopy(registry["ownerMergedGovernanceStates"][1])
                | {"stateId": "EXTRA"}
            ),
            "removed-state": lambda registry: registry["ownerMergedGovernanceStates"].pop(),
            "substituted-sha256": lambda registry: registry[
                "ownerMergedGovernanceStates"
            ][2]["files"]["AGENTS.md"].update(sha256="0" * 64),
            "path-set": lambda registry: registry[
                "ownerMergedGovernanceStatePaths"
            ].pop(),
        }
        for label, tamper in tamperings.items():
            with self.subTest(tampering=label):
                self.registry = copy.deepcopy(original)
                tamper(self.registry)
                self._write_registry()
                with self.assertRaisesRegex(
                    ScopeError, "owner-merged governance state registry drift"
                ):
                    _verify_native_read_only(self.repo, NATIVE_BASE_SHA, "HEAD")

    def test_governance_policy_rows_are_closed(self) -> None:
        original = copy.deepcopy(self.registry)
        for label in ("foreign-path", "repin"):
            with self.subTest(row=label):
                self.registry = copy.deepcopy(original)
                rows = self.registry["dependencies"]
                if label == "foreign-path":
                    row = next(
                        row for row in rows
                        if row["mutationPolicy"] == "READ_ONLY_BYTE_IDENTICAL"
                    )
                    row["mutationPolicy"] = GOVERNANCE_STATE_POLICY
                else:
                    row = next(row for row in rows if row["path"] == "AGENTS.md")
                    row["repin"] = {"reason": "negative control only"}
                self._write_registry()
                with self.assertRaisesRegex(ScopeError, "unauthorized governance-state row"):
                    _verify_native_read_only(self.repo, NATIVE_BASE_SHA, "HEAD")

    def test_governance_states_match_exact_pairs_only(self) -> None:
        identities = {
            state["stateId"]: {
                path: (
                    state["files"][path]["gitBlobOid"],
                    state["files"][path]["byteSize"],
                )
                for path in GOVERNANCE_STATE_PATHS
            }
            for state in OWNER_MERGED_GOVERNANCE_STATES
        }
        agents, plan = GOVERNANCE_STATE_PATHS
        accepted = set()
        for agents_state in identities:
            for plan_state in identities:
                observed = {
                    agents: identities[agents_state][agents],
                    plan: identities[plan_state][plan],
                }
                result = governance_state_by_identity(observed, "gitBlobOid")
                if result is not None:
                    accepted.add((agents, identities[agents_state][agents], plan, identities[plan_state][plan], result))
        self.assertEqual(
            {row[-1] for row in accepted},
            {"BASE_E0AF4E1", "M3_PROC_497", "MAIN_PHASE_480_490"},
        )
        self.assertEqual(len({row[:4] for row in accepted}), 3)
        self.assertIsNone(
            governance_state_by_identity({agents: identities["MAIN_PHASE_480_490"][agents]}, "gitBlobOid")
        )


if __name__ == "__main__":
    unittest.main()
