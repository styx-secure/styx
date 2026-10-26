from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from inventory import (
    CONTRACT_FILES,
    GOVERNANCE_STATE_PATHS,
    GOVERNANCE_STATE_POLICY,
    OWNER_MERGED_GOVERNANCE_STATES,
    InventoryError,
    verify_contract_package,
)
from unittest.mock import patch


class ContractPackageTests(unittest.TestCase):
    @staticmethod
    def _semantic_validator_and_documents():
        validator_path = ROOT / "contract" / "validate_app_core_contract_candidates.py"
        spec = importlib.util.spec_from_file_location("app_core_contract_validator", validator_path)
        assert spec is not None
        assert spec.loader is not None
        validator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(validator)
        schema = json.loads(
            (ROOT / "contract" / "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json").read_text()
        )
        semantics = json.loads(
            (ROOT / "contract" / "APP-CORE-IFACE-0-SEMANTIC-CONSTRAINTS-CANDIDATE.json").read_text()
        )
        return validator, schema, semantics

    def test_exact_ratified_package_passes(self) -> None:
        manifest = verify_contract_package(ROOT / "contract")
        self.assertEqual(len(manifest["artifacts"]), 27)
        self.assertEqual(len(list((ROOT / "contract").iterdir())), CONTRACT_FILES)

    def test_missing_extra_symlink_and_altered_bytes_fail_closed(self) -> None:
        for mutation in ("missing", "extra", "symlink", "altered"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                package = Path(raw) / "contract"
                shutil.copytree(ROOT / "contract", package)
                target = package / "APP-CORE-FLOW-CLOSURE.md"
                if mutation == "missing":
                    target.unlink()
                elif mutation == "extra":
                    (package / "unexpected.txt").write_text("x", encoding="utf-8")
                elif mutation == "symlink":
                    target.unlink()
                    target.symlink_to("APP-CORE-EVIDENCE-UPDATE-CANDIDATE.md")
                else:
                    target.write_bytes(target.read_bytes() + b"x")
                with self.assertRaises((InventoryError, FileNotFoundError)):
                    verify_contract_package(package)

    def test_every_semantic_target_resolves_and_dangling_target_fails_closed(self) -> None:
        validator, schema, semantics = self._semantic_validator_and_documents()
        validator.validate_semantic_targets(schema, semantics)

        dangling = copy.deepcopy(semantics)
        dangling["rules"][0]["targets"][0] = "$defs.DoesNotExist"
        with self.assertRaisesRegex(SystemExit, "unresolved semantic target"):
            validator.validate_semantic_targets(schema, dangling)

    def test_nested_semantic_dimensions_must_resolve(self) -> None:
        validator, schema, semantics = self._semantic_validator_and_documents()
        mutated = copy.deepcopy(semantics)
        rule = next(
            row
            for row in mutated["rules"]
            if "targetDimensions" in row.get("parameters", {})
        )
        first_target = next(iter(rule["parameters"]["targetDimensions"]))
        rule["parameters"]["targetDimensions"][first_target] = "DOES_NOT_EXIST"
        with self.assertRaisesRegex(SystemExit, "unresolved semantic dimension"):
            validator.validate_semantic_targets(schema, mutated)

    def test_semantic_targets_cannot_end_at_schema_keywords(self) -> None:
        validator, schema, semantics = self._semantic_validator_and_documents()
        mutated = copy.deepcopy(semantics)
        mutated["rules"][0]["targets"][0] = "$defs.InterfaceLimitsV0.required"
        with self.assertRaisesRegex(SystemExit, "unresolved semantic target"):
            validator.validate_semantic_targets(schema, mutated)


class OwnerMergedGovernanceStateTests(unittest.TestCase):
    NAME = "APP-CORE-IFACE-0-NATIVE-DEPENDENCIES-CANDIDATE.json"

    @staticmethod
    def _load_contract_module(package: Path, name: str):
        spec = importlib.util.spec_from_file_location(
            f"app_core_{package.name}_{name}", package / f"{name}.py"
        )
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_derivator_registry_and_shared_constants_are_identical(self) -> None:
        derivator = self._load_contract_module(
            ROOT / "contract", "derive_app_core_native_dependencies"
        )
        self.assertEqual(derivator.GOVERNANCE, GOVERNANCE_STATE_PATHS)
        self.assertEqual(derivator.GOVERNANCE_STATE_POLICY, GOVERNANCE_STATE_POLICY)
        self.assertEqual(
            derivator.OWNER_MERGED_GOVERNANCE_STATES, OWNER_MERGED_GOVERNANCE_STATES
        )
        registry = json.loads((ROOT / "contract" / self.NAME).read_text())
        self.assertEqual(
            registry["ownerMergedGovernanceStatePaths"], list(GOVERNANCE_STATE_PATHS)
        )
        self.assertEqual(
            registry["ownerMergedGovernanceStates"],
            [
                {
                    "stateId": state["stateId"],
                    "provenance": state["provenance"],
                    "files": {
                        path: state["files"][path] for path in GOVERNANCE_STATE_PATHS
                    },
                }
                for state in OWNER_MERGED_GOVERNANCE_STATES
            ],
        )
        policies = {}
        for row in registry["dependencies"]:
            policies[row["mutationPolicy"]] = policies.get(row["mutationPolicy"], 0) + 1
        self.assertEqual(
            policies,
            {
                "READ_ONLY_BYTE_IDENTICAL": 58,
                GOVERNANCE_STATE_POLICY: 2,
                "SEEDED_EXTENSION_ONLY_PRESERVE_BASE_SEMANTICS": 4,
                "RATIFIED_H12_H3_EXACT_REPIN": 1,
            },
        )
        base = OWNER_MERGED_GOVERNANCE_STATES[0]
        for row in registry["dependencies"]:
            if row["mutationPolicy"] == GOVERNANCE_STATE_POLICY:
                self.assertNotIn("repin", row)
                self.assertEqual(
                    base["files"][row["path"]],
                    {
                        "gitBlobOid": row["gitBlobOid"],
                        "sha256": row["sha256"],
                        "byteSize": row["byteSize"],
                    },
                )

    def test_validator_structure_rejects_governance_tampering(self) -> None:
        def fourth(registry):
            extra = copy.deepcopy(registry["ownerMergedGovernanceStates"][1])
            extra["stateId"] = "EXTRA"
            registry["ownerMergedGovernanceStates"].append(extra)

        def removed(registry):
            registry["ownerMergedGovernanceStates"].pop(1)

        def duplicated(registry):
            registry["ownerMergedGovernanceStates"][2]["files"] = copy.deepcopy(
                registry["ownerMergedGovernanceStates"][1]["files"]
            )

        def bad_oid(registry):
            registry["ownerMergedGovernanceStates"][2]["files"]["AGENTS.md"][
                "gitBlobOid"
            ] = "XYZ"

        def base_differs(registry):
            registry["ownerMergedGovernanceStates"][0]["files"]["AGENTS.md"][
                "byteSize"
            ] += 1

        def foreign_policy(registry):
            row = next(
                row for row in registry["dependencies"]
                if row["mutationPolicy"] == "READ_ONLY_BYTE_IDENTICAL"
            )
            row["mutationPolicy"] = GOVERNANCE_STATE_POLICY

        def governance_repin(registry):
            row = next(row for row in registry["dependencies"] if row["path"] == "AGENTS.md")
            row["repin"] = {"reason": "negative control only"}

        cases = (
            (fourth, "owner-merged governance state relation drift"),
            (removed, "owner-merged governance state relation drift"),
            (duplicated, "duplicate owner-merged governance state"),
            (bad_oid, "owner-merged governance state relation drift"),
            (base_differs, "Base governance state drift"),
            (foreign_policy, "owner-merged governance state path drift"),
            (governance_repin, "owner-merged governance state path drift"),
        )
        for tamper, expected in cases:
            with self.subTest(tampering=tamper.__name__), tempfile.TemporaryDirectory() as raw:
                package = Path(raw) / "contract"
                shutil.copytree(ROOT / "contract", package)
                registry = json.loads((package / self.NAME).read_text())
                tamper(registry)
                (package / self.NAME).write_text(json.dumps(registry), encoding="utf-8")
                validator = self._load_contract_module(
                    package, "validate_app_core_contract_candidates"
                )
                # Bypass only the derivation subprocess so the structural check
                # under test, not the byte-identity check, must reject.
                with patch.object(validator.subprocess, "run"):
                    with self.assertRaisesRegex(SystemExit, expected):
                        validator.validate_native_dependencies(
                            ROOT.parents[2], "e0af4e1e2173deb2481eabdb24d8622282b33455"
                        )

    def test_derivator_requires_exactly_one_owner_merged_state(self) -> None:
        derivator = self._load_contract_module(
            ROOT / "contract", "derive_app_core_native_dependencies"
        )
        repo = ROOT.parents[2]
        with tempfile.TemporaryDirectory() as raw:
            checkout = Path(raw) / "checkout"
            subprocess.run(
                ["git", "clone", "--quiet", "--shared", str(repo), str(checkout)],
                check=True,
            )
            head = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=repo, check=True,
                capture_output=True, text=True,
            ).stdout.strip()
            subprocess.run(
                ["git", "checkout", "--quiet", "--detach", head], cwd=checkout, check=True
            )
            base = "e0af4e1e2173deb2481eabdb24d8622282b33455"
            relation, state = derivator.derive(checkout, base)
            self.assertIn(state, {row["stateId"] for row in OWNER_MERGED_GOVERNANCE_STATES})
            self.assertEqual(
                derivator.canonical_bytes(relation),
                (ROOT / "contract" / self.NAME).read_bytes(),
            )
            agents, plan = (checkout / path for path in GOVERNANCE_STATE_PATHS)
            originals = {path: path.read_bytes() for path in (agents, plan)}
            base_blobs = {
                path: subprocess.run(
                    ["git", "cat-file", "blob", f"{base}:{path}"], cwd=checkout,
                    check=True, capture_output=True,
                ).stdout
                for path in GOVERNANCE_STATE_PATHS
            }
            agents.write_bytes(base_blobs[GOVERNANCE_STATE_PATHS[0]])
            plan.write_bytes(base_blobs[GOVERNANCE_STATE_PATHS[1]])
            self.assertEqual(derivator.derive(checkout, base)[1], "BASE_E0AF4E1")
            for label, agents_bytes, plan_bytes in (
                ("one-byte", originals[agents] + b" ", originals[plan]),
                ("plan-normative", originals[agents], originals[plan].replace(b"human", b"agent", 1)),
                ("mixed-base-agents", base_blobs[GOVERNANCE_STATE_PATHS[0]], originals[plan]),
            ):
                if (agents_bytes, plan_bytes) in {
                    (originals[agents], originals[plan]),
                    tuple(base_blobs[path] for path in GOVERNANCE_STATE_PATHS),
                }:
                    continue
                with self.subTest(case=label):
                    agents.write_bytes(agents_bytes)
                    plan.write_bytes(plan_bytes)
                    with self.assertRaisesRegex(SystemExit, "unratified governance state"):
                        derivator.derive(checkout, base)
            agents.write_bytes(originals[agents])
            plan.write_bytes(originals[plan])

    def test_tampered_registry_fails_artifact_digest_and_manifest_pin(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            package = Path(raw) / "contract"
            shutil.copytree(ROOT / "contract", package)
            registry = json.loads((package / self.NAME).read_text())
            registry["ownerMergedGovernanceStates"][1]["provenance"] += " (tampered)"
            data = (json.dumps(registry, indent=2, ensure_ascii=False) + "\n").encode()
            (package / self.NAME).write_bytes(data)
            with self.assertRaisesRegex(InventoryError, "contract artifact digest mismatch"):
                verify_contract_package(package)
            manifest_path = package / "APP-CORE-IFACE-0-CANDIDATE-MANIFEST.json"
            manifest_text = manifest_path.read_text(encoding="utf-8")
            old = next(
                row["sha256"]
                for row in json.loads(manifest_text)["artifacts"]
                if row["path"] == self.NAME
            )
            manifest_path.write_text(
                manifest_text.replace(old, hashlib.sha256(data).hexdigest()),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(InventoryError, "ratified manifest digest mismatch"):
                verify_contract_package(package)


if __name__ == "__main__":
    unittest.main()
