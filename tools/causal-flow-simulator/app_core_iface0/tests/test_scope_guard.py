from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scope_guard import EXACT_MUTABLE, IMPLEMENTATION_FILES, TEST_FILES, _is_allowed


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
            "test_authority_projection.py",
            "test_canonical_json.py",
            "test_contract_package.py",
            "test_cross_runtime.py",
            "test_final_gate.py",
            "test_interface_maxima.py",
            "test_interface_model.py",
            "test_inventory.py",
            "test_mutations.py",
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


if __name__ == "__main__":
    unittest.main()
