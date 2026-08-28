from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scope_guard import CORPUS_FILES, SYNC_FILES, TOOL_FILES, allowed  # noqa: E402


class ScopeGuardTests(unittest.TestCase):
    def test_closed_package_sets_and_forbidden_neighbors(self) -> None:
        self.assertEqual(len(CORPUS_FILES), 6)
        self.assertEqual(len(TOOL_FILES), 20)
        self.assertEqual(len(SYNC_FILES), 6)
        self.assertTrue(allowed("conformance/application-protocol/c03/manifest.json"))
        self.assertTrue(allowed("tools/causal-flow-simulator/c03/tests/test_scope_guard.py"))
        for path in (
            "conformance/application-protocol/c03/seventh.json",
            "tools/causal-flow-simulator/o10/outcome-taxonomy.json",
            "styx-js/src/index.js",
            ".github/workflows/ci.yml",
        ):
            with self.subTest(path=path):
                self.assertFalse(allowed(path))

    def test_every_declared_endpoint_maps_back_to_one_inventory(self) -> None:
        corpus_paths = {f"conformance/application-protocol/c03/{name}" for name in CORPUS_FILES}
        tool_paths = {f"tools/causal-flow-simulator/c03/{name}" for name in TOOL_FILES}
        declared = corpus_paths | tool_paths | set(SYNC_FILES)
        self.assertEqual(len(declared), 32)
        for endpoint in sorted(declared):
            with self.subTest(endpoint=endpoint):
                self.assertTrue(allowed(endpoint))
                self.assertFalse(endpoint.startswith("/"))
                self.assertNotIn("..", endpoint.split("/"))
                self.assertNotIn("__pycache__", endpoint)

    def test_lockfiles_and_sensitive_boundaries_never_match(self) -> None:
        forbidden = {
            "AGENTS.md", "CODEOWNERS", "REUSE.toml",
            "docs/protocol/styx-app-kernel-v0-decisions.md",
            "tools/causal-flow-simulator/o06c/integrated_model.py",
            "tools/causal-flow-simulator/o07/genesis_model.py",
            "tools/causal-flow-simulator/o08/envelope_model.py",
            "tools/causal-flow-simulator/o10/taxonomy_model.py",
            "tools/causal-flow-simulator/o14/model.py",
            "styx-js/package-lock.json", "packages/styx/pubspec.lock",
        }
        self.assertFalse(any(allowed(path) for path in forbidden))


if __name__ == "__main__":
    unittest.main()
