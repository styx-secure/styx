from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scope_guard import ALLOWED, NEW, PINS, allowed  # noqa: E402


class ScopeGuardTests(unittest.TestCase):
    def test_closed_package_a_relation_and_forbidden_neighbors(self) -> None:
        self.assertEqual(len(PINS), 8)
        self.assertEqual(len(NEW), 2)
        self.assertEqual(len(ALLOWED), 10)
        self.assertTrue(allowed("tools/causal-flow-simulator/c03/corpus_model.py"))
        self.assertTrue(allowed("tools/causal-flow-simulator/c03/tests/test_scope_guard.py"))
        for path in (
            "conformance/application-protocol/c03/manifest.json",
            "tools/causal-flow-simulator/o10/outcome-taxonomy.json",
            "styx-js/src/index.js",
            ".github/workflows/ci.yml",
        ):
            with self.subTest(path=path):
                self.assertFalse(allowed(path))

    def test_every_declared_endpoint_maps_back_to_one_inventory(self) -> None:
        self.assertEqual(ALLOWED, set(PINS) | NEW)
        for endpoint in sorted(ALLOWED):
            with self.subTest(endpoint=endpoint):
                self.assertTrue(allowed(endpoint))
                self.assertFalse(endpoint.startswith("/"))
                self.assertNotIn("..", endpoint.split("/"))
                self.assertNotIn("__pycache__", endpoint)

    def test_lockfiles_and_sensitive_boundaries_never_match(self) -> None:
        forbidden = {
            "AGENTS.md", "CODEOWNERS", "REUSE.toml",
            "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md",
            "tools/causal-flow-simulator/o06c/integrated_model.py",
            "tools/causal-flow-simulator/o07/genesis_model.py",
            "tools/causal-flow-simulator/o08/envelope_model.py",
            "tools/causal-flow-simulator/o10/taxonomy_model.py",
            "tools/causal-flow-simulator/o14/model.py",
            "tools/causal-flow-simulator/c03/generate_corpus.py",
            "styx-js/package-lock.json", "packages/styx/pubspec.lock",
        }
        self.assertFalse(any(allowed(path) for path in forbidden))


if __name__ == "__main__":
    unittest.main()
