from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scope_guard import EXACT_MUTABLE, IMPLEMENTATION_FILES, TEST_FILES, _is_allowed


class ScopeGuardTests(unittest.TestCase):
    def test_only_exact_shared_paths_and_closed_subtree_are_allowed(self) -> None:
        for path in EXACT_MUTABLE:
            self.assertTrue(_is_allowed(path))
        self.assertTrue(_is_allowed("tools/causal-flow-simulator/app_core_iface0/README.md"))
        self.assertFalse(_is_allowed("tools/causal-flow-simulator/o10/taxonomy.py"))
        self.assertFalse(_is_allowed("styx-js/src/adapter.js"))
        self.assertEqual(len(IMPLEMENTATION_FILES), 15)
        self.assertEqual(len(TEST_FILES), 10)


if __name__ == "__main__":
    unittest.main()
