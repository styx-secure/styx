from __future__ import annotations

import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scope_guard import PACKAGE_FILES, _allowed


class ScopeGuardTests(unittest.TestCase):
    def test_exact_final_package_inventory(self):
        self.assertEqual(len(PACKAGE_FILES), 29)
        self.assertIn("resource-envelope.candidate.json", PACKAGE_FILES)
        self.assertNotIn("__pycache__", PACKAGE_FILES)

    def test_allowed_paths_are_closed(self):
        self.assertTrue(_allowed("tools/causal-flow-simulator/o08/envelope_model.py"))
        self.assertFalse(_allowed("styx-js/src/crypto/forbidden.js"))


if __name__ == "__main__":
    unittest.main()
