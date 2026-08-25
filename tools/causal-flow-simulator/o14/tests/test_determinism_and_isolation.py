from __future__ import annotations

import ast
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from common import canonical_bytes
from mutation_harness_o14 import build_report as build_mutation_report
from signature_suite_probe import build_report as build_probe_report


class DeterminismAndIsolationTest(unittest.TestCase):
    def test_reports_are_byte_deterministic(self) -> None:
        first, _ = build_probe_report()
        second, _ = build_probe_report()
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))
        first_mutations, _ = build_mutation_report()
        second_mutations, _ = build_mutation_report()
        self.assertEqual(
            canonical_bytes(first_mutations), canonical_bytes(second_mutations)
        )

    def test_python_package_has_no_product_imports(self) -> None:
        forbidden = {"styx_js", "packages", "push_bridge_server"}
        for path in ROOT.glob("*.py"):
            tree = ast.parse(path.read_bytes(), filename=str(path))
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split(".")[0])
            self.assertFalse(imported & forbidden, path.name)


if __name__ == "__main__":
    unittest.main()
