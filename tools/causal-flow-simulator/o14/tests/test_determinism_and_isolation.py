from __future__ import annotations

import ast
import math
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evidence_io import CanonicalJsonReport
from cross_runtime_gate import ADAPTER_VECTOR_FIELDS, adapter_vector, public_failure
from mutation_harness_o14 import build_report as build_mutation_report
from signature_suite_probe import build_report as build_probe_report


class DeterminismAndIsolationTest(unittest.TestCase):
    def test_reports_are_byte_deterministic(self) -> None:
        first, _ = build_probe_report()
        second, _ = build_probe_report()
        self.assertEqual(CanonicalJsonReport.encode(first), CanonicalJsonReport.encode(second))
        first_mutations, _ = build_mutation_report()
        second_mutations, _ = build_mutation_report()
        self.assertEqual(
            CanonicalJsonReport.encode(first_mutations),
            CanonicalJsonReport.encode(second_mutations),
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

    def test_adapter_projection_excludes_oracle_outputs(self) -> None:
        probe, _ = build_probe_report()
        for vector in probe["runtime_vectors"]:
            projected = adapter_vector(vector)
            self.assertEqual(tuple(projected), ADAPTER_VECTOR_FIELDS)
            self.assertEqual(set(projected), set(ADAPTER_VECTOR_FIELDS))
            self.assertFalse(any(key.startswith("oracle_") for key in projected))

    def test_canonical_evidence_rejects_every_float(self) -> None:
        for value in (0.0, math.nan, math.inf, {"nested": [1, -math.inf]}):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    CanonicalJsonReport.encode(value)

    def test_public_failure_does_not_expose_os_paths(self) -> None:
        error = OSError(2, "missing", "/tmp/styx-random-workspace/secret")
        message = public_failure(error)
        self.assertEqual(message, "operating system error (errno=2)")
        self.assertNotIn("/tmp/", message)


if __name__ == "__main__":
    unittest.main()
