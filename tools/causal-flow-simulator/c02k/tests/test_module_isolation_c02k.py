from __future__ import annotations

import ast
from pathlib import Path
import unittest


C02K_ROOT = Path(__file__).resolve().parents[1]


class ModuleIsolationTests(unittest.TestCase):
    def test_c02k_does_not_import_historical_or_product_modules(self) -> None:
        forbidden = {
            "causal_flow_simulator",
            "causal_flow_simulator_v2",
            "causal_flow_simulator_v3",
            "kernel_model_v2",
            "protocol_model_v3",
            "scenarios",
            "scenarios_v2",
            "scenarios_v3",
        }
        for path in sorted(C02K_ROOT.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            imports: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module)
            self.assertFalse(imports & forbidden, f"{path}: {imports & forbidden}")

    def test_c02k_uses_only_standard_library_and_local_c02k_modules(self) -> None:
        allowed_roots = {
            "__future__",
            "argparse",
            "commitment_context_model",
            "dataclasses",
            "hashlib",
            "json",
            "pathlib",
            "scenarios_c02k",
            "sys",
            "typing",
        }
        for path in sorted(C02K_ROOT.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            imports: set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module.split(".")[0])
            self.assertLessEqual(imports, allowed_roots, f"{path}: {imports - allowed_roots}")

    def test_sources_do_not_read_historical_or_repository_files(self) -> None:
        forbidden_fragments = (
            "../",
            "/v2/",
            "/v3/",
            "docs/",
            "styx-js/",
            "packages/",
        )
        for path in sorted(C02K_ROOT.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            for fragment in forbidden_fragments:
                self.assertNotIn(fragment, source, f"{path}: {fragment}")


if __name__ == "__main__":
    unittest.main()
