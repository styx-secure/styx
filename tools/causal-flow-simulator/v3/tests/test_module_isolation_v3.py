from __future__ import annotations

import ast
from pathlib import Path
import unittest


V3_ROOT = Path(__file__).resolve().parents[1]


class ModuleIsolationTests(unittest.TestCase):
    def test_v3_does_not_import_historical_simulators(self) -> None:
        forbidden = {"kernel_model_v2", "scenarios_v2", "kernel_model", "scenarios"}
        for path in sorted(V3_ROOT.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.add(node.module)
            self.assertFalse(imports & forbidden, f"{path}: {imports & forbidden}")

    def test_v3_sources_do_not_read_historical_files(self) -> None:
        for path in sorted(V3_ROOT.glob("*.py")):
            source = path.read_text(encoding="utf-8")
            self.assertNotIn("/v2/", source)
            self.assertNotIn("causal_flow_simulator_v2.py", source)


if __name__ == "__main__":
    unittest.main()
