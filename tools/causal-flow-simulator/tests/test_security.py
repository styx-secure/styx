from __future__ import annotations

import ast
from pathlib import Path
import unittest

import support


TOOL = Path(__file__).resolve().parents[1]
RUNTIME_FILES = (
    TOOL / "model.py",
    TOOL / "payload_model.py",
    TOOL / "payload_scenarios.py",
    TOOL / "scenarios.py",
    TOOL / "causal_flow_simulator.py",
)


class IsolationTest(unittest.TestCase):
    def imported_roots(self, path: Path) -> set[str]:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                roots.add(node.module.split(".", 1)[0])
        return roots

    def test_runtime_has_no_ambient_or_external_io_dependencies(self):
        forbidden = {
            "asyncio",
            "datetime",
            "http",
            "os",
            "random",
            "requests",
            "secrets",
            "socket",
            "subprocess",
            "time",
            "urllib",
        }
        for path in RUNTIME_FILES:
            with self.subTest(path=path.name):
                self.assertTrue(forbidden.isdisjoint(self.imported_roots(path)))

    def test_runtime_does_not_import_any_styx_implementation(self):
        local_modules = {"model", "payload_model", "payload_scenarios", "scenarios"}
        standard_modules = {
            "__future__",
            "argparse",
            "dataclasses",
            "enum",
            "itertools",
            "json",
            "pathlib",
            "sys",
            "typing",
        }
        for path in RUNTIME_FILES:
            with self.subTest(path=path.name):
                self.assertTrue(
                    self.imported_roots(path).issubset(local_modules | standard_modules)
                )

    def test_runtime_uses_no_dynamic_code_execution(self):
        forbidden_calls = {"__import__", "compile", "eval", "exec"}
        for path in RUNTIME_FILES:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            called = {
                node.func.id
                for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            }
            with self.subTest(path=path.name):
                self.assertTrue(forbidden_calls.isdisjoint(called))

    def test_event_model_has_no_clock_or_arrival_field(self):
        model_source = (TOOL / "model.py").read_text(encoding="utf-8")
        tree = ast.parse(model_source)
        event = next(
            node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Event"
        )
        fields = {
            node.target.id
            for node in event.body
            if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name)
        }
        self.assertTrue(
            fields.isdisjoint({"time", "timestamp", "hlc", "arrival", "relay_order", "storage_order"})
        )


if __name__ == "__main__":
    unittest.main()
