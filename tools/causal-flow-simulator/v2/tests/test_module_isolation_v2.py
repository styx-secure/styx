from __future__ import annotations

import importlib
import sys
import unittest
from pathlib import Path

V2_ROOT = Path(__file__).resolve().parents[1]
SIMULATOR_ROOT = V2_ROOT.parent.resolve()
sys.path.insert(0, str(V2_ROOT))


class ModuleIsolationTests(unittest.TestCase):
    def test_v2_entry_points_load_no_v1_simulator_module(self) -> None:
        for name in (
            "kernel_model_v2",
            "scenarios_v2",
            "causal_flow_simulator_v2",
        ):
            sys.modules.pop(name, None)
        before = set(sys.modules)
        importlib.import_module("kernel_model_v2")
        importlib.import_module("scenarios_v2")
        importlib.import_module("causal_flow_simulator_v2")
        loaded = []
        for name in set(sys.modules) - before:
            module_file = getattr(sys.modules[name], "__file__", None)
            if module_file is None:
                continue
            path = Path(module_file).resolve()
            if path.is_relative_to(SIMULATOR_ROOT):
                loaded.append(path)
        self.assertTrue(loaded)
        self.assertTrue(all(path.is_relative_to(V2_ROOT) for path in loaded), loaded)

    def test_v2_module_basenames_are_distinct_from_frozen_v1(self) -> None:
        v1 = {
            "causal_flow_simulator.py",
            "model.py",
            "payload_model.py",
            "payload_scenarios.py",
            "scenarios.py",
            "test_model.py",
            "test_payload_model.py",
            "test_scenarios.py",
            "test_security.py",
        }
        v2 = {path.name for path in V2_ROOT.rglob("*.py")}
        self.assertFalse(v1 & v2, v1 & v2)


if __name__ == "__main__":
    unittest.main()
