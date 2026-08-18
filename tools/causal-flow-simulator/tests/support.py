from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

sys.dont_write_bytecode = True

TOOL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOL))


def load_cli():
    path = TOOL / "causal_flow_simulator.py"
    spec = importlib.util.spec_from_file_location("causal_flow_simulator", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module
