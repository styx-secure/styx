"""Test support for loading the standalone validator module."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType


HERE = Path(__file__).resolve().parent
TOOL_ROOT = HERE.parent
REPO_ROOT = TOOL_ROOT.parents[1]
MODEL_PATH = REPO_ROOT / "docs/protocol/review/styx-app-kernel-v0-review-model.json"
SCHEMA_PATH = REPO_ROOT / "docs/protocol/review/styx-app-kernel-v0-review-model.schema.json"
FIXTURE_ROOT = HERE / "fixtures"


def load_validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "styx_protocol_review_model_validator",
        TOOL_ROOT / "validate.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load protocol review-model validator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module
