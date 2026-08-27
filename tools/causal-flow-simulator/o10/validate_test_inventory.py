#!/usr/bin/env python3
"""Require every ratified O-10 evidence family to have a collected test."""

from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True

EXPECTED_MODULES = frozenset(
    {
        "test_canonical_reports.py",
        "test_cross_runtime.py",
        "test_hostile_fixtures.py",
        "test_mutations.py",
        "test_precedence.py",
        "test_recovery.py",
        "test_remote_collapse.py",
        "test_source_inventory.py",
        "test_taxonomy_classifier.py",
        "test_taxonomy_registry.py",
    }
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    args = parser.parse_args(argv)
    root = args.repo_root.resolve() / "tools/causal-flow-simulator/o10/tests"
    files = sorted(root.glob("test_*.py"))
    names = {path.name for path in files}
    if names != set(EXPECTED_MODULES):
        print("O-10 test inventory: FAIL: module set drift", file=sys.stderr)
        return 2
    missing = [
        path.name
        for path in files
        if unittest.defaultTestLoader.discover(str(root), pattern=path.name).countTestCases()
        == 0
    ]
    if missing:
        print("O-10 test inventory: FAIL: zero-test modules", file=sys.stderr)
        return 2
    print(f"O-10 test inventory: PASS modules={len(files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
