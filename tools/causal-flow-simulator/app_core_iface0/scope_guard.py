#!/usr/bin/env python3
"""Fail-closed path and Base-byte scope guard for Issue #295."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from canonical_report import ReportError, store_report
from inventory import BASE_SHA, InventoryError, _load_json, verify_contract_package


EXACT_MUTABLE = frozenset(
    {
        "docs/protocol/styx-app-core-interface-v0.md",
        "docs/protocol/review/README.md",
        "docs/protocol/review/styx-app-kernel-v0-review-model.json",
        "docs/protocol/review/styx-app-kernel-v0-review-model.schema.json",
        "tools/protocol-review-model/validate.py",
        "tools/protocol-review-model/tests/test_app_core_interface_v0.py",
    }
)
SUBTREE = "tools/causal-flow-simulator/app_core_iface0/"
IMPLEMENTATION_FILES = frozenset(
    {
        "README.md",
        "canonical_json.py",
        "canonical_report.py",
        "final_gate.py",
        "generate_seed_registry.py",
        "generate_structural_witnesses.py",
        "interface_model.py",
        "inventory.py",
        "node_adapter.mjs",
        "run_cross_runtime.py",
        "run_mutations.py",
        "run_probe.py",
        "scope_guard.py",
        "validate_inventory.py",
    }
)
TEST_FILES = frozenset(
    {
        "test_canonical_json.py",
        "test_contract_package.py",
        "test_cross_runtime.py",
        "test_final_gate.py",
        "test_interface_model.py",
        "test_inventory.py",
        "test_mutations.py",
        "test_report_hygiene.py",
        "test_scope_guard.py",
    }
)
REPORT_FIELDS = frozenset(
    {
        "changed_path_count",
        "contract_file_count",
        "implementation_file_count",
        "native_read_only_count",
        "schema",
        "test_module_count",
        "verdict",
    }
)


class ScopeError(ValueError):
    """The candidate escapes or weakens the ratified path boundary."""


def _git(repo: Path, *arguments: str, allow_empty: bool = False) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise ScopeError("required Git query failed")
    if not allow_empty and not completed.stdout.strip():
        raise ScopeError("required Git query returned empty output")
    return completed.stdout


def _changed_rows(repo: Path, base: str, candidate: str) -> list[tuple[str, str]]:
    output = _git(
        repo,
        "diff",
        "--name-status",
        "--no-renames",
        "--diff-filter=ACDMRTUXB",
        base,
        candidate,
    )
    rows: list[tuple[str, str]] = []
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 2 or fields[0] not in {"A", "M"}:
            raise ScopeError("rename, deletion, copy, type change, or malformed diff")
        path = fields[1]
        if path.startswith("/") or ".." in Path(path).parts:
            raise ScopeError("non-repository-relative changed path")
        rows.append((fields[0], path))
    if not rows:
        raise ScopeError("candidate has no changed paths")
    return rows


def _is_allowed(path: str) -> bool:
    return path in EXACT_MUTABLE or path.startswith(SUBTREE)


def _verify_subtree(repo: Path, candidate: str) -> tuple[int, int, int]:
    output = _git(repo, "ls-tree", "-r", "--name-only", candidate, SUBTREE)
    relative = {line.removeprefix(SUBTREE) for line in output.splitlines() if line}
    contracts = {name for name in relative if name.startswith("contract/")}
    implementations = {name for name in relative if "/" not in name}
    tests = {
        name.removeprefix("tests/")
        for name in relative
        if name.startswith("tests/") and name.count("/") == 1
    }
    if implementations != IMPLEMENTATION_FILES:
        raise ScopeError("APP-core implementation file set mismatch")
    if tests != TEST_FILES:
        raise ScopeError("APP-core test-module set mismatch")
    if len(contracts) != 27:
        raise ScopeError("APP-core contract file set mismatch")
    if relative != {
        *IMPLEMENTATION_FILES,
        *(f"tests/{name}" for name in TEST_FILES),
        *contracts,
    }:
        raise ScopeError("unexpected APP-core subtree entry")
    for path in sorted(relative):
        mode = _git(repo, "ls-tree", candidate, SUBTREE + path).split()[0]
        if mode != "100644" and not (path.endswith(".py") and mode == "100755"):
            raise ScopeError("symlink, submodule, binary mode, or unexpected mode")
    return len(contracts), len(implementations), len(tests)


def _verify_native_read_only(repo: Path, base: str, candidate: str) -> int:
    contract = repo / SUBTREE / "contract"
    inventory = _load_json(
        contract / "APP-CORE-IFACE-0-NATIVE-DEPENDENCIES-CANDIDATE.json"
    )
    count = 0
    for row in inventory["dependencies"]:
        if row["mutationPolicy"] != "READ_ONLY_BYTE_IDENTICAL":
            continue
        path = row["path"]
        before = _git(repo, "rev-parse", f"{base}:{path}").strip()
        after = _git(repo, "rev-parse", f"{candidate}:{path}").strip()
        if before != after:
            raise ScopeError(f"read-only native dependency changed: {path}")
        count += 1
    if count != 59:
        raise ScopeError("read-only native dependency count drift")
    return count


def build_report(repo: Path, base: str, candidate: str, mode: str) -> dict[str, Any]:
    if mode != "strict" or base != BASE_SHA:
        raise ScopeError("unsupported scope mode or Base")
    head = _git(repo, "rev-parse", candidate).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ScopeError("candidate identity is invalid")
    _git(repo, "merge-base", "--is-ancestor", base, head, allow_empty=True)
    rows = _changed_rows(repo, base, head)
    for _, path in rows:
        if not _is_allowed(path):
            raise ScopeError(f"changed path is outside ratified scope: {path}")
    contract_count, implementation_count, test_count = _verify_subtree(repo, head)
    native_count = _verify_native_read_only(repo, base, head)
    return {
        "changed_path_count": len(rows),
        "contract_file_count": contract_count,
        "implementation_file_count": implementation_count,
        "native_read_only_count": native_count,
        "schema": "styx.app-core-iface0.scope-report.v1",
        "test_module_count": test_count,
        "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_report(
            args.repo_root.resolve(), args.base, args.candidate, args.mode
        )
        store_report(args.output, report, allowed_fields=REPORT_FIELDS)
    except (OSError, InventoryError, ScopeError, ReportError) as error:
        print(f"APP-core scope: FAIL: {error}", file=sys.stderr)
        return 2
    print("APP-core scope: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

