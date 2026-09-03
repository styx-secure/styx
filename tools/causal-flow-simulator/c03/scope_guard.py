#!/usr/bin/env python3
"""Fail-closed Base-to-candidate relation guard for Issue #297 Package A."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from canonical_json import store  # noqa: E402


BASE_SHA = "16274cc194cd2f8f7b631332687a252bad92ce02"
COPY_THRESHOLD = 50
PINS = {
    "tools/causal-flow-simulator/c03/corpus_model.py": "c5fae0f950cc8f9691a95d8231cc88e6c43c5e1e74b797d716928b6c8f5b1558",
    "tools/causal-flow-simulator/c03/node_adapter.mjs": "fc52c0800fab4c7cf75785b962ba09ffd67d06cb0b7bd02e850d6f13b0868da0",
    "tools/causal-flow-simulator/c03/README.md": "bd7f0459836c07d849780789b7ba7b11107cd853921b185838c3a7b9db575d3c",
    "tools/causal-flow-simulator/c03/scope_guard.py": "434c0b5276a0aba79cfc8d2b3cc56c4e337c58c6415db0ced2f9f9339aed4c66",
    "tools/causal-flow-simulator/c03/tests/test_scope_guard.py": "208dd5995f2518bd1245cc6968bc6acc9c0d8686d620352d16006c8c12846011",
    "tools/causal-flow-simulator/c03/tests/test_replay.py": "f1566d7412b16f3210b17c8e076c7d836e7693b7404c9af14a6ac1e6293b56ab",
    "docs/protocol/protocol-hardening-plan.md": "21033486045cfcfc0947b8b516489d1683fe2ec3b48a184faa068bf1777ad0bf",
    "docs/protocol/review/README.md": "d355ad16b2025240dadedbf2ca6ca1b78a5036c8ff2a727cf19d48414299b050",
}
NEW = frozenset({
    "tools/causal-flow-simulator/c03/h1_h2_relation.py",
    "tools/causal-flow-simulator/c03/tests/test_h1_h2_relation.py",
})
ALLOWED = frozenset(PINS) | NEW


class ScopeViolation(ValueError):
    pass


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).stdout


def commit(repo: Path, value: str) -> str:
    return git(repo, "rev-parse", f"{value}^{{commit}}").decode().strip()


def allowed(path: str) -> bool:
    return path in ALLOWED


def changed_relation(repo: Path, base: str, candidate: str) -> list[dict[str, Any]]:
    fields = git(
        repo, "diff", "--name-status", "-z", "--no-renames", base, candidate,
    ).split(b"\0")
    if fields and not fields[-1]:
        fields.pop()
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    cursor = 0
    while cursor < len(fields):
        status = fields[cursor].decode("ascii")
        cursor += 1
        if status not in {"A", "M"}:
            raise ScopeViolation(f"forbidden change status: {status}")
        paths = [fields[cursor].decode("utf-8")]
        cursor += 1
        path = paths[0]
        if not allowed(path):
            raise ScopeViolation(f"out-of-scope endpoint: {path}")
        if path in seen:
            raise ScopeViolation(f"duplicate endpoint: {path}")
        seen.add(path)
        if (status == "A") != (path in NEW):
            raise ScopeViolation(f"wrong endpoint state: {path}")
        rows.append({"paths": paths, "status": status})
    return rows


def check_endpoints(repo: Path, candidate: str, rows: list[dict[str, Any]]) -> None:
    for row in rows:
        for path in row["paths"]:
            line = git(repo, "ls-tree", candidate, "--", path).decode().strip()
            if not line:
                raise ScopeViolation(f"missing endpoint: {path}")
            metadata = line.split("\t", 1)[0].split()
            if metadata[0] in {"120000", "160000"} or metadata[1] != "blob":
                raise ScopeViolation(f"symlink/submodule endpoint: {path}")
            blob = git(repo, "cat-file", "blob", f"{candidate}:{path}")
            if b"\0" in blob:
                raise ScopeViolation(f"binary endpoint: {path}")
            if "__pycache__" in path or path.endswith((".pyc", ".pyo")):
                raise ScopeViolation(f"cache endpoint: {path}")


def check_base_contract(repo: Path) -> None:
    from hashlib import sha256

    for path, expected in PINS.items():
        blob = git(repo, "show", f"{BASE_SHA}:{path}")
        if sha256(blob).hexdigest() != expected:
            raise ScopeViolation(f"Base pin mismatch: {path}")
    for path in NEW:
        present = subprocess.run(
            ["git", "-C", str(repo), "cat-file", "-e", f"{BASE_SHA}:{path}"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0
        if present:
            raise ScopeViolation(f"new endpoint exists at Base: {path}")


def check_copy_relation(repo: Path, base: str, candidate: str) -> None:
    fields = git(
        repo,
        "diff",
        "--name-status",
        "-z",
        "--find-copies-harder",
        f"--find-copies={COPY_THRESHOLD}%",
        f"--find-renames={COPY_THRESHOLD}%",
        "-l0",
        base,
        candidate,
    ).split(b"\0")
    if any(field[:1] in {b"C", b"R"} for field in fields[::2] if field):
        raise ScopeViolation("copy/rename relation forbidden")


def check_text_relation(repo: Path, base: str, candidate: str) -> None:
    for line in git(repo, "diff", "--numstat", base, candidate).decode().splitlines():
        added, deleted, _ = line.split("\t", 2)
        if added == "-" or deleted == "-":
            raise ScopeViolation("binary endpoint")


def build_report(repo: Path, base_value: str, candidate_value: str) -> dict[str, Any]:
    base, candidate = commit(repo, base_value), commit(repo, candidate_value)
    if base_value != BASE_SHA or base != BASE_SHA:
        raise ScopeViolation("contract Base mismatch")
    if git(repo, "merge-base", base, candidate).decode().strip() != base:
        raise ScopeViolation("Base is not an ancestor")
    check_base_contract(repo)
    rows = changed_relation(repo, base, candidate)
    changed = {path for row in rows for path in row["paths"]}
    if not NEW <= changed:
        raise ScopeViolation("both required new evidence endpoints must be added")
    check_endpoints(repo, candidate, rows)
    check_copy_relation(repo, base, candidate)
    check_text_relation(repo, base, candidate)
    return {
        "changedRelation": rows,
        "copyThresholdPercent": COPY_THRESHOLD,
        "endpointCount": len(rows),
        "result": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--mode", choices=("strict",), default="strict")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        store(args.output.resolve(), build_report(args.repo_root.resolve(), args.base, args.candidate))
    except (OSError, UnicodeError, subprocess.CalledProcessError, ScopeViolation, ValueError) as error:
        print(f"c03_scope_failure={error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
