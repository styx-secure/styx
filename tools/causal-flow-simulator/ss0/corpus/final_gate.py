#!/usr/bin/env python3
"""Reproduce SS-CORPUS-0 evidence in two independent exact-HEAD checkouts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


BASE_SHA = "28a5e78e80a014a27b94683479d4e82206abac2f"
ISSUE_NUMBER = 293
PYTHON_VERSION = "Python 3.14.4"
NODE_VERSION = "v24.18.0"
REQUIRED_HISTORY = (
    "fc7d15356f2299e9acd8a106f46d6631d0c66b74",
    "4a4ebc4b8fc91e500ecd8002801896dc73d5073f",
    "d35052dfbf0631c726f250933bc401f424602f31",
    "bd13fac2df51e8585db6487fff7217fb68fb6242",
    "bd9a06f08131c6fcd4edbaa1e0eeae38d8e28eb5",
    "c8430b2fbcb4bd9d0668e5877210d0244ff8bf81",
)
CORPUS_FILES = (
    "manifest.json",
    "valid-session-vectors.json",
    "invalid-session-vectors.json",
    "state-machine-scenarios.json",
    "adversarial-mutations.json",
    "expected-traces.json",
)
CANONICAL_REPORTS = (
    "replay.json",
    "mutations.json",
    "frozen-cross-runtime.json",
    "frozen-mutations.json",
)


class FinalGateError(ValueError):
    """A fail-closed SS-CORPUS-0 final-gate rejection."""


def _store(value: dict[str, Any], output: Path) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(
        dir=output.parent, prefix=f".{output.name}.", suffix=".tmp"
    )
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def _environment(temporary_root: Path, node: Path) -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "LC_ALL": "C",
        "PATH": f"{node.parent}:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(temporary_root),
    }


def _run(
    command: list[str], *, root: Path, temporary_root: Path, node: Path
) -> bytes:
    completed = subprocess.run(
        command,
        cwd=root,
        env=_environment(temporary_root, node),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=300,
    )
    if completed.returncode != 0:
        label = next(
            (
                Path(argument).name
                for argument in command
                if argument.endswith((".py", ".mjs"))
            ),
            Path(command[0]).name,
        )
        raise FinalGateError(f"required SS-CORPUS-0 command failed: {label}")
    return completed.stdout


def _git(
    root: Path, temporary_root: Path, node: Path, *arguments: str
) -> str:
    return _run(
        ["/usr/bin/git", *arguments],
        root=root,
        temporary_root=temporary_root,
        node=node,
    ).decode("utf-8", "strict").strip()


def _inside(candidate: Path, parent: Path) -> bool:
    return candidate == parent or candidate.is_relative_to(parent)


def _resolve_plain_directory(path: Path, label: str) -> Path:
    absolute = path.absolute()
    if not absolute.is_dir() or absolute.is_symlink():
        raise FinalGateError(f"{label} is absent, non-directory or a symlink")
    resolved = absolute.resolve(strict=True)
    if resolved != absolute:
        raise FinalGateError(f"{label} contains a symlinked path component")
    return resolved


def _require_external_root(root: Path, forbidden: tuple[Path, ...]) -> None:
    for boundary in forbidden:
        if _inside(root, boundary) or _inside(boundary, root):
            raise FinalGateError("evidence root overlaps a checkout or Git directory")


def _checkout_identity(
    root: Path,
    *,
    base: str,
    head: str,
    temporary_root: Path,
    node: Path,
) -> Path:
    top = Path(
        _git(
            root,
            temporary_root,
            node,
            "rev-parse",
            "--path-format=absolute",
            "--show-toplevel",
        )
    ).resolve(strict=True)
    if top != root:
        raise FinalGateError("checkout argument is not the repository root")
    if _git(root, temporary_root, node, "rev-parse", "HEAD") != head:
        raise FinalGateError("checkout HEAD mismatch")
    if _git(root, temporary_root, node, "merge-base", base, head) != base:
        raise FinalGateError("Base is not an ancestor of final HEAD")
    status = _git(
        root,
        temporary_root,
        node,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=matching",
    )
    if status:
        raise FinalGateError("checkout is not clean")
    for identity in REQUIRED_HISTORY:
        _git(root, temporary_root, node, "cat-file", "-e", f"{identity}^{{commit}}")
    git_dir = Path(
        _git(
            root,
            temporary_root,
            node,
            "rev-parse",
            "--path-format=absolute",
            "--git-dir",
        )
    ).resolve(strict=True)
    alternates = Path(
        _git(
            root,
            temporary_root,
            node,
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "objects/info/alternates",
        )
    )
    if alternates.exists() and alternates.read_bytes().strip():
        raise FinalGateError("checkout uses a local object-store alternate")
    return git_dir


def _require_runtime(node: Path) -> None:
    if "PYTHONOPTIMIZE" in os.environ:
        raise FinalGateError("PYTHONOPTIMIZE must be unset")
    python = subprocess.run(
        ["/usr/bin/python3", "--version"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    if python.returncode != 0 or python.stdout.decode().strip() != PYTHON_VERSION:
        raise FinalGateError("Python capability mismatch")
    runtime = subprocess.run(
        [str(node), "--version"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
    )
    if runtime.returncode != 0 or runtime.stdout.decode().strip() != NODE_VERSION:
        raise FinalGateError("Node capability mismatch")


def _regenerate(
    checkout: Path,
    destination: Path,
    *,
    base: str,
    head: str,
    issue: int,
    node: Path,
    temporary_root: Path,
) -> None:
    python = "/usr/bin/python3"
    destination.mkdir(parents=True, exist_ok=False)
    commands = (
        [
            python,
            "tools/causal-flow-simulator/ss0/corpus/generate_corpus.py",
            "--repo-root", ".",
            "--output-dir", "conformance/secure-session/ss0",
            "--check",
        ],
        [
            python,
            "tools/causal-flow-simulator/ss0/corpus/validate_corpus.py",
            "--repo-root", ".",
            "--corpus-dir", "conformance/secure-session/ss0",
        ],
        [
            python,
            "-m", "unittest", "discover", "-v",
            "-s", "tools/causal-flow-simulator/ss0/corpus/tests",
            "-p", "test_*.py",
        ],
        [
            python,
            "tools/causal-flow-simulator/ss0/corpus/replay_corpus.py",
            "--repo-root", ".", "--node", str(node),
            "--corpus-dir", "conformance/secure-session/ss0",
            "--output", str(destination / "replay.json"),
        ],
        [
            python,
            "tools/causal-flow-simulator/ss0/corpus/run_mutations.py",
            "--repo-root", ".", "--node", str(node),
            "--corpus-dir", "conformance/secure-session/ss0",
            "--output", str(destination / "mutations.json"),
        ],
        [
            python,
            "tools/causal-flow-simulator/ss0/run_cross_runtime.py",
            "--root", ".", "--node", str(node),
            "--output", str(destination / "frozen-cross-runtime.json"),
        ],
        [
            python,
            "tools/causal-flow-simulator/ss0/run_mutations.py",
            "--root", ".", "--output", str(destination / "frozen-mutations.json"),
        ],
        [
            python,
            "tools/causal-flow-simulator/ss0/corpus/scope_guard.py",
            "--repo-root", ".", "--base", base, "--head", head,
            "--issue", str(issue), "--output", str(destination / "scope.json"),
        ],
        [
            python,
            "tools/protocol-review-model/validate.py",
            "--repo-root", ".",
            "--schema", "docs/protocol/review/styx-app-kernel-v0-review-model.schema.json",
            "--model", "docs/protocol/review/styx-app-kernel-v0-review-model.json",
            "--output", str(destination / "review-model.json"),
        ],
    )
    for command in commands:
        _run(
            command,
            root=checkout,
            temporary_root=temporary_root,
            node=node,
        )


def _read_regular(root: Path, name: str) -> bytes:
    path = root / name
    if not path.is_file() or path.is_symlink():
        raise FinalGateError(f"missing or non-regular evidence: {name}")
    return path.read_bytes()


def _compare_corpus(checkout_a: Path, checkout_b: Path) -> list[dict[str, str]]:
    roots = (
        checkout_a / "conformance/secure-session/ss0",
        checkout_b / "conformance/secure-session/ss0",
    )
    rows: list[dict[str, str]] = []
    for name in CORPUS_FILES:
        left = _read_regular(roots[0], name)
        right = _read_regular(roots[1], name)
        if left != right:
            raise FinalGateError(f"corpus differs between checkouts: {name}")
        rows.append({"name": name, "sha256": hashlib.sha256(left).hexdigest()})
    return rows


def _compare_reports(*roots: Path) -> list[dict[str, str]]:
    if len(roots) != 4 or len(set(roots)) != 4:
        raise FinalGateError("exactly four distinct report roots are required")
    rows: list[dict[str, str]] = []
    for name in CANONICAL_REPORTS:
        values = tuple(_read_regular(root, name) for root in roots)
        if any(value != values[0] for value in values[1:]):
            raise FinalGateError(f"canonical report mismatch: {name}")
        rows.append({"name": name, "sha256": hashlib.sha256(values[0]).hexdigest()})
    return rows


def _require_pass_report(root: Path, name: str) -> str:
    data = _read_regular(root, name)
    try:
        value = json.loads(data)
    except json.JSONDecodeError as error:
        raise FinalGateError(f"invalid external evidence: {name}") from error
    if not isinstance(value, dict) or value.get("result") != "PASS":
        raise FinalGateError(f"external evidence did not pass: {name}")
    return hashlib.sha256(data).hexdigest()


def execute(arguments: argparse.Namespace) -> dict[str, Any]:
    if arguments.base != BASE_SHA or arguments.issue != ISSUE_NUMBER:
        raise FinalGateError("contract identity mismatch")
    if len(arguments.head) != 40 or any(
        character not in "0123456789abcdef" for character in arguments.head
    ):
        raise FinalGateError("final HEAD is not a full lowercase Git object identity")

    node = arguments.node.resolve(strict=True)
    if not node.is_file() or node.is_symlink():
        raise FinalGateError("Node capability is not a regular file")
    _require_runtime(node)
    checkout_a = _resolve_plain_directory(arguments.checkout_a, "checkout A")
    checkout_b = _resolve_plain_directory(arguments.checkout_b, "checkout B")
    evidence_a = _resolve_plain_directory(arguments.evidence_a, "evidence A")
    evidence_b = _resolve_plain_directory(arguments.evidence_b, "evidence B")
    output = arguments.output.absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    final_root = _resolve_plain_directory(output.parent, "final evidence root")
    if output.parent != final_root or output.exists() and output.is_symlink():
        raise FinalGateError("final output path is not a plain external path")
    if len({checkout_a, checkout_b, evidence_a, evidence_b, final_root}) != 5:
        raise FinalGateError("checkouts and evidence roots must be distinct")

    with tempfile.TemporaryDirectory(dir=final_root, prefix=".ss0-corpus-final-") as name:
        temporary_root = Path(name).resolve(strict=True)
        git_a = _checkout_identity(
            checkout_a,
            base=arguments.base,
            head=arguments.head,
            temporary_root=temporary_root,
            node=node,
        )
        git_b = _checkout_identity(
            checkout_b,
            base=arguments.base,
            head=arguments.head,
            temporary_root=temporary_root,
            node=node,
        )
        if git_a == git_b:
            raise FinalGateError("checkouts share one Git metadata directory")
        forbidden = (checkout_a, checkout_b, git_a, git_b)
        for root in (evidence_a, evidence_b, final_root, temporary_root):
            _require_external_root(root, forbidden)

        regenerated_a = temporary_root / "regenerated-a"
        regenerated_b = temporary_root / "regenerated-b"
        _regenerate(
            checkout_a,
            regenerated_a,
            base=arguments.base,
            head=arguments.head,
            issue=arguments.issue,
            node=node,
            temporary_root=temporary_root,
        )
        _regenerate(
            checkout_b,
            regenerated_b,
            base=arguments.base,
            head=arguments.head,
            issue=arguments.issue,
            node=node,
            temporary_root=temporary_root,
        )
        corpus = _compare_corpus(checkout_a, checkout_b)
        reports = _compare_reports(
            evidence_a, evidence_b, regenerated_a, regenerated_b
        )
        external = [
            {
                "name": name,
                "sha256A": _require_pass_report(regenerated_a, name),
                "sha256B": _require_pass_report(regenerated_b, name),
            }
            for name in ("scope.json", "review-model.json")
        ]
        _checkout_identity(
            checkout_a,
            base=arguments.base,
            head=arguments.head,
            temporary_root=temporary_root,
            node=node,
        )
        _checkout_identity(
            checkout_b,
            base=arguments.base,
            head=arguments.head,
            temporary_root=temporary_root,
            node=node,
        )
    return {
        "base": arguments.base,
        "canonicalReports": reports,
        "corpusFiles": corpus,
        "externalEvidence": external,
        "head": arguments.head,
        "issue": arguments.issue,
        "result": "PASS",
        "schema": "styx.ss0.corpus.final-gate-report.v1",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--issue", type=int, required=True)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--checkout-a", type=Path, required=True)
    parser.add_argument("--checkout-b", type=Path, required=True)
    parser.add_argument("--evidence-a", type=Path, required=True)
    parser.add_argument("--evidence-b", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    _store(execute(arguments), arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
