#!/usr/bin/env python3
"""Reproduce and compare the complete SS-0 canonical evidence in two clones."""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from canonical_report import store


BASE_SHA = "bd13fac2df51e8585db6487fff7217fb68fb6242"
PHASE_A_SHA = "bd9a06f08131c6fcd4edbaa1e0eeae38d8e28eb5"
GATE_A_COMMENT_ID = "5469898009"
ISSUE_NUMBER = "285"
REPORT_NAMES = (
    "cross-runtime.json",
    "inventory.json",
    "mutations.json",
    "probe.json",
    "review-model.json",
    "scope.json",
)


class FinalGateError(ValueError):
    pass


def _environment(temporary_root: Path) -> dict[str, str]:
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(temporary_root),
    }


def _run(
    command: list[str],
    *,
    root: Path,
    temporary_root: Path,
) -> bytes:
    completed = subprocess.run(
        command,
        cwd=root,
        env=_environment(temporary_root),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise FinalGateError("required SS-0 gate command failed")
    return completed.stdout


def _git(root: Path, temporary_root: Path, *arguments: str) -> str:
    return _run(
        ["/usr/bin/git", *arguments], root=root, temporary_root=temporary_root
    ).decode("utf-8").strip()


def _inside(candidate: Path, parent: Path) -> bool:
    return candidate == parent or candidate.is_relative_to(parent)


def _checkout_identity(
    root: Path,
    *,
    base: str,
    head: str,
    temporary_root: Path,
) -> Path:
    if not root.is_dir() or root.is_symlink():
        raise FinalGateError("checkout is absent, non-directory or a symlink")
    top = Path(
        _git(root, temporary_root, "rev-parse", "--path-format=absolute", "--show-toplevel")
    ).resolve(strict=True)
    if top != root:
        raise FinalGateError("checkout argument is not the repository root")
    if _git(root, temporary_root, "rev-parse", "HEAD") != head:
        raise FinalGateError("checkout HEAD mismatch")
    if _git(root, temporary_root, "merge-base", base, head) != base:
        raise FinalGateError("Base is not an ancestor of final HEAD")
    status = _git(
        root,
        temporary_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=matching",
    )
    if status:
        raise FinalGateError("checkout is not clean")
    git_dir = Path(
        _git(root, temporary_root, "rev-parse", "--path-format=absolute", "--git-dir")
    ).resolve(strict=True)
    alternates = Path(
        _git(
            root,
            temporary_root,
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "objects/info/alternates",
        )
    )
    if alternates.exists() and alternates.read_bytes().strip():
        raise FinalGateError("checkout uses a local object-store alternate")
    return git_dir


def _require_external_root(root: Path, forbidden: tuple[Path, ...]) -> None:
    if root.is_symlink():
        raise FinalGateError("evidence root is a symlink")
    for boundary in forbidden:
        if _inside(root, boundary) or _inside(boundary, root):
            raise FinalGateError("evidence root overlaps a checkout or Git directory")


def _gate_a_command(
    checkout: Path,
    *,
    base: str,
    head: str,
    phase_a: str,
    comment_id: str,
    output: Path,
) -> list[str]:
    return [
        "/usr/bin/python3",
        "-I",
        "-S",
        "-B",
        str(checkout / "tools/causal-flow-simulator/ss0/verify_gate_a.py"),
        "--mode",
        "model-binding",
        "--repo",
        str(checkout),
        "--base",
        base,
        "--phase-a-head",
        phase_a,
        "--final-head",
        head,
        "--issue-number",
        ISSUE_NUMBER,
        "--comment-id",
        comment_id,
        "--output",
        str(output),
    ]


def _regenerate(
    checkout: Path,
    destination: Path,
    *,
    base: str,
    head: str,
    phase_a: str,
    node: Path,
    temporary_root: Path,
) -> None:
    python = "/usr/bin/python3"
    commands = (
        [
            python,
            "-B",
            "tools/protocol-review-model/validate.py",
            "--repo-root",
            ".",
            "--model",
            "docs/protocol/review/styx-app-kernel-v0-review-model.json",
            "--schema",
            "docs/protocol/review/styx-app-kernel-v0-review-model.schema.json",
            "--output",
            str(destination / "review-model.json"),
        ],
        [
            python,
            "-B",
            "tools/causal-flow-simulator/ss0/validate_inventory.py",
            "--root",
            ".",
            "--output",
            str(destination / "inventory.json"),
        ],
        [
            python,
            "-B",
            "tools/causal-flow-simulator/ss0/run_probe.py",
            "--root",
            ".",
            "--output",
            str(destination / "probe.json"),
        ],
        [
            python,
            "-B",
            "tools/causal-flow-simulator/ss0/run_cross_runtime.py",
            "--root",
            ".",
            "--node",
            str(node),
            "--output",
            str(destination / "cross-runtime.json"),
        ],
        [
            python,
            "-B",
            "tools/causal-flow-simulator/ss0/run_mutations.py",
            "--root",
            ".",
            "--output",
            str(destination / "mutations.json"),
        ],
        [
            python,
            "-B",
            "tools/causal-flow-simulator/ss0/scope_guard.py",
            "--repo",
            ".",
            "--base",
            base,
            "--head",
            head,
            "--phase-a-head",
            phase_a,
            "--output",
            str(destination / "scope.json"),
        ],
    )
    destination.mkdir(parents=True, exist_ok=False)
    for command in commands:
        _run(command, root=checkout, temporary_root=temporary_root)


def _read_report(root: Path, name: str) -> bytes:
    path = root / name
    if not path.is_file() or path.is_symlink():
        raise FinalGateError(f"missing or non-regular SS-0 report: {name}")
    return path.read_bytes()


def _compare_reports(
    evidence_one: Path,
    evidence_two: Path,
    regenerated_one: Path,
    regenerated_two: Path,
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for name in REPORT_NAMES:
        values = (
            _read_report(evidence_one, name),
            _read_report(evidence_two, name),
            _read_report(regenerated_one, name),
            _read_report(regenerated_two, name),
        )
        if any(value != values[0] for value in values[1:]):
            raise FinalGateError(f"canonical report mismatch: {name}")
        rows.append({"id": name.removesuffix(".json"), "sha256": hashlib.sha256(values[0]).hexdigest()})
    return rows


def execute(arguments: argparse.Namespace) -> dict[str, object]:
    if (
        arguments.base != BASE_SHA
        or arguments.phase_a_head != PHASE_A_SHA
        or arguments.gate_a_comment_id != GATE_A_COMMENT_ID
    ):
        raise FinalGateError("contract identity mismatch")
    if len(arguments.head) != 40 or any(character not in "0123456789abcdef" for character in arguments.head):
        raise FinalGateError("final HEAD is not a full lowercase Git object identity")

    checkout_one = arguments.checkout_one.resolve(strict=True)
    checkout_two = arguments.checkout_two.resolve(strict=True)
    evidence_one = arguments.evidence_one.resolve(strict=True)
    evidence_two = arguments.evidence_two.resolve(strict=True)
    output = arguments.output.resolve(strict=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_parent = output.parent.resolve(strict=True)
    if checkout_one == checkout_two or evidence_one == evidence_two:
        raise FinalGateError("two distinct checkouts and evidence roots are required")

    with tempfile.TemporaryDirectory(dir=temporary_parent, prefix=".ss0-final-") as directory:
        temporary_root = Path(directory)
        git_one = _checkout_identity(
            checkout_one,
            base=arguments.base,
            head=arguments.head,
            temporary_root=temporary_root,
        )
        git_two = _checkout_identity(
            checkout_two,
            base=arguments.base,
            head=arguments.head,
            temporary_root=temporary_root,
        )
        if git_one == git_two:
            raise FinalGateError("checkouts share one Git metadata directory")
        forbidden = (checkout_one, checkout_two, git_one, git_two)
        for root in (evidence_one, evidence_two, temporary_parent):
            _require_external_root(root, forbidden)

        gate_one = temporary_root / "gate-one.json"
        gate_two = temporary_root / "gate-two.json"
        for checkout, gate_output in (
            (checkout_one, gate_one),
            (checkout_two, gate_two),
        ):
            _run(
                _gate_a_command(
                    checkout,
                    base=arguments.base,
                    head=arguments.head,
                    phase_a=arguments.phase_a_head,
                    comment_id=arguments.gate_a_comment_id,
                    output=gate_output,
                ),
                root=checkout,
                temporary_root=temporary_root,
            )
            if not gate_output.is_file() or gate_output.is_symlink():
                raise FinalGateError("inner Gate-A verifier produced no regular evidence")

        node_name = shutil.which("node")
        if node_name is None:
            raise FinalGateError("Node is unavailable")
        node = Path(node_name).resolve(strict=True)
        regenerated_one = temporary_root / "regenerated-one"
        regenerated_two = temporary_root / "regenerated-two"
        _regenerate(
            checkout_one,
            regenerated_one,
            base=arguments.base,
            head=arguments.head,
            phase_a=arguments.phase_a_head,
            node=node,
            temporary_root=temporary_root,
        )
        _regenerate(
            checkout_two,
            regenerated_two,
            base=arguments.base,
            head=arguments.head,
            phase_a=arguments.phase_a_head,
            node=node,
            temporary_root=temporary_root,
        )
        reports = _compare_reports(
            evidence_one, evidence_two, regenerated_one, regenerated_two
        )
    return {
        "reports": reports,
        "result": "PASS",
        "schema": "styx.ss0.final-gate-report.v1",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--phase-a-head", required=True)
    parser.add_argument("--gate-a-comment-id", required=True)
    parser.add_argument("--checkout-one", type=Path, required=True)
    parser.add_argument("--checkout-two", type=Path, required=True)
    parser.add_argument("--evidence-one", type=Path, required=True)
    parser.add_argument("--evidence-two", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    store(execute(arguments), arguments.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
