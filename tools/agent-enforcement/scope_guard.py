#!/usr/bin/env python3
"""Styx task-contract parser and report-only Git scope guard."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import sys
from typing import Sequence

# The guard is commonly executed from the repository it validates. Prevent
# local module imports from creating __pycache__ and dirtying that worktree
# before the read-only repository check runs.
sys.dont_write_bytecode = True

from contract import ContractError, evaluate_path, parse_contract, pattern_matches, validate_pattern
from git_inventory import (
    SHA_RE,
    content_diagnostics,
    inventory_changes,
    output_is_inside_repository,
    repository_toplevel,
    run_git,
    verify_repository,
)
from model import (
    ChangedEntry,
    Contract,
    Diagnostic,
    EXIT_ERROR,
    EXIT_FAIL,
    EXIT_PASS,
    GuardError,
    PathEvaluation,
)
from report import build_report, canonical_json_bytes, write_report

# Re-exported imports are intentional: tests and future local callers may use the
# parser/model/report helpers without importing a package whose directory name
# contains a hyphen.
__all__ = [
    "ChangedEntry",
    "Contract",
    "ContractError",
    "Diagnostic",
    "PathEvaluation",
    "build_report",
    "canonical_json_bytes",
    "parse_contract",
    "pattern_matches",
    "validate_pattern",
]


class GuardArgumentParser(argparse.ArgumentParser):
    """Argument parser whose usage errors exit with the documented ERROR code.

    ``argparse`` exits with status 2 by default, which would collide with the
    documented policy-FAIL exit code.
    """

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_ERROR)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = GuardArgumentParser(
        description="Parse a Styx task contract, compare it with a Git diff, and emit canonical JSON evidence."
    )
    parser.add_argument("--issue-number", type=int, required=True)
    parser.add_argument("--issue-body-file", type=Path, required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--head-sha", required=True)
    parser.add_argument(
        "--worktree-sha",
        help=(
            "full SHA expected at worktree HEAD; defaults to --head-sha. "
            "CI observation may set this to the trusted base SHA while inspecting the head as object data"
        ),
    )
    parser.add_argument("--execution-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    return parser.parse_args(argv)


def _validate_scalar_inputs(args: argparse.Namespace) -> None:
    if args.issue_number <= 0:
        raise ContractError("issue number must be a positive integer")
    if not args.execution_id or args.execution_id.strip() != args.execution_id:
        raise ContractError("execution ID must be non-empty and have no surrounding whitespace")
    if any(ord(char) < 32 or ord(char) == 127 for char in args.execution_id):
        raise ContractError("execution ID contains control characters")


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    repo = args.repo.resolve()
    output_path = args.output.resolve(strict=False)
    # Guard the output location against the declared --repo directory AND the
    # real worktree root containing it: when --repo points at a subdirectory of
    # a repository, the report must still never land inside that repository.
    protected_roots = [repo]
    toplevel = repository_toplevel(repo)
    if toplevel is not None:
        protected_roots.append(toplevel)
    if any(output_is_inside_repository(root, output_path) for root in protected_roots):
        print("scope_guard: output file must be outside the tested repository", file=sys.stderr)
        return EXIT_ERROR

    issue_hash: str | None = None
    contract: Contract | None = None
    entries: tuple[ChangedEntry, ...] = ()
    evaluations: dict[str, PathEvaluation] = {}
    diagnostics: list[Diagnostic] = []
    initial_status: bytes | None = None
    expected_worktree_sha = args.worktree_sha or args.head_sha

    try:
        _validate_scalar_inputs(args)
        issue_body_bytes = args.issue_body_file.read_bytes()
        issue_hash = hashlib.sha256(issue_body_bytes).hexdigest()
        contract = parse_contract(issue_body_bytes)
        initial_status = verify_repository(
            repo,
            args.base_sha,
            args.head_sha,
            worktree_sha=expected_worktree_sha,
        )
        entries = inventory_changes(repo, args.base_sha, args.head_sha)

        for entry in entries:
            for path in entry.checked_paths():
                evaluations[path] = evaluate_path(path, contract)
        for evaluation in evaluations.values():
            if "PATH_NOT_ALLOWED" in evaluation.violations:
                diagnostics.append(
                    Diagnostic("P_PATH_NOT_ALLOWED", "path matches no allowed pattern", "error", evaluation.path)
                )
            if "PATH_FORBIDDEN" in evaluation.violations:
                diagnostics.append(
                    Diagnostic("P_PATH_FORBIDDEN", "forbidden patterns override allowed patterns", "error", evaluation.path)
                )
        diagnostics.extend(content_diagnostics(repo, args.base_sha, args.head_sha, entries))

        final_head = run_git(repo, ["rev-parse", "HEAD"], text=True).stdout.strip()
        final_status = run_git(
            repo, ["status", "--porcelain=v1", "-z", "--untracked-files=all"]
        ).stdout
        if final_head != expected_worktree_sha or final_status != initial_status:
            diagnostics.append(
                Diagnostic(
                    "E_REPOSITORY_CHANGED",
                    "repository HEAD, index or worktree changed during execution",
                    "error",
                )
            )

        if any(item.code.startswith("E_") for item in diagnostics):
            verdict, exit_code = "ERROR", EXIT_ERROR
        elif diagnostics:
            verdict, exit_code = "FAIL", EXIT_FAIL
        else:
            verdict, exit_code = "PASS", EXIT_PASS
    except (OSError, GuardError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, GuardError):
            code, message, path = exc.code, exc.message, exc.path
        elif isinstance(exc, RecursionError):
            code, message, path = "E_INTERNAL", "internal recursion limit exceeded", None
        else:
            code, message, path = "E_IO", str(exc), None
        diagnostics.append(Diagnostic(code, message, "error", path))
        verdict, exit_code = "ERROR", EXIT_ERROR

    # Fields that echo CLI input are reported as null when the input failed
    # validation, so every written report satisfies the published schema.
    report = build_report(
        issue_number=args.issue_number if args.issue_number >= 1 else None,
        execution_id=args.execution_id,
        base_sha=args.base_sha if SHA_RE.fullmatch(args.base_sha) else None,
        head_sha=args.head_sha if SHA_RE.fullmatch(args.head_sha) else None,
        issue_body_sha256=issue_hash,
        contract=contract,
        entries=entries,
        evaluations=evaluations,
        diagnostics=diagnostics,
        verdict=verdict,
    )
    try:
        write_report(output_path, report)
    except OSError as exc:
        print(f"scope_guard: unable to write report: {exc}", file=sys.stderr)
        return EXIT_ERROR

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
