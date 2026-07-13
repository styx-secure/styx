#!/usr/bin/env python3
"""Styx automatic test planner and executor CLI.

Subcommands:

- ``plan``: derive a ``styx.test-plan/v1`` from trusted task inputs;
- ``execute``: validate a plan, run it, emit a ``styx.test-report/v1``;
- ``eligibility``: apply the frozen review-eligibility rule.

Evidence files are always written outside the tested repository. Exit codes
follow the repository convention: 0 PASS, 2 FAIL, 3 ERROR.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import subprocess
import sys
from typing import Sequence

# Keep local imports from creating __pycache__ inside the repository under
# test before the clean-worktree verification runs.
sys.dont_write_bytecode = True

from contract_inputs import load_scope_report, load_task_inputs
from executor import execute_plan, review_eligible, validate_plan_document
from model import (
    EXIT_ERROR,
    EXIT_FAIL,
    EXIT_PASS,
    OrchestratorError,
    atomic_write,
    canonical_json_bytes,
    load_strict_json,
    redact_text,
)
from planner import build_plan, plan_bytes

__all__ = [
    "build_plan",
    "execute_plan",
    "load_scope_report",
    "load_task_inputs",
    "main",
    "review_eligible",
    "validate_plan_document",
]


class OrchestratorArgumentParser(argparse.ArgumentParser):
    """Exit with the documented ERROR code on usage errors, not 2."""

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_ERROR)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = OrchestratorArgumentParser(
        description="Derive and execute exact-HEAD-bound automatic test plans with canonical evidence."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    plan = commands.add_parser("plan", help="derive a styx.test-plan/v1 from trusted task inputs")
    plan.add_argument("--issue-number", type=int, required=True)
    plan.add_argument("--issue-body-file", type=Path, required=True)
    plan.add_argument("--scope-report", type=Path, required=True)
    plan.add_argument("--base-sha", required=True)
    plan.add_argument("--head-sha", required=True)
    plan.add_argument("--execution-id", required=True)
    plan.add_argument("--repo", type=Path, default=Path.cwd())
    plan.add_argument("--proposals", type=Path, help="optional untrusted generated-test proposals (JSON array)")
    plan.add_argument("--output", type=Path, required=True)

    execute = commands.add_parser("execute", help="validate and run a plan, emitting a styx.test-report/v1")
    execute.add_argument("--plan", type=Path, required=True)
    execute.add_argument("--issue-body-file", type=Path, required=True)
    execute.add_argument("--scope-report", type=Path, required=True)
    execute.add_argument("--repo", type=Path, default=Path.cwd())
    execute.add_argument("--output", type=Path, required=True)

    eligibility = commands.add_parser("eligibility", help="apply the frozen review-eligibility rule")
    eligibility.add_argument("--test-report", type=Path, required=True)
    eligibility.add_argument("--scope-report", type=Path, required=True)
    eligibility.add_argument("--head-sha", required=True)

    return parser.parse_args(argv)


def _repository_toplevel(repo: Path) -> Path | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return Path(result.stdout.strip()).resolve()


def _ensure_output_outside_repo(repo: Path, output: Path) -> None:
    protected = [repo.resolve()]
    toplevel = _repository_toplevel(repo)
    if toplevel is not None:
        protected.append(toplevel)
    resolved = output.resolve(strict=False)
    for root in protected:
        if resolved == root or resolved.is_relative_to(root):
            raise OrchestratorError("evidence output must be outside the tested repository")


def _command_plan(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    _ensure_output_outside_repo(repo, args.output)
    issue_body_bytes = args.issue_body_file.read_bytes()
    inputs = load_task_inputs(repo, args.issue_number, issue_body_bytes)
    scope_report = load_scope_report(args.scope_report.read_bytes())
    proposals = None
    if args.proposals is not None:
        proposals = load_strict_json(args.proposals.read_bytes(), source="generated-test proposals")
    plan = build_plan(
        repo=repo,
        inputs=inputs,
        scope_report=scope_report,
        base_sha=args.base_sha,
        head_sha=args.head_sha,
        execution_id=args.execution_id,
        proposals=proposals,
    )
    atomic_write(args.output, plan_bytes(plan))
    return EXIT_PASS


def _command_execute(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    _ensure_output_outside_repo(repo, args.output)
    raw_plan = args.plan.read_bytes()
    plan = validate_plan_document(raw_plan)
    plan_sha256 = hashlib.sha256(raw_plan).hexdigest()
    issue_body_bytes = args.issue_body_file.read_bytes()
    scope_report = load_scope_report(args.scope_report.read_bytes())
    report = execute_plan(
        plan,
        plan_sha256,
        repo=repo,
        issue_body_bytes=issue_body_bytes,
        scope_report=scope_report,
    )
    atomic_write(args.output, canonical_json_bytes(report))
    if report["verdict"] == "PASS":
        return EXIT_PASS
    if report["verdict"] == "FAIL":
        return EXIT_FAIL
    return EXIT_ERROR


def _command_eligibility(args: argparse.Namespace) -> int:
    test_report = load_strict_json(args.test_report.read_bytes(), source="test report")
    scope_report = load_strict_json(args.scope_report.read_bytes(), source="scope report")
    if not isinstance(test_report, dict) or not isinstance(scope_report, dict):
        raise OrchestratorError("evidence documents must be JSON objects")
    if review_eligible(test_report, scope_report, args.head_sha):
        print("ELIGIBLE")
        return EXIT_PASS
    print("NOT_ELIGIBLE")
    return EXIT_FAIL


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    handlers = {
        "plan": _command_plan,
        "execute": _command_execute,
        "eligibility": _command_eligibility,
    }
    try:
        return handlers[args.command](args)
    except OrchestratorError as exc:
        print(f"test-orchestrator: {exc.code}: {redact_text(exc.message)}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"test-orchestrator: E_IO: {redact_text(str(exc))}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
