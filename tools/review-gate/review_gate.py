#!/usr/bin/env python3
"""Styx isolated review gate and structured remediation CLI.

Subcommands:

- ``review``: validate the technical evidence pair and a reviewer's request,
  then emit a canonical ``styx.review-report/v1``;
- ``remediate``: turn a change-requesting review report into a canonical
  ``styx.remediation-request/v1``.

The gate never executes tests, never runs git, never opens a network socket,
never reads credentials and never writes inside the reviewed repository. Its
only side effect is one atomic write of a canonical evidence document to a
caller-chosen output path outside the repository. Exit codes: 0 accepting
review / successful remediation, 2 a review that requests changes or blocks,
3 any fail-closed error (no output is written).
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

# Never write __pycache__ into a checkout that a clean-worktree verification
# might inspect.
sys.dont_write_bytecode = True

from evidence import load_evidence
from model import (
    ACCEPTANCE_VERDICTS,
    EXIT_CHANGES,
    EXIT_ERROR,
    EXIT_PASS,
    PreconditionError,
    ReviewGateError,
    atomic_write,
    ensure_writable_output,
    load_strict_json,
    read_regular_file,
    redact_text,
    require,
    sha256_hex,
)
from remediation import build_remediation_request, remediation_request_bytes
from review import (
    build_review_report,
    review_report_bytes,
    validate_review_request,
)

__all__ = ["main"]


class ReviewGateArgumentParser(argparse.ArgumentParser):
    """Exit with the documented ERROR code on usage errors, not 2."""

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_ERROR)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = ReviewGateArgumentParser(
        description="Isolated, fail-closed review gate and structured remediation loop.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    review = commands.add_parser("review", help="emit a styx.review-report/v1 from evidence and a reviewer request")
    review.add_argument("--review-request", type=Path, required=True)
    review.add_argument("--scope-report", type=Path, required=True)
    review.add_argument("--test-report", type=Path, required=True)
    review.add_argument("--issue-body-file", type=Path, help="optional Issue body; its sha256 must match the candidate")
    review.add_argument("--repo-root", type=Path, help="reviewed repository root; output must live outside it")
    review.add_argument("--output", type=Path, required=True)

    remediate = commands.add_parser("remediate", help="emit a styx.remediation-request/v1 from a review report")
    remediate.add_argument("--review-report", type=Path, required=True)
    remediate.add_argument("--round", type=int, required=True, dest="round_id")
    remediate.add_argument("--repo-root", type=Path, help="reviewed repository root; output must live outside it")
    remediate.add_argument("--output", type=Path, required=True)

    return parser.parse_args(argv)


def _command_review(args: argparse.Namespace) -> int:
    ensure_writable_output(args.output, repo_root=args.repo_root)

    request_bytes = read_regular_file(args.review_request, source="review request")
    scope_bytes = read_regular_file(args.scope_report, source="scope report")
    test_bytes = read_regular_file(args.test_report, source="test report")

    raw_request = load_strict_json(request_bytes, source="review request", error=ReviewGateError)
    request = validate_review_request(raw_request)
    evidence = load_evidence(scope_bytes, test_bytes)

    if args.issue_body_file is not None:
        body_bytes = read_regular_file(args.issue_body_file, source="issue body")
        require(
            sha256_hex(body_bytes) == request["candidate"]["issue_body_sha256"],
            "issue body file does not match the candidate issue_body_sha256",
            error=PreconditionError,
        )

    report = build_review_report(request, evidence)
    atomic_write(args.output, review_report_bytes(report))

    print(f"REVIEW {report['verdict']}")
    return EXIT_PASS if report["verdict"] in ACCEPTANCE_VERDICTS else EXIT_CHANGES


def _command_remediate(args: argparse.Namespace) -> int:
    ensure_writable_output(args.output, repo_root=args.repo_root)
    report_bytes = read_regular_file(args.review_report, source="review report")
    request = build_remediation_request(report_bytes, args.round_id)
    atomic_write(args.output, remediation_request_bytes(request))
    print(f"REMEDIATION round={request['remediation_round_id']} items={len(request['items'])}")
    return EXIT_PASS


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    handlers = {
        "review": _command_review,
        "remediate": _command_remediate,
    }
    try:
        return handlers[args.command](args)
    except ReviewGateError as exc:
        print(f"review-gate: {exc.code}: {redact_text(exc.message)}", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"review-gate: E_IO: {redact_text(str(exc))}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
