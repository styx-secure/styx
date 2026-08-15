#!/usr/bin/env python3
"""Offline, deterministic observer for existing Styx governance evidence.

Exit 0 means only that a diagnostic report was emitted.  It is never an
authorization, gate verdict, or claim that a candidate is mergeable.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

sys.dont_write_bytecode = True

from model import (
    EXIT_DIAGNOSTIC,
    EXIT_INPUT,
    EXIT_INTERNAL,
    InputError,
    ObserverError,
    OutputError,
    atomic_write,
    build_report,
    canonical_json_bytes,
    ensure_output_path,
    load_candidate,
    read_evidence,
    read_required,
)


class ObserverArgumentParser(argparse.ArgumentParser):
    """Use the observer's documented invalid-input exit code."""

    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_INPUT)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = ObserverArgumentParser(
        description=(
            "Emit a report-only styx.evidence-status/v1 diagnosis. "
            "Exit 0 means report emitted, not gate success."
        )
    )
    parser.add_argument(
        "--candidate", type=Path, required=True, help="absolute path to the closed candidate identity JSON"
    )
    parser.add_argument(
        "--scope-report", type=Path, required=True, help="absolute path to scope evidence (may be missing)"
    )
    parser.add_argument(
        "--test-report", type=Path, required=True, help="absolute path to test evidence (may be missing)"
    )
    parser.add_argument(
        "--review-report", type=Path, required=True, help="absolute path to review evidence (may be missing)"
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        required=True,
        help="absolute reviewed repository root; output must be outside every Git worktree",
    )
    parser.add_argument("--output", type=Path, required=True, help="absolute path for the canonical diagnostic report")
    return parser.parse_args(argv)


def summary_lines(report: dict[str, object]) -> list[str]:
    """Return a deterministic summary using only closed states and identities."""

    candidate = report["candidate"]
    assert isinstance(candidate, dict)
    lines = [
        (
            "EVIDENCE STATUS (diagnostic only) "
            f"repository={candidate['repository']} issue={candidate['issue_number']} "
            f"base={candidate['base_sha']} head={candidate['head_sha']}"
        )
    ]
    items = report["items"]
    assert isinstance(items, list)
    for item in items:
        assert isinstance(item, dict)
        reasons = item["reasons"]
        assert isinstance(reasons, list)
        lines.append(f"{item['kind']}: {item['state']} [{','.join(reasons)}]")
    lines.append("Exit 0 means diagnostic report emitted; it is not an authorization verdict.")
    return lines


def run(args: argparse.Namespace) -> int:
    ensure_output_path(args.output, repo_root=args.repo_root)
    candidate = load_candidate(read_required(args.candidate, label="candidate"))
    inputs = {
        "scope": read_evidence(args.scope_report, label="scope report"),
        "test": read_evidence(args.test_report, label="test report"),
        "review": read_evidence(args.review_report, label="review report"),
    }
    report = build_report(candidate, inputs)
    atomic_write(args.output, canonical_json_bytes(report))
    print("\n".join(summary_lines(report)))
    return EXIT_DIAGNOSTIC


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run(parse_args(sys.argv[1:] if argv is None else argv))
    except (InputError, OutputError) as exc:
        print(f"evidence-status: {exc.code}: {exc.message}", file=sys.stderr)
        return EXIT_INPUT
    except ObserverError as exc:
        print(f"evidence-status: {exc.code}: {exc.message}", file=sys.stderr)
        return EXIT_INTERNAL
    except Exception:
        # Evidence is untrusted.  Unexpected exception details can include
        # caller paths or environment-derived text, so do not echo them.
        print("evidence-status: E_INTERNAL: unexpected observer failure", file=sys.stderr)
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
