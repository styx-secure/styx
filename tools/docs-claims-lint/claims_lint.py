#!/usr/bin/env python3
"""Advisory linter for forbidden security claims in documentation.

Enforces the CLAUDE.md policy: the product must not be advertised with
"serverless", "zero-knowledge" or equivalent claims while H1/H2 remain open.
The linter flags *affirmative* uses of the forbidden terms and allows negated,
honest usage ("this is not a serverless system"), which is the framing README
and PANORAMICA already use.

Detection model, deliberately simple and reviewable:

- a line containing a forbidden term is a finding, unless
- the same line or the immediately preceding non-blank line carries a negation
  cue (``not``, ``never``, ``non``, ``do not``, ...), or
- the line or the immediately preceding line carries the explicit suppression
  marker ``<!-- claims-lint: allow -->`` (for documents that legitimately
  discuss the claims, e.g. security reviews).

The check is advisory evidence, not merge authority: a finding turns the CI
check red for a human to look at; nothing is blocked automatically.

Exit codes follow the repository convention: 0 PASS, 2 findings, 3 error.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

FORBIDDEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("zero-server", re.compile(r"zero[\s-]server", re.IGNORECASE)),
    ("serverless", re.compile(r"\bserverless\b", re.IGNORECASE)),
    ("zero-knowledge", re.compile(r"zero[\s-]knowledge", re.IGNORECASE)),
    ("zero-metadata", re.compile(r"zero[\s-]metadata", re.IGNORECASE)),
    (
        "relay-cannot-read",
        re.compile(
            r"relays?\s+(cannot|can't|will\s+never)\s+read"
            r"|relay\s+non\s+pu[oò]\s+legger",
            re.IGNORECASE,
        ),
    ),
)

NEGATION_CUES = re.compile(
    r"\b(not|n't|never|no\s+longer|do(es)?\s+not|forbidden|avoid|without"
    r"|non|mai|né|senza|vietat[oaie]|evitare)\b",
    re.IGNORECASE,
)

SUPPRESSION_MARKER = "<!-- claims-lint: allow -->"

EXIT_PASS = 0
EXIT_FAIL = 2
EXIT_ERROR = 3


def line_is_allowed(line: str, previous_line: str, match: re.Match[str]) -> bool:
    """Return True when the surrounding context negates or suppresses a claim.

    Negation cues are searched on the line with the matched claim text
    removed: a negation word that is *part of the claim itself* ("il relay
    non può leggere") must not count as a negation *of* the claim.
    """
    if SUPPRESSION_MARKER in line or SUPPRESSION_MARKER in previous_line:
        return True
    context = line[: match.start()] + line[match.end() :]
    return bool(NEGATION_CUES.search(context) or NEGATION_CUES.search(previous_line))


def lint_text(text: str, path: str) -> list[str]:
    findings: list[str] = []
    previous_non_blank = ""
    for number, line in enumerate(text.splitlines(), start=1):
        for name, pattern in FORBIDDEN_PATTERNS:
            match = pattern.search(line)
            if match and not line_is_allowed(line, previous_non_blank, match):
                findings.append(
                    f"{path}:{number}: affirmative forbidden claim"
                    f" ({name}): {line.strip()[:120]}"
                )
        if line.strip():
            previous_non_blank = line
    return findings


def collect_markdown(roots: list[str], excludes: list[str]) -> list[Path]:
    excluded = [Path(e) for e in excludes]

    def is_excluded(path: Path) -> bool:
        return any(path == e or e in path.parents for e in excluded)

    files: list[Path] = []
    for root in roots:
        base = Path(root)
        if base.is_file():
            if not is_excluded(base):
                files.append(base)
        elif base.is_dir():
            files.extend(f for f in sorted(base.rglob("*.md")) if not is_excluded(f))
        else:
            raise FileNotFoundError(root)
    return files


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--scan",
        nargs="+",
        metavar="PATH",
        required=True,
        help="files or directories to lint (directories are scanned for *.md)",
    )
    parser.add_argument(
        "--exclude",
        nargs="*",
        metavar="PATH",
        default=[],
        help=(
            "files or directories to skip — for historical design records and"
            " analyses that legitimately discuss the forbidden claims"
        ),
    )
    args = parser.parse_args(argv)

    try:
        files = collect_markdown(args.scan, args.exclude)
    except FileNotFoundError as missing:
        print(f"claims-lint: path not found: {missing}", file=sys.stderr)
        return EXIT_ERROR

    findings: list[str] = []
    for file in files:
        try:
            text = file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            print(f"claims-lint: cannot read {file}: {exc}", file=sys.stderr)
            return EXIT_ERROR
        findings.extend(lint_text(text, str(file)))

    for finding in findings:
        print(finding)
    print(
        f"claims-lint: {len(files)} file(s) scanned,"
        f" {len(findings)} finding(s)"
    )
    return EXIT_FAIL if findings else EXIT_PASS


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main())
