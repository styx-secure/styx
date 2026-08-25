#!/usr/bin/env python3
"""Validate both canonical-report runs against the actual final bundle identity."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys


sys.dont_write_bytecode = True

O07_ROOT = Path(__file__).resolve().parent
if str(O07_ROOT) not in sys.path:
    sys.path.insert(0, str(O07_ROOT))

from report_schema import (  # noqa: E402
    CROSS_RUNTIME_SCHEMA,
    MUTATION_SCHEMA,
    PROBE_SCHEMA,
    SCOPE_SCHEMA,
    repository_hygiene_context,
    validate_canonical_report,
)


EXPECTED_SCHEMAS = frozenset(
    {PROBE_SCHEMA, CROSS_RUNTIME_SCHEMA, MUTATION_SCHEMA, SCOPE_SCHEMA}
)


def _canonical_bytes(report: dict[str, object]) -> bytes:
    return (
        json.dumps(report, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def validate_final_reports(
    *,
    repo: Path,
    base: str,
    candidate: str,
    bundle: Path,
    report_paths: list[Path],
) -> str:
    """Require two identical canonical reports per schema and the real bundle SHA."""

    bundle_bytes = bundle.read_bytes()
    if not bundle_bytes:
        raise ValueError("final Git bundle is empty")
    bundle_identity = hashlib.sha256(bundle_bytes).hexdigest()
    hygiene = repository_hygiene_context(
        repo,
        base,
        candidate,
        additional_identities=(bundle_identity,),
    )

    by_schema: dict[str, list[bytes]] = defaultdict(list)
    for path in report_paths:
        raw = path.read_bytes()
        report = json.loads(raw)
        validated = validate_canonical_report(report, hygiene_context=hygiene)
        if raw != _canonical_bytes(validated):
            raise ValueError(f"non-canonical report bytes: {path.name}")
        by_schema[str(validated["schema"])].append(raw)

    counts = Counter({schema: len(items) for schema, items in by_schema.items()})
    expected_counts = Counter({schema: 2 for schema in EXPECTED_SCHEMAS})
    if counts != expected_counts:
        raise ValueError("final evidence requires two reports for each canonical schema")
    for schema, items in by_schema.items():
        if items[0] != items[1]:
            raise ValueError(f"two-worktree report mismatch: {schema}")
    return bundle_identity


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--report", required=True, action="append", type=Path)
    args = parser.parse_args(argv)
    try:
        bundle_identity = validate_final_reports(
            repo=args.repo_root.resolve(),
            base=args.base,
            candidate=args.candidate,
            bundle=args.bundle,
            report_paths=args.report,
        )
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        print(f"O-07 final evidence hygiene failed: {error}", file=sys.stderr)
        return 2
    print(
        "O-07 FINAL EVIDENCE HYGIENE verdict=PASS "
        f"reports={len(args.report)} bundle_sha256={bundle_identity}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
