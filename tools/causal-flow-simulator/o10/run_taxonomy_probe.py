"""Run all literal hostile fixtures against the Python reference."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from canonical_report import ReportError, store_report
from fixtures import cases
from taxonomy import evaluate


REPORT_FIELDS = frozenset(
    {"family_counts", "primary_counts", "result_count", "schema", "verdict"}
)


def build_report() -> dict[str, object]:
    family_counts: Counter[str] = Counter()
    primary_counts: Counter[str] = Counter()
    for case in cases():
        observed = evaluate(case["input"])
        if observed.primary != case["expected_primary"]:
            raise ValueError(f"fixture mismatch: {case['input']['id']}")
        expected_remote = case.get("expected_remote")
        if expected_remote is not None and observed.as_dict()["remote"]["result"] != expected_remote:
            raise ValueError(f"privacy mismatch: {case['input']['id']}")
        family_counts[case["family"]] += 1
        primary_counts[observed.primary] += 1
    return {
        "family_counts": dict(sorted(family_counts.items())),
        "primary_counts": dict(sorted(primary_counts.items())),
        "result_count": sum(family_counts.values()),
        "schema": "styx.o10-probe-report.v1",
        "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        store_report(args.output, build_report(), allowed_fields=REPORT_FIELDS)
    except (OSError, ValueError, ReportError, json.JSONDecodeError) as exc:
        print(f"O-10 probe: FAIL: {exc}", file=sys.stderr)
        return 2
    print(f"O-10 probe: PASS cases={build_report()['result_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
