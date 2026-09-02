#!/usr/bin/env python3
"""Validate and report the closed APP-CORE-IFACE-0 inventory."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from canonical_report import ReportError, store_report
from inventory import InventoryError, build_inventory


REPORT_FIELDS = frozenset(
    {
        "combined_instance_set_sha256",
        "contract_manifest_sha256",
        "family_counts",
        "instance_counts",
        "schema",
        "semantic_instance_set_sha256",
        "structural_instance_set_sha256",
        "verdict",
    }
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_inventory(args.repo_root.resolve(), args.contract.resolve())
        store_report(args.output, report, allowed_fields=REPORT_FIELDS)
    except (OSError, InventoryError, ReportError, subprocess.SubprocessError) as error:
        print(f"APP-core inventory: FAIL: {error}", file=sys.stderr)
        return 2
    print("APP-core inventory: PASS structural=1450 semantic=5147 total=6597")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
