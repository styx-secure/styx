"""Validate the checked-in O-10 source inventory fail closed."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from inventory import InventoryError, validate_literal


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        inventory = validate_literal(args.repo_root.resolve())
    except (InventoryError, OSError, ValueError) as exc:
        print(f"O-10 inventory: FAIL: {exc}", file=sys.stderr)
        return 2
    positives = sum(row["kind"] == "positive" for row in inventory["rows"])
    negatives = len(inventory["rows"]) - positives
    print(f"O-10 inventory: PASS rows={len(inventory['rows'])} positive={positives} negative={negatives}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
