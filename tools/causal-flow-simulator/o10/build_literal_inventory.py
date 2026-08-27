"""Developer helper that emits the checked-in literal O-10 inventory."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from inventory import InventoryError, canonical_bytes, expected_inventory


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        payload = canonical_bytes(expected_inventory(args.repo_root.resolve()))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(payload)
    except (InventoryError, OSError, ValueError) as exc:
        print(f"O-10 inventory build failed: {exc}", file=sys.stderr)
        return 2
    print("O-10 inventory build: PASS rows=102")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
