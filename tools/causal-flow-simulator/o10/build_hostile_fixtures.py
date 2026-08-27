"""Emit the checked-in hostile fixture corpus."""

from __future__ import annotations

import argparse
from pathlib import Path

from canonical_report import canonical_bytes
from fixtures import cases


FIELDS = frozenset({"cases", "schema"})


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = {"cases": cases(), "schema": "styx.o10-hostile-fixtures.v1"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_bytes(report, allowed_fields=FIELDS))
    print(f"O-10 fixtures: PASS cases={len(report['cases'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
