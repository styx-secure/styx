#!/usr/bin/env python3
"""Build the canonical literal O-10 taxonomy registry."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from taxonomy import (  # noqa: E402
    ALIAS,
    EVENT_PRECEDENCE,
    K_PRECEDENCE,
    POST_C03_MARKERS,
    PRIMARY_ROWS,
    REMOTE_COLLAPSE,
)


def registry() -> dict[str, object]:
    primaries = []
    for identifier, row in sorted(PRIMARY_ROWS.items()):
        owner, stage, mutation, recovery, retry, observability = row
        primaries.append(
            {
                "id": identifier,
                "mutation": mutation,
                "observability": observability,
                "owner": owner,
                "recovery": recovery,
                "retry_precondition": retry,
                "stage": stage,
            }
        )
    return {
        "alias": {"id": ALIAS, "primary": "LINEAGE_QUARANTINED"},
        "event_precedence": list(EVENT_PRECEDENCE),
        "k_precedence": list(K_PRECEDENCE),
        "post_c03_markers": sorted(POST_C03_MARKERS),
        "primaries": primaries,
        "remote_collapse": REMOTE_COLLAPSE,
        "schema": "styx-o10-outcome-taxonomy/v1",
    }


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_bytes(registry()))
    print(f"O-10 taxonomy registry: PASS primaries={len(PRIMARY_ROWS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
