#!/usr/bin/env python3
"""Closed inventory and Phase-B anchor validation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from model import DISPOSITIONS


DECISIONS = tuple(f"SSD-{index:02d}" for index in range(1, 12))
OBLIGATIONS = tuple(f"OB-SS{index:02d}" for index in range(1, 10))
KINDS = ("FORBIDDEN_SUBSTITUTION", "HOSTILE_BOUNDARY", "POSITIVE")
REPORT_DIGESTS = {
    "phase-b-verdict": "73922a8c2c2bf6acb27cde6d48288adeaa0ee924deb3cb44ad28e424e91a210e",
    "phase-b3-3a": "8e53b5c2c138a80cab0596ef57b1fdd05118e1eabb86eb7e4d103416ec27e9c8",
    "phase-b3-3b-1": "435a135e89d2e5c7ce6160462e1018f44d7daf8712a66200e706b4249d38800b",
    "phase-b3-3b-2a": "d83329844439c302d120da241792691dcd2b99a34969aa0783ab54a2622b4d6b",
    "phase-b3-3b-2b": "0d1e2015bd30bc6e9f0c293a74ef26afd43c7d328f8d0e6c4cd8cbde3140b660",
}


def load_unique(path: Path) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in values:
            if key in result:
                raise ValueError(f"duplicate key: {key}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs)


def validate_anchor(root: Path, anchor: dict[str, Any]) -> None:
    if anchor.get("schema") != "styx.ss0.phase-b-anchor.v1":
        raise ValueError("unknown anchor schema")
    reports = anchor.get("reports")
    if not isinstance(reports, list) or len(reports) != len(REPORT_DIGESTS):
        raise ValueError("anchor report set mismatch")
    observed: dict[str, str] = {}
    for report in reports:
        if not isinstance(report, dict) or set(report) != {"label", "path", "sha256"}:
            raise ValueError("invalid anchor report")
        path = root / report["path"]
        if not path.is_file() or path.is_symlink():
            raise ValueError("anchor path unavailable")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != report["sha256"]:
            raise ValueError("anchor digest mismatch")
        observed[report["label"]] = digest
    if observed != REPORT_DIGESTS:
        raise ValueError("anchor labels or digests mismatch")


def validate_inventory(document: dict[str, Any]) -> list[dict[str, Any]]:
    if set(document) != {"cases", "closed_dispositions", "owners", "schema"}:
        raise ValueError("inventory has unknown or missing keys")
    if document["schema"] != "styx.ss0.inventory.v1":
        raise ValueError("unknown inventory schema")
    owners = sorted((*DECISIONS, *OBLIGATIONS))
    if document["owners"] != owners:
        raise ValueError("owner set mismatch")
    if document["closed_dispositions"] != sorted(DISPOSITIONS):
        raise ValueError("disposition set mismatch")
    cases = document["cases"]
    if not isinstance(cases, list) or len(cases) != 66:
        raise ValueError("inventory cardinality mismatch")
    if [case.get("id") for case in cases] != sorted(case.get("id") for case in cases):
        raise ValueError("case order is not canonical")
    ids: set[str] = set()
    inputs: set[str] = set()
    relation: set[tuple[str, str]] = set()
    for case in cases:
        if not isinstance(case, dict) or set(case) != {
            "assertion", "expected", "id", "input", "kind", "owner"
        }:
            raise ValueError("case shape mismatch")
        if case["id"] in ids or not isinstance(case["assertion"], str) or not case["assertion"]:
            raise ValueError("duplicate case or empty assertion")
        ids.add(case["id"])
        if case["owner"] not in owners or case["kind"] not in KINDS:
            raise ValueError("case owner or kind mismatch")
        if case["expected"] not in DISPOSITIONS or not isinstance(case["input"], dict):
            raise ValueError("case expected result or input mismatch")
        if "expected" in case["input"] or "assertion" in case["input"]:
            raise ValueError("oracle leaked into adapter input")
        encoded_input = json.dumps(
            case["input"], ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )
        if encoded_input in inputs:
            raise ValueError("one candidate input cannot evidence distinct atoms")
        inputs.add(encoded_input)
        relation.add((case["owner"], case["kind"]))
    required = {(owner, kind) for owner in owners for kind in KINDS}
    if relation != required:
        raise ValueError("owner-kind relation is incomplete")
    return cases
