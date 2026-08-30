#!/usr/bin/env python3
"""Closed inventory and Phase-B anchor validation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from model import DISPOSITIONS, PROFILE


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
ANCHOR_PROFILE = {**PROFILE, "terminal_result": "B33B2B=BOUNDED_GO"}
PUBLIC_DERIVATIONS = {
    "profile": "EXACT_ANCHOR_PROFILE_WITHOUT_TERMINAL_RESULT",
    "retention-distance-five": "EPOCH_DISTANCE_LE_RETAINED_PAST_EPOCHS",
    "retention-distance-six": "EPOCH_DISTANCE_LE_RETAINED_PAST_EPOCHS",
    "two-candidate-selection": (
        "LOWER_UNSIGNED_LEXICOGRAPHIC_ACCOUNT_AFTER_FIXED_INPUT_CHECKS"
    ),
    "unsupported-recovery": "UNSUPPORTED_OPERATION_NONCLAIM",
}
ORACLE_ALLOWED_INPUTS = [
    "oracle-reader-task.json",
    "phase-b-anchor.json",
    "public-candidate-projections.json",
]
ORACLE_FORBIDDEN_INPUTS = [
    "canonical reports",
    "Gate-A normative source",
    "implementation source",
    "mutant registry",
    "prior reviews",
    "scenario expected dispositions",
]
ORACLE_QUESTIONS = [
    "Does the public profile name exactly three dependency pins, one registry-qualified ciphersuite, two member profiles and retention depth five?",
    "Does a current or retained-past-epoch public observation distinguish distance five from distance six?",
    "Does the two-candidate public projection select the lower authenticated account identity without application-derived input?",
    "Does any public projection claim adapter, product, transport, recovery, wire-format or persistence support?",
]


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
    if set(anchor) != {"profile", "reports", "schema"}:
        raise ValueError("anchor has unknown or missing keys")
    if anchor.get("schema") != "styx.ss0.phase-b-anchor.v1":
        raise ValueError("unknown anchor schema")
    if anchor.get("profile") != ANCHOR_PROFILE:
        raise ValueError("anchor profile mismatch")
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
    if not isinstance(cases, list) or len(cases) != 67:
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


def validate_public_reader_inputs(root: Path) -> int:
    package = root / "tools/causal-flow-simulator/ss0"
    task = load_unique(package / "oracle-reader-task.json")
    if set(task) != {"allowed_inputs", "forbidden_inputs", "questions", "schema"}:
        raise ValueError("oracle-reader task has unknown or missing keys")
    if task["schema"] != "styx.ss0.oracle-reader-task.v1":
        raise ValueError("unknown oracle-reader task schema")
    if task["allowed_inputs"] != ORACLE_ALLOWED_INPUTS:
        raise ValueError("oracle-reader allowed-input set mismatch")
    if task["forbidden_inputs"] != ORACLE_FORBIDDEN_INPUTS:
        raise ValueError("oracle-reader forbidden-input set mismatch")
    if task["questions"] != ORACLE_QUESTIONS:
        raise ValueError("oracle-reader question set mismatch")

    document = load_unique(package / "public-candidate-projections.json")
    if set(document) != {"projections", "schema"}:
        raise ValueError("public projections have unknown or missing keys")
    if document["schema"] != "styx.ss0.public-candidate-projections.v1":
        raise ValueError("unknown public-projection schema")
    projections = document["projections"]
    if not isinstance(projections, list) or len(projections) != len(PUBLIC_DERIVATIONS):
        raise ValueError("public-projection cardinality mismatch")
    if [row.get("id") for row in projections] != list(PUBLIC_DERIVATIONS):
        raise ValueError("public-projection identity or order mismatch")
    for row in projections:
        if not isinstance(row, dict) or set(row) != {"derivation", "id", "input"}:
            raise ValueError("public-projection shape mismatch")
        identity = row["id"]
        if row["derivation"] != PUBLIC_DERIVATIONS[identity]:
            raise ValueError("public-projection derivation mismatch")
        candidate = row["input"]
        if not isinstance(candidate, dict) or candidate.get("profile") != PROFILE:
            raise ValueError("public-projection profile mismatch")
        if any(key in candidate for key in ("assertion", "expected", "disposition", "result")):
            raise ValueError("oracle leaked into public projection")

    by_id = {row["id"]: row["input"] for row in projections}
    if set(by_id["profile"]) != {"operation", "profile"} or by_id["profile"]["operation"] != "profile":
        raise ValueError("public profile projection mismatch")
    for identity, message_epoch in (
        ("retention-distance-five", 7),
        ("retention-distance-six", 6),
    ):
        candidate = by_id[identity]
        if (
            set(candidate) != {"current_epoch", "message_epoch", "operation", "profile"}
            or candidate["operation"] != "retention"
            or candidate["current_epoch"] != 12
            or candidate["message_epoch"] != message_epoch
        ):
            raise ValueError("public retention projection mismatch")
    convergence = by_id["two-candidate-selection"]
    if set(convergence) != {"candidates", "operation", "profile"} or convergence["operation"] != "convergence":
        raise ValueError("public convergence projection mismatch")
    candidates = convergence["candidates"]
    if not isinstance(candidates, list) or len(candidates) != 2:
        raise ValueError("public convergence candidate mismatch")
    accounts = [
        candidate.get("account") if isinstance(candidate, dict) else None
        for candidate in candidates
    ]
    if not all(isinstance(account, str) for account in accounts) or sorted(accounts) != [
        "1" * 64,
        "2" * 64,
    ]:
        raise ValueError("public convergence account mismatch")
    required = {
        "app_witness_score": 0,
        "authenticated": True,
        "depth": 1,
        "parent": "parent-a",
        "proposal_free": True,
        "tip_priority": "ordinary",
    }
    if any(
        set(candidate) != {"account", *required}
        or any(candidate[key] != value for key, value in required.items())
        for candidate in candidates
    ):
        raise ValueError("public convergence constraint mismatch")
    recovery = by_id["unsupported-recovery"]
    if set(recovery) != {"operation", "profile"} or recovery["operation"] != "recovery":
        raise ValueError("public recovery non-claim mismatch")
    return len(projections)
