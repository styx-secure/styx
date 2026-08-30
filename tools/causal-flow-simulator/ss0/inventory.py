#!/usr/bin/env python3
"""Closed inventory and Phase-B anchor validation."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from model import DISPOSITIONS, OPERATION_FIELDS, PROFILE


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


def validate_inventory(document: dict[str, Any]) -> dict[str, Any]:
    if set(document) != {
        "atoms",
        "closed_dispositions",
        "owners",
        "schema",
        "witnesses",
    }:
        raise ValueError("inventory has unknown or missing keys")
    if document["schema"] != "styx.ss0.inventory.v2":
        raise ValueError("unknown inventory schema")
    owners = sorted((*DECISIONS, *OBLIGATIONS))
    if document["owners"] != owners:
        raise ValueError("owner set mismatch")
    if document["closed_dispositions"] != sorted(DISPOSITIONS):
        raise ValueError("disposition set mismatch")
    witnesses = document["witnesses"]
    if not isinstance(witnesses, list) or not witnesses:
        raise ValueError("witness inventory is empty")
    if [row.get("id") for row in witnesses] != sorted(
        row.get("id") for row in witnesses
    ):
        raise ValueError("witness order is not canonical")
    witness_ids: set[str] = set()
    inputs: set[str] = set()
    for witness in witnesses:
        if not isinstance(witness, dict) or set(witness) != {
            "expected",
            "id",
            "input",
        }:
            raise ValueError("witness shape mismatch")
        identity = witness["id"]
        if not isinstance(identity, str) or not identity or identity in witness_ids:
            raise ValueError("duplicate or invalid witness")
        witness_ids.add(identity)
        candidate = witness["input"]
        if not isinstance(candidate, dict):
            raise ValueError("witness input mismatch")
        operation = candidate.get("operation")
        expected_fields = OPERATION_FIELDS.get(
            operation, frozenset({"operation", "profile"})
        )
        if not isinstance(operation, str) or set(candidate) != expected_fields:
            raise ValueError("witness input field set mismatch")
        if "scenario_variant" in candidate:
            raise ValueError("non-behavioral witness discriminator")
        if "expected" in candidate or "assertion" in candidate:
            raise ValueError("oracle leaked into adapter input")
        encoded_input = json.dumps(
            candidate, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )
        if encoded_input in inputs:
            raise ValueError("duplicate executable witness input")
        inputs.add(encoded_input)
        expected = witness["expected"]
        if not isinstance(expected, dict) or set(expected) not in (
            {"applied", "disposition", "emitted_plaintext"},
            {"applied", "disposition", "emitted_plaintext", "selected"},
        ):
            raise ValueError("witness full observation mismatch")
        if (
            expected["disposition"] not in DISPOSITIONS
            or not isinstance(expected["applied"], bool)
            or not isinstance(expected["emitted_plaintext"], bool)
            or ("selected" in expected and not isinstance(expected["selected"], str))
        ):
            raise ValueError("witness full observation value mismatch")

    atoms = document["atoms"]
    required_atoms = {
        f"ATOM-{owner}-{kind}": (owner, kind)
        for owner in owners
        for kind in KINDS
    }
    if not isinstance(atoms, list) or [row.get("id") for row in atoms] != sorted(
        required_atoms
    ):
        raise ValueError("atom identity or order mismatch")
    relations: list[dict[str, object]] = []
    referenced: set[str] = set()
    for atom in atoms:
        if not isinstance(atom, dict) or set(atom) != {
            "id",
            "kind",
            "owner",
            "source_id",
            "witnesses",
        }:
            raise ValueError("atom shape mismatch")
        identity = atom["id"]
        owner, kind = required_atoms.get(identity, (None, None))
        if (
            atom["owner"] != owner
            or atom["kind"] != kind
            or atom["source_id"] != owner
        ):
            raise ValueError("atom owner, kind or source mismatch")
        mappings = atom["witnesses"]
        if not isinstance(mappings, list) or not mappings or [
            row.get("id") for row in mappings
        ] != sorted(row.get("id") for row in mappings):
            raise ValueError("atom witness relation mismatch")
        atom_seen: set[str] = set()
        for mapping in mappings:
            if not isinstance(mapping, dict) or set(mapping) != {"assertions", "id"}:
                raise ValueError("atom witness mapping shape mismatch")
            witness_id = mapping["id"]
            assertions = mapping["assertions"]
            if (
                witness_id not in witness_ids
                or witness_id in atom_seen
                or not isinstance(assertions, list)
                or not assertions
                or assertions != sorted(set(assertions))
                or not all(isinstance(value, str) and value for value in assertions)
            ):
                raise ValueError("atom witness mapping value mismatch")
            atom_seen.add(witness_id)
            referenced.add(witness_id)
            relations.append(
                {
                    "assertions": assertions,
                    "atom": identity,
                    "witness": witness_id,
                }
            )
    if referenced != witness_ids:
        raise ValueError("unreferenced executable witness")
    return {
        "atoms": atoms,
        "relations": sorted(
            relations, key=lambda row: (row["atom"], row["witness"])
        ),
        "witnesses": witnesses,
    }


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
        ("retention-distance-five", "7"),
        ("retention-distance-six", "6"),
    ):
        candidate = by_id[identity]
        if (
            set(candidate) != {"current_epoch", "message_epoch", "operation", "profile"}
            or candidate["operation"] != "retention"
            or candidate["current_epoch"] != "12"
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
