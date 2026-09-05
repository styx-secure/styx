#!/usr/bin/env python3
"""Derive the closed semantic execution relation from real Phase-A carriers."""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from canonical_json import dumps
from canonical_report import ReportError, store_report
from generate_structural_witnesses import WitnessGenerationError, derive_seed_registry
from inventory import (
    InventoryError,
    SEMANTIC_COUNT,
    derive_semantic_execution_relation,
    digest_lines,
    sha256_bytes,
)


REPORT_FIELDS = frozenset(
    {
        "acv048_phase_counts",
        "execution_phase_counts",
        "fixed_phase_counts",
        "positive_carrier_inventory_sha256",
        "schema",
        "seed_direction_counts",
        "seed_registry_sha256",
        "semantic_execution_relation_sha256",
        "semantic_instance_count",
        "semantic_instance_set_sha256",
        "status",
        "verdict",
    }
)

PHASES = (
    "BLIND_INPUT_EXECUTION",
    "POST_OUTPUT_MUTATION",
    "VALIDATOR_SELF_TEST",
)
FIXED_PHASE_COUNTS = {
    "BLIND_INPUT_EXECUTION": 575,
    "POST_OUTPUT_MUTATION": 4151,
    "VALIDATOR_SELF_TEST": 26,
}


class SemanticPreflightError(ValueError):
    """The derived semantic execution relation is not exact and closed."""


def _closed_counts(values: list[str], registry: tuple[str, ...]) -> dict[str, int]:
    observed = Counter(values)
    if set(observed) - set(registry):
        raise SemanticPreflightError("semantic execution phase is outside registry")
    return {name: observed[name] for name in registry}


def build_report_from_seed_registry(
    seed_registry: dict[str, Any], contract: Path
) -> dict[str, Any]:
    """Build non-authoritative preselection evidence for all semantic rows."""

    seed_rows = seed_registry.get("rows")
    if not isinstance(seed_rows, list) or len(seed_rows) != 87:
        raise SemanticPreflightError("semantic preflight requires 87 seed rows")
    directions = _closed_counts(
        [
            row.get("carrierDirection") if isinstance(row, dict) else ""
            for row in seed_rows
        ],
        ("REQUEST", "RESPONSE"),
    )
    rows = derive_semantic_execution_relation(contract, seed_registry)
    if len(rows) != SEMANTIC_COUNT:
        raise SemanticPreflightError("semantic execution relation count drift")
    instance_ids = [row["instanceId"] for row in rows]
    if len(set(instance_ids)) != SEMANTIC_COUNT:
        raise SemanticPreflightError("semantic execution instance collision")

    acv048 = [row for row in rows if row["semanticRuleId"] == "ACV-048"]
    fixed = [row for row in rows if row["semanticRuleId"] != "ACV-048"]
    acv048_counts = _closed_counts(
        [row["executionPhase"] for row in acv048], PHASES
    )
    fixed_counts = _closed_counts([row["executionPhase"] for row in fixed], PHASES)
    all_counts = _closed_counts([row["executionPhase"] for row in rows], PHASES)
    if fixed_counts != FIXED_PHASE_COUNTS:
        raise SemanticPreflightError("fixed semantic phase partition drift")
    if (
        len(acv048) != 783
        or acv048_counts["BLIND_INPUT_EXECUTION"] != directions["REQUEST"] * 9
        or acv048_counts["POST_OUTPUT_MUTATION"] != directions["RESPONSE"] * 9
        or acv048_counts["VALIDATOR_SELF_TEST"] != 0
    ):
        raise SemanticPreflightError("ACV-048 carrier phase partition drift")

    inventory_sha = seed_registry.get("positiveCarrierInventorySha256")
    if not isinstance(inventory_sha, str) or len(inventory_sha) != 64:
        raise SemanticPreflightError("positive carrier inventory identity is absent")
    return {
        "acv048_phase_counts": acv048_counts,
        "execution_phase_counts": all_counts,
        "fixed_phase_counts": fixed_counts,
        "positive_carrier_inventory_sha256": inventory_sha,
        "schema": "styx.app-core-iface0.semantic-preflight-report.v1",
        "seed_direction_counts": directions,
        "seed_registry_sha256": sha256_bytes(dumps(seed_registry)),
        "semantic_execution_relation_sha256": sha256_bytes(dumps(rows)),
        "semantic_instance_count": len(rows),
        "semantic_instance_set_sha256": digest_lines(instance_ids),
        "status": "PRESELECTION_EVIDENCE",
        "verdict": "PASS",
    }


def build_report(repo_root: Path, contract: Path, evidence_root: Path) -> dict[str, Any]:
    seed_registry, _cases = derive_seed_registry(repo_root, contract, evidence_root)
    return build_report_from_seed_registry(seed_registry, contract)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_report(
            args.repo_root.resolve(),
            args.contract.resolve(),
            args.evidence_root.resolve(),
        )
        store_report(args.output, report, allowed_fields=REPORT_FIELDS)
    except (
        InventoryError,
        OSError,
        ReportError,
        SemanticPreflightError,
        WitnessGenerationError,
    ) as error:
        print(f"APP-core semantic preflight: FAIL: {error}", file=sys.stderr)
        return 2
    print(
        "APP-core semantic preflight: PASS "
        f"instances={report['semantic_instance_count']} "
        f"relation_sha256={report['semantic_execution_relation_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
