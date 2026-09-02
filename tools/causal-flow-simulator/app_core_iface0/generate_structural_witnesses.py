#!/usr/bin/env python3
"""Derive the immutable structural-instance plan before Phase-B synthesis."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from canonical_json import dumps
from canonical_report import ReportError, store_report
from inventory import (
    InventoryError,
    STRUCTURAL_COUNT,
    _load_json,
    expand_structural_instances,
    verify_contract_package,
)


PLAN_FIELDS = frozenset(
    {
        "instance_count",
        "instance_set_sha256",
        "rows",
        "schema",
        "verdict",
    }
)


class WitnessGenerationError(ValueError):
    """The contract-driven structural plan cannot be derived exactly."""


def derive_structural_plan(contract: Path) -> dict[str, Any]:
    """Derive fields that are independent of carrier selection and oracle release."""

    verify_contract_package(contract)
    axes = _load_json(contract / "APP-CORE-IFACE-0-STRUCTURAL-AXES-CANDIDATE.json")
    by_id = {row["id"]: row for row in axes["rules"]}
    if len(by_id) != 24:
        raise WitnessGenerationError("structural rule registry drift")
    rows: list[dict[str, str]] = []
    for instance in expand_structural_instances(contract):
        rule = by_id.get(instance.family_id)
        if rule is None:
            raise WitnessGenerationError("structural instance has no owning rule")
        rows.append(
            {
                "assertionId": instance.assertion_id,
                "detectorId": instance.detector_id,
                "expectedDisposition": instance.expected_disposition,
                "instanceId": instance.instance_id,
                "isolationMode": rule.get(
                    "isolationMode", "TARGET_ONLY_COUNTERFACTUAL"
                ),
                "mutationId": instance.perturbation_id.replace("PRT-", "MUT-", 1),
                "perturbationId": instance.perturbation_id,
                "perturbationKind": rule["perturbationKind"],
                "sourcePointerOrRowId": instance.source,
                "structuralRuleId": instance.family_id,
            }
        )
    if len(rows) != STRUCTURAL_COUNT or len({row["instanceId"] for row in rows}) != STRUCTURAL_COUNT:
        raise WitnessGenerationError("structural plan count or identity drift")
    instance_set = hashlib.sha256(
        "".join(row["instanceId"] + "\n" for row in rows).encode("utf-8")
    ).hexdigest()
    return {
        "instance_count": STRUCTURAL_COUNT,
        "instance_set_sha256": instance_set,
        "rows": rows,
        "schema": "styx.app-core-iface0.structural-instance-plan.v1",
        "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--derive-plan", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if not args.derive_plan:
            raise WitnessGenerationError(
                "Phase-B witness synthesis requires provider-bound carrier ratification"
            )
        report = derive_structural_plan(args.contract.resolve())
        store_report(args.output, report, allowed_fields=PLAN_FIELDS)
    except (InventoryError, OSError, ReportError, WitnessGenerationError) as error:
        print(f"APP-core structural generation: FAIL: {error}", file=sys.stderr)
        return 2
    print("APP-core structural plan: PASS instances=1450")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
