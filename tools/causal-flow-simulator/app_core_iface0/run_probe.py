#!/usr/bin/env python3
"""Execute the closed APP-CORE Phase-A request population before oracle release."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from jsonschema.validators import Draft202012Validator

from canonical_json import CanonicalJsonError, dumps, loads
from canonical_report import ReportError, store_report
from interface_model import (
    ContractAuthority,
    HarnessFailure,
    InterfaceModelError,
    RequestRejected,
    evaluate_interface_request,
    validate_request_structure,
    validate_response_before_release,
)
from inventory import InventoryError, verify_contract_package
from validate_inventory import PhaseAValidationError, validate_phase_a


REPORT_FIELDS = frozenset(
    {
        "case_count",
        "inventory_sha256",
        "observation_set_sha256",
        "observations",
        "operation_counts",
        "request_case_count",
        "response_case_count",
        "schema",
        "verdict",
    }
)


class ProbeError(ValueError):
    """The blind request execution or post-freeze oracle comparison failed."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_object(path: Path) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or path.is_symlink():
        raise ProbeError("required Phase-A artifact is absent or non-regular")
    raw = path.read_bytes()
    try:
        value = loads(raw)
    except CanonicalJsonError as error:
        raise ProbeError("required Phase-A artifact is not canonical JSON") from error
    if not isinstance(value, dict) or dumps(value) != raw:
        raise ProbeError("required Phase-A artifact is not a canonical object")
    return value, raw


def build_report(repo_root: Path, contract: Path, evidence_root: Path) -> dict[str, Any]:
    """Freeze all reference outputs before reading any withheld response bytes."""

    verify_contract_package(contract)
    inventory, inventory_bytes = _canonical_object(
        evidence_root / "positive-carrier-inventory.json"
    )
    inventory_schema = json.loads(
        (
            contract
            / "APP-CORE-IFACE-0-POSITIVE-CARRIER-INVENTORY-SCHEMA-CANDIDATE.json"
        ).read_bytes()
    )
    if not isinstance(inventory_schema, dict) or list(
        Draft202012Validator(inventory_schema).iter_errors(inventory)
    ):
        raise ProbeError("positive carrier inventory schema validation failed")
    cases = inventory.get("cases")
    if not isinstance(cases, list) or len(cases) != 80:
        raise ProbeError("positive carrier inventory count drift")
    request_rows = [row for row in cases if row.get("direction") == "REQUEST"]
    if len(request_rows) != 65 or sum(
        row.get("direction") == "RESPONSE" for row in cases
    ) != 15:
        raise ProbeError("positive carrier direction partition drift")

    authority = ContractAuthority.load(repo_root, contract)
    frozen: dict[str, bytes] = {}
    operation_counts: Counter[str] = Counter()
    # This loop deliberately has no access to response carrier bytes.
    for row in sorted(request_rows, key=lambda item: item["caseId"].encode("utf-8")):
        carrier, carrier_bytes = _canonical_object(evidence_root / row["carrierFile"])
        if (
            _sha256(carrier_bytes) != row["carrierSha256"]
            or len(carrier_bytes) != row["carrierOctets"]
        ):
            raise ProbeError("blind request carrier identity drift")
        try:
            validate_request_structure(authority, carrier)
            response = evaluate_interface_request(authority, carrier)
            validate_response_before_release(authority, response)
        except (HarnessFailure, InterfaceModelError, RequestRejected) as error:
            raise ProbeError("blind reference execution failed closed") from error
        if response.get("operation") != row["operation"]:
            raise ProbeError("blind reference response operation drift")
        frozen[row["caseId"]] = dumps(response)
        operation_counts[row["operation"]] += 1

    # Oracle release occurs only after all 65 outputs have been frozen.
    response_rows = [row for row in cases if row.get("direction") == "RESPONSE"]
    response_by_bytes: dict[bytes, dict[str, Any]] = {}
    for row in response_rows:
        _value, payload = _canonical_object(evidence_root / row["carrierFile"])
        if (
            _sha256(payload) != row["carrierSha256"]
            or len(payload) != row["carrierOctets"]
            or payload in response_by_bytes
        ):
            raise ProbeError("withheld response carrier identity or uniqueness drift")
        response_by_bytes[payload] = row

    observations: list[dict[str, str]] = []
    for request_case_id, payload in sorted(frozen.items()):
        response_row = response_by_bytes.get(payload)
        if response_row is None:
            raise ProbeError("frozen response escaped the ratified oracle set")
        observations.append(
            {
                "requestCaseId": request_case_id,
                "responseCaseId": response_row["caseId"],
                "responseCarrierSha256": _sha256(payload),
            }
        )

    # Full package validation is intentionally post-freeze.
    validated = validate_phase_a(repo_root, contract, evidence_root)
    observation_bytes = dumps(observations)
    return {
        "case_count": 80,
        "inventory_sha256": validated["inventory_sha256"],
        "observation_set_sha256": _sha256(observation_bytes),
        "observations": observations,
        "operation_counts": dict(sorted(operation_counts.items())),
        "request_case_count": 65,
        "response_case_count": 15,
        "schema": "styx.app-core-iface0.reference-probe-report.v1",
        "verdict": "PASS",
    }


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
        InterfaceModelError,
        OSError,
        PhaseAValidationError,
        ProbeError,
        ReportError,
    ) as error:
        print(f"APP-core reference probe: FAIL: {error}", file=sys.stderr)
        return 2
    print("APP-core reference probe: PASS requests=65 responses=15")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
