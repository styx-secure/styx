#!/usr/bin/env python3
"""Validate and report the closed APP-CORE-IFACE-0 inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import importlib.metadata
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True

from jsonschema.validators import Draft202012Validator

from canonical_json import CanonicalJsonError, dumps, loads
from canonical_report import ReportError, store_report
from generate_seed_registry import (
    OPERATIONS,
    SeedGenerationError,
    TERMINAL_IMPLEMENTATION_FILES,
    _case_ids,
    _coverage,
    _enforce_cross_case_response_state_non_disclosure,
    _evaluate_fixture_request,
    _positive_population,
    _reference_source_set_sha256,
    _semantic_request_carriers,
)
from interface_model import (
    ContractAuthority,
    InterfaceModelError,
    validate_request_structure,
    validate_response_before_release,
)
from inventory import InventoryError, build_inventory, verify_contract_package


REPORT_FIELDS = frozenset(
    {
        "combined_instance_set_sha256",
        "contract_manifest_sha256",
        "family_counts",
        "instance_counts",
        "schema",
        "semantic_instance_set_sha256",
        "structural_instance_set_sha256",
        "verdict",
    }
)


class PhaseAValidationError(ValueError):
    """The external Phase-A carrier package is not exact or reproducible."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _load_canonical(path: Path) -> dict[str, object]:
    if not path.is_file() or path.is_symlink():
        raise PhaseAValidationError(f"invalid Phase-A file: {path.name}")
    raw = path.read_bytes()
    try:
        value = loads(raw)
    except CanonicalJsonError as error:
        raise PhaseAValidationError(f"non-canonical Phase-A file: {path.name}") from error
    if not isinstance(value, dict) or dumps(value) != raw:
        raise PhaseAValidationError(f"invalid canonical object: {path.name}")
    return value


def _validate_positive_coverage_union(
    object_pointers: list[str],
    one_of_arms: list[tuple[str, int]],
    reachability: dict[str, object],
) -> None:
    """Require exact reconstructed coverage, including duplicate rejection."""

    object_rows = reachability.get("objectCoverage")
    arm_rows = reachability.get("oneOfArmCoverage")
    if not isinstance(object_rows, list) or not isinstance(arm_rows, list):
        raise PhaseAValidationError("POSITIVE_COVERAGE_UNION_DRIFT")
    expected_objects = {
        row.get("objectSchemaPointer")
        for row in object_rows
        if isinstance(row, dict) and isinstance(row.get("objectSchemaPointer"), str)
    }
    expected_arms = {
        (row.get("oneOfPointer"), row.get("armIndex"))
        for row in arm_rows
        if isinstance(row, dict)
        and isinstance(row.get("oneOfPointer"), str)
        and isinstance(row.get("armIndex"), int)
    }
    if (
        len(expected_objects) != 87
        or len(expected_arms) != 57
        or len(object_pointers) != len(set(object_pointers))
        or len(one_of_arms) != len(set(one_of_arms))
        or set(object_pointers) != expected_objects
        or set(one_of_arms) != expected_arms
    ):
        raise PhaseAValidationError("POSITIVE_COVERAGE_UNION_DRIFT")


def validate_phase_a(repo_root: Path, contract: Path, evidence_root: Path) -> dict[str, object]:
    """Independently reconstruct and validate every Phase-A identity."""

    verify_contract_package(contract)
    root = evidence_root.resolve()
    if not root.is_dir() or root.is_symlink():
        raise PhaseAValidationError("Phase-A evidence root is not a directory")
    if repo_root == root or repo_root in root.parents or root in repo_root.parents:
        raise PhaseAValidationError("Phase-A evidence root overlaps the repository")

    inventory_path = root / "positive-carrier-inventory.json"
    inventory = _load_canonical(inventory_path)
    schema = json.loads(
        (
            contract
            / "APP-CORE-IFACE-0-POSITIVE-CARRIER-INVENTORY-SCHEMA-CANDIDATE.json"
        ).read_bytes()
    )
    if list(Draft202012Validator(schema).iter_errors(inventory)):
        raise PhaseAValidationError("positive inventory schema validation failed")
    cases = inventory.get("cases")
    if not isinstance(cases, list) or inventory.get("caseCount") != 96:
        raise PhaseAValidationError("positive inventory case count drift")
    by_id = {
        row["caseId"]: row
        for row in cases
        if isinstance(row, dict) and isinstance(row.get("caseId"), str)
    }
    if len(by_id) != 96 or len(cases) != 96:
        raise PhaseAValidationError("positive inventory case ID collision")

    (
        expected_requests,
        expected_responses,
        expected_producers,
        expected_request_provenance,
        synthesizer,
        roots,
        reachability,
    ) = _positive_population(repo_root, contract)
    request_ids = _case_ids(expected_requests, "REQUEST")
    response_ids = _case_ids(expected_responses, "RESPONSE")
    expected_payloads = {**request_ids, **response_ids}
    if set(by_id) != set(expected_payloads.values()):
        raise PhaseAValidationError("stable positive case ID set drift")
    expected_inventory_header = {
        "inventoryVersion": "APP-CORE-IFACE-0-POSITIVE-CARRIERS-V1",
        "status": "PRE_RATIFICATION_CANDIDATE",
        "interfaceSchemaSha256": reachability["schemaSha256"],
        "oneOfArmSetSha256": reachability["oneOfArmSetSha256"],
        "objectSchemaPointerSetSha256": reachability[
            "objectSchemaPointerSetSha256"
        ],
        "caseCount": 96,
    }
    if any(inventory.get(key) != value for key, value in expected_inventory_header.items()):
        raise PhaseAValidationError("positive inventory authority header drift")
    expected_root_files = {
        "positive-carrier-inventory.json",
        "reference-toolchain.json",
        "phase-a-package-report.json",
        *(f"carriers/{case_id}.json" for case_id in expected_payloads.values()),
        *(
            f"reference-executions/{case_id}.json"
            for case_id in response_ids.values()
        ),
    }
    observed_root_files: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise PhaseAValidationError("Phase-A evidence contains a symlink")
        if path.is_dir():
            continue
        if not path.is_file():
            raise PhaseAValidationError("Phase-A evidence contains a non-regular entry")
        observed_root_files.add(path.relative_to(root).as_posix())
    if observed_root_files != expected_root_files:
        raise PhaseAValidationError("Phase-A external file set drift")

    authority = ContractAuthority.load(repo_root, contract)
    collision_oracles = {
        dumps(case.request): case.collision_oracle
        for case in _semantic_request_carriers(authority)
        if case.collision_oracle is not None
    }
    if len(collision_oracles) != 3:
        raise PhaseAValidationError(
            "closed test-only collision-oracle relation drift"
        )
    request_payload_by_id = {case_id: payload for payload, case_id in request_ids.items()}
    response_report_files: set[str] = set()
    submitted_requests: list[dict[str, object]] = []
    submitted_responses: list[dict[str, object]] = []
    reconstructed_objects: set[str] = set()
    reconstructed_arms: set[tuple[str, int]] = set()
    for payload, case_id in expected_payloads.items():
        row = by_id[case_id]
        carrier_file = row.get("carrierFile")
        if carrier_file != f"carriers/{case_id}.json":
            raise PhaseAValidationError("carrier path derivation drift")
        carrier_path = root / carrier_file
        if carrier_path.read_bytes() != payload:
            raise PhaseAValidationError(f"carrier byte drift: {case_id}")
        if row.get("carrierSha256") != _sha256(payload) or row.get("carrierOctets") != len(payload):
            raise PhaseAValidationError(f"carrier identity drift: {case_id}")
        value = loads(payload)
        if not isinstance(value, dict):
            raise PhaseAValidationError("carrier root is not an object")
        direction = row.get("direction")
        operation = row.get("operation")
        expected_direction = "REQUEST" if payload in expected_requests else "RESPONSE"
        if direction != expected_direction or operation not in OPERATIONS:
            raise PhaseAValidationError("carrier root relation drift")
        objects, arms = _coverage(
            synthesizer, roots[f"{direction}-{operation}"], value, reachability
        )
        if row.get("coveredObjectSchemaPointers") != objects or row.get("coveredOneOfArms") != arms:
            raise PhaseAValidationError(f"carrier coverage drift: {case_id}")
        reconstructed_objects.update(objects)
        reconstructed_arms.update(
            (arm["oneOfPointer"], arm["armIndex"]) for arm in arms
        )
        if direction == "REQUEST":
            submitted_requests.append(value)
            validate_request_structure(authority, value)
            response = _evaluate_fixture_request(
                authority, value, collision_oracles.get(payload)
            )
            validate_response_before_release(authority, response)
            if dumps(response) not in expected_responses:
                raise PhaseAValidationError("request reference output escaped closed set")
            if "requestCaseId" in row or "referenceExecutionReportSha256" in row:
                raise PhaseAValidationError("request contains response authority")
            continue

        submitted_responses.append(value)

        producer_ids = sorted(
            (
                request_ids[request_payload]
                for request_payload in expected_producers[payload]
                if expected_requests[request_payload]["operation"] == operation
            ),
            key=lambda value: value.encode("utf-8"),
        )
        if not producer_ids or row.get("requestCaseId") != producer_ids[0]:
            raise PhaseAValidationError("response request link is not first and exact")
        report_file = f"reference-executions/{case_id}.json"
        response_report_files.add(report_file)
        report_path = root / report_file
        report = _load_canonical(report_path)
        report_bytes = report_path.read_bytes()
        if row.get("referenceExecutionReportSha256") != _sha256(report_bytes):
            raise PhaseAValidationError("reference report digest drift")
        report_validator = Draft202012Validator(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$ref": "#/$defs/ReferenceExecutionReportV1",
                "$defs": schema["$defs"],
            }
        )
        if list(report_validator.iter_errors(report)):
            raise PhaseAValidationError("reference report schema failure")
        request_payload = request_payload_by_id[producer_ids[0]]
        expected_report = {
            "reportVersion": "APP-CORE-IFACE-0-REFERENCE-EXECUTION-V1",
            "contractManifestSha256": _sha256(
                (contract / "APP-CORE-IFACE-0-CANDIDATE-MANIFEST.json").read_bytes()
            ),
            "canonicalJsonSourceSha256": _sha256(
                (repo_root / "tools/causal-flow-simulator/app_core_iface0/canonical_json.py").read_bytes()
            ),
            "referenceSourceSetSha256": _reference_source_set_sha256(repo_root),
            "toolchainSha256": _sha256((root / "reference-toolchain.json").read_bytes()),
            "requestCaseId": producer_ids[0],
            "responseCaseId": case_id,
            "operation": operation,
            "requestCarrierSha256": _sha256(request_payload),
            "responseCarrierSha256": _sha256(payload),
            "requestValidation": "PASS",
            "referenceEvaluation": "COMPLETED",
            "responseReleaseValidation": "PASS",
        }
        if report != expected_report:
            raise PhaseAValidationError("reference report reconstruction drift")

    try:
        _enforce_cross_case_response_state_non_disclosure(
            synthesizer.schema,
            reachability,
            submitted_requests,
            submitted_responses,
        )
    except SeedGenerationError as error:
        raise PhaseAValidationError(str(error)) from error
    _validate_positive_coverage_union(
        sorted(reconstructed_objects),
        sorted(reconstructed_arms),
        reachability,
    )

    toolchain = _load_canonical(root / "reference-toolchain.json")
    if toolchain != {
        "jsonschemaVersion": importlib.metadata.version("jsonschema"),
        "pythonVersion": platform.python_version(),
    }:
        raise PhaseAValidationError("reference toolchain drift")

    package_path = root / "phase-a-package-report.json"
    package = _load_canonical(package_path)
    artifact_paths = sorted(
        (
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and path != package_path
        ),
        key=lambda value: value.encode("utf-8"),
    )
    expected_paths = {
        "positive-carrier-inventory.json",
        "reference-toolchain.json",
        *(f"carriers/{case_id}.json" for case_id in by_id),
        *response_report_files,
    }
    if set(artifact_paths) != expected_paths or len(artifact_paths) != 117:
        raise PhaseAValidationError("Phase-A external file set drift")
    artifacts = [
        {
            "path": relative,
            "sha256": _sha256((root / relative).read_bytes()),
            "octets": (root / relative).stat().st_size,
        }
        for relative in artifact_paths
    ]
    request_provenance = sorted(
        (
            {"caseId": request_ids[payload], **provenance}
            for payload, provenance in expected_request_provenance.items()
        ),
        key=lambda row: row["caseId"].encode("utf-8"),
    )
    if len(request_provenance) != 77:
        raise PhaseAValidationError("request provenance reconstruction count drift")
    expected_package = {
        "reportVersion": "APP-CORE-IFACE-0-PHASE-A-PACKAGE-V1",
        "status": "PRE_RATIFICATION_CANDIDATE",
        "verdict": "PASS",
        "contractManifestSha256": _sha256(
            (contract / "APP-CORE-IFACE-0-CANDIDATE-MANIFEST.json").read_bytes()
        ),
        "positiveCarrierInventorySha256": _sha256(inventory_path.read_bytes()),
        "referenceSourceSetSha256": _reference_source_set_sha256(repo_root),
        "toolchainSha256": _sha256((root / "reference-toolchain.json").read_bytes()),
        "caseCount": 96,
        "requestCaseCount": 77,
        "responseCaseCount": 19,
        "requestProvenance": request_provenance,
        "artifactCount": 117,
        "artifacts": artifacts,
    }
    if package != expected_package:
        raise PhaseAValidationError("Phase-A package report reconstruction drift")
    return {
        "case_count": 96,
        "inventory_sha256": _sha256(inventory_path.read_bytes()),
        "package_report_sha256": _sha256(package_path.read_bytes()),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--phase-a-evidence-root", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.phase_a_evidence_root is None:
            report = build_inventory(args.repo_root.resolve(), args.contract.resolve())
            store_report(args.output, report, allowed_fields=REPORT_FIELDS)
        else:
            result = validate_phase_a(
                args.repo_root.resolve(),
                args.contract.resolve(),
                args.phase_a_evidence_root,
            )
            store_report(
                args.output,
                {
                    "schema": "styx.app-core-iface0.phase-a-validation.v1",
                    "verdict": "PASS",
                    **result,
                },
                allowed_fields=frozenset(
                    {
                        "schema",
                        "verdict",
                        "case_count",
                        "inventory_sha256",
                        "package_report_sha256",
                    }
                ),
            )
    except (
        OSError,
        InventoryError,
        InterfaceModelError,
        SeedGenerationError,
        PhaseAValidationError,
        ReportError,
        subprocess.SubprocessError,
    ) as error:
        print(f"APP-core inventory: FAIL: {error}", file=sys.stderr)
        return 2
    if args.phase_a_evidence_root is None:
        print("APP-core inventory: PASS structural=1553 semantic=5535 total=7088")
    else:
        print("APP-core Phase A: PASS cases=96 requests=77 responses=19")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
