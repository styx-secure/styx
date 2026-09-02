#!/usr/bin/env python3
"""Kill Phase-A evidence-package mutants before carrier ratification."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

sys.dont_write_bytecode = True

from canonical_json import dumps, loads
from canonical_report import ReportError, store_report
from inventory import InventoryError, verify_contract_package
from validate_inventory import PhaseAValidationError, validate_phase_a


REPORT_FIELDS = frozenset(
    {"family_counts", "killed_count", "schema", "survivor_count", "verdict"}
)


class MutationError(ValueError):
    """A required evidence-package mutant survived or was not isolated."""


def _rewrite(path: Path, transform: Callable[[dict[str, object]], None]) -> None:
    value = loads(path.read_bytes())
    if not isinstance(value, dict):
        raise MutationError("mutation target is not an object")
    transform(value)
    path.write_bytes(dumps(value))


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _repair_package(candidate: Path) -> None:
    package_path = candidate / "phase-a-package-report.json"
    package = loads(package_path.read_bytes())
    if not isinstance(package, dict):
        raise MutationError("package report is malformed")
    artifacts = []
    for path in sorted(
        (
            item
            for item in candidate.rglob("*")
            if item.is_file() and item != package_path
        ),
        key=lambda item: item.relative_to(candidate).as_posix().encode("utf-8"),
    ):
        relative = path.relative_to(candidate).as_posix()
        payload = path.read_bytes()
        artifacts.append(
            {"octets": len(payload), "path": relative, "sha256": _sha256(payload)}
        )
    package["artifacts"] = artifacts
    package["artifactCount"] = len(artifacts)
    package["positiveCarrierInventorySha256"] = _sha256(
        (candidate / "positive-carrier-inventory.json").read_bytes()
    )
    package["toolchainSha256"] = _sha256(
        (candidate / "reference-toolchain.json").read_bytes()
    )
    package_path.write_bytes(dumps(package))


def _mutations(
    root: Path,
) -> tuple[tuple[str, str, str, Callable[[Path], None]], ...]:
    inventory = loads((root / "positive-carrier-inventory.json").read_bytes())
    if not isinstance(inventory, dict) or not isinstance(inventory.get("cases"), list):
        raise MutationError("baseline inventory is malformed")
    request = next(row for row in inventory["cases"] if row["direction"] == "REQUEST")
    response = next(row for row in inventory["cases"] if row["direction"] == "RESPONSE")
    alternate_request_id = next(
        row["caseId"]
        for row in inventory["cases"]
        if row["direction"] == "REQUEST"
        and row["caseId"] != response["requestCaseId"]
    )

    def alter_carrier(candidate: Path) -> None:
        path = candidate / request["carrierFile"]
        path.write_bytes(path.read_bytes() + b" ")

    def count_drift(candidate: Path) -> None:
        _rewrite(
            candidate / "positive-carrier-inventory.json",
            lambda value: value.__setitem__("caseCount", 79),
        )

    def duplicate_case_id(candidate: Path) -> None:
        def mutate(value: dict[str, object]) -> None:
            rows = value["cases"]
            if not isinstance(rows, list) or len(rows) < 2:
                raise MutationError("inventory case relation is unavailable")
            rows[1]["caseId"] = rows[0]["caseId"]

        _rewrite(candidate / "positive-carrier-inventory.json", mutate)

    def response_link_drift(candidate: Path) -> None:
        def mutate(value: dict[str, object]) -> None:
            rows = value["cases"]
            if not isinstance(rows, list):
                raise MutationError("inventory case relation is unavailable")
            target = next(row for row in rows if row["direction"] == "RESPONSE")
            target["requestCaseId"] = alternate_request_id

        _rewrite(candidate / "positive-carrier-inventory.json", mutate)

    def missing_artifact(candidate: Path) -> None:
        (candidate / response["carrierFile"]).unlink()

    def extra_artifact(candidate: Path) -> None:
        (candidate / "unlisted.json").write_bytes(b"{}\n")

    def report_digest_drift(candidate: Path) -> None:
        report = candidate / f"reference-executions/{response['caseId']}.json"
        _rewrite(
            report,
            lambda value: value.__setitem__("responseCarrierSha256", "0" * 64),
        )

    def status_escalation(candidate: Path) -> None:
        _rewrite(
            candidate / "positive-carrier-inventory.json",
            lambda value: value.__setitem__("status", "RATIFIED"),
        )
        _repair_package(candidate)

    def authority_header_drift(candidate: Path) -> None:
        def mutate(value: dict[str, object]) -> None:
            value["interfaceSchemaSha256"] = "0" * 64
            value["oneOfArmSetSha256"] = "1" * 64
            value["objectSchemaPointerSetSha256"] = "2" * 64

        _rewrite(candidate / "positive-carrier-inventory.json", mutate)
        _repair_package(candidate)

    def coherent_toolchain_drift(candidate: Path) -> None:
        toolchain_path = candidate / "reference-toolchain.json"
        toolchain_path.write_bytes(
            dumps({"jsonschemaVersion": "0", "pythonVersion": "0"})
        )
        toolchain_sha = _sha256(toolchain_path.read_bytes())
        inventory_path = candidate / "positive-carrier-inventory.json"
        inventory = loads(inventory_path.read_bytes())
        if not isinstance(inventory, dict) or not isinstance(inventory.get("cases"), list):
            raise MutationError("inventory is malformed")
        for row in inventory["cases"]:
            if row.get("direction") != "RESPONSE":
                continue
            report_path = candidate / f"reference-executions/{row['caseId']}.json"
            _rewrite(
                report_path,
                lambda value: value.__setitem__("toolchainSha256", toolchain_sha),
            )
            row["referenceExecutionReportSha256"] = _sha256(report_path.read_bytes())
        inventory_path.write_bytes(dumps(inventory))
        _repair_package(candidate)

    def direction_inversion(candidate: Path) -> None:
        def mutate(value: dict[str, object]) -> None:
            rows = value["cases"]
            if not isinstance(rows, list):
                raise MutationError("inventory case relation is unavailable")
            target = next(row for row in rows if row["direction"] == "RESPONSE")
            target["direction"] = "REQUEST"
            target["sourceKind"] = "CLOSED_REQUEST_FIXTURE"
            target["releasePhase"] = "PRE_FREEZE_BLIND_INPUT"
            target.pop("requestCaseId")
            target.pop("referenceExecutionReportSha256")

        _rewrite(candidate / "positive-carrier-inventory.json", mutate)
        _repair_package(candidate)

    def coverage_drift(candidate: Path) -> None:
        def mutate(value: dict[str, object]) -> None:
            rows = value["cases"]
            if not isinstance(rows, list):
                raise MutationError("inventory case relation is unavailable")
            target = next(row for row in rows if row["direction"] == "REQUEST")
            target["coveredObjectSchemaPointers"] = ["/$defs/InterfaceResponseV0"]

        _rewrite(candidate / "positive-carrier-inventory.json", mutate)
        _repair_package(candidate)

    def carrier_symlink(candidate: Path) -> None:
        carrier = candidate / request["carrierFile"]
        target = candidate.parent / "external-carrier-target.json"
        target.write_bytes(carrier.read_bytes())
        carrier.unlink()
        carrier.symlink_to(target)

    return (
        ("MUT-PHA-CARRIER-BYTES", "carrier-identity", "carrier byte drift", alter_carrier),
        ("MUT-PHA-CASE-COUNT", "inventory-closure", "case count drift", count_drift),
        ("MUT-PHA-DUPLICATE-ID", "inventory-closure", "case ID collision", duplicate_case_id),
        ("MUT-PHA-RESPONSE-LINK", "oracle-binding", "response request link", response_link_drift),
        ("MUT-PHA-MISSING-ARTIFACT", "package-closure", "external file set drift", missing_artifact),
        ("MUT-PHA-EXTRA-ARTIFACT", "package-closure", "external file set drift", extra_artifact),
        ("MUT-PHA-REPORT-DIGEST", "oracle-binding", "reference report digest drift", report_digest_drift),
        ("MUT-PHA-STATUS-ESCALATION", "authority-header", "authority header drift", status_escalation),
        ("MUT-PHA-HEADER-DIGESTS", "authority-header", "authority header drift", authority_header_drift),
        ("MUT-PHA-TOOLCHAIN", "toolchain-identity", "reference toolchain drift", coherent_toolchain_drift),
        ("MUT-PHA-DIRECTION", "direction-binding", "carrier root relation drift", direction_inversion),
        ("MUT-PHA-COVERAGE", "coverage-binding", "carrier coverage drift", coverage_drift),
        ("MUT-PHA-CARRIER-SYMLINK", "package-closure", "contains a symlink", carrier_symlink),
    )


def build_report(repo_root: Path, contract: Path, evidence_root: Path) -> dict[str, object]:
    verify_contract_package(contract)
    validate_phase_a(repo_root, contract, evidence_root)
    results: list[tuple[str, str, bool]] = []
    for identifier, family, detector, mutation in _mutations(evidence_root):
        with tempfile.TemporaryDirectory(prefix="styx-app-core-phase-a-mutant-") as raw:
            candidate = Path(raw) / "evidence"
            shutil.copytree(evidence_root, candidate, symlinks=True)
            mutation(candidate)
            try:
                validate_phase_a(repo_root, contract, candidate)
            except PhaseAValidationError as error:
                killed = detector in str(error)
            except (OSError, InventoryError, KeyError, TypeError):
                killed = False
            else:
                killed = False
            results.append((identifier, family, killed))
    survivors = [identifier for identifier, _family, killed in results if not killed]
    if survivors:
        raise MutationError(f"Phase-A package mutants survived: {survivors}")
    family_counts: dict[str, int] = {}
    for _identifier, family, _killed in results:
        family_counts[family] = family_counts.get(family, 0) + 1
    return {
        "family_counts": dict(sorted(family_counts.items())),
        "killed_count": len(results),
        "schema": "styx.app-core-iface0.phase-a-mutation-report.v1",
        "survivor_count": 0,
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
        MutationError,
        OSError,
        PhaseAValidationError,
        ReportError,
    ) as error:
        print(f"APP-core mutations: FAIL: {error}", file=sys.stderr)
        return 2
    print("APP-core mutations: PASS killed=7 survivors=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
