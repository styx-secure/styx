#!/usr/bin/env python3
"""Kill Phase-A evidence-package mutants before carrier ratification."""

from __future__ import annotations

import argparse
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


def _mutations(root: Path) -> tuple[tuple[str, str, Callable[[Path], None]], ...]:
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

    return (
        ("MUT-PHA-CARRIER-BYTES", "carrier-identity", alter_carrier),
        ("MUT-PHA-CASE-COUNT", "inventory-closure", count_drift),
        ("MUT-PHA-DUPLICATE-ID", "inventory-closure", duplicate_case_id),
        ("MUT-PHA-RESPONSE-LINK", "oracle-binding", response_link_drift),
        ("MUT-PHA-MISSING-ARTIFACT", "package-closure", missing_artifact),
        ("MUT-PHA-EXTRA-ARTIFACT", "package-closure", extra_artifact),
        ("MUT-PHA-REPORT-DIGEST", "oracle-binding", report_digest_drift),
    )


def build_report(repo_root: Path, contract: Path, evidence_root: Path) -> dict[str, object]:
    verify_contract_package(contract)
    validate_phase_a(repo_root, contract, evidence_root)
    results: list[tuple[str, str, bool]] = []
    for identifier, family, mutation in _mutations(evidence_root):
        with tempfile.TemporaryDirectory(prefix="styx-app-core-phase-a-mutant-") as raw:
            candidate = Path(raw) / "evidence"
            shutil.copytree(evidence_root, candidate, symlinks=True)
            mutation(candidate)
            try:
                validate_phase_a(repo_root, contract, candidate)
            except (OSError, PhaseAValidationError, InventoryError, KeyError, TypeError):
                killed = True
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
