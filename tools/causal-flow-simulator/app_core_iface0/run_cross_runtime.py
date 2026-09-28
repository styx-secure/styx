#!/usr/bin/env python3
"""Run the independent JavaScript Phase-A response-release boundary."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from canonical_json import CanonicalJsonError, dumps, loads
from canonical_report import ReportError, store_report
from inventory import InventoryError, verify_contract_package
from validate_inventory import PhaseAValidationError, validate_phase_a


REPORT_FIELDS = frozenset(
    {
        "inventory_sha256",
        "response_case_count",
        "response_set_sha256",
        "schema",
        "verdict",
    }
)


class CrossRuntimeError(ValueError):
    """The independent JavaScript release reader failed or disagreed."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _load_object(path: Path) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or path.is_symlink():
        raise CrossRuntimeError("cross-runtime artifact is absent or non-regular")
    raw = path.read_bytes()
    try:
        value = loads(raw)
    except CanonicalJsonError as error:
        raise CrossRuntimeError("cross-runtime artifact is non-canonical") from error
    if not isinstance(value, dict) or dumps(value) != raw:
        raise CrossRuntimeError("cross-runtime artifact is not a canonical object")
    return value, raw


def _validate_static_isolation(adapter: Path) -> None:
    source = adapter.read_text(encoding="utf-8")
    forbidden = (
        "interface_model.py",
        "generate_seed_registry.py",
        "validate_inventory.py",
        "child_process",
        "python",
    )
    if any(token in source for token in forbidden):
        raise CrossRuntimeError("JavaScript reader shares a Python or fixture oracle")
    imports = sorted(
        line.strip() for line in source.splitlines() if line.startswith("import ")
    )
    if imports != sorted(
        [
            'import crypto from "node:crypto";',
            'import fs from "node:fs";',
            'import path from "node:path";',
            'import process from "node:process";',
        ]
    ):
        raise CrossRuntimeError("JavaScript import boundary drift")


def build_report(
    repo_root: Path,
    contract: Path,
    evidence_root: Path,
    javascript: str,
) -> dict[str, Any]:
    verify_contract_package(contract)
    validated = validate_phase_a(repo_root, contract, evidence_root)
    inventory, _inventory_bytes = _load_object(
        evidence_root / "positive-carrier-inventory.json"
    )
    adapter = repo_root / "tools/causal-flow-simulator/app_core_iface0/node_adapter.mjs"
    _validate_static_isolation(adapter)
    response_rows = sorted(
        (row for row in inventory["cases"] if row["direction"] == "RESPONSE"),
        key=lambda row: row["caseId"].encode("utf-8"),
    )
    if len(response_rows) != 19:
        raise CrossRuntimeError("withheld response partition drift")
    response_identities: list[str] = []
    for row in response_rows:
        _value, payload = _load_object(evidence_root / row["carrierFile"])
        completed = subprocess.run(
            [
                javascript,
                str(adapter),
                "--validate-response",
                "--contract",
                str(contract),
            ],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
        if completed.returncode != 0 or completed.stdout != b'{"verdict":"PASS"}\n':
            raise CrossRuntimeError("JavaScript response-release validation failed")
        response_identities.append(f"{row['caseId']}\t{_sha256(payload)}\n")
    response_set_sha = _sha256("".join(response_identities).encode("utf-8"))
    return {
        "inventory_sha256": validated["inventory_sha256"],
        "response_case_count": 19,
        "response_set_sha256": response_set_sha,
        "schema": "styx.app-core-iface0.phase-a-js-release-report.v1",
        "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--javascript", default="node")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_report(
            args.repo_root.resolve(),
            args.contract.resolve(),
            args.evidence_root.resolve(),
            args.javascript,
        )
        store_report(args.output, report, allowed_fields=REPORT_FIELDS)
    except (
        CrossRuntimeError,
        InventoryError,
        OSError,
        PhaseAValidationError,
        ReportError,
        subprocess.SubprocessError,
    ) as error:
        print(f"APP-core cross-runtime: FAIL: {error}", file=sys.stderr)
        return 2
    print("APP-core cross-runtime: PASS released-responses=19")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
