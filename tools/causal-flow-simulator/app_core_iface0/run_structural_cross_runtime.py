#!/usr/bin/env python3
"""Execute the ratified Phase-B structural relation in Python and JavaScript."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from canonical_json import dumps
from canonical_report import ReportError, store_report
from generate_structural_witnesses import (
    STRUCTURAL_EXECUTION_FIELDS,
    WitnessGenerationError,
    derive_structural_python_execution,
)
from inventory import InventoryError, sha256_bytes


PRIVATE_DIAGNOSTIC_TOKENS = (
    b"branchTrace",
    b"nestedOperationArmIndex",
    b"topLevelArmIndex",
    b"branch trace",
    b"branch-trace",
)


class StructuralCrossRuntimeError(ValueError):
    """One runtime failed to reproduce the closed structural relation."""


def _node_accepts(
    node: str,
    adapter: Path,
    contract: Path,
    raw_document: bytes,
    direction: str,
    *,
    mutant_schema: dict[str, Any] | None,
    v1_detector_mutant: bool,
    schema_path: Path,
) -> bool:
    command = [
        node,
        str(adapter),
        "--validate-v2-evidence",
        "--direction",
        direction,
        "--contract",
        str(contract),
    ]
    if mutant_schema is not None:
        schema_path.write_text(
            json.dumps(mutant_schema, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        command.extend(("--schema-override", str(schema_path)))
    if v1_detector_mutant:
        command.append("--v1-detector-mutant")
    completed = subprocess.run(
        command,
        input=raw_document,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    diagnostics = completed.stdout + completed.stderr
    if any(token.lower() in diagnostics.lower() for token in PRIVATE_DIAGNOSTIC_TOKENS):
        raise StructuralCrossRuntimeError("private branch diagnostic escaped")
    if completed.returncode == 0:
        try:
            result = json.loads(completed.stdout)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise StructuralCrossRuntimeError("JavaScript result is malformed") from error
        if result != {"verdict": "PASS"} or completed.stderr:
            raise StructuralCrossRuntimeError("JavaScript success result drift")
        return True
    if completed.returncode == 2 and not completed.stdout:
        return False
    raise StructuralCrossRuntimeError(
        f"JavaScript structural evaluator failed with exit {completed.returncode}"
    )


def build_reports(
    repo_root: Path,
    contract: Path,
    evidence_root: Path,
    *,
    node: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return byte-identical reports after both actual runtimes execute every row."""

    adapter = repo_root / "tools/causal-flow-simulator/app_core_iface0/node_adapter.mjs"
    javascript_rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="styx-app-core-structural-js-") as raw:
        schema_path = Path(raw) / "mutant-schema.json"

        def observe(
            row: dict[str, Any],
            classification: str,
            vector: dict[str, Any],
            direction: str,
        ) -> None:
            exact = _node_accepts(
                node,
                adapter,
                contract,
                vector["rawDocument"],
                direction,
                mutant_schema=None,
                v1_detector_mutant=False,
                schema_path=schema_path,
            )
            mutant = _node_accepts(
                node,
                adapter,
                contract,
                vector["rawDocument"],
                direction,
                mutant_schema=(
                    None if vector["v1DetectorMutant"] else vector["mutantSchema"]
                ),
                v1_detector_mutant=vector["v1DetectorMutant"],
                schema_path=schema_path,
            )
            if (exact, mutant) != (
                vector["exactAccepted"],
                vector["mutantAccepted"],
            ):
                raise StructuralCrossRuntimeError(
                    f"cross-runtime observation drift: {row['instanceId']}"
                )
            javascript_rows.append(
                {
                    "carrierCaseId": row["carrierCaseId"],
                    "classification": classification,
                    "exactAccepted": exact,
                    "instanceId": row["instanceId"],
                    "mutantAccepted": mutant,
                }
            )

        python_report = derive_structural_python_execution(
            repo_root,
            contract,
            evidence_root,
            execution_observer=observe,
        )
    javascript_report = {**python_report, "rows": javascript_rows}
    if dumps(python_report) != dumps(javascript_report):
        raise StructuralCrossRuntimeError("runtime reports are not byte-identical")
    return python_report, javascript_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--node", default="node")
    parser.add_argument("--python-output", required=True, type=Path)
    parser.add_argument("--javascript-output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        python_report, javascript_report = build_reports(
            args.repo_root.resolve(),
            args.contract.resolve(),
            args.evidence_root.resolve(),
            node=args.node,
        )
        store_report(
            args.python_output,
            python_report,
            allowed_fields=STRUCTURAL_EXECUTION_FIELDS,
        )
        store_report(
            args.javascript_output,
            javascript_report,
            allowed_fields=STRUCTURAL_EXECUTION_FIELDS,
        )
    except (
        InventoryError,
        OSError,
        ReportError,
        StructuralCrossRuntimeError,
        subprocess.SubprocessError,
        WitnessGenerationError,
    ) as error:
        print(f"APP-core structural cross-runtime: FAIL: {error}", file=sys.stderr)
        return 2
    print(
        "APP-core structural cross-runtime: PASS "
        f"instances=1450 sha256={sha256_bytes(dumps(python_report))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
