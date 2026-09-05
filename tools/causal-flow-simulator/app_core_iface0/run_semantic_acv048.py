#!/usr/bin/env python3
"""Execute all ACV-048 cross-plane field-smuggling instances."""

from __future__ import annotations

import argparse
import copy
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, Callable

sys.dont_write_bytecode = True

from canonical_json import dumps
from canonical_report import ReportError, store_report
from generate_structural_witnesses import (
    WitnessGenerationError,
    _load_phase_a,
    _resolve_data_pointer,
    _schema_node_at,
    derive_seed_registry,
)
from interface_model import (
    ContractAuthority,
    HarnessFailure,
    RequestRejected,
    _validate_structural_v2_evidence,
)
from inventory import (
    InventoryError,
    derive_semantic_execution_relation,
    expand_semantic_instances,
    sha256_bytes,
)


REPORT_FIELDS = frozenset(
    {
        "exact_rejected_count",
        "instance_count",
        "mutant_admitted_count",
        "phase_counts",
        "rows",
        "schema",
        "semantic_rule_id",
        "status",
        "verdict",
    }
)

FORBIDDEN_FIELDS = {
    "CALLER_RUNTIME_CAPABILITY": "callerRuntimeCapability",
    "CEREMONY_CAPABILITY_OR_VERDICT": "ceremonyCapabilityOrVerdict",
    "O11_MUTATION_OR_COMMIT": "o11MutationOrCommit",
    "SS_DECRYPTION_AS_AUTHORITY": "ssDecryptionAsAuthority",
    "SS_MEMBERSHIP_AS_AUTHORITY": "ssMembershipAsAuthority",
    "TRANSPORT_ACK_AS_COMMIT": "transportAcknowledgementAsCommit",
    "TRANSPORT_IDENTITY_AS_AUTHORITY": "transportIdentityAsAuthority",
    "TRANSPORT_ORDER_AS_CAUSALITY": "transportOrderAsCausality",
    "TRUSTED_SNAPSHOT_OR_DELTA_DIGEST": "trustedSnapshotOrDeltaDigest",
}


class SemanticACV048Error(ValueError):
    """The ACV-048 execution or its isolated mutant relation failed."""


def _accepted_python(
    authority: ContractAuthority,
    raw_document: bytes,
    direction: str,
    *,
    schema_override: dict[str, Any] | None,
) -> bool:
    try:
        _validate_structural_v2_evidence(
            authority,
            raw_document,
            trusted_direction=direction,
            schema_override=schema_override,
        )
    except (HarnessFailure, RequestRejected):
        return False
    return True


def _mutant_schema(
    schema: dict[str, Any], object_pointer: str, field: str, value: str
) -> dict[str, Any]:
    mutant = copy.deepcopy(schema)
    node = _schema_node_at(mutant, object_pointer)
    if not isinstance(node, dict) or node.get("additionalProperties") is not False:
        raise SemanticACV048Error("ACV-048 target is not a closed object")
    properties = node.get("properties")
    if not isinstance(properties, dict) or field in properties:
        raise SemanticACV048Error("ACV-048 field mutant is not isolated")
    properties[field] = {"const": value}
    return mutant


def _vectors(
    repo_root: Path, contract: Path, evidence_root: Path
) -> tuple[ContractAuthority, list[dict[str, Any]]]:
    authority = ContractAuthority.load(repo_root, contract)
    seed_registry, _cases = derive_seed_registry(repo_root, contract, evidence_root)
    _inventory, _inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    seed_by_pointer = {
        row["objectSchemaPointer"]: row for row in seed_registry["rows"]
    }
    phase_by_instance = {
        row["instanceId"]: row
        for row in derive_semantic_execution_relation(contract, seed_registry)
        if row["semanticRuleId"] == "ACV-048"
    }
    instances = [
        row
        for row in expand_semantic_instances(contract)
        if row.family_id == "ACV-048"
    ]
    if len(instances) != 702 or len(phase_by_instance) != 702:
        raise SemanticACV048Error("ACV-048 instance relation drift")

    baseline_cache: dict[tuple[str, str], bool] = {}
    vectors: list[dict[str, Any]] = []
    for instance in instances:
        if "::" not in instance.source:
            raise SemanticACV048Error("ACV-048 source identity drift")
        object_pointer, family = instance.source.rsplit("::", 1)
        field = FORBIDDEN_FIELDS.get(family)
        seed = seed_by_pointer.get(object_pointer)
        phase = phase_by_instance.get(instance.instance_id)
        if field is None or seed is None or phase is None:
            raise SemanticACV048Error("ACV-048 carrier binding drift")
        direction = seed["carrierDirection"]
        carrier, raw_carrier = carriers[seed["carrierCaseId"]]
        baseline_key = (seed["carrierCaseId"], direction)
        if baseline_key not in baseline_cache:
            baseline_cache[baseline_key] = _accepted_python(
                authority, raw_carrier, direction, schema_override=None
            )
        if not baseline_cache[baseline_key]:
            raise SemanticACV048Error("ACV-048 baseline carrier is rejected")

        hostile = copy.deepcopy(carrier)
        target = _resolve_data_pointer(hostile, seed["targetJsonPointer"])
        if not isinstance(target, dict) or field in target:
            raise SemanticACV048Error("ACV-048 data target is not isolated")
        target[field] = family
        raw_hostile = dumps(hostile)
        mutant_schema = _mutant_schema(
            authority.schema, object_pointer, field, family
        )
        exact = _accepted_python(
            authority, raw_hostile, direction, schema_override=None
        )
        mutant = _accepted_python(
            authority, raw_hostile, direction, schema_override=mutant_schema
        )
        if exact or not mutant:
            raise SemanticACV048Error(
                f"ACV-048 Python mutant isolation failed: {instance.instance_id}"
            )
        vectors.append(
            {
                "carrierCaseId": seed["carrierCaseId"],
                "direction": direction,
                "executionPhase": phase["executionPhase"],
                "instanceId": instance.instance_id,
                "mutantSchema": mutant_schema,
                "rawDocument": raw_hostile,
            }
        )
    return authority, vectors


def derive_python_report(
    repo_root: Path,
    contract: Path,
    evidence_root: Path,
    *,
    observer: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    _authority, vectors = _vectors(repo_root, contract, evidence_root)
    rows: list[dict[str, Any]] = []
    for vector in vectors:
        if observer is not None:
            observer(vector)
        rows.append(
            {
                "carrierCaseId": vector["carrierCaseId"],
                "exactAccepted": False,
                "executionPhase": vector["executionPhase"],
                "instanceId": vector["instanceId"],
                "mutantAccepted": True,
            }
        )
    counts = Counter(row["executionPhase"] for row in rows)
    if counts != Counter(
        {"BLIND_INPUT_EXECUTION": 432, "POST_OUTPUT_MUTATION": 270}
    ):
        raise SemanticACV048Error("ACV-048 execution phase count drift")
    return {
        "exact_rejected_count": len(rows),
        "instance_count": len(rows),
        "mutant_admitted_count": len(rows),
        "phase_counts": dict(sorted(counts.items())),
        "rows": rows,
        "schema": "styx.app-core-iface0.semantic-acv048-execution-report.v1",
        "semantic_rule_id": "ACV-048",
        "status": "PRESELECTION_EVIDENCE",
        "verdict": "PASS",
    }


def _node_accepts(
    node: str,
    adapter: Path,
    contract: Path,
    raw_document: bytes,
    direction: str,
    *,
    schema_override: dict[str, Any] | None,
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
    if schema_override is not None:
        schema_path.write_text(
            json.dumps(schema_override, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        command.extend(("--schema-override", str(schema_path)))
    completed = subprocess.run(
        command,
        input=raw_document,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if completed.returncode == 0:
        try:
            result = json.loads(completed.stdout)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise SemanticACV048Error("JavaScript result is malformed") from error
        if result != {"verdict": "PASS"} or completed.stderr:
            raise SemanticACV048Error("JavaScript success result drift")
        return True
    if completed.returncode == 2 and not completed.stdout:
        return False
    raise SemanticACV048Error(
        f"JavaScript ACV-048 evaluator failed with exit {completed.returncode}"
    )


def build_reports(
    repo_root: Path,
    contract: Path,
    evidence_root: Path,
    *,
    node: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    adapter = repo_root / "tools/causal-flow-simulator/app_core_iface0/node_adapter.mjs"
    javascript_rows: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="styx-app-core-acv048-js-") as raw:
        schema_path = Path(raw) / "mutant-schema.json"

        def observe(vector: dict[str, Any]) -> None:
            exact = _node_accepts(
                node,
                adapter,
                contract,
                vector["rawDocument"],
                vector["direction"],
                schema_override=None,
                schema_path=schema_path,
            )
            mutant = _node_accepts(
                node,
                adapter,
                contract,
                vector["rawDocument"],
                vector["direction"],
                schema_override=vector["mutantSchema"],
                schema_path=schema_path,
            )
            if exact or not mutant:
                raise SemanticACV048Error(
                    f"ACV-048 JavaScript mutant isolation failed: {vector['instanceId']}"
                )
            javascript_rows.append(
                {
                    "carrierCaseId": vector["carrierCaseId"],
                    "exactAccepted": exact,
                    "executionPhase": vector["executionPhase"],
                    "instanceId": vector["instanceId"],
                    "mutantAccepted": mutant,
                }
            )

        python_report = derive_python_report(
            repo_root, contract, evidence_root, observer=observe
        )
    javascript_report = {**python_report, "rows": javascript_rows}
    if dumps(python_report) != dumps(javascript_report):
        raise SemanticACV048Error("ACV-048 runtime reports are not byte-identical")
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
        store_report(args.python_output, python_report, allowed_fields=REPORT_FIELDS)
        store_report(
            args.javascript_output, javascript_report, allowed_fields=REPORT_FIELDS
        )
    except (
        InventoryError,
        OSError,
        ReportError,
        SemanticACV048Error,
        subprocess.SubprocessError,
        WitnessGenerationError,
    ) as error:
        print(f"APP-core semantic ACV-048: FAIL: {error}", file=sys.stderr)
        return 2
    print(
        "APP-core semantic ACV-048: PASS "
        f"instances={python_report['instance_count']} "
        f"sha256={sha256_bytes(dumps(python_report))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
