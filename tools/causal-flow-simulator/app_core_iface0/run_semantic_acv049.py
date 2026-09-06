#!/usr/bin/env python3
"""Derive and preflight the ratified five-relation ACV-049 evidence model."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from jsonschema.validators import Draft202012Validator

sys.dont_write_bytecode = True

from canonical_json import dumps
from canonical_report import ReportError, store_report
from generate_structural_witnesses import WitnessGenerationError, _load_phase_a
from interface_model import (
    ContractAuthority,
    HarnessFailure,
    validate_response_before_release,
)
from inventory import (
    ACV049_LITERAL_FAMILIES,
    InventoryError,
    LogicalTerminal,
    derive_acv049_path_partition,
    derive_acv049_old_to_new_reconciliation,
    derive_acv049_relation_members,
    digest_lines,
    expand_acv049_replacement_instances,
    resolve_logical_terminal,
    sha256_bytes,
)


REPORT_FIELDS = frozenset(
    {
        "claimed_mutant_kills", "historical_reconciliation_count",
        "historical_reconciliation_sha256", "instance_count",
        "materialized_mutable_path_count", "materialized_path_count",
        "materialized_singleton_path_count", "path_count", "relation_counts",
        "relation_member_set_sha256", "rows", "schema", "semantic_rule_id",
        "status", "unmaterialized_path_count", "verdict",
    }
)


class SemanticACV049Error(ValueError):
    """The ACV-049 preflight relation is malformed or overclaims evidence."""


def _data_value(value: Any, tokens: tuple[str | int, ...]) -> Any:
    current = value
    for token in tokens:
        if isinstance(token, int):
            if not isinstance(current, list) or token >= len(current):
                raise KeyError(token)
            current = current[token]
        else:
            if not isinstance(current, dict) or token not in current:
                raise KeyError(token)
            current = current[token]
    return current


def _validator(schema: dict[str, Any], node: dict[str, Any]) -> Draft202012Validator:
    return Draft202012Validator(
        {"$schema": schema["$schema"], **node, "$defs": schema["$defs"]}
    )


def _materialized_carrier(
    schema: dict[str, Any], terminal: LogicalTerminal,
    responses: list[tuple[str, dict[str, Any]]],
) -> tuple[str, dict[str, Any]] | None:
    for case_id, response in responses:
        try:
            target = _data_value(response, terminal.data_tokens)
            selected = all(
                _validator(schema, arm).is_valid(_data_value(response, prefix))
                for prefix, arm in terminal.branches
            )
        except (KeyError, TypeError):
            continue
        if isinstance(target, str) and selected:
            return case_id, response
    return None


def derive_phase_a_materialized_paths(
    repo_root: Path, contract: Path, evidence_root: Path
) -> set[str]:
    """Re-derive the exact ACV-049 Phase-A response-path materialization set."""

    authority = ContractAuthority.load(repo_root, contract)
    _inventory, _inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    responses = sorted(
        (
            (case_id, value)
            for case_id, (value, _raw) in carriers.items()
            if case_id.startswith("PCR-RESPONSE-")
        ),
        key=lambda row: row[0].encode("utf-8"),
    )
    if len(responses) != 19:
        raise SemanticACV049Error("ACV-049 requires 19 frozen responses")
    partition = derive_acv049_path_partition(contract)
    terminals = {
        path: resolve_logical_terminal(authority.schema, path)
        for path in partition["logical"]
    }
    materialized = {
        path
        for path, terminal in terminals.items()
        if _materialized_carrier(authority.schema, terminal, responses) is not None
    }
    mutable = sorted(materialized & set(partition["mutable"]))
    singleton = sorted(materialized & set(partition["singleton"]))
    non_string = materialized & set(partition["non_string"])
    if (
        len(materialized) != 321
        or len(mutable) != 228
        or len(singleton) != 93
        or non_string
        or sha256_bytes("".join(path + "\n" for path in mutable).encode("utf-8"))
        != "47756a4adf5eaa79589f21c4b443e8f273e94efc4c798bace194cb9e1fe611de"
        or sha256_bytes("".join(path + "\n" for path in singleton).encode("utf-8"))
        != "6f06ee47fe0950fec29462ab849d46d7928ee7ff85de4829829731b82839c77a"
    ):
        raise SemanticACV049Error("ACV-049 Phase-A materialization relation drift")
    return materialized


def _python_rejects(authority: ContractAuthority, response: dict[str, Any]) -> bool:
    try:
        validate_response_before_release(authority, response)
    except HarnessFailure:
        return True
    return False


def build_report(
    repo_root: Path, contract: Path, evidence_root: Path, *, node: str
) -> dict[str, Any]:
    """Build the exact replacement-relation registry without overclaiming execution.

    The runner deliberately records zero mutant kills. Source-purity and
    two-environment execution are separate, later gates; deriving their closed
    relation rows here must not be reported as satisfying them.
    """

    del node
    authority = ContractAuthority.load(repo_root, contract)
    _inventory, _inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    responses = sorted(
        (
            (case_id, value)
            for case_id, (value, _raw) in carriers.items()
            if case_id.startswith("PCR-RESPONSE-")
        ),
        key=lambda row: row[0].encode("utf-8"),
    )
    if len(responses) != 19:
        raise SemanticACV049Error("ACV-049 requires 19 frozen responses")
    if any(_python_rejects(authority, response) for _case_id, response in responses):
        raise SemanticACV049Error("ACV-049 negative control is rejected")

    partition = derive_acv049_path_partition(contract)
    relation_members = derive_acv049_relation_members(contract)
    instances = expand_acv049_replacement_instances(contract)
    instance_by_relation_and_source = {
        (row.family_id, row.source): row for row in instances
    }
    if len(instance_by_relation_and_source) != 884:
        raise SemanticACV049Error("ACV-049 replacement instance identity drift")

    terminals = {
        path: resolve_logical_terminal(authority.schema, path)
        for path in partition["logical"]
    }

    def carrier_ids(path: str) -> list[str]:
        terminal = terminals[path]
        found: list[str] = []
        for case_id, response in responses:
            try:
                target = _data_value(response, terminal.data_tokens)
                selected = all(
                    _validator(authority.schema, arm).is_valid(
                        _data_value(response, prefix)
                    )
                    for prefix, arm in terminal.branches
                )
            except (KeyError, TypeError):
                continue
            if isinstance(target, str) and selected:
                found.append(case_id)
        return found

    materialized_by_path = {
        path: carrier_ids(path) for path in partition["literal"]
    }
    materialized = {
        path for path, case_ids in materialized_by_path.items() if case_ids
    }
    derived_materialized = derive_phase_a_materialized_paths(
        repo_root, contract, evidence_root
    )
    if materialized != derived_materialized:
        raise SemanticACV049Error("ACV-049 materialization derivations disagree")

    mutable = set(partition["mutable"])
    singleton = set(partition["singleton"])
    rows: list[dict[str, Any]] = []
    for relation_id in (
        "ACV-049-L",
        "ACV-049-P",
        "ACV-049-S",
        "ACV-049-N",
        "ACV-049-E",
    ):
        for source in relation_members[relation_id]:
            instance = instance_by_relation_and_source[(relation_id, source)]
            row: dict[str, Any] = {
                "assertionId": instance.assertion_id,
                "detectorId": instance.detector_id,
                "instanceId": instance.instance_id,
                "observationId": instance.observation_id,
                "relationId": relation_id,
                "sourceIdentity": source,
            }
            if relation_id == "ACV-049-L":
                row.update(
                    {
                        "carrierCaseIds": materialized_by_path[source],
                        "domainClass": (
                            "MUTABLE_DOMAIN" if source in mutable else "SINGLETON_CONST"
                        ),
                        "executionPhase": (
                            "POST_OUTPUT_MUTATION"
                            if source in materialized
                            else "VALIDATOR_SELF_TEST"
                        ),
                        "literalFamilyVector": list(ACV049_LITERAL_FAMILIES),
                        "materialized": source in materialized,
                    }
                )
            elif relation_id == "ACV-049-P":
                row.update(
                    {
                        "executionPhase": "TWO_ENVIRONMENT_SOURCE_MUTATION",
                        "evidenceDisposition": "SOURCE_SITE_EVIDENCE_PENDING",
                    }
                )
            elif relation_id in {"ACV-049-S", "ACV-049-N"}:
                row.update(
                    {
                        "executionPhase": "VALIDATOR_SELF_TEST",
                        "evidenceDisposition": "DOMAIN_CLOSURE_PENDING",
                    }
                )
            else:
                row.update(
                    {
                        "executionPhase": "BLIND_INPUT_EXECUTION",
                        "evidenceDisposition": "TWO_ENVIRONMENT_EXECUTION_PENDING",
                    }
                )
            rows.append(row)

    reconciliation = derive_acv049_old_to_new_reconciliation(contract)
    relation_counts = {
        relation_id: len(members)
        for relation_id, members in relation_members.items()
    }
    relation_digests = {
        relation_id: digest_lines(members)
        for relation_id, members in relation_members.items()
    }
    if len(rows) != 884 or relation_counts != {
        "ACV-049-L": 401,
        "ACV-049-P": 300,
        "ACV-049-S": 101,
        "ACV-049-N": 5,
        "ACV-049-E": 77,
    }:
        raise SemanticACV049Error("ACV-049 replacement report count drift")
    return {
        "claimed_mutant_kills": 0,
        "historical_reconciliation_count": len(reconciliation),
        "historical_reconciliation_sha256": sha256_bytes(dumps(reconciliation)),
        "instance_count": len(rows),
        "materialized_mutable_path_count": len(materialized & mutable),
        "materialized_path_count": len(materialized),
        "materialized_singleton_path_count": len(materialized & singleton),
        "path_count": len(partition["logical"]),
        "relation_counts": relation_counts,
        "relation_member_set_sha256": relation_digests,
        "rows": rows,
        "schema": "styx.app-core-iface0.semantic-acv049-relation-registry.v2",
        "semantic_rule_id": "ACV-049",
        "status": "REMEDIATION_RELATION_REGISTRY",
        "unmaterialized_path_count": len(set(partition["literal"]) - materialized),
        "verdict": "RELATION_DERIVATION_PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--node", default="node")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_report(
            args.repo_root.resolve(), args.contract.resolve(),
            args.evidence_root.resolve(), node=args.node,
        )
        store_report(args.output, report, allowed_fields=REPORT_FIELDS)
    except (
        InventoryError, OSError, ReportError, SemanticACV049Error,
        WitnessGenerationError,
    ) as error:
        print(f"APP-core semantic ACV-049 preflight: FAIL: {error}", file=sys.stderr)
        return 2
    print(
        "APP-core semantic ACV-049 relation registry: PASS "
        f"instances={report['instance_count']} sha256={sha256_bytes(dumps(report))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
