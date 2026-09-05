#!/usr/bin/env python3
"""Preflight the flawed ACV-049 provenance-isolation evidence model."""

from __future__ import annotations

import argparse
import copy
import hashlib
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
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
from inventory import InventoryError, expand_semantic_instances, sha256_bytes


REPORT_FIELDS = frozenset(
    {
        "claimed_mutant_kills", "class_counts", "class_materialization_counts",
        "instance_count", "live_rejection_count", "materialized_path_count",
        "non_string_path_count", "path_count", "rows", "schema",
        "semantic_rule_id", "status", "string_path_count",
        "unmaterialized_path_count", "verdict",
    }
)

LITERAL_REPRESENTATIVES = {
    "DURATION": "duration=1.25s",
    "ELAPSED": "elapsed=1.25s",
    "ENVIRONMENT": "environment=production",
    "EXCEPTION": "exception=ValueError",
    "HOST": "hostname=review-host",
    "PATH": "provenance=/tmp/styx-runtime",
    "PID": "pid=4242",
    "STACK": "stack trace: frame",
    "TIMESTAMP": "timestamp=2026-09-03T12:34:56Z",
    "USER": "username=operator",
}


class SemanticACV049Error(ValueError):
    """The ACV-049 preflight relation is malformed or overclaims evidence."""


@dataclass(frozen=True)
class LogicalTerminal:
    data_tokens: tuple[str | int, ...]
    nodes: tuple[dict[str, Any], ...]
    branches: tuple[tuple[tuple[str | int, ...], dict[str, Any]], ...]


def _unescape(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def _logical_terminal(schema: dict[str, Any], source: str) -> LogicalTerminal:
    parts = source.split("/")
    if not parts or parts[0] != "InterfaceResponseV0":
        raise SemanticACV049Error("ACV-049 logical path root drift")
    definitions = schema.get("$defs")
    if not isinstance(definitions, dict):
        raise SemanticACV049Error("interface definitions are absent")

    def walk(
        node: Any,
        remaining: tuple[str, ...],
        data_tokens: tuple[str | int, ...],
        branches: tuple[tuple[tuple[str | int, ...], dict[str, Any]], ...],
        stack: tuple[str, ...],
    ) -> list[LogicalTerminal]:
        if not isinstance(node, dict):
            return []
        reference = node.get("$ref")
        if isinstance(reference, str):
            if not reference.startswith("#/$defs/"):
                raise SemanticACV049Error("ACV-049 contains a non-local reference")
            name = _unescape(reference.rsplit("/", 1)[-1])
            if name in stack or not isinstance(definitions.get(name), dict):
                raise SemanticACV049Error("ACV-049 reference is cyclic or absent")
            return walk(
                definitions[name], remaining, data_tokens, branches, stack + (name,)
            )
        all_of = node.get("allOf")
        if isinstance(all_of, list):
            results = [
                result
                for arm in all_of
                for result in walk(arm, remaining, data_tokens, branches, stack)
            ]
            if not results:
                return []
            first = results[0]
            if any(
                row.data_tokens != first.data_tokens or row.branches != first.branches
                for row in results[1:]
            ):
                raise SemanticACV049Error("ACV-049 allOf logical path is ambiguous")
            return [
                LogicalTerminal(
                    first.data_tokens,
                    tuple(item for row in results for item in row.nodes),
                    first.branches,
                )
            ]
        one_of = node.get("oneOf")
        if isinstance(one_of, list):
            if not remaining:
                return []
            label = remaining[0]
            matches: list[dict[str, Any]] = []
            for index, arm in enumerate(one_of):
                if not isinstance(arm, dict):
                    continue
                arm_ref = arm.get("$ref")
                arm_label = (
                    arm_ref.rsplit("/", 1)[-1]
                    if isinstance(arm_ref, str)
                    else str(index)
                )
                if label == f"<{arm_label}>":
                    matches.append(arm)
            if len(matches) != 1:
                raise SemanticACV049Error("ACV-049 oneOf label is ambiguous")
            selected = matches[0]
            return walk(
                selected, remaining[1:], data_tokens,
                branches + ((data_tokens, selected),), stack,
            )
        properties = node.get("properties")
        if isinstance(properties, dict):
            if not remaining or remaining[0] not in properties:
                return []
            name = remaining[0]
            return walk(
                properties[name], remaining[1:], data_tokens + (name,), branches, stack
            )
        if node.get("type") == "array":
            if not remaining or remaining[0] != "*":
                return []
            return walk(
                node.get("items"), remaining[1:], data_tokens + (0,), branches, stack
            )
        if remaining:
            return []
        return [LogicalTerminal(data_tokens, (node,), branches)]

    results = walk(
        definitions["InterfaceResponseV0"], tuple(parts[1:]), (), (),
        ("InterfaceResponseV0",),
    )
    if len(results) != 1:
        raise SemanticACV049Error("ACV-049 logical path does not resolve exactly once")
    return results[0]


def _subschema_validator(
    schema: dict[str, Any], nodes: tuple[dict[str, Any], ...]
) -> Draft202012Validator:
    body: dict[str, Any] = (
        copy.deepcopy(nodes[0])
        if len(nodes) == 1
        else {"allOf": [copy.deepcopy(node) for node in nodes]}
    )
    return Draft202012Validator(
        {"$schema": schema["$schema"], **body, "$defs": schema["$defs"]}
    )


def _is_string_terminal(nodes: tuple[dict[str, Any], ...]) -> bool:
    for node in nodes:
        if node.get("type") == "string" or isinstance(node.get("const"), str):
            return True
        enum = node.get("enum")
        if isinstance(enum, list) and enum and all(isinstance(item, str) for item in enum):
            return True
    return False


def _encoded_representatives(family: str) -> tuple[str, ...]:
    literal = LITERAL_REPRESENTATIVES[family]
    digest = hashlib.sha256(literal.encode("utf-8")).hexdigest()
    decimal = {
        "DURATION": "1250", "ELAPSED": "1250", "ENVIRONMENT": "1",
        "EXCEPTION": "1", "HOST": "1", "PATH": "1", "PID": "4242",
        "STACK": "1", "TIMESTAMP": "1788438896", "USER": "1",
    }[family]
    return (decimal, literal.encode("utf-8").hex(), digest)


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


def _set_data_value(value: Any, tokens: tuple[str | int, ...], replacement: str) -> None:
    if not tokens:
        raise SemanticACV049Error("ACV-049 cannot replace the response root")
    parent = _data_value(value, tokens[:-1])
    final = tokens[-1]
    if isinstance(final, int):
        if not isinstance(parent, list) or final >= len(parent):
            raise SemanticACV049Error("ACV-049 array target disappeared")
        parent[final] = replacement
    else:
        if not isinstance(parent, dict) or final not in parent:
            raise SemanticACV049Error("ACV-049 object target disappeared")
        parent[final] = replacement


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


def _python_rejects(authority: ContractAuthority, response: dict[str, Any]) -> bool:
    try:
        validate_response_before_release(authority, response)
    except HarnessFailure:
        return True
    return False


def _javascript_rejects(
    node: str, adapter: Path, contract: Path, response: dict[str, Any]
) -> bool:
    completed = subprocess.run(
        [node, str(adapter), "--validate-response", "--contract", str(contract)],
        input=dumps(response), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=30,
    )
    if completed.returncode == 2 and not completed.stdout:
        return True
    if completed.returncode == 0 and completed.stdout == b'{"verdict":"PASS"}\n':
        return False
    raise SemanticACV049Error(
        f"JavaScript ACV-049 preflight failed with exit {completed.returncode}"
    )


def build_report(
    repo_root: Path, contract: Path, evidence_root: Path, *, node: str
) -> dict[str, Any]:
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
    if len(responses) != 15:
        raise SemanticACV049Error("ACV-049 requires 15 frozen responses")
    if any(_python_rejects(authority, response) for _case_id, response in responses):
        raise SemanticACV049Error("ACV-049 negative control is rejected")

    instances = [
        row for row in expand_semantic_instances(contract) if row.family_id == "ACV-049"
    ]
    if len(instances) != 3770:
        raise SemanticACV049Error("ACV-049 instance count drift")
    paths = sorted({row.source.rsplit("::", 1)[0] for row in instances})
    if len(paths) != 377:
        raise SemanticACV049Error("ACV-049 path count drift")
    terminals = {path: _logical_terminal(authority.schema, path) for path in paths}
    materialized = {
        path: _materialized_carrier(authority.schema, terminal, responses)
        for path, terminal in terminals.items()
    }

    adapter = repo_root / "tools/causal-flow-simulator/app_core_iface0/node_adapter.mjs"
    rows: list[dict[str, Any]] = []
    live_rejections = 0
    for instance in instances:
        path, family = instance.source.rsplit("::", 1)
        if family not in LITERAL_REPRESENTATIVES:
            raise SemanticACV049Error("ACV-049 provenance family drift")
        terminal = terminals[path]
        validator = _subschema_validator(authority.schema, terminal.nodes)
        literal_accepted = validator.is_valid(LITERAL_REPRESENTATIVES[family])
        encoded_accepted = any(
            validator.is_valid(value) for value in _encoded_representatives(family)
        )
        if not _is_string_terminal(terminal.nodes):
            classification = "NON_STRING_CONST"
            if literal_accepted or encoded_accepted:
                raise SemanticACV049Error("non-string ACV-049 path accepts a string")
        elif literal_accepted:
            classification = "LITERAL_SCHEMA_ADMISSIBLE"
        elif encoded_accepted:
            classification = "SCHEMA_ADMISSIBLE_ENCODED"
        else:
            classification = "SCHEMA_CLOSED"

        carrier = materialized[path]
        python_rejected: bool | None = None
        javascript_rejected: bool | None = None
        if carrier is not None and classification == "SCHEMA_CLOSED":
            _case_id, baseline = carrier
            hostile = copy.deepcopy(baseline)
            _set_data_value(
                hostile, terminal.data_tokens, LITERAL_REPRESENTATIVES[family]
            )
            python_rejected = _python_rejects(authority, hostile)
            javascript_rejected = _javascript_rejects(node, adapter, contract, hostile)
            if not python_rejected or not javascript_rejected:
                raise SemanticACV049Error(
                    f"ACV-049 live rejection drift: {instance.instance_id}"
                )
            live_rejections += 1
        rows.append(
            {
                "branchLabels": [
                    part[1:-1]
                    for part in path.split("/")
                    if part.startswith("<") and part.endswith(">")
                ],
                "carrierCaseId": carrier[0] if carrier is not None else None,
                "classification": classification,
                "dataPointerTokens": list(terminal.data_tokens),
                "encodedAcceptedBySchema": encoded_accepted,
                "instanceId": instance.instance_id,
                "isStringPath": _is_string_terminal(terminal.nodes),
                "javascriptRejectedLiteral": javascript_rejected,
                "literalAcceptedBySchema": literal_accepted,
                "materialized": carrier is not None,
                "pythonRejectedLiteral": python_rejected,
            }
        )

    class_counts = dict(sorted(Counter(row["classification"] for row in rows).items()))
    class_materialization_counts = dict(
        sorted(
            Counter(
                f"{row['classification']}:"
                f"{'MATERIALIZED' if row['materialized'] else 'UNMATERIALIZED'}"
                for row in rows
            ).items()
        )
    )
    materialized_count = sum(value is not None for value in materialized.values())
    non_string_count = sum(
        not _is_string_terminal(terminal.nodes) for terminal in terminals.values()
    )
    if (
        len(rows) != 3770
        or non_string_count != 5
        or materialized_count != 296
        or live_rejections != 1676
        or class_counts
        != {
            "NON_STRING_CONST": 50,
            "SCHEMA_ADMISSIBLE_ENCODED": 1921,
            "SCHEMA_CLOSED": 1799,
        }
        or class_materialization_counts
        != {
            "NON_STRING_CONST:UNMATERIALIZED": 50,
            "SCHEMA_ADMISSIBLE_ENCODED:MATERIALIZED": 1284,
            "SCHEMA_ADMISSIBLE_ENCODED:UNMATERIALIZED": 637,
            "SCHEMA_CLOSED:MATERIALIZED": 1676,
            "SCHEMA_CLOSED:UNMATERIALIZED": 123,
        }
    ):
        raise SemanticACV049Error(
            "ACV-049 preflight summary drift: "
            f"rows={len(rows)} non_string={non_string_count} "
            f"materialized={materialized_count} classes={class_counts} "
            f"materialization={class_materialization_counts}"
        )
    return {
        "claimed_mutant_kills": 0,
        "class_counts": class_counts,
        "class_materialization_counts": class_materialization_counts,
        "instance_count": len(rows),
        "live_rejection_count": live_rejections,
        "materialized_path_count": materialized_count,
        "non_string_path_count": non_string_count,
        "path_count": len(paths),
        "rows": rows,
        "schema": "styx.app-core-iface0.semantic-acv049-preflight-report.v1",
        "semantic_rule_id": "ACV-049",
        "status": "PRESELECTION_EVIDENCE",
        "string_path_count": len(paths) - non_string_count,
        "unmaterialized_path_count": len(paths) - materialized_count,
        "verdict": "AMEND_REQUIRED",
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
        subprocess.SubprocessError, WitnessGenerationError,
    ) as error:
        print(f"APP-core semantic ACV-049 preflight: FAIL: {error}", file=sys.stderr)
        return 2
    print(
        "APP-core semantic ACV-049 preflight: AMEND_REQUIRED "
        f"instances={report['instance_count']} sha256={sha256_bytes(dumps(report))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
