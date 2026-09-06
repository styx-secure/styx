#!/usr/bin/env python3
"""Derive ACV-049 relations and execute the L/S/N reader evidence."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from jsonschema.validators import Draft202012Validator

sys.dont_write_bytecode = True

from canonical_json import dumps
from canonical_report import ReportError, store_report
from generate_structural_witnesses import (
    WitnessGenerationError,
    _load_phase_a,
    derive_structural_plan,
)
from generate_seed_registry import (  # noqa: E402
    _evaluate_fixture_request,
    _semantic_request_carriers,
)
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
        "executed_relation_counts",
        "materialized_mutable_path_count", "materialized_path_count",
        "materialized_singleton_path_count", "path_count",
        "pending_relation_counts", "relation_counts",
        "relation_member_set_sha256", "rows", "schema", "semantic_rule_id",
        "status", "unmaterialized_path_count", "verdict",
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


def _encoded_representatives(family: str) -> tuple[str, ...]:
    literal = LITERAL_REPRESENTATIVES[family]
    digest = hashlib.sha256(literal.encode("utf-8")).hexdigest()
    decimal = {
        "DURATION": "1250", "ELAPSED": "1250", "ENVIRONMENT": "1",
        "EXCEPTION": "1", "HOST": "1", "PATH": "1", "PID": "4242",
        "STACK": "1", "TIMESTAMP": "1788438896", "USER": "1",
    }[family]
    return (decimal, literal.encode("utf-8").hex(), digest)


def _terminal_test_values() -> list[str]:
    return [
        value
        for family in ACV049_LITERAL_FAMILIES
        for value in (LITERAL_REPRESENTATIVES[family], *_encoded_representatives(family))
    ]


def _javascript_terminal_results(
    node: str, adapter: Path, contract: Path, jobs: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for offset in range(0, len(jobs), 64):
        batch = jobs[offset:offset + 64]
        with tempfile.TemporaryFile() as input_file:
            input_file.write(dumps({"jobs": batch}))
            input_file.seek(0)
            completed = subprocess.run(
                [
                    node,
                    str(adapter),
                    "--self-test-terminal-schema",
                    "--contract",
                    str(contract),
                ],
                stdin=input_file,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=180,
            )
        if completed.returncode != 0:
            raise SemanticACV049Error(
                "JavaScript terminal-schema self-test failed: "
                + completed.stderr.decode("utf-8", errors="replace").strip()
            )
        try:
            result = json.loads(completed.stdout)
        except (UnicodeDecodeError, ValueError) as error:
            raise SemanticACV049Error(
                "JavaScript terminal-schema self-test emitted invalid JSON"
            ) from error
        if (
            not isinstance(result, dict)
            or set(result) != {"results"}
            or not isinstance(result["results"], list)
            or len(result["results"]) != len(batch)
        ):
            raise SemanticACV049Error("JavaScript terminal-schema result drift")
        for job, row in zip(batch, result["results"], strict=True):
            expected_release_rows = len(job["baselines"])
            if (
                not isinstance(row, dict)
                or set(row) != {"logicalPath", "releaseAccepted", "schemaAccepted"}
                or row["logicalPath"] != job["logicalPath"]
                or not isinstance(row["schemaAccepted"], list)
                or len(row["schemaAccepted"]) != len(job["values"])
                or any(not isinstance(value, bool) for value in row["schemaAccepted"])
                or not isinstance(row["releaseAccepted"], list)
                or len(row["releaseAccepted"]) != expected_release_rows
                or any(
                    not isinstance(releases, list)
                    or len(releases) != len(job["values"])
                    or any(not isinstance(value, bool) for value in releases)
                    for releases in row["releaseAccepted"]
                )
            ):
                raise SemanticACV049Error("JavaScript terminal-schema row drift")
        rows.extend(result["results"])
    return rows


def _set_data_value(
    value: Any, tokens: tuple[str | int, ...], replacement: Any
) -> None:
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


def _json_pointer(tokens: tuple[str | int, ...]) -> str:
    return "".join(
        "/" + str(token).replace("~", "~0").replace("/", "~1")
        for token in tokens
    )


def _report_pointer(pointer: str) -> str:
    if not pointer.startswith("/") or pointer == "/":
        raise SemanticACV049Error("ACV-049 report pointer is not rooted")
    return "JSON_POINTER:" + pointer[1:].replace("%", "%25").replace("/", "%2F")


def _raw_report_pointer(pointer: str) -> str:
    prefix = "JSON_POINTER:"
    if not pointer.startswith(prefix):
        raise SemanticACV049Error("ACV-049 report pointer encoding drift")
    return "/" + pointer[len(prefix):].replace("%2F", "/").replace("%25", "%")


def _report_logical_path(path: str) -> str:
    if not path or path.startswith("/"):
        raise SemanticACV049Error("ACV-049 logical path identity drift")
    return "LOGICAL_PATH:" + path.replace("%", "%25").replace("/", "%2F")


def _constraint_occurrences(terminal: LogicalTerminal) -> list[dict[str, Any]]:
    constraint_keywords = {
        "$ref", "allOf", "anyOf", "const", "enum", "items", "maxItems",
        "maxLength", "minItems", "minLength", "not", "oneOf", "pattern",
        "type", "uniqueItems",
    }
    rows = [
        {
            "keyword": keyword,
            "occurrence": _report_pointer(
                f"{pointer}/{keyword.replace('~', '~0').replace('/', '~1')}"
            ),
            "valueSha256": sha256_bytes(dumps(node[keyword])),
        }
        for pointer, node in zip(
            terminal.node_pointers, terminal.nodes, strict=True
        )
        for keyword in sorted(set(node) & constraint_keywords)
    ]
    if not rows:
        raise SemanticACV049Error("ACV-049 terminal has no constraint occurrence")
    return rows


def _const_value(terminal: LogicalTerminal) -> Any:
    values = [node["const"] for node in terminal.nodes if "const" in node]
    if not values or any(value != values[0] for value in values[1:]):
        raise SemanticACV049Error("ACV-049 const binding is absent or ambiguous")
    return copy.deepcopy(values[0])


def _non_const_value(value: Any) -> Any:
    if isinstance(value, str):
        candidate = value + "-ACV049-DISTINCT"
        return candidate if candidate != value else "ACV049-DISTINCT"
    if isinstance(value, list):
        return [*copy.deepcopy(value), "ACV049-DISTINCT"]
    raise SemanticACV049Error("ACV-049 const has an unsupported terminal type")


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
    """Build the exact registry and execute its L/S/N evidence.

    The runner deliberately records zero mutant kills. P source-purity and E
    two-environment execution remain separate gates and stay explicitly pending.
    """

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

    requests = sorted(
        (
            (case_id, value, raw)
            for case_id, (value, raw) in carriers.items()
            if case_id.startswith("PCR-REQUEST-")
        ),
        key=lambda row: row[0].encode("utf-8"),
    )
    if len(requests) != 77:
        raise SemanticACV049Error("ACV-049 requires 77 frozen requests")
    collision_oracle_by_request = {
        dumps(case.request): case.collision_oracle
        for case in _semantic_request_carriers(authority)
        if case.collision_oracle is not None
    }
    if (
        len(collision_oracle_by_request) != 3
        or not set(collision_oracle_by_request).issubset({raw for _id, _value, raw in requests})
    ):
        raise SemanticACV049Error("ACV-049 collision-oracle identity drift")
    response_carriers_by_bytes: dict[bytes, list[str]] = {}
    for case_id, response in responses:
        response_carriers_by_bytes.setdefault(dumps(response), []).append(case_id)
    e_execution: dict[str, dict[str, Any]] = {}
    for case_id, request, raw in requests:
        collision_oracle = collision_oracle_by_request.get(raw)
        response = _evaluate_fixture_request(
            authority, request, collision_oracle
        )
        validate_response_before_release(authority, response)
        response_bytes = dumps(response)
        response_carrier_ids = response_carriers_by_bytes.get(response_bytes, [])
        if not response_carrier_ids:
            raise SemanticACV049Error(
                f"ACV-049 blind response left the frozen carrier set: {case_id}"
            )
        e_execution[case_id] = {
            "faultContext": (
                "FIXED_INTERNAL_COLLISION_ORACLE"
                if collision_oracle is not None
                else "NONE"
            ),
            "requestOctets": len(raw),
            "requestSha256": sha256_bytes(raw),
            "responseCarrierCaseIds": response_carrier_ids,
            "responseOctets": len(response_bytes),
            "responseSha256": sha256_bytes(response_bytes),
        }

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

    def selected_carriers(path: str) -> list[tuple[str, dict[str, Any], str]]:
        terminal = terminals[path]
        found: list[tuple[str, dict[str, Any], str]] = []
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
                found.append((case_id, response, target))
        return found

    carriers_by_path = {
        path: selected_carriers(path) for path in partition["literal"]
    }
    materialized = {
        path for path, carriers in carriers_by_path.items() if carriers
    }
    derived_materialized = derive_phase_a_materialized_paths(
        repo_root, contract, evidence_root
    )
    if materialized != derived_materialized:
        raise SemanticACV049Error("ACV-049 materialization derivations disagree")

    literal_values = _terminal_test_values()
    job_specs: list[tuple[str, str, list[Any], list[dict[str, Any]]]] = []
    for path in partition["literal"]:
        job_specs.append(
            (
                "ACV-049-L",
                path,
                literal_values,
                [response for _case_id, response, _value in carriers_by_path[path]],
            )
        )
    for path in partition["singleton"]:
        const_value = _const_value(terminals[path])
        job_specs.append(
            ("ACV-049-S", path, [const_value, _non_const_value(const_value)], [])
        )
    for path in partition["non_string"]:
        const_value = _const_value(terminals[path])
        job_specs.append(
            (
                "ACV-049-N",
                path,
                [const_value, "ACV049-STRING-HOSTILE", _non_const_value(const_value)],
                [],
            )
        )
    adapter = repo_root / "tools/causal-flow-simulator/app_core_iface0/node_adapter.mjs"
    javascript_rows = _javascript_terminal_results(
        node,
        adapter,
        contract,
        [
            {"baselines": baselines, "logicalPath": path, "values": values}
            for _relation_id, path, values, baselines in job_specs
        ],
    )
    execution_results: dict[tuple[str, str], dict[str, Any]] = {}
    for spec, javascript_row in zip(job_specs, javascript_rows, strict=True):
        relation_id, path, values, baselines = spec
        terminal = terminals[path]
        validator = _subschema_validator(authority.schema, terminal.nodes)
        python_schema = [validator.is_valid(value) for value in values]
        python_release: list[list[bool]] = []
        for baseline in baselines:
            carrier_results: list[bool] = []
            for value in values:
                candidate = copy.deepcopy(baseline)
                _set_data_value(candidate, terminal.data_tokens, value)
                carrier_results.append(not _python_rejects(authority, candidate))
            python_release.append(carrier_results)
        if (
            javascript_row["schemaAccepted"] != python_schema
            or javascript_row["releaseAccepted"] != python_release
        ):
            raise SemanticACV049Error(
                f"ACV-049 Python/JavaScript terminal result drift: {relation_id} {path}"
            )
        if relation_id == "ACV-049-S" and python_schema != [True, False]:
            raise SemanticACV049Error(f"ACV-049 singleton closure drift: {path}")
        if relation_id == "ACV-049-N" and python_schema != [True, False, False]:
            raise SemanticACV049Error(f"ACV-049 non-string closure drift: {path}")
        execution_results[(relation_id, path)] = {
            "javascriptReleaseAccepted": javascript_row["releaseAccepted"],
            "javascriptSchemaAccepted": javascript_row["schemaAccepted"],
            "pythonReleaseAccepted": python_release,
            "pythonSchemaAccepted": python_schema,
            "testValues": values,
        }

    structural_rows = derive_structural_plan(contract)["rows"]
    structural_by_occurrence: dict[str, list[str]] = {}
    for structural_row in structural_rows:
        structural_by_occurrence.setdefault(
            structural_row["sourcePointerOrRowId"], []
        ).append(structural_row["instanceId"])

    def terminal_binding(path: str) -> dict[str, Any]:
        terminal = terminals[path]
        occurrences = _constraint_occurrences(terminal)
        witness_ids = sorted(
            {
                witness_id
                for occurrence in occurrences
                for witness_id in structural_by_occurrence.get(
                    _raw_report_pointer(occurrence["occurrence"]),
                    [],
                )
            },
            key=lambda value: value.encode("utf-8"),
        )
        if not witness_ids:
            raise SemanticACV049Error(
                f"ACV-049 terminal has no structural witness binding: {path}"
            )
        return {
            "branchLabels": [
                part[1:-1]
                for part in path.split("/")
                if part.startswith("<") and part.endswith(">")
            ],
            "coConstrainingKeywordOccurrences": occurrences,
            "dataPointer": _report_pointer(_json_pointer(terminal.data_tokens)),
            "structuralWitnessIds": witness_ids,
            "terminalSchemaOccurrences": [
                _report_pointer(pointer) for pointer in terminal.node_pointers
            ],
            "terminalSchemaSha256": sha256_bytes(dumps(list(terminal.nodes))),
        }

    mutable = set(partition["mutable"])
    singleton = set(partition["singleton"])
    reconciliation = derive_acv049_old_to_new_reconciliation(contract)

    def equality_status(path: str, value: Any) -> tuple[str, list[str]]:
        equal_carriers = [
            case_id
            for case_id, _response, baseline_value in carriers_by_path.get(path, [])
            if baseline_value == value
        ]
        if not carriers_by_path.get(path):
            return "NO_PHASE_A_BASELINE", []
        return (
            "EQUIVALENT_REPRESENTATIVE" if equal_carriers
            else "DISTINCT_REPRESENTATIVE",
            equal_carriers,
        )

    def literal_family_vector(path: str) -> list[dict[str, Any]]:
        evidence = execution_results[("ACV-049-L", path)]
        detector_ids = terminal_binding(path)["structuralWitnessIds"]
        carrier_ids = [
            case_id for case_id, _response, _value in carriers_by_path[path]
        ]
        vector: list[dict[str, Any]] = []
        for family_index, family in enumerate(ACV049_LITERAL_FAMILIES):
            start = family_index * 4
            family_values = evidence["testValues"][start:start + 4]
            representations: list[dict[str, Any]] = []
            for value_index, value in enumerate(family_values):
                global_index = start + value_index
                equality, equal_carriers = equality_status(path, value)
                representations.append(
                    {
                        "encoding": (
                            "LITERAL" if value_index == 0
                            else ("DECIMAL", "LOWERCASE_HEX", "SHA256_HEX")[value_index - 1]
                        ),
                        "equalCarrierCaseIds": equal_carriers,
                        "equalityToBaseline": equality,
                        "javascriptReleaseAccepted": [
                            {
                                "accepted": row[global_index],
                                "carrierCaseId": case_id,
                            }
                            for case_id, row in zip(
                                carrier_ids,
                                evidence["javascriptReleaseAccepted"],
                                strict=True,
                            )
                        ],
                        "javascriptSchemaAccepted": evidence[
                            "javascriptSchemaAccepted"
                        ][global_index],
                        "pythonReleaseAccepted": [
                            {
                                "accepted": row[global_index],
                                "carrierCaseId": case_id,
                            }
                            for case_id, row in zip(
                                carrier_ids,
                                evidence["pythonReleaseAccepted"],
                                strict=True,
                            )
                        ],
                        "pythonSchemaAccepted": evidence["pythonSchemaAccepted"][
                            global_index
                        ],
                        "representativeSha256": sha256_bytes(dumps(value)),
                    }
                )
            vector.append(
                {
                    "detector": detector_ids,
                    "encodedRepresentatives": representations[1:],
                    "familyId": f"LITERAL-FAMILY-{family_index:02d}",
                    "literalRepresentative": representations[0],
                }
            )
        return vector

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
                "sourceIdentity": (
                    source if relation_id == "ACV-049-E"
                    else _report_logical_path(source)
                ),
            }
            if relation_id == "ACV-049-L":
                binding = terminal_binding(source)
                row.update(
                    {
                        **binding,
                        "carrierCaseIds": [
                            case_id
                            for case_id, _response, _value in carriers_by_path[source]
                        ],
                        "domainClass": (
                            "MUTABLE_DOMAIN" if source in mutable else "SINGLETON_CONST"
                        ),
                        "evidenceDisposition": "LITERAL_PROVENANCE_CLOSURE_PASS",
                        "executionPhase": (
                            "POST_OUTPUT_MUTATION"
                            if source in materialized
                            else "VALIDATOR_SELF_TEST"
                        ),
                        "literalFamilyVector": literal_family_vector(source),
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
                binding = terminal_binding(source)
                evidence = execution_results[(relation_id, source)]
                const_value = _const_value(terminals[source])
                const_occurrences = [
                    item
                    for item in binding["coConstrainingKeywordOccurrences"]
                    if item["keyword"] == "const"
                ]
                if not const_occurrences:
                    raise SemanticACV049Error(
                        f"ACV-049 const occurrence is absent: {source}"
                    )
                row.update(
                    {
                        **binding,
                        "constOccurrences": const_occurrences,
                        "constValue": const_value,
                        "executionPhase": "VALIDATOR_SELF_TEST",
                        "evidenceDisposition": (
                            "DOMAIN_CLOSURE_PASS"
                            if relation_id == "ACV-049-S"
                            else "NON_STRING_RECONCILIATION_PASS"
                        ),
                        "javascriptSchemaAccepted": evidence[
                            "javascriptSchemaAccepted"
                        ],
                        "materialized": source in materialized,
                        "pythonSchemaAccepted": evidence["pythonSchemaAccepted"],
                        "selfTestValues": evidence["testValues"],
                    }
                )
                if relation_id == "ACV-049-S":
                    row.update(
                        {
                            "carrierCaseIds": [
                                case_id
                                for case_id, _response, _value
                                in carriers_by_path[source]
                            ],
                            "supplementaryReachability": (
                                "NOT_REQUIRED_PHASE_A_MATERIALIZED"
                                if source in materialized
                                else "REQUIRED_PENDING_SEPARATE_RATIFICATION"
                            ),
                        }
                    )
                else:
                    retired = [
                        item["historicalInstanceId"]
                        for item in reconciliation
                        if item["logicalPath"] == source
                    ]
                    if len(retired) != 10:
                        raise SemanticACV049Error(
                            f"ACV-049 non-string reconciliation drift: {source}"
                        )
                    row.update(
                        {
                            "historicalStringProvenanceIdsRetired": retired,
                            "terminalType": "array",
                        }
                    )
            else:
                row.update(
                    {
                        **e_execution[source],
                        "executionPhase": "BLIND_INPUT_EXECUTION",
                        "evidenceDisposition": (
                            "LOCAL_BLIND_EXECUTION_PASS_TWO_ENVIRONMENT_PENDING"
                        ),
                    }
                )
            rows.append(row)

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
        "executed_relation_counts": {
            "ACV-049-L": 401,
            "ACV-049-N": 5,
            "ACV-049-S": 101,
        },
        "historical_reconciliation_count": len(reconciliation),
        "historical_reconciliation_sha256": sha256_bytes(dumps(reconciliation)),
        "instance_count": len(rows),
        "materialized_mutable_path_count": len(materialized & mutable),
        "materialized_path_count": len(materialized),
        "materialized_singleton_path_count": len(materialized & singleton),
        "path_count": len(partition["logical"]),
        "pending_relation_counts": {"ACV-049-E": 77, "ACV-049-P": 300},
        "relation_counts": relation_counts,
        "relation_member_set_sha256": relation_digests,
        "rows": rows,
        "schema": "styx.app-core-iface0.semantic-acv049-partial-execution.v3",
        "semantic_rule_id": "ACV-049",
        "status": "REMEDIATION_PARTIAL_EXECUTION",
        "unmaterialized_path_count": len(set(partition["literal"]) - materialized),
        "verdict": "PARTIAL_EXECUTION_PASS",
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
        "APP-core semantic ACV-049 L/S/N partial execution: PASS "
        f"instances={report['instance_count']} sha256={sha256_bytes(dumps(report))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
