"""Closed schemas and identity hygiene for canonical O-07 evidence reports."""

from __future__ import annotations

from collections.abc import Iterable
import re


PROBE_SCHEMA = "styx-o07-genesis-checkpoint-probe/v2"
CROSS_RUNTIME_SCHEMA = "styx-o07-cross-runtime/v2"
MUTATION_SCHEMA = "styx-o07-source-mutations/v2"
SCOPE_SCHEMA = "styx-o07-scope-report/v2"

_IDENTIFIER = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]*$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")
_ABSOLUTE_PATH = re.compile(r"(?:^|\s)(?:/[^\s]+|[A-Za-z]:[\\/][^\s]+)")
_TIMESTAMP = re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2})?")
_PROCESS_ID = re.compile(r"\b(?:pid|process[-_ ]?id)\s*[:=]?\s*\d+\b", re.IGNORECASE)


def _dict(value: object, keys: set[str], label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{label} schema mismatch")
    if not all(isinstance(key, str) for key in value):
        raise ValueError(f"{label} has a non-string key")
    return value


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a list")
    return value


def _string(value: object, label: str, allowed: set[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    if allowed is not None and value not in allowed:
        raise ValueError(f"{label} value is not permitted")
    return value


def _integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{label} must be boolean")
    return value


def _identifier(value: object, label: str) -> str:
    result = _string(value, label)
    if _IDENTIFIER.fullmatch(result) is None:
        raise ValueError(f"{label} is not a closed identifier")
    return result


def _token(value: object, label: str) -> str:
    result = _string(value, label)
    if _TOKEN.fullmatch(result) is None:
        raise ValueError(f"{label} is not a closed token")
    return result


def _validate_probe(report: dict[str, object]) -> None:
    _dict(
        report,
        {
            "schema",
            "inventory_relation_count",
            "semantic_atom_count",
            "external_gate_count",
            "semantic_cases",
            "external_gates",
            "failed_semantic_atoms",
            "semantic_verdict",
            "final_o07_gate",
        },
        "probe report",
    )
    for key in ("inventory_relation_count", "semantic_atom_count", "external_gate_count"):
        _integer(report[key], key)
    for index, item in enumerate(_list(report["semantic_cases"], "semantic_cases")):
        case = _dict(
            item,
            {
                "atom_instance_id",
                "scenario_instance_id",
                "assertion_id",
                "observation_id",
                "expected_disposition",
                "observed_disposition",
                "observation",
                "passed",
            },
            f"semantic case {index}",
        )
        for key in case.keys() - {"passed", "observation"}:
            _identifier(case[key], f"semantic case {index}.{key}")
        _token(case["observation"], f"semantic case {index}.observation")
        _boolean(case["passed"], f"semantic case {index}.passed")
    for index, item in enumerate(_list(report["external_gates"], "external_gates")):
        gate = _dict(
            item,
            {"atom_instance_id", "gate_instance_id", "requirement", "state"},
            f"external gate {index}",
        )
        _identifier(gate["atom_instance_id"], f"external gate {index}.atom")
        _identifier(gate["gate_instance_id"], f"external gate {index}.gate")
        _string(gate["requirement"], f"external gate {index}.requirement")
        _string(gate["state"], f"external gate {index}.state", {"REQUIRED_SEPARATE_GATE"})
    for item in _list(report["failed_semantic_atoms"], "failed_semantic_atoms"):
        _identifier(item, "failed semantic atom")
    _string(report["semantic_verdict"], "semantic_verdict", {"PASS", "FAIL"})
    _string(report["final_o07_gate"], "final_o07_gate", {"NOT_EVALUATED_BY_THIS_PROBE"})


def _validate_cross_runtime(report: dict[str, object]) -> None:
    _dict(
        report,
        {"schema", "adapter_count", "semantic_atom_count", "comparisons", "failed", "verdict"},
        "cross-runtime report",
    )
    _integer(report["adapter_count"], "adapter_count")
    _integer(report["semantic_atom_count"], "semantic_atom_count")
    for index, item in enumerate(_list(report["comparisons"], "comparisons")):
        comparison = _dict(
            item,
            {
                "atom_instance_id",
                "scenario_instance_id",
                "assertion_id",
                "observation_id",
                "expected_disposition",
                "python",
                "javascript",
                "exact",
            },
            f"comparison {index}",
        )
        for key in (
            "atom_instance_id",
            "scenario_instance_id",
            "assertion_id",
            "observation_id",
            "expected_disposition",
        ):
            _identifier(comparison[key], f"comparison {index}.{key}")
        for runtime in ("python", "javascript"):
            result = _dict(
                comparison[runtime],
                {"disposition", "observation"},
                f"comparison {index}.{runtime}",
            )
            _identifier(result["disposition"], f"comparison {index}.{runtime}.disposition")
            _token(result["observation"], f"comparison {index}.{runtime}.observation")
        _boolean(comparison["exact"], f"comparison {index}.exact")
    for item in _list(report["failed"], "failed"):
        _identifier(item, "failed runtime atom")
    _string(report["verdict"], "verdict", {"PASS", "FAIL"})


def _validate_mutations(report: dict[str, object]) -> None:
    _dict(
        report,
        {
            "schema",
            "registered_mutant_count",
            "semantic_relation_count",
            "mutants",
            "relations",
            "survived",
            "uncovered_atoms",
            "verdict",
        },
        "mutation report",
    )
    _integer(report["registered_mutant_count"], "registered_mutant_count")
    _integer(report["semantic_relation_count"], "semantic_relation_count")
    for index, item in enumerate(_list(report["mutants"], "mutants")):
        mutant = _dict(
            item,
            {"mutant_id", "family", "source_file", "detector_atom", "anchor_count", "killed"},
            f"mutant {index}",
        )
        for key in ("mutant_id", "family", "detector_atom"):
            _identifier(mutant[key], f"mutant {index}.{key}")
        source_file = _string(mutant["source_file"], f"mutant {index}.source_file")
        if source_file.startswith("/") or ".." in source_file.split("/"):
            raise ValueError("mutant source path is not repository-relative")
        _integer(mutant["anchor_count"], f"mutant {index}.anchor_count")
        _boolean(mutant["killed"], f"mutant {index}.killed")
    for index, item in enumerate(_list(report["relations"], "relations")):
        relation = _dict(
            item,
            {"relation_id", "atom_instance_id", "mutant_id", "detector_atom", "killed"},
            f"mutation relation {index}",
        )
        for key in relation.keys() - {"killed"}:
            _identifier(relation[key], f"mutation relation {index}.{key}")
        _boolean(relation["killed"], f"mutation relation {index}.killed")
    for key in ("survived", "uncovered_atoms"):
        for item in _list(report[key], key):
            _identifier(item, key)
    _string(
        report["verdict"],
        "verdict",
        {"ALL_REGISTERED_MUTANTS_KILLED", "MUTANT_SURVIVED"},
    )


def _validate_scope(report: dict[str, object]) -> None:
    _dict(
        report,
        {
            "schema",
            "copy_threshold_percent",
            "changed_relation",
            "changed_endpoint_count",
            "validator_assignments_changed",
            "approved_artifact_count",
            "predecessor_review_test_count",
            "byte_identical_o07_base_blob_count",
            "predecessor_import_count",
            "verdict",
        },
        "scope report",
    )
    for key in (
        "copy_threshold_percent",
        "changed_endpoint_count",
        "approved_artifact_count",
        "predecessor_review_test_count",
        "byte_identical_o07_base_blob_count",
        "predecessor_import_count",
    ):
        _integer(report[key], key)
    for index, item in enumerate(_list(report["changed_relation"], "changed_relation")):
        relation = _dict(item, {"status", "paths"}, f"scope relation {index}")
        _identifier(relation["status"], f"scope relation {index}.status")
        for path in _list(relation["paths"], f"scope relation {index}.paths"):
            relative = _string(path, f"scope relation {index}.path")
            if relative.startswith("/") or ".." in relative.split("/"):
                raise ValueError("scope report path is not repository-relative")
    for item in _list(report["validator_assignments_changed"], "validator assignments"):
        _identifier(item, "validator assignment")
    _string(report["verdict"], "verdict", {"PASS"})


_VALIDATORS = {
    PROBE_SCHEMA: _validate_probe,
    CROSS_RUNTIME_SCHEMA: _validate_cross_runtime,
    MUTATION_SCHEMA: _validate_mutations,
    SCOPE_SCHEMA: _validate_scope,
}


def _strings(value: object) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key)
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def validate_canonical_report(
    report: object,
    *,
    forbidden_identities: Iterable[str] = (),
    forbidden_runtime_values: Iterable[str] = (),
) -> dict[str, object]:
    """Validate a closed schema and reject runtime or repository identity leakage."""

    if not isinstance(report, dict):
        raise ValueError("canonical report must be an object")
    schema = report.get("schema")
    if not isinstance(schema, str) or schema not in _VALIDATORS:
        raise ValueError("unknown canonical report schema")
    _VALIDATORS[schema](report)

    identity_needles: set[str] = set()
    for identity in forbidden_identities:
        if identity:
            identity_needles.update(identity[:length] for length in range(7, len(identity) + 1))
    runtime_needles = {value for value in forbidden_runtime_values if value}
    for value in _strings(report):
        if _ABSOLUTE_PATH.search(value):
            raise ValueError("canonical report contains an absolute path")
        if _TIMESTAMP.search(value):
            raise ValueError("canonical report contains a timestamp")
        if _PROCESS_ID.search(value):
            raise ValueError("canonical report contains a process identifier")
        if any(needle in value for needle in identity_needles):
            raise ValueError("canonical report contains repository identity")
        if any(needle == value or needle in value for needle in runtime_needles):
            raise ValueError("canonical report contains runtime identity")
    return report
