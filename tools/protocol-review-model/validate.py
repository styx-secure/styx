#!/usr/bin/env python3
"""Fail-closed validator for the derived Styx protocol review model."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


EXPECTED_REGISTRIES = {
    "confidentiality": [
        "LOCAL_RUNTIME_PROFILE",
        "NONE",
        "PROFILE_DEPENDENT",
        "SECURE_SESSION_PROFILE",
        "UNRESOLVED",
    ],
    "integrity": [
        "COMMITMENT",
        "DIGEST_DERIVED",
        "NONE",
        "PROFILE_DEPENDENT",
        "SESSION_AUTHENTICATED",
        "SIGNED_TRANSCRIPT",
        "UNRESOLVED",
    ],
    "decisions": [
        "O-01",
        "O-02",
        "O-03",
        "O-04",
        "O-05",
        "O-06",
        "O-06a",
        "O-06b-1",
        "O-06b-2",
        "O-06c",
        "O-07",
        "O-08",
        "O-09",
        "O-10",
        "O-11",
        "O-12",
        "O-13",
        "O-14",
        "O-15",
        "O-16",
    ],
    "gated_capabilities": [
        "corpus",
        "demo",
        "destruction_capable_increment",
        "erasure_claim",
        "implementation_alignment",
        "irreversible_effects",
        "product",
        "product_readiness",
        "product_recovery",
        "profile_succession",
        "sensitive_use",
        "time_bearing_profile",
    ],
    "layers": ["AP", "K", "PV", "RS", "SS", "TR"],
    "obligations": [
        *[f"OB-AP{index:02d}" for index in range(1, 11)],
        *[f"OB-K{index:02d}" for index in range(1, 19)],
        *[f"OB-PV{index:02d}" for index in range(1, 12)],
        *[f"OB-RS{index:02d}" for index in range(1, 14)],
        *[f"OB-SS{index:02d}" for index in range(1, 10)],
        *[f"OB-TR{index:02d}" for index in range(1, 11)],
    ],
    "statuses": [
        "DECIDED",
        "DERIVED",
        "EVIDENCE_ONLY",
        "NO_GO",
        "OPEN",
        "PROFILE_DEPENDENT",
        "SYMBOLIC",
        "UNRESOLVED",
    ],
    "trust_classes": [
        "APPLICATION",
        "CRYPTOGRAPHIC",
        "HUMAN",
        "NETWORK",
        "RUNTIME",
        "SESSION",
    ],
    "wire_presence": [
        "DERIVED",
        "NOT_CARRIED",
        "OUT_OF_BAND",
        "PROFILE_DEPENDENT",
        "SIGNED_TRANSCRIPT",
        "SYMBOLIC_INPUT",
    ],
}

REQUIRED_COUNTEREXAMPLES = {
    "CE_CHECKPOINT_STALE",
    "CE_CREDENTIAL_COLLISION",
    "CE_FORK_CONTEXT_QUARANTINE",
    "CE_GRANT_REVOKE_LAUNDERING_ORDER_A",
    "CE_GRANT_REVOKE_LAUNDERING_ORDER_B",
    "CE_MISSING_REQUIRED_OPENING",
    "CE_SELECTIVE_REVEAL",
}

REQUIRED_NON_CLAIMS = {
    "NC_AUDIT_READINESS",
    "NC_AVAILABILITY",
    "NC_COMMITMENT_COPY",
    "NC_ERASURE",
    "NC_FINALITY",
    "NC_GENESIS_CHECKPOINT",
    "NC_HIDING_ASSUMPTION",
    "NC_METADATA_ANONYMITY",
    "NC_REVOCATION_COMPROMISE",
    "NC_ROLLBACK_DETECTION",
    "NC_SUPPORTED_ADAPTER",
}

REQUIRED_REVIEW_QUERIES = {
    "RQ_AUTHORIZATION",
    "RQ_BLOCKERS",
    "RQ_COUNTEREXAMPLES",
    "RQ_FIELD_PROTECTION",
    "RQ_REPLAY",
    "RQ_SCOPE",
    "RQ_SOURCE_STALENESS",
    "RQ_STATUS_DISCIPLINE",
    "RQ_VISIBILITY",
}

REQUIRED_INVARIANTS = {
    "INV_AUTH_NOT_KEY",
    "INV_C0_3_NO_GO",
    "INV_CAUSALITY_TRANSCRIPT_ONLY",
    "INV_CONTROL_NONE_CLASS",
    "INV_CROSS_CONTEXT_REJECTION",
    "INV_FORK_QUARANTINE",
    "INV_NO_CHECKPOINT_SUBSTITUTION",
    "INV_NO_OPENING_SUBSTITUTION",
    "INV_PENDING_SELECTIVE_PROGRESS",
    "INV_PROTECTION_SEPARATION",
    "INV_REPLAY_NO_AUTHORITY",
    "INV_SET_RELATIVE_REPLAY",
    "INV_SOURCE_AUTHORITY",
}

REQUIRED_RESIDUAL_RISKS = {
    "RR_CHECKPOINT_STALENESS",
    "RR_FORK_AVAILABILITY",
    "RR_METADATA_EXPOSURE",
    "RR_NO_FINALITY",
    "RR_OPENING_LOSS",
    "RR_ROLLBACK_LIMIT",
    "RR_SECURE_ADAPTER_ABSENT",
    "RR_UNAUDITED",
}

REQUIRED_C03_DEPENDENCIES = {
    "C0.3_CORPUS_PATH_APPROVAL",
    "O-06c",
    "O-07",
    "O-08",
    "O-10",
    "O-14",
}

EXPECTED_STATUS_BY_COLLECTION = {
    "blockers": {
        "C0.2j": "OPEN",
        "C0.2k": "OPEN",
        "C0.3": "NO_GO",
        "C0.3_CORPUS_PATH_APPROVAL": "OPEN",
        "O-06c": "OPEN",
        "O-07": "OPEN",
        "O-08": "OPEN",
        "O-10": "OPEN",
        "O-12": "OPEN",
        "O-13": "OPEN",
        "O-14": "OPEN",
        "O-15": "OPEN",
        "O-16": "OPEN",
    },
    "counterexamples": {item: "EVIDENCE_ONLY" for item in REQUIRED_COUNTEREXAMPLES},
    "flows": {
        "author_application_event": "DECIDED",
        "checkpoint_restore": "SYMBOLIC",
        "fork_quarantine": "DECIDED",
        "logical_removal": "DECIDED",
        "missing_required_opening": "DECIDED",
        "receive_late_opening": "DECIDED",
        "secure_session_receive": "PROFILE_DEPENDENT",
        "secure_session_send": "PROFILE_DEPENDENT",
        "transport_publish": "PROFILE_DEPENDENT",
        "validate_and_fold": "DECIDED",
    },
    "invariants": {
        "INV_AUTH_NOT_KEY": "DECIDED",
        "INV_C0_3_NO_GO": "NO_GO",
        "INV_CAUSALITY_TRANSCRIPT_ONLY": "DECIDED",
        "INV_CONTROL_NONE_CLASS": "DECIDED",
        "INV_CROSS_CONTEXT_REJECTION": "DECIDED",
        "INV_FORK_QUARANTINE": "DECIDED",
        "INV_NO_CHECKPOINT_SUBSTITUTION": "DECIDED",
        "INV_NO_OPENING_SUBSTITUTION": "DECIDED",
        "INV_PENDING_SELECTIVE_PROGRESS": "DECIDED",
        "INV_PROTECTION_SEPARATION": "DECIDED",
        "INV_REPLAY_NO_AUTHORITY": "DECIDED",
        "INV_SET_RELATIVE_REPLAY": "DECIDED",
        "INV_SOURCE_AUTHORITY": "DERIVED",
    },
    "objects": {
        "application_event": "DECIDED",
        "checkpoint_evidence": "SYMBOLIC",
        "content_bytes": "DECIDED",
        "content_descriptor": "DECIDED",
        "genesis": "UNRESOLVED",
        "opening": "DECIDED",
    },
    "state_models": {
        "ap_projection": "DECIDED",
        "k_admission": "DECIDED",
        "pending_replay": "DECIDED",
    },
}

SUPPORTED_SCHEMA_KEYWORDS = {
    "$defs",
    "$id",
    "$ref",
    "$schema",
    "additionalProperties",
    "const",
    "description",
    "enum",
    "items",
    "minItems",
    "minLength",
    "pattern",
    "properties",
    "required",
    "title",
    "type",
}

SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"

PROTECTED_UNRESOLVED_FIELDS = {
    ("application_event", "ap_transition_block"),
    ("application_event", "credential_identifier"),
    ("application_event", "event_type_identifier"),
    ("application_event", "genesis_reference"),
    ("application_event", "schema_identifier"),
    ("application_event", "schema_version"),
    ("application_event", "signature"),
    ("genesis", "derived_genesis_reference"),
    ("genesis", "genesis_body"),
}

SORTED_RECORD_ARRAYS = (
    "actors",
    "blockers",
    "counterexamples",
    "flows",
    "invariants",
    "layers",
    "non_claims",
    "objects",
    "outcomes",
    "residual_risks",
    "review_queries",
    "sources",
    "state_models",
)


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    message: str


class DuplicateKeyError(ValueError):
    pass


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def load_json_unique(path: Path) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_object_without_duplicates,
        )
    except DuplicateKeyError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot parse {path}: {exc}") from exc


def _json_type_matches(value: Any, expected: str) -> bool:
    return {
        "array": isinstance(value, list),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "null": value is None,
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
    }.get(expected, False)


def _resolve_ref(schema_root: dict[str, Any], reference: str) -> dict[str, Any]:
    prefix = "#/$defs/"
    if not isinstance(reference, str):
        raise ValueError("schema reference must be a string")
    if not reference.startswith(prefix):
        raise ValueError(f"unsupported schema reference: {reference}")
    name = reference[len(prefix) :]
    target = schema_root.get("$defs", {}).get(name)
    if not isinstance(target, dict):
        raise ValueError(f"unknown schema reference: {reference}")
    return target


def _schema_definition_findings(
    schema: Any,
    schema_root: dict[str, Any],
    path: str,
) -> list[Finding]:
    if not isinstance(schema, dict):
        return [Finding("SCHEMA_DEFINITION", path, "schema node must be an object")]

    findings: list[Finding] = []
    for keyword in schema:
        if keyword not in SUPPORTED_SCHEMA_KEYWORDS:
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.{keyword}",
                    "unsupported schema keyword would fail open",
                )
            )

    for keyword in ("$id", "$schema", "description", "title"):
        if keyword in schema and not isinstance(schema[keyword], str):
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.{keyword}",
                    f"{keyword} must be a string",
                )
            )

    if "$ref" in schema:
        if set(schema) != {"$ref"}:
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    path,
                    "$ref nodes must not contain ignored sibling keywords",
                )
            )
        try:
            _resolve_ref(schema_root, schema["$ref"])
        except (TypeError, ValueError) as exc:
            findings.append(Finding("SCHEMA_DEFINITION", path, str(exc)))
        return findings

    if "enum" in schema:
        enum_values = schema["enum"]
        if not isinstance(enum_values, list) or not enum_values:
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.enum",
                    "enum must be a non-empty array",
                )
            )
        elif len({json.dumps(value, sort_keys=True) for value in enum_values}) != len(
            enum_values
        ):
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.enum",
                    "enum values must be unique",
                )
            )

    schema_type = schema.get("type")
    if schema_type is not None and schema_type not in {
        "array",
        "boolean",
        "integer",
        "null",
        "number",
        "object",
        "string",
    }:
        findings.append(
            Finding("SCHEMA_DEFINITION", f"{path}.type", "unsupported schema type")
        )

    if schema_type == "object":
        if schema.get("additionalProperties") is not False:
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.additionalProperties",
                    "every object schema must fail closed",
                )
            )
        properties = schema.get("properties")
        if not isinstance(properties, dict):
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.properties",
                    "object schema properties must be an object",
                )
            )
        else:
            required = schema.get("required", [])
            if not isinstance(required, list) or any(
                not isinstance(item, str) for item in required
            ):
                findings.append(
                    Finding(
                        "SCHEMA_DEFINITION",
                        f"{path}.required",
                        "required must be an array of property names",
                    )
                )
            elif not set(required).issubset(properties):
                findings.append(
                    Finding(
                        "SCHEMA_DEFINITION",
                        f"{path}.required",
                        "required names must exist in properties",
                    )
                )
            for name, child in properties.items():
                if not isinstance(name, str):
                    findings.append(
                        Finding(
                            "SCHEMA_DEFINITION",
                            f"{path}.properties",
                            "property names must be strings",
                        )
                    )
                    continue
                findings.extend(
                    _schema_definition_findings(
                        child,
                        schema_root,
                        f"{path}.properties.{name}",
                    )
                )

    if "items" in schema:
        if not isinstance(schema["items"], dict):
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.items",
                    "items must be an object schema",
                )
            )
        else:
            findings.extend(
                _schema_definition_findings(
                    schema["items"], schema_root, f"{path}.items"
                )
            )

    for keyword in ("minItems", "minLength"):
        if keyword in schema and (
            not isinstance(schema[keyword], int)
            or isinstance(schema[keyword], bool)
            or schema[keyword] < 0
        ):
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.{keyword}",
                    f"{keyword} must be a non-negative integer",
                )
            )

    if "pattern" in schema:
        try:
            re.compile(schema["pattern"])
        except (TypeError, re.error) as exc:
            findings.append(Finding("SCHEMA_DEFINITION", f"{path}.pattern", str(exc)))

    if "$defs" in schema:
        definitions = schema["$defs"]
        if not isinstance(definitions, dict):
            findings.append(
                Finding("SCHEMA_DEFINITION", f"{path}.$defs", "$defs must be an object")
            )
        else:
            for name, child in definitions.items():
                findings.extend(
                    _schema_definition_findings(child, schema_root, f"{path}.$defs.{name}")
                )
    return findings


def _schema_findings(
    value: Any,
    schema: dict[str, Any],
    schema_root: dict[str, Any],
    path: str,
) -> list[Finding]:
    findings: list[Finding] = []
    if "$ref" in schema:
        try:
            target = _resolve_ref(schema_root, schema["$ref"])
        except ValueError as exc:
            return [Finding("SCHEMA_DEFINITION", path, str(exc))]
        return _schema_findings(value, target, schema_root, path)

    if "type" in schema and not _json_type_matches(value, schema["type"]):
        return [
            Finding(
                "SCHEMA_MISMATCH",
                path,
                f"expected {schema['type']}, got {type(value).__name__}",
            )
        ]
    if "const" in schema and value != schema["const"]:
        findings.append(Finding("SCHEMA_MISMATCH", path, "const value mismatch"))
    if "enum" in schema and value not in schema["enum"]:
        findings.append(Finding("SCHEMA_MISMATCH", path, "value outside enum"))
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            findings.append(Finding("SCHEMA_MISMATCH", path, "string too short"))
        pattern = schema.get("pattern")
        if pattern is not None and re.search(pattern, value) is None:
            findings.append(Finding("SCHEMA_MISMATCH", path, "pattern mismatch"))
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            findings.append(Finding("SCHEMA_MISMATCH", path, "array too short"))
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                findings.extend(
                    _schema_findings(item, item_schema, schema_root, f"{path}[{index}]")
                )
    if isinstance(value, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                findings.append(
                    Finding("SCHEMA_MISMATCH", f"{path}.{key}", "required key missing")
                )
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    findings.append(
                        Finding("SCHEMA_MISMATCH", f"{path}.{key}", "unknown key")
                    )
        for key, child_schema in properties.items():
            if key in value:
                findings.extend(
                    _schema_findings(
                        value[key], child_schema, schema_root, f"{path}.{key}"
                    )
                )
    return findings


def validate_schema(model: Any, schema: Any) -> list[Finding]:
    if not isinstance(schema, dict):
        return [Finding("SCHEMA_DEFINITION", "$schema", "schema root must be object")]
    findings: list[Finding] = []
    if schema.get("$schema") != SCHEMA_DRAFT:
        findings.append(
            Finding("SCHEMA_DEFINITION", "$schema.$schema", "unexpected schema draft")
        )
    definition_findings = _schema_definition_findings(schema, schema, "$schema")
    findings.extend(definition_findings)
    if findings:
        return findings
    findings.extend(_schema_findings(model, schema, schema, "$model"))
    return findings


def _unique_ids(records: list[dict[str, Any]], path: str) -> tuple[set[str], list[Finding]]:
    seen: set[str] = set()
    findings: list[Finding] = []
    for index, record in enumerate(records):
        record_id = record.get("id")
        if not isinstance(record_id, str):
            continue
        if record_id in seen:
            findings.append(
                Finding("DUPLICATE_ID", f"{path}[{index}].id", f"duplicate id {record_id}")
            )
        seen.add(record_id)
    return seen, findings


def _require_sorted_ids(records: list[dict[str, Any]], path: str) -> list[Finding]:
    ids = [record.get("id") for record in records]
    if not all(isinstance(value, str) for value in ids):
        return []
    if ids != sorted(ids):
        return [Finding("NONDETERMINISTIC_ORDER", path, "records must be sorted by id")]
    return []


def _require_sorted_unique_strings(values: Any, path: str) -> list[Finding]:
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        return []
    if len(values) != len(set(values)):
        return [Finding("DUPLICATE_ID", path, "set-like array contains duplicate values")]
    if values != sorted(values):
        return [Finding("NONDETERMINISTIC_ORDER", path, "set-like array must be sorted")]
    return []


def _record_map(model: dict[str, Any], name: str) -> dict[str, dict[str, Any]]:
    return {
        record["id"]: record
        for record in model.get(name, [])
        if isinstance(record, dict) and isinstance(record.get("id"), str)
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_sources(
    model: dict[str, Any], repo_root: Path
) -> tuple[dict[str, bytes], list[Finding]]:
    findings: list[Finding] = []
    source_bytes: dict[str, bytes] = {}
    paths_seen: set[str] = set()
    root = repo_root.resolve()
    for index, source in enumerate(model.get("sources", [])):
        if not isinstance(source, dict):
            continue
        source_id = source.get("id")
        relative = source.get("path")
        expected = source.get("sha256")
        path_label = f"$model.sources[{index}]"
        if not isinstance(source_id, str) or not isinstance(relative, str):
            continue
        if relative in paths_seen:
            findings.append(Finding("DUPLICATE_ID", f"{path_label}.path", relative))
        paths_seen.add(relative)
        candidate = repo_root / relative
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            findings.append(Finding("SOURCE_MISSING", f"{path_label}.path", str(exc)))
            continue
        if candidate.is_symlink() or resolved == root or root not in resolved.parents:
            findings.append(
                Finding("SOURCE_BOUNDARY", f"{path_label}.path", "source escapes repository")
            )
            continue
        if not resolved.is_file():
            findings.append(Finding("SOURCE_MISSING", f"{path_label}.path", "not a file"))
            continue
        actual = _sha256(resolved)
        if actual != expected:
            findings.append(
                Finding(
                    "SOURCE_DIGEST_MISMATCH",
                    f"{path_label}.sha256",
                    f"expected {expected}, got {actual}",
                )
            )
        try:
            source_bytes[source_id] = resolved.read_bytes()
        except OSError as exc:
            findings.append(Finding("SOURCE_MISSING", f"{path_label}.path", str(exc)))
    return source_bytes, findings


def _iter_cited_records(model: dict[str, Any]):
    for name in (
        "actors",
        "blockers",
        "counterexamples",
        "flows",
        "invariants",
        "layers",
        "non_claims",
        "objects",
        "outcomes",
        "residual_risks",
        "review_queries",
        "state_models",
    ):
        for index, record in enumerate(model.get(name, [])):
            if not isinstance(record, dict):
                continue
            yield f"$model.{name}[{index}]", record
            if name == "objects":
                for field_index, field in enumerate(record.get("fields", [])):
                    if isinstance(field, dict):
                        yield f"$model.{name}[{index}].fields[{field_index}]", field
            if name == "state_models":
                for transition_index, transition in enumerate(record.get("transitions", [])):
                    if isinstance(transition, dict):
                        yield (
                            f"$model.{name}[{index}].transitions[{transition_index}]",
                            transition,
                        )


def _validate_citations(
    model: dict[str, Any],
    source_bytes: dict[str, bytes],
    source_authority: dict[str, str],
) -> list[Finding]:
    findings: list[Finding] = []
    for path, record in _iter_cited_records(model):
        citations = record.get("citations", [])
        if not citations:
            findings.append(Finding("MISSING_CITATION", path, "record has no citation"))
            continue
        if not any(
            source_authority.get(citation.get("source_id")) == "normative"
            for citation in citations
            if isinstance(citation, dict)
        ):
            findings.append(
                Finding(
                    "MISSING_NORMATIVE_CITATION",
                    path,
                    "security-relevant record has no normative source citation",
                )
            )
        for index, citation in enumerate(citations):
            if not isinstance(citation, dict):
                continue
            source_id = citation.get("source_id")
            anchor = citation.get("anchor")
            citation_path = f"{path}.citations[{index}]"
            raw = source_bytes.get(source_id)
            if raw is None:
                findings.append(
                    Finding("DANGLING_REFERENCE", citation_path, f"unknown source {source_id}")
                )
                continue
            try:
                anchor_bytes = anchor.encode("utf-8")
            except (AttributeError, UnicodeError):
                continue
            if len(anchor_bytes) < 16 or b"\n" in anchor_bytes or b"\r" in anchor_bytes:
                findings.append(
                    Finding(
                        "CITATION_ANCHOR_INVALID",
                        citation_path,
                        "anchor must be a single line of at least 16 UTF-8 bytes",
                    )
                )
                continue
            if anchor_bytes not in raw:
                findings.append(
                    Finding(
                        "CITATION_ANCHOR_MISSING",
                        citation_path,
                        f"anchor absent from source {source_id}",
                    )
                )
    return findings


def _validate_blocker_dag(blockers: dict[str, dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visited:
            return
        if node in visiting:
            findings.append(Finding("BLOCKER_CYCLE", "$model.blockers", node))
            return
        visiting.add(node)
        for dependency in blockers.get(node, {}).get("depends_on", []):
            if dependency not in blockers:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"$model.blockers.{node}.depends_on",
                        dependency,
                    )
                )
            else:
                visit(dependency)
        visiting.remove(node)
        visited.add(node)

    for blocker_id in blockers:
        visit(blocker_id)
    return findings


def validate_domain(model: dict[str, Any], repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    artifact = model.get("artifact", {})
    if artifact.get("normative") is not False:
        findings.append(
            Finding(
                "FORBIDDEN_STATUS_PROMOTION",
                "$model.artifact.normative",
                "must be false",
            )
        )
    if artifact.get("security_proof") is not False:
        findings.append(
            Finding(
                "FORBIDDEN_STATUS_PROMOTION",
                "$model.artifact.security_proof",
                "must be false",
            )
        )
    if artifact.get("implementation_claim") is not False:
        findings.append(
            Finding(
                "FORBIDDEN_STATUS_PROMOTION",
                "$model.artifact.implementation_claim",
                "must be false",
            )
        )
    if artifact.get("c03_verdict") != "NO_GO":
        findings.append(
            Finding(
                "C03_GATE_MISSING",
                "$model.artifact.c03_verdict",
                "must be NO_GO",
            )
        )
    if re.fullmatch(r"[0-9a-f]{40}", str(artifact.get("contract_base_commit"))) is None:
        findings.append(
            Finding(
                "SCHEMA_MISMATCH",
                "$model.artifact.contract_base_commit",
                "must be exactly 40 lowercase hexadecimal characters",
            )
        )

    registries = model.get("registries", {})
    if registries != EXPECTED_REGISTRIES:
        findings.append(
            Finding(
                "UNKNOWN_REGISTRY_VALUE",
                "$model.registries",
                "closed registry mismatch",
            )
        )
    for name, values in registries.items() if isinstance(registries, dict) else []:
        findings.extend(_require_sorted_unique_strings(values, f"$model.registries.{name}"))

    id_sets: dict[str, set[str]] = {}
    for name in SORTED_RECORD_ARRAYS:
        records = model.get(name, [])
        if not isinstance(records, list):
            continue
        ids, duplicate_findings = _unique_ids(records, f"$model.{name}")
        id_sets[name] = ids
        findings.extend(duplicate_findings)
        findings.extend(_require_sorted_ids(records, f"$model.{name}"))

    for object_index, obj in enumerate(model.get("objects", [])):
        if not isinstance(obj, dict):
            continue
        fields = obj.get("fields", [])
        _, duplicate_findings = _unique_ids(fields, f"$model.objects[{object_index}].fields")
        findings.extend(duplicate_findings)
        findings.extend(_require_sorted_ids(fields, f"$model.objects[{object_index}].fields"))
    for state_index, state_model in enumerate(model.get("state_models", [])):
        if not isinstance(state_model, dict):
            continue
        transitions = state_model.get("transitions", [])
        _, duplicate_findings = _unique_ids(
            transitions, f"$model.state_models[{state_index}].transitions"
        )
        findings.extend(duplicate_findings)
        findings.extend(
            _require_sorted_ids(transitions, f"$model.state_models[{state_index}].transitions")
        )

    global_ids: dict[str, str] = {}
    for collection in SORTED_RECORD_ARRAYS:
        for index, record in enumerate(model.get(collection, [])):
            if not isinstance(record, dict) or not isinstance(record.get("id"), str):
                continue
            record_id = record["id"]
            location = f"$model.{collection}[{index}].id"
            if record_id in global_ids:
                findings.append(
                    Finding(
                        "DUPLICATE_ID",
                        location,
                        f"global id {record_id} already used at {global_ids[record_id]}",
                    )
                )
            else:
                global_ids[record_id] = location
            if collection == "objects":
                nested = record.get("fields", [])
                nested_name = "fields"
            elif collection == "state_models":
                nested = record.get("transitions", [])
                nested_name = "transitions"
            else:
                nested = []
                nested_name = ""
            for nested_index, child in enumerate(nested):
                if not isinstance(child, dict) or not isinstance(child.get("id"), str):
                    continue
                child_id = child["id"]
                child_location = f"$model.{collection}[{index}].{nested_name}[{nested_index}].id"
                if child_id in global_ids:
                    findings.append(
                        Finding(
                            "DUPLICATE_ID",
                            child_location,
                            f"global id {child_id} already used at {global_ids[child_id]}",
                        )
                    )
                else:
                    global_ids[child_id] = child_location

    if id_sets.get("layers") != set(EXPECTED_REGISTRIES["layers"]):
        findings.append(
            Finding(
                "UNKNOWN_REGISTRY_VALUE",
                "$model.layers",
                "must define exactly six layers",
            )
        )

    source_bytes, source_findings = _validate_sources(model, repo_root)
    findings.extend(source_findings)
    source_authority = {
        source.get("id"): source.get("authority")
        for source in model.get("sources", [])
        if isinstance(source, dict)
    }
    findings.extend(_validate_citations(model, source_bytes, source_authority))

    actors = _record_map(model, "actors")
    objects = _record_map(model, "objects")
    outcomes = _record_map(model, "outcomes")
    blockers = _record_map(model, "blockers")
    counterexamples = _record_map(model, "counterexamples")
    sources = _record_map(model, "sources")
    layers = set(EXPECTED_REGISTRIES["layers"])
    statuses = set(EXPECTED_REGISTRIES["statuses"])
    decisions = set(EXPECTED_REGISTRIES["decisions"])
    obligations = set(EXPECTED_REGISTRIES["obligations"])

    for collection in (
        "blockers",
        "counterexamples",
        "flows",
        "invariants",
        "objects",
        "outcomes",
        "residual_risks",
        "state_models",
    ):
        for index, record in enumerate(model.get(collection, [])):
            if not isinstance(record, dict):
                continue
            if record.get("status") not in statuses:
                findings.append(
                    Finding(
                        "UNKNOWN_REGISTRY_VALUE",
                        f"$model.{collection}[{index}].status",
                        str(record.get("status")),
                    )
                )
            expected_status = EXPECTED_STATUS_BY_COLLECTION.get(collection, {}).get(
                record.get("id")
            )
            if expected_status is not None and record.get("status") != expected_status:
                findings.append(
                    Finding(
                        "FORBIDDEN_STATUS_PROMOTION",
                        f"$model.{collection}[{index}].status",
                        f"{record.get('id')} must remain {expected_status}",
                    )
                )

    for collection in (
        "actors",
        "blockers",
        "counterexamples",
        "flows",
        "invariants",
        "layers",
        "non_claims",
        "objects",
        "outcomes",
        "residual_risks",
        "review_queries",
        "state_models",
    ):
        for index, record in enumerate(model.get(collection, [])):
            if not isinstance(record, dict):
                continue
            path = f"$model.{collection}[{index}]"
            for key, registry in (
                ("decision_refs", decisions),
                ("obligation_refs", obligations),
            ):
                if key not in record:
                    continue
                values = record.get(key, [])
                findings.extend(_require_sorted_unique_strings(values, f"{path}.{key}"))
                for reference in values:
                    if reference not in registry:
                        findings.append(
                            Finding("DANGLING_REFERENCE", f"{path}.{key}", reference)
                        )
            for field_index, field in enumerate(record.get("fields", [])):
                if not isinstance(field, dict):
                    continue
                field_path = f"{path}.fields[{field_index}]"
                for key, registry in (
                    ("decision_refs", decisions),
                    ("obligation_refs", obligations),
                ):
                    if key not in field:
                        continue
                    values = field.get(key, [])
                    findings.extend(
                        _require_sorted_unique_strings(values, f"{field_path}.{key}")
                    )
                    for reference in values:
                        if reference not in registry:
                            findings.append(
                                Finding(
                                    "DANGLING_REFERENCE",
                                    f"{field_path}.{key}",
                                    reference,
                                )
                            )

            for transition_index, transition in enumerate(
                record.get("transitions", [])
            ):
                if not isinstance(transition, dict):
                    continue
                transition_path = f"{path}.transitions[{transition_index}]"
                for key, registry in (
                    ("decision_refs", decisions),
                    ("obligation_refs", obligations),
                ):
                    values = transition.get(key, [])
                    findings.extend(
                        _require_sorted_unique_strings(
                            values, f"{transition_path}.{key}"
                        )
                    )
                    for reference in values:
                        if reference not in registry:
                            findings.append(
                                Finding(
                                    "DANGLING_REFERENCE",
                                    f"{transition_path}.{key}",
                                    reference,
                                )
                            )

    for index, actor in enumerate(model.get("actors", [])):
        if actor.get("owner") not in layers:
            findings.append(
                Finding(
                    "DANGLING_REFERENCE",
                    f"$model.actors[{index}].owner",
                    str(actor.get("owner")),
                )
            )
        if actor.get("trust_class") not in EXPECTED_REGISTRIES["trust_classes"]:
            findings.append(
                Finding(
                    "UNKNOWN_REGISTRY_VALUE",
                    f"$model.actors[{index}].trust_class",
                    str(actor.get("trust_class")),
                )
            )

    for object_index, obj in enumerate(model.get("objects", [])):
        owner = obj.get("owner")
        if owner not in layers:
            findings.append(
                Finding(
                    "DANGLING_REFERENCE",
                    f"$model.objects[{object_index}].owner",
                    str(owner),
                )
            )
        if obj.get("status") not in statuses:
            findings.append(
                Finding(
                    "UNKNOWN_REGISTRY_VALUE",
                    f"$model.objects[{object_index}].status",
                    str(obj.get("status")),
                )
            )
        for field_index, field in enumerate(obj.get("fields", [])):
            path = f"$model.objects[{object_index}].fields[{field_index}]"
            if field.get("owner") not in layers:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"{path}.owner",
                        str(field.get("owner")),
                    )
                )
            if field.get("status") not in statuses:
                findings.append(
                    Finding(
                        "UNKNOWN_REGISTRY_VALUE",
                        f"{path}.status",
                        str(field.get("status")),
                    )
                )
            if field.get("wire_presence") not in EXPECTED_REGISTRIES["wire_presence"]:
                findings.append(
                    Finding(
                        "MISSING_PROTECTION_METADATA",
                        f"{path}.wire_presence",
                        str(field.get("wire_presence")),
                    )
                )
            if field.get("confidentiality") not in EXPECTED_REGISTRIES["confidentiality"]:
                findings.append(
                    Finding(
                        "MISSING_PROTECTION_METADATA",
                        f"{path}.confidentiality",
                        str(field.get("confidentiality")),
                    )
                )
            integrity = field.get("integrity", [])
            if not integrity or any(
                value not in EXPECTED_REGISTRIES["integrity"] for value in integrity
            ):
                findings.append(
                    Finding(
                        "MISSING_PROTECTION_METADATA",
                        f"{path}.integrity",
                        str(integrity),
                    )
                )
            findings.extend(_require_sorted_unique_strings(integrity, f"{path}.integrity"))
            for key in ("visible_to", "mutable_by"):
                values = field.get(key, [])
                findings.extend(_require_sorted_unique_strings(values, f"{path}.{key}"))
                for actor_id in values:
                    if actor_id not in actors:
                        findings.append(Finding("DANGLING_REFERENCE", f"{path}.{key}", actor_id))
            if not set(field.get("mutable_by", [])).issubset(field.get("visible_to", [])):
                findings.append(
                    Finding(
                        "VISIBILITY_MUTABILITY_MISMATCH",
                        path,
                        "every mutator must be an observer under the declared semantics",
                    )
                )
            wire_presence = field.get("wire_presence")
            integrity_set = set(integrity)
            if wire_presence == "SIGNED_TRANSCRIPT" and "SIGNED_TRANSCRIPT" not in integrity_set:
                findings.append(
                    Finding(
                        "MISSING_PROTECTION_METADATA",
                        f"{path}.integrity",
                        "signed-transcript field lacks signed-transcript integrity",
                    )
                )
            if wire_presence == "DERIVED" and "DIGEST_DERIVED" not in integrity_set:
                findings.append(
                    Finding(
                        "MISSING_PROTECTION_METADATA",
                        f"{path}.integrity",
                        "derived field lacks digest-derived integrity",
                    )
                )
            if wire_presence == "SYMBOLIC_INPUT" and field.get("status") != "SYMBOLIC":
                findings.append(
                    Finding(
                        "FORBIDDEN_STATUS_PROMOTION",
                        f"{path}.status",
                        "symbolic input must remain SYMBOLIC",
                    )
                )
            locator = (obj.get("id"), field.get("id"))
            if locator in PROTECTED_UNRESOLVED_FIELDS and field.get("status") != "UNRESOLVED":
                findings.append(
                    Finding(
                        "FORBIDDEN_STATUS_PROMOTION",
                        path,
                        f"{locator} must remain UNRESOLVED",
                    )
                )

    if "NC_SUPPORTED_ADAPTER" in _record_map(model, "non_claims"):
        for object_index, obj in enumerate(model.get("objects", [])):
            for field_index, field in enumerate(obj.get("fields", [])):
                path = f"$model.objects[{object_index}].fields[{field_index}]"
                if (
                    field.get("confidentiality") == "SECURE_SESSION_PROFILE"
                    or "SESSION_AUTHENTICATED" in field.get("integrity", [])
                ):
                    findings.append(
                        Finding(
                            "FORBIDDEN_STATUS_PROMOTION",
                            path,
                            "secure-session protection cannot be claimed before "
                            "a supported adapter is selected",
                        )
                    )

    for flow_index, flow in enumerate(model.get("flows", [])):
        path = f"$model.flows[{flow_index}]"
        if flow.get("owner") not in layers:
            findings.append(Finding("DANGLING_REFERENCE", f"{path}.owner", str(flow.get("owner"))))
        if flow.get("status") not in statuses:
            findings.append(
                Finding(
                    "UNKNOWN_REGISTRY_VALUE",
                    f"{path}.status",
                    str(flow.get("status")),
                )
            )
        if flow.get("producer") not in actors:
            findings.append(
                Finding(
                    "DANGLING_REFERENCE",
                    f"{path}.producer",
                    str(flow.get("producer")),
                )
            )
        for key in ("consumers", "observers"):
            values = flow.get(key, [])
            findings.extend(_require_sorted_unique_strings(values, f"{path}.{key}"))
            for actor_id in values:
                if actor_id not in actors:
                    findings.append(Finding("DANGLING_REFERENCE", f"{path}.{key}", actor_id))
        for key, registry in (("object_refs", objects), ("outcomes", outcomes)):
            values = flow.get(key, [])
            findings.extend(_require_sorted_unique_strings(values, f"{path}.{key}"))
            for reference in values:
                if reference not in registry:
                    findings.append(Finding("DANGLING_REFERENCE", f"{path}.{key}", reference))
        actions = flow.get("actor_actions", [])
        action_actors = [item.get("actor") for item in actions if isinstance(item, dict)]
        if action_actors != sorted(action_actors) or len(action_actors) != len(set(action_actors)):
            findings.append(
                Finding(
                    "NONDETERMINISTIC_ORDER",
                    f"{path}.actor_actions",
                    "actor action records must be unique and sorted by actor",
                )
            )
        for action_index, action in enumerate(actions):
            action_path = f"{path}.actor_actions[{action_index}]"
            actor_id = action.get("actor") if isinstance(action, dict) else None
            if actor_id not in actors:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"{action_path}.actor",
                        str(actor_id),
                    )
                )
            findings.extend(
                _require_sorted_unique_strings(
                    action.get("actions", []) if isinstance(action, dict) else [],
                    f"{action_path}.actions",
                )
            )
        findings.extend(
            _require_sorted_unique_strings(
                flow.get("emitted_evidence", []), f"{path}.emitted_evidence"
            )
        )

    for index, outcome in enumerate(model.get("outcomes", [])):
        path = f"$model.outcomes[{index}]"
        if outcome.get("owner") not in layers:
            findings.append(
                Finding(
                    "DANGLING_REFERENCE",
                    f"{path}.owner",
                    str(outcome.get("owner")),
                )
            )
        if outcome.get("status") not in statuses:
            findings.append(
                Finding(
                    "UNKNOWN_REGISTRY_VALUE",
                    f"{path}.status",
                    str(outcome.get("status")),
                )
            )

    for index, invariant in enumerate(model.get("invariants", [])):
        path = f"$model.invariants[{index}]"
        if invariant.get("owner") not in layers:
            findings.append(
                Finding(
                    "DANGLING_REFERENCE",
                    f"{path}.owner",
                    str(invariant.get("owner")),
                )
            )
        for reference in invariant.get("object_refs", []):
            if reference not in objects:
                findings.append(Finding("DANGLING_REFERENCE", f"{path}.object_refs", reference))
        evidence_registry = set(counterexamples) | set(sources)
        findings.extend(
            _require_sorted_unique_strings(
                invariant.get("object_refs", []), f"{path}.object_refs"
            )
        )
        findings.extend(
            _require_sorted_unique_strings(
                invariant.get("evidence_refs", []), f"{path}.evidence_refs"
            )
        )
        for reference in invariant.get("evidence_refs", []):
            if reference not in evidence_registry:
                findings.append(Finding("DANGLING_REFERENCE", f"{path}.evidence_refs", reference))

    for index, counterexample in enumerate(model.get("counterexamples", [])):
        path = f"$model.counterexamples[{index}]"
        if counterexample.get("owner") not in layers:
            findings.append(
                Finding(
                    "DANGLING_REFERENCE",
                    f"{path}.owner",
                    str(counterexample.get("owner")),
                )
            )
        if counterexample.get("status") not in statuses:
            findings.append(
                Finding(
                    "UNKNOWN_REGISTRY_VALUE",
                    f"{path}.status",
                    str(counterexample.get("status")),
                )
            )
        findings.extend(
            _require_sorted_unique_strings(
                counterexample.get("blocks", []), f"{path}.blocks"
            )
        )
        for reference in counterexample.get("blocks", []):
            if reference not in blockers:
                findings.append(Finding("DANGLING_REFERENCE", f"{path}.blocks", reference))

    for collection in ("blockers", "non_claims", "residual_risks", "review_queries"):
        for index, record in enumerate(model.get(collection, [])):
            path = f"$model.{collection}[{index}]"
            if record.get("owner") not in layers:
                findings.append(
                    Finding("DANGLING_REFERENCE", f"{path}.owner", str(record.get("owner")))
                )
            for key in ("blocks", "depends_on", "record_refs"):
                if key in record:
                    findings.extend(
                        _require_sorted_unique_strings(record.get(key, []), f"{path}.{key}")
                    )

    for index, layer in enumerate(model.get("layers", [])):
        if layer.get("owner") != layer.get("id"):
            findings.append(
                Finding(
                    "DANGLING_REFERENCE",
                    f"$model.layers[{index}].owner",
                    "a responsibility layer must own its own boundary record",
                )
            )

    findings.extend(_validate_blocker_dag(blockers))
    c03 = blockers.get("C0.3")
    if c03 is None or c03.get("status") != "NO_GO":
        findings.append(
            Finding(
                "C03_GATE_MISSING",
                "$model.blockers.C0.3",
                "missing NO_GO blocker",
            )
        )
    elif not REQUIRED_C03_DEPENDENCIES.issubset(set(c03.get("depends_on", []))):
        findings.append(
            Finding(
                "C03_GATE_MISSING",
                "$model.blockers.C0.3.depends_on",
                "required blocker edge missing",
            )
        )
    if blockers.get("C0.2k", {}).get("depends_on") != ["C0.2j"]:
        findings.append(
            Finding(
                "C03_GATE_MISSING",
                "$model.blockers.C0.2k.depends_on",
                "must depend exactly on C0.2j",
            )
        )
    if blockers.get("O-06c", {}).get("depends_on") != ["C0.2k"]:
        findings.append(
            Finding(
                "C03_GATE_MISSING",
                "$model.blockers.O-06c.depends_on",
                "must depend exactly on C0.2k",
            )
        )
    if not {"C0.2k", "C0.3", "demo", "product", "sensitive_use"}.issubset(
        set(blockers.get("C0.2j", {}).get("blocks", []))
    ):
        findings.append(
            Finding(
                "C03_GATE_MISSING",
                "$model.blockers.C0.2j.blocks",
                "C0.2j must block C0.2k, C0.3, demo, product and sensitive use",
            )
        )

    def transitively_depends_on(target: str, dependency: str) -> bool:
        pending = list(blockers.get(target, {}).get("depends_on", []))
        seen: set[str] = set()
        while pending:
            current = pending.pop()
            if current == dependency:
                return True
            if current in seen:
                continue
            seen.add(current)
            pending.extend(blockers.get(current, {}).get("depends_on", []))
        return False

    for blocker_id, blocker in blockers.items():
        for blocked_id in blocker.get("blocks", []):
            if blocked_id not in blockers and blocked_id not in EXPECTED_REGISTRIES[
                "gated_capabilities"
            ]:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"$model.blockers.{blocker_id}.blocks",
                        blocked_id,
                    )
                )
            elif blocked_id in blockers and not transitively_depends_on(
                blocked_id, blocker_id
            ):
                findings.append(
                    Finding(
                        "BLOCKER_EDGE_MISMATCH",
                        f"$model.blockers.{blocker_id}.blocks",
                        f"{blocked_id} does not depend transitively on {blocker_id}",
                    )
                )

    if not REQUIRED_COUNTEREXAMPLES.issubset(id_sets.get("counterexamples", set())):
        findings.append(
            Finding(
                "REQUIRED_RECORD_MISSING",
                "$model.counterexamples",
                "required hostile witness missing",
            )
        )
    if not REQUIRED_NON_CLAIMS.issubset(id_sets.get("non_claims", set())):
        findings.append(
            Finding(
                "REQUIRED_RECORD_MISSING",
                "$model.non_claims",
                "required non-claim missing",
            )
        )
    if not REQUIRED_REVIEW_QUERIES.issubset(id_sets.get("review_queries", set())):
        findings.append(
            Finding(
                "REQUIRED_RECORD_MISSING",
                "$model.review_queries",
                "required review query missing",
            )
        )
    if not REQUIRED_INVARIANTS.issubset(id_sets.get("invariants", set())):
        findings.append(
            Finding(
                "REQUIRED_RECORD_MISSING",
                "$model.invariants",
                "required invariant missing",
            )
        )
    if not REQUIRED_RESIDUAL_RISKS.issubset(id_sets.get("residual_risks", set())):
        findings.append(
            Finding(
                "REQUIRED_RECORD_MISSING",
                "$model.residual_risks",
                "required residual risk missing",
            )
        )

    all_record_ids = set().union(*id_sets.values()) if id_sets else set()
    all_record_ids |= {
        field.get("id")
        for obj in model.get("objects", [])
        for field in obj.get("fields", [])
        if isinstance(field, dict) and isinstance(field.get("id"), str)
    }
    for index, query in enumerate(model.get("review_queries", [])):
        for reference in query.get("record_refs", []):
            if reference not in all_record_ids:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"$model.review_queries[{index}].record_refs",
                        reference,
                    )
                )

    for state_index, state_model in enumerate(model.get("state_models", [])):
        path = f"$model.state_models[{state_index}]"
        if state_model.get("owner") not in layers:
            findings.append(
                Finding(
                    "DANGLING_REFERENCE",
                    f"{path}.owner",
                    str(state_model.get("owner")),
                )
            )
        states = set(state_model.get("states", []))
        findings.extend(
            _require_sorted_unique_strings(
                state_model.get("states", []), f"{path}.states"
            )
        )
        terminal_states = state_model.get("terminal_states", [])
        findings.extend(_require_sorted_unique_strings(terminal_states, f"{path}.terminal_states"))
        for terminal_state in terminal_states:
            if terminal_state not in states:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"{path}.terminal_states",
                        terminal_state,
                    )
                )
        allowed_precedence = states | set(outcomes)
        for precedence_item in state_model.get("precedence", []):
            if precedence_item not in allowed_precedence:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"{path}.precedence",
                        precedence_item,
                    )
                )
        for transition_index, transition in enumerate(state_model.get("transitions", [])):
            transition_path = f"{path}.transitions[{transition_index}]"
            if transition.get("owner") != state_model.get("owner"):
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"{transition_path}.owner",
                        "transition owner must match state-model owner",
                    )
                )
            if transition.get("status") not in statuses:
                findings.append(
                    Finding(
                        "UNKNOWN_REGISTRY_VALUE",
                        f"{transition_path}.status",
                        str(transition.get("status")),
                    )
                )
            findings.extend(
                _require_sorted_unique_strings(
                    transition.get("from", []), f"{transition_path}.from"
                )
            )
            for source_state in transition.get("from", []):
                if source_state not in states:
                    findings.append(
                        Finding(
                            "DANGLING_REFERENCE",
                            f"{transition_path}.from",
                            source_state,
                        )
                    )
            if transition.get("to") not in states:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"{transition_path}.to",
                        str(transition.get("to")),
                    )
                )
            if transition.get("outcome") not in outcomes:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"{transition_path}.outcome",
                        str(transition.get("outcome")),
                    )
                )

    return findings


def validate(model: Any, schema: Any, repo_root: Path) -> list[Finding]:
    findings = validate_schema(model, schema)
    if not isinstance(model, dict):
        return sorted(findings, key=lambda item: (item.code, item.path, item.message))
    findings.extend(validate_domain(model, repo_root))
    return sorted(findings, key=lambda item: (item.code, item.path, item.message))


def build_report(model_path: Path, schema_path: Path, model: dict[str, Any]) -> dict[str, Any]:
    return {
        "artifact": model["artifact"]["format"],
        "c03_verdict": model["artifact"]["c03_verdict"],
        "counts": {
            "actors": len(model["actors"]),
            "blockers": len(model["blockers"]),
            "counterexamples": len(model["counterexamples"]),
            "fields": sum(len(item["fields"]) for item in model["objects"]),
            "flows": len(model["flows"]),
            "invariants": len(model["invariants"]),
            "objects": len(model["objects"]),
            "residual_risks": len(model["residual_risks"]),
            "review_queries": len(model["review_queries"]),
            "sources": len(model["sources"]),
            "state_models": len(model["state_models"]),
        },
        "model_sha256": _sha256(model_path),
        "result": "PASS",
        "schema_sha256": _sha256(schema_path),
        "source_sha256": {
            source["id"]: source["sha256"] for source in model["sources"]
        },
    }


def write_canonical_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        model = load_json_unique(args.model)
        schema = load_json_unique(args.schema)
    except (ValueError, DuplicateKeyError) as exc:
        print(f"protocol-review-model: error: {exc}", file=sys.stderr)
        return 2
    findings = validate(model, schema, args.repo_root)
    if findings:
        for finding in findings:
            print(
                f"protocol-review-model: {finding.code}: {finding.path}: {finding.message}",
                file=sys.stderr,
            )
        return 2
    write_canonical_json(args.output, build_report(args.model, args.schema, model))
    print(f"protocol-review-model: PASS: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
