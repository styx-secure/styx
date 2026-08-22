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
    "layers": ["AP", "K", "PV", "RS", "SS", "TR"],
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
    "NC_COMMITMENT_COPY",
    "NC_FINALITY",
    "NC_GENESIS_CHECKPOINT",
    "NC_METADATA_ANONYMITY",
    "NC_REVOCATION_COMPROMISE",
    "NC_SUPPORTED_ADAPTER",
}

REQUIRED_REVIEW_QUERIES = {
    "RQ_AUTHORIZATION",
    "RQ_BLOCKERS",
    "RQ_COUNTEREXAMPLES",
    "RQ_FIELD_PROTECTION",
    "RQ_REPLAY",
    "RQ_SCOPE",
}

REQUIRED_C03_DEPENDENCIES = {
    "O-06c",
    "O-07",
    "O-08",
    "O-10",
    "O-14",
}

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
    if not reference.startswith(prefix):
        raise ValueError(f"unsupported schema reference: {reference}")
    name = reference[len(prefix) :]
    target = schema_root.get("$defs", {}).get(name)
    if not isinstance(target, dict):
        raise ValueError(f"unknown schema reference: {reference}")
    return target


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
    return _schema_findings(model, schema, schema, "$model")


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
        findings.append(Finding("FORBIDDEN_STATUS_PROMOTION", "$model.artifact.normative", "must be false"))
    if artifact.get("security_proof") is not False:
        findings.append(Finding("FORBIDDEN_STATUS_PROMOTION", "$model.artifact.security_proof", "must be false"))
    if artifact.get("implementation_claim") is not False:
        findings.append(Finding("FORBIDDEN_STATUS_PROMOTION", "$model.artifact.implementation_claim", "must be false"))
    if artifact.get("c03_verdict") != "NO_GO":
        findings.append(Finding("C03_GATE_MISSING", "$model.artifact.c03_verdict", "must be NO_GO"))

    registries = model.get("registries", {})
    if registries != EXPECTED_REGISTRIES:
        findings.append(Finding("UNKNOWN_REGISTRY_VALUE", "$model.registries", "closed registry mismatch"))
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

    if id_sets.get("layers") != set(EXPECTED_REGISTRIES["layers"]):
        findings.append(Finding("UNKNOWN_REGISTRY_VALUE", "$model.layers", "must define exactly six layers"))

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

    for index, actor in enumerate(model.get("actors", [])):
        if actor.get("trust_class") not in EXPECTED_REGISTRIES["trust_classes"]:
            findings.append(Finding("UNKNOWN_REGISTRY_VALUE", f"$model.actors[{index}].trust_class", str(actor.get("trust_class"))))

    for object_index, obj in enumerate(model.get("objects", [])):
        owner = obj.get("owner")
        if owner not in layers:
            findings.append(Finding("DANGLING_REFERENCE", f"$model.objects[{object_index}].owner", str(owner)))
        if obj.get("status") not in statuses:
            findings.append(Finding("UNKNOWN_REGISTRY_VALUE", f"$model.objects[{object_index}].status", str(obj.get("status"))))
        for field_index, field in enumerate(obj.get("fields", [])):
            path = f"$model.objects[{object_index}].fields[{field_index}]"
            if field.get("owner") not in layers:
                findings.append(Finding("DANGLING_REFERENCE", f"{path}.owner", str(field.get("owner"))))
            if field.get("status") not in statuses:
                findings.append(Finding("UNKNOWN_REGISTRY_VALUE", f"{path}.status", str(field.get("status"))))
            if field.get("wire_presence") not in EXPECTED_REGISTRIES["wire_presence"]:
                findings.append(Finding("MISSING_PROTECTION_METADATA", f"{path}.wire_presence", str(field.get("wire_presence"))))
            if field.get("confidentiality") not in EXPECTED_REGISTRIES["confidentiality"]:
                findings.append(Finding("MISSING_PROTECTION_METADATA", f"{path}.confidentiality", str(field.get("confidentiality"))))
            integrity = field.get("integrity", [])
            if not integrity or any(value not in EXPECTED_REGISTRIES["integrity"] for value in integrity):
                findings.append(Finding("MISSING_PROTECTION_METADATA", f"{path}.integrity", str(integrity)))
            findings.extend(_require_sorted_unique_strings(integrity, f"{path}.integrity"))
            for key in ("visible_to", "mutable_by"):
                values = field.get(key, [])
                findings.extend(_require_sorted_unique_strings(values, f"{path}.{key}"))
                for actor_id in values:
                    if actor_id not in actors:
                        findings.append(Finding("DANGLING_REFERENCE", f"{path}.{key}", actor_id))
            locator = (obj.get("id"), field.get("id"))
            if locator in PROTECTED_UNRESOLVED_FIELDS and field.get("status") != "UNRESOLVED":
                findings.append(Finding("FORBIDDEN_STATUS_PROMOTION", path, f"{locator} must remain UNRESOLVED"))

    for flow_index, flow in enumerate(model.get("flows", [])):
        path = f"$model.flows[{flow_index}]"
        if flow.get("producer") not in actors:
            findings.append(Finding("DANGLING_REFERENCE", f"{path}.producer", str(flow.get("producer"))))
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

    for index, outcome in enumerate(model.get("outcomes", [])):
        path = f"$model.outcomes[{index}]"
        if outcome.get("owner") not in layers:
            findings.append(Finding("DANGLING_REFERENCE", f"{path}.owner", str(outcome.get("owner"))))
        if outcome.get("status") not in statuses:
            findings.append(Finding("UNKNOWN_REGISTRY_VALUE", f"{path}.status", str(outcome.get("status"))))

    for index, invariant in enumerate(model.get("invariants", [])):
        path = f"$model.invariants[{index}]"
        if invariant.get("owner") not in layers:
            findings.append(Finding("DANGLING_REFERENCE", f"{path}.owner", str(invariant.get("owner"))))
        for reference in invariant.get("object_refs", []):
            if reference not in objects:
                findings.append(Finding("DANGLING_REFERENCE", f"{path}.object_refs", reference))
        evidence_registry = set(counterexamples) | set(sources)
        for reference in invariant.get("evidence_refs", []):
            if reference not in evidence_registry:
                findings.append(Finding("DANGLING_REFERENCE", f"{path}.evidence_refs", reference))

    for index, counterexample in enumerate(model.get("counterexamples", [])):
        for reference in counterexample.get("blocks", []):
            if reference not in blockers:
                findings.append(Finding("DANGLING_REFERENCE", f"$model.counterexamples[{index}].blocks", reference))

    findings.extend(_validate_blocker_dag(blockers))
    c03 = blockers.get("C0.3")
    if c03 is None or c03.get("status") != "NO_GO":
        findings.append(Finding("C03_GATE_MISSING", "$model.blockers.C0.3", "missing NO_GO blocker"))
    elif not REQUIRED_C03_DEPENDENCIES.issubset(set(c03.get("depends_on", []))):
        findings.append(Finding("C03_GATE_MISSING", "$model.blockers.C0.3.depends_on", "required blocker edge missing"))
    if blockers.get("C0.2k", {}).get("depends_on") != ["C0.2j"]:
        findings.append(Finding("C03_GATE_MISSING", "$model.blockers.C0.2k.depends_on", "must depend exactly on C0.2j"))
    if blockers.get("O-06c", {}).get("depends_on") != ["C0.2k"]:
        findings.append(Finding("C03_GATE_MISSING", "$model.blockers.O-06c.depends_on", "must depend exactly on C0.2k"))

    if not REQUIRED_COUNTEREXAMPLES.issubset(id_sets.get("counterexamples", set())):
        findings.append(Finding("REQUIRED_RECORD_MISSING", "$model.counterexamples", "required hostile witness missing"))
    if not REQUIRED_NON_CLAIMS.issubset(id_sets.get("non_claims", set())):
        findings.append(Finding("REQUIRED_RECORD_MISSING", "$model.non_claims", "required non-claim missing"))
    if not REQUIRED_REVIEW_QUERIES.issubset(id_sets.get("review_queries", set())):
        findings.append(Finding("REQUIRED_RECORD_MISSING", "$model.review_queries", "required review query missing"))

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
                findings.append(Finding("DANGLING_REFERENCE", f"$model.review_queries[{index}].record_refs", reference))

    for state_index, state_model in enumerate(model.get("state_models", [])):
        path = f"$model.state_models[{state_index}]"
        if state_model.get("owner") not in layers:
            findings.append(Finding("DANGLING_REFERENCE", f"{path}.owner", str(state_model.get("owner"))))
        states = set(state_model.get("states", []))
        for transition_index, transition in enumerate(state_model.get("transitions", [])):
            transition_path = f"{path}.transitions[{transition_index}]"
            for source_state in transition.get("from", []):
                if source_state not in states:
                    findings.append(Finding("DANGLING_REFERENCE", f"{transition_path}.from", source_state))
            if transition.get("to") not in states:
                findings.append(Finding("DANGLING_REFERENCE", f"{transition_path}.to", str(transition.get("to"))))
            if transition.get("outcome") not in outcomes:
                findings.append(Finding("DANGLING_REFERENCE", f"{transition_path}.outcome", str(transition.get("outcome"))))

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
