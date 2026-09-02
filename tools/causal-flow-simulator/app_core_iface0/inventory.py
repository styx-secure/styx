"""Derive and validate the closed APP-CORE-IFACE-0 evidence inventory."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator


BASE_SHA = "16274cc194cd2f8f7b631332687a252bad92ce02"
MANIFEST_SHA256 = "521abeea5d8ea294dde4ab29b1ebe999caa43e8fbf0bc26c4708d958f16e514c"
STRUCTURAL_COUNT = 1450
SEMANTIC_COUNT = 5147
TOTAL_COUNT = 6597
CONTRACT_FILES = 27


class InventoryError(ValueError):
    """The ratified contract or derived inventory is inconsistent."""


@dataclass(frozen=True)
class EvidenceInstance:
    instance_id: str
    family_id: str
    source: str
    perturbation_id: str
    assertion_id: str
    observation_id: str
    detector_id: str
    expected_disposition: str

    def as_dict(self) -> dict[str, str]:
        return {
            "assertion_id": self.assertion_id,
            "detector_id": self.detector_id,
            "expected_disposition": self.expected_disposition,
            "family_id": self.family_id,
            "instance_id": self.instance_id,
            "observation_id": self.observation_id,
            "perturbation_id": self.perturbation_id,
            "source": self.source,
        }


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_lines(values: Iterable[str]) -> str:
    material = "".join(value + "\n" for value in sorted(values)).encode("utf-8")
    return sha256_bytes(material)


def _load_json(path: Path) -> Any:
    if not path.is_file() or path.is_symlink():
        raise InventoryError(f"invalid contract artifact: {path.name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InventoryError(f"invalid JSON artifact: {path.name}") from error


def verify_contract_package(contract: Path) -> dict[str, Any]:
    """Verify the exact self-contained manifest-plus-26 package."""

    contract = contract.resolve()
    manifest_path = contract / "APP-CORE-IFACE-0-CANDIDATE-MANIFEST.json"
    if sha256_bytes(manifest_path.read_bytes()) != MANIFEST_SHA256:
        raise InventoryError("ratified manifest digest mismatch")
    manifest = _load_json(manifest_path)
    rows = manifest.get("artifacts")
    if not isinstance(rows, list) or len(rows) != 26:
        raise InventoryError("manifest must contain exactly 26 artifact rows")
    names = [row.get("path") for row in rows if isinstance(row, dict)]
    if len(names) != 26 or len(set(names)) != 26:
        raise InventoryError("manifest artifact names are not unique")
    expected = {manifest_path.name, *names}
    entries = list(contract.iterdir())
    actual = {entry.name for entry in entries}
    if actual != expected or len(entries) != CONTRACT_FILES:
        raise InventoryError("contract package file set mismatch")
    if any(not entry.is_file() or entry.is_symlink() for entry in entries):
        raise InventoryError("contract package contains a non-regular file")
    for row in rows:
        path = contract / row["path"]
        if sha256_bytes(path.read_bytes()) != row["sha256"]:
            raise InventoryError(f"contract artifact digest mismatch: {path.name}")
    return manifest


def run_ratified_package_validator(repo_root: Path, contract: Path) -> None:
    command = [
        sys.executable,
        str(contract / "validate_app_core_contract_candidates.py"),
        "--repository",
        str(repo_root),
        "--base-ref",
        BASE_SHA,
    ]
    completed = subprocess.run(
        command,
        cwd=repo_root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=120,
        env={**__import__("os").environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    if completed.returncode != 0 or "total=6597" not in completed.stdout:
        raise InventoryError("ratified contract validator failed")


def _escape_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def walk(value: Any, pointer: str = "") -> Iterator[tuple[str, Any]]:
    yield pointer, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, pointer + "/" + _escape_pointer(key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, pointer + "/" + str(index))


def _structural_sources(schema: dict[str, Any], rule: dict[str, Any]) -> list[str]:
    nodes = list(walk(schema))
    objects = [
        (pointer, node)
        for pointer, node in nodes
        if isinstance(node, dict)
        and node.get("additionalProperties") is False
        and isinstance(node.get("properties"), dict)
        and node["properties"]
    ]
    mode = rule["mode"]
    keyword_modes = {
        "PER_TYPE_OCCURRENCE": "type",
        "PER_REF_OCCURRENCE": "$ref",
        "PER_CONST_OCCURRENCE": "const",
        "PER_ENUM_OCCURRENCE": "enum",
        "PER_PATTERN_OCCURRENCE": "pattern",
        "PER_MIN_LENGTH_OCCURRENCE": "minLength",
        "PER_MAX_LENGTH_OCCURRENCE": "maxLength",
        "PER_MIN_ITEMS_OCCURRENCE": "minItems",
        "PER_MAX_ITEMS_OCCURRENCE": "maxItems",
        "PER_UNIQUE_ITEMS_TRUE_OCCURRENCE": "uniqueItems",
        "PER_ITEMS_OCCURRENCE": "items",
        "PER_NOT_OCCURRENCE": "not",
        "PER_MAX_PROPERTIES_OCCURRENCE": "maxProperties",
    }
    if mode == "PER_REQUIRED_PROPERTY_OF_PROPERTY_BEARING_OBJECT_SCHEMA":
        result = [
            f"{pointer}/required/{_escape_pointer(name)}"
            for pointer, node in objects
            for name in node.get("required", [])
        ]
    elif mode == "PER_DECLARED_PROPERTY":
        result = [
            f"{pointer}/properties/{_escape_pointer(name)}"
            for pointer, node in objects
            for name in node["properties"]
        ]
    elif mode == "PER_PROPERTY_BEARING_OBJECT_SCHEMA":
        result = [pointer for pointer, _ in objects]
    elif mode == "PER_ADDITIONAL_PROPERTIES_FALSE_OCCURRENCE":
        result = [
            f"{pointer}/additionalProperties"
            for pointer, node in nodes
            if isinstance(node, dict) and node.get("additionalProperties") is False
        ]
    elif mode in keyword_modes:
        keyword = keyword_modes[mode]
        result = [
            f"{pointer}/{_escape_pointer(keyword)}"
            for pointer, node in nodes
            if isinstance(node, dict)
            and keyword in node
            and (keyword != "uniqueItems" or node[keyword] is True)
        ]
    elif mode == "PER_ONE_OF_OCCURRENCE":
        result = [
            f"{pointer}/oneOf"
            for pointer, node in nodes
            if isinstance(node, dict) and isinstance(node.get("oneOf"), list)
        ]
    elif mode == "PER_ONE_OF_ARM":
        result = [
            f"{pointer}/oneOf#{index}"
            for pointer, node in nodes
            if isinstance(node, dict) and isinstance(node.get("oneOf"), list)
            for index in range(len(node["oneOf"]))
        ]
    elif mode == "PER_ANY_OF_OCCURRENCE":
        result = [
            f"{pointer}/anyOf"
            for pointer, node in nodes
            if isinstance(node, dict) and isinstance(node.get("anyOf"), list)
        ]
    elif mode == "PER_ANY_OF_ARM":
        result = [
            f"{pointer}/anyOf/{index}"
            for pointer, node in nodes
            if isinstance(node, dict) and isinstance(node.get("anyOf"), list)
            for index in range(len(node["anyOf"]))
        ]
    elif mode == "PER_ALL_OF_ARM":
        result = [
            f"{pointer}/allOf/{index}"
            for pointer, node in nodes
            if isinstance(node, dict) and isinstance(node.get("allOf"), list)
            for index in range(len(node["allOf"]))
        ]
    elif mode == "LITERAL_RELATION":
        result = list(rule["relation"])
    else:
        raise InventoryError(f"unknown structural derivation mode: {mode}")
    result = sorted(result)
    if len(result) != rule["expectedCount"] or len(result) != len(set(result)):
        raise InventoryError(f"structural source count drift: {rule['id']}")
    expected_digest = rule.get("sourceSetSha256")
    if expected_digest is not None and digest_lines(result) != expected_digest:
        raise InventoryError(f"structural source digest drift: {rule['id']}")
    return result


def expand_structural_instances(contract: Path) -> list[EvidenceInstance]:
    schema = _load_json(contract / "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json")
    registry = _load_json(
        contract / "APP-CORE-IFACE-0-STRUCTURAL-AXES-CANDIDATE.json"
    )
    rows: list[EvidenceInstance] = []
    for rule in registry["rules"]:
        sources = _structural_sources(schema, rule)
        suffix = rule["id"].removeprefix("STR-")
        for index, source in enumerate(sources, 1):
            disposition = rule["expectedDisposition"]
            if disposition == "FROM_RELATION_SUFFIX":
                if source.endswith("_ACCEPTS"):
                    disposition = "ACCEPT"
                elif source.endswith("_REJECTS"):
                    disposition = "REJECT"
                else:
                    raise InventoryError("conditional relation has no disposition suffix")
            serial = f"{index:04d}"
            rows.append(
                EvidenceInstance(
                    instance_id=f"{rule['id']}--{serial}",
                    family_id=rule["id"],
                    source=source,
                    perturbation_id=f"PRT-{suffix}--{serial}",
                    assertion_id=f"AST-{suffix}--{serial}",
                    observation_id=f"OBS-{suffix}--{serial}",
                    detector_id=f"DET-{suffix}--{serial}",
                    expected_disposition=disposition,
                )
            )
    if len(rows) != STRUCTURAL_COUNT or len({row.instance_id for row in rows}) != STRUCTURAL_COUNT:
        raise InventoryError("structural instance relation drift")
    return rows


def _semantic_axis_members(
    axis: dict[str, Any], semantic: dict[str, Any], contract: Path
) -> list[str]:
    schema = _load_json(contract / "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json")
    mode = axis["mode"]
    if mode in {"SINGLE", "SINGLE_RELATION"}:
        return ["SINGLE"]
    if mode == "PER_TARGET":
        targets = sorted(semantic["targets"])
        if len(targets) == axis["expectedCount"]:
            return targets
        if axis["id"] == "ACV-020":
            occurrences = sorted(
                occurrence
                for occurrence, owner in semantic["customKeywordCoverage"].items()
                if owner == axis["id"]
            )
            if len(occurrences) == axis["expectedCount"]:
                return occurrences
        raise InventoryError(f"PER_TARGET relation drift: {axis['id']}")
    if mode == "PER_LITERAL_VALUE":
        return list(axis["values"])
    if mode == "PER_LITERAL_RELATION_ROW":
        relation_name = axis["axisSources"][0].split("#", 1)[1]
        relations = _load_json(
            contract / "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json"
        )
        return [row["id"] for row in relations[relation_name]]
    if mode == "PER_OBJECT_SCHEMA_X_LITERAL_VALUE":
        reachability = _load_json(
            contract / "APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json"
        )
        pointers = sorted(row["objectSchemaPointer"] for row in reachability["objectCoverage"])
        return [f"{pointer}::{value}" for pointer in pointers for value in axis["values"]]
    if mode == "PER_CUSTOM_KEYWORD_OCCURRENCE_PLUS_UNKNOWN":
        coverage = sorted(semantic["customKeywordCoverage"])
        return [*coverage, "UNKNOWN_X_STYX_KEYWORD"]
    if mode == "PER_UNION_ARM":
        return _union_arm_members(schema, axis["axisSources"])
    if mode == "PER_RECURSIVE_TERMINAL_PATH":
        return _recursive_terminal_members(schema, axis["axisSources"])
    if mode == "PER_RESPONSE_STRING_PATH_X_PARAMETER_FAMILY":
        paths = _string_terminal_paths(schema, axis["axisSources"][0])
        if len(paths) != axis["pathCount"]:
            raise InventoryError("response string-path count drift")
        if digest_lines(paths) != axis["pathSha256"]:
            raise InventoryError("response string-path digest drift")
        families = semantic.get("parameters", {}).get("families")
        if not isinstance(families, list) or len(families) != axis["familyCount"]:
            raise InventoryError("response provenance-family drift")
        return [f"{path}::{family}" for path in paths for family in families]
    raise InventoryError(f"unknown semantic derivation mode: {mode}")


def _resolve_axis_source(
    schema: dict[str, Any], source: str
) -> tuple[dict[str, Any], tuple[str, ...]]:
    parts = source.split(".")
    definitions = schema.get("$defs")
    if not isinstance(definitions, dict) or parts[0] not in definitions:
        raise InventoryError(f"unknown semantic axis source: {source}")
    node = definitions[parts[0]]
    path = (parts[0],)
    for property_name in parts[1:]:
        properties = node.get("properties") if isinstance(node, dict) else None
        if not isinstance(properties, dict) or property_name not in properties:
            raise InventoryError(f"unknown semantic axis property: {source}")
        node = properties[property_name]
        path += (property_name,)
    if not isinstance(node, dict):
        raise InventoryError(f"invalid semantic axis source: {source}")
    return node, path


def _terminal_rows(
    schema: dict[str, Any],
    node: dict[str, Any],
    path: tuple[str, ...],
    stack: tuple[str, ...] = (),
) -> list[tuple[str, str]]:
    """Return unique terminal-schema-class/data-path pairs.

    A data field can have more than one terminal schema class through allOf
    (for example a canonical decimal string plus a maximum length).  The
    ratified recursive axes count those independently.  oneOf arms are labelled
    by definition and one bounded array element is labelled `*`.
    """

    if "$ref" in node:
        reference = node["$ref"]
        if not isinstance(reference, str) or not reference.startswith("#/$defs/"):
            raise InventoryError("semantic axis contains a non-local reference")
        name = reference.rsplit("/", 1)[-1]
        if name in stack:
            raise InventoryError(f"semantic axis schema cycle: {name}")
        definition = schema["$defs"].get(name)
        if not isinstance(definition, dict):
            raise InventoryError(f"unresolved semantic axis reference: {name}")
        return _terminal_rows(schema, definition, path, stack + (name,))
    if "allOf" in node:
        arms = node["allOf"]
        if not isinstance(arms, list) or not arms:
            raise InventoryError("invalid allOf in semantic axis")
        return [
            row
            for arm in arms
            for row in _terminal_rows(schema, arm, path, stack)
        ]
    if "oneOf" in node:
        arms = node["oneOf"]
        if not isinstance(arms, list) or not arms:
            raise InventoryError("invalid oneOf in semantic axis")
        result: list[tuple[str, str]] = []
        for index, arm in enumerate(arms):
            if not isinstance(arm, dict):
                raise InventoryError("invalid oneOf arm in semantic axis")
            reference = arm.get("$ref")
            label = reference.rsplit("/", 1)[-1] if isinstance(reference, str) else str(index)
            result.extend(
                _terminal_rows(schema, arm, path + (f"<{label}>",), stack)
            )
        return result
    properties = node.get("properties")
    if node.get("type") == "object" or isinstance(properties, dict):
        if properties is None and node.get("type") == "object":
            return []
        if not isinstance(properties, dict):
            raise InventoryError("object semantic axis has invalid properties")
        return [
            row
            for name, child in properties.items()
            for row in _terminal_rows(schema, child, path + (name,), stack)
        ]
    if node.get("type") == "array":
        items = node.get("items")
        if not isinstance(items, dict):
            raise InventoryError("array semantic axis has no item schema")
        return _terminal_rows(schema, items, path + ("*",), stack)
    terminal_class = node.get("type")
    if not isinstance(terminal_class, str):
        terminal_class = (
            "string" if {"enum", "const", "pattern"}.intersection(node) else "constraint"
        )
    return [(terminal_class, "/".join(path))]


def _recursive_terminal_members(
    schema: dict[str, Any], sources: list[str]
) -> list[str]:
    rows: set[tuple[str, str]] = set()
    for source in sources:
        node, path = _resolve_axis_source(schema, source)
        rows.update(_terminal_rows(schema, node, path))
    return [f"{terminal_class}\t{path}" for terminal_class, path in sorted(rows)]


def _string_terminal_paths(schema: dict[str, Any], source: str) -> list[str]:
    node, path = _resolve_axis_source(schema, source)
    return sorted(
        {
            data_path
            for terminal_class, data_path in _terminal_rows(schema, node, path)
            if terminal_class == "string"
        }
    )


def _union_arm_members(schema: dict[str, Any], sources: list[str]) -> list[str]:
    members: list[str] = []
    for source in sources:
        node, _ = _resolve_axis_source(schema, source)
        arms = node.get("oneOf")
        if not isinstance(arms, list) or not arms:
            raise InventoryError(f"semantic union axis is not oneOf: {source}")
        for index, arm in enumerate(arms):
            if not isinstance(arm, dict):
                raise InventoryError(f"invalid semantic union arm: {source}")
            reference = arm.get("$ref")
            label = reference.rsplit("/", 1)[-1] if isinstance(reference, str) else str(index)
            members.append(f"{source}::<{label}>")
    return sorted(members)


def expand_semantic_instances(contract: Path) -> list[EvidenceInstance]:
    semantics = _load_json(
        contract / "APP-CORE-IFACE-0-SEMANTIC-CONSTRAINTS-CANDIDATE.json"
    )
    axes = _load_json(contract / "APP-CORE-IFACE-0-INSTANCE-AXES-CANDIDATE.json")
    semantic_by_id = {row["id"]: row for row in semantics["rules"]}
    rows: list[EvidenceInstance] = []
    for axis in axes["rules"]:
        semantic = {
            **semantic_by_id[axis["id"]],
            "customKeywordCoverage": semantics["customKeywordCoverage"],
        }
        members = _semantic_axis_members(axis, semantic, contract)
        if len(members) != axis["expectedCount"] or len(members) != len(set(members)):
            raise InventoryError(f"semantic axis drift: {axis['id']}")
        for index, member in enumerate(members, 1):
            serial = f"{index:04d}"
            rows.append(
                EvidenceInstance(
                    instance_id=f"SEM-{axis['id']}--{serial}",
                    family_id=axis["id"],
                    source=member,
                    perturbation_id=f"PRT-{axis['id']}--{serial}",
                    assertion_id=f"AST-{axis['id']}--{serial}",
                    observation_id=f"OBS-{axis['id']}--{serial}",
                    detector_id=f"DET-{axis['id']}--{serial}",
                    expected_disposition="PASS",
                )
            )
    if len(rows) != SEMANTIC_COUNT or len({row.instance_id for row in rows}) != SEMANTIC_COUNT:
        raise InventoryError("semantic instance relation drift")
    return rows


def build_inventory(repo_root: Path, contract: Path) -> dict[str, Any]:
    verify_contract_package(contract)
    run_ratified_package_validator(repo_root, contract)
    structural = expand_structural_instances(contract)
    semantic = expand_semantic_instances(contract)
    all_ids = [row.instance_id for row in (*structural, *semantic)]
    if len(all_ids) != TOTAL_COUNT or len(set(all_ids)) != TOTAL_COUNT:
        raise InventoryError("combined hostile instance relation drift")
    return {
        "combined_instance_set_sha256": digest_lines(all_ids),
        "contract_manifest_sha256": MANIFEST_SHA256,
        "family_counts": {"semantic": 82, "structural": 24},
        "instance_counts": {
            "semantic": SEMANTIC_COUNT,
            "structural": STRUCTURAL_COUNT,
            "total": TOTAL_COUNT,
        },
        "schema": "styx.app-core-iface0.inventory-report.v1",
        "semantic_instance_set_sha256": digest_lines(row.instance_id for row in semantic),
        "structural_instance_set_sha256": digest_lines(row.instance_id for row in structural),
        "verdict": "PASS",
    }
