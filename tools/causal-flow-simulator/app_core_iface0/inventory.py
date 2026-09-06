"""Derive and validate the closed APP-CORE-IFACE-0 evidence inventory."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator


BASE_SHA = "e0af4e1e2173deb2481eabdb24d8622282b33455"
MANIFEST_SHA256 = "15d75531e1fff1ff751754585561f68254a6657e4de40ff69c3a4678d1ba7cf2"
STRUCTURAL_COUNT = 1553
SEMANTIC_COUNT = 2359
TOTAL_COUNT = 3912
CONTRACT_FILES = 28
ACV049_RELATION_COUNTS = {
    "ACV-049-L": 401,
    "ACV-049-P": 300,
    "ACV-049-S": 101,
    "ACV-049-N": 5,
    "ACV-049-E": 77,
}
ACV049_RELATION_COUNT = 884
ACV049_LITERAL_FAMILIES = (
    "PATH",
    "HOST",
    "USER",
    "PID",
    "TIMESTAMP",
    "DURATION",
    "ELAPSED",
    "ENVIRONMENT",
    "EXCEPTION",
    "STACK",
)
ACV049_REQUEST_CASE_IDS = tuple(
    sorted(
        (
            *(f"PCR-REQUEST-DESCRIBE-PROFILE-{index:04d}" for index in range(1, 3)),
            *(f"PCR-REQUEST-EVALUATE-CANDIDATE-{index:04d}" for index in range(1, 27)),
            *(f"PCR-REQUEST-EVALUATE-EVIDENCE-UPDATE-{index:04d}" for index in range(1, 30)),
            *(f"PCR-REQUEST-EVALUATE-GENESIS-{index:04d}" for index in range(1, 5)),
            *(f"PCR-REQUEST-REPLAY-CONTEXT-{index:04d}" for index in range(1, 12)),
            *(f"PCR-REQUEST-VALIDATE-TRANSCRIPT-{index:04d}" for index in range(1, 6)),
        ),
        key=lambda value: value.encode("utf-8"),
    )
)


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


@dataclass(frozen=True)
class LogicalTerminal:
    """One definition-qualified response leaf and its effective constraints."""

    data_tokens: tuple[str | int, ...]
    nodes: tuple[dict[str, Any], ...]
    node_pointers: tuple[str, ...]
    branches: tuple[tuple[tuple[str | int, ...], dict[str, Any]], ...]


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
    """Verify the exact self-contained manifest-plus-27 package."""

    contract = contract.resolve()
    manifest_path = contract / "APP-CORE-IFACE-0-CANDIDATE-MANIFEST.json"
    if sha256_bytes(manifest_path.read_bytes()) != MANIFEST_SHA256:
        raise InventoryError("ratified manifest digest mismatch")
    manifest = _load_json(manifest_path)
    rows = manifest.get("artifacts")
    if not isinstance(rows, list) or len(rows) != 27:
        raise InventoryError("manifest must contain exactly 27 artifact rows")
    names = [row.get("path") for row in rows if isinstance(row, dict)]
    if len(names) != 27 or len(set(names)) != 27:
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
    if completed.returncode != 0 or "total=3912" not in completed.stdout:
        raise InventoryError("ratified contract validator failed")


def _escape_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _unescape_pointer(value: str) -> str:
    return value.replace("~1", "/").replace("~0", "~")


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
    acv049_relation_by_mode = {
        "PER_RESPONSE_STRING_PATH_WITH_FAMILY_VECTOR": "ACV-049-L",
        "PER_MUTABLE_RESPONSE_STRING_PATH": "ACV-049-P",
        "PER_SINGLETON_RESPONSE_STRING_PATH": "ACV-049-S",
        "PER_NON_STRING_HISTORICAL_RESPONSE_PATH": "ACV-049-N",
        "PER_RATIFIED_REQUEST_CARRIER": "ACV-049-E",
    }
    relation_id = acv049_relation_by_mode.get(mode)
    if relation_id is not None:
        if axis.get("id") != relation_id or axis.get("semanticRuleId") != "ACV-049":
            raise InventoryError("ACV-049 relation identity drift")
        members = derive_acv049_relation_members(contract)[relation_id]
        if len(members) != axis.get("expectedCount"):
            raise InventoryError(f"{relation_id} axis count drift")
        if digest_lines(members) != axis.get("memberSetSha256"):
            raise InventoryError(f"{relation_id} axis digest drift")
        if relation_id == "ACV-049-L" and axis.get("literalFamilyVector") != list(
            ACV049_LITERAL_FAMILIES
        ):
            raise InventoryError("ACV-049-L family vector drift")
        return members
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


def resolve_logical_terminal(schema: dict[str, Any], source: str) -> LogicalTerminal:
    """Resolve one definition-qualified logical path exactly once.

    Unlike ``_terminal_rows``, this retains every effective ``allOf``
    constraint and the selected ``oneOf`` branches. ACV-049 needs that
    information to distinguish actual string leaves from historical
    constant-array leaves and singleton string domains from mutable domains.
    """

    parts = source.split("/")
    if not parts or parts[0] != "InterfaceResponseV0":
        raise InventoryError("ACV-049 logical path root drift")
    definitions = schema.get("$defs")
    if not isinstance(definitions, dict):
        raise InventoryError("interface definitions are absent")

    def walk(
        node: Any,
        pointer: str,
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
                raise InventoryError("ACV-049 contains a non-local reference")
            name = _unescape_pointer(reference.rsplit("/", 1)[-1])
            if name in stack or not isinstance(definitions.get(name), dict):
                raise InventoryError("ACV-049 reference is cyclic or absent")
            return walk(
                definitions[name], f"/$defs/{_escape_pointer(name)}", remaining,
                data_tokens, branches, stack + (name,)
            )
        all_of = node.get("allOf")
        if isinstance(all_of, list):
            results = [
                result
                for index, arm in enumerate(all_of)
                for result in walk(
                    arm, f"{pointer}/allOf/{index}", remaining, data_tokens,
                    branches, stack,
                )
            ]
            if not results:
                return []
            first = results[0]
            if any(
                row.data_tokens != first.data_tokens or row.branches != first.branches
                for row in results[1:]
            ):
                raise InventoryError("ACV-049 allOf logical path is ambiguous")
            return [
                LogicalTerminal(
                    first.data_tokens,
                    tuple(item for row in results for item in row.nodes),
                    tuple(item for row in results for item in row.node_pointers),
                    first.branches,
                )
            ]
        one_of = node.get("oneOf")
        if isinstance(one_of, list):
            if not remaining:
                return []
            label = remaining[0]
            matches: list[tuple[int, dict[str, Any]]] = []
            for index, arm in enumerate(one_of):
                if not isinstance(arm, dict):
                    continue
                arm_reference = arm.get("$ref")
                arm_label = (
                    arm_reference.rsplit("/", 1)[-1]
                    if isinstance(arm_reference, str)
                    else str(index)
                )
                if label == f"<{arm_label}>":
                    matches.append((index, arm))
            if len(matches) != 1:
                raise InventoryError("ACV-049 oneOf label is ambiguous")
            selected_index, selected = matches[0]
            return walk(
                selected,
                f"{pointer}/oneOf/{selected_index}",
                remaining[1:],
                data_tokens,
                branches + ((data_tokens, selected),),
                stack,
            )
        properties = node.get("properties")
        if isinstance(properties, dict):
            if not remaining or remaining[0] not in properties:
                return []
            name = remaining[0]
            return walk(
                properties[name],
                f"{pointer}/properties/{_escape_pointer(name)}",
                remaining[1:],
                data_tokens + (name,),
                branches,
                stack,
            )
        if node.get("type") == "array":
            if not remaining or remaining[0] != "*":
                return []
            return walk(
                node.get("items"),
                f"{pointer}/items",
                remaining[1:],
                data_tokens + (0,),
                branches,
                stack,
            )
        if remaining:
            return []
        return [LogicalTerminal(data_tokens, (node,), (pointer,), branches)]

    results = walk(
        definitions["InterfaceResponseV0"],
        "/$defs/InterfaceResponseV0",
        tuple(parts[1:]),
        (),
        (),
        ("InterfaceResponseV0",),
    )
    if len(results) != 1:
        raise InventoryError("ACV-049 logical path does not resolve exactly once")
    return results[0]


def is_string_terminal(nodes: tuple[dict[str, Any], ...]) -> bool:
    """Return whether the effective leaf domain is string-valued."""

    for node in nodes:
        if node.get("type") == "string" or isinstance(node.get("const"), str):
            return True
        enum = node.get("enum")
        if isinstance(enum, list) and enum and all(isinstance(item, str) for item in enum):
            return True
    return False


def derive_acv049_path_partition(contract: Path) -> dict[str, list[str]]:
    """Derive the ratified ACV-049 L/P/S/N path partition from the schema."""

    schema = _load_json(contract / "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json")
    logical = _string_terminal_paths(schema, "InterfaceResponseV0")
    terminals = {path: resolve_logical_terminal(schema, path) for path in logical}
    strings = [path for path in logical if is_string_terminal(terminals[path].nodes)]
    singleton = [
        path
        for path in strings
        if any(isinstance(node.get("const"), str) for node in terminals[path].nodes)
    ]
    singleton_set = set(singleton)
    string_set = set(strings)
    mutable = [path for path in strings if path not in singleton_set]
    non_string = [path for path in logical if path not in string_set]
    result = {
        "logical": logical,
        "literal": strings,
        "mutable": mutable,
        "singleton": singleton,
        "non_string": non_string,
    }
    expected = {
        "logical": (406, "cdd2f3f325800fffd08b23c08ab51d3b3ba6a3eb949af10ad488d72a854e5fe4"),
        "literal": (401, "253048d2193a1d37cd51d9505409b7b1ad943333ad0993cb22c09cc9e6986419"),
        "mutable": (300, "beee0c5b76943e52a0e55d7420f952b759e0732be06e4071c34d5d370d4a0c21"),
        "singleton": (101, "50c380ce5b29a7158774fd11daf93675428cc6c56c3b7832a23aa050063856fe"),
        "non_string": (5, "ff6a882b2805320261707316f8a3c354806b27fc042c5f64d6dafedb47e2d509"),
    }
    for relation, (count, digest) in expected.items():
        members = result[relation]
        if len(members) != count or len(set(members)) != count:
            raise InventoryError(f"ACV-049 {relation} path count drift")
        if digest_lines(members) != digest:
            raise InventoryError(f"ACV-049 {relation} path digest drift")
    if set(mutable) & set(singleton) or set(mutable) | set(singleton) != string_set:
        raise InventoryError("ACV-049 string-domain partition drift")
    return result


def derive_acv049_relation_members(contract: Path) -> dict[str, list[str]]:
    """Derive all five ratified replacement relations and their exact sets."""

    paths = derive_acv049_path_partition(contract)
    relations = {
        "ACV-049-L": paths["literal"],
        "ACV-049-P": paths["mutable"],
        "ACV-049-S": paths["singleton"],
        "ACV-049-N": paths["non_string"],
        "ACV-049-E": list(ACV049_REQUEST_CASE_IDS),
    }
    if len(ACV049_REQUEST_CASE_IDS) != 77 or digest_lines(ACV049_REQUEST_CASE_IDS) != (
        "8233dd1a8172383e4679780474910b468139baeb4df028ecadc18f1fa83ecb8f"
    ):
        raise InventoryError("ACV-049 ratified request-carrier identity drift")
    for relation_id, expected_count in ACV049_RELATION_COUNTS.items():
        members = relations[relation_id]
        if len(members) != expected_count or len(set(members)) != expected_count:
            raise InventoryError(f"{relation_id} relation count or uniqueness drift")
    if sum(len(members) for members in relations.values()) != ACV049_RELATION_COUNT:
        raise InventoryError("ACV-049 replacement relation total drift")
    return relations


def expand_acv049_replacement_instances(contract: Path) -> list[EvidenceInstance]:
    """Expand the five ACV-049 relations without Cartesian family inflation."""

    relations = derive_acv049_relation_members(contract)
    rows: list[EvidenceInstance] = []
    for relation_id in (
        "ACV-049-L",
        "ACV-049-P",
        "ACV-049-S",
        "ACV-049-N",
        "ACV-049-E",
    ):
        for index, member in enumerate(relations[relation_id], 1):
            serial = f"{index:04d}"
            rows.append(
                EvidenceInstance(
                    instance_id=f"SEM-{relation_id}--{serial}",
                    family_id=relation_id,
                    source=member,
                    perturbation_id=f"PRT-{relation_id}--{serial}",
                    assertion_id=f"AST-{relation_id}--{serial}",
                    observation_id=f"OBS-{relation_id}--{serial}",
                    detector_id=f"DET-{relation_id}--{serial}",
                    expected_disposition="PASS",
                )
            )
    if len(rows) != ACV049_RELATION_COUNT or len(
        {row.instance_id for row in rows}
    ) != ACV049_RELATION_COUNT:
        raise InventoryError("ACV-049 replacement instance relation drift")
    return rows


def derive_acv049_old_to_new_reconciliation(
    contract: Path,
) -> list[dict[str, str]]:
    """Retire every historical path-by-family ID into its literal/N owner."""

    partition = derive_acv049_path_partition(contract)
    literal_index = {path: index for index, path in enumerate(partition["literal"], 1)}
    non_string_index = {
        path: index for index, path in enumerate(partition["non_string"], 1)
    }
    rows: list[dict[str, str]] = []
    serial = 0
    for path in partition["logical"]:
        relation_id = "ACV-049-L" if path in literal_index else "ACV-049-N"
        relation_index = (
            literal_index[path] if relation_id == "ACV-049-L" else non_string_index[path]
        )
        replacement_id = f"SEM-{relation_id}--{relation_index:04d}"
        for family in ACV049_LITERAL_FAMILIES:
            serial += 1
            rows.append(
                {
                    "historicalInstanceId": f"SEM-ACV-049--{serial:04d}",
                    "historicalLiteralFamily": family,
                    "logicalPath": path,
                    "replacementInstanceId": replacement_id,
                }
            )
    if serial != 4060 or len(
        {row["historicalInstanceId"] for row in rows}
    ) != 4060:
        raise InventoryError("ACV-049 historical reconciliation drift")
    replacement_counts: dict[str, int] = {}
    for row in rows:
        replacement = row["replacementInstanceId"]
        replacement_counts[replacement] = replacement_counts.get(replacement, 0) + 1
    if len(replacement_counts) != 406 or set(replacement_counts.values()) != {10}:
        raise InventoryError("ACV-049 reconciliation fan-in drift")
    return rows


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
        semantic_id = axis.get("semanticRuleId", axis["id"])
        semantic = {
            **semantic_by_id[semantic_id],
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


def _semantic_reachability_by_row(contract: Path) -> dict[str, str]:
    relations = _load_json(
        contract / "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json"
    )
    result: dict[str, str] = {}
    for relation in relations.values():
        if not isinstance(relation, list):
            continue
        for row in relation:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str):
                continue
            reachability = row.get("reachability")
            nested = row.get("result")
            if reachability is None and isinstance(nested, dict):
                reachability = nested.get("reachability")
            if reachability not in {"REACHABLE", "RESERVED_UNREACHABLE_V0"}:
                continue
            previous = result.setdefault(row["id"], reachability)
            if previous != reachability:
                raise InventoryError("semantic relation reachability conflicts")
    return result


def derive_semantic_execution_relation(
    contract: Path,
    seed_registry: dict[str, Any],
    *,
    acv049_materialized_paths: Iterable[str] | None = None,
) -> list[dict[str, str]]:
    """Bind every semantic instance to its closed execution phase.

    Only ACV-048 depends on the populated seed registry; every other override
    is frozen by the execution-phase and semantic-relation artifacts.
    """

    phases = _load_json(
        contract / "APP-CORE-IFACE-0-EXECUTION-PHASES-CANDIDATE.json"
    )
    overrides = {row["id"]: row for row in phases["overrides"]}
    if len(overrides) != len(phases["overrides"]):
        raise InventoryError("semantic execution override IDs are duplicated")
    seed_rows = seed_registry.get("rows")
    if not isinstance(seed_rows, list) or len(seed_rows) != 87:
        raise InventoryError("semantic phase derivation requires 87 seed rows")
    direction_by_pointer: dict[str, str] = {}
    for row in seed_rows:
        if not isinstance(row, dict):
            raise InventoryError("semantic phase seed row is malformed")
        pointer = row.get("objectSchemaPointer")
        direction = row.get("carrierDirection")
        if (
            not isinstance(pointer, str)
            or direction not in {"REQUEST", "RESPONSE"}
            or pointer in direction_by_pointer
        ):
            raise InventoryError("semantic phase seed partition drift")
        direction_by_pointer[pointer] = direction
    reachability = _semantic_reachability_by_row(contract)
    materialized = set(acv049_materialized_paths or ())
    if "ACV-049-L" in overrides:
        partition = derive_acv049_path_partition(contract)
        mutable_materialized = sorted(materialized & set(partition["mutable"]))
        singleton_materialized = sorted(materialized & set(partition["singleton"]))
        if (
            len(materialized) != 321
            or len(mutable_materialized) != 228
            or len(singleton_materialized) != 93
            or materialized - set(partition["literal"])
            or digest_lines(mutable_materialized)
            != "47756a4adf5eaa79589f21c4b443e8f273e94efc4c798bace194cb9e1fe611de"
            or digest_lines(singleton_materialized)
            != "6f06ee47fe0950fec29462ab849d46d7928ee7ff85de4829829731b82839c77a"
        ):
            raise InventoryError("ACV-049 materialized phase partition drift")

    rows: list[dict[str, str]] = []
    for instance in expand_semantic_instances(contract):
        override = overrides.get(instance.family_id)
        phase = phases["defaultPhase"]
        if override is not None:
            partition = override["partition"]
            if partition == "ALL_INSTANCES":
                phase = override["phase"]
            elif partition == "BY_AXIS_SOURCE_ROOT":
                source_root = instance.source.split("::", 1)[0]
                matches = [
                    row["phase"]
                    for row in override["relation"]
                    if row["axisSource"] == source_root
                ]
                if len(matches) != 1:
                    raise InventoryError("semantic axis-source phase is ambiguous")
                phase = matches[0]
            elif partition == "BY_RELATION_ROW_REACHABILITY":
                state = reachability.get(instance.source)
                matches = [
                    row["phase"]
                    for row in override["relation"]
                    if row["reachability"] == state
                ]
                if len(matches) != 1:
                    raise InventoryError("semantic reachability phase is ambiguous")
                phase = matches[0]
            elif partition == "BY_SEED_CARRIER_DIRECTION_X_LITERAL_VALUE":
                pointer = instance.source.split("::", 1)[0]
                direction = direction_by_pointer.get(pointer)
                if direction == "REQUEST":
                    phase = override["requestCarrierPhase"]
                elif direction == "RESPONSE":
                    phase = override["responseCarrierPhase"]
                else:
                    raise InventoryError("ACV-048 seed direction is absent")
            elif partition == "BY_PHASE_A_MATERIALIZATION":
                phase = (
                    override["materializedPhase"]
                    if instance.source in materialized
                    else override["unmaterializedPhase"]
                )
            else:
                raise InventoryError(f"unknown semantic phase partition: {partition}")
        if phase not in phases["phaseRegistry"]:
            raise InventoryError("semantic execution phase is outside registry")
        rows.append(
            {
                "assertionId": instance.assertion_id,
                "detectorId": instance.detector_id,
                "executionPhase": phase,
                "instanceId": instance.instance_id,
                "mutationId": instance.perturbation_id.replace("PRT-", "MUT-", 1),
                "observationId": instance.observation_id,
                "semanticRuleId": instance.family_id,
                "sourceIdentity": instance.source,
            }
        )
    if (
        len(rows) != SEMANTIC_COUNT
        or len({row["instanceId"] for row in rows}) != SEMANTIC_COUNT
    ):
        raise InventoryError("semantic execution phase relation drift")
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
        "family_counts": {"semantic": 84, "structural": 24},
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
