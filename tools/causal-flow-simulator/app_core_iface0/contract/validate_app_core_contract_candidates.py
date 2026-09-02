#!/usr/bin/env python3
"""Fail-closed validation of the APP-CORE-IFACE-0 planning package.

This tool validates candidate evidence only. It grants no protocol, adapter,
repository or product authority.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import subprocess
from pathlib import Path
from typing import Any, Iterable

from jsonschema.validators import Draft202012Validator


ROOT = Path(__file__).resolve().parent


def require(ok: bool, message: str) -> None:
    if not ok:
        raise SystemExit(message)


def load(name: str) -> Any:
    path = ROOT / name
    require(path.is_file() and not path.is_symlink(), f"invalid artifact: {name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid JSON {name}: {exc}") from exc


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest_lines(values: Iterable[str]) -> str:
    material = "".join(value + "\n" for value in sorted(values)).encode()
    return hashlib.sha256(material).hexdigest()


def escape_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def walk(value: Any, pointer: str = "") -> Iterable[tuple[str, Any]]:
    yield pointer, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, pointer + "/" + escape_pointer(key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, pointer + "/" + str(index))


def resolve(schema: dict[str, Any], reference: str) -> Any:
    require(reference.startswith("#/"), f"remote or invalid reference: {reference}")
    current: Any = schema
    for encoded in reference[2:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        require(isinstance(current, dict) and token in current, f"unresolved ref: {reference}")
        current = current[token]
    return current


def terminal_rows(
    schema: dict[str, Any],
    node: dict[str, Any],
    path: tuple[str, ...],
    stack: tuple[str, ...] = (),
) -> list[tuple[str, str]]:
    """Derive terminal-schema-class/data-path rows from one schema node."""

    if "$ref" in node:
        reference = node["$ref"]
        require(
            isinstance(reference, str) and reference.startswith("#/$defs/"),
            f"non-local terminal-path reference: {reference}",
        )
        name = reference.rsplit("/", 1)[-1]
        require(name not in stack, f"terminal-path schema cycle: {name}")
        definition = schema["$defs"].get(name)
        require(isinstance(definition, dict), f"unresolved terminal-path ref: {name}")
        return terminal_rows(schema, definition, path, stack + (name,))
    if "allOf" in node:
        arms = node["allOf"]
        require(isinstance(arms, list) and arms, "invalid terminal-path allOf")
        return [
            row
            for arm in arms
            for row in terminal_rows(schema, arm, path, stack)
        ]
    if "oneOf" in node:
        arms = node["oneOf"]
        require(isinstance(arms, list) and arms, "invalid terminal-path oneOf")
        result: list[tuple[str, str]] = []
        for index, arm in enumerate(arms):
            require(isinstance(arm, dict), "invalid terminal-path oneOf arm")
            reference = arm.get("$ref")
            label = (
                reference.rsplit("/", 1)[-1]
                if isinstance(reference, str)
                else str(index)
            )
            result.extend(
                terminal_rows(schema, arm, path + (f"<{label}>",), stack)
            )
        return result
    properties = node.get("properties")
    if node.get("type") == "object" or isinstance(properties, dict):
        if properties is None and node.get("type") == "object":
            return []
        require(isinstance(properties, dict), "invalid terminal-path properties")
        return [
            row
            for name, child in properties.items()
            for row in terminal_rows(schema, child, path + (name,), stack)
        ]
    if node.get("type") == "array":
        items = node.get("items")
        require(isinstance(items, dict), "invalid terminal-path items")
        return terminal_rows(schema, items, path + ("*",), stack)
    terminal_class = node.get("type")
    if not isinstance(terminal_class, str):
        terminal_class = (
            "string"
            if {"enum", "const", "pattern"}.intersection(node)
            else "constraint"
        )
    return [(terminal_class, "/".join(path))]


def validate_terminal_path_bindings(
    schema: dict[str, Any], axes: dict[str, Any]
) -> None:
    """Bind path counts/digests to the exact packaged schema, not prose counts."""

    derived: dict[str, tuple[int, list[str], str]] = {}
    for root in ("InterfaceRequestV0", "InterfaceResponseV0"):
        rows = set(
            terminal_rows(
                schema,
                {"$ref": f"#/$defs/{root}"},
                (root,),
            )
        )
        string_paths = sorted(path for terminal_class, path in rows if terminal_class == "string")
        derived[root] = (
            len(rows),
            string_paths,
            digest_lines(string_paths),
        )

    acv049 = next((row for row in axes["rules"] if row["id"] == "ACV-049"), None)
    require(isinstance(acv049, dict), "missing ACV-049 path binding")
    response_all, response_strings, response_digest = derived["InterfaceResponseV0"]
    require(
        acv049.get("axisSources") == ["InterfaceResponseV0"]
        and acv049.get("pathCount") == len(response_strings)
        and acv049.get("pathSha256") == response_digest
        and acv049.get("familyCount") == 10
        and acv049.get("expectedCount") == len(response_strings) * 10,
        "ACV-049 response path binding drift",
    )

    atom = (ROOT / "APP-CORE-IFACE-0-ATOM-DERIVATION-CANDIDATE.md").read_text(
        encoding="utf-8"
    )
    request_all, request_strings, request_digest = derived["InterfaceRequestV0"]
    rows = (
        f"| `InterfaceRequestV0` | {request_all} | {len(request_strings)} | `{request_digest}` |",
        f"| `InterfaceResponseV0` | {response_all} | {len(response_strings)} | `{response_digest}` |",
    )
    for row in rows:
        require(atom.count(row) == 1, "documented terminal-path binding drift")


def definition_graph(schema: dict[str, Any]) -> dict[str, set[str]]:
    graph = {name: set() for name in schema["$defs"]}
    for name, definition in schema["$defs"].items():
        for _, node in walk(definition):
            if isinstance(node, dict) and isinstance(node.get("$ref"), str):
                reference = node["$ref"]
                resolve(schema, reference)
                if reference.startswith("#/$defs/"):
                    target = reference.split("/", 2)[2]
                    require(target in graph, f"unknown definition ref: {reference}")
                    graph[name].add(target)
    return graph


def validate_definition_closure(schema: dict[str, Any]) -> set[str]:
    graph = definition_graph(schema)
    permanent: set[str] = set()
    temporary: set[str] = set()

    def visit(name: str) -> None:
        require(name not in temporary, f"schema definition cycle: {name}")
        if name in permanent:
            return
        temporary.add(name)
        for target in sorted(graph[name]):
            visit(target)
        temporary.remove(name)
        permanent.add(name)

    for root in ("InterfaceRequestV0", "InterfaceResponseV0"):
        require(root in graph, f"missing public root: {root}")
        visit(root)
    require(permanent == set(graph), f"dead definitions: {sorted(set(graph) - permanent)}")
    return permanent


def validate_ownership(
    schema: dict[str, Any], objects: list[tuple[str, dict[str, Any]]]
) -> None:
    registry = load("APP-CORE-IFACE-0-OWNERSHIP-CANDIDATE.json")
    owner_tokens = set(registry["ownerTokens"])
    source_tokens = set(registry["sourceTokens"])
    direct = {
        pointer.split("/", 2)[2]: node
        for pointer, node in objects
        if pointer.startswith("/$defs/") and pointer.count("/") == 2
    }
    inline = {
        pointer: node
        for pointer, node in objects
        if not (pointer.startswith("/$defs/") and pointer.count("/") == 2)
    }
    require(len(direct) == 73 and len(inline) == 5, "object partition drift")
    require(set(registry["definitions"]) == set(direct), "definition ownership drift")
    require(set(registry["inlineObjects"]) == set(inline), "inline ownership drift")
    covered = 0
    for key, node in itertools.chain(direct.items(), inline.items()):
        entry = (
            registry["definitions"][key]
            if key in direct
            else registry["inlineObjects"][key]
        )
        require(set(entry["owners"]) <= owner_tokens and entry["owners"], f"owner drift: {key}")
        require(entry["source"] in source_tokens, f"source drift: {key}")
        overrides = entry.get("overrides", {})
        require(set(overrides) <= set(node["properties"]), f"unknown override: {key}")
        for property_name in node["properties"]:
            selected = overrides.get(property_name, entry)
            require(set(selected["owners"]) <= owner_tokens and selected["owners"], f"owner drift: {key}.{property_name}")
            require(selected["source"] in source_tokens, f"source drift: {key}.{property_name}")
            covered += 1
    require(covered == 323, f"ownership coverage drift: {covered}")


def validate_schema_and_relations(repository: Path, base_ref: str) -> None:
    schema_name = "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json"
    schema = load(schema_name)
    for name in (
        schema_name,
        "APP-CORE-IFACE-0-SEED-REGISTRY-SCHEMA-CANDIDATE.json",
        "APP-CORE-IFACE-0-POSITIVE-CARRIER-INVENTORY-SCHEMA-CANDIDATE.json",
        "APP-CORE-IFACE-0-STRUCTURAL-WITNESS-SCHEMA-CANDIDATE.json",
    ):
        Draft202012Validator.check_schema(load(name))

    nodes = list(walk(schema))
    references = [node["$ref"] for _, node in nodes if isinstance(node, dict) and "$ref" in node]
    require(len(references) == 263, f"ref count drift: {len(references)}")
    for reference in references:
        resolve(schema, reference)
    definitions = validate_definition_closure(schema)
    require(len(definitions) == 114, f"definition count drift: {len(definitions)}")

    enums = [pointer for pointer, node in nodes if isinstance(node, dict) and "enum" in node]
    one_ofs = [
        (pointer + "/oneOf", node["oneOf"])
        for pointer, node in nodes
        if isinstance(node, dict) and isinstance(node.get("oneOf"), list)
    ]
    objects = [
        (pointer, node)
        for pointer, node in nodes
        if isinstance(node, dict)
        and node.get("additionalProperties") is False
        and isinstance(node.get("properties"), dict)
        and node["properties"]
    ]
    require(len(enums) == 35, f"enum count drift: {len(enums)}")
    require(len(one_ofs) == 16, f"oneOf count drift: {len(one_ofs)}")
    require(sum(len(arms) for _, arms in one_ofs) == 54, "oneOf arm drift")
    require(len(objects) == 78, f"object count drift: {len(objects)}")
    require(sum(len(node["properties"]) for _, node in objects) == 323, "property count drift")
    require(sum(len(node.get("required", [])) for _, node in objects) == 322, "required count drift")
    validate_ownership(schema, objects)

    pair_registry = load("APP-CORE-IFACE-0-ONEOF-DISJOINTNESS-CANDIDATE.json")
    expected_pairs = {
        f"{pointer}/pair/{left}-{right}"
        for pointer, arms in one_ofs
        for left, right in itertools.combinations(range(len(arms)), 2)
    }
    actual_pairs = [row["pairId"] for row in pair_registry["rows"]]
    require(len(actual_pairs) == len(set(actual_pairs)) == 93, "oneOf pair uniqueness drift")
    require(set(actual_pairs) == expected_pairs, "oneOf pair relation drift")
    require(pair_registry["pairCount"] == 93, "oneOf pair count field drift")
    require(pair_registry["pairSetSha256"] == digest_lines(actual_pairs), "oneOf pair digest drift")
    require(pair_registry["schemaSha256"] == sha256(ROOT / schema_name), "oneOf schema binding drift")

    reachability = load("APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json")
    require(
        (
            reachability["rootCount"],
            reachability["definitionCount"],
            reachability["objectSchemaCount"],
            reachability["oneOfArmCount"],
        )
        == (12, 114, 78, 54),
        "carrier reachability count drift",
    )
    require(
        {row["definitionPointer"] for row in reachability["definitionCoverage"]}
        == {f"/$defs/{name}" for name in definitions},
        "definition reachability drift",
    )
    require(
        {row["objectSchemaPointer"] for row in reachability["objectCoverage"]}
        == {pointer for pointer, _ in objects},
        "object reachability drift",
    )
    expected_arms = {
        f"{pointer}#{index}"
        for pointer, arms in one_ofs
        for index in range(len(arms))
    }
    actual_arms = {
        f"{row['oneOfPointer']}#{row['armIndex']}"
        for row in reachability["oneOfArmCoverage"]
    }
    require(actual_arms == expected_arms, "union-arm reachability drift")

    structural = load("APP-CORE-IFACE-0-STRUCTURAL-AXES-CANDIDATE.json")
    require(len(structural["rules"]) == 24, "structural family drift")
    require(sum(row["expectedCount"] for row in structural["rules"]) == 1450, "structural count drift")
    require(structural["derivedCounts"] == {"structuralRuleFamilies": 24, "structuralExecutionInstances": 1450}, "structural derived-count drift")
    structural_by_id = {row["id"]: row for row in structural["rules"]}
    keyword_rules = {
        "type": "STR-TYPE-MISMATCH",
        "$ref": "STR-REF-TARGET-CONSTRAINT",
        "pattern": "STR-PATTERN-MISMATCH",
        "maxItems": "STR-MAX-ITEMS-OVERFLOW",
    }
    for keyword, rule_id in keyword_rules.items():
        pointers = {
            pointer + "/" + escape_pointer(keyword)
            for pointer, node in nodes
            if isinstance(node, dict) and keyword in node
        }
        row = structural_by_id[rule_id]
        require(
            row["sourceCount"] == row["expectedCount"] == len(pointers)
            and row["sourceSetSha256"] == digest_lines(pointers),
            f"structural source binding drift: {rule_id}",
        )
    all_of_arms = {
        f"{pointer}/allOf/{index}"
        for pointer, node in nodes
        if isinstance(node, dict) and isinstance(node.get("allOf"), list)
        for index in range(len(node["allOf"]))
    }
    all_of_rule = structural_by_id["STR-ALL-OF-BRANCH-CONSTRAINT"]
    require(
        all_of_rule["sourceCount"]
        == all_of_rule["expectedCount"]
        == len(all_of_arms)
        and all_of_rule["sourceSetSha256"] == digest_lines(all_of_arms),
        "structural source binding drift: STR-ALL-OF-BRANCH-CONSTRAINT",
    )
    conditional_rules = [
        row
        for row in structural["rules"]
        if row["expectedDisposition"] == "FROM_RELATION_SUFFIX"
    ]
    require(
        len(conditional_rules) == 1
        and conditional_rules[0]["id"] == "STR-CONDITIONAL-BRANCH-MATRIX"
        and conditional_rules[0]["mode"] == "LITERAL_RELATION",
        "conditional disposition rule drift",
    )
    conditional_rows = conditional_rules[0]["relation"]
    require(
        len(conditional_rows)
        == len(set(conditional_rows))
        == conditional_rules[0]["sourceCount"]
        == conditional_rules[0]["expectedCount"],
        "conditional relation cardinality drift",
    )
    require(
        all(
            isinstance(row, str)
            and row.endswith(("_ACCEPTS", "_REJECTS"))
            for row in conditional_rows
        ),
        "conditional relation has no disposition suffix",
    )
    require(
        {row for row in conditional_rows if "_SKIPS_" in row}
        == {
            "NON_ORDINARY_SKIPS_ORDINARY_BRANCH_ACCEPTS",
            "NON_REMOVAL_SKIPS_REMOVAL_BRANCH_ACCEPTS",
            "NON_CONTROL_SKIPS_CONTROL_BRANCH_ACCEPTS",
        },
        "inactive conditional relation drift",
    )
    palette = load("APP-CORE-IFACE-0-PERTURBATION-PALETTE-CANDIDATE.json")
    conditional_recipes = [
        row
        for row in palette["recipes"]
        if row["perturbationKind"] == "CONDITIONAL_MATRIX_ROW"
    ]
    require(
        palette["paletteVersion"] == "APP-CORE-IFACE-0-PERTURBATION-PALETTE-V2"
        and len(conditional_recipes) == 1
        and conditional_recipes[0]["candidateOperations"]
        == [
            "BUILD_EXACT_LITERAL_RELATION_ROW_WITH_ACTIVE_PREDICATE_AND_SELECTED_BRANCH",
            "BUILD_EXACT_LITERAL_SKIP_ROW_WITH_INACTIVE_PREDICATE_AND_NO_SELECTED_BRANCH",
        ],
        "conditional perturbation recipe drift",
    )
    bindings = {
        "schemaSha256": schema_name,
        "oneOfDisjointnessRegistrySha256": "APP-CORE-IFACE-0-ONEOF-DISJOINTNESS-CANDIDATE.json",
        "perturbationPaletteSha256": "APP-CORE-IFACE-0-PERTURBATION-PALETTE-CANDIDATE.json",
        "positiveCarrierInventorySchemaSha256": "APP-CORE-IFACE-0-POSITIVE-CARRIER-INVENTORY-SCHEMA-CANDIDATE.json",
        "structuralWitnessRegistrySchemaSha256": "APP-CORE-IFACE-0-STRUCTURAL-WITNESS-SCHEMA-CANDIDATE.json",
    }
    for field, name in bindings.items():
        require(structural[field] == sha256(ROOT / name), f"structural binding drift: {field}")

    positive = load("APP-CORE-IFACE-0-POSITIVE-CARRIER-INVENTORY-SCHEMA-CANDIDATE.json")
    witness = load("APP-CORE-IFACE-0-STRUCTURAL-WITNESS-SCHEMA-CANDIDATE.json")
    require(positive["properties"]["caseCount"]["maximum"] == 144, "carrier maximum drift")
    require(positive["properties"]["cases"]["maxItems"] == 144, "carrier maxItems drift")
    require(witness["properties"]["rowCount"]["const"] == 1450, "witness count drift")
    require(witness["properties"]["rows"]["minItems"] == witness["properties"]["rows"]["maxItems"] == 1450, "witness cardinality drift")

    semantics = load("APP-CORE-IFACE-0-SEMANTIC-CONSTRAINTS-CANDIDATE.json")
    axes = load("APP-CORE-IFACE-0-INSTANCE-AXES-CANDIDATE.json")
    validate_terminal_path_bindings(schema, axes)
    semantic_ids = [row["id"] for row in semantics["rules"]]
    require(len(semantic_ids) == len(set(semantic_ids)) == 82, "semantic family drift")
    require(
        set(semantic_ids) == {f"ACV-{index:03d}" for index in range(1, 83)},
        "semantic rule-id set drift",
    )
    for field in ("scenario", "mutant"):
        values = [row[field] for row in semantics["rules"]]
        require(len(values) == len(set(values)) == 82, f"semantic {field} drift")
    axis_ids = [row["id"] for row in axes["rules"]]
    require(set(axis_ids) == set(semantic_ids) and len(axis_ids) == 82, "semantic axis relation drift")
    require(sum(row["expectedCount"] for row in axes["rules"]) == 5147, "semantic execution count drift")
    require(axes["unresolvedAxes"] == [], "unresolved semantic axes")
    phases = load("APP-CORE-IFACE-0-EXECUTION-PHASES-CANDIDATE.json")
    require(
        phases.get("semanticRuleSetSha256") == digest_lines(semantic_ids),
        "execution-phase semantic-rule binding drift",
    )
    require(
        phases.get("instanceAxisRegistrySha256")
        == sha256(ROOT / "APP-CORE-IFACE-0-INSTANCE-AXES-CANDIDATE.json"),
        "execution-phase instance-axis binding drift",
    )
    require(
        phases.get("fixedCountsBeforeSeedPartition", {}).get(
            "totalSemanticExecutionInstances"
        )
        == 5147,
        "execution-phase total drift",
    )
    acv066_phase = next(
        (row for row in phases.get("overrides", []) if row.get("id") == "ACV-066"),
        None,
    )
    require(
        acv066_phase
        == {
            "id": "ACV-066",
            "partition": "ALL_INSTANCES",
            "phase": "POST_OUTPUT_MUTATION",
            "expectedCount": 7,
        },
        "ACV-066 execution-phase drift",
    )
    phase_by_id = {row["id"]: row for row in phases.get("overrides", [])}
    require(
        phase_by_id.get("ACV-043")
        == {
            "id": "ACV-043",
            "partition": "BY_RELATION_ROW_REACHABILITY",
            "relation": [
                {
                    "reachability": "REACHABLE",
                    "phase": "BLIND_INPUT_EXECUTION",
                    "expectedCount": 15,
                },
                {
                    "reachability": "RESERVED_UNREACHABLE_V0",
                    "phase": "POST_OUTPUT_MUTATION",
                    "expectedCount": 1,
                },
            ],
        }
        and phase_by_id.get("ACV-044")
        == {
            "id": "ACV-044",
            "partition": "BY_RELATION_ROW_REACHABILITY",
            "relation": [
                {
                    "reachability": "REACHABLE",
                    "phase": "BLIND_INPUT_EXECUTION",
                    "expectedCount": 12,
                },
                {
                    "reachability": "RESERVED_UNREACHABLE_V0",
                    "phase": "POST_OUTPUT_MUTATION",
                    "expectedCount": 5,
                },
            ],
        },
        "reason/stage reachability phase partition drift",
    )
    require(
        phase_by_id.get("ACV-067")
        == {
            "id": "ACV-067",
            "partition": "ALL_INSTANCES",
            "phase": "BLIND_INPUT_EXECUTION",
            "expectedCount": 1,
        }
        and phase_by_id.get("ACV-068")
        == {
            "id": "ACV-068",
            "partition": "ALL_INSTANCES",
            "phase": "BLIND_INPUT_EXECUTION",
            "expectedCount": 17,
        },
        "signature execution-phase drift",
    )
    require(
        phase_by_id.get("ACV-069")
        == {
            "id": "ACV-069",
            "partition": "BY_RELATION_ROW_REACHABILITY",
            "relation": [
                {
                    "reachability": "REACHABLE",
                    "phase": "BLIND_INPUT_EXECUTION",
                    "expectedCount": 27,
                },
                {
                    "reachability": "RESERVED_UNREACHABLE_V0",
                    "phase": "POST_OUTPUT_MUTATION",
                    "expectedCount": 6,
                },
            ],
        },
        "terminal-predicate execution-phase drift",
    )
    expected_reachability_partitions = {
        "ACV-027": (7, 16),
        "ACV-033": (21, 4),
        "ACV-052": (21, 4),
        "ACV-073": (7, 3),
        "ACV-078": (12, 4),
        "ACV-079": (4, 6),
    }
    for rule_id, (blind_count, mutation_count) in expected_reachability_partitions.items():
        require(
            phase_by_id.get(rule_id)
            == {
                "id": rule_id,
                "partition": "BY_RELATION_ROW_REACHABILITY",
                "relation": [
                    {
                        "reachability": "REACHABLE",
                        "phase": "BLIND_INPUT_EXECUTION",
                        "expectedCount": blind_count,
                    },
                    {
                        "reachability": "RESERVED_UNREACHABLE_V0",
                        "phase": "POST_OUTPUT_MUTATION",
                        "expectedCount": mutation_count,
                    },
                ],
            },
            f"V9 reachability phase partition drift: {rule_id}",
        )
    for rule_id, count in {
        "ACV-070": 1,
        "ACV-071": 2,
        "ACV-072": 1,
        "ACV-081": 2,
        "ACV-082": 1,
    }.items():
        require(
            phase_by_id.get(rule_id)
            == {
                "id": rule_id,
                "partition": "ALL_INSTANCES",
                "phase": "POST_OUTPUT_MUTATION",
                "expectedCount": count,
            },
            f"V9 post-output phase drift: {rule_id}",
        )
    require(
        set(phase_by_id)
        == {
            "ACV-013",
            "ACV-015",
            "ACV-027",
            "ACV-033",
            "ACV-043",
            "ACV-044",
            "ACV-048",
            "ACV-049",
            "ACV-050",
            "ACV-052",
            "ACV-056",
            "ACV-066",
            "ACV-067",
            "ACV-068",
            "ACV-069",
            "ACV-070",
            "ACV-071",
            "ACV-072",
            "ACV-073",
            "ACV-078",
            "ACV-079",
            "ACV-081",
            "ACV-082",
        },
        "V9 phase override set drift",
    )
    require(
        phases.get("fixedCountsBeforeSeedPartition")
        == {
            "BLIND_INPUT_EXECUTION": 558,
            "POST_OUTPUT_MUTATION": 3860,
            "VALIDATOR_SELF_TEST": 27,
            "ACV048PendingCarrierPartition": 702,
            "totalSemanticExecutionInstances": 5147,
        },
        "execution-phase count drift",
    )
    custom_occurrences = {
        pointer.lstrip("/").replace("/", ".") + "." + key
        for pointer, node in nodes
        if isinstance(node, dict)
        for key in node
        if key.startswith("x-styx-")
    }
    require(custom_occurrences == set(semantics["customKeywordCoverage"]), "custom keyword coverage drift")
    require(set(semantics["customKeywordCoverage"].values()) <= set(semantic_ids), "custom keyword owner drift")
    concrete_transcript_annotations = {
        "$defs.GenesisTranscriptCandidateV0.properties.transcriptHex": {
            "dimension": "GENESIS_BODY_OCTETS",
            "prefixOctets": "20",
        },
        "$defs.ApplicationTranscriptCandidateV0.properties.transcriptHex": {
            "dimension": "FRAMING_OBJECT_OCTETS",
            "prefixOctets": "20",
        },
    }
    for path, expected_annotation in concrete_transcript_annotations.items():
        node: object = schema
        for component in path.split("."):
            require(isinstance(node, dict) and component in node, f"missing concrete transcript annotation: {path}")
            node = node[component]
        require(
            isinstance(node, dict)
            and node.get("$ref") == "#/$defs/TranscriptHex"
            and node.get("x-styx-o08-body-plus-prefix-limit")
            == expected_annotation,
            f"concrete transcript annotation drift: {path}",
        )
    require(
        "x-styx-o08-limit" not in schema["$defs"]["TranscriptHex"],
        "generic transcript O-08 annotation drift",
    )
    acv004 = next(row for row in semantics["rules"] if row["id"] == "ACV-004")
    require(
        acv004
        == {
            "id": "ACV-004",
            "owners": ["K", "O08"],
            "targets": list(concrete_transcript_annotations),
            "rule": "HEX_BODY_PLUS_FIXED_PREFIX_LIMIT_BEFORE_DECODE",
            "parameters": {
                "fixedPrefixOctets": "20",
                "targetDimensions": {
                    path: annotation["dimension"]
                    for path, annotation in concrete_transcript_annotations.items()
                },
            },
            "scenario": "ACI-TRANSCRIPT-LIMIT-HEADER-ONLY",
            "mutant": "M-ACI-TRANSCRIPT-LIMIT-AFTER-DECODE",
        },
        "ACV-004 body-plus-prefix rule drift",
    )
    acv050_rule = next(row for row in semantics["rules"] if row["id"] == "ACV-050")
    acv050_axis = next(row for row in axes["rules"] if row["id"] == "ACV-050")
    require(
        acv050_rule["parameters"] == {"ruleCount": "82"}
        and acv050_axis["mappedOccurrenceCount"] == len(custom_occurrences) == 26
        and acv050_axis["expectedCount"] == len(custom_occurrences) + 1 == 27,
        "ACV-050 exact-registry binding drift",
    )
    semantic_by_id = {row["id"]: row for row in semantics["rules"]}
    axis_by_id = {row["id"]: row for row in axes["rules"]}
    require(
        semantic_by_id["ACV-010"]["rule"]
        == "DERIVED_ARRAY_COUNT_LIMIT_BEFORE_ITEM_WORK"
        and semantic_by_id["ACV-010"]["parameters"]
        == {"expression": "RECORDS + 1", "selectedValue": "129"}
        and semantic_by_id["ACV-029"]["parameters"]
        == {
            "perCredentialDimension": "ALIASES_PER_CREDENTIAL",
            "membershipDimension": "CREDENTIALS",
            "membershipMustExistInCredentialBindings": True,
            "maximumGroupCountExpression": "floor((RECORDS + 1) / 2)",
            "maximumGroupMemberExpression": "RECORDS + 1",
            "maximumTotalMemberExpression": "RECORDS + 1",
        }
        and semantic_by_id["ACV-046"]["parameters"]
        == {"projectedDimensionCount": "37"}
        and semantic_by_id["ACV-059"]["parameters"]
        == {
            "expression": "floor((RECORDS + 1) / 2)",
            "selectedValue": "64",
        },
        "V9 derived-bound constraint drift",
    )
    expected_ordering = {
        "$defs.EvidenceProjectionV0.contentMaterial": "eventReferenceHex",
        "$defs.EvidenceProjectionV0.openingMaterial": "eventReferenceHex",
        "$defs.CanonicalReferenceArray": "lexicographic-hex",
        "$defs.ContextProjectionV0.records": "protocol-k-order",
        "$defs.ContextProjectionV0.recordOutcomes": "eventReferenceHex",
        "$defs.ContextProjectionV0.credentialBindings": "credentialIdentifierHex",
        "$defs.ContextProjectionV0.reductionStandings": "eventReferenceHex",
        "$defs.ContextProjectionV0.eventAuthority": "eventReferenceHex",
        "$defs.ContextProjectionV0.forkJoins": "joinLabelHex",
        "$defs.ContextProjectionV0.contentStates": "eventReferenceHex",
    }
    require(
        semantic_by_id["ACV-051"]["parameters"]
        == {"orderingRelationByTarget": expected_ordering},
        "V9 collection-order constraint drift",
    )
    credential_targets = semantic_by_id["ACV-057"]["targets"]
    expected_credential_parameters = {
        target: (
            {"expression": "RECORDS + 1", "selectedValue": "129"}
            if target == "$defs.AliasGroupV0.allOf[0]"
            else {"dimension": "CREDENTIALS"}
        )
        for target in credential_targets
    }
    require(
        semantic_by_id["ACV-057"]["parameters"]
        == {"parametersByTarget": expected_credential_parameters},
        "V9 credential-derived bound map drift",
    )
    require(
        semantic_by_id["ACV-061"]["parameters"]
        == {
            "parametersByTarget": {
                "$defs.ContextProjectionV0.reductionStandings": {
                    "dimension": "CONTROL_EVENTS"
                },
                "$defs.ContextProjectionV0.eventAuthority": {"dimension": "RECORDS"},
                "$defs.ContextProjectionV0.forkJoins": {"dimension": "FORK_SLOTS"},
                "$defs.ContextProjectionV0.replayDependencyReferences": {
                    "dimension": "RECORDS"
                },
            },
            "forkJoinBoundJustification": "join-label uniqueness over complete slots and recomputation from the retained closure without checkpoint pruning",
        },
        "V9 record-derived bound map drift",
    )
    expected_axis_fragments = {
        "ACV-019": {"expectedCount": 49},
        "ACV-027": {
            "mode": "PER_LITERAL_RELATION_ROW",
            "axisSources": [
                "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json#contentAxisLegalRelationV0"
            ],
            "expectedCount": 23,
        },
        "ACV-034": {"expectedCount": 81},
        "ACV-036": {"expectedCount": 81},
        "ACV-046": {"expectedCount": 44},
        "ACV-049": {
            "pathCount": 377,
            "pathSha256": "ae9149055d83b3c1960d6f0ec6db796a4e9b019551632e70dc86571b8f90c3a0",
            "familyCount": 10,
            "expectedCount": 3770,
        },
    }
    for rule_id, fragment in expected_axis_fragments.items():
        require(
            all(axis_by_id[rule_id].get(key) == value for key, value in fragment.items()),
            f"V9 semantic axis drift: {rule_id}",
        )
    expected_literal_axes = {
        "ACV-071": ["CONTEXT_CAPACITY_EXHAUSTED", "DEPENDENCY_DEFERRED"],
        "ACV-075": [
            "MINIMAL_PENDING_PARTITION",
            "K_FORK_EVIDENCE_IMPLIES_COMPLETE_SLOT",
            "K_PENDING_OPENING_IMPLIES_PENDING_ROOT",
            "K_PENDING_ANCESTOR_IMPLIES_PENDING_REFERENCE",
            "K_NULL_IMPLIES_NOT_PENDING",
        ],
        "ACV-076": ["EVENT_OUTCOME_PRECEDENCE", "CONTEXT_STATE_PRECEDENCE"],
        "ACV-080": [
            "REPLAY_CONTEXT",
            "EVALUATE_CANDIDATE",
            "EVALUATE_EVIDENCE_UPDATE",
        ],
        "ACV-081": [
            "NO_OPERATIONAL_AUTHORITY_ENTRY",
            "NO_OPERATIONAL_AUTHORITY_TO_AUTHORITY_UNAVAILABLE",
        ],
    }
    for rule_id, values in expected_literal_axes.items():
        require(
            axis_by_id[rule_id]
            == {
                "id": rule_id,
                "mode": "PER_LITERAL_VALUE",
                "values": values,
                "expectedCount": len(values),
            },
            f"V9 literal semantic axis drift: {rule_id}",
        )

    relations = load("APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json")
    relation_counts = {
        "contentAxisLegalRelationV0": 23,
        "forkJoinLabelRelationV0": 10,
        "authorityProjectionDimensionRelationV0": 16,
        "graphAdmissionDimensionRelationV0": 10,
        "candidateEvaluationPrimaryRelationV0": 25,
        "transcriptReasonStageRelationV0": 16,
        "genesisReasonStageRelationV0": 17,
        "signatureVerificationPathRelationV0": 17,
        "terminalPredicateRelationV0": 33,
    }
    for field, count in relation_counts.items():
        rows = relations[field]
        require(len(rows) == count, f"relation count drift: {field}")
        ids = [row["id"] for row in rows]
        require(len(ids) == len(set(ids)), f"relation ID drift: {field}")

    fork_join = schema["$defs"]["ForkJoinProjectionV0"]
    require(
        fork_join.get("additionalProperties") is False
        and fork_join.get("required")
        == [
            "joinLabelHex",
            "credentialIdentifierHex",
            "authorSequence",
            "siblingReferences",
            "lineageClosureCredentialIdentifiers",
        ]
        and fork_join.get("properties")
        == {
            "joinLabelHex": {"$ref": "#/$defs/FixedHex32"},
            "credentialIdentifierHex": {"$ref": "#/$defs/FixedHex32"},
            "authorSequence": {"$ref": "#/$defs/U64Text"},
            "siblingReferences": {
                "$ref": "#/$defs/CanonicalReferenceArray",
                "minItems": 2,
                "maxItems": 3,
            },
            "lineageClosureCredentialIdentifiers": {
                "$ref": "#/$defs/CanonicalReferenceArray"
            },
        },
        "V9 fork-join schema drift",
    )
    context_properties = schema["$defs"]["ContextProjectionV0"]["properties"]
    require(
        context_properties["contextState"]
        == {
            "enum": [
                "ACTIVE",
                "AUTHORITY_UNAVAILABLE",
                "EMPTY_STALE",
                "NO_OPERATIONAL_AUTHORITY",
                "PARTIALLY_LINEAGE_QUARANTINED",
                "PARTIALLY_PENDING",
            ]
        }
        and context_properties["forkJoins"].get("x-styx-canonical-order")
        == "joinLabelHex",
        "V9 context-state or fork-order drift",
    )
    expected_limits = {
        "ACTIVE_FRONTIER": "16",
        "ACTORS": "8",
        "ALIASES_PER_CREDENTIAL": "4",
        "ANCESTRY_RELATIONS": "32768",
        "AP_EXPANDED_CONTENT_OCTETS": "131072",
        "AP_TRANSITION_BLOCK_OCTETS": "4096",
        "AUTHORITY_CONCURRENT_CONTROLS": "3",
        "AUTHORITY_STATES": "256",
        "AUTHORITY_TRANSITIONS": "512",
        "CHUNKS_PER_CONTENT": "64",
        "CHUNK_OCTETS": "16384",
        "COMMITMENT_VALUE_OCTETS": "32",
        "CONTENT_EXACT_OCTETS": "262144",
        "CONTEXT_LIFETIME_EVENTS": "4096",
        "CONTROL_EVENTS": "12",
        "CREDENTIALS": "16",
        "EVENTS_ADMITTED": "64",
        "EVIDENCE_PER_CREDENTIAL": "16",
        "FORK_SLOTS": "3",
        "FRAMING_OBJECT_OCTETS": "8192",
        "GENESIS_BODY_OCTETS": "8192",
        "GENESIS_POLICY_OCTETS": "4096",
        "GRAPH_DEPTH": "256",
        "HALTED_REPLAY_SPAN": "256",
        "LINEAGE_DEPTH": "8",
        "ORDINARY_PREFIX_QUERIES": "64",
        "PARENTS_PER_EVENT": "8",
        "PENDING_DESCENDANTS": "128",
        "PENDING_ROOTS": "16",
        "RANDOMIZER_OCTETS": "32",
        "RECORDS": "128",
        "REFERENCE_OCTETS": "32",
        "REMOVAL_DIRECTIVES": "32",
        "REPLAYED_EVENT_WORK": "65536",
        "SIGNATURE_OCTETS": "64",
        "SIBLINGS_PER_FORK": "3",
        "VERIFICATION_KEY_OCTETS": "32",
    }
    require(
        schema["$defs"]["InterfaceLimitsV0"]["properties"]
        == {key: {"const": value} for key, value in expected_limits.items()}
        and schema["$defs"]["InterfaceLimitsV0"]["required"]
        == list(expected_limits),
        "V9 interface-limit projection drift",
    )

    content_reachability = {
        "CAR-001": ("REACHABLE", ["REPLAY_CONTEXT", "EVALUATE_CANDIDATE", "EVALUATE_EVIDENCE_UPDATE"]),
        "CAR-002": ("RESERVED_UNREACHABLE_V0", []),
        "CAR-003": ("REACHABLE", ["REPLAY_CONTEXT", "EVALUATE_CANDIDATE", "EVALUATE_EVIDENCE_UPDATE"]),
        "CAR-004": ("REACHABLE", ["REPLAY_CONTEXT", "EVALUATE_CANDIDATE", "EVALUATE_EVIDENCE_UPDATE"]),
        "CAR-005": ("RESERVED_UNREACHABLE_V0", []),
        "CAR-006": ("REACHABLE", ["REPLAY_CONTEXT", "EVALUATE_CANDIDATE", "EVALUATE_EVIDENCE_UPDATE"]),
        "CAR-007": ("REACHABLE", ["REPLAY_CONTEXT", "EVALUATE_CANDIDATE", "EVALUATE_EVIDENCE_UPDATE"]),
        "CAR-008": ("RESERVED_UNREACHABLE_V0", []),
        "CAR-009": ("RESERVED_UNREACHABLE_V0", []),
        "CAR-010": ("RESERVED_UNREACHABLE_V0", []),
        "CAR-011": ("RESERVED_UNREACHABLE_V0", []),
        "CAR-012": ("RESERVED_UNREACHABLE_V0", []),
        "CAR-013": ("REACHABLE", ["REPLAY_CONTEXT", "EVALUATE_CANDIDATE", "EVALUATE_EVIDENCE_UPDATE"]),
        "CAR-014": ("RESERVED_UNREACHABLE_V0", []),
        "CAR-015": ("RESERVED_UNREACHABLE_V0", []),
        "CAR-016": ("RESERVED_UNREACHABLE_V0", []),
        "CAR-017": ("RESERVED_UNREACHABLE_V0", []),
        "CAR-018": ("RESERVED_UNREACHABLE_V0", []),
        "CAR-019": ("RESERVED_UNREACHABLE_V0", []),
        "CAR-020": ("REACHABLE", ["REPLAY_CONTEXT", "EVALUATE_CANDIDATE", "EVALUATE_EVIDENCE_UPDATE"]),
        "CAR-021": ("RESERVED_UNREACHABLE_V0", []),
        "CAR-022": ("RESERVED_UNREACHABLE_V0", []),
        "CAR-023": ("RESERVED_UNREACHABLE_V0", []),
    }
    require(
        {
            row["id"]: (row.get("reachability"), row.get("reachableOperations"))
            for row in relations["contentAxisLegalRelationV0"]
        }
        == content_reachability,
        "V9 content reachability drift",
    )

    fork_checks = [
        "COMPLETE_SLOT_BIJECTION",
        "EXACT_DOMAIN_SEPARATED_PREIMAGE",
        "AUTHOR_SEQUENCE_U64_BIG_ENDIAN",
        "SIBLING_COUNT_U32_BIG_ENDIAN",
        "SIBLINGS_SORTED_BY_REFERENCE_OCTETS",
        "LATE_SIBLING_RECOMPUTES_LABEL",
        "REFLEXIVE_TRANSITIVE_GRANT_LINEAGE_CLOSURE",
        "DISTINCT_PREIMAGE_LABEL_COLLISION",
        "LABEL_EQUALS_EVENT_REFERENCE_COLLISION",
        "LABEL_EQUALS_CREDENTIAL_IDENTIFIER_COLLISION",
    ]
    require(
        relations["forkJoinLabelRelationV0"]
        == [
            {
                "id": f"FJL-{index:03d}",
                "check": check,
                "reachability": (
                    "REACHABLE" if index <= 7 else "RESERVED_UNREACHABLE_V0"
                ),
                "scenario": f"ACI-FJL-{index:03d}",
                "mutant": f"M-ACI-FJL-{index:03d}",
            }
            for index, check in enumerate(fork_checks, 1)
        ],
        "V9 fork-join relation drift",
    )

    s5_dimensions = [
        "FORK_SLOTS",
        "SIBLINGS_PER_FORK",
        "CREDENTIALS",
        "LINEAGE_DEPTH",
        "ALIASES_PER_CREDENTIAL",
        "ACTORS",
        "CONTROL_EVENTS",
        "AUTHORITY_CONCURRENT_CONTROLS",
        "REMOVAL_DIRECTIVES",
        "AUTHORITY_TRANSITIONS",
        "AUTHORITY_STATES",
        "ORDINARY_PREFIX_QUERIES",
        "REPLAYED_EVENT_WORK",
        "GENESIS_POLICY_OCTETS",
        "ROLE_ASSIGNMENTS",
        "EVIDENCE_PER_CREDENTIAL",
    ]
    expected_s5 = []
    for index, dimension in enumerate(s5_dimensions, 1):
        expected_s5.append(
            {
                "id": f"S5D-{index:03d}",
                "dimension": dimension,
                "branch": "A" if index <= 6 else "B",
                "reachability": (
                    "REACHABLE" if index <= 12 else "RESERVED_UNREACHABLE_V0"
                ),
                "scenario": (
                    "AUTHORITY_STATES_ISOLATED_V0"
                    if index == 11
                    else f"ACI-S5D-{index:03d}"
                ),
                "mutant": (
                    "M-ACI-S5D-011-OMIT-CHECK"
                    if index == 11
                    else f"M-ACI-S5D-{index:03d}"
                ),
            }
        )
    require(
        relations["authorityProjectionDimensionRelationV0"] == expected_s5,
        "V9 S5 dimension relation drift",
    )

    s4_rows = [
        ("PARENTS_PER_EVENT", "CONTEXT_CAPACITY_EXHAUSTED", ["REPLAY_CONTEXT", "EVALUATE_CANDIDATE"]),
        ("ACTIVE_FRONTIER", "CONTEXT_CAPACITY_EXHAUSTED", ["REPLAY_CONTEXT", "EVALUATE_CANDIDATE"]),
        ("EVIDENCE_PER_CREDENTIAL", "CONTEXT_CAPACITY_EXHAUSTED", ["REPLAY_CONTEXT", "EVALUATE_CANDIDATE"]),
        ("PENDING_ROOTS", "DEPENDENCY_DEFERRED", ["REPLAY_CONTEXT", "EVALUATE_CANDIDATE"]),
        ("EVENTS_ADMITTED", "RESERVED_UNREACHABLE_V0", []),
        ("GRAPH_DEPTH", "RESERVED_UNREACHABLE_V0", []),
        ("ANCESTRY_RELATIONS", "RESERVED_UNREACHABLE_V0", []),
        ("CONTEXT_LIFETIME_EVENTS", "RESERVED_UNREACHABLE_V0", []),
        ("PENDING_DESCENDANTS", "RESERVED_UNREACHABLE_V0", []),
        ("HALTED_REPLAY_SPAN", "RESERVED_UNREACHABLE_V0", []),
    ]
    require(
        relations["graphAdmissionDimensionRelationV0"]
        == [
            {
                "id": f"S4D-{index:03d}",
                "dimension": dimension,
                "result": result,
                "operations": operations,
                "reachability": (
                    "REACHABLE" if index <= 4 else "RESERVED_UNREACHABLE_V0"
                ),
                "scenario": f"ACI-S4D-{index:03d}",
                "mutant": f"M-ACI-S4D-{index:03d}",
            }
            for index, (dimension, result, operations) in enumerate(s4_rows, 1)
        ],
        "V9 S4 dimension relation drift",
    )
    f13_reachability = {
        row["id"]: row.get("reachability")
        for row in relations["candidateEvaluationPrimaryRelationV0"]
    }
    require(
        {
            row_id
            for row_id, reachability in f13_reachability.items()
            if reachability == "RESERVED_UNREACHABLE_V0"
        }
        == {"F13R-007", "F13R-013", "F13R-020", "F13R-022"}
        and set(f13_reachability.values())
        == {"REACHABLE", "RESERVED_UNREACHABLE_V0"},
        "V9 F13 reachability drift",
    )

    transcript_reachability = {
        row["id"]: row.get("reachability")
        for row in relations["transcriptReasonStageRelationV0"]
    }
    genesis_reachability = {
        row["id"]: row.get("reachability")
        for row in relations["genesisReasonStageRelationV0"]
    }
    require(
        {
            row_id
            for row_id, reachability in (
                *transcript_reachability.items(),
                *genesis_reachability.items(),
            )
            if reachability == "RESERVED_UNREACHABLE_V0"
        }
        == {"TRS-011", "GRS-009", "GRS-010", "GRS-011", "GRS-015", "GRS-016"},
        "reserved terminal-row set drift",
    )
    require(
        set(transcript_reachability.values())
        | set(genesis_reachability.values())
        == {"REACHABLE", "RESERVED_UNREACHABLE_V0"}
        and sum(
            value == "RESERVED_UNREACHABLE_V0"
            for value in (
                *transcript_reachability.values(),
                *genesis_reachability.values(),
            )
        )
        == 6,
        "terminal-row reachability relation drift",
    )
    acv066 = next(row for row in semantics["rules"] if row["id"] == "ACV-066")
    require(
        acv066
        == {
            "id": "ACV-066",
            "owners": ["K", "O03", "O04", "O07", "AP", "INTERFACE"],
            "targets": [
                "$defs.ValidateTranscriptResultV0",
                "$defs.EvaluateGenesisResultV0",
                "$defs.TranscriptObservationV0",
            ],
            "rule": "RESERVED_ROWS_UNREACHABLE_IN_V0",
            "parameters": {
                "reservedRows": [
                    "TRS-011",
                    "GRS-009",
                    "GRS-010",
                    "GRS-011",
                    "GRS-015",
                    "GRS-016",
                ],
                "independentObservationDetector": "referenceVerification=REJECTED",
            },
            "scenario": "ACI-RESERVED-ROW-RELEASE",
            "mutant": "M-ACI-RELEASE-RESERVED-ROW",
        },
        "ACV-066 rule drift",
    )
    acv067 = next(row for row in semantics["rules"] if row["id"] == "ACV-067")
    require(
        acv067
        == {
            "id": "ACV-067",
            "owners": ["K", "O08", "O14"],
            "targets": ["$defs.SignatureHex"],
            "rule": "HEX_OCTETS_LIMIT_BEFORE_DECODE",
            "parameters": {"dimension": "SIGNATURE_OCTETS"},
            "scenario": "ACI-SIGNATURE-O08-BOUNDARY",
            "mutant": "M-ACI-SIGNATURE-LIMIT-AFTER-DECODE",
        },
        "ACV-067 rule drift",
    )
    acv068 = next(row for row in semantics["rules"] if row["id"] == "ACV-068")
    require(
        acv068
        == {
            "id": "ACV-068",
            "owners": ["K", "O14", "O08", "INTERFACE"],
            "targets": [
                "$defs.ValidateTranscriptInputV0",
                "$defs.EvaluateGenesisInputV0",
                "$defs.TranscriptObservationV0",
                "$defs.ValidateTranscriptResultV0",
                "$defs.EvaluateGenesisResultV0",
            ],
            "rule": "SIGNATURE_VERIFICATION_EXACT_PATH_RELATION",
            "parameters": {
                "relation": "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json#signatureVerificationPathRelationV0",
                "relationRowCount": "17",
                "signatureLengthGateFirst": True,
                "standaloneKeyApplicationOnly": True,
                "genesisKeySource": "PARSED_TRANSCRIPT_ONLY",
                "standaloneAuthorityEffect": "NONE",
            },
            "scenario": "ACI-SIGNATURE-VERIFICATION-PATH",
            "mutant": "M-ACI-SIGNATURE-PATH-RELATION",
        },
        "ACV-068 rule drift",
    )
    acv069 = next(row for row in semantics["rules"] if row["id"] == "ACV-069")
    require(
        acv069
        == {
            "id": "ACV-069",
            "owners": [
                "INTERFACE",
                "K",
                "O03",
                "O04",
                "O07",
                "O08",
                "O14",
                "AP",
                "AP_PROFILE",
            ],
            "targets": [
                "$defs.ValidateTranscriptInputV0",
                "$defs.ValidateTranscriptResultV0",
                "$defs.EvaluateGenesisInputV0",
                "$defs.EvaluateGenesisResultV0",
            ],
            "rule": "TRANSCRIPT_AND_GENESIS_TERMINAL_PREDICATE_EXACT_RELATION",
            "parameters": {
                "relation": "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json#terminalPredicateRelationV0",
                "relationRowCount": "33",
                "reachableRowCount": "27",
                "reservedRowCount": "6",
                "selectedEnvelopeCandidateProjection": "CURRENT_OBJECT_OUT_OF_PROFILE",
            },
            "scenario": "ACI-TERMINAL-PREDICATE-EXACT-ROW",
            "mutant": "M-ACI-TERMINAL-PREDICATE-OR-ORDER",
        },
        "ACV-069 rule drift",
    )

    terminal_predicates = relations["terminalPredicateRelationV0"]
    terminal_sources = {
        row["id"]: row
        for row in (
            *relations["transcriptReasonStageRelationV0"],
            *relations["genesisReasonStageRelationV0"],
        )
    }
    terminal_required_keys = {
        "id",
        "relationRowId",
        "owners",
        "operation",
        "candidateKinds",
        "predicate",
        "predecessorGatesPassed",
        "laterGatesNotEvaluated",
        "requiredObservations",
        "result",
        "scenario",
        "mutant",
    }
    terminal_source_ids = [
        *(f"TRS-{index:03d}" for index in range(1, 17)),
        *(f"GRS-{index:03d}" for index in range(1, 18)),
    ]
    require(
        [row["relationRowId"] for row in terminal_predicates] == terminal_source_ids
        and [row["id"] for row in terminal_predicates]
        == [f"TPR-{row_id}" for row_id in terminal_source_ids]
        and all(set(row) == terminal_required_keys for row in terminal_predicates),
        "terminal predicate relation shape drift",
    )
    for row in terminal_predicates:
        source = terminal_sources[row["relationRowId"]]
        require(
            row["result"]
            == {
                "kind": source["kind"],
                "reason": source["reason"],
                "stage": source["stage"],
                "reachability": source["reachability"],
            }
            and row["owners"] == sorted(set(row["owners"]))
            and row["owners"]
            and row["candidateKinds"] == sorted(set(row["candidateKinds"]))
            and row["candidateKinds"]
            and isinstance(row["predicate"], str)
            and row["predicate"]
            and row["predecessorGatesPassed"]
            == list(dict.fromkeys(row["predecessorGatesPassed"]))
            and row["laterGatesNotEvaluated"]
            == list(dict.fromkeys(row["laterGatesNotEvaluated"])),
            f"terminal predicate row drift: {row['relationRowId']}",
        )
        if row["operation"] == "VALIDATE_TRANSCRIPT":
            require(
                set(row["requiredObservations"])
                == {
                    "transcriptVerification",
                    "referenceVerification",
                    "signatureVerification",
                },
                f"terminal observation binding drift: {row['relationRowId']}",
            )
        else:
            require(
                row["operation"] == "EVALUATE_GENESIS"
                and row["candidateKinds"] == ["GENESIS"]
                and row["requiredObservations"] == {},
                f"genesis terminal applicability drift: {row['relationRowId']}",
            )
    require(
        sum(
            row["result"]["reachability"] == "REACHABLE"
            for row in terminal_predicates
        )
        == 27
        and sum(
            row["result"]["reachability"] == "RESERVED_UNREACHABLE_V0"
            for row in terminal_predicates
        )
        == 6
        and len({row["scenario"] for row in terminal_predicates}) == 33
        and len({row["mutant"] for row in terminal_predicates}) == 33,
        "terminal predicate cardinality or witness identity drift",
    )
    reserved_owner_sets = {
        row["relationRowId"]: row["owners"]
        for row in terminal_predicates
        if row["result"]["reachability"] == "RESERVED_UNREACHABLE_V0"
    }
    require(
        reserved_owner_sets
        == {
            "TRS-011": ["INTERFACE", "K", "O07"],
            "GRS-009": ["INTERFACE", "K", "O04"],
            "GRS-010": ["INTERFACE", "K", "O04"],
            "GRS-011": ["INTERFACE", "K", "O07"],
            "GRS-015": ["INTERFACE", "K", "O03", "O07"],
            "GRS-016": ["AP", "INTERFACE", "K", "O07"],
        },
        "reserved terminal reopening authority drift",
    )
    signature_paths = relations["signatureVerificationPathRelationV0"]
    required_signature_keys = {
        "id",
        "operation",
        "candidateKind",
        "keySource",
        "signatureLengthClass",
        "keyState",
        "signatureState",
        "resultMapping",
        "signatureObservation",
        "backendInvocations",
        "authorityEffect",
    }
    require(
        [row["id"] for row in signature_paths]
        == [f"SVP-{index:03d}" for index in range(1, 18)]
        and all(set(row) == required_signature_keys for row in signature_paths)
        and all(row["authorityEffect"] == "NONE" for row in signature_paths)
        and all(row["backendInvocations"] in {0, 1} for row in signature_paths),
        "signature path relation shape drift",
    )
    require(
        sum(row["operation"] == "VALIDATE_TRANSCRIPT" for row in signature_paths)
        == 12
        and sum(row["operation"] == "EVALUATE_GENESIS" for row in signature_paths)
        == 5
        and sum(row["signatureLengthClass"] == "SHORT_0_TO_63" for row in signature_paths)
        == 4
        and sum(row["backendInvocations"] == 1 for row in signature_paths)
        == 6,
        "signature path relation cardinality drift",
    )
    require(
        all(
            row["backendInvocations"] == 0
            for row in signature_paths
            if row["signatureLengthClass"] == "SHORT_0_TO_63"
            or row["keyState"] == "O14_POINT_GUARD_REJECTED"
            or row["signatureState"] == "O14_RS_GUARD_REJECTED"
        )
        and all(
            row["resultMapping"] == "TRS-012"
            for row in signature_paths
            if row["operation"] == "VALIDATE_TRANSCRIPT"
            and row["signatureLengthClass"] == "SHORT_0_TO_63"
        )
        and all(
            row["resultMapping"] == "GRS-012"
            for row in signature_paths
            if row["operation"] == "EVALUATE_GENESIS"
            and row["signatureLengthClass"] == "SHORT_0_TO_63"
        ),
        "signature path ordering or short-signature mapping drift",
    )

    evidence_rejections = set(schema["$defs"]["EvidenceUpdateRejectionV0"]["enum"])
    primary_tokens = set(schema["$defs"]["PrimaryToken"]["enum"])
    require(not evidence_rejections.intersection(primary_tokens), "F16/O-10 token registry collision")
    require(
        "EVIDENCE_COMMITMENT_MISMATCH" in evidence_rejections
        and "COMMITMENT_MISMATCH" not in evidence_rejections,
        "F16 commitment token drift",
    )

    require(repository.is_dir(), f"repository unavailable: {repository}")
    try:
        taxonomy_bytes = subprocess.check_output(
            [
                "git",
                "-C",
                str(repository),
                "show",
                f"{base_ref}:tools/causal-flow-simulator/o10/outcome-taxonomy.json",
            ],
            stderr=subprocess.STDOUT,
        )
        taxonomy = json.loads(taxonomy_bytes)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot load O-10 taxonomy at {base_ref}: {exc}") from exc
    primaries = {row["id"]: row for row in taxonomy["primaries"]}
    f13 = relations["candidateEvaluationPrimaryRelationV0"]
    require(set(row["primary"] for row in f13) == set(primaries), "F13 primary-set drift")
    for row in f13:
        source = primaries[row["primary"]]
        require(row["existingO10Mutation"] == source["mutation"], f"F13 mutation drift: {row['primary']}")
        require(row["existingO10Stage"] == source["stage"], f"F13 stage drift: {row['primary']}")
    stale = next(row for row in f13 if row["primary"] == "STALE_EVIDENCE")
    require(
        stale["existingO10Stage"] == "POST_S3_REPLAY_EVIDENCE"
        and stale["kRetentionEffect"] == "RETAIN_NEW"
        and stale["coreResultKind"] == "PROPOSAL_READY",
        "reserved STALE_EVIDENCE row drift",
    )


def validate_manifest() -> None:
    manifest = load("APP-CORE-IFACE-0-CANDIDATE-MANIFEST.json")
    artifacts = manifest["artifacts"]
    require(len(artifacts) == 26, f"manifest artifact count drift: {len(artifacts)}")
    names = [row["path"] for row in artifacts]
    roles = [row["role"] for row in artifacts]
    require(len(names) == len(set(names)), "duplicate manifest path")
    require(len(roles) == len(set(roles)), "duplicate manifest role")
    expected_entries = set(names) | {"APP-CORE-IFACE-0-CANDIDATE-MANIFEST.json"}
    entries = list(ROOT.iterdir())
    require(
        all(path.is_file() and not path.is_symlink() for path in entries),
        "contract package contains a non-regular entry",
    )
    require(
        {path.name for path in entries} == expected_entries,
        "contract package file-set drift",
    )
    for row in artifacts:
        path = ROOT / row["path"]
        require(path.is_file() and not path.is_symlink(), f"invalid manifest artifact: {row['path']}")
        require(sha256(path) == row["sha256"], f"manifest digest drift: {row['path']}")
    counts = manifest["derivedCounts"]
    expected = {
        "operations": 6,
        "propertyBearingObjectSchemas": 78,
        "directObjectDefinitions": 73,
        "inlineObjectSchemas": 5,
        "properties": 323,
        "directlyRequiredProperties": 322,
        "customKeywordOccurrences": 26,
        "structuralRuleFamilies": 24,
        "structuralExecutionInstances": 1450,
        "oneOfOccurrences": 16,
        "oneOfArms": 54,
        "oneOfPairwiseDisjointnessRows": 93,
        "semanticFamilies": 82,
        "semanticExecutionInstances": 5147,
        "totalExecutionInstances": 6597,
        "contentRelationRows": 23,
        "forkJoinLabelRelationRows": 10,
        "authorityProjectionDimensionRelationRows": 16,
        "graphAdmissionDimensionRelationRows": 10,
        "candidatePrimaryRelationRows": 25,
        "transcriptRelationRows": 16,
        "genesisRelationRows": 17,
        "terminalPredicateRelationRows": 33,
        "signatureVerificationPathRows": 17,
        "nativeDependencies": 63,
        "readOnlyNativeDependencies": 59,
        "seededExtensionNativeDependencies": 4,
        "historicalProviderIncrements": 5,
        "seedRegistryRowsPendingPostBase": 78,
        "structuralWitnessRowsPendingPostBase": 1450,
    }
    require(counts == expected, "manifest derived-count drift")


def validate_documented_artifact_bindings() -> None:
    atom_name = "APP-CORE-IFACE-0-ATOM-DERIVATION-CANDIDATE.md"
    witness_name = "APP-CORE-IFACE-0-WITNESS-GENERATION-CONTRACT.md"
    atom = (ROOT / atom_name).read_text(encoding="utf-8")
    witness = (ROOT / witness_name).read_text(encoding="utf-8")

    reachability = sha256(ROOT / "APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json")
    structural = sha256(ROOT / "APP-CORE-IFACE-0-STRUCTURAL-AXES-CANDIDATE.json")
    one_of = sha256(ROOT / "APP-CORE-IFACE-0-ONEOF-DISJOINTNESS-CANDIDATE.json")
    palette = sha256(ROOT / "APP-CORE-IFACE-0-PERTURBATION-PALETTE-CANDIDATE.json")
    instance_axes = sha256(ROOT / "APP-CORE-IFACE-0-INSTANCE-AXES-CANDIDATE.json")
    execution_phases = sha256(ROOT / "APP-CORE-IFACE-0-EXECUTION-PHASES-CANDIDATE.json")

    required_fragments = {
        atom_name: (
            "`APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json`, SHA-256\n"
            f"`{reachability}`.",
            "The structural axis registry has SHA-256\n"
            f"`{structural}`.",
            "`APP-CORE-IFACE-0-PERTURBATION-PALETTE-CANDIDATE.json`, SHA-256\n"
            f"`{palette}`.",
            "`APP-CORE-IFACE-0-ONEOF-DISJOINTNESS-CANDIDATE.json`, SHA-256\n"
            f"`{one_of}`:",
            "The 82-row instance-axis registry has no unresolved axis and has SHA-256\n"
            f"`{instance_axes}`.",
            "`APP-CORE-IFACE-0-EXECUTION-PHASES-CANDIDATE.json`, SHA-256\n"
            f"`{execution_phases}`.",
        ),
        witness_name: (
            "`APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json`, SHA-256\n"
            f"`{reachability}`.",
            "`APP-CORE-IFACE-0-PERTURBATION-PALETTE-CANDIDATE.json`, SHA-256\n"
            f"`{palette}`.",
        ),
    }
    documents = {atom_name: atom, witness_name: witness}
    for document_name, fragments in required_fragments.items():
        for fragment in fragments:
            require(
                documents[document_name].count(fragment) == 1,
                f"documented artifact binding drift: {document_name}",
            )

    stale_digests = {
        "df80c390b2a0f342210e63cc56023716b88eaff71faccb51f141662c181dc221",
        "e10e4b998df10f4c858c90dee5b564fe306ab820784364cbd86e5db9ae1ed5d8",
        "78fd0ad6d45e34de673005070b0d5645c9fef3281655764806fa622e5be02b02",
        "f9128cf591ef474d8a347864fd6cf865841e0de73e0d7da97b90cd0fed2ff5d1",
        "3f267e1ec254b0d478ec3968e8485adb88f3785332f1926a1676213374fc03d3",
        "b9a1d1e48a2832b672b669ad23a7b396d1b3230d6b64d7f92ec3e032ee3964bc",
    }
    for document_name, document in documents.items():
        require(
            not any(digest in document for digest in stale_digests),
            f"stale documented artifact digest: {document_name}",
        )


def validate_native_dependencies(repository: Path, base_ref: str) -> None:
    subprocess.run(
        [
            "python3",
            str(ROOT / "derive_app_core_native_dependencies.py"),
            "--repository",
            str(repository),
            "--base-ref",
            base_ref,
            "--check",
        ],
        check=True,
    )
    inventory = load("APP-CORE-IFACE-0-NATIVE-DEPENDENCIES-CANDIDATE.json")
    require(
        inventory["baseSha"] == "16274cc194cd2f8f7b631332687a252bad92ce02",
        "native dependency Base drift",
    )
    require(
        inventory["derivedCounts"]
        == {
            "dependencies": 63,
            "readOnlyDependencies": 59,
            "seededExtensionDependencies": 4,
            "c03CanonicalFiles": 6,
            "c03ImplementationAndTestFiles": 24,
            "protocolReviewToolFiles": 16,
        },
        "native dependency count drift",
    )
    rows = inventory["dependencies"]
    paths = [row["path"] for row in rows]
    require(len(paths) == len(set(paths)) == 63, "native dependency path drift")
    require(
        {row["path"] for row in rows if row["mutationPolicy"] != "READ_ONLY_BYTE_IDENTICAL"}
        == set(inventory["seededExtensionPaths"]),
        "native dependency mutation-policy drift",
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--base-ref", default="origin/main")
    parser.add_argument("--verify-provider", action="store_true")
    args = parser.parse_args()
    validate_schema_and_relations(args.repository.resolve(), args.base_ref)
    subprocess.run(
        ["python3", str(ROOT / "derive_app_core_carrier_reachability.py"), "--check"],
        check=True,
    )
    validate_native_dependencies(args.repository.resolve(), args.base_ref)
    if args.verify_provider:
        subprocess.run(
            ["python3", str(ROOT / "validate_app_core_provider_bindings.py")],
            cwd=args.repository.resolve(),
            check=True,
        )
    validate_manifest()
    subprocess.run(
        [
            "python3",
            str(ROOT.parent / "derive_interface_maxima.py"),
            "--check",
        ],
        check=True,
    )
    validate_documented_artifact_bindings()
    print(
        "PASS schemas=4 defs=114 refs=263 enums=35 oneOf=16 arms=54 "
        "pairs=93 objects=78 properties=323 required=322 structural=1450 "
        "semantic=5147 total=6597 terminal=33 F13=25 dependencies=63 provider_history=5 "
        "manifest=26 provider_live=" + ("PASS" if args.verify_provider else "NOT_RUN")
    )


if __name__ == "__main__":
    main()
