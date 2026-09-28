#!/usr/bin/env python3
"""Derive APP-CORE-IFACE-0 positive-carrier reachability from exact schema bytes.

This is planning evidence only. Reachability does not prove that a positive
carrier exists or satisfies semantic preconditions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
SCHEMA_PATH = ROOT / "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json"
OUTPUT_PATH = ROOT / "APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json"

OPERATIONS = (
    ("DESCRIBE_PROFILE", "DescribeProfile"),
    ("VALIDATE_TRANSCRIPT", "ValidateTranscript"),
    ("EVALUATE_GENESIS", "EvaluateGenesis"),
    ("REPLAY_CONTEXT", "ReplayContext"),
    ("EVALUATE_CANDIDATE", "EvaluateCandidate"),
    ("EVALUATE_EVIDENCE_UPDATE", "EvaluateEvidenceUpdate"),
)


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def escape_pointer_token(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def resolve_local_ref(schema: dict[str, Any], ref: str) -> tuple[Any, str]:
    if not ref.startswith("#/"):
        raise SystemExit(f"non-local ref: {ref}")
    current: Any = schema
    for encoded in ref[2:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        current = current[token]
    return current, ref[1:]


def collect_reachable(
    schema: dict[str, Any], node: Any, pointer: str
) -> tuple[set[str], set[str], set[tuple[str, int]]]:
    definitions: set[str] = set()
    objects: set[str] = set()
    arms: set[tuple[str, int]] = set()
    visited_refs: set[str] = set()

    def visit(value: Any, path: str) -> None:
        if isinstance(value, dict):
            if path.startswith("/$defs/") and path.count("/") == 2:
                definitions.add(path)
            if (
                value.get("additionalProperties") is False
                and isinstance(value.get("properties"), dict)
                and value["properties"]
            ):
                objects.add(path)
            one_of = value.get("oneOf")
            if isinstance(one_of, list):
                for index in range(len(one_of)):
                    arms.add((path + "/oneOf", index))
            for key, child in value.items():
                if key == "$ref":
                    _, ref_pointer = resolve_local_ref(schema, child)
                    if ref_pointer not in visited_refs:
                        visited_refs.add(ref_pointer)
                        target, _ = resolve_local_ref(schema, child)
                        visit(target, ref_pointer)
                else:
                    visit(child, path + "/" + escape_pointer_token(key))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, path + "/" + str(index))

    visit(node, pointer)
    return definitions, objects, arms


def arm_key(pointer: str, index: int) -> str:
    return f"{pointer}#{index}"


def digest_lines(values: list[str]) -> str:
    return sha256_bytes(("".join(value + "\n" for value in sorted(values))).encode())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail unless the existing output is byte-identical; do not write",
    )
    args = parser.parse_args()
    schema_bytes = SCHEMA_PATH.read_bytes()
    schema = json.loads(schema_bytes)
    roots: list[dict[str, Any]] = []

    interface_unions = {
        "REQUEST": ("InterfaceRequestV0", 0),
        "RESPONSE": ("InterfaceResponseV0", 1),
    }

    for direction, prefix in (("REQUEST", "OperationRequest"), ("RESPONSE", "OperationResponse")):
        interface_name, root_arm = interface_unions[direction]
        interface_arms = schema["$defs"][interface_name]["oneOf"]
        for operation, suffix in OPERATIONS:
            wrapper_name = prefix + suffix + "V0"
            expected_ref = f"#/$defs/{wrapper_name}"
            matches = [
                index for index, arm in enumerate(interface_arms) if arm.get("$ref") == expected_ref
            ]
            if len(matches) != 1:
                raise SystemExit(f"operation arm mismatch: {direction} {operation} {matches}")
            definitions, objects, arms = collect_reachable(
                schema, schema["$defs"][wrapper_name], f"/$defs/{wrapper_name}"
            )
            definitions.add(f"/$defs/{interface_name}")
            arms.add(("/oneOf", root_arm))
            arms.add((f"/$defs/{interface_name}/oneOf", matches[0]))
            root_id = f"{direction}-{operation}"
            roots.append(
                {
                    "rootId": root_id,
                    "direction": direction,
                    "operation": operation,
                    "wrapperSchemaPointer": f"/$defs/{wrapper_name}",
                    "eligibleDefinitionPointers": sorted(definitions),
                    "eligibleObjectSchemaPointers": sorted(objects),
                    "eligibleOneOfArms": [
                        {"oneOfPointer": pointer, "armIndex": index}
                        for pointer, index in sorted(arms)
                    ],
                }
            )

    definition_to_roots: dict[str, list[str]] = {}
    object_to_roots: dict[str, list[str]] = {}
    arm_to_roots: dict[str, list[str]] = {}
    for root in roots:
        for pointer in root["eligibleDefinitionPointers"]:
            definition_to_roots.setdefault(pointer, []).append(root["rootId"])
        for pointer in root["eligibleObjectSchemaPointers"]:
            object_to_roots.setdefault(pointer, []).append(root["rootId"])
        for arm in root["eligibleOneOfArms"]:
            key = arm_key(arm["oneOfPointer"], arm["armIndex"])
            arm_to_roots.setdefault(key, []).append(root["rootId"])

    definition_pointers = sorted(definition_to_roots)
    object_pointers = sorted(object_to_roots)
    arm_keys = sorted(arm_to_roots)
    if (
        len(roots) != 12
        or len(definition_pointers) != 124
        or len(object_pointers) != 87
        or len(arm_keys) != 57
    ):
        raise SystemExit(
            f"unexpected reachability closure: roots={len(roots)} "
            f"definitions={len(definition_pointers)} objects={len(object_pointers)} "
            f"arms={len(arm_keys)}"
        )

    result = {
        "reachabilityVersion": "APP-CORE-IFACE-0-CARRIER-REACHABILITY-V1",
        "status": "PRE_RATIFICATION_PLANNING_EVIDENCE",
        "authorityEffect": "NONE",
        "schema": SCHEMA_PATH.name,
        "schemaSha256": sha256_bytes(schema_bytes),
        "definitionPointerSetSha256": digest_lines(definition_pointers),
        "objectSchemaPointerSetSha256": digest_lines(object_pointers),
        "oneOfArmEncoding": "lexicographically sorted <oneOfPointer>#<decimal-arm-index> plus LF",
        "oneOfArmSetSha256": digest_lines(arm_keys),
        "rootCount": len(roots),
        "definitionCount": len(definition_pointers),
        "objectSchemaCount": len(object_pointers),
        "oneOfArmCount": len(arm_keys),
        "roots": roots,
        "definitionCoverage": [
            {"definitionPointer": pointer, "eligibleRootIds": sorted(definition_to_roots[pointer])}
            for pointer in definition_pointers
        ],
        "objectCoverage": [
            {"objectSchemaPointer": pointer, "eligibleRootIds": sorted(object_to_roots[pointer])}
            for pointer in object_pointers
        ],
        "oneOfArmCoverage": [
            {
                "oneOfPointer": key.rsplit("#", 1)[0],
                "armIndex": int(key.rsplit("#", 1)[1]),
                "eligibleRootIds": sorted(arm_to_roots[key]),
            }
            for key in arm_keys
        ],
        "nonClaim": "Reachability is not positive-carrier existence, semantic validity, oracle independence or execution evidence.",
    }
    output_bytes = json.dumps(result, ensure_ascii=False, indent=2).encode() + b"\n"
    if args.check:
        if not OUTPUT_PATH.is_file() or OUTPUT_PATH.read_bytes() != output_bytes:
            raise SystemExit("carrier reachability output drift")
    else:
        OUTPUT_PATH.write_bytes(output_bytes)
    print(
        f"PASS roots={len(roots)} definitions={len(definition_pointers)} "
        f"objects={len(object_pointers)} arms={len(arm_keys)} "
        f"sha256={sha256_bytes(output_bytes)}"
    )


if __name__ == "__main__":
    main()
