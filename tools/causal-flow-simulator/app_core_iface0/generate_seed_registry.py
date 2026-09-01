#!/usr/bin/env python3
"""Generate deterministic positive APP-CORE-IFACE-0 carrier seeds.

The generator is deliberately schema-driven.  It never accepts a caller
supplied expected disposition or a hand-authored coverage waiver.  Response
carriers remain withheld evidence and are not adapter inputs.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema.validators import Draft202012Validator

from canonical_json import dumps
from inventory import InventoryError, _load_json, verify_contract_package


OPERATIONS = (
    "DESCRIBE_PROFILE",
    "VALIDATE_TRANSCRIPT",
    "EVALUATE_GENESIS",
    "REPLAY_CONTEXT",
    "EVALUATE_CANDIDATE",
    "EVALUATE_EVIDENCE_UPDATE",
)
ROOT_ORDER = tuple(
    f"{direction}-{operation}"
    for direction in ("REQUEST", "RESPONSE")
    for operation in OPERATIONS
)


class SeedGenerationError(ValueError):
    """The ratified schema cannot produce the required closed seed relation."""


@dataclass(frozen=True)
class GeneratedCarrier:
    root_id: str
    value: dict[str, Any]
    target_json_pointer: str

    @property
    def canonical_bytes(self) -> bytes:
        return dumps(self.value)


def _escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _unescape(value: str) -> str:
    return value.replace("~1", "/").replace("~0", "~")


def _join(pointer: str, token: str | int) -> str:
    return pointer + "/" + _escape(str(token))


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _resolve_data_pointer(value: Any, pointer: str) -> Any:
    node = value
    if pointer == "":
        return node
    for token in pointer.removeprefix("/").split("/"):
        token = _unescape(token)
        node = node[int(token)] if isinstance(node, list) else node[token]
    return node


def _deep_merge(left: Any, right: Any) -> Any:
    if isinstance(left, dict) and isinstance(right, dict):
        merged = copy.deepcopy(left)
        for key, value in right.items():
            merged[key] = _deep_merge(merged[key], value) if key in merged else copy.deepcopy(value)
        return merged
    if isinstance(left, list) and isinstance(right, list):
        return right if len(right) >= len(left) else left
    return copy.deepcopy(right)


class SchemaSynthesizer:
    """Produce the first bounded valid carrier containing a requested target."""

    def __init__(self, schema: dict[str, Any]) -> None:
        self.schema = schema
        self._contains_cache: dict[tuple[str, str, str], bool] = {}
        self._target_data_pointer: str | None = None

    def resolve(self, pointer: str) -> Any:
        if pointer == "":
            return self.schema
        node: Any = self.schema
        for token in pointer.removeprefix("/").split("/"):
            token = _unescape(token)
            node = node[int(token)] if isinstance(node, list) else node[token]
        return node

    def _data_child(self, token: str | int) -> str:
        return _join(self._current_data_pointer, token)

    def _inline_at(
        self,
        data_pointer: str,
        node: dict[str, Any],
        pointer: str,
        target_pointer: str | None,
        arm_goal: tuple[str, int] | None,
        variant: int,
    ) -> Any:
        previous = self._current_data_pointer
        self._current_data_pointer = data_pointer
        try:
            return self._generate_inline(
                node, pointer, target_pointer, arm_goal, variant
            )
        finally:
            self._current_data_pointer = previous

    def _constrain_at(
        self,
        data_pointer: str,
        value: Any,
        node: dict[str, Any],
        pointer: str,
        target_pointer: str | None,
        arm_goal: tuple[str, int] | None,
        variant: int,
    ) -> Any:
        previous = self._current_data_pointer
        self._current_data_pointer = data_pointer
        try:
            return self._constrain(
                value, node, pointer, target_pointer, arm_goal, variant
            )
        finally:
            self._current_data_pointer = previous

    def _contains(
        self,
        pointer: str,
        target_pointer: str | None,
        arm_goal: tuple[str, int] | None,
        stack: tuple[str, ...] = (),
    ) -> bool:
        target_key = target_pointer or ""
        arm_key = "" if arm_goal is None else f"{arm_goal[0]}#{arm_goal[1]}"
        cache_key = (pointer, target_key, arm_key)
        if cache_key in self._contains_cache:
            return self._contains_cache[cache_key]
        if pointer == target_pointer or (
            arm_goal is not None and pointer == f"{arm_goal[0]}/{arm_goal[1]}"
        ):
            self._contains_cache[cache_key] = True
            return True
        if pointer in stack:
            return False
        node = self.resolve(pointer)
        if not isinstance(node, (dict, list)):
            return False
        if isinstance(node, dict) and isinstance(node.get("$ref"), str):
            reference = node["$ref"].removeprefix("#")
            result = self._contains(reference, target_pointer, arm_goal, stack + (pointer,))
            self._contains_cache[cache_key] = result
            return result
        children: list[str] = []
        if isinstance(node, dict):
            for key, child in node.items():
                if isinstance(child, (dict, list)):
                    children.append(_join(pointer, key))
        else:
            children.extend(_join(pointer, index) for index in range(len(node)))
        result = any(
            self._contains(child, target_pointer, arm_goal, stack + (pointer,))
            for child in children
        )
        self._contains_cache[cache_key] = result
        return result

    def _primitive(self, node: dict[str, Any], variant: int) -> Any:
        if "const" in node:
            return copy.deepcopy(node["const"])
        enum = node.get("enum")
        if isinstance(enum, list) and enum:
            return copy.deepcopy(enum[min(variant, len(enum) - 1)])
        kind = node.get("type")
        if kind == "boolean":
            return False
        if kind == "integer":
            return max(int(node.get("minimum", 0)), variant)
        if kind == "number":
            return max(int(node.get("minimum", 0)), variant)
        if kind == "null":
            return None
        if kind != "string" and not {"pattern", "minLength", "maxLength"}.intersection(node):
            raise SeedGenerationError("schema node has no deterministic primitive recipe")
        pattern = node.get("pattern")
        minimum = int(node.get("minLength", 0))
        if pattern == "^(0|[1-9][0-9]*)$":
            return str(variant)
        if pattern == "^[0-9a-f]{64}$":
            return format(variant % 16, "x") * 64
        if pattern == "^[0-9a-f]{128}$":
            return format(variant % 16, "x") * 128
        if pattern == "^(?:[0-9a-f]{2})*$":
            return format(variant % 256, "02x") * ((minimum + 1) // 2)
        return "0" * max(1, minimum)

    def _force_condition(self, value: Any, condition: dict[str, Any], truth: bool) -> Any:
        if not isinstance(value, dict):
            return value
        validator = Draft202012Validator(
            {
                "$schema": self.schema["$schema"],
                **condition,
                "$defs": self.schema["$defs"],
            }
        )
        currently_true = validator.is_valid(value)
        if currently_true == truth:
            return value
        properties = condition.get("properties")
        required = condition.get("required")
        if truth:
            if isinstance(properties, dict):
                for name, constraint in properties.items():
                    value[name] = self._generate_inline(constraint, "", None, None, 0)
            if isinstance(required, list):
                for name in required:
                    if name not in value:
                        constraint = properties.get(name, {}) if isinstance(properties, dict) else {}
                        value[name] = self._generate_inline(constraint, "", None, None, 0)
        else:
            if isinstance(properties, dict) and properties:
                name, constraint = next(iter(properties.items()))
                if "const" in constraint:
                    constant = constraint["const"]
                    if isinstance(constant, str) and constant.isdecimal():
                        value[name] = str(int(constant) + 1)
                    else:
                        value[name] = "__other__" if isinstance(constant, str) else None
            elif isinstance(required, list) and required:
                value.pop(required[0], None)
        return value

    def _constrain(
        self,
        value: Any,
        node: dict[str, Any],
        pointer: str,
        target_pointer: str | None,
        arm_goal: tuple[str, int] | None,
        variant: int,
    ) -> Any:
        """Apply an allOf/conditional constraint to an already-built value."""

        if pointer == target_pointer or (
            arm_goal is not None and pointer == f"{arm_goal[0]}/{arm_goal[1]}"
        ):
            if self._target_data_pointer is None:
                self._target_data_pointer = self._current_data_pointer
        if "$ref" in node:
            return self._generate(
                node["$ref"].removeprefix("#"), target_pointer, arm_goal, variant
            )
        for keyword in ("oneOf", "anyOf"):
            if keyword in node:
                validator = Draft202012Validator(
                    {
                        "$schema": self.schema["$schema"],
                        **node,
                        "$defs": self.schema["$defs"],
                    }
                )
                if validator.is_valid(value) and not self._contains(
                    pointer, target_pointer, arm_goal
                ):
                    return value
                arm_pointer = _join(pointer, keyword)
                arms = node[keyword]
                selected = next(
                    (
                        index
                        for index in range(len(arms))
                        if self._contains(
                            _join(arm_pointer, index), target_pointer, arm_goal
                        )
                    ),
                    0,
                )
                return self._constrain(
                    value,
                    arms[selected],
                    _join(arm_pointer, selected),
                    target_pointer,
                    arm_goal,
                    variant,
                )
        if isinstance(value, dict):
            forbidden = node.get("not")
            if isinstance(forbidden, dict) and isinstance(forbidden.get("required"), list):
                for name in forbidden["required"]:
                    value.pop(name, None)
            properties = node.get("properties")
            required = node.get("required", [])
            if isinstance(properties, dict):
                for name, constraint in properties.items():
                    child_pointer = _join(_join(pointer, "properties"), name)
                    if name in value or name in required or self._contains(
                        child_pointer, target_pointer, arm_goal
                    ):
                        if name in value:
                            value[name] = self._constrain_at(
                                self._data_child(name),
                                value[name],
                                constraint,
                                child_pointer,
                                target_pointer,
                                arm_goal,
                                variant,
                            )
                        else:
                            value[name] = self._inline_at(
                                self._data_child(name),
                                constraint,
                                child_pointer,
                                target_pointer,
                                arm_goal,
                                variant,
                            )
            if isinstance(required, list):
                for name in required:
                    if name not in value:
                        constraint = properties.get(name, {}) if isinstance(properties, dict) else {}
                        value[name] = self._inline_at(
                            self._data_child(name),
                            constraint,
                            _join(_join(pointer, "properties"), name),
                            target_pointer,
                            arm_goal,
                            variant,
                        )
            return value
        if isinstance(value, list):
            minimum = int(node.get("minItems", 0))
            while len(value) < minimum:
                item_schema = node.get("items")
                if not isinstance(item_schema, dict):
                    property_name = _unescape(pointer.rsplit("/", 1)[-1])
                    fallback = {
                        "contentMaterial": {"$ref": "#/$defs/ContentMaterialEvidenceV0"},
                        "openingMaterial": {"$ref": "#/$defs/OpeningEvidenceV0"},
                    }
                    item_schema = fallback.get(property_name)
                if not isinstance(item_schema, dict):
                    raise SeedGenerationError("array constraint has no item recipe")
                value.append(
                    self._inline_at(
                        self._data_child(len(value)),
                        item_schema, _join(pointer, "items"), None, None, len(value)
                    )
                )
            return value
        if {"const", "enum", "type", "pattern"}.intersection(node):
            return self._generate_inline(node, pointer, target_pointer, arm_goal, variant)
        return value

    def _generate_inline(
        self,
        node: dict[str, Any],
        pointer: str,
        target_pointer: str | None,
        arm_goal: tuple[str, int] | None,
        variant: int,
    ) -> Any:
        if pointer == target_pointer or (
            arm_goal is not None and pointer == f"{arm_goal[0]}/{arm_goal[1]}"
        ):
            if self._target_data_pointer is None:
                self._target_data_pointer = self._current_data_pointer
        if "$ref" in node:
            return self._generate(
                node["$ref"].removeprefix("#"), target_pointer, arm_goal, variant
            )
        if "oneOf" in node:
            one_of_pointer = _join(pointer, "oneOf")
            arms = node["oneOf"]
            selected = 0
            if arm_goal is not None and arm_goal[0] == one_of_pointer:
                selected = arm_goal[1]
            else:
                for index in range(len(arms)):
                    if self._contains(
                        _join(one_of_pointer, index), target_pointer, arm_goal
                    ):
                        selected = index
                        break
            return self._generate_inline(
                arms[selected], _join(one_of_pointer, selected), target_pointer, arm_goal, variant
            )
        if "anyOf" in node:
            any_pointer = _join(pointer, "anyOf")
            selected = next(
                (
                    index
                    for index in range(len(node["anyOf"]))
                    if self._contains(_join(any_pointer, index), target_pointer, arm_goal)
                ),
                0,
            )
            return self._generate_inline(
                node["anyOf"][selected],
                _join(any_pointer, selected),
                target_pointer,
                arm_goal,
                variant,
            )
        if "allOf" in node and not node.get("type") and not node.get("properties"):
            value: Any = None
            for index, arm in enumerate(node["allOf"]):
                arm_pointer = _join(_join(pointer, "allOf"), index)
                if value is None:
                    value = self._generate_inline(
                        arm, arm_pointer, target_pointer, arm_goal, variant
                    )
                else:
                    value = self._constrain(
                        value,
                        arm,
                        arm_pointer,
                        target_pointer,
                        arm_goal,
                        variant,
                    )
            if isinstance(value, list):
                minimum = max(
                    [int(arm.get("minItems", 0)) for arm in node["allOf"] if isinstance(arm, dict)]
                    or [0]
                )
                item_schema = next(
                    (
                        self.resolve(arm["$ref"].removeprefix("#")).get("items")
                        for arm in node["allOf"]
                        if isinstance(arm, dict)
                        and "$ref" in arm
                        and isinstance(self.resolve(arm["$ref"].removeprefix("#")), dict)
                    ),
                    None,
                )
                while len(value) < minimum:
                    if not isinstance(item_schema, dict):
                        raise SeedGenerationError("allOf array has no item recipe")
                    value.append(
                        self._inline_at(
                            self._data_child(len(value)),
                            item_schema,
                            pointer,
                            None,
                            None,
                            len(value),
                        )
                    )
            if isinstance(value, str):
                minimum = int(node.get("minLength", 0))
                if len(value) < minimum:
                    value = "00" * ((minimum + 1) // 2)
                maximum = node.get("maxLength")
                if isinstance(maximum, int) and len(value) > maximum:
                    value = value[:maximum]
            return value
        kind = node.get("type")
        if kind == "object" or isinstance(node.get("properties"), dict):
            value: dict[str, Any] = {}
            properties = node.get("properties", {})
            required = list(node.get("required", []))
            for name in properties:
                child_pointer = _join(_join(pointer, "properties"), name)
                if name in required or self._contains(child_pointer, target_pointer, arm_goal):
                    value[name] = self._inline_at(
                        self._data_child(name),
                        properties[name], child_pointer, target_pointer, arm_goal, variant
                    )
            if (
                pointer == "/$defs/ApplicationEventProjectionV0"
                and arm_goal is not None
                and arm_goal[0] == "/$defs/RoleTailProjectionV0/oneOf"
            ):
                index = arm_goal[1]
                value["eventRole"] = (
                    "ORDINARY"
                    if index == 0
                    else "LOGICAL_REMOVAL"
                    if index == 1
                    else "CREDENTIAL_CONTROL"
                )
            for index, arm in enumerate(node.get("allOf", [])):
                arm_pointer = _join(_join(pointer, "allOf"), index)
                if "if" in arm:
                    then_has = self._contains(
                        _join(arm_pointer, "then"), target_pointer, arm_goal
                    )
                    else_has = self._contains(
                        _join(arm_pointer, "else"), target_pointer, arm_goal
                    ) if "else" in arm else False
                    if then_has:
                        take_then = True
                    elif else_has:
                        take_then = False
                    else:
                        validator = Draft202012Validator(
                            {"$schema": self.schema["$schema"], **arm["if"], "$defs": self.schema["$defs"]}
                        )
                        take_then = validator.is_valid(value)
                    value = self._force_condition(value, arm["if"], take_then)
                    branch_name = "then" if take_then else "else"
                    branch = arm.get(branch_name)
                    if isinstance(branch, dict):
                        value = self._constrain(
                            value,
                            branch,
                            _join(arm_pointer, branch_name),
                            target_pointer,
                            arm_goal,
                            variant,
                        )
                else:
                    value = self._constrain(
                        value,
                        arm,
                        arm_pointer,
                        target_pointer,
                        arm_goal,
                        variant,
                    )
            return value
        if kind == "array":
            minimum = int(node.get("minItems", 0))
            items = node.get("items")
            needs_item = isinstance(items, dict) and self._contains(
                _join(pointer, "items"), target_pointer, arm_goal
            )
            count = max(minimum, 1 if needs_item else 0)
            if count and not isinstance(items, dict):
                raise SeedGenerationError("bounded array has no item schema")
            return [
                self._inline_at(
                    self._data_child(index),
                    items, _join(pointer, "items"), target_pointer, arm_goal, index
                )
                for index in range(count)
            ]
        try:
            return self._primitive(node, variant)
        except SeedGenerationError as error:
            raise SeedGenerationError(f"{error}: {pointer}") from error

    def _generate(
        self,
        pointer: str,
        target_pointer: str | None,
        arm_goal: tuple[str, int] | None,
        variant: int,
    ) -> Any:
        if pointer == target_pointer or (
            arm_goal is not None and pointer == f"{arm_goal[0]}/{arm_goal[1]}"
        ):
            if self._target_data_pointer is None:
                self._target_data_pointer = self._current_data_pointer
        return self._generate_inline(
            self.resolve(pointer), pointer, target_pointer, arm_goal, variant
        )

    def carrier(
        self,
        root: dict[str, Any],
        *,
        target_pointer: str | None = None,
        arm_goal: tuple[str, int] | None = None,
    ) -> GeneratedCarrier:
        wrapper = root["wrapperSchemaPointer"]
        virtual_arm = False
        if arm_goal is not None:
            pointer, index = arm_goal
            operation_index = OPERATIONS.index(root["operation"])
            virtual_arm = (
                pointer == "/oneOf"
                and index == (0 if root["direction"] == "REQUEST" else 1)
            ) or (
                pointer == "/$defs/InterfaceRequestV0/oneOf"
                and root["direction"] == "REQUEST"
                and index == operation_index
            ) or (
                pointer == "/$defs/InterfaceResponseV0/oneOf"
                and root["direction"] == "RESPONSE"
                and index == operation_index
            )
        if not virtual_arm and not self._contains(wrapper, target_pointer, arm_goal):
            raise SeedGenerationError("target is not reachable from selected root")
        self._target_data_pointer = None
        self._current_data_pointer = ""
        value = self._generate_with_data_path(
            wrapper, target_pointer, None if virtual_arm else arm_goal, 0, ""
        )
        if virtual_arm:
            self._target_data_pointer = ""
        if not isinstance(value, dict) or self._target_data_pointer is None:
            raise SeedGenerationError("target did not materialize exactly once")
        validator = Draft202012Validator(
            {
                "$schema": self.schema["$schema"],
                "$ref": f"#{wrapper}",
                "$defs": self.schema["$defs"],
            }
        )
        errors = sorted(validator.iter_errors(value), key=lambda row: list(row.path))
        if errors:
            raise SeedGenerationError(
                "generated carrier is invalid at "
                + "/".join(str(item) for item in errors[0].absolute_path)
                + ": "
                + errors[0].message
            )
        target_schema_pointer = (
            target_pointer
            if target_pointer is not None
            else f"{arm_goal[0]}/{arm_goal[1]}" if arm_goal is not None else wrapper
        )
        target_value = _resolve_data_pointer(value, self._target_data_pointer)
        target_node = self.resolve(target_schema_pointer)
        target_validator = Draft202012Validator(
            {
                "$schema": self.schema["$schema"],
                **target_node,
                "$defs": self.schema["$defs"],
            }
        )
        if not target_validator.is_valid(target_value):
            raise SeedGenerationError("selected target does not validate at its data pointer")
        return GeneratedCarrier(root["rootId"], value, self._target_data_pointer)

    def _generate_with_data_path(
        self,
        pointer: str,
        target_pointer: str | None,
        arm_goal: tuple[str, int] | None,
        variant: int,
        data_pointer: str,
    ) -> Any:
        previous = getattr(self, "_current_data_pointer", "")
        self._current_data_pointer = data_pointer
        try:
            return self._generate(pointer, target_pointer, arm_goal, variant)
        finally:
            self._current_data_pointer = previous


def _ordered_roots(reachability: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = {row["rootId"]: row for row in reachability["roots"]}
    if set(rows) != set(ROOT_ORDER):
        raise SeedGenerationError("root relation drift")
    return rows


def prove_reachability(contract: Path) -> dict[str, int]:
    """Materialize and validate one deterministic carrier per coverage target."""

    verify_contract_package(contract)
    schema = _load_json(contract / "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json")
    reachability = _load_json(
        contract / "APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json"
    )
    roots = _ordered_roots(reachability)
    synthesizer = SchemaSynthesizer(schema)
    object_count = 0
    for row in reachability["objectCoverage"]:
        eligible = sorted(row["eligibleRootIds"], key=ROOT_ORDER.index)
        try:
            synthesizer.carrier(
                roots[eligible[0]], target_pointer=row["objectSchemaPointer"]
            )
        except SeedGenerationError as error:
            raise SeedGenerationError(
                f"object carrier failed for {row['objectSchemaPointer']}: {error}"
            ) from error
        object_count += 1
    arm_count = 0
    for row in reachability["oneOfArmCoverage"]:
        eligible = sorted(row["eligibleRootIds"], key=ROOT_ORDER.index)
        try:
            synthesizer.carrier(
                roots[eligible[0]],
                arm_goal=(row["oneOfPointer"], int(row["armIndex"])),
            )
        except SeedGenerationError as error:
            raise SeedGenerationError(
                f"union carrier failed for {row['oneOfPointer']}#{row['armIndex']}: {error}"
            ) from error
        arm_count += 1
    if object_count != 78 or arm_count != 54:
        raise SeedGenerationError("carrier coverage count drift")
    return {"object_schema_count": object_count, "one_of_arm_count": arm_count}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--prove-reachability", action="store_true")
    args = parser.parse_args(argv)
    if not args.prove_reachability:
        print("seed registry output mode is not yet selected", file=sys.stderr)
        return 2
    try:
        result = prove_reachability(args.contract.resolve())
    except (InventoryError, OSError, SeedGenerationError) as error:
        print(f"APP-core seed generation: FAIL: {error}", file=sys.stderr)
        return 2
    print(
        "APP-core seed generation: PASS "
        f"objects={result['object_schema_count']} arms={result['one_of_arm_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
