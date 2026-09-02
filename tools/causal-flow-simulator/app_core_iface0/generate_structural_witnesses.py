#!/usr/bin/env python3
"""Derive the immutable structural-instance plan before Phase-B synthesis."""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from jsonschema.validators import Draft202012Validator

from canonical_json import CanonicalJsonError, dumps, loads
from canonical_report import ReportError, store_report
from generate_seed_registry import (
    OPERATIONS,
    ROOT_ORDER,
    SchemaSynthesizer,
    _resolve_data_pointer,
)
from inventory import (
    InventoryError,
    STRUCTURAL_COUNT,
    _load_json,
    digest_lines,
    expand_structural_instances,
    sha256_bytes,
    verify_contract_package,
)
from validate_inventory import validate_phase_a


PLAN_FIELDS = frozenset(
    {
        "instance_count",
        "instance_set_sha256",
        "rows",
        "schema",
        "verdict",
    }
)

SEED_COUNT = 78
OPERATION_ORDER = {operation: index for index, operation in enumerate(OPERATIONS)}


def _unescape(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _join(pointer: str, token: str) -> str:
    return pointer + "/" + _escape(token)


def _canonical_object(path: Path) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or path.is_symlink():
        raise WitnessGenerationError("Phase-A carrier is absent or non-regular")
    raw = path.read_bytes()
    try:
        value = loads(raw)
    except CanonicalJsonError as error:
        raise WitnessGenerationError("Phase-A carrier is not canonical JSON") from error
    if not isinstance(value, dict) or dumps(value) != raw:
        raise WitnessGenerationError("Phase-A carrier is not a canonical object")
    return value, raw


def _schema_validator(schema: dict[str, Any], node: dict[str, Any]) -> Draft202012Validator:
    return Draft202012Validator(
        {"$schema": schema["$schema"], **node, "$defs": schema["$defs"]}
    )


def _validate_plan_identifier_schemas(
    contract: Path, rows: list[dict[str, str]]
) -> None:
    """Validate every derived identifier against its field-specific schema."""

    schema = _load_json(
        contract / "APP-CORE-IFACE-0-STRUCTURAL-WITNESS-SCHEMA-CANDIDATE.json"
    )
    definitions = schema["$defs"]
    fields = {
        "assertionId": "AssertionId",
        "mutationId": "MutationId",
        "detectorId": "DetectorId",
    }
    validators = {
        field: Draft202012Validator(
            {"$schema": schema["$schema"], **definitions[definition]}
        )
        for field, definition in fields.items()
    }
    for row in rows:
        for field, validator in validators.items():
            if not validator.is_valid(row.get(field)):
                raise WitnessGenerationError(
                    f"derived structural {field} violates its exact schema"
                )


def validate_structural_witness_identifiers(registry: dict[str, Any]) -> None:
    """Recompute all derived IDs before consuming a stored witness registry."""

    rows = registry.get("rows")
    if not isinstance(rows, list):
        raise WitnessGenerationError("stored witness rows are absent")
    for row in rows:
        if not isinstance(row, dict):
            raise WitnessGenerationError("stored witness row is malformed")
        rule_id = row.get("structuralRuleId")
        instance_id = row.get("instanceId")
        if not isinstance(rule_id, str) or not rule_id.startswith("STR-"):
            raise WitnessGenerationError("stored witness structural rule ID drift")
        prefix = rule_id + "--"
        if not isinstance(instance_id, str) or not instance_id.startswith(prefix):
            raise WitnessGenerationError("stored witness instance ID drift")
        index = instance_id[len(prefix) :]
        if len(index) != 4 or not index.isdecimal():
            raise WitnessGenerationError("stored witness instance index drift")
        suffix = rule_id.removeprefix("STR-")
        expected = {
            "assertionId": f"AST-{suffix}--{index}",
            "mutationId": f"MUT-{suffix}--{index}",
            "detectorId": f"DET-{suffix}--{index}",
        }
        for field, value in expected.items():
            if row.get(field) != value:
                raise WitnessGenerationError(f"stored witness {field} drift")


def _root_rows(reachability: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows = reachability.get("roots")
    if not isinstance(rows, list) or len(rows) != 12:
        raise WitnessGenerationError("carrier-root relation drift")
    result = {row.get("rootId"): row for row in rows if isinstance(row, dict)}
    if set(result) != set(ROOT_ORDER):
        raise WitnessGenerationError("carrier-root identity drift")
    return result


def _load_phase_a(
    repo_root: Path, contract: Path, evidence_root: Path
) -> tuple[dict[str, Any], bytes, dict[str, tuple[dict[str, Any], bytes]]]:
    """Load provider-shaped Phase-A bytes after the complete package validator."""

    validate_phase_a(repo_root, contract, evidence_root)
    inventory, inventory_bytes = _canonical_object(
        evidence_root / "positive-carrier-inventory.json"
    )
    cases = inventory.get("cases")
    if not isinstance(cases, list) or len(cases) != 80:
        raise WitnessGenerationError("positive carrier inventory count drift")
    carriers: dict[str, tuple[dict[str, Any], bytes]] = {}
    for row in cases:
        if not isinstance(row, dict) or not isinstance(row.get("caseId"), str):
            raise WitnessGenerationError("positive carrier row is malformed")
        case_id = row["caseId"]
        if case_id in carriers:
            raise WitnessGenerationError("positive carrier case ID is duplicated")
        value, raw = _canonical_object(evidence_root / row["carrierFile"])
        if (
            len(raw) != row.get("carrierOctets")
            or sha256_bytes(raw) != row.get("carrierSha256")
            or value.get("operation") != row.get("operation")
        ):
            raise WitnessGenerationError("positive carrier identity drift")
        carriers[case_id] = (value, raw)
    return inventory, inventory_bytes, carriers


def _candidate_key(row: dict[str, Any], target_pointer: str, target_sha: str) -> tuple[Any, ...]:
    direction = row["direction"]
    return (
        0 if direction == "REQUEST" else 1,
        OPERATION_ORDER[row["operation"]],
        row["caseId"].encode("utf-8"),
        target_pointer.encode("utf-8"),
        row["carrierSha256"],
        target_sha,
    )


def _direct_structural_families(
    object_pointer: str, structural_rows: list[Any]
) -> set[str]:
    """Return families whose literal schema occurrence is inside this object."""

    prefix = object_pointer + "/"
    result = {
        row.family_id
        for row in structural_rows
        if row.source == object_pointer or row.source.startswith(prefix)
    }
    # Every property-bearing object has a literal duplicate-member instance.
    if "STR-DUPLICATE-JSON-PROPERTY" not in result:
        raise WitnessGenerationError("object seed lacks duplicate-member ownership")
    return result


def derive_seed_registry(
    repo_root: Path,
    contract: Path,
    evidence_root: Path,
) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Derive the exact 78-row canonical object seed registry.

    The function accepts an external Phase-A candidate package, so repository
    tests can use a test-local population while the production final gate can
    require provider-bound bytes without changing the derivation algorithm.
    """

    verify_contract_package(contract)
    inventory, inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    schema_path = contract / "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json"
    schema = _load_json(schema_path)
    reachability = _load_json(
        contract / "APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json"
    )
    roots = _root_rows(reachability)
    synthesizer = SchemaSynthesizer(schema)
    cases = {row["caseId"]: row for row in inventory["cases"]}
    structural = expand_structural_instances(contract)
    object_pointers = sorted(
        (row["objectSchemaPointer"] for row in reachability["objectCoverage"]),
        key=lambda value: value.encode("utf-8"),
    )
    if len(object_pointers) != SEED_COUNT or len(set(object_pointers)) != SEED_COUNT:
        raise WitnessGenerationError("object-schema relation drift")

    rows: list[dict[str, Any]] = []
    for ordinal, object_pointer in enumerate(object_pointers, 1):
        object_schema = synthesizer.resolve(object_pointer)
        if not isinstance(object_schema, dict):
            raise WitnessGenerationError("object-schema pointer is not an object")
        candidates: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        for case in inventory["cases"]:
            if object_pointer not in case["coveredObjectSchemaPointers"]:
                continue
            root = roots[f"{case['direction']}-{case['operation']}"]
            carrier, carrier_bytes = carriers[case["caseId"]]
            for target_pointer in synthesizer.target_locations(
                root, carrier, object_pointer
            ):
                target = _resolve_data_pointer(carrier, target_pointer)
                if not isinstance(target, dict) or not _schema_validator(
                    schema, object_schema
                ).is_valid(target):
                    raise WitnessGenerationError("seed target fails its object schema")
                target_sha = sha256_bytes(dumps(target))
                row = {
                    "objectSchemaId": f"OBJ-{ordinal:04d}",
                    "objectSchemaPointer": object_pointer,
                    "objectSchemaSha256": sha256_bytes(dumps(object_schema)),
                    "carrierCaseId": case["caseId"],
                    "carrierDirection": case["direction"],
                    "disclosureClass": (
                        "BLIND_INPUT"
                        if case["direction"] == "REQUEST"
                        else "WITHHELD_ORACLE"
                    ),
                    "operation": case["operation"],
                    "carrierFile": case["carrierFile"],
                    "carrierSha256": sha256_bytes(carrier_bytes),
                    "carrierOctets": len(carrier_bytes),
                    "targetJsonPointer": target_pointer,
                    "targetCanonicalJsonSha256": target_sha,
                    "positiveObservationId": case["positiveObservationId"],
                    "structuralFamilyIds": sorted(
                        _direct_structural_families(object_pointer, structural)
                    ),
                }
                candidates.append((_candidate_key(case, target_pointer, target_sha), row))
        if not candidates:
            raise WitnessGenerationError(f"object schema has no eligible carrier: {object_pointer}")
        rows.append(min(candidates, key=lambda item: item[0])[1])

    registry = {
        "registryVersion": "APP-CORE-IFACE-0-SEEDS-V1",
        "status": "PRE_RATIFICATION_CANDIDATE",
        "interfaceSchemaSha256": sha256_bytes(schema_path.read_bytes()),
        "positiveCarrierInventorySha256": sha256_bytes(inventory_bytes),
        "objectSchemaPointerSetSha256": digest_lines(object_pointers),
        "rowCount": SEED_COUNT,
        "rows": rows,
    }
    registry_schema = _load_json(
        contract / "APP-CORE-IFACE-0-SEED-REGISTRY-SCHEMA-CANDIDATE.json"
    )
    if list(Draft202012Validator(registry_schema).iter_errors(registry)):
        raise WitnessGenerationError("derived seed registry fails its closed schema")
    return registry, cases


_PARENT_KEYWORD_FAMILIES = frozenset(
    {
        "STR-UNKNOWN-OBJECT-PROPERTY",
        "STR-TYPE-MISMATCH",
        "STR-REF-TARGET-CONSTRAINT",
        "STR-CONST-SUBSTITUTION",
        "STR-UNKNOWN-ENUM-VALUE",
        "STR-PATTERN-MISMATCH",
        "STR-MIN-LENGTH-UNDERFLOW",
        "STR-MAX-LENGTH-OVERFLOW",
        "STR-MIN-ITEMS-UNDERFLOW",
        "STR-MAX-ITEMS-OVERFLOW",
        "STR-UNIQUE-ITEMS-DUPLICATE",
        "STR-ITEM-CONSTRAINT-VIOLATION",
        "STR-ONE-OF-NO-ARM",
        "STR-ANY-OF-NO-ARM",
        "STR-ANY-OF-ALL-ARMS",
        "STR-NOT-SUBSCHEMA-MATCH",
        "STR-MAX-PROPERTIES-OVERFLOW",
    }
)

_PARENT_RESOLVED_ARRAY_INSERTION_FAMILIES = frozenset(
    {
        "STR-ALL-OF-BRANCH-CONSTRAINT",
        "STR-MIN-ITEMS-UNDERFLOW",
        "STR-REF-TARGET-CONSTRAINT",
    }
)


def _instance_schema_target(instance: Any) -> tuple[str, str, str | None]:
    """Map a structural source identity to its constrained data location."""

    family = instance.family_id
    source = instance.source
    if family == "STR-REQUIRED-PROPERTY-OMISSION":
        marker = "/required/"
        if marker not in source:
            raise WitnessGenerationError("required-property source identity drift")
        owner, property_token = source.rsplit(marker, 1)
        return "REQUIRED_PROPERTY", owner, _unescape(property_token)
    if family == "STR-CONDITIONAL-BRANCH-MATRIX":
        return "SCHEMA", "/$defs/ApplicationEventProjectionV0", None
    if family == "STR-ONE-OF-POSITIVE-ARM":
        if "#" not in source:
            raise WitnessGenerationError("oneOf-arm source identity drift")
        pointer, arm = source.rsplit("#", 1)
        if not arm.isdecimal():
            raise WitnessGenerationError("oneOf-arm index is not decimal")
        return "SCHEMA", f"{pointer}/{arm}", None
    if family in _PARENT_KEYWORD_FAMILIES:
        if "/" not in source:
            raise WitnessGenerationError("keyword source has no schema parent")
        return "SCHEMA", source.rsplit("/", 1)[0], None
    # Declared properties, complete object occurrences and applicator arms are
    # already literal schema pointers.
    return "SCHEMA", source, None


def _witness_target_locations(
    synthesizer: SchemaSynthesizer,
    root: dict[str, Any],
    carrier: dict[str, Any],
    instance: Any,
    prospective_cache: dict[tuple[str, str, str, str | None], list[str]],
) -> list[str]:
    if instance.family_id == "STR-ONE-OF-NO-ARM":
        if instance.source == "/oneOf":
            return [""]
        if (
            instance.source == "/$defs/InterfaceRequestV0/oneOf"
            and root["direction"] == "REQUEST"
        ) or (
            instance.source == "/$defs/InterfaceResponseV0/oneOf"
            and root["direction"] == "RESPONSE"
        ):
            return [""]
    mode, schema_pointer, property_name = _instance_schema_target(instance)
    if mode == "SCHEMA":
        direct = synthesizer.target_locations(root, carrier, schema_pointer)
        if direct:
            return direct
        # A constraint inside an `if` predicate is not visited by
        # SchemaSynthesizer.target_locations(), which follows only the active
        # then/else branch.  Bind its direct property to an actually
        # materialized enclosing object instead of fabricating a path.
        conditional_marker = "/if/properties/"
        if conditional_marker in schema_pointer and "/allOf/" in schema_pointer:
            owner_pointer = schema_pointer.split("/allOf/", 1)[0]
            property_tail = schema_pointer.split(conditional_marker, 1)[1]
            if "/" not in property_tail:
                property_name = _unescape(property_tail)
                result = []
                for owner in synthesizer.target_locations(
                    root, carrier, owner_pointer
                ):
                    owner_value = _resolve_data_pointer(carrier, owner)
                    if isinstance(owner_value, dict) and property_name in owner_value:
                        result.append(_join(owner, property_name))
                if result:
                    return sorted(
                        set(result), key=lambda value: value.encode("utf-8")
                    )
        # Optional declared properties need not occur in a positive carrier.
        # Their hostile witness inserts the selected palette value at the
        # otherwise exact property location; the containing object remains the
        # provider-bound positive seed.  Only a direct declared-property edge
        # is inferred here -- deeper absent shapes require an explicit carrier.
        marker = "/properties/"
        if marker in schema_pointer:
            owner_pointer, remainder = schema_pointer.split(marker, 1)
            if "/" not in remainder:
                property_name = _unescape(remainder)
                result = []
                for owner in synthesizer.target_locations(
                    root, carrier, owner_pointer
                ):
                    result.append(_join(owner, property_name))
                if result:
                    return sorted(set(result), key=lambda value: value.encode("utf-8"))
        # A prospective schema path is not by itself evidence that a positive
        # carrier contains the target.  An insertion at the next array index is
        # eligible only for the three structural families that explicitly
        # construct an item value and only when the exact parent array exists.
        # This covers an empty optional array without permitting deeper absent
        # shapes or a lexicographically early carrier with a missing parent.
        if instance.family_id in _PARENT_RESOLVED_ARRAY_INSERTION_FAMILIES:
            key = (root["rootId"], mode, schema_pointer, property_name)
            if key not in prospective_cache:
                prospective_cache[key] = _prospective_target_locations(
                    synthesizer, root, mode, schema_pointer, property_name
                )
            eligible = []
            for target in prospective_cache[key]:
                if "/" not in target:
                    continue
                parent_pointer, index_token = target.rsplit("/", 1)
                try:
                    parent = _resolve_data_pointer(carrier, parent_pointer)
                except (KeyError, IndexError, TypeError, ValueError):
                    continue
                if (
                    isinstance(parent, list)
                    and index_token.isdecimal()
                    and int(index_token) == len(parent)
                ):
                    eligible.append(target)
            if eligible:
                return sorted(set(eligible), key=lambda value: value.encode("utf-8"))
        return []
    result: list[str] = []
    for owner_pointer in synthesizer.target_locations(root, carrier, schema_pointer):
        owner = _resolve_data_pointer(carrier, owner_pointer)
        if isinstance(owner, dict) and property_name in owner:
            result.append(_join(owner_pointer, property_name))
    return sorted(set(result), key=lambda value: value.encode("utf-8"))


def _prospective_target_locations(
    synthesizer: SchemaSynthesizer,
    root: dict[str, Any],
    mode: str,
    target_schema_pointer: str,
    property_name: str | None,
) -> list[str]:
    """Derive bounded insertion paths for targets absent from a positive case.

    Applicators and references do not consume data-path components; object
    properties consume their literal member and array items use the first
    bounded element.  This is the contract's bounded deep-replacement path
    order, not a fabricated positive carrier.
    """

    result: set[str] = set()

    def visit(
        pointer: str,
        node: Any,
        data_pointer: str,
        active: frozenset[tuple[str, str]],
    ) -> None:
        if not isinstance(node, dict):
            return
        marker = (pointer, data_pointer)
        if marker in active:
            return
        nested = active | {marker}
        if pointer == target_schema_pointer:
            result.add(
                _join(data_pointer, property_name)
                if mode == "REQUIRED_PROPERTY" and property_name is not None
                else data_pointer
            )
        reference = node.get("$ref")
        if isinstance(reference, str) and reference.startswith("#/"):
            resolved = reference.removeprefix("#")
            visit(
                resolved,
                synthesizer.resolve(resolved),
                data_pointer,
                nested,
            )
        properties = node.get("properties")
        if isinstance(properties, dict):
            for name, child in properties.items():
                visit(
                    f"{pointer}/properties/{_escape(name)}",
                    child,
                    _join(data_pointer, name),
                    nested,
                )
        items = node.get("items")
        if isinstance(items, dict):
            visit(f"{pointer}/items", items, data_pointer + "/0", nested)
        for keyword in ("allOf", "anyOf", "oneOf"):
            arms = node.get(keyword)
            if isinstance(arms, list):
                for index, arm in enumerate(arms):
                    visit(f"{pointer}/{keyword}/{index}", arm, data_pointer, nested)
        for keyword in ("if", "then", "else", "not"):
            child = node.get(keyword)
            if isinstance(child, dict):
                visit(f"{pointer}/{keyword}", child, data_pointer, nested)

    wrapper = root["wrapperSchemaPointer"]
    visit(wrapper, synthesizer.resolve(wrapper), "", frozenset())
    return sorted(result, key=lambda value: value.encode("utf-8"))


def _data_pointer_contains(owner: str, target: str) -> bool:
    return owner == "" or target == owner or target.startswith(owner + "/")


def _owning_seed_id(
    target_pointer: str,
    object_locations: list[tuple[str, str]],
    seed_id_by_pointer: dict[str, str],
) -> str:
    """Select the deepest property-bearing schema enclosing one data target."""

    candidates: list[tuple[int, bytes, bytes, str]] = []
    for object_pointer, owner_pointer in object_locations:
        seed_id = seed_id_by_pointer.get(object_pointer)
        if seed_id is None:
            raise WitnessGenerationError("carrier names an unknown object schema")
        if _data_pointer_contains(owner_pointer, target_pointer):
            candidates.append(
                (
                    -len(owner_pointer.split("/")),
                    owner_pointer.encode("utf-8"),
                    object_pointer.encode("utf-8"),
                    seed_id,
                )
            )
    if not candidates:
        raise WitnessGenerationError("hostile target has no enclosing object seed")
    return min(candidates)[3]


def _expected_execution(
    axes: dict[str, Any], direction: str, disposition: str
) -> tuple[str, str, str]:
    key = direction.lower()
    relation = axes["executionContract"].get(key)
    if not isinstance(relation, dict):
        raise WitnessGenerationError("execution contract direction drift")
    observation = relation[
        "acceptObservation" if disposition == "ACCEPT" else "rejectObservation"
    ]
    return relation["oracleDisclosure"], relation["executionPhase"], observation


def derive_phase_b_registries(
    repo_root: Path,
    contract: Path,
    evidence_root: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Derive the candidate seed and complete 1,450-row witness registries."""

    seed_registry, case_rows = derive_seed_registry(
        repo_root, contract, evidence_root
    )
    _inventory, _inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    schema_path = contract / "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json"
    schema = _load_json(schema_path)
    reachability = _load_json(
        contract / "APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json"
    )
    roots = _root_rows(reachability)
    synthesizer = SchemaSynthesizer(schema)
    axes_path = contract / "APP-CORE-IFACE-0-STRUCTURAL-AXES-CANDIDATE.json"
    axes = _load_json(axes_path)
    rules = {row["id"]: row for row in axes["rules"]}
    instances = expand_structural_instances(contract)
    seed_by_id = {row["objectSchemaId"]: row for row in seed_registry["rows"]}
    if len(seed_by_id) != SEED_COUNT:
        raise WitnessGenerationError("seed object-schema ID relation drift")
    seed_id_by_pointer = {
        row["objectSchemaPointer"]: row["objectSchemaId"]
        for row in seed_registry["rows"]
    }
    object_locations_by_case: dict[str, list[tuple[str, str]]] = {}
    for case in case_rows.values():
        carrier, _raw = carriers[case["caseId"]]
        root = roots[f"{case['direction']}-{case['operation']}"]
        locations: list[tuple[str, str]] = []
        for object_pointer in case["coveredObjectSchemaPointers"]:
            locations.extend(
                (object_pointer, data_pointer)
                for data_pointer in synthesizer.target_locations(
                    root, carrier, object_pointer
                )
            )
        if not locations:
            raise WitnessGenerationError("positive carrier has no object locations")
        object_locations_by_case[case["caseId"]] = locations

    witness_rows: list[dict[str, Any]] = []
    assigned_families = {
        seed_id: set(row["structuralFamilyIds"])
        for seed_id, row in seed_by_id.items()
    }
    prospective_cache: dict[tuple[str, str, str, str | None], list[str]] = {}
    missing_instances: list[str] = []
    for instance in instances:
        candidates: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        for case in case_rows.values():
            carrier, _raw = carriers[case["caseId"]]
            root = roots[f"{case['direction']}-{case['operation']}"]
            for target_pointer in _witness_target_locations(
                synthesizer, root, carrier, instance, prospective_cache
            ):
                seed_id = _owning_seed_id(
                    target_pointer,
                    object_locations_by_case[case["caseId"]],
                    seed_id_by_pointer,
                )
                key = (
                    0 if case["direction"] == "REQUEST" else 1,
                    OPERATION_ORDER[case["operation"]],
                    case["caseId"].encode("utf-8"),
                    target_pointer.encode("utf-8"),
                    seed_id,
                )
                disclosure, phase, observation = _expected_execution(
                    axes, case["direction"], instance.expected_disposition
                )
                rule = rules.get(instance.family_id)
                if rule is None:
                    raise WitnessGenerationError("structural witness has no rule")
                row = {
                    "instanceId": instance.instance_id,
                    "structuralRuleId": instance.family_id,
                    "sourcePointerOrRowId": instance.source,
                    "seedObjectSchemaId": seed_id,
                    "carrierCaseId": case["caseId"],
                    "carrierDirection": case["direction"],
                    "disclosureClass": disclosure,
                    "executionPhase": phase,
                    "targetJsonPointer": target_pointer,
                    "perturbationKind": rule["perturbationKind"],
                    "isolationMode": rule.get(
                        "isolationMode", axes["executionContract"]["defaultIsolationMode"]
                    ),
                    "expectedDisposition": instance.expected_disposition,
                    "expectedObservation": observation,
                    "assertionId": instance.assertion_id,
                    "mutationId": instance.perturbation_id.replace("PRT-", "MUT-", 1),
                    "detectorId": instance.detector_id,
                }
                candidates.append((key, row))
        if not candidates:
            missing_instances.append(instance.instance_id)
            continue
        chosen = min(candidates, key=lambda item: item[0])[1]
        witness_rows.append(chosen)
        assigned_families[chosen["seedObjectSchemaId"]].add(instance.family_id)

    if missing_instances:
        raise WitnessGenerationError(
            "structural instances have no carrier: "
            + ",".join(missing_instances)
        )

    for seed in seed_registry["rows"]:
        seed["structuralFamilyIds"] = sorted(
            assigned_families[seed["objectSchemaId"]]
        )
    family_union = {
        family
        for seed in seed_registry["rows"]
        for family in seed["structuralFamilyIds"]
    }
    if family_union != set(rules):
        raise WitnessGenerationError("seed structural-family union drift")
    seed_schema = _load_json(
        contract / "APP-CORE-IFACE-0-SEED-REGISTRY-SCHEMA-CANDIDATE.json"
    )
    if list(Draft202012Validator(seed_schema).iter_errors(seed_registry)):
        raise WitnessGenerationError("augmented seed registry fails its closed schema")

    if (
        len(witness_rows) != STRUCTURAL_COUNT
        or {row["instanceId"] for row in witness_rows}
        != {instance.instance_id for instance in instances}
    ):
        raise WitnessGenerationError("structural witness set equality drift")
    seed_bytes = dumps(seed_registry)
    witness_registry = {
        "registryVersion": "APP-CORE-IFACE-0-STRUCTURAL-WITNESSES-V1",
        "status": "PRE_RATIFICATION_CANDIDATE",
        "interfaceSchemaSha256": sha256_bytes(schema_path.read_bytes()),
        "structuralAxisRegistrySha256": sha256_bytes(axes_path.read_bytes()),
        "seedRegistrySha256": sha256_bytes(seed_bytes),
        "oneOfDisjointnessRegistrySha256": sha256_bytes(
            (
                contract
                / "APP-CORE-IFACE-0-ONEOF-DISJOINTNESS-CANDIDATE.json"
            ).read_bytes()
        ),
        "instanceSetSha256": digest_lines(
            row["instanceId"] for row in witness_rows
        ),
        "rowCount": STRUCTURAL_COUNT,
        "rows": witness_rows,
    }
    validate_structural_witness_identifiers(witness_registry)
    witness_schema = _load_json(
        contract / "APP-CORE-IFACE-0-STRUCTURAL-WITNESS-SCHEMA-CANDIDATE.json"
    )
    witness_errors = sorted(
        Draft202012Validator(witness_schema).iter_errors(witness_registry),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if witness_errors:
        first = witness_errors[0]
        location = "/".join(str(part) for part in first.absolute_path)
        raise WitnessGenerationError(
            f"derived witness registry fails its closed schema at {location}: "
            f"{first.message}"
        )
    return seed_registry, witness_registry


class WitnessGenerationError(ValueError):
    """The contract-driven structural plan cannot be derived exactly."""


def derive_structural_plan(contract: Path) -> dict[str, Any]:
    """Derive fields that are independent of carrier selection and oracle release."""

    verify_contract_package(contract)
    axes = _load_json(contract / "APP-CORE-IFACE-0-STRUCTURAL-AXES-CANDIDATE.json")
    by_id = {row["id"]: row for row in axes["rules"]}
    if len(by_id) != 24:
        raise WitnessGenerationError("structural rule registry drift")
    rows: list[dict[str, str]] = []
    for instance in expand_structural_instances(contract):
        rule = by_id.get(instance.family_id)
        if rule is None:
            raise WitnessGenerationError("structural instance has no owning rule")
        rows.append(
            {
                "assertionId": instance.assertion_id,
                "detectorId": instance.detector_id,
                "expectedDisposition": instance.expected_disposition,
                "instanceId": instance.instance_id,
                "isolationMode": rule.get(
                    "isolationMode", "TARGET_ONLY_COUNTERFACTUAL"
                ),
                "mutationId": instance.perturbation_id.replace("PRT-", "MUT-", 1),
                "perturbationId": instance.perturbation_id,
                "perturbationKind": rule["perturbationKind"],
                "sourcePointerOrRowId": instance.source,
                "structuralRuleId": instance.family_id,
            }
        )
    if len(rows) != STRUCTURAL_COUNT or len({row["instanceId"] for row in rows}) != STRUCTURAL_COUNT:
        raise WitnessGenerationError("structural plan count or identity drift")
    _validate_plan_identifier_schemas(contract, rows)
    instance_set = hashlib.sha256(
        "".join(row["instanceId"] + "\n" for row in rows).encode("utf-8")
    ).hexdigest()
    return {
        "instance_count": STRUCTURAL_COUNT,
        "instance_set_sha256": instance_set,
        "rows": rows,
        "schema": "styx.app-core-iface0.structural-instance-plan.v1",
        "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--derive-plan", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if not args.derive_plan:
            raise WitnessGenerationError(
                "Phase-B witness synthesis requires provider-bound carrier ratification"
            )
        report = derive_structural_plan(args.contract.resolve())
        store_report(args.output, report, allowed_fields=PLAN_FIELDS)
    except (InventoryError, OSError, ReportError, WitnessGenerationError) as error:
        print(f"APP-core structural generation: FAIL: {error}", file=sys.stderr)
        return 2
    print("APP-core structural plan: PASS instances=1450")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
