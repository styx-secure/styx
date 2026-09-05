#!/usr/bin/env python3
"""Derive the immutable structural-instance plan before Phase-B synthesis."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
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

TARGET_PREFLIGHT_FIELDS = frozenset(
    {
        "instance_count",
        "instance_set_sha256",
        "resolution_counts",
        "schema",
        "unresolved_instance_ids",
        "verdict",
    }
)

ISOLATION_PREFLIGHT_FIELDS = frozenset(
    {
        "classification_counts",
        "instance_count",
        "instance_set_sha256",
        "non_satisfiable_rows",
        "reselected_count",
        "reselected_rows",
        "schema",
        "selected_classification_counts",
        "verdict",
    }
)

STRUCTURAL_EXECUTION_FIELDS = frozenset(
    {
        "classification_counts",
        "instance_count",
        "instance_set_sha256",
        "rows",
        "schema",
        "verdict",
    }
)

SEED_COUNT = 78
OPERATION_ORDER = {operation: index for index, operation in enumerate(OPERATIONS)}
ISOLATION_RELATION_FILENAME = (
    "APP-CORE-IFACE-0-STRUCTURAL-ISOLATION-RELATION-CANDIDATE.json"
)
ISOLATION_AUTHORITY = {
    "humanRequestSha256": "279d5ac04c86628be031b6a50dc275540d2137033a72ea7275b9796c1942534a",
    "priorHumanRequestSha256": "43d7660ec64733ec626acd26d390539ac75e0fcb954a1b12f5f511e16cfeed9d",
    "priorProviderCommentId": "5519811594",
    "providerCommentId": "5522978433",
    "v21Sha256": "6587d427a524744e58b6ba38107b9537e3c4b32672b2f41b3d00dcf313d79d77",
    "v22Sha256": "e1d42d9782a47b6e4dbeb6cc09b4bb51bde5a3d3a137058cb1f5147534499e04",
    "v23Sha256": "fc02bf72fcfa16b976abe1dc4bc390b5b71312cce80bdf79ab65dadd91139f17",
    "v24Sha256": "4edf99760b850892b2a64730724e3bc7ecf287254022a9015993885e090ea6ba",
}
ISOLATION_CLASSIFICATION_COUNTS = {
    "ANTI_DOWNGRADE_OVERLAP_SELF_TEST": 1,
    "CO_CONSTRAINED_OCCURRENCE_SELF_TEST": 81,
    "RATIFIED_REDUNDANT_OCCURRENCE_SELF_TEST": 1,
    "TARGET_ONLY_COUNTERFACTUAL": 1367,
}


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


def _require_exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise WitnessGenerationError(f"{label} shape drift")
    return value


def load_structural_isolation_relation(
    contract: Path, instance_ids: set[str]
) -> dict[str, Any]:
    """Load and fail-closed validate the exact V21+V22+V23+V24 relation."""

    relation = _load_json(contract / ISOLATION_RELATION_FILENAME)
    _require_exact_keys(
        relation,
        {
            "antiDowngrade",
            "authority",
            "boundedRecipeRows",
            "carrierReselections",
            "classificationCounts",
            "coConstrainedClasses",
            "completeSchemaLiveInstanceIds",
            "exactCounts",
            "frozenInputs",
            "recipeDefinitions",
            "relationVersion",
            "status",
        },
        "structural isolation relation",
    )
    if relation["relationVersion"] != "APP-CORE-IFACE-0-STRUCTURAL-ISOLATION-V2":
        raise WitnessGenerationError("structural isolation relation version drift")
    if relation["status"] != "HUMAN_RATIFIED_REMEDIATION_AUTHORITY":
        raise WitnessGenerationError("structural isolation relation status drift")
    if relation["authority"] != ISOLATION_AUTHORITY:
        raise WitnessGenerationError("structural isolation authority drift")
    frozen = _require_exact_keys(
        relation["frozenInputs"],
        {
            "instanceCount",
            "instanceSetSha256",
            "preImplementationHead",
            "requestCarrierCount",
            "responseCarrierCount",
        },
        "structural isolation frozen input",
    )
    if frozen != {
        "instanceCount": 1450,
        "instanceSetSha256": "e1f5e66ffc94691fb03eac4221dd6558dacd667eeb5e511ca3f06359847d5a43",
        "preImplementationHead": "1966736cc539efb8514e2be005581cf102e07fcc",
        "requestCarrierCount": 65,
        "responseCarrierCount": 15,
    }:
        raise WitnessGenerationError("structural isolation frozen input drift")
    if relation["classificationCounts"] != ISOLATION_CLASSIFICATION_COUNTS:
        raise WitnessGenerationError("structural isolation classification drift")
    expected_counts = {
        "antiDowngradeRows": 1,
        "boundedRecipeRows": 20,
        "carrierReselections": 31,
        "coConstrainedRows": 81,
        "completeSchemaLiveRows": 26,
        "oneOfPairwiseRelations": 93,
    }
    if relation["exactCounts"] != expected_counts:
        raise WitnessGenerationError("structural isolation exact-count drift")

    reselections: dict[str, dict[str, Any]] = {}
    for row in relation["carrierReselections"]:
        _require_exact_keys(
            row,
            {"candidateOrdinal", "carrierCaseId", "instanceId", "targetJsonPointer"},
            "carrier reselection row",
        )
        instance_id = row["instanceId"]
        if (
            instance_id not in instance_ids
            or instance_id in reselections
            or not isinstance(row["candidateOrdinal"], int)
            or isinstance(row["candidateOrdinal"], bool)
            or row["candidateOrdinal"] < 2
            or not isinstance(row["carrierCaseId"], str)
            or not isinstance(row["targetJsonPointer"], str)
        ):
            raise WitnessGenerationError("carrier reselection relation drift")
        reselections[instance_id] = row
    if len(reselections) != 31:
        raise WitnessGenerationError("carrier reselection cardinality drift")

    complete = relation["completeSchemaLiveInstanceIds"]
    if (
        not isinstance(complete, list)
        or len(complete) != 26
        or len(set(complete)) != 26
        or not set(complete) <= instance_ids
    ):
        raise WitnessGenerationError("complete-schema live relation drift")

    recipes: dict[str, dict[str, Any]] = {}
    for row in relation["recipeDefinitions"]:
        if not isinstance(row, dict):
            raise WitnessGenerationError("recipe definition is malformed")
        allowed = {"candidateSequence", "memberName", "operation", "recipeId"}
        if set(row) - allowed or not {"candidateSequence", "operation", "recipeId"} <= set(row):
            raise WitnessGenerationError("recipe definition shape drift")
        recipe_id = row["recipeId"]
        if (
            not isinstance(recipe_id, str)
            or recipe_id in recipes
            or not isinstance(row["candidateSequence"], list)
            or not row["candidateSequence"]
        ):
            raise WitnessGenerationError("recipe definition identity drift")
        recipes[recipe_id] = row
    if len(recipes) != 9:
        raise WitnessGenerationError("recipe definition cardinality drift")

    recipe_instances: set[str] = set()
    used_recipes: set[str] = set()
    for row in relation["boundedRecipeRows"]:
        _require_exact_keys(
            row,
            {
                "candidateOrdinal",
                "carrierCaseId",
                "instanceId",
                "recipeId",
                "targetJsonPointer",
            },
            "bounded recipe row",
        )
        instance_id = row["instanceId"]
        if (
            instance_id not in instance_ids
            or instance_id in recipe_instances
            or row["recipeId"] not in recipes
            or not isinstance(row["candidateOrdinal"], int)
            or isinstance(row["candidateOrdinal"], bool)
            or row["candidateOrdinal"] < 1
        ):
            raise WitnessGenerationError("bounded recipe relation drift")
        recipe_instances.add(instance_id)
        used_recipes.add(row["recipeId"])
    if len(recipe_instances) != 20 or used_recipes != set(recipes):
        raise WitnessGenerationError("bounded recipe coverage drift")

    co_instances: set[str] = set()
    class_ids: set[str] = set()
    for row in relation["coConstrainedClasses"]:
        _require_exact_keys(
            row,
            {"classId", "dependencyIds", "instanceIds", "reason"},
            "co-constrained class",
        )
        if (
            not isinstance(row["classId"], str)
            or row["classId"] in class_ids
            or not isinstance(row["reason"], str)
            or not row["reason"]
            or not isinstance(row["dependencyIds"], list)
            or not row["dependencyIds"]
            or len(set(row["dependencyIds"])) != len(row["dependencyIds"])
            or not isinstance(row["instanceIds"], list)
            or not row["instanceIds"]
        ):
            raise WitnessGenerationError("co-constrained class relation drift")
        class_ids.add(row["classId"])
        for instance_id in row["instanceIds"]:
            if instance_id not in instance_ids or instance_id in co_instances:
                raise WitnessGenerationError("co-constrained instance relation drift")
            co_instances.add(instance_id)
    if len(class_ids) != 8 or len(co_instances) != 81:
        raise WitnessGenerationError("co-constrained relation cardinality drift")

    anti = _require_exact_keys(
        relation["antiDowngrade"],
        {
            "carrierCaseId",
            "independentDisjointnessRelation",
            "instanceId",
            "mutantMatchingNestedInputArmIndices",
            "mutation",
            "reducedCarrierAcceptedNestedInputArmIndex",
            "targetJsonPointer",
        },
        "anti-downgrade relation",
    )
    anti_id = anti["instanceId"]
    if (
        anti_id != "STR-REQUIRED-PROPERTY-OMISSION--0315"
        or anti_id not in instance_ids
        or anti["carrierCaseId"] != "PCR-REQUEST-VALIDATE-TRANSCRIPT-0002"
        or anti["targetJsonPointer"] != "/input/standaloneVerification"
        or anti["mutation"]
        != "REMOVE_ONLY_STANDALONE_VERIFICATION_FROM_RICHER_REQUIRED_SET"
        or anti["reducedCarrierAcceptedNestedInputArmIndex"] != 1
        or anti["mutantMatchingNestedInputArmIndices"] != [1, 2]
        or anti["independentDisjointnessRelation"]
        != "ValidateTranscriptInputV0/oneOf/1--2"
    ):
        raise WitnessGenerationError("anti-downgrade relation drift")

    partition = set(complete) | recipe_instances | co_instances | {anti_id}
    if (
        len(partition) != 128
        or set(complete) & recipe_instances
        or set(complete) & co_instances
        or recipe_instances & co_instances
        or anti_id in set(complete) | recipe_instances | co_instances
    ):
        raise WitnessGenerationError("structural isolation residual partition drift")
    return relation


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


def _witness_candidates_for_instance(
    instance: Any,
    case_rows: dict[str, dict[str, Any]],
    carriers: dict[str, tuple[dict[str, Any], bytes]],
    roots: dict[str, dict[str, Any]],
    synthesizer: SchemaSynthesizer,
    prospective_cache: dict[tuple[str, str, str, str | None], list[str]],
    object_locations_by_case: dict[str, list[tuple[str, str]]],
    seed_id_by_pointer: dict[str, str],
    axes: dict[str, Any],
    rules: dict[str, dict[str, Any]],
) -> list[tuple[tuple[Any, ...], dict[str, Any]]]:
    """Enumerate every eligible carrier binding in the ratified byte order."""

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
    return sorted(candidates, key=lambda item: item[0])


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
    instance_ids = {instance.instance_id for instance in instances}
    isolation = load_structural_isolation_relation(contract, instance_ids)
    reselections = {
        row["instanceId"]: row for row in isolation["carrierReselections"]
    }
    co_constrained_ids = {
        instance_id
        for row in isolation["coConstrainedClasses"]
        for instance_id in row["instanceIds"]
    }
    anti_downgrade_id = isolation["antiDowngrade"]["instanceId"]
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
        candidates = _witness_candidates_for_instance(
            instance,
            case_rows,
            carriers,
            roots,
            synthesizer,
            prospective_cache,
            object_locations_by_case,
            seed_id_by_pointer,
            axes,
            rules,
        )
        if not candidates:
            missing_instances.append(instance.instance_id)
            continue
        reselection = reselections.get(instance.instance_id)
        if reselection is None:
            chosen = candidates[0][1]
        else:
            ordinal = reselection["candidateOrdinal"]
            if ordinal > len(candidates):
                raise WitnessGenerationError("carrier reselection ordinal drift")
            chosen = candidates[ordinal - 1][1]
            if (
                chosen["carrierCaseId"] != reselection["carrierCaseId"]
                or chosen["targetJsonPointer"] != reselection["targetJsonPointer"]
            ):
                raise WitnessGenerationError("carrier reselection bytes drift")
        if instance.instance_id in co_constrained_ids:
            chosen["isolationMode"] = "CO_CONSTRAINED_OCCURRENCE_SELF_TEST"
        elif instance.instance_id == anti_downgrade_id:
            chosen["isolationMode"] = "ANTI_DOWNGRADE_OVERLAP_SELF_TEST"
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
        "structuralIsolationRelationSha256": sha256_bytes(
            (contract / ISOLATION_RELATION_FILENAME).read_bytes()
        ),
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


def _target_resolution(carrier: dict[str, Any], row: dict[str, Any]) -> str:
    """Classify one selected hostile target without fabricating a parent.

    The populated registry may name an absent member or the next element of an
    existing array only when the perturbation itself constructs that value.
    Every other target must resolve in the provider-shaped positive carrier.
    """

    pointer = row.get("targetJsonPointer")
    if not isinstance(pointer, str):
        return "UNRESOLVED_TARGET"
    try:
        _resolve_data_pointer(carrier, pointer)
    except (KeyError, IndexError, TypeError, ValueError):
        pass
    else:
        return "RESOLVED"

    if not pointer or "/" not in pointer:
        return "UNRESOLVED_TARGET"
    parent_pointer, token = pointer.rsplit("/", 1)
    token = _unescape(token)
    try:
        parent = _resolve_data_pointer(carrier, parent_pointer)
    except (KeyError, IndexError, TypeError, ValueError):
        return "UNRESOLVED_TARGET"

    kind = row.get("perturbationKind")
    if isinstance(parent, dict):
        if token in parent:
            return "UNRESOLVED_TARGET"
        if kind in {"REPLACE_WITH_NULL", "VIOLATE_REFERENCED_SCHEMA"}:
            return "PARENT_RESOLVED_MEMBER_ABSENT"
        return "UNRESOLVED_TARGET"
    if isinstance(parent, list):
        family = row.get("structuralRuleId")
        if (
            isinstance(family, str)
            and family in _PARENT_RESOLVED_ARRAY_INSERTION_FAMILIES
            and token.isdecimal()
            and int(token) == len(parent)
        ):
            return "PARENT_RESOLVED_MEMBER_ABSENT"
    return "UNRESOLVED_TARGET"


def derive_structural_target_preflight(
    repo_root: Path,
    contract: Path,
    evidence_root: Path,
) -> dict[str, Any]:
    """Prove target reachability for the complete derived Phase-B relation."""

    _seed_registry, witness_registry = derive_phase_b_registries(
        repo_root, contract, evidence_root
    )
    inventory, _inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    carrier_ids = {
        row.get("caseId")
        for row in inventory.get("cases", [])
        if isinstance(row, dict)
    }
    if carrier_ids != set(carriers):
        raise WitnessGenerationError("target preflight carrier set drift")

    counts = {
        "PARENT_RESOLVED_MEMBER_ABSENT": 0,
        "RESOLVED": 0,
        "UNRESOLVED_TARGET": 0,
    }
    unresolved: list[str] = []
    for row in witness_registry["rows"]:
        case_id = row.get("carrierCaseId")
        if not isinstance(case_id, str) or case_id not in carriers:
            raise WitnessGenerationError("target preflight names an unknown carrier")
        carrier, _raw = carriers[case_id]
        resolution = _target_resolution(carrier, row)
        counts[resolution] += 1
        if resolution == "UNRESOLVED_TARGET":
            unresolved.append(row["instanceId"])

    if sum(counts.values()) != STRUCTURAL_COUNT:
        raise WitnessGenerationError("target preflight count drift")
    return {
        "instance_count": STRUCTURAL_COUNT,
        "instance_set_sha256": witness_registry["instanceSetSha256"],
        "resolution_counts": counts,
        "schema": "styx.app-core-iface0.structural-target-preflight.v1",
        "unresolved_instance_ids": unresolved,
        "verdict": "PASS" if not unresolved else "AMEND_REQUIRED",
    }


_DIRECT_PREFLIGHT_KINDS = frozenset(
    {
        "DUPLICATE_ARRAY_ITEM",
        "EXCEED_MAX_PROPERTIES",
        "INSERT_UNKNOWN_PROPERTY",
        "MATCH_FORBIDDEN_NOT_SUBSCHEMA",
        "OVERFLOW_MAX_ITEMS",
        "OVERFLOW_MAX_LENGTH",
        "REMOVE_REQUIRED_PROPERTY",
        "REPLACE_CONST_VALUE",
        "REPLACE_ENUM_VALUE",
        "REPLACE_PATTERN_VALUE",
        "REPLACE_WITH_NULL",
        "REPLACE_WITH_WRONG_TYPE",
        "UNDERFLOW_MIN_ITEMS",
        "UNDERFLOW_MIN_LENGTH",
        "VIOLATE_ARRAY_ITEM_SCHEMA",
    }
)

_POSITIVE_UNION_KINDS = frozenset(
    {
        "POSITIVE_ALL_ANYOF_ARMS",
        "POSITIVE_ANYOF_ARM",
        "POSITIVE_ONEOF_ARM",
    }
)

_DEEP_PREFLIGHT_KINDS = frozenset(
    {
        "CONSTRUCT_NO_ANYOF_ARM",
        "CONSTRUCT_NO_ONEOF_ARM",
        "VIOLATE_ALLOF_ARM",
        "VIOLATE_REFERENCED_SCHEMA",
    }
)


def _json_type_matches(value: Any, declared: str) -> bool:
    if declared == "null":
        return value is None
    if declared == "boolean":
        return isinstance(value, bool)
    if declared == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if declared == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if declared == "string":
        return isinstance(value, str)
    if declared == "array":
        return isinstance(value, list)
    if declared == "object":
        return isinstance(value, dict)
    return False


def _ordered_palette_values(palette: dict[str, Any]) -> list[Any]:
    """Expand the literal bounded palette without reordering or invention."""

    values = list(palette["jsonValueOrder"])
    string_order = palette["stringRecipeOrder"]
    values.extend(string_order["literalOrder"])
    for character in string_order["repeatCharacterOrder"]:
        for length in string_order["repeatLengthOrder"]:
            values.append(character * length)
    values.extend(palette["integerRecipeOrder"])
    result: list[Any] = []
    seen: set[bytes] = set()
    for value in values:
        encoded = dumps(value)
        if encoded not in seen:
            seen.add(encoded)
            result.append(value)
    return result


def _replace_data_target(carrier: dict[str, Any], pointer: str, value: Any) -> Any:
    if pointer == "":
        return copy.deepcopy(value)
    tokens = [_unescape(token) for token in pointer.removeprefix("/").split("/")]

    def replace(node: Any, offset: int) -> Any:
        token = tokens[offset]
        terminal = offset == len(tokens) - 1
        if isinstance(node, dict):
            if not terminal and token not in node:
                raise WitnessGenerationError("replacement path is unresolved")
            candidate = dict(node)
            candidate[token] = (
                copy.deepcopy(value)
                if terminal
                else replace(node[token], offset + 1)
            )
            return candidate
        if isinstance(node, list) and token.isdecimal():
            index = int(token)
            candidate = list(node)
            if terminal and index == len(candidate):
                candidate.append(copy.deepcopy(value))
            elif 0 <= index < len(candidate):
                candidate[index] = (
                    copy.deepcopy(value)
                    if terminal
                    else replace(node[index], offset + 1)
                )
            else:
                raise WitnessGenerationError("array replacement index is not bounded")
            return candidate
        raise WitnessGenerationError("replacement parent is not a container")

    return replace(carrier, 0)


def _remove_data_target(carrier: dict[str, Any], pointer: str) -> dict[str, Any]:
    if not pointer or "/" not in pointer:
        raise WitnessGenerationError("removal target has no parent")
    tokens = [_unescape(token) for token in pointer.removeprefix("/").split("/")]

    def remove(node: Any, offset: int) -> Any:
        token = tokens[offset]
        terminal = offset == len(tokens) - 1
        if isinstance(node, dict) and token in node:
            candidate = dict(node)
            if terminal:
                del candidate[token]
            else:
                candidate[token] = remove(node[token], offset + 1)
            return candidate
        if isinstance(node, list) and token.isdecimal() and not terminal:
            index = int(token)
            if 0 <= index < len(node):
                candidate = list(node)
                candidate[index] = remove(node[index], offset + 1)
                return candidate
        raise WitnessGenerationError("required member is absent from its carrier")

    result = remove(carrier, 0)
    if not isinstance(result, dict):
        raise WitnessGenerationError("required-member removal changed root type")
    return result


def _schema_parent(schema: dict[str, Any], pointer: str) -> tuple[Any, str]:
    if not pointer or "/" not in pointer:
        raise WitnessGenerationError("schema mutation target has no parent")
    parent_pointer, token = pointer.rsplit("/", 1)
    parent = schema
    if parent_pointer:
        for part in parent_pointer.removeprefix("/").split("/"):
            part = _unescape(part)
            parent = parent[int(part)] if isinstance(parent, list) else parent[part]
    return parent, _unescape(token)


def _schema_node_at(schema: dict[str, Any], pointer: str) -> Any:
    node: Any = schema
    if pointer:
        for part in pointer.removeprefix("/").split("/"):
            part = _unescape(part)
            node = node[int(part)] if isinstance(node, list) else node[part]
    return node


def _reachable_schema_pointers(
    schema: dict[str, Any], start_pointer: str
) -> frozenset[str]:
    """Return a conservative schema-occurrence closure from one wrapper.

    Every literal child of a reachable schema node is included and local
    references are followed.  The result therefore over-approximates runtime
    branch selection: absence from this set proves that mutating the occurrence
    cannot affect validation through the selected operation wrapper.
    """

    reached: set[str] = set()

    def visit(pointer: str, node: Any) -> None:
        if pointer in reached:
            return
        reached.add(pointer)
        if isinstance(node, dict):
            reference = node.get("$ref")
            if isinstance(reference, str) and reference.startswith("#/"):
                target_pointer = reference.removeprefix("#")
                visit(target_pointer, _schema_node_at(schema, target_pointer))
            for name in sorted(node):
                visit(_join(pointer, name), node[name])
        elif isinstance(node, list):
            for index, item in enumerate(node):
                visit(_join(pointer, str(index)), item)

    visit(start_pointer, _schema_node_at(schema, start_pointer))
    return frozenset(reached)


def _instance_occurrence_pointer(instance: Any) -> str | None:
    """Map virtual positive-arm identities to their literal schema pointer."""

    if instance.family_id == "STR-CONDITIONAL-BRANCH-MATRIX":
        return None
    if instance.family_id == "STR-ONE-OF-POSITIVE-ARM":
        pointer, index = instance.source.rsplit("#", 1)
        return f"{pointer}/{index}"
    return instance.source


def _direct_schema_mutant(schema: dict[str, Any], instance: Any) -> dict[str, Any]:
    mutant = copy.deepcopy(schema)
    source = instance.source
    family = instance.family_id
    if family == "STR-REQUIRED-PROPERTY-OMISSION":
        marker = "/required/"
        owner_pointer, property_token = source.rsplit(marker, 1)
        owner = mutant
        for part in owner_pointer.removeprefix("/").split("/"):
            if part:
                part = _unescape(part)
                owner = owner[int(part)] if isinstance(owner, list) else owner[part]
        required = owner.get("required") if isinstance(owner, dict) else None
        property_name = _unescape(property_token)
        if not isinstance(required, list) or property_name not in required:
            raise WitnessGenerationError("required-property mutant target drift")
        owner["required"] = [name for name in required if name != property_name]
        return mutant
    if family == "STR-NULL-SUBSTITUTION":
        parent, token = _schema_parent(mutant, source)
        if isinstance(parent, list):
            parent[int(token)] = {}
        else:
            parent[token] = {}
        return mutant
    parent, token = _schema_parent(mutant, source)
    if not isinstance(parent, dict) or token not in parent:
        raise WitnessGenerationError("direct schema mutant target drift")
    if family == "STR-UNKNOWN-OBJECT-PROPERTY":
        parent[token] = True
    elif family == "STR-ITEM-CONSTRAINT-VIOLATION":
        parent[token] = {}
    else:
        del parent[token]
    return mutant


def _deep_schema_mutant(schema: dict[str, Any], instance: Any) -> dict[str, Any]:
    mutant = copy.deepcopy(schema)
    parent, token = _schema_parent(mutant, instance.source)
    if instance.family_id in {
        "STR-ONE-OF-NO-ARM",
        "STR-ANY-OF-NO-ARM",
        "STR-REF-TARGET-CONSTRAINT",
    }:
        if not isinstance(parent, dict) or token not in parent:
            raise WitnessGenerationError("deep schema keyword target drift")
        del parent[token]
    elif instance.family_id == "STR-ALL-OF-BRANCH-CONSTRAINT":
        if not isinstance(parent, list) or not token.isdecimal():
            raise WitnessGenerationError("allOf arm target drift")
        parent[int(token)] = {}
    else:
        raise WitnessGenerationError("deep schema mutant kind is not implemented")
    return mutant


def _constraint_node(schema: dict[str, Any], instance: Any) -> dict[str, Any]:
    mode, pointer, _property = _instance_schema_target(instance)
    node = _schema_node_at(schema, pointer)
    if not isinstance(node, dict):
        raise WitnessGenerationError("structural constraint node is not an object")
    return node


def _schema_literal_candidates(
    schema: dict[str, Any], node: dict[str, Any], active: frozenset[str] = frozenset()
) -> list[Any]:
    values: list[Any] = []
    if "const" in node:
        values.append(copy.deepcopy(node["const"]))
    enum = node.get("enum")
    if isinstance(enum, list):
        values.extend(copy.deepcopy(enum))
    reference = node.get("$ref")
    if isinstance(reference, str) and reference.startswith("#/"):
        pointer = reference.removeprefix("#")
        if pointer not in active:
            target = _schema_node_at(schema, pointer)
            if isinstance(target, dict):
                values.extend(
                    _schema_literal_candidates(schema, target, active | {pointer})
                )
    result: list[Any] = []
    seen: set[bytes] = set()
    for value in values:
        encoded = dumps(value)
        if encoded not in seen:
            seen.add(encoded)
            result.append(value)
    return result


def _direct_perturbations(
    carrier: dict[str, Any],
    row: dict[str, Any],
    instance: Any,
    schema: dict[str, Any],
    palette: dict[str, Any],
) -> list[Any]:
    kind = row["perturbationKind"]
    pointer = row["targetJsonPointer"]
    node = _constraint_node(schema, instance)
    try:
        current = _resolve_data_pointer(carrier, pointer)
    except (KeyError, IndexError, TypeError, ValueError):
        current = None

    if kind == "REMOVE_REQUIRED_PROPERTY":
        return [_remove_data_target(carrier, pointer)]
    if kind == "REPLACE_WITH_NULL":
        return [_replace_data_target(carrier, pointer, None)]
    if kind == "INSERT_UNKNOWN_PROPERTY":
        if not isinstance(current, dict):
            return []
        properties = node.get("properties", {})
        for name in palette["unknownPropertyNameOrder"]:
            if name not in current and name not in properties:
                value = copy.deepcopy(current)
                value[name] = None
                return [_replace_data_target(carrier, pointer, value)]
        return []
    if kind == "REPLACE_WITH_WRONG_TYPE":
        declared = node.get("type")
        allowed = {declared} if isinstance(declared, str) else set(declared or [])
        values = [
            value
            for value in _ordered_palette_values(palette)
            if not any(_json_type_matches(value, item) for item in allowed)
        ]
        return [_replace_data_target(carrier, pointer, value) for value in values]
    if kind == "REPLACE_CONST_VALUE":
        constant = node.get("const")
        constant_type = (
            "boolean"
            if isinstance(constant, bool)
            else "integer"
            if isinstance(constant, int)
            else "string"
            if isinstance(constant, str)
            else "array"
            if isinstance(constant, list)
            else "object"
            if isinstance(constant, dict)
            else "null"
        )
        values = [
            value
            for value in _ordered_palette_values(palette)
            if value != constant
            and _json_type_matches(value, constant_type)
        ]
        return [_replace_data_target(carrier, pointer, value) for value in values]
    if kind == "REPLACE_ENUM_VALUE":
        enum = node.get("enum")
        if not isinstance(enum, list) or not enum:
            return []
        types = set()
        for value in enum:
            if isinstance(value, bool):
                types.add("boolean")
            elif isinstance(value, int):
                types.add("integer")
            elif isinstance(value, str):
                types.add("string")
            elif isinstance(value, list):
                types.add("array")
            elif isinstance(value, dict):
                types.add("object")
            else:
                types.add("null")
        values = [
            value
            for value in _ordered_palette_values(palette)
            if value not in enum
            and any(_json_type_matches(value, declared) for declared in types)
        ]
        return [_replace_data_target(carrier, pointer, value) for value in values]
    if kind == "REPLACE_PATTERN_VALUE":
        values = [value for value in _ordered_palette_values(palette) if isinstance(value, str)]
        return [_replace_data_target(carrier, pointer, value) for value in values]
    if kind == "UNDERFLOW_MIN_LENGTH":
        minimum = node.get("minLength")
        if not isinstance(minimum, int) or minimum < 1:
            return []
        return [_replace_data_target(carrier, pointer, "0" * (minimum - 1))]
    if kind == "OVERFLOW_MAX_LENGTH":
        maximum = node.get("maxLength")
        if not isinstance(maximum, int):
            return []
        return [_replace_data_target(carrier, pointer, "0" * (maximum + 1))]
    if kind == "UNDERFLOW_MIN_ITEMS":
        minimum = node.get("minItems")
        if not isinstance(minimum, int) or minimum < 1 or not isinstance(current, list):
            return []
        return [_replace_data_target(carrier, pointer, current[: minimum - 1])]
    if kind == "OVERFLOW_MAX_ITEMS":
        maximum = node.get("maxItems")
        item_schema = node.get("items")
        if (
            not isinstance(maximum, int)
            or not isinstance(current, list)
            or not isinstance(item_schema, dict)
        ):
            return []
        value = copy.deepcopy(current)
        item_validator = _schema_validator(schema, item_schema)
        item_candidates = _schema_literal_candidates(schema, item_schema)
        item_candidates.extend(_ordered_palette_values(palette))
        for candidate in item_candidates:
            if item_validator.is_valid(candidate) and candidate not in value:
                value.append(copy.deepcopy(candidate))
            if len(value) > maximum:
                break
        if len(value) <= maximum:
            return []
        return [_replace_data_target(carrier, pointer, value)]
    if kind == "DUPLICATE_ARRAY_ITEM":
        if not isinstance(current, list) or not current:
            return []
        value = copy.deepcopy(current)
        first = min(current, key=dumps)
        value.append(copy.deepcopy(first))
        return [_replace_data_target(carrier, pointer, value)]
    if kind == "VIOLATE_ARRAY_ITEM_SCHEMA":
        if not isinstance(current, list) or not current:
            return []
        target_index = min(range(len(current)), key=lambda index: dumps(current[index]))
        candidates = []
        for value in _ordered_palette_values(palette):
            replacement = copy.deepcopy(current)
            replacement[target_index] = copy.deepcopy(value)
            candidates.append(_replace_data_target(carrier, pointer, replacement))
        return candidates
    if kind == "MATCH_FORBIDDEN_NOT_SUBSCHEMA":
        return [
            _replace_data_target(carrier, pointer, value)
            for value in _ordered_palette_values(palette)
        ]
    if kind == "EXCEED_MAX_PROPERTIES":
        maximum = node.get("maxProperties")
        if not isinstance(maximum, int) or not isinstance(current, dict):
            return []
        value = copy.deepcopy(current)
        for name in palette["unknownPropertyNameOrder"]:
            if name not in value:
                value[name] = None
            if len(value) > maximum:
                return [_replace_data_target(carrier, pointer, value)]
        return []
    raise WitnessGenerationError("direct perturbation kind is not implemented")


def _encode_with_duplicate_member(value: Any, target_pointer: str) -> bytes | None:
    """Serialize canonically except for one repeated member at the target object."""

    injected = False

    def encode(node: Any, pointer: str) -> str:
        nonlocal injected
        if isinstance(node, dict):
            pairs = []
            for key in sorted(node):
                key_text = json.dumps(
                    key, ensure_ascii=False, allow_nan=False, separators=(",", ":")
                )
                pairs.append(
                    key_text + ":" + encode(node[key], _join(pointer, key))
                )
            if pointer == target_pointer and pairs:
                pairs.append(pairs[0])
                injected = True
            return "{" + ",".join(pairs) + "}"
        if isinstance(node, list):
            return "[" + ",".join(
                encode(item, _join(pointer, str(index)))
                for index, item in enumerate(node)
            ) + "]"
        return json.dumps(
            node, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        )

    raw = (encode(value, "") + "\n").encode("utf-8")
    return raw if injected else None


def _duplicate_member_status(
    carrier: dict[str, Any], row: dict[str, Any], exact: Draft202012Validator
) -> str:
    raw = _encode_with_duplicate_member(carrier, row["targetJsonPointer"])
    if raw is None:
        return "PALETTE_EXHAUSTED"
    try:
        loads(raw)
    except CanonicalJsonError:
        pass
    else:
        return "PALETTE_EXHAUSTED"
    try:
        weakened = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return "PALETTE_EXHAUSTED"
    return "SATISFIABLE" if exact.is_valid(weakened) else "EQUIVALENT_MUTANT"


def _positive_union_status(
    carrier: dict[str, Any],
    row: dict[str, Any],
    instance: Any,
    schema: dict[str, Any],
    root: dict[str, Any],
) -> str:
    try:
        target = _resolve_data_pointer(carrier, row["targetJsonPointer"])
    except (KeyError, IndexError, TypeError, ValueError):
        return "UNRESOLVED_TARGET"
    source = instance.source
    if instance.family_id == "STR-ONE-OF-POSITIVE-ARM":
        arms_pointer, raw_index = source.rsplit("#", 1)
    elif instance.family_id == "STR-ANY-OF-POSITIVE-ARM":
        arms_pointer, raw_index = source.rsplit("/", 1)
    else:
        arms_pointer, raw_index = source, ""
    arms = _schema_node_at(schema, arms_pointer)
    if not isinstance(arms, list) or not arms:
        raise WitnessGenerationError("positive union source drift")
    matches = [
        _schema_validator(schema, arm).is_valid(target)
        for arm in arms
    ]
    if instance.family_id == "STR-ANY-OF-ALL-ARMS":
        return "SATISFIABLE" if all(matches) else "PALETTE_EXHAUSTED"
    if not raw_index.isdecimal():
        raise WitnessGenerationError("positive union arm index drift")
    index = int(raw_index)
    if index >= len(arms) or not matches[index] or sum(matches) != 1:
        return "PALETTE_EXHAUSTED"
    mutant_schema = copy.deepcopy(schema)
    mutant_arms = _schema_node_at(mutant_schema, arms_pointer)
    mutant_arms[index] = {"not": {}}
    mutant = _schema_validator(mutant_schema, mutant_schema)
    return "SATISFIABLE" if not mutant.is_valid(carrier) else "EQUIVALENT_MUTANT"


def _deep_data_targets(value: Any, maximum_depth: int) -> list[str]:
    pointers: list[str] = []

    def visit(node: Any, pointer: str, depth: int) -> None:
        pointers.append(pointer)
        if depth >= maximum_depth:
            return
        if isinstance(node, dict):
            for name in sorted(node):
                visit(node[name], _join(pointer, name), depth + 1)
        elif isinstance(node, list):
            for index, item in enumerate(node):
                visit(item, _join(pointer, str(index)), depth + 1)

    visit(value, "", 0)
    return sorted(set(pointers), key=lambda item: item.encode("utf-8"))


def _combine_data_pointer(owner: str, relative: str) -> str:
    if not relative:
        return owner
    return owner + relative if owner else relative


def _deep_perturbations(
    carrier: dict[str, Any],
    row: dict[str, Any],
    palette: dict[str, Any],
) -> Any:
    """Yield the bounded deep single-target replacement order literally."""

    target_pointer = row["targetJsonPointer"]
    try:
        target = _resolve_data_pointer(carrier, target_pointer)
    except (KeyError, IndexError, TypeError, ValueError):
        target = None
        relative_pointers = [""]
    else:
        relative_pointers = _deep_data_targets(
            target, palette["boundedDeepReplacement"]["maximumDepth"]
        )
    values = _ordered_palette_values(palette)
    for relative in relative_pointers:
        pointer = _combine_data_pointer(target_pointer, relative)
        try:
            current = _resolve_data_pointer(carrier, pointer)
        except (KeyError, IndexError, TypeError, ValueError):
            current = object()
        for value in values:
            if type(value) is type(current) and value == current:
                continue
            try:
                yield _replace_data_target(carrier, pointer, value)
            except WitnessGenerationError:
                continue


def _relation_recipe_candidates(
    carrier: dict[str, Any],
    row: dict[str, Any],
    definition: dict[str, Any],
) -> list[Any]:
    """Apply the exact bounded V22 recipe selected for one residual row."""

    operation = definition["operation"]
    pointer = row["targetJsonPointer"]
    sequence = definition["candidateSequence"]
    if operation == "REPLACE_TARGET":
        return [
            _replace_data_target(carrier, pointer, value) for value in sequence
        ]
    if operation == "INSERT_OBJECT_MEMBER":
        try:
            target = _resolve_data_pointer(carrier, pointer)
        except (KeyError, IndexError, TypeError, ValueError) as error:
            raise WitnessGenerationError("recipe insertion target is unresolved") from error
        if not isinstance(target, dict):
            raise WitnessGenerationError("recipe insertion target is not an object")
        member = definition.get("memberName")
        if not isinstance(member, str) or not member or member in target:
            raise WitnessGenerationError("recipe insertion member drift")
        candidates: list[Any] = []
        for value in sequence:
            replacement = copy.deepcopy(target)
            replacement[member] = copy.deepcopy(value)
            candidates.append(_replace_data_target(carrier, pointer, replacement))
        return candidates
    if operation == "REPLACE_ROLE_TAIL_FIRST_WHOLE_V2_KILL":
        event_pointer = pointer.removesuffix("/roleTail")
        try:
            event = _resolve_data_pointer(carrier, event_pointer)
        except (KeyError, IndexError, TypeError, ValueError) as error:
            raise WitnessGenerationError("role-tail recipe target is unresolved") from error
        if not isinstance(event, dict) or "eventRole" not in event or "roleTail" not in event:
            raise WitnessGenerationError("role-tail recipe target drift")
        role_pointer = _join(event_pointer, "roleTail")
        return [
            _replace_data_target(carrier, role_pointer, value) for value in sequence
        ]
    raise WitnessGenerationError("unknown structural isolation recipe operation")


def _conditional_candidate(
    carrier: dict[str, Any], row: dict[str, Any], relation: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    pointer = row["targetJsonPointer"]
    try:
        record = copy.deepcopy(_resolve_data_pointer(carrier, pointer))
    except (KeyError, IndexError, TypeError, ValueError) as error:
        raise WitnessGenerationError("conditional target is unresolved") from error
    if not isinstance(record, dict):
        raise WitnessGenerationError("conditional target is not an event projection")
    zero = "0" * 64
    ordinary = {"kind": "ORDINARY"}
    removal = {
        "kind": "LOGICAL_REMOVAL",
        "targetCommitmentHex": zero,
        "targetEventReferenceHex": zero,
    }
    control = {"kind": "CLOSURE"}

    if relation.startswith("AUTHOR_SEQUENCE_ZERO_"):
        record["authorSequence"] = "0"
        if "WITH_PREDECESSOR_" in relation:
            record["directPredecessorReferenceHex"] = zero
        else:
            record.pop("directPredecessorReferenceHex", None)
    elif relation.startswith("AUTHOR_SEQUENCE_NONZERO_"):
        record["authorSequence"] = "1"
        if "WITHOUT_PREDECESSOR_" in relation:
            record.pop("directPredecessorReferenceHex", None)
        else:
            record["directPredecessorReferenceHex"] = zero
    elif relation == "ORDINARY_WITH_ORDINARY_TAIL_ACCEPTS":
        record.update(eventRole="ORDINARY", roleTail=ordinary)
    elif relation == "ORDINARY_WITH_NON_ORDINARY_TAIL_REJECTS":
        record.update(eventRole="ORDINARY", roleTail=control)
    elif relation == "NON_ORDINARY_SKIPS_ORDINARY_BRANCH_ACCEPTS":
        record.update(eventRole="LOGICAL_REMOVAL", roleTail=removal)
    elif relation == "LOGICAL_REMOVAL_WITH_REMOVAL_TAIL_ACCEPTS":
        record.update(eventRole="LOGICAL_REMOVAL", roleTail=removal)
    elif relation == "LOGICAL_REMOVAL_WITH_NON_REMOVAL_TAIL_REJECTS":
        record.update(eventRole="LOGICAL_REMOVAL", roleTail=ordinary)
    elif relation == "NON_REMOVAL_SKIPS_REMOVAL_BRANCH_ACCEPTS":
        record.update(eventRole="ORDINARY", roleTail=ordinary)
    elif relation == "CREDENTIAL_CONTROL_WITH_CONTROL_TAIL_ACCEPTS":
        record.update(eventRole="CREDENTIAL_CONTROL", roleTail=control)
    elif relation == "CREDENTIAL_CONTROL_WITH_NON_CONTROL_TAIL_REJECTS":
        record.update(eventRole="CREDENTIAL_CONTROL", roleTail=ordinary)
    elif relation == "NON_CONTROL_SKIPS_CONTROL_BRANCH_ACCEPTS":
        record.update(eventRole="ORDINARY", roleTail=ordinary)
    else:
        raise WitnessGenerationError("conditional relation row drift")
    return _replace_data_target(carrier, pointer, record), record


def _conditional_schema_mutant(
    schema: dict[str, Any], relation: str, record: dict[str, Any]
) -> dict[str, Any]:
    mutant = copy.deepcopy(schema)
    arms = mutant["$defs"]["ApplicationEventProjectionV0"]["allOf"]
    if relation.startswith("AUTHOR_SEQUENCE_"):
        index = 0
    elif "ORDINARY" in relation and "REMOVAL" not in relation:
        index = 1
    elif "REMOVAL" in relation:
        index = 2
    else:
        index = 3

    if relation.endswith("_REJECTS"):
        arms[index] = {}
        return mutant
    if relation.startswith("AUTHOR_SEQUENCE_ZERO_"):
        arms[0]["if"]["properties"]["authorSequence"]["const"] = "1"
    elif relation.startswith("AUTHOR_SEQUENCE_NONZERO_"):
        arms[0]["if"]["properties"]["authorSequence"]["const"] = record[
            "authorSequence"
        ]
    elif "_SKIPS_" in relation:
        arms[index]["if"]["properties"]["eventRole"]["const"] = record[
            "eventRole"
        ]
    else:
        arms[index]["then"]["properties"]["roleTail"] = {"not": {}}
    return mutant


def _conditional_status(
    carrier: dict[str, Any],
    row: dict[str, Any],
    instance: Any,
    schema: dict[str, Any],
    root: dict[str, Any],
) -> str:
    candidate, record = _conditional_candidate(carrier, row, instance.source)
    exact = _schema_validator(schema, schema)
    accepted = exact.is_valid(candidate)
    expected_accept = row["expectedDisposition"] == "ACCEPT"
    if accepted != expected_accept:
        return "PALETTE_EXHAUSTED"
    mutant_schema = _conditional_schema_mutant(schema, instance.source, record)
    mutant = _schema_validator(mutant_schema, mutant_schema)
    mutant_accepted = mutant.is_valid(candidate)
    return "SATISFIABLE" if mutant_accepted != accepted else "EQUIVALENT_MUTANT"


def _classify_structural_binding(
    carrier: dict[str, Any],
    row: dict[str, Any],
    instance: Any,
    schema: dict[str, Any],
    root: dict[str, Any],
    palette: dict[str, Any],
    validator_cache: dict[tuple[str, str, str], Draft202012Validator],
    baseline_cache: dict[tuple[str, int], bool] | None = None,
    recipe_definition: dict[str, Any] | None = None,
) -> str:
    root_id = root["rootId"]
    exact_key = ("EXACT_ROOT", "ALL", "")
    exact = validator_cache.get(exact_key)
    if exact is None:
        exact = _schema_validator(schema, schema)
        validator_cache[exact_key] = exact
    resolution = _target_resolution(carrier, row)
    if resolution == "UNRESOLVED_TARGET":
        return "UNRESOLVED_TARGET"
    baseline_key = (root_id, id(carrier))
    baseline_valid = (
        baseline_cache.get(baseline_key)
        if baseline_cache is not None
        else None
    )
    if baseline_valid is None:
        baseline_valid = exact.is_valid(carrier)
        if baseline_cache is not None:
            baseline_cache[baseline_key] = baseline_valid
    if not baseline_valid:
        return "BASELINE_INVALID"
    if row["perturbationKind"] == "DUPLICATE_RAW_JSON_MEMBER":
        return _duplicate_member_status(carrier, row, exact)
    if row["perturbationKind"] in _POSITIVE_UNION_KINDS:
        return _positive_union_status(carrier, row, instance, schema, root)
    if row["perturbationKind"] in _DEEP_PREFLIGHT_KINDS:
        mutant_key = ("DEEP", root_id, instance.instance_id)
        mutant = validator_cache.get(mutant_key)
        local_exact_key = ("DEEP_LOCAL_EXACT", root_id, instance.instance_id)
        local_mutant_key = ("DEEP_LOCAL_MUTANT", root_id, instance.instance_id)
        local_exact = validator_cache.get(local_exact_key)
        local_mutant = validator_cache.get(local_mutant_key)
        if mutant is None:
            mutant_schema = _deep_schema_mutant(schema, instance)
            mutant = _schema_validator(mutant_schema, mutant_schema)
            validator_cache[mutant_key] = mutant
        else:
            mutant_schema = None
        if local_exact is None or local_mutant is None:
            _mode, local_pointer, _property = _instance_schema_target(instance)
            if mutant_schema is None:
                mutant_schema = _deep_schema_mutant(schema, instance)
            local_exact_node = _schema_node_at(schema, local_pointer)
            local_mutant_node = _schema_node_at(mutant_schema, local_pointer)
            if not isinstance(local_exact_node, dict) or not isinstance(
                local_mutant_node, dict
            ):
                raise WitnessGenerationError("deep local schema target drift")
            local_exact = _schema_validator(schema, local_exact_node)
            local_mutant = _schema_validator(mutant_schema, local_mutant_node)
            validator_cache[local_exact_key] = local_exact
            validator_cache[local_mutant_key] = local_mutant
        rejected = False
        candidates = (
            _relation_recipe_candidates(carrier, row, recipe_definition)
            if recipe_definition is not None
            else _deep_perturbations(carrier, row, palette)
        )
        for candidate in candidates:
            # Mutant admission is the rarer condition and is independent of
            # the exact-validator result.  Check it first so a constraint
            # masked by a sibling does not force a full exact-schema walk for
            # every bounded deep replacement.
            mutant_admits = mutant.is_valid(candidate)
            if not mutant_admits and rejected:
                continue
            try:
                local_target = _resolve_data_pointer(
                    candidate, row["targetJsonPointer"]
                )
            except (KeyError, IndexError, TypeError, ValueError):
                continue
            if local_exact.is_valid(local_target) or not local_mutant.is_valid(
                local_target
            ):
                continue
            if exact.is_valid(candidate):
                continue
            rejected = True
            if mutant_admits:
                return "SATISFIABLE"
        return "EQUIVALENT_MUTANT" if rejected else "PALETTE_EXHAUSTED"
    if row["perturbationKind"] == "CONDITIONAL_MATRIX_ROW":
        return _conditional_status(carrier, row, instance, schema, root)
    if row["perturbationKind"] not in _DIRECT_PREFLIGHT_KINDS:
        return "RECIPE_NOT_IMPLEMENTED"

    mutant_key = ("DIRECT", root_id, instance.instance_id)
    mutant = validator_cache.get(mutant_key)
    if mutant is None:
        mutant_schema = _direct_schema_mutant(schema, instance)
        mutant = _schema_validator(mutant_schema, mutant_schema)
        validator_cache[mutant_key] = mutant
    rejected = False
    candidates = (
        _relation_recipe_candidates(carrier, row, recipe_definition)
        if recipe_definition is not None
        else _direct_perturbations(carrier, row, instance, schema, palette)
    )
    for candidate in candidates:
        mutant_admits = mutant.is_valid(candidate)
        if not mutant_admits and rejected:
            continue
        if exact.is_valid(candidate):
            continue
        rejected = True
        if mutant_admits:
            return "SATISFIABLE"
    if (
        row["isolationMode"] == "RATIFIED_REDUNDANT_OCCURRENCE_SELF_TEST"
        and rejected
    ):
        return "RATIFIED_REDUNDANT_OCCURRENCE_SELF_TEST"
    return "EQUIVALENT_MUTANT" if rejected else "PALETTE_EXHAUSTED"


def _anti_downgrade_status(
    carrier: dict[str, Any],
    relation: dict[str, Any],
    schema: dict[str, Any],
) -> str:
    """Prove that weakening the richer nested arm creates forbidden overlap."""

    reduced = _remove_data_target(carrier, relation["targetJsonPointer"])
    exact = _schema_validator(schema, schema)
    if not exact.is_valid(reduced):
        return "BASELINE_INVALID"
    try:
        input_value = reduced["input"]
        arms = schema["$defs"]["ValidateTranscriptInputV0"]["oneOf"]
    except (KeyError, TypeError) as error:
        raise WitnessGenerationError("anti-downgrade schema drift") from error
    exact_matches = [
        index
        for index, arm in enumerate(arms)
        if _schema_validator(schema, arm).is_valid(input_value)
    ]
    if exact_matches != [relation["reducedCarrierAcceptedNestedInputArmIndex"]]:
        return "PALETTE_EXHAUSTED"

    mutant_schema = copy.deepcopy(schema)
    mutant_arms = mutant_schema["$defs"]["ValidateTranscriptInputV0"]["oneOf"]
    richer = mutant_arms[2]
    required = richer.get("required")
    if not isinstance(required, list) or required.count("standaloneVerification") != 1:
        raise WitnessGenerationError("anti-downgrade required set drift")
    richer["required"] = [
        name for name in required if name != "standaloneVerification"
    ]
    mutant_matches = [
        index
        for index, arm in enumerate(mutant_arms)
        if _schema_validator(mutant_schema, arm).is_valid(input_value)
    ]
    if mutant_matches != relation["mutantMatchingNestedInputArmIndices"]:
        return "PALETTE_EXHAUSTED"
    mutant = _schema_validator(mutant_schema, mutant_schema)
    return (
        "ANTI_DOWNGRADE_OVERLAP_SELF_TEST"
        if not mutant.is_valid(reduced)
        else "EQUIVALENT_MUTANT"
    )


def structural_execution_vector(
    authority: Any,
    carrier: dict[str, Any],
    row: dict[str, Any],
    instance: Any,
    schema: dict[str, Any],
    palette: dict[str, Any],
    *,
    trusted_direction: str,
    isolation_mode: str,
    recipe_definition: dict[str, Any] | None = None,
    anti_relation: dict[str, Any] | None = None,
    co_constraint: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Derive one bounded hostile document and its exact target mutant.

    The returned object is test-internal input to the actual Python/JavaScript
    V1/V2 paths.  It contains no expected result inside either adapter input.
    """

    from interface_model import (  # Local import keeps plan derivation acyclic.
        HarnessFailure,
        RequestRejected,
        _validate_structural_v2_evidence,
    )

    def whole_v2_accepts(
        raw: bytes,
        candidate_schema: dict[str, Any],
        *,
        v1_detector_mutant: bool = False,
    ) -> bool:
        try:
            _validate_structural_v2_evidence(
                authority,
                raw,
                trusted_direction=trusted_direction,
                schema_override=candidate_schema,
                v1_detector_mutant=v1_detector_mutant,
            )
        except (HarnessFailure, RequestRejected):
            return False
        return True

    exact = _schema_validator(schema, schema)
    kind = row["perturbationKind"]
    if kind == "DUPLICATE_RAW_JSON_MEMBER":
        raw = _encode_with_duplicate_member(carrier, row["targetJsonPointer"])
        if raw is None:
            raise WitnessGenerationError("duplicate-member execution vector drift")
        try:
            loads(raw)
        except CanonicalJsonError:
            pass
        else:
            raise WitnessGenerationError("duplicate-member V1 detector did not reject")
        parsed = json.loads(raw.decode("utf-8"))
        if not exact.is_valid(parsed) or not whole_v2_accepts(
            raw, schema, v1_detector_mutant=True
        ):
            raise WitnessGenerationError("duplicate-member V1 mutant cannot reach V2")
        return {
            "document": parsed,
            "exactAccepted": False,
            "mutantAccepted": True,
            "mutantSchema": schema,
            "rawDocument": raw,
            "v1DetectorMutant": True,
        }

    if anti_relation is not None:
        candidate = _remove_data_target(carrier, anti_relation["targetJsonPointer"])
        mutant_schema = copy.deepcopy(schema)
        required = mutant_schema["$defs"]["ValidateTranscriptInputV0"]["oneOf"][2][
            "required"
        ]
        mutant_schema["$defs"]["ValidateTranscriptInputV0"]["oneOf"][2][
            "required"
        ] = [name for name in required if name != "standaloneVerification"]
        raw_document = dumps(candidate)
        if not whole_v2_accepts(raw_document, schema) or whole_v2_accepts(
            raw_document, mutant_schema
        ):
            raise WitnessGenerationError("anti-downgrade execution vector drift")
        return {
            "document": candidate,
            "exactAccepted": True,
            "mutantAccepted": False,
            "mutantSchema": mutant_schema,
            "rawDocument": raw_document,
            "v1DetectorMutant": False,
        }

    if kind in _POSITIVE_UNION_KINDS:
        source = instance.source
        if instance.family_id == "STR-ONE-OF-POSITIVE-ARM":
            arms_pointer, raw_index = source.rsplit("#", 1)
        elif instance.family_id == "STR-ANY-OF-POSITIVE-ARM":
            arms_pointer, raw_index = source.rsplit("/", 1)
        else:
            arms_pointer, raw_index = source, ""
        if instance.family_id == "STR-ANY-OF-ALL-ARMS":
            arms = _schema_node_at(schema, arms_pointer)
            target = _resolve_data_pointer(carrier, row["targetJsonPointer"])
            if (
                not isinstance(arms, list)
                or not arms
                or not all(
                    _schema_validator(schema, arm).is_valid(target) for arm in arms
                )
                or not whole_v2_accepts(dumps(carrier), schema)
            ):
                raise WitnessGenerationError("all-anyOf-arms execution relation drift")
            return {
                "document": carrier,
                "exactAccepted": True,
                "mutantAccepted": True,
                "mutantSchema": schema,
                "rawDocument": dumps(carrier),
                "v1DetectorMutant": False,
                "schemaEngineSelfTest": "ALL_ANYOF_ARMS",
            }
        mutant_schema = copy.deepcopy(schema)
        mutant_arms = _schema_node_at(mutant_schema, arms_pointer)
        if not raw_index.isdecimal() or not isinstance(mutant_arms, list):
            raise WitnessGenerationError("positive union execution relation drift")
        mutant_arms[int(raw_index)] = {"not": {}}
        raw_document = dumps(carrier)
        mutant_accepted = whole_v2_accepts(raw_document, mutant_schema)
        if not whole_v2_accepts(raw_document, schema):
            raise WitnessGenerationError("positive execution carrier is invalid")
        expected_mutant = isolation_mode == "CO_CONSTRAINED_OCCURRENCE_SELF_TEST"
        if mutant_accepted != expected_mutant:
            raise WitnessGenerationError("positive execution mutant disposition drift")
        return {
            "document": carrier,
            "exactAccepted": True,
            "mutantAccepted": mutant_accepted,
            "mutantSchema": mutant_schema,
            "rawDocument": raw_document,
            "v1DetectorMutant": False,
        }

    if kind == "CONDITIONAL_MATRIX_ROW":
        candidate, record = _conditional_candidate(carrier, row, instance.source)
        mutant_schema = _conditional_schema_mutant(schema, instance.source, record)
        raw_document = dumps(candidate)
        exact_accepted = whole_v2_accepts(raw_document, schema)
        mutant_accepted = whole_v2_accepts(raw_document, mutant_schema)
        if exact_accepted == mutant_accepted:
            raise WitnessGenerationError("conditional execution mutant is equivalent")
        return {
            "document": candidate,
            "exactAccepted": exact_accepted,
            "mutantAccepted": mutant_accepted,
            "mutantSchema": mutant_schema,
            "rawDocument": raw_document,
            "v1DetectorMutant": False,
        }

    if kind in _DEEP_PREFLIGHT_KINDS:
        mutant_schema = _deep_schema_mutant(schema, instance)
        candidates = (
            _relation_recipe_candidates(carrier, row, recipe_definition)
            if recipe_definition is not None
            else list(_deep_perturbations(carrier, row, palette))
        )
    elif kind in _DIRECT_PREFLIGHT_KINDS:
        mutant_schema = _direct_schema_mutant(schema, instance)
        candidates = (
            _relation_recipe_candidates(carrier, row, recipe_definition)
            if recipe_definition is not None
            else _direct_perturbations(carrier, row, instance, schema, palette)
        )
        if (
            not candidates
            and row["instanceId"] == "STR-MAX-ITEMS-OVERFLOW--0001"
        ):
            current = _resolve_data_pointer(carrier, row["targetJsonPointer"])
            if not isinstance(current, list):
                raise WitnessGenerationError("collection-bound execution target drift")
            replacement = copy.deepcopy(current)
            counter = 0
            while len(replacement) <= 3:
                value = f"{counter:064x}"
                counter += 1
                if value not in replacement:
                    replacement.append(value)
            candidates = [
                _replace_data_target(
                    carrier, row["targetJsonPointer"], replacement
                )
            ]
    else:
        raise WitnessGenerationError("execution-vector perturbation is unsupported")

    mutant = _schema_validator(mutant_schema, mutant_schema)
    want_mutant = isolation_mode == "TARGET_ONLY_COUNTERFACTUAL"
    co_constraint_id = None if co_constraint is None else co_constraint["classId"]
    schema_want_mutant = want_mutant or co_constraint_id in {
        "BRANCH_IDENTITY_IMPLICATION",
        "O08_COLLECTION_BOUND_IMPLICATION",
        "OPERATION_LITERAL_BINDING_IMPLICATION",
        "V1_OBJECT_ROOT_ADMISSION_IMPLICATION",
    }
    for candidate in candidates:
        raw_document = dumps(candidate)
        exact_accepted = whole_v2_accepts(raw_document, schema)
        schema_mutant_accepted = mutant.is_valid(candidate)
        mutant_accepted = whole_v2_accepts(raw_document, mutant_schema)
        if (
            not exact_accepted
            and mutant_accepted == want_mutant
            and schema_mutant_accepted == schema_want_mutant
        ):
            return {
                "document": candidate,
                "exactAccepted": False,
                "mutantAccepted": mutant_accepted,
                "mutantSchema": mutant_schema,
                "rawDocument": raw_document,
                "schemaMutantAccepted": schema_mutant_accepted,
                "coConstraintClassId": co_constraint_id,
                "v1DetectorMutant": False,
            }
    raise WitnessGenerationError("no exact structural execution vector exists")


def derive_structural_isolation_preflight(
    repo_root: Path,
    contract: Path,
    evidence_root: Path,
) -> dict[str, Any]:
    """Classify isolation recipes for the currently selected carrier bindings."""

    _seed_registry, witness_registry = derive_phase_b_registries(
        repo_root, contract, evidence_root
    )
    inventory, _inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    schema = _load_json(contract / "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json")
    palette = _load_json(
        contract / "APP-CORE-IFACE-0-PERTURBATION-PALETTE-CANDIDATE.json"
    )
    reachability = _load_json(
        contract / "APP-CORE-IFACE-0-CARRIER-REACHABILITY-CANDIDATE.json"
    )
    roots = _root_rows(reachability)
    cases = {
        row["caseId"]: row
        for row in inventory["cases"]
        if isinstance(row, dict) and isinstance(row.get("caseId"), str)
    }
    instances = {
        instance.instance_id: instance
        for instance in expand_structural_instances(contract)
    }
    relation = load_structural_isolation_relation(contract, set(instances))
    recipe_definitions = {
        row["recipeId"]: row for row in relation["recipeDefinitions"]
    }
    recipe_rows = {
        row["instanceId"]: row for row in relation["boundedRecipeRows"]
    }
    co_constrained = {
        instance_id
        for row in relation["coConstrainedClasses"]
        for instance_id in row["instanceIds"]
    }
    anti = relation["antiDowngrade"]

    selected_counts: dict[str, int] = {}
    final_counts: dict[str, int] = {}
    failures: list[dict[str, Any]] = []
    validator_cache: dict[tuple[str, str, str], Draft202012Validator] = {}
    baseline_cache: dict[tuple[str, int], bool] = {}
    for row in witness_registry["rows"]:
        instance = instances[row["instanceId"]]
        carrier, _raw = carriers[row["carrierCaseId"]]
        case = cases[row["carrierCaseId"]]
        root = roots[f"{case['direction']}-{case['operation']}"]
        recipe_row = recipe_rows.get(row["instanceId"])
        if recipe_row is not None:
            if (
                recipe_row["carrierCaseId"] != row["carrierCaseId"]
                or recipe_row["targetJsonPointer"] != row["targetJsonPointer"]
            ):
                raise WitnessGenerationError("bounded recipe witness binding drift")
            recipe_definition = recipe_definitions[recipe_row["recipeId"]]
        else:
            recipe_definition = None
        if row["instanceId"] == anti["instanceId"]:
            if (
                anti["carrierCaseId"] != row["carrierCaseId"]
                or anti["targetJsonPointer"] != row["targetJsonPointer"]
            ):
                raise WitnessGenerationError("anti-downgrade witness binding drift")
            status = _anti_downgrade_status(carrier, anti, schema)
        else:
            status = _classify_structural_binding(
                carrier,
                row,
                instance,
                schema,
                root,
                palette,
                validator_cache,
                baseline_cache,
                recipe_definition,
            )
        selected_counts[status] = selected_counts.get(status, 0) + 1
        if row["instanceId"] == anti["instanceId"]:
            final_status = "ANTI_DOWNGRADE_OVERLAP_SELF_TEST"
            accepted_statuses = {final_status}
        elif row["instanceId"] in co_constrained:
            final_status = "CO_CONSTRAINED_OCCURRENCE_SELF_TEST"
            accepted_statuses = {"EQUIVALENT_MUTANT", "SATISFIABLE"}
            if row["instanceId"] == "STR-MAX-ITEMS-OVERFLOW--0001":
                # Its executable counterfactual is the ACV-058 runtime bound,
                # not a materialized JSON array larger than the selected cap.
                accepted_statuses.add("PALETTE_EXHAUSTED")
        elif row["isolationMode"] == "RATIFIED_REDUNDANT_OCCURRENCE_SELF_TEST":
            final_status = "RATIFIED_REDUNDANT_OCCURRENCE_SELF_TEST"
            accepted_statuses = {final_status}
        else:
            final_status = "TARGET_ONLY_COUNTERFACTUAL"
            accepted_statuses = {"SATISFIABLE"}
        if status not in accepted_statuses:
            failures.append(
                {
                    "instance_id": row["instanceId"],
                    "required_classification": final_status,
                    "status": status,
                }
            )
        final_counts[final_status] = final_counts.get(final_status, 0) + 1
    if sum(selected_counts.values()) != STRUCTURAL_COUNT or sum(
        final_counts.values()
    ) != STRUCTURAL_COUNT:
        raise WitnessGenerationError("isolation preflight count drift")
    if final_counts != ISOLATION_CLASSIFICATION_COUNTS:
        raise WitnessGenerationError("structural isolation classification count drift")
    reselected = [
        {
            "candidate_ordinal": row["candidateOrdinal"],
            "carrier_case_id": row["carrierCaseId"],
            "instance_id": row["instanceId"],
        }
        for row in relation["carrierReselections"]
    ]
    return {
        "classification_counts": dict(sorted(final_counts.items())),
        "instance_count": STRUCTURAL_COUNT,
        "instance_set_sha256": witness_registry["instanceSetSha256"],
        "non_satisfiable_rows": failures,
        "reselected_count": len(reselected),
        "reselected_rows": reselected,
        "schema": "styx.app-core-iface0.carrier-search-isolation-preflight.v1",
        "selected_classification_counts": dict(sorted(selected_counts.items())),
        "verdict": "PASS" if not failures else "AMEND_REQUIRED",
    }


def derive_structural_python_execution(
    repo_root: Path,
    contract: Path,
    evidence_root: Path,
    *,
    execution_observer: Any | None = None,
) -> dict[str, Any]:
    """Execute every ratified structural row through Python's actual V1/V2 path."""

    from interface_model import ContractAuthority

    authority = ContractAuthority.load(repo_root, contract)
    _seed_registry, witness_registry = derive_phase_b_registries(
        repo_root, contract, evidence_root
    )
    inventory, _inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    schema = _load_json(contract / "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json")
    palette = _load_json(
        contract / "APP-CORE-IFACE-0-PERTURBATION-PALETTE-CANDIDATE.json"
    )
    cases = {
        row["caseId"]: row
        for row in inventory["cases"]
        if isinstance(row, dict) and isinstance(row.get("caseId"), str)
    }
    instances = {
        instance.instance_id: instance for instance in expand_structural_instances(contract)
    }
    relation = load_structural_isolation_relation(contract, set(instances))
    recipes = {row["recipeId"]: row for row in relation["recipeDefinitions"]}
    recipe_rows = {
        row["instanceId"]: row for row in relation["boundedRecipeRows"]
    }
    co_by_instance = {
        instance_id: row
        for row in relation["coConstrainedClasses"]
        for instance_id in row["instanceIds"]
    }
    anti = relation["antiDowngrade"]
    execution_rows: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for row in witness_registry["rows"]:
        instance_id = row["instanceId"]
        instance = instances[instance_id]
        carrier, _carrier_raw = carriers[row["carrierCaseId"]]
        case = cases[row["carrierCaseId"]]
        recipe_row = recipe_rows.get(instance_id)
        recipe = None if recipe_row is None else recipes[recipe_row["recipeId"]]
        if instance_id == anti["instanceId"]:
            classification = "ANTI_DOWNGRADE_OVERLAP_SELF_TEST"
        elif instance_id in co_by_instance:
            classification = "CO_CONSTRAINED_OCCURRENCE_SELF_TEST"
        else:
            classification = row["isolationMode"]
        try:
            vector = structural_execution_vector(
                authority,
                carrier,
                row,
                instance,
                schema,
                palette,
                trusted_direction=case["direction"],
                isolation_mode=classification,
                recipe_definition=recipe,
                anti_relation=anti if instance_id == anti["instanceId"] else None,
                co_constraint=co_by_instance.get(instance_id),
            )
        except WitnessGenerationError as error:
            raise WitnessGenerationError(
                f"whole-V2 vector failed: {instance_id}: {error}"
            ) from error
        observed = (vector["exactAccepted"], vector["mutantAccepted"])
        if classification == "TARGET_ONLY_COUNTERFACTUAL":
            if instance.family_id == "STR-CONDITIONAL-BRANCH-MATRIX":
                exact_accepts = row["expectedDisposition"] == "ACCEPT"
                expected = (exact_accepts, not exact_accepts)
            elif instance.family_id == "STR-ANY-OF-ALL-ARMS":
                expected = (True, True)
            elif instance.family_id in {
                "STR-ANY-OF-POSITIVE-ARM",
                "STR-ONE-OF-POSITIVE-ARM",
            }:
                expected = (True, False)
            else:
                expected = (False, True)
        elif classification == "ANTI_DOWNGRADE_OVERLAP_SELF_TEST":
            expected = (True, False)
        else:
            expected = (False, False)
        if observed != expected:
            raise WitnessGenerationError(
                f"whole-V2 observation drift: {instance_id}: "
                f"observed={observed!r} expected={expected!r}"
            )
        if execution_observer is not None:
            execution_observer(row, classification, vector, case["direction"])
        counts[classification] = counts.get(classification, 0) + 1
        execution_rows.append(
            {
                "carrierCaseId": row["carrierCaseId"],
                "classification": classification,
                "exactAccepted": observed[0],
                "instanceId": instance_id,
                "mutantAccepted": observed[1],
            }
        )
    if counts != ISOLATION_CLASSIFICATION_COUNTS or len(execution_rows) != STRUCTURAL_COUNT:
        raise WitnessGenerationError("whole-V2 execution classification drift")
    return {
        "classification_counts": dict(sorted(counts.items())),
        "instance_count": STRUCTURAL_COUNT,
        "instance_set_sha256": witness_registry["instanceSetSha256"],
        "rows": execution_rows,
        "schema": "styx.app-core-iface0.structural-execution.v1",
        "verdict": "PASS",
    }


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
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--derive-plan", action="store_true")
    mode.add_argument("--execute-structural-python", action="store_true")
    mode.add_argument("--preflight-isolation", action="store_true")
    mode.add_argument("--preflight-targets", action="store_true")
    parser.add_argument("--repo-root", type=Path)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.derive_plan:
            report = derive_structural_plan(args.contract.resolve())
            allowed_fields = PLAN_FIELDS
            success = "APP-core structural plan: PASS instances=1450"
        elif (
            args.preflight_targets
            or args.preflight_isolation
            or args.execute_structural_python
        ):
            if args.repo_root is None or args.evidence_root is None:
                raise WitnessGenerationError(
                    "structural preflight requires repo root and evidence root"
                )
            if args.execute_structural_python:
                report = derive_structural_python_execution(
                    args.repo_root.resolve(),
                    args.contract.resolve(),
                    args.evidence_root.resolve(),
                )
                allowed_fields = STRUCTURAL_EXECUTION_FIELDS
                success = "APP-core structural Python execution: PASS instances=1450"
            elif args.preflight_targets:
                report = derive_structural_target_preflight(
                    args.repo_root.resolve(),
                    args.contract.resolve(),
                    args.evidence_root.resolve(),
                )
                allowed_fields = TARGET_PREFLIGHT_FIELDS
                label = "target"
            else:
                report = derive_structural_isolation_preflight(
                    args.repo_root.resolve(),
                    args.contract.resolve(),
                    args.evidence_root.resolve(),
                )
                allowed_fields = ISOLATION_PREFLIGHT_FIELDS
                label = "isolation"
            if not args.execute_structural_python:
                success = (
                    f"APP-core structural {label} preflight: "
                    f"{report['verdict']} instances=1450"
                )
        else:
            raise WitnessGenerationError(
                "Phase-B witness synthesis requires provider-bound carrier ratification"
            )
        store_report(args.output, report, allowed_fields=allowed_fields)
    except (InventoryError, OSError, ReportError, WitnessGenerationError) as error:
        print(f"APP-core structural generation: FAIL: {error}", file=sys.stderr)
        return 2
    print(success)
    return 0 if report["verdict"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
