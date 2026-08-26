"""Closed registry for the bounded O-08 C0.3 resource envelope."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any


O08_ROOT = Path(__file__).resolve().parent
SOURCES_PATH = O08_ROOT / "resource-envelope.sources.json"
CANDIDATES_PATH = O08_ROOT / "resource-envelope.candidates.json"
SELECTED_PATH = O08_ROOT / "resource-envelope.candidate.json"

BASE_SHA = "ba0525da1dd78c76c5cc60bc2041e2d3bed44bb3"
SOURCE_SCHEMA = "styx-o08-resource-envelope-sources/v1"
CANDIDATE_SET_SCHEMA = "styx-o08-resource-envelope-candidate-set/v1"
ENVELOPE_SCHEMA = "styx-o08-resource-envelope/v1"
ENVELOPE_VERSION = "styx-app-kernel-v0-resource-envelope/1"

ROLE_SEMANTIC = "C03_SEMANTIC_LIMIT"
ROLE_CAPABILITY = "C03_ACTIVATION_CAPABILITY_INPUT"
ROLE_ZERO = "C03_EXPLICIT_ZERO_OR_UNSUPPORTED"
ROLE_POST = "POST_C03_LAYER_PROFILE"
ROLE_EVIDENCE = "EVIDENCE_ONLY"
ENTRY_ROLES = frozenset({ROLE_SEMANTIC, ROLE_CAPABILITY, ROLE_ZERO})
NON_ENTRY_ROLES = frozenset({ROLE_POST, ROLE_EVIDENCE})
ROLES = ENTRY_ROLES | NON_ENTRY_ROLES

STAGES = (
    "S0_PROFILE_ACTIVATION",
    "S1_TRANSPORT_ADMISSION",
    "S2_SESSION_ADMISSION",
    "S3_KERNEL_STRUCTURAL",
    "S4_GRAPH_ADMISSION",
    "S5_AUTHORITY_PROJECTION",
    "S6_DURABLE_COMMIT",
    "S7_PRESENTATION",
)

RECOVERY_CLASSES = frozenset(
    {
        "PROFILE_ACTIVATION_UNSUPPORTED",
        "CURRENT_OBJECT_OUT_OF_PROFILE",
        "DEPENDENCY_DEFERRED",
        "CONTEXT_CAPACITY_EXHAUSTED",
        "AUTHORITY_PROJECTION_UNAVAILABLE",
        "EVIDENCE_ONLY_NO_RUNTIME_OUTCOME",
    }
)

EXPECTED_ROLE_COUNTS = {
    ROLE_SEMANTIC: 45,
    ROLE_CAPABILITY: 5,
    ROLE_ZERO: 2,
    ROLE_POST: 11,
    ROLE_EVIDENCE: 4,
}
EXPECTED_HANDOFF_STAGE_COUNTS = {
    "S0_PROFILE_ACTIVATION": 9,
    "S1_TRANSPORT_ADMISSION": 0,
    "S3_KERNEL_STRUCTURAL": 21,
    "S4_GRAPH_ADMISSION": 10,
    "S5_AUTHORITY_PROJECTION": 15,
    "S6_DURABLE_COMMIT": 10,
}

FIXED_SEMANTIC_VALUES = {
    "REFERENCE_OCTETS": 32,
    "TEXT_FIELD_OCTETS": 0,
    "TREE_FAN_OUT": 2,
    "COMMITMENT_VALUE_OCTETS": 32,
    "RANDOMIZER_OCTETS": 32,
    "PART_SYMBOL_OCTETS": 32,
    "SIGNATURE_OCTETS": 64,
    "VERIFICATION_KEY_OCTETS": 32,
    "PROFILE_VERSION_SKEW": 0,
}

DERIVED_STRUCTURAL_VALUES = {
    "ACTIVATION_CAPABILITY_SET": 4,
}

FROZEN_CANDIDATE_VALUES = FIXED_SEMANTIC_VALUES | DERIVED_STRUCTURAL_VALUES

EXPECTED_INTEGER_FIELDS = frozenset({
    "transcript.outer.body_length", "transcript.protocol_version",
    "transcript.application_profile_id", "transcript.application_profile_version",
    "transcript.object_kind", "transcript.event_role_class", "transcript.event_type",
    "transcript.schema_identifier", "transcript.schema_version",
    "transcript.ap_transition_block.length", "transcript.author_sequence",
    "transcript.direct_predecessor_presence", "transcript.causal_parent_vector.count",
    "transcript.content_descriptor.content_class",
    "transcript.content_descriptor.exact_content_length",
    "transcript.commitment_descriptor.content_type_id",
    "transcript.commitment_descriptor.commitment_suite_id",
    "transcript.commitment_descriptor.commitment_shape",
    "transcript.commitment_descriptor.commitment_value.length",
    "transcript.commitment_descriptor.chunk_geometry_presence",
    "transcript.commitment_descriptor.chunk_geometry.length",
    "transcript.removal.target_commitment.length",
    "transcript.credential_control.control_kind",
    "transcript.credential_control.grantee_suite_id",
    "transcript.credential_control.grantee_verification_key.length",
    "commitment.context.commitment_suite_id", "commitment.context.styx_protocol_version",
    "commitment.context.application_profile_id",
    "commitment.context.application_profile_version", "commitment.context.author_sequence",
    "commitment.content_type_id", "commitment.exact_content_length",
    "commitment.single_shape.exact_content_length", "commitment.commitment_shape",
    "commitment.chunk_size", "commitment.chunk_count", "commitment.final_chunk_length",
    "commitment.leaf_ordinal", "commitment.leaf_length", "commitment.subtree_leaf_count",
    "genesis.outer.body_length", "genesis.protocol_version",
    "genesis.application_profile_id", "genesis.application_profile_version",
    "genesis.signature_suite_id", "genesis.root_verification_key.length",
    "genesis.initial_authority_policy.length",
})

DEPENDENCY_DEFERRED_DIMENSIONS = frozenset(
    {"PENDING_ROOTS", "PENDING_DESCENDANTS", "HALTED_REPLAY_SPAN"}
)


class RegistryError(ValueError):
    """The closed source, role or stage registry is inconsistent."""


@dataclass(frozen=True)
class SourceRegistry:
    payload: dict[str, Any]
    dimensions: tuple[str, ...]
    roles: dict[str, str]
    stages: dict[str, tuple[str, ...]]
    anchors: tuple[tuple[str, str], ...]
    integer_field_coverage: tuple[dict[str, Any], ...]

    @property
    def entry_dimensions(self) -> tuple[str, ...]:
        return tuple(item for item in self.dimensions if self.roles[item] in ENTRY_ROLES)

    @property
    def non_entry_dimensions(self) -> tuple[str, ...]:
        return tuple(item for item in self.dimensions if self.roles[item] in NON_ENTRY_ROLES)


def load_json(path: Path) -> dict[str, Any]:
    def closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise RegistryError(f"duplicate JSON member: {key}")
            result[key] = item
        return result

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=closed_object)
    if not isinstance(value, dict):
        raise RegistryError(f"object required: {path.name}")
    return value


def load_source_registry(path: Path = SOURCES_PATH) -> SourceRegistry:
    payload = load_json(path)
    if payload.get("schema") != SOURCE_SCHEMA:
        raise RegistryError("source schema mismatch")
    if payload.get("candidate_head") != BASE_SHA:
        raise RegistryError("source Base mismatch")
    if tuple(payload.get("enforcement_stages", ())) != STAGES:
        raise RegistryError("enforcement-stage registry mismatch")

    groups = payload.get("groups")
    role_payload = payload.get("scope_roles")
    stage_payload = payload.get("dimension_enforcement_stages")
    if not isinstance(groups, list) or not isinstance(role_payload, dict):
        raise RegistryError("source groups or roles missing")
    if not isinstance(stage_payload, dict):
        raise RegistryError("dimension stage map missing")

    dimensions: list[str] = []
    anchors: list[tuple[str, str]] = []
    for group in groups:
        if not isinstance(group, dict):
            raise RegistryError("group object required")
        dimensions.extend(group.get("dimensions", ()))
        for source in group.get("sources", ()):
            anchors.append((source["path"], source["anchor"]))
    if len(dimensions) != 67 or len(set(dimensions)) != 67:
        raise RegistryError("source inventory must contain 67 unique dimensions")
    if len(anchors) != 28 or len(set(anchors)) != 28:
        raise RegistryError("source inventory must contain 28 unique anchors")

    roles: dict[str, str] = {}
    for role, expected_count in EXPECTED_ROLE_COUNTS.items():
        role_dimensions = role_payload.get(role)
        if not isinstance(role_dimensions, list) or len(role_dimensions) != expected_count:
            raise RegistryError(f"role count mismatch: {role}")
        for dimension in role_dimensions:
            if dimension in roles:
                raise RegistryError(f"duplicate role assignment: {dimension}")
            roles[dimension] = role
    if set(roles) != set(dimensions):
        raise RegistryError("role partition is not exact")

    stages: dict[str, tuple[str, ...]] = {}
    for dimension in dimensions:
        values = stage_payload.get(dimension)
        if not isinstance(values, list) or any(value not in STAGES for value in values):
            raise RegistryError(f"invalid stage assignment: {dimension}")
        stages[dimension] = tuple(values)
    if set(stage_payload) != set(dimensions):
        raise RegistryError("stage map is not exact")

    handoff_counts: dict[str, int] = {key: 0 for key in EXPECTED_HANDOFF_STAGE_COUNTS}
    for dimension in dimensions:
        if roles[dimension] not in ENTRY_ROLES:
            continue
        for stage in stages[dimension]:
            if stage not in handoff_counts:
                raise RegistryError(f"C0.3 entry uses forbidden handoff stage: {stage}")
            handoff_counts[stage] += 1
    if handoff_counts != EXPECTED_HANDOFF_STAGE_COUNTS:
        raise RegistryError("65-row handoff stage distribution mismatch")

    coverage = payload.get("integer_field_coverage")
    if not isinstance(coverage, list) or not coverage:
        raise RegistryError("integer-field coverage relation missing")
    fields: set[str] = set()
    for row in coverage:
        if not isinstance(row, dict) or set(row) not in (
            {"field", "width", "reserved", "dimension"},
            {"field", "width", "reserved", "classification"},
        ):
            raise RegistryError("integer-field coverage row mismatch")
        field = row.get("field")
        width = row.get("width")
        reserved = row.get("reserved")
        if not isinstance(field, str) or not field or field in fields:
            raise RegistryError("duplicate or invalid integer-field coverage")
        if width not in {8, 16, 32, 64} or not isinstance(reserved, int) or reserved < 0:
            raise RegistryError(f"invalid integer-field domain: {field}")
        fields.add(field)
        if "dimension" in row:
            dimension = row["dimension"]
            if dimension not in roles or roles[dimension] != ROLE_SEMANTIC:
                raise RegistryError(f"integer field lacks semantic owner: {field}")
            if dimension == "INTEGER_FIELD_RANGE":
                raise RegistryError("generic integer fallback is forbidden")
        elif row.get("classification") != "REGISTRY_ONLY_NO_WORK":
            raise RegistryError(f"invalid integer-field classification: {field}")
    if fields != EXPECTED_INTEGER_FIELDS:
        raise RegistryError(
            f"integer-field coverage set mismatch missing={sorted(EXPECTED_INTEGER_FIELDS - fields)} "
            f"extra={sorted(fields - EXPECTED_INTEGER_FIELDS)}"
        )

    return SourceRegistry(
        payload, tuple(dimensions), roles, stages, tuple(anchors), tuple(coverage)
    )


def unit_for(dimension: str) -> str:
    if dimension.endswith("_OCTETS") or dimension in {"TRANSIENT_MEMORY_CAPABILITY"}:
        return "OCTETS"
    if dimension == "CUSTODY_REDUNDANCY":
        return "DECLARED_FAILURE_DOMAIN_COPIES"
    if dimension == "PROFILE_VERSION_SKEW":
        return "VERSION_DISTANCE"
    if dimension == "PHYSICAL_TIME_SKEW":
        return "PHYSICAL_TIME_UNITS"
    return "COUNT"


def scope_for(dimension: str) -> str:
    if dimension in {
        "FRAMING_OBJECT_OCTETS", "AP_TRANSITION_BLOCK_OCTETS", "REFERENCE_OCTETS",
        "TEXT_FIELD_OCTETS", "PARENTS_PER_EVENT", "CHUNK_OCTETS",
        "CHUNKS_PER_CONTENT", "SIGNATURE_OCTETS", "VERIFICATION_KEY_OCTETS",
        "GENESIS_BODY_OCTETS", "GENESIS_POLICY_OCTETS",
    }:
        return "PER_CANONICAL_OBJECT"
    if dimension in {"EVIDENCE_PER_CREDENTIAL", "ALIASES_PER_CREDENTIAL", "LINEAGE_DEPTH"}:
        return "PER_CREDENTIAL_AND_CONTEXT"
    if dimension in {"ACTORS", "ROLE_ASSIGNMENTS", "ACTIVATION_CAPABILITY_SET", "PROFILE_VERSION_SKEW"}:
        return "PER_PROFILE_ACTIVATION"
    return "PER_CONTEXT_EVALUATION"


def recovery_for(dimension: str, stage: str, role: str) -> str:
    if role == ROLE_EVIDENCE:
        return "EVIDENCE_ONLY_NO_RUNTIME_OUTCOME"
    if stage == "S0_PROFILE_ACTIVATION":
        return "PROFILE_ACTIVATION_UNSUPPORTED"
    if dimension in DEPENDENCY_DEFERRED_DIMENSIONS:
        return "DEPENDENCY_DEFERRED"
    if stage == "S5_AUTHORITY_PROJECTION":
        return "AUTHORITY_PROJECTION_UNAVAILABLE"
    if stage in {"S4_GRAPH_ADMISSION", "S6_DURABLE_COMMIT"}:
        return "CONTEXT_CAPACITY_EXHAUSTED"
    return "CURRENT_OBJECT_OUT_OF_PROFILE"


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
