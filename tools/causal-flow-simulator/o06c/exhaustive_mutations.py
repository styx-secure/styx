"""Exhaustive octet and scalar mutation evidence for selected O-06c objects."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from protocol_model import (
    CONTENT_NONE,
    DOMAINS,
    ROLE_CREDENTIAL,
    ROLE_REMOVAL,
    SHAPE_TREE,
    ModelError,
    encode_event_transcript,
    event_reference,
    parse_commitment_preimage,
    parse_event_reference_preimage,
    parse_event_transcript,
    parse_leaf_preimage,
    parse_node_preimage,
    u8,
    u16,
    u32,
    u64,
)
from python_encoder import derive_registry
from semantic_registry import build_registry


@dataclass(frozen=True)
class ScalarField:
    name: str
    offset: int
    width: int


@dataclass(frozen=True)
class ObjectSpec:
    identifier: str
    kind: str
    encoded: bytes
    scalars: tuple[ScalarField, ...]


def _context_scalars(prefix: int) -> list[ScalarField]:
    return [
        ScalarField("commitment_suite_id", prefix, 2),
        ScalarField("styx_protocol_version", prefix + 2, 2),
        ScalarField("application_profile_id", prefix + 4, 4),
        ScalarField("application_profile_version", prefix + 8, 4),
        ScalarField("author_sequence", prefix + 76, 8),
    ]


def _event_scalars(encoded: bytes) -> tuple[ScalarField, ...]:
    fields = [ScalarField("body_length", 16, 4)]
    cursor = 20
    fixed = (
        ("styx_protocol_version", 2), ("application_profile_id", 4),
        ("application_profile_version", 4),
    )
    for name, width in fixed:
        fields.append(ScalarField(name, cursor, width)); cursor += width
    cursor += 32
    for name, width in (
        ("object_kind", 2), ("event_role", 1), ("event_type_id", 4),
        ("schema_id", 4), ("schema_version", 4),
    ):
        fields.append(ScalarField(name, cursor, width)); cursor += width
    fields.append(ScalarField("transition_block_length", cursor, 4))
    transition_length = int.from_bytes(encoded[cursor:cursor + 4], "big")
    cursor += 4 + transition_length + 32
    fields.append(ScalarField("author_sequence", cursor, 8)); cursor += 8
    fields.append(ScalarField("predecessor_presence", cursor, 1))
    predecessor_presence = encoded[cursor]; cursor += 1 + (32 if predecessor_presence else 0)
    fields.append(ScalarField("causal_parent_count", cursor, 4))
    parent_count = int.from_bytes(encoded[cursor:cursor + 4], "big")
    cursor += 4 + 32 * parent_count + 32
    content_class = encoded[cursor]
    fields.append(ScalarField("content_class", cursor, 1)); cursor += 1
    fields.append(ScalarField("exact_content_length", cursor, 8)); cursor += 8
    if content_class != CONTENT_NONE:
        for name, width in (("content_type_id", 4), ("commitment_suite_id", 2), ("commitment_shape", 1)):
            fields.append(ScalarField(name, cursor, width)); cursor += width
        fields.append(ScalarField("commitment_value_length", cursor, 4))
        value_length = int.from_bytes(encoded[cursor:cursor + 4], "big")
        cursor += 4 + value_length
        fields.append(ScalarField("chunk_geometry_presence", cursor, 1))
        geometry_presence = encoded[cursor]; cursor += 1
        if geometry_presence:
            fields.append(ScalarField("chunk_geometry_length", cursor, 4))
            geometry_length = int.from_bytes(encoded[cursor:cursor + 4], "big")
            cursor += 4
            if geometry_length == 16:
                fields.extend(
                    (
                        ScalarField("chunk_size", cursor, 4),
                        ScalarField("chunk_count", cursor + 4, 8),
                        ScalarField("final_chunk_length", cursor + 12, 4),
                    )
                )
            cursor += geometry_length
    role = encoded[20 + 2 + 4 + 4 + 32 + 2]
    if role == ROLE_REMOVAL:
        cursor += 32
        fields.append(ScalarField("target_commitment_length", cursor, 4))
    elif role == ROLE_CREDENTIAL:
        fields.append(ScalarField("control_kind", cursor, 1))
        kind = encoded[cursor]; cursor += 1
        if kind == 1:
            fields.append(ScalarField("grantee_suite_id", cursor, 2)); cursor += 2
            fields.append(ScalarField("grantee_verification_key_length", cursor, 4))
    return tuple(fields)


def _reencode(kind: str, encoded: bytes) -> tuple[bytes, bytes]:
    if kind == "transcript":
        event = parse_event_transcript(encoded)
        return encode_event_transcript(event), event_reference(event)
    if kind == "reference_preimage":
        parsed = parse_event_reference_preimage(encoded)
        return DOMAINS["event_reference"] + u32(len(parsed["transcript"])) + parsed["transcript"], parsed["reference"]
    if kind == "leaf_preimage":
        parsed = parse_leaf_preimage(encoded)
        body = b"".join(
            (
                parsed["context"].encode(), u32(parsed["content_type_id"]),
                u64(parsed["leaf_ordinal"]), u32(parsed["leaf_length"]),
                parsed["randomizer"], parsed["leaf_octets"],
            )
        )
        value = DOMAINS["leaf"] + u32(len(body)) + body
        return value, hashlib.sha256(value).digest()
    if kind == "node_preimage":
        parsed = parse_node_preimage(encoded)
        body = u16(parsed["suite"]) + u64(parsed["subtree_leaf_count"]) + parsed["left"] + parsed["right"]
        value = DOMAINS["node"] + u32(len(body)) + body
        return value, hashlib.sha256(value).digest()
    if kind == "commitment_preimage":
        parsed = parse_commitment_preimage(encoded)
        body = b"".join(
            (
                parsed["context"].encode(), u32(parsed["content_type_id"]),
                u64(parsed["exact_content_length"]), u8(parsed["shape"]),
                parsed["geometry"].encode() if parsed["geometry"] is not None else b"",
                parsed["root"], parsed["randomizer"],
            )
        )
        value = DOMAINS["commitment"] + u32(len(body)) + body
        return value, hashlib.sha256(value).digest()
    raise ModelError(f"unknown exhaustive object kind: {kind}")


def _object_specs() -> tuple[ObjectSpec, ...]:
    derived = derive_registry(build_registry())
    specs = []
    for event in derived["events"]:
        transcript = bytes.fromhex(event["transcript"])
        reference = bytes.fromhex(event["reference_preimage"])
        specs.append(ObjectSpec(f"{event['id']}:transcript", "transcript", transcript, _event_scalars(transcript)))
        specs.append(ObjectSpec(f"{event['id']}:reference", "reference_preimage", reference, (ScalarField("transcript_length", 16, 4),)))
        commitment = event["commitment"]
        if commitment is None:
            continue
        for index, value in enumerate(commitment["leaf_preimages"]):
            scalars = tuple(_context_scalars(20)) + (
                ScalarField("leaf_ordinal", 108, 8), ScalarField("leaf_length", 116, 4),
                ScalarField("body_length", 16, 4),
            )
            specs.append(ObjectSpec(f"{event['id']}:leaf:{index}", "leaf_preimage", bytes.fromhex(value), scalars))
        for index, value in enumerate(commitment["node_preimages"]):
            specs.append(ObjectSpec(f"{event['id']}:node:{index}", "node_preimage", bytes.fromhex(value), (ScalarField("body_length", 16, 4), ScalarField("subtree_leaf_count", 22, 8))))
        commitment_bytes = bytes.fromhex(commitment["commitment_preimage"])
        commitment_scalars = list(_context_scalars(20))
        commitment_scalars.extend(
            (ScalarField("body_length", 16, 4), ScalarField("content_type_id", 104, 4),
             ScalarField("exact_content_length", 108, 8), ScalarField("commitment_shape", 116, 1))
        )
        if commitment["geometry"] is not None:
            commitment_scalars.extend(
                (ScalarField("chunk_size", 117, 4), ScalarField("chunk_count", 121, 8), ScalarField("final_chunk_length", 129, 4))
            )
        specs.append(ObjectSpec(f"{event['id']}:commitment", "commitment_preimage", commitment_bytes, tuple(commitment_scalars)))
    return tuple(specs)


def _classify_with(
    spec: ObjectSpec,
    mutated: bytes,
    original_identity: bytes,
    reencode,
) -> str:
    try:
        canonical, identity = reencode(spec.kind, mutated)
    except ModelError:
        return "TYPED_REJECTION"
    if canonical != mutated:
        return "NONCANONICAL_ACCEPTANCE"
    if identity == original_identity:
        return "IDENTITY_COLLISION"
    return "CANONICAL_SEMANTIC_REASSIGNMENT"


def _classify(spec: ObjectSpec, mutated: bytes, original_identity: bytes) -> str:
    return _classify_with(spec, mutated, original_identity, _reencode)


def _classifier_negative_controls(spec: ObjectSpec) -> dict[str, object]:
    """Prove that both forbidden accepted dispositions are reachable and fatal.

    The controls inject parser/re-encoder outcomes rather than pretending to
    produce a SHA-256 collision in the real registry.
    """

    _, identity = _reencode(spec.kind, spec.encoded)

    def reject(_kind: str, _value: bytes):
        raise ModelError("negative-control rejection")

    controls = {
        "typed_rejection": _classify_with(spec, spec.encoded, identity, reject),
        "noncanonical_acceptance": _classify_with(
            spec,
            spec.encoded,
            identity,
            lambda _kind, value: (value + b"noncanonical", bytes.fromhex("01" * 32)),
        ),
        "identity_collision": _classify_with(
            spec,
            spec.encoded,
            identity,
            lambda _kind, value: (value, identity),
        ),
        "canonical_reassignment": _classify_with(
            spec,
            spec.encoded,
            identity,
            lambda _kind, value: (value, bytes.fromhex("02" * 32)),
        ),
    }
    expected = {
        "typed_rejection": "TYPED_REJECTION",
        "noncanonical_acceptance": "NONCANONICAL_ACCEPTANCE",
        "identity_collision": "IDENTITY_COLLISION",
        "canonical_reassignment": "CANONICAL_SEMANTIC_REASSIGNMENT",
    }
    return {
        "observed": controls,
        "expected": expected,
        "forbidden_dispositions_exercised": sorted(
            value
            for value in controls.values()
            if value in {"NONCANONICAL_ACCEPTANCE", "IDENTITY_COLLISION"}
        ),
        "status": "PASS" if controls == expected else "FAIL",
    }


def run_exhaustive() -> dict[str, object]:
    specs = _object_specs()
    if not specs:
        raise ModelError("empty exhaustive object registry")
    negative_controls = _classifier_negative_controls(specs[0])
    octet_records = []
    scalar_records = []
    invalid = []
    for spec in specs:
        canonical, original_identity = _reencode(spec.kind, spec.encoded)
        if canonical != spec.encoded:
            raise ModelError(f"baseline object is not canonical: {spec.identifier}")
        for offset in range(len(spec.encoded)):
            dispositions = []
            for mask in (0x01, 0x80, 0xFF):
                mutated = bytearray(spec.encoded)
                mutated[offset] ^= mask
                disposition = _classify(spec, bytes(mutated), original_identity)
                dispositions.append({"xor": f"0x{mask:02x}", "disposition": disposition})
                if disposition not in {"TYPED_REJECTION", "CANONICAL_SEMANTIC_REASSIGNMENT"}:
                    invalid.append(f"{spec.identifier}:{offset}:{mask:02x}:{disposition}")
            octet_records.append({"object": spec.identifier, "offset": offset, "mutations": dispositions})
        for field in spec.scalars:
            value = int.from_bytes(spec.encoded[field.offset:field.offset + field.width], "big")
            maximum = (1 << (field.width * 8)) - 1
            candidates = {
                "minus_one": value - 1 if value > 0 else None,
                "plus_one": value + 1 if value < maximum else None,
                "boundary_zero": 0,
                "boundary_max": maximum,
            }
            mutations = []
            for label, candidate in candidates.items():
                if candidate is None:
                    mutations.append({"mutation": label, "disposition": "CHECKED_UNDERFLOW_OR_OVERFLOW"})
                    continue
                if candidate == value:
                    mutations.append({"mutation": label, "disposition": "IDENTITY_BOUNDARY"})
                    continue
                mutated = bytearray(spec.encoded)
                mutated[field.offset:field.offset + field.width] = candidate.to_bytes(field.width, "big")
                disposition = _classify(spec, bytes(mutated), original_identity)
                mutations.append({"mutation": label, "disposition": disposition})
                if disposition not in {"TYPED_REJECTION", "CANONICAL_SEMANTIC_REASSIGNMENT"}:
                    invalid.append(f"{spec.identifier}:{field.name}:{label}:{disposition}")
            scalar_records.append(
                {
                    "object": spec.identifier,
                    "field": field.name,
                    "offset": field.offset,
                    "width": field.width,
                    "original": value,
                    "mutations": mutations,
                }
            )
    applicability = [
        {
            "object": spec.identifier,
            "kind": spec.kind,
            "encoded_length": len(spec.encoded),
            "scalar_fields": [field.name for field in spec.scalars],
        }
        for spec in specs
    ]
    return {
        "applicability_matrix": applicability,
        "object_count": len(specs),
        "mutated_octet_count": sum(len(spec.encoded) for spec in specs),
        "octet_operation_count": sum(len(spec.encoded) for spec in specs) * 3,
        "octet_mutations": octet_records,
        "scalar_mutation_count": len(scalar_records),
        "scalar_mutations": scalar_records,
        "invalid_dispositions": invalid,
        "classifier_negative_controls": negative_controls,
        "verdict": (
            "PASS"
            if not invalid and negative_controls["status"] == "PASS"
            else "COUNTEREXAMPLE"
        ),
    }
