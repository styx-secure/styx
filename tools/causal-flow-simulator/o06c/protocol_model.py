"""Independent executable model of the selected Styx O-06c byte construction.

This module deliberately imports neither a historical falsification model nor
product code.  It is bounded evidence, not a production codec.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Iterable


PROTOCOL_VERSION = 0x0001
OBJECT_KIND_APPLICATION_EVENT = 0x0001
COMMITMENT_SUITE = 0x0001

ROLE_ORDINARY = 0x00
ROLE_REMOVAL = 0x01
ROLE_CREDENTIAL = 0x02

CONTENT_NONE = 0x00
CONTENT_REQUIRED = 0x01
CONTENT_DETACHABLE = 0x02

SHAPE_SINGLE = 0x00
SHAPE_TREE = 0x01

CONTROL_GRANT = 0x01
CONTROL_REVOKE = 0x02
CONTROL_ROTATE = 0x03
CONTROL_RECOVER = 0x04
CONTROL_POLICY = 0x05
CONTROL_CLOSURE = 0x06

DOMAIN_HEX = {
    "application": "53545958000100010000000000000000",
    "genesis_signature": "53545958000100020000000000000000",
    "event_reference": "53545958000100030000000000000000",
    "genesis_reference": "53545958000100040000000000000000",
    "commitment": "53545958000100050000000000000000",
    "leaf": "53545958000100060000000000000000",
    "node": "53545958000100070000000000000000",
}
DOMAINS = {name: bytes.fromhex(value) for name, value in DOMAIN_HEX.items()}

TEST_CHUNK_SIZES = frozenset((1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64))
MAX_U8 = (1 << 8) - 1
MAX_U16 = (1 << 16) - 1
MAX_U32 = (1 << 32) - 1
MAX_U64 = (1 << 64) - 1


class ModelError(ValueError):
    """A structural or bounded semantic requirement failed."""


@dataclass
class WorkCounter:
    parsing: int = 0
    inverse: int = 0
    serialization: int = 0
    transcript_regeneration: int = 0
    leaf_hashes: int = 0
    node_hashes: int = 0
    commitment_hashes: int = 0
    reference_hashes: int = 0
    graph_construction: int = 0
    opening_verification: int = 0
    replay: int = 0
    hashed_octets: int = 0
    geometry_checks: int = 0
    content_split_chunks: int = 0

    def record_hash(self, family: str, octets: int) -> None:
        if family == "leaf":
            self.leaf_hashes += 1
        elif family == "node":
            self.node_hashes += 1
        elif family == "commitment":
            self.commitment_hashes += 1
        elif family == "reference":
            self.reference_hashes += 1
        else:
            raise ModelError(f"unknown hash family: {family}")
        self.hashed_octets += octets

    def record(self) -> dict[str, int]:
        return {
            name: int(value)
            for name, value in vars(self).items()
        }


def _bounded(value: int, maximum: int, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > maximum:
        raise ModelError(f"{label} outside unsigned range")
    return value


def u8(value: int, label: str = "u8") -> bytes:
    return _bounded(value, MAX_U8, label).to_bytes(1, "big")


def u16(value: int, label: str = "u16") -> bytes:
    return _bounded(value, MAX_U16, label).to_bytes(2, "big")


def u32(value: int, label: str = "u32") -> bytes:
    return _bounded(value, MAX_U32, label).to_bytes(4, "big")


def u64(value: int, label: str = "u64") -> bytes:
    return _bounded(value, MAX_U64, label).to_bytes(8, "big")


def opaque_u32(value: bytes, label: str) -> bytes:
    if not isinstance(value, bytes):
        raise ModelError(f"{label} must be bytes")
    return u32(len(value), f"{label} length") + value


def opaque32(value: bytes, label: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ModelError(f"{label} must contain exactly 32 octets")
    return value


def framed_hash(domain: bytes, body: bytes, family: str, work: WorkCounter) -> bytes:
    if len(domain) != 16:
        raise ModelError("domain must contain exactly 16 octets")
    preimage = domain + u32(len(body), "hash body length") + body
    work.record_hash(family, len(preimage))
    return hashlib.sha256(preimage).digest()


@dataclass(frozen=True)
class CommitmentContext:
    application_profile_id: int
    application_profile_version: int
    context_identifier: bytes
    credential_identifier: bytes
    author_sequence: int
    commitment_suite_id: int = COMMITMENT_SUITE
    styx_protocol_version: int = PROTOCOL_VERSION

    def encode(self) -> bytes:
        encoded = b"".join(
            (
                u16(self.commitment_suite_id, "commitment suite"),
                u16(self.styx_protocol_version, "protocol version"),
                u32(self.application_profile_id, "application profile id"),
                u32(self.application_profile_version, "application profile version"),
                opaque32(self.context_identifier, "context identifier"),
                opaque32(self.credential_identifier, "credential identifier"),
                u64(self.author_sequence, "author sequence"),
            )
        )
        if len(encoded) != 84:
            raise ModelError("commitment context width drift")
        return encoded


@dataclass(frozen=True)
class Geometry:
    chunk_size: int
    chunk_count: int
    final_chunk_length: int

    def encode(self) -> bytes:
        encoded = (
            u32(self.chunk_size, "chunk size")
            + u64(self.chunk_count, "chunk count")
            + u32(self.final_chunk_length, "final chunk length")
        )
        if len(encoded) != 16:
            raise ModelError("geometry width drift")
        return encoded


@dataclass(frozen=True)
class CommitmentObject:
    context: CommitmentContext
    content_type_id: int
    exact_content_length: int
    shape: int
    root: bytes
    randomizer: bytes
    geometry: Geometry | None
    commitment_value: bytes
    leaf_digests: tuple[bytes, ...]
    leaf_preimages: tuple[bytes, ...]
    node_preimages: tuple[bytes, ...]
    commitment_preimage: bytes
    work: dict[str, int]


@dataclass(frozen=True)
class ContentDescriptor:
    content_class: int
    exact_content_length: int
    content_type_id: int | None = None
    commitment_suite_id: int | None = None
    commitment_shape: int | None = None
    commitment_value: bytes | None = None
    geometry: Geometry | None = None


@dataclass(frozen=True)
class CredentialTail:
    control_kind: int
    grantee_suite_id: int | None = None
    grantee_verification_key: bytes | None = None
    target_credential_id: bytes | None = None
    retiring_credential_id: bytes | None = None
    replacement_grant_reference: bytes | None = None
    retired_credential_id: bytes | None = None
    recovery_grant_reference: bytes | None = None


@dataclass(frozen=True)
class RemovalTail:
    target_event_reference: bytes
    target_commitment: bytes


@dataclass(frozen=True)
class EventAssignment:
    application_profile_id: int
    application_profile_version: int
    context_identifier: bytes
    event_role: int
    event_type_id: int
    schema_id: int
    schema_version: int
    transition_block: bytes
    credential_identifier: bytes
    author_sequence: int
    direct_predecessor: bytes | None
    causal_parents: tuple[bytes, ...]
    genesis_reference: bytes
    content: ContentDescriptor
    tail: CredentialTail | RemovalTail | None = None
    styx_protocol_version: int = PROTOCOL_VERSION
    object_kind: int = OBJECT_KIND_APPLICATION_EVENT


@dataclass
class Reader:
    data: bytes
    work: WorkCounter
    offset: int = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset

    def take(self, length: int, label: str) -> bytes:
        _bounded(length, MAX_U64, f"{label} requested length")
        if length > len(self.data) - self.offset:
            raise ModelError(f"truncated {label}")
        value = self.data[self.offset : self.offset + length]
        self.offset += length
        self.work.parsing += 1
        return value

    def integer(self, width: int, label: str) -> int:
        return int.from_bytes(self.take(width, label), "big")

    def finish(self, label: str) -> None:
        if self.offset != len(self.data):
            raise ModelError(f"trailing octets after {label}")
        self.work.inverse += 1


def _validate_geometry(
    length: int,
    shape: int,
    geometry: Geometry | None,
    work: WorkCounter | None = None,
) -> None:
    work = work or WorkCounter()
    # One fixed unit records entry into the constant-work geometry guard.  No
    # attacker-declared count is iterated or allocated before this guard exits.
    work.geometry_checks += 1
    _bounded(length, MAX_U64, "exact content length")
    if shape == SHAPE_SINGLE:
        if geometry is not None:
            raise ModelError("single shape forbids geometry")
        if length > 4294967163:
            raise ModelError("single content exceeds framing ceiling")
        return
    if shape != SHAPE_TREE or geometry is None:
        raise ModelError("unknown shape or missing tree geometry")
    if geometry.chunk_size not in TEST_CHUNK_SIZES:
        raise ModelError("chunk size outside test-only O-08 set")
    if geometry.chunk_size >= length or geometry.chunk_count < 2:
        raise ModelError("tree requires at least two chunks")
    expected_count = (length + geometry.chunk_size - 1) // geometry.chunk_size
    if expected_count > MAX_U64 or expected_count != geometry.chunk_count:
        raise ModelError("inconsistent chunk count")
    consumed = geometry.chunk_size * (geometry.chunk_count - 1)
    if consumed > MAX_U64:
        raise ModelError("chunk multiplication overflow")
    final = length - consumed
    if final != geometry.final_chunk_length or not 1 <= final <= geometry.chunk_size:
        raise ModelError("inconsistent final chunk length")


def encode_content_descriptor(
    descriptor: ContentDescriptor, work: WorkCounter | None = None
) -> bytes:
    work = work or WorkCounter()
    prefix = u8(descriptor.content_class, "content class") + u64(
        descriptor.exact_content_length, "exact content length"
    )
    if descriptor.content_class == CONTENT_NONE:
        if descriptor.exact_content_length != 0 or any(
            value is not None
            for value in (
                descriptor.content_type_id,
                descriptor.commitment_suite_id,
                descriptor.commitment_shape,
                descriptor.commitment_value,
                descriptor.geometry,
            )
        ):
            raise ModelError("NONE descriptor must end after zero length")
        return prefix
    if descriptor.content_class not in (CONTENT_REQUIRED, CONTENT_DETACHABLE):
        raise ModelError("unknown content class")
    if descriptor.content_type_id is None or descriptor.content_type_id == 0:
        raise ModelError("content type must be non-zero")
    if descriptor.commitment_suite_id != COMMITMENT_SUITE:
        raise ModelError("unsupported commitment suite")
    if descriptor.commitment_shape is None or descriptor.commitment_value is None:
        raise ModelError("incomplete commitment descriptor")
    _validate_geometry(
        descriptor.exact_content_length,
        descriptor.commitment_shape,
        descriptor.geometry,
        work,
    )
    geometry_presence = descriptor.geometry is not None
    return b"".join(
        (
            prefix,
            u32(descriptor.content_type_id, "content type"),
            u16(descriptor.commitment_suite_id, "commitment suite"),
            u8(descriptor.commitment_shape, "commitment shape"),
            opaque_u32(opaque32(descriptor.commitment_value, "commitment value"), "commitment value"),
            u8(1 if geometry_presence else 0, "geometry presence"),
            (
                opaque_u32(descriptor.geometry.encode(), "chunk geometry")
                if descriptor.geometry is not None
                else b""
            ),
        )
    )


def _parse_opaque_u32(reader: Reader, label: str) -> bytes:
    length = reader.integer(4, f"{label} length")
    return reader.take(length, label)


def _parse_content_descriptor(reader: Reader) -> ContentDescriptor:
    content_class = reader.integer(1, "content class")
    exact_length = reader.integer(8, "exact content length")
    if content_class == CONTENT_NONE:
        if exact_length != 0:
            raise ModelError("NONE descriptor must have zero length")
        return ContentDescriptor(content_class, exact_length)
    if content_class not in (CONTENT_REQUIRED, CONTENT_DETACHABLE):
        raise ModelError("unknown content class")
    content_type = reader.integer(4, "content type")
    suite = reader.integer(2, "commitment suite")
    shape = reader.integer(1, "commitment shape")
    commitment_value = _parse_opaque_u32(reader, "commitment value")
    if len(commitment_value) != 32:
        raise ModelError("commitment value must contain exactly 32 octets")
    geometry_presence = reader.integer(1, "geometry presence")
    if geometry_presence not in (0, 1):
        raise ModelError("invalid geometry presence")
    geometry = None
    if geometry_presence:
        geometry_bytes = _parse_opaque_u32(reader, "chunk geometry")
        if len(geometry_bytes) != 16:
            raise ModelError("chunk geometry must contain exactly 16 octets")
        geometry_reader = Reader(geometry_bytes, reader.work)
        geometry = Geometry(
            geometry_reader.integer(4, "chunk size"),
            geometry_reader.integer(8, "chunk count"),
            geometry_reader.integer(4, "final chunk length"),
        )
        geometry_reader.finish("chunk geometry")
    descriptor = ContentDescriptor(
        content_class=content_class,
        exact_content_length=exact_length,
        content_type_id=content_type,
        commitment_suite_id=suite,
        commitment_shape=shape,
        commitment_value=commitment_value,
        geometry=geometry,
    )
    # The forward encoder is a separate semantic-legality check.  Equality is
    # checked again by the complete transcript inverse below.
    encode_content_descriptor(descriptor, reader.work)
    return descriptor


def _encode_credential_tail(tail: CredentialTail) -> bytes:
    kind = tail.control_kind
    prefix = u8(kind, "control kind")
    if kind == CONTROL_GRANT:
        if tail.grantee_suite_id is None or not tail.grantee_verification_key:
            raise ModelError("GRANT requires suite and non-empty key")
        return prefix + u16(tail.grantee_suite_id, "grantee suite") + opaque_u32(
            tail.grantee_verification_key, "grantee verification key"
        )
    if kind == CONTROL_REVOKE:
        return prefix + opaque32(tail.target_credential_id or b"", "target credential")
    if kind == CONTROL_ROTATE:
        return (
            prefix
            + opaque32(tail.retiring_credential_id or b"", "retiring credential")
            + opaque32(tail.replacement_grant_reference or b"", "replacement grant")
        )
    if kind == CONTROL_RECOVER:
        return (
            prefix
            + opaque32(tail.retired_credential_id or b"", "retired credential")
            + opaque32(tail.recovery_grant_reference or b"", "recovery grant")
        )
    if kind in (CONTROL_POLICY, CONTROL_CLOSURE):
        unexpected = (
            tail.grantee_suite_id,
            tail.grantee_verification_key,
            tail.target_credential_id,
            tail.retiring_credential_id,
            tail.replacement_grant_reference,
            tail.retired_credential_id,
            tail.recovery_grant_reference,
        )
        if any(value is not None for value in unexpected):
            raise ModelError("empty control arm carries unexpected field")
        return prefix
    raise ModelError("unknown credential control kind")


def encode_event_body(event: EventAssignment, work: WorkCounter | None = None) -> bytes:
    work = work or WorkCounter()
    if event.styx_protocol_version != PROTOCOL_VERSION:
        raise ModelError("unsupported protocol version")
    if event.object_kind != OBJECT_KIND_APPLICATION_EVENT:
        raise ModelError("unsupported object kind")
    if min(
        event.application_profile_id,
        event.application_profile_version,
        event.event_type_id,
        event.schema_id,
        event.schema_version,
    ) <= 0:
        raise ModelError("registry identifiers and versions must be non-zero")
    predecessor_present = event.direct_predecessor is not None
    if (event.author_sequence == 0) == predecessor_present:
        raise ModelError("author sequence/predecessor presence mismatch")
    parents = tuple(event.causal_parents)
    if parents != tuple(sorted(set(parents))):
        raise ModelError("causal parents must be sorted and unique")
    if any(len(parent) != 32 for parent in parents):
        raise ModelError("causal parent width")
    if event.direct_predecessor in parents:
        raise ModelError("direct predecessor must be excluded from parent vector")
    content = encode_content_descriptor(event.content, work)
    if event.event_role == ROLE_ORDINARY:
        if event.tail is not None:
            raise ModelError("ordinary event forbids a tail")
        tail = b""
    elif event.event_role == ROLE_REMOVAL:
        if event.content.content_class != CONTENT_NONE or not isinstance(event.tail, RemovalTail):
            raise ModelError("removal requires NONE and removal tail")
        tail = opaque32(event.tail.target_event_reference, "target event") + opaque_u32(
            opaque32(event.tail.target_commitment, "target commitment"),
            "target commitment",
        )
    elif event.event_role == ROLE_CREDENTIAL:
        if event.content.content_class != CONTENT_NONE or not isinstance(event.tail, CredentialTail):
            raise ModelError("credential control requires NONE and credential tail")
        tail = _encode_credential_tail(event.tail)
    else:
        raise ModelError("unknown event role")
    body = b"".join(
        (
            u16(event.styx_protocol_version, "protocol version"),
            u32(event.application_profile_id, "application profile id"),
            u32(event.application_profile_version, "application profile version"),
            opaque32(event.context_identifier, "context identifier"),
            u16(event.object_kind, "object kind"),
            u8(event.event_role, "event role"),
            u32(event.event_type_id, "event type"),
            u32(event.schema_id, "schema id"),
            u32(event.schema_version, "schema version"),
            opaque_u32(event.transition_block, "transition block"),
            opaque32(event.credential_identifier, "credential identifier"),
            u64(event.author_sequence, "author sequence"),
            u8(1 if predecessor_present else 0, "predecessor presence"),
            (
                opaque32(event.direct_predecessor or b"", "direct predecessor")
                if predecessor_present
                else b""
            ),
            u32(len(parents), "causal parent count"),
            b"".join(parents),
            opaque32(event.genesis_reference, "genesis reference"),
            content,
            tail,
        )
    )
    work.serialization += 1
    return body


def encode_event_transcript(event: EventAssignment, work: WorkCounter | None = None) -> bytes:
    work = work or WorkCounter()
    body = encode_event_body(event, work)
    validate_event_body_length(len(body))
    transcript = DOMAINS["application"] + u32(len(body), "event body length") + body
    work.transcript_regeneration += 1
    return transcript


def validate_event_body_length(body_length: int) -> int:
    """Apply the shared ceiling required by outer event-reference framing."""

    return _bounded(body_length, MAX_U32 - 20, "event body framing length")


def _parse_credential_tail(reader: Reader) -> CredentialTail:
    kind = reader.integer(1, "control kind")
    if kind == CONTROL_GRANT:
        suite = reader.integer(2, "grantee suite")
        key = _parse_opaque_u32(reader, "grantee verification key")
        if not key:
            raise ModelError("GRANT key must be non-empty")
        return CredentialTail(kind, grantee_suite_id=suite, grantee_verification_key=key)
    if kind == CONTROL_REVOKE:
        return CredentialTail(kind, target_credential_id=reader.take(32, "target credential"))
    if kind == CONTROL_ROTATE:
        return CredentialTail(
            kind,
            retiring_credential_id=reader.take(32, "retiring credential"),
            replacement_grant_reference=reader.take(32, "replacement grant"),
        )
    if kind == CONTROL_RECOVER:
        return CredentialTail(
            kind,
            retired_credential_id=reader.take(32, "retired credential"),
            recovery_grant_reference=reader.take(32, "recovery grant"),
        )
    if kind in (CONTROL_POLICY, CONTROL_CLOSURE):
        return CredentialTail(kind)
    raise ModelError("unknown credential control kind")


def parse_event_transcript(
    transcript: bytes, work: WorkCounter | None = None
) -> EventAssignment:
    """Parse the full application transcript and prove canonical re-encoding."""

    work = work or WorkCounter()
    outer = Reader(transcript, work)
    if outer.take(16, "application domain") != DOMAINS["application"]:
        raise ModelError("wrong application domain")
    body_length = outer.integer(4, "event body length")
    validate_event_body_length(body_length)
    body_bytes = outer.take(body_length, "event body")
    outer.finish("event transcript")

    body = Reader(body_bytes, work)
    protocol_version = body.integer(2, "protocol version")
    profile_id = body.integer(4, "application profile id")
    profile_version = body.integer(4, "application profile version")
    context = body.take(32, "context identifier")
    object_kind = body.integer(2, "object kind")
    role = body.integer(1, "event role")
    event_type = body.integer(4, "event type")
    schema_id = body.integer(4, "schema id")
    schema_version = body.integer(4, "schema version")
    transition_block = _parse_opaque_u32(body, "transition block")
    credential = body.take(32, "credential identifier")
    author_sequence = body.integer(8, "author sequence")
    predecessor_presence = body.integer(1, "predecessor presence")
    if predecessor_presence not in (0, 1):
        raise ModelError("invalid predecessor presence")
    predecessor = body.take(32, "direct predecessor") if predecessor_presence else None
    parent_count = body.integer(4, "causal parent count")
    parent_octets = parent_count * 32
    if parent_octets > body.remaining:
        raise ModelError("causal parent count exceeds remaining body")
    parent_block = body.take(parent_octets, "causal parent vector")
    parents = tuple(
        parent_block[index : index + 32]
        for index in range(0, len(parent_block), 32)
    )
    genesis = body.take(32, "genesis reference")
    content = _parse_content_descriptor(body)

    tail: CredentialTail | RemovalTail | None
    if role == ROLE_ORDINARY:
        tail = None
    elif role == ROLE_REMOVAL:
        target = body.take(32, "target event reference")
        target_commitment = _parse_opaque_u32(body, "target commitment")
        if len(target_commitment) != 32:
            raise ModelError("target commitment must contain exactly 32 octets")
        tail = RemovalTail(target, target_commitment)
    elif role == ROLE_CREDENTIAL:
        tail = _parse_credential_tail(body)
    else:
        raise ModelError("unknown event role")
    body.finish("event body")

    event = EventAssignment(
        application_profile_id=profile_id,
        application_profile_version=profile_version,
        context_identifier=context,
        event_role=role,
        event_type_id=event_type,
        schema_id=schema_id,
        schema_version=schema_version,
        transition_block=transition_block,
        credential_identifier=credential,
        author_sequence=author_sequence,
        direct_predecessor=predecessor,
        causal_parents=parents,
        genesis_reference=genesis,
        content=content,
        tail=tail,
        styx_protocol_version=protocol_version,
        object_kind=object_kind,
    )
    if encode_event_transcript(event) != transcript:
        raise ModelError("event transcript is not its canonical re-encoding")
    work.inverse += 1
    return event


def parse_event_reference_preimage(
    preimage: bytes, work: WorkCounter | None = None
) -> dict[str, object]:
    work = work or WorkCounter()
    reader = Reader(preimage, work)
    if reader.take(16, "event-reference domain") != DOMAINS["event_reference"]:
        raise ModelError("wrong event-reference domain")
    transcript = _parse_opaque_u32(reader, "application transcript")
    reader.finish("event-reference preimage")
    event = parse_event_transcript(transcript, work)
    return {
        "event": event,
        "transcript": transcript,
        "reference": hashlib.sha256(preimage).digest(),
    }


def event_reference(event: EventAssignment, work: WorkCounter | None = None) -> bytes:
    work = work or WorkCounter()
    transcript = encode_event_transcript(event, work)
    return framed_hash(DOMAINS["event_reference"], transcript, "reference", work)


def _split_content(
    content: bytes, geometry: Geometry | None, work: WorkCounter
) -> tuple[bytes, ...]:
    if geometry is None:
        work.content_split_chunks += 1
        return (content,)
    chunks = tuple(
        content[offset : offset + geometry.chunk_size]
        for offset in range(0, len(content), geometry.chunk_size)
    )
    work.content_split_chunks += len(chunks)
    return chunks


def _largest_power_below(value: int) -> int:
    return 1 << ((value - 1).bit_length() - 1)


def _tree_root(
    digests: tuple[bytes, ...], work: WorkCounter, node_preimages: list[bytes]
) -> bytes:
    if len(digests) == 1:
        return digests[0]
    split = _largest_power_below(len(digests))
    left = _tree_root(digests[:split], work, node_preimages)
    right = _tree_root(digests[split:], work, node_preimages)
    body = (
        u16(COMMITMENT_SUITE, "node suite")
        + u64(len(digests), "subtree leaf count")
        + opaque32(left, "left child")
        + opaque32(right, "right child")
    )
    preimage = DOMAINS["node"] + u32(len(body), "node body length") + body
    node_preimages.append(preimage)
    work.record_hash("node", len(preimage))
    return hashlib.sha256(preimage).digest()


def build_commitment(
    context: CommitmentContext,
    content_type_id: int,
    content: bytes,
    randomizer: bytes,
    *,
    chunk_size: int | None = None,
    work: WorkCounter | None = None,
) -> CommitmentObject:
    work = work or WorkCounter()
    if not isinstance(content, bytes):
        raise ModelError("content must be bytes")
    opaque32(randomizer, "opening randomizer")
    if content_type_id <= 0:
        raise ModelError("content type must be non-zero")
    if chunk_size is None:
        shape = SHAPE_SINGLE
        geometry = None
    else:
        count = (len(content) + chunk_size - 1) // chunk_size if chunk_size else 0
        final = len(content) - chunk_size * (count - 1) if count else 0
        geometry = Geometry(chunk_size, count, final)
        shape = SHAPE_TREE
    _validate_geometry(len(content), shape, geometry, work)
    chunks = _split_content(content, geometry, work)
    leaf_preimages = []
    leaf_digests = []
    context_bytes = context.encode()
    for ordinal, chunk in enumerate(chunks):
        body = b"".join(
            (
                context_bytes,
                u32(content_type_id, "content type"),
                u64(ordinal, "leaf ordinal"),
                u32(len(chunk), "leaf length"),
                randomizer,
                chunk,
            )
        )
        preimage = DOMAINS["leaf"] + u32(len(body), "leaf body length") + body
        leaf_preimages.append(preimage)
        work.record_hash("leaf", len(preimage))
        leaf_digests.append(hashlib.sha256(preimage).digest())
    node_preimages: list[bytes] = []
    root = _tree_root(tuple(leaf_digests), work, node_preimages)
    commitment_body = b"".join(
        (
            context_bytes,
            u32(content_type_id, "content type"),
            u64(len(content), "exact content length"),
            u8(shape, "commitment shape"),
            geometry.encode() if geometry is not None else b"",
            root,
            randomizer,
        )
    )
    commitment_preimage = (
        DOMAINS["commitment"]
        + u32(len(commitment_body), "commitment body length")
        + commitment_body
    )
    work.record_hash("commitment", len(commitment_preimage))
    value = hashlib.sha256(commitment_preimage).digest()
    return CommitmentObject(
        context=context,
        content_type_id=content_type_id,
        exact_content_length=len(content),
        shape=shape,
        root=root,
        randomizer=randomizer,
        geometry=geometry,
        commitment_value=value,
        leaf_digests=tuple(leaf_digests),
        leaf_preimages=tuple(leaf_preimages),
        node_preimages=tuple(node_preimages),
        commitment_preimage=commitment_preimage,
        work=work.record(),
    )


def _read_context(reader: Reader) -> CommitmentContext:
    context = CommitmentContext(
        commitment_suite_id=reader.integer(2, "commitment suite"),
        styx_protocol_version=reader.integer(2, "protocol version"),
        application_profile_id=reader.integer(4, "application profile id"),
        application_profile_version=reader.integer(4, "application profile version"),
        context_identifier=reader.take(32, "context identifier"),
        credential_identifier=reader.take(32, "credential identifier"),
        author_sequence=reader.integer(8, "author sequence"),
    )
    if context.commitment_suite_id != COMMITMENT_SUITE:
        raise ModelError("unsupported commitment suite")
    if context.styx_protocol_version != PROTOCOL_VERSION:
        raise ModelError("unsupported protocol version")
    if context.application_profile_id <= 0 or context.application_profile_version <= 0:
        raise ModelError("invalid application profile")
    return context


def parse_leaf_preimage(preimage: bytes, work: WorkCounter | None = None) -> dict[str, object]:
    work = work or WorkCounter()
    outer = Reader(preimage, work)
    if outer.take(16, "leaf domain") != DOMAINS["leaf"]:
        raise ModelError("wrong leaf domain")
    length = outer.integer(4, "leaf body length")
    body = outer.take(length, "leaf body")
    outer.finish("leaf preimage")
    reader = Reader(body, work)
    context = _read_context(reader)
    content_type = reader.integer(4, "content type")
    ordinal = reader.integer(8, "leaf ordinal")
    leaf_length = reader.integer(4, "leaf length")
    randomizer = reader.take(32, "opening randomizer")
    leaf = reader.take(leaf_length, "leaf octets")
    reader.finish("leaf body")
    return {
        "context": context,
        "content_type_id": content_type,
        "leaf_ordinal": ordinal,
        "leaf_length": leaf_length,
        "randomizer": randomizer,
        "leaf_octets": leaf,
    }


def parse_node_preimage(preimage: bytes, work: WorkCounter | None = None) -> dict[str, object]:
    work = work or WorkCounter()
    reader = Reader(preimage, work)
    if reader.take(16, "node domain") != DOMAINS["node"]:
        raise ModelError("wrong node domain")
    length = reader.integer(4, "node body length")
    if length != 74:
        raise ModelError("node body must contain 74 octets")
    body = Reader(reader.take(length, "node body"), work)
    reader.finish("node preimage")
    suite = body.integer(2, "node suite")
    count = body.integer(8, "subtree leaf count")
    left = body.take(32, "left child")
    right = body.take(32, "right child")
    body.finish("node body")
    if suite != COMMITMENT_SUITE or count < 2:
        raise ModelError("invalid node fields")
    return {"suite": suite, "subtree_leaf_count": count, "left": left, "right": right}


def parse_commitment_preimage(
    preimage: bytes, work: WorkCounter | None = None
) -> dict[str, object]:
    work = work or WorkCounter()
    outer = Reader(preimage, work)
    if outer.take(16, "commitment domain") != DOMAINS["commitment"]:
        raise ModelError("wrong commitment domain")
    length = outer.integer(4, "commitment body length")
    body = Reader(outer.take(length, "commitment body"), work)
    outer.finish("commitment preimage")
    context = _read_context(body)
    content_type = body.integer(4, "content type")
    exact_length = body.integer(8, "exact content length")
    shape = body.integer(1, "commitment shape")
    geometry = None
    if shape == SHAPE_TREE:
        geometry = Geometry(
            body.integer(4, "chunk size"),
            body.integer(8, "chunk count"),
            body.integer(4, "final chunk length"),
        )
    elif shape != SHAPE_SINGLE:
        raise ModelError("unknown commitment shape")
    root = body.take(32, "root")
    randomizer = body.take(32, "opening randomizer")
    body.finish("commitment body")
    _validate_geometry(exact_length, shape, geometry, work)
    return {
        "context": context,
        "content_type_id": content_type,
        "exact_content_length": exact_length,
        "shape": shape,
        "geometry": geometry,
        "root": root,
        "randomizer": randomizer,
    }


def verify_opening(
    descriptor: ContentDescriptor,
    context: CommitmentContext,
    content: bytes,
    randomizer: bytes,
) -> CommitmentObject:
    if descriptor.content_class == CONTENT_NONE:
        raise ModelError("NONE has no opening")
    if len(content) != descriptor.exact_content_length:
        raise ModelError("supplied content length mismatch")
    chunk_size = descriptor.geometry.chunk_size if descriptor.geometry else None
    commitment = build_commitment(
        context,
        descriptor.content_type_id or 0,
        content,
        randomizer,
        chunk_size=chunk_size,
    )
    if commitment.shape != descriptor.commitment_shape:
        raise ModelError("shape mismatch")
    if commitment.geometry != descriptor.geometry:
        raise ModelError("geometry mismatch")
    if commitment.commitment_value != descriptor.commitment_value:
        raise ModelError("commitment mismatch")
    return commitment


def descriptor_from_commitment(
    content_class: int, commitment: CommitmentObject
) -> ContentDescriptor:
    if content_class not in (CONTENT_REQUIRED, CONTENT_DETACHABLE):
        raise ModelError("content-bearing descriptor requires REQUIRED or DETACHABLE")
    return ContentDescriptor(
        content_class=content_class,
        exact_content_length=commitment.exact_content_length,
        content_type_id=commitment.content_type_id,
        commitment_suite_id=COMMITMENT_SUITE,
        commitment_shape=commitment.shape,
        commitment_value=commitment.commitment_value,
        geometry=commitment.geometry,
    )


def make_grant(
    *,
    issuer_credential: bytes,
    context_identifier: bytes,
    genesis_reference: bytes,
    transition_block: bytes,
    verification_key: bytes,
    direct_predecessor: bytes | None = None,
    author_sequence: int = 0,
    causal_parents: Iterable[bytes] = (),
) -> EventAssignment:
    return EventAssignment(
        application_profile_id=1,
        application_profile_version=1,
        context_identifier=context_identifier,
        event_role=ROLE_CREDENTIAL,
        event_type_id=1,
        schema_id=1,
        schema_version=1,
        transition_block=transition_block,
        credential_identifier=issuer_credential,
        author_sequence=author_sequence,
        direct_predecessor=direct_predecessor,
        causal_parents=tuple(causal_parents),
        genesis_reference=genesis_reference,
        content=ContentDescriptor(CONTENT_NONE, 0),
        tail=CredentialTail(
            control_kind=CONTROL_GRANT,
            grantee_suite_id=1,
            grantee_verification_key=verification_key,
        ),
    )
