"""Exact-byte C0.2k commitment-context model.

This standard-library-only model exercises the pre-corpus C0.2k amendment.  It
is not a product implementation, a wire decoder, a supported resource profile,
or an O-06c security proof.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Sequence


SUITE_ID = 0x0001
PROTOCOL_VERSION = 0x0001
PROFILE_REVISION = "c0.2k-pre-corpus-supersession"

D_COMMIT = bytes.fromhex("53545958000100050000000000000000")
D_LEAF = bytes.fromhex("53545958000100060000000000000000")
D_NODE = bytes.fromhex("53545958000100070000000000000000")

LEGACY_CONTEXT_OCTETS = 44
CONTEXT_OCTETS = 84
LEAF_FIXED_PREFIX_OCTETS = 132
LEAF_PREIMAGE_OVERHEAD = 152
NODE_BODY_OCTETS = 74
NODE_PREIMAGE_OCTETS = 94
COMMIT_BODY_SINGLE_OCTETS = 161
COMMIT_BODY_TREE_OCTETS = 177
COMMIT_PREIMAGE_SINGLE_OCTETS = 181
COMMIT_PREIMAGE_TREE_OCTETS = 197
MAX_LEN32 = 2**32 - 1
MAX_U64 = 2**64 - 1
MAX_LEAF_OCTETS = MAX_LEN32 - LEAF_FIXED_PREFIX_OCTETS

SHAPE_SINGLE = 0x00
SHAPE_TREE = 0x01


class ModelInputError(ValueError):
    """Typed bounded-model rejection."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Mutation:
    identifier: str = "NONE"


@dataclass(frozen=True)
class WorkCounters:
    parse_invocations: int = 0
    inverse_invocations: int = 0
    serialization_invocations: int = 0
    digest_invocations: int = 0
    bytes_hashed: int = 0
    leaf_visits: int = 0
    node_visits: int = 0

    def add(
        self,
        *,
        parse_invocations: int = 0,
        inverse_invocations: int = 0,
        serialization_invocations: int = 0,
        digest_invocations: int = 0,
        bytes_hashed: int = 0,
        leaf_visits: int = 0,
        node_visits: int = 0,
    ) -> "WorkCounters":
        return WorkCounters(
            self.parse_invocations + parse_invocations,
            self.inverse_invocations + inverse_invocations,
            self.serialization_invocations + serialization_invocations,
            self.digest_invocations + digest_invocations,
            self.bytes_hashed + bytes_hashed,
            self.leaf_visits + leaf_visits,
            self.node_visits + node_visits,
        )


@dataclass(frozen=True)
class CommitmentContext:
    application_profile_id: int
    application_profile_version: int
    context_identifier: bytes
    credential_identifier: bytes
    author_sequence: int
    commitment_suite_id: int = SUITE_ID
    styx_protocol_version: int = PROTOCOL_VERSION

    def validate(self) -> None:
        if self.commitment_suite_id != SUITE_ID:
            raise ModelInputError("UNKNOWN_SUITE", "suite must be 0x0001")
        if self.styx_protocol_version != PROTOCOL_VERSION:
            raise ModelInputError("UNKNOWN_PROTOCOL", "protocol must be v1")
        if not 0 < self.application_profile_id <= MAX_LEN32:
            raise ModelInputError("INVALID_AP_ID", "AP id must be a non-zero u32")
        if not 0 < self.application_profile_version <= MAX_LEN32:
            raise ModelInputError(
                "INVALID_AP_VERSION", "AP version must be a non-zero u32"
            )
        _require_width("context_identifier", self.context_identifier, 32)
        _require_width("credential_identifier", self.credential_identifier, 32)
        _require_u64("author_sequence", self.author_sequence)


@dataclass(frozen=True)
class Geometry:
    chunk_size: int
    chunk_count: int
    final_chunk_length: int


@dataclass(frozen=True)
class CommitmentResult:
    commitment_value: bytes
    root: bytes
    shape: int
    exact_content_length: int
    content_type_id: int
    geometry: Geometry | None
    opening_randomizer: bytes
    leaf_preimages: tuple[bytes, ...]
    node_preimages: tuple[bytes, ...]
    commitment_preimage: bytes
    counters: WorkCounters


def _require_width(name: str, value: bytes, width: int) -> None:
    if not isinstance(value, bytes) or len(value) != width:
        raise ModelInputError("INVALID_WIDTH", f"{name} must be {width} octets")


def _require_u16(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFF:
        raise ModelInputError("INTEGER_RANGE", f"{name} must be a u16")


def _require_u32(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_LEN32:
        raise ModelInputError("INTEGER_RANGE", f"{name} must be a u32")


def _require_u64(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= MAX_U64:
        raise ModelInputError("INTEGER_RANGE", f"{name} must be a u64")


def _u16(value: int) -> bytes:
    _require_u16("value", value)
    return value.to_bytes(2, "big")


def _u32(value: int) -> bytes:
    _require_u32("value", value)
    return value.to_bytes(4, "big")


def _u64(value: int) -> bytes:
    _require_u64("value", value)
    return value.to_bytes(8, "big")


def checked_u64_multiply(left: int, right: int) -> int:
    """Multiply two u64 values without permitting fixed-width wrap."""

    _require_u64("left", left)
    _require_u64("right", right)
    if left and right > MAX_U64 // left:
        raise ModelInputError("ARITHMETIC_OVERFLOW", "u64 multiplication wraps")
    return left * right


def _legacy_context(context: CommitmentContext) -> bytes:
    context.validate()
    return b"".join(
        (
            _u16(context.commitment_suite_id),
            _u16(context.styx_protocol_version),
            _u32(context.application_profile_id),
            _u32(context.application_profile_version),
            context.context_identifier,
        )
    )


def encode_context(
    context: CommitmentContext, mutation: Mutation = Mutation()
) -> bytes:
    """Encode the only active C0.2k context grammar."""

    if mutation.identifier == "M06_ACCEPT_SEQUENCE_WRAP":
        wrapped = CommitmentContext(
            application_profile_id=context.application_profile_id,
            application_profile_version=context.application_profile_version,
            context_identifier=context.context_identifier,
            credential_identifier=context.credential_identifier,
            author_sequence=context.author_sequence & MAX_U64,
            commitment_suite_id=context.commitment_suite_id,
            styx_protocol_version=context.styx_protocol_version,
        )
        return _legacy_context(wrapped) + wrapped.credential_identifier + _u64(
            wrapped.author_sequence
        )
    legacy = _legacy_context(context)
    if mutation.identifier == "M01_OMIT_CREDENTIAL":
        return legacy + _u64(context.author_sequence)
    if mutation.identifier == "M02_OMIT_SEQUENCE":
        return legacy + context.credential_identifier
    if mutation.identifier == "M03_REORDER_FIELDS":
        return legacy + _u64(context.author_sequence) + context.credential_identifier
    if mutation.identifier == "M04_LITTLE_ENDIAN_SEQUENCE":
        return legacy + context.credential_identifier + context.author_sequence.to_bytes(8, "little")
    if mutation.identifier == "M05_TRUNCATE_SEQUENCE_U32":
        if context.author_sequence > MAX_LEN32:
            return legacy + context.credential_identifier + _u32(context.author_sequence & MAX_LEN32)
        return legacy + context.credential_identifier + _u32(context.author_sequence)
    return legacy + context.credential_identifier + _u64(context.author_sequence)


def parse_context(data: bytes, mutation: Mutation = Mutation()) -> CommitmentContext:
    """Parse one exact C0.2k context; legacy fallback is forbidden."""

    if mutation.identifier == "M07_ACCEPT_LEGACY_CONTEXT" and len(data) == LEGACY_CONTEXT_OCTETS:
        data = data + bytes(40)
    if len(data) != CONTEXT_OCTETS:
        raise ModelInputError("CONTEXT_LENGTH", "context must be exactly 84 octets")
    value = CommitmentContext(
        commitment_suite_id=int.from_bytes(data[0:2], "big"),
        styx_protocol_version=int.from_bytes(data[2:4], "big"),
        application_profile_id=int.from_bytes(data[4:8], "big"),
        application_profile_version=int.from_bytes(data[8:12], "big"),
        context_identifier=data[12:44],
        credential_identifier=data[44:76],
        author_sequence=int.from_bytes(data[76:84], "big"),
    )
    if mutation.identifier == "M17_SELECT_UNTRUSTED_SUITE":
        value = CommitmentContext(
            application_profile_id=value.application_profile_id,
            application_profile_version=value.application_profile_version,
            context_identifier=value.context_identifier,
            credential_identifier=value.credential_identifier,
            author_sequence=value.author_sequence,
            commitment_suite_id=SUITE_ID,
            styx_protocol_version=value.styx_protocol_version,
        )
    value.validate()
    return value


def _context_for_role(
    context: CommitmentContext,
    *,
    role: str,
    shape: int,
    mutation: Mutation,
) -> bytes:
    if mutation.identifier == "M08_BIND_ONLY_COMMITMENT" and role == "leaf":
        return _legacy_context(context)
    if mutation.identifier == "M09_BIND_ONLY_LEAF" and role == "commitment":
        return _legacy_context(context)
    if mutation.identifier == "M10_BIND_ONLY_SINGLE" and shape == SHAPE_TREE:
        return _legacy_context(context)
    if mutation.identifier == "M11_BIND_ONLY_TREE" and shape == SHAPE_SINGLE:
        return _legacy_context(context)
    return encode_context(context, mutation)


def frame(domain: bytes, body: bytes, mutation: Mutation = Mutation()) -> bytes:
    _require_width("domain", domain, 16)
    if len(body) > MAX_LEN32:
        raise ModelInputError("BODY_LENGTH", "body exceeds len32")
    framed = domain + _u32(len(body)) + body
    if mutation.identifier == "M13_ACCEPT_TRAILING_BYTES":
        return framed + b"\x00"
    return framed


def split_frame(data: bytes, domain: bytes, mutation: Mutation = Mutation()) -> bytes:
    if len(data) < 20 or data[:16] != domain:
        raise ModelInputError("DOMAIN", "wrong or truncated domain")
    body_length = int.from_bytes(data[16:20], "big")
    end = 20 + body_length
    if len(data) < end:
        raise ModelInputError("TRUNCATED", "declared body is unavailable")
    if len(data) != end and mutation.identifier != "M13_ACCEPT_TRAILING_BYTES":
        raise ModelInputError("TRAILING_BYTES", "exact end required")
    return data[20:end]


def leaf_body(
    context: CommitmentContext,
    content_type_id: int,
    ordinal: int,
    leaf_octets: bytes,
    opening_randomizer: bytes,
    *,
    shape: int,
    mutation: Mutation = Mutation(),
) -> bytes:
    _require_u32("content_type_id", content_type_id)
    _require_u64("leaf_ordinal", ordinal)
    _require_width("opening_randomizer", opening_randomizer, 32)
    if len(leaf_octets) > MAX_LEAF_OCTETS:
        raise ModelInputError("LEAF_LENGTH", "leaf exceeds len32-safe ceiling")
    return b"".join(
        (
            _context_for_role(context, role="leaf", shape=shape, mutation=mutation),
            _u32(content_type_id),
            _u64(ordinal),
            _u32(len(leaf_octets)),
            opening_randomizer,
            leaf_octets,
        )
    )


def parse_leaf_preimage(data: bytes, mutation: Mutation = Mutation()) -> dict[str, object]:
    body = split_frame(data, D_LEAF, mutation)
    prefix = 92 if mutation.identifier == "M12_RETAIN_OLD_WIDTHS" else LEAF_FIXED_PREFIX_OCTETS
    if len(body) < prefix:
        raise ModelInputError("LEAF_PREFIX", "leaf fixed prefix is truncated")
    context_width = LEGACY_CONTEXT_OCTETS if prefix == 92 else CONTEXT_OCTETS
    context_bytes = body[:context_width]
    if context_width == CONTEXT_OCTETS:
        parse_context(context_bytes)
    offset = context_width
    content_type_id = int.from_bytes(body[offset : offset + 4], "big")
    ordinal = int.from_bytes(body[offset + 4 : offset + 12], "big")
    leaf_length = int.from_bytes(body[offset + 12 : offset + 16], "big")
    randomizer = body[offset + 16 : offset + 48]
    leaf_octets = body[offset + 48 :]
    if len(randomizer) != 32 or len(leaf_octets) != leaf_length:
        raise ModelInputError("LEAF_INVERSE", "leaf inverse is not exact")
    return {
        "context": context_bytes,
        "content_type_id": content_type_id,
        "leaf_ordinal": ordinal,
        "leaf_length": leaf_length,
        "opening_randomizer": randomizer,
        "leaf_octets": leaf_octets,
    }


def leaf_preimage_lengths(declared_leaf_length: int) -> tuple[int, int]:
    """Return checked body/complete widths without allocating attacker-sized input."""

    _require_u64("declared_leaf_length", declared_leaf_length)
    if declared_leaf_length > MAX_LEAF_OCTETS:
        raise ModelInputError("LEAF_LENGTH", "leaf exceeds len32-safe ceiling")
    body_length = LEAF_FIXED_PREFIX_OCTETS + declared_leaf_length
    if body_length > MAX_LEN32:
        raise ModelInputError("ARITHMETIC_OVERFLOW", "leaf body exceeds len32")
    return body_length, 20 + body_length


def _digest(preimage: bytes, counters: WorkCounters, *, leaf: bool = False, node: bool = False) -> tuple[bytes, WorkCounters]:
    return sha256(preimage).digest(), counters.add(
        digest_invocations=1,
        bytes_hashed=len(preimage),
        leaf_visits=1 if leaf else 0,
        node_visits=1 if node else 0,
    )


def node_preimage(subtree_leaf_count: int, left: bytes, right: bytes) -> bytes:
    _require_u64("subtree_leaf_count", subtree_leaf_count)
    if subtree_leaf_count < 2:
        raise ModelInputError("NODE_COUNT", "interior node must cover at least two leaves")
    _require_width("left_child", left, 32)
    _require_width("right_child", right, 32)
    body = _u16(SUITE_ID) + _u64(subtree_leaf_count) + left + right
    if len(body) != NODE_BODY_OCTETS:
        raise AssertionError("node body width drift")
    return frame(D_NODE, body)


def parse_node_preimage(data: bytes, mutation: Mutation = Mutation()) -> dict[str, object]:
    body = split_frame(data, D_NODE, mutation)
    if len(body) != NODE_BODY_OCTETS:
        raise ModelInputError("NODE_LENGTH", "node body must be exactly 74 octets")
    suite = int.from_bytes(body[0:2], "big")
    if suite != SUITE_ID:
        raise ModelInputError("UNKNOWN_SUITE", "node suite must be 0x0001")
    subtree_leaf_count = int.from_bytes(body[2:10], "big")
    if subtree_leaf_count < 2:
        raise ModelInputError("NODE_COUNT", "interior node must cover at least two leaves")
    return {
        "commitment_suite_id": suite,
        "subtree_leaf_count": subtree_leaf_count,
        "left_child": body[10:42],
        "right_child": body[42:74],
    }


def encode_removal_tail(target_event_reference: bytes, target_commitment: bytes) -> bytes:
    """Encode the unchanged O-06b-2 logical-removal tail for suite 0x0001."""

    _require_width("target_event_reference", target_event_reference, 32)
    _require_width("target_commitment", target_commitment, 32)
    return target_event_reference + _u32(len(target_commitment)) + target_commitment


def parse_removal_tail(data: bytes) -> dict[str, bytes]:
    """Invert the fixed suite-0x0001 logical-removal tail with exact end."""

    if len(data) < 36:
        raise ModelInputError("REMOVAL_TAIL", "logical-removal tail is truncated")
    target_length = int.from_bytes(data[32:36], "big")
    if target_length != 32 or len(data) != 36 + target_length:
        raise ModelInputError(
            "REMOVAL_TAIL", "target commitment must be exactly 32 octets"
        )
    return {
        "target_event_reference": data[:32],
        "target_commitment": data[36:],
    }


def node_preimage_for_mutation(
    subtree_leaf_count: int,
    left: bytes,
    right: bytes,
    mutation: Mutation = Mutation(),
) -> bytes:
    preimage = node_preimage(subtree_leaf_count, left, right)
    if mutation.identifier == "M15_CHANGE_NODE_FORMAT":
        body = split_frame(preimage, D_NODE) + bytes(CONTEXT_OCTETS)
        return frame(D_NODE, body)
    return preimage


def _largest_power_of_two_below(value: int) -> int:
    if value < 2:
        raise ModelInputError("TREE_SIZE", "tree split requires at least two leaves")
    return 1 << ((value - 1).bit_length() - 1)


def _tree_root(
    leaves: Sequence[bytes], counters: WorkCounters, mutation: Mutation = Mutation()
) -> tuple[bytes, tuple[bytes, ...], WorkCounters]:
    if not leaves:
        raise ModelInputError("TREE_SIZE", "tree has no leaves")
    if len(leaves) == 1:
        return leaves[0], (), counters
    split = _largest_power_of_two_below(len(leaves))
    left, left_preimages, counters = _tree_root(leaves[:split], counters, mutation)
    right, right_preimages, counters = _tree_root(leaves[split:], counters, mutation)
    preimage = node_preimage_for_mutation(len(leaves), left, right, mutation)
    counters = counters.add(serialization_invocations=1)
    digest, counters = _digest(preimage, counters, node=True)
    return digest, left_preimages + right_preimages + (preimage,), counters


def derive_geometry(exact_content_length: int, chunk_size: int) -> Geometry:
    _require_u64("exact_content_length", exact_content_length)
    _require_u32("chunk_size", chunk_size)
    if chunk_size < 1 or chunk_size > MAX_LEAF_OCTETS:
        raise ModelInputError("CHUNK_SIZE", "chunk size outside representational ceiling")
    if chunk_size >= exact_content_length:
        raise ModelInputError("TREE_SHAPE", "tree requires at least two chunks")
    # Avoid the conventional ``(length + size - 1) // size`` form: its
    # intermediate addition can wrap at the u64 ceiling in fixed-width
    # implementations.  Division plus a remainder bit has the same result
    # without an overflowing intermediate.
    complete_chunks, remainder = divmod(exact_content_length, chunk_size)
    chunk_count = complete_chunks + (1 if remainder else 0)
    _require_u64("chunk_count", chunk_count)
    if chunk_count < 2:
        raise ModelInputError("CHUNK_COUNT", "tree requires at least two chunks")
    prefix_product = checked_u64_multiply(chunk_size, chunk_count - 1)
    final_length = exact_content_length - prefix_product
    if not 1 <= final_length <= chunk_size:
        raise ModelInputError("FINAL_CHUNK", "invalid final chunk length")
    return Geometry(chunk_size, chunk_count, final_length)


def commitment_body(
    context: CommitmentContext,
    content_type_id: int,
    exact_content_length: int,
    shape: int,
    geometry: Geometry | None,
    root: bytes,
    opening_randomizer: bytes,
    mutation: Mutation = Mutation(),
) -> bytes:
    _require_u32("content_type_id", content_type_id)
    _require_u64("exact_content_length", exact_content_length)
    _require_width("root", root, 32)
    _require_width("opening_randomizer", opening_randomizer, 32)
    if shape not in (SHAPE_SINGLE, SHAPE_TREE):
        raise ModelInputError("SHAPE", "unknown commitment shape")
    if shape == SHAPE_SINGLE and geometry is not None:
        raise ModelInputError("GEOMETRY", "single shape has no geometry")
    if shape == SHAPE_TREE and geometry is None:
        raise ModelInputError("GEOMETRY", "tree shape requires geometry")
    if shape == SHAPE_SINGLE and exact_content_length > MAX_LEAF_OCTETS:
        raise ModelInputError(
            "CONTENT_LENGTH", "single content exceeds len32-safe ceiling"
        )
    if shape == SHAPE_TREE:
        expected_geometry = derive_geometry(exact_content_length, geometry.chunk_size)
        if geometry != expected_geometry:
            raise ModelInputError(
                "GEOMETRY", "tree geometry does not match exact content length"
            )
    body = b"".join(
        (
            _context_for_role(context, role="commitment", shape=shape, mutation=mutation),
            _u32(content_type_id),
            _u64(exact_content_length),
            bytes((shape,)),
        )
    )
    if geometry is not None:
        body += _u32(geometry.chunk_size) + _u64(geometry.chunk_count) + _u32(geometry.final_chunk_length)
    body += root + opening_randomizer
    return body


def parse_commitment_preimage(data: bytes, mutation: Mutation = Mutation()) -> dict[str, object]:
    body = split_frame(data, D_COMMIT, mutation)
    if len(body) not in (COMMIT_BODY_SINGLE_OCTETS, COMMIT_BODY_TREE_OCTETS):
        raise ModelInputError("COMMITMENT_LENGTH", "unexpected commitment body width")
    context_bytes = body[:CONTEXT_OCTETS]
    parse_context(context_bytes)
    content_type_id = int.from_bytes(body[84:88], "big")
    exact_length = int.from_bytes(body[88:96], "big")
    shape = body[96]
    offset = 97
    geometry: Geometry | None = None
    if shape == SHAPE_TREE:
        if len(body) != COMMIT_BODY_TREE_OCTETS:
            raise ModelInputError("COMMITMENT_LENGTH", "tree body width mismatch")
        geometry = Geometry(
            int.from_bytes(body[offset : offset + 4], "big"),
            int.from_bytes(body[offset + 4 : offset + 12], "big"),
            int.from_bytes(body[offset + 12 : offset + 16], "big"),
        )
        offset += 16
    elif shape == SHAPE_SINGLE:
        if len(body) != COMMIT_BODY_SINGLE_OCTETS:
            raise ModelInputError("COMMITMENT_LENGTH", "single body width mismatch")
        if exact_length > MAX_LEAF_OCTETS:
            raise ModelInputError(
                "CONTENT_LENGTH", "single content exceeds len32-safe ceiling"
            )
    else:
        raise ModelInputError("SHAPE", "unknown commitment shape")
    root = body[offset : offset + 32]
    randomizer = body[offset + 32 : offset + 64]
    if len(root) != 32 or len(randomizer) != 32 or offset + 64 != len(body):
        raise ModelInputError("COMMITMENT_INVERSE", "commitment inverse is not exact")
    if geometry is not None and geometry != derive_geometry(
        exact_length, geometry.chunk_size
    ):
        raise ModelInputError(
            "GEOMETRY", "tree geometry does not match exact content length"
        )
    return {
        "context": context_bytes,
        "content_type_id": content_type_id,
        "exact_content_length": exact_length,
        "shape": shape,
        "geometry": geometry,
        "root": root,
        "opening_randomizer": randomizer,
    }


def build_commitment(
    context: CommitmentContext,
    content_type_id: int,
    content: bytes,
    opening_randomizer: bytes,
    *,
    chunk_size: int | None = None,
    mutation: Mutation = Mutation(),
) -> CommitmentResult:
    context.validate()
    _require_width("opening_randomizer", opening_randomizer, 32)
    shape = SHAPE_SINGLE if chunk_size is None else SHAPE_TREE
    if shape == SHAPE_SINGLE:
        if len(content) > MAX_LEAF_OCTETS:
            raise ModelInputError("CONTENT_LENGTH", "single content exceeds len32-safe ceiling")
        geometry = None
        chunks = (content,)
    else:
        geometry = derive_geometry(len(content), chunk_size)
        chunks = tuple(
            content[offset : min(offset + chunk_size, len(content))]
            for offset in range(0, len(content), chunk_size)
        )
        if len(chunks) != geometry.chunk_count or len(chunks[-1]) != geometry.final_chunk_length:
            raise AssertionError("derived geometry drift")

    counters = WorkCounters()
    leaves: list[bytes] = []
    leaf_preimages: list[bytes] = []
    for ordinal, chunk in enumerate(chunks):
        body = leaf_body(
            context,
            content_type_id,
            ordinal,
            chunk,
            opening_randomizer,
            shape=shape,
            mutation=mutation,
        )
        preimage = frame(D_LEAF, body)
        counters = counters.add(serialization_invocations=1)
        digest, counters = _digest(preimage, counters, leaf=True)
        leaves.append(digest)
        leaf_preimages.append(preimage)

    root, node_preimages, counters = _tree_root(leaves, counters, mutation)
    body = commitment_body(
        context,
        content_type_id,
        len(content),
        shape,
        geometry,
        root,
        opening_randomizer,
        mutation,
    )
    commitment_preimage = frame(D_COMMIT, body)
    counters = counters.add(serialization_invocations=1)
    commitment_value, counters = _digest(commitment_preimage, counters)
    return CommitmentResult(
        commitment_value,
        root,
        shape,
        len(content),
        content_type_id,
        geometry,
        opening_randomizer,
        tuple(leaf_preimages),
        node_preimages,
        commitment_preimage,
        counters,
    )


def measure_roundtrip_work(result: CommitmentResult) -> WorkCounters:
    """Parse every canonical preimage and expose bounded round-trip work.

    One parse and one inverse validation are counted for each framed leaf,
    interior-node and commitment preimage. Serialization counters originate in
    the producer path; hashing counters originate at each digest invocation.
    """

    counters = result.counters
    for preimage in result.leaf_preimages:
        parse_leaf_preimage(preimage)
        counters = counters.add(parse_invocations=1, inverse_invocations=1)
    for preimage in result.node_preimages:
        parse_node_preimage(preimage)
        counters = counters.add(parse_invocations=1, inverse_invocations=1)
    parse_commitment_preimage(result.commitment_preimage)
    return counters.add(parse_invocations=1, inverse_invocations=1)


def verifies(
    expected: CommitmentResult,
    context: CommitmentContext,
    content: bytes,
    *,
    mutation: Mutation = Mutation(),
) -> bool:
    chunk_size = expected.geometry.chunk_size if expected.geometry is not None else None
    rebuilt = build_commitment(
        context,
        expected.content_type_id,
        content,
        expected.opening_randomizer,
        chunk_size=chunk_size,
        mutation=mutation,
    )
    return rebuilt.commitment_value == expected.commitment_value


def derived_widths(mutation: Mutation = Mutation()) -> dict[str, int]:
    if mutation.identifier == "M12_RETAIN_OLD_WIDTHS":
        return {
            "context": 44,
            "leaf_body_prefix": 92,
            "leaf_preimage_overhead": 112,
            "commit_body_single": 121,
            "commit_body_tree": 137,
            "commit_preimage_single": 141,
            "commit_preimage_tree": 157,
            "max_leaf_octets": 4294967203,
        }
    return {
        "context": CONTEXT_OCTETS,
        "leaf_body_prefix": LEAF_FIXED_PREFIX_OCTETS,
        "leaf_preimage_overhead": LEAF_PREIMAGE_OVERHEAD,
        "commit_body_single": COMMIT_BODY_SINGLE_OCTETS,
        "commit_body_tree": COMMIT_BODY_TREE_OCTETS,
        "commit_preimage_single": COMMIT_PREIMAGE_SINGLE_OCTETS,
        "commit_preimage_tree": COMMIT_PREIMAGE_TREE_OCTETS,
        "max_leaf_octets": MAX_LEAF_OCTETS,
    }


def same_slot_relationship(
    credential_identifier: bytes,
    author_sequence: int,
    left_event_reference: bytes,
    right_event_reference: bytes,
    mutation: Mutation = Mutation(),
) -> str:
    _require_width("credential_identifier", credential_identifier, 32)
    _require_u64("author_sequence", author_sequence)
    _require_width("left_event_reference", left_event_reference, 32)
    _require_width("right_event_reference", right_event_reference, 32)
    if left_event_reference == right_event_reference:
        return "EXACT_DUPLICATE"
    if mutation.identifier == "M14_EQUAL_COMMITMENT_IS_DUPLICATE":
        return "EXACT_DUPLICATE"
    return "FORK_EVIDENCE"


def successful_verification_claims(mutation: Mutation = Mutation()) -> frozenset[str]:
    claims = {"CONTEXT_BOUND_COMMITMENT"}
    if mutation.identifier == "M16_INFER_AUTHORSHIP_ORIGINALITY":
        claims.update({"AUTHORSHIP", "ORIGINALITY", "TRUTH", "AUTHORITY"})
    return frozenset(claims)


def partial_verification_supported() -> bool:
    """C0.2k models complete-object verification only; O-11 owns proofs."""

    return False


def commitment_required_for_content_class(
    content_class: str, mutation: Mutation = Mutation()
) -> bool:
    if content_class not in {"NONE", "REQUIRED", "DETACHABLE"}:
        raise ModelInputError("CONTENT_CLASS", "unknown content class")
    if mutation.identifier == "M18_CONTROL_NONE_HAS_COMMITMENT" and content_class == "NONE":
        return True
    return content_class != "NONE"
