"""Closed Base-relative source and inventory model for C0.3 corpus generation."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from typing import Any


BASE_SHA = "7768c32d3ddba230bd60f8b5db1b34d4bcb8ec3b"
ENTRY_ROLES = frozenset(
    {
        "C03_SEMANTIC_LIMIT",
        "C03_ACTIVATION_CAPABILITY_INPUT",
        "C03_EXPLICIT_ZERO_OR_UNSUPPORTED",
    }
)
EXPECTED_COUNTS = {
    "actors": 10,
    "blockers": 13,
    "counterexamples": 16,
    "flows": 12,
    "invariants": 23,
    "layers": 6,
    "non_claims": 12,
    "objects": 7,
    "outcomes": 24,
    "residual_risks": 14,
    "review_queries": 9,
    "sources": 20,
    "state_models": 3,
}


class CorpusModelError(ValueError):
    """Pinned corpus input or closed inventory is invalid."""


class ProtocolError(CorpusModelError):
    """One transcript-only candidate failed at an exact local stage."""

    def __init__(self, code: str, stage: str = "S3_KERNEL_STRUCTURAL") -> None:
        super().__init__(code)
        self.code = code
        self.stage = stage


DOMAINS = {
    "application": bytes.fromhex("53545958000100010000000000000000"),
    "genesis_signature": bytes.fromhex("53545958000100020000000000000000"),
    "event_reference": bytes.fromhex("53545958000100030000000000000000"),
    "genesis_reference": bytes.fromhex("53545958000100040000000000000000"),
    "commitment": bytes.fromhex("53545958000100050000000000000000"),
    "leaf": bytes.fromhex("53545958000100060000000000000000"),
    "node": bytes.fromhex("53545958000100070000000000000000"),
}
MAX_U32 = (1 << 32) - 1
MAX_U64 = (1 << 64) - 1


def _uint(value: int, width: int, label: str) -> bytes:
    maximum = (1 << (8 * width)) - 1
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ProtocolError(f"{label.upper()}_OUT_OF_RANGE")
    return value.to_bytes(width, "big")


def _opaque(value: bytes, label: str) -> bytes:
    if not isinstance(value, bytes) or len(value) > MAX_U32:
        raise ProtocolError(f"{label.upper()}_LENGTH_INVALID")
    return _uint(len(value), 4, f"{label}_length") + value


def _fixed(value: bytes, width: int, label: str) -> bytes:
    if not isinstance(value, bytes) or len(value) != width:
        raise ProtocolError(f"{label.upper()}_WIDTH_INVALID")
    return value


def synthetic_octets(label: str, length: int) -> bytes:
    """Expand a public label deterministically; output is never secret material."""

    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(sha256(f"styx-c03/{label}/{counter}".encode()).digest())
        counter += 1
    return bytes(output[:length])


def framed_hash(domain: bytes, body: bytes) -> bytes:
    return sha256(domain + _uint(len(body), 4, "preimage") + body).digest()


def encode_genesis(fields: dict[str, Any]) -> bytes:
    policy = bytes.fromhex(fields["initialAuthorityPolicyHex"])
    key = bytes.fromhex(fields["rootVerificationKeyHex"])
    if not policy or len(key) != 32:
        raise ProtocolError("GENESIS_FIELDS_INVALID")
    body = b"".join(
        (
            _uint(1, 2, "protocol_version"),
            _uint(fields["applicationProfileId"], 4, "profile_id"),
            _uint(fields["applicationProfileVersion"], 4, "profile_version"),
            _fixed(bytes.fromhex(fields["contextIdentifierHex"]), 32, "context"),
            _uint(1, 2, "signature_suite"),
            _opaque(key, "root_key"),
            _opaque(policy, "initial_authority_policy"),
        )
    )
    if len(body) > MAX_U32 - 20:
        raise ProtocolError("GENESIS_BODY_LIMIT")
    return DOMAINS["genesis_signature"] + _uint(len(body), 4, "body_length") + body


def parse_genesis(transcript: bytes) -> dict[str, Any]:
    outer = ByteReader(transcript)
    if outer.take(16, "domain") != DOMAINS["genesis_signature"]:
        raise ProtocolError("WRONG_DOMAIN")
    body_length = outer.integer(4, "body_length")
    if body_length > MAX_U32 - 20:
        raise ProtocolError("GENESIS_BODY_LIMIT")
    body = ByteReader(outer.take(body_length, "body"))
    outer.finish("transcript")
    protocol = body.integer(2, "protocol")
    profile = body.integer(4, "profile")
    version = body.integer(4, "profile_version")
    context = body.take(32, "context")
    suite = body.integer(2, "signature_suite")
    key = body.opaque("root_key")
    policy = body.opaque("initial_authority_policy")
    body.finish("body")
    if protocol != 1 or profile <= 0 or version <= 0 or suite != 1 or len(key) != 32 or not policy:
        raise ProtocolError("GENESIS_FIELDS_INVALID")
    fields = {
        "applicationProfileId": profile,
        "applicationProfileVersion": version,
        "contextIdentifierHex": context.hex(),
        "initialAuthorityPolicyHex": policy.hex(),
        "rootVerificationKeyHex": key.hex(),
    }
    if encode_genesis(fields) != transcript:
        raise ProtocolError("NONCANONICAL_REENCODING")
    return fields


def encode_commitment(
    *,
    profile_id: int,
    profile_version: int,
    context: bytes,
    credential: bytes,
    sequence: int,
    content_type: int,
    content: bytes,
    randomizer: bytes,
    chunk_size: int | None = None,
) -> dict[str, Any]:
    """Compute the exact selected O-06b-2 commitment construction."""

    context_bytes = b"".join(
        (
            _uint(1, 2, "commitment_suite"),
            _uint(1, 2, "protocol_version"),
            _uint(profile_id, 4, "profile_id"),
            _uint(profile_version, 4, "profile_version"),
            _fixed(context, 32, "context"),
            _fixed(credential, 32, "credential"),
            _uint(sequence, 8, "sequence"),
        )
    )
    if len(context_bytes) != 84 or content_type <= 0:
        raise ProtocolError("COMMITMENT_CONTEXT_INVALID")
    _fixed(randomizer, 32, "randomizer")
    if chunk_size is None:
        chunks = [content]
        shape = 0
        geometry = None
    else:
        if chunk_size not in (4096, 16384) or not content or chunk_size >= len(content):
            raise ProtocolError("CHUNK_GEOMETRY_INVALID")
        chunks = [content[offset : offset + chunk_size] for offset in range(0, len(content), chunk_size)]
        shape = 1
        geometry = {
            "chunkCount": len(chunks),
            "chunkSize": chunk_size,
            "finalChunkLength": len(chunks[-1]),
        }
    leaves: list[bytes] = []
    for ordinal, chunk in enumerate(chunks):
        body = b"".join(
            (
                context_bytes,
                _uint(content_type, 4, "content_type"),
                _uint(ordinal, 8, "leaf_ordinal"),
                _uint(len(chunk), 4, "leaf_length"),
                randomizer,
                chunk,
            )
        )
        leaves.append(framed_hash(DOMAINS["leaf"], body))

    def tree(values: list[bytes]) -> bytes:
        if len(values) == 1:
            return values[0]
        split = 1 << ((len(values) - 1).bit_length() - 1)
        left = tree(values[:split])
        right = tree(values[split:])
        node_body = _uint(1, 2, "suite") + _uint(len(values), 8, "subtree") + left + right
        return framed_hash(DOMAINS["node"], node_body)

    root = tree(leaves)
    geometry_bytes = b""
    if geometry is not None:
        geometry_bytes = (
            _uint(geometry["chunkSize"], 4, "chunk_size")
            + _uint(geometry["chunkCount"], 8, "chunk_count")
            + _uint(geometry["finalChunkLength"], 4, "final_chunk_length")
        )
    commitment_body = b"".join(
        (
            context_bytes,
            _uint(content_type, 4, "content_type"),
            _uint(len(content), 8, "content_length"),
            _uint(shape, 1, "shape"),
            geometry_bytes,
            root,
            randomizer,
        )
    )
    return {
        "commitmentHex": framed_hash(DOMAINS["commitment"], commitment_body).hex(),
        "geometry": geometry,
        "leafDigests": [value.hex() for value in leaves],
        "randomizerHex": randomizer.hex(),
        "rootHex": root.hex(),
        "shape": "TREE" if shape else "SINGLE",
    }


def encode_event(fields: dict[str, Any]) -> bytes:
    """Encode the exact application-event transcript selected by O-06b-1."""

    role = fields["eventRole"]
    content = fields["content"]
    parents = [bytes.fromhex(value) for value in fields["causalParents"]]
    if parents != sorted(set(parents)):
        raise ProtocolError("CAUSAL_FRONTIER_NONCANONICAL")
    predecessor_hex = fields["directPredecessorHex"]
    predecessor = bytes.fromhex(predecessor_hex) if predecessor_hex is not None else None
    sequence = fields["authorSequence"]
    if (sequence == 0) == (predecessor is not None):
        raise ProtocolError("SEQUENCE_PREDECESSOR_MISMATCH")
    if predecessor is not None and predecessor in parents:
        raise ProtocolError("PREDECESSOR_DUPLICATED_IN_FRONTIER")
    content_class = {"NONE": 0, "REQUIRED": 1, "DETACHABLE": 2}.get(content["class"])
    if content_class is None:
        raise ProtocolError("CONTENT_CLASS_UNKNOWN")
    descriptor = _uint(content_class, 1, "content_class") + _uint(
        content["exactLength"], 8, "content_length"
    )
    if content_class == 0:
        if content["exactLength"] != 0 or set(content) != {"class", "exactLength"}:
            raise ProtocolError("NONE_DESCRIPTOR_INVALID")
    else:
        commitment = bytes.fromhex(content["commitmentHex"])
        shape = {"SINGLE": 0, "TREE": 1}.get(content["shape"])
        if shape is None or len(commitment) != 32 or content["contentType"] <= 0:
            raise ProtocolError("CONTENT_DESCRIPTOR_INVALID")
        geometry = content.get("geometry")
        if shape == 0 and geometry is not None:
            raise ProtocolError("SINGLE_GEOMETRY_PRESENT")
        if shape == 1 and not isinstance(geometry, dict):
            raise ProtocolError("TREE_GEOMETRY_MISSING")
        descriptor += b"".join(
            (
                _uint(content["contentType"], 4, "content_type"),
                _uint(1, 2, "commitment_suite"),
                _uint(shape, 1, "shape"),
                _opaque(commitment, "commitment"),
                _uint(1 if geometry else 0, 1, "geometry_presence"),
            )
        )
        if geometry:
            geometry_bytes = (
                _uint(geometry["chunkSize"], 4, "chunk_size")
                + _uint(geometry["chunkCount"], 8, "chunk_count")
                + _uint(geometry["finalChunkLength"], 4, "final_chunk_length")
            )
            descriptor += _opaque(geometry_bytes, "geometry")
    tail = b""
    if role == "ORDINARY":
        role_code = 0
        if "tail" in fields:
            raise ProtocolError("ORDINARY_TAIL_FORBIDDEN")
    elif role == "REMOVAL":
        role_code = 1
        if content_class != 0:
            raise ProtocolError("CONTROL_CONTENT_FORBIDDEN")
        tail_value = fields["tail"]
        tail = _fixed(bytes.fromhex(tail_value["targetEventReferenceHex"]), 32, "target_event")
        tail += _opaque(
            _fixed(bytes.fromhex(tail_value["targetCommitmentHex"]), 32, "target_commitment"),
            "target_commitment",
        )
    elif role == "CREDENTIAL":
        role_code = 2
        if content_class != 0:
            raise ProtocolError("CONTROL_CONTENT_FORBIDDEN")
        tail_value = fields["tail"]
        kind = {"GRANT": 1, "REVOKE": 2, "ROTATE": 3, "RECOVER": 4, "POLICY": 5, "CLOSURE": 6}.get(
            tail_value["kind"]
        )
        if kind is None:
            raise ProtocolError("CONTROL_KIND_UNKNOWN")
        tail = _uint(kind, 1, "control_kind")
        if kind == 1:
            key = bytes.fromhex(tail_value["granteeVerificationKeyHex"])
            tail += _uint(1, 2, "grantee_suite") + _opaque(key, "grantee_key")
        elif kind == 2:
            tail += _fixed(bytes.fromhex(tail_value["targetCredentialHex"]), 32, "target_credential")
        elif kind == 3:
            tail += _fixed(bytes.fromhex(tail_value["retiringCredentialHex"]), 32, "retiring_credential")
            tail += _fixed(bytes.fromhex(tail_value["replacementGrantHex"]), 32, "replacement_grant")
        elif kind == 4:
            tail += _fixed(bytes.fromhex(tail_value["retiredCredentialHex"]), 32, "retired_credential")
            tail += _fixed(bytes.fromhex(tail_value["recoveryGrantHex"]), 32, "recovery_grant")
    else:
        raise ProtocolError("EVENT_ROLE_UNKNOWN")
    body = b"".join(
        (
            _uint(1, 2, "protocol_version"),
            _uint(fields["applicationProfileId"], 4, "profile_id"),
            _uint(fields["applicationProfileVersion"], 4, "profile_version"),
            _fixed(bytes.fromhex(fields["contextIdentifierHex"]), 32, "context"),
            _uint(1, 2, "object_kind"),
            _uint(role_code, 1, "event_role"),
            _uint(fields["eventTypeId"], 4, "event_type"),
            _uint(fields["schemaId"], 4, "schema_id"),
            _uint(fields["schemaVersion"], 4, "schema_version"),
            _opaque(bytes.fromhex(fields["transitionBlockHex"]), "transition_block"),
            _fixed(bytes.fromhex(fields["credentialIdentifierHex"]), 32, "credential"),
            _uint(sequence, 8, "author_sequence"),
            _uint(1 if predecessor is not None else 0, 1, "predecessor_presence"),
            predecessor or b"",
            _uint(len(parents), 4, "parent_count"),
            b"".join(parents),
            _fixed(bytes.fromhex(fields["genesisReferenceHex"]), 32, "genesis_reference"),
            descriptor,
            tail,
        )
    )
    if len(body) > MAX_U32 - 20:
        raise ProtocolError("FRAMING_OBJECT_LIMIT")
    return DOMAINS["application"] + _uint(len(body), 4, "body_length") + body


@dataclass
class ByteReader:
    data: bytes
    offset: int = 0

    def take(self, count: int, label: str) -> bytes:
        if count < 0 or count > len(self.data) - self.offset:
            raise ProtocolError(f"TRUNCATED_{label.upper()}")
        result = self.data[self.offset : self.offset + count]
        self.offset += count
        return result

    def integer(self, width: int, label: str) -> int:
        return int.from_bytes(self.take(width, label), "big")

    def opaque(self, label: str) -> bytes:
        return self.take(self.integer(4, f"{label}_length"), label)

    def finish(self, label: str) -> None:
        if self.offset != len(self.data):
            raise ProtocolError(f"TRAILING_{label.upper()}")


def parse_event(transcript: bytes) -> dict[str, Any]:
    """Parse and canonically re-encode a corpus event."""

    outer = ByteReader(transcript)
    if outer.take(16, "domain") != DOMAINS["application"]:
        raise ProtocolError("WRONG_DOMAIN")
    body_length = outer.integer(4, "body_length")
    if body_length > MAX_U32 - 20:
        raise ProtocolError("FRAMING_OBJECT_LIMIT")
    body = ByteReader(outer.take(body_length, "body"))
    outer.finish("transcript")
    protocol = body.integer(2, "protocol")
    profile = body.integer(4, "profile")
    profile_version = body.integer(4, "profile_version")
    context = body.take(32, "context")
    object_kind = body.integer(2, "object_kind")
    role_code = body.integer(1, "role")
    event_type = body.integer(4, "event_type")
    schema = body.integer(4, "schema")
    schema_version = body.integer(4, "schema_version")
    transition = body.opaque("transition_block")
    credential = body.take(32, "credential")
    sequence = body.integer(8, "sequence")
    presence = body.integer(1, "predecessor_presence")
    if presence not in (0, 1):
        raise ProtocolError("PREDECESSOR_PRESENCE_INVALID")
    predecessor = body.take(32, "predecessor") if presence else None
    parent_count = body.integer(4, "parent_count")
    if parent_count > 8:
        raise ProtocolError("PARENTS_PER_EVENT_LIMIT")
    parents = [body.take(32, "parent") for _ in range(parent_count)]
    genesis = body.take(32, "genesis")
    content_class = body.integer(1, "content_class")
    exact_length = body.integer(8, "content_length")
    content: dict[str, Any] = {
        "class": {0: "NONE", 1: "REQUIRED", 2: "DETACHABLE"}.get(content_class),
        "exactLength": exact_length,
    }
    if content["class"] is None:
        raise ProtocolError("CONTENT_CLASS_UNKNOWN")
    if content_class == 0:
        if exact_length != 0:
            raise ProtocolError("NONE_DESCRIPTOR_INVALID")
    else:
        content_type = body.integer(4, "content_type")
        suite = body.integer(2, "suite")
        shape_code = body.integer(1, "shape")
        commitment = body.opaque("commitment")
        geometry_presence = body.integer(1, "geometry_presence")
        if suite != 1 or len(commitment) != 32 or geometry_presence not in (0, 1):
            raise ProtocolError("CONTENT_DESCRIPTOR_INVALID")
        geometry = None
        if geometry_presence:
            encoded_geometry = ByteReader(body.opaque("geometry"))
            geometry = {
                "chunkSize": encoded_geometry.integer(4, "chunk_size"),
                "chunkCount": encoded_geometry.integer(8, "chunk_count"),
                "finalChunkLength": encoded_geometry.integer(4, "final_chunk_length"),
            }
            encoded_geometry.finish("geometry")
        shape = {0: "SINGLE", 1: "TREE"}.get(shape_code)
        if shape is None or (shape == "SINGLE") == (geometry is not None):
            raise ProtocolError("CONTENT_GEOMETRY_INVALID")
        content.update(
            {
                "commitmentHex": commitment.hex(),
                "contentType": content_type,
                "shape": shape,
            }
        )
        if geometry is not None:
            content["geometry"] = geometry
    role = {0: "ORDINARY", 1: "REMOVAL", 2: "CREDENTIAL"}.get(role_code)
    fields: dict[str, Any] = {
        "applicationProfileId": profile,
        "applicationProfileVersion": profile_version,
        "authorSequence": sequence,
        "causalParents": [value.hex() for value in parents],
        "content": content,
        "contextIdentifierHex": context.hex(),
        "credentialIdentifierHex": credential.hex(),
        "directPredecessorHex": predecessor.hex() if predecessor else None,
        "eventRole": role,
        "eventTypeId": event_type,
        "genesisReferenceHex": genesis.hex(),
        "schemaId": schema,
        "schemaVersion": schema_version,
        "transitionBlockHex": transition.hex(),
    }
    if protocol != 1 or object_kind != 1 or min(profile, profile_version, event_type, schema, schema_version) <= 0:
        raise ProtocolError("UNSUPPORTED_PROFILE_OR_REGISTRY")
    if role == "REMOVAL":
        target_event = body.take(32, "target_event")
        fields["tail"] = {
            "targetCommitmentHex": body.opaque("target_commitment").hex(),
            "targetEventReferenceHex": target_event.hex(),
        }
    elif role == "CREDENTIAL":
        kind_code = body.integer(1, "control_kind")
        kind = {1: "GRANT", 2: "REVOKE", 3: "ROTATE", 4: "RECOVER", 5: "POLICY", 6: "CLOSURE"}.get(kind_code)
        if kind is None:
            raise ProtocolError("CONTROL_KIND_UNKNOWN")
        tail: dict[str, Any] = {"kind": kind}
        if kind == "GRANT":
            if body.integer(2, "grantee_suite") != 1:
                raise ProtocolError("GRANTEE_SUITE_UNSUPPORTED")
            tail["granteeVerificationKeyHex"] = body.opaque("grantee_key").hex()
        elif kind == "REVOKE":
            tail["targetCredentialHex"] = body.take(32, "target_credential").hex()
        elif kind == "ROTATE":
            tail["retiringCredentialHex"] = body.take(32, "retiring_credential").hex()
            tail["replacementGrantHex"] = body.take(32, "replacement_grant").hex()
        elif kind == "RECOVER":
            tail["retiredCredentialHex"] = body.take(32, "retired_credential").hex()
            tail["recoveryGrantHex"] = body.take(32, "recovery_grant").hex()
        fields["tail"] = tail
    elif role != "ORDINARY":
        raise ProtocolError("EVENT_ROLE_UNKNOWN")
    body.finish("body")
    if encode_event(fields) != transcript:
        raise ProtocolError("NONCANONICAL_REENCODING")
    return fields


# Minimal verification-only Ed25519 implementation. It is deterministic corpus
# evidence, deliberately non-constant-time, and never imported by product code.
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
_B = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202,
    46316835694926478169428394003475163141307993866256225615783033603165251855960,
)


def _ed_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    x1, y1 = left
    x2, y2 = right
    factor = _D * x1 * x2 * y1 * y2 % _P
    return (
        (x1 * y2 + x2 * y1) * pow(1 + factor, _P - 2, _P) % _P,
        (y1 * y2 + x1 * x2) * pow(1 - factor, _P - 2, _P) % _P,
    )


def _ed_mul(scalar: int, point: tuple[int, int] = _B) -> tuple[int, int]:
    result = (0, 1)
    addend = point
    while scalar:
        if scalar & 1:
            result = _ed_add(result, addend)
        addend = _ed_add(addend, addend)
        scalar >>= 1
    return result


def _ed_encode(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_decode(encoded: bytes) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ProtocolError("SIGNATURE_POINT_LENGTH")
    raw = int.from_bytes(encoded, "little")
    sign = raw >> 255
    y = raw & ((1 << 255) - 1)
    if y >= _P:
        raise ProtocolError("SIGNATURE_POINT_NONCANONICAL")
    value = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(value, (_P + 3) // 8, _P)
    if x * x % _P != value:
        x = x * _I % _P
    if x * x % _P != value or (x == 0 and sign):
        raise ProtocolError("SIGNATURE_POINT_INVALID")
    if (x & 1) != sign:
        x = (-x) % _P
    return x, y


def ed25519_sign(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    from hashlib import sha512

    _fixed(seed, 32, "signing_seed")
    expanded = sha512(seed).digest()
    clamped = bytearray(expanded[:32])
    clamped[0] &= 248
    clamped[31] &= 63
    clamped[31] |= 64
    secret = int.from_bytes(clamped, "little")
    public = _ed_encode(_ed_mul(secret))
    nonce = int.from_bytes(sha512(expanded[32:] + message).digest(), "little") % _L
    encoded_r = _ed_encode(_ed_mul(nonce))
    challenge = int.from_bytes(sha512(encoded_r + public + message).digest(), "little") % _L
    scalar = (nonce + challenge * secret) % _L
    return public, encoded_r + scalar.to_bytes(32, "little")


def ed25519_verify(public: bytes, signature: bytes, message: bytes) -> bool:
    from hashlib import sha512

    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        point_a = _ed_decode(public)
        point_r = _ed_decode(signature[:32])
    except ProtocolError:
        return False
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= _L:
        return False
    challenge = int.from_bytes(sha512(signature[:32] + public + message).digest(), "little") % _L
    return _ed_mul(scalar) == _ed_add(point_r, _ed_mul(challenge, point_a))


def evaluate_vector(record: dict[str, Any]) -> dict[str, Any]:
    """Independently evaluate ordinary corpus inputs without expected-result fields."""

    transcript = bytes.fromhex(record["transcriptHex"])
    state_digest = sha256(b"styx-c03/evaluation/initial").hexdigest()
    result: dict[str, Any] = {
        "commitmentVerification": "NOT_PRESENT",
        "externalEffects": [],
        "localOutcome": "APPLIED",
        "postStateDigest": None,
        "preStateDigest": state_digest,
        "remoteClass": "APPLIED",
        "signatureVerification": "NOT_EVALUATED",
        "stage": "FINAL_AFTER_S6",
        "transcriptVerification": "VALID",
    }

    def reject(outcome: str, stage: str, *, transcript_status: str = "VALID") -> dict[str, Any]:
        result.update(
            {
                "localOutcome": outcome,
                "postStateDigest": state_digest,
                "remoteClass": "OPAQUE_REMOTE_FAILURE",
                "stage": stage,
                "transcriptVerification": transcript_status,
            }
        )
        return result

    try:
        if record["kind"] == "GENESIS":
            fields = parse_genesis(transcript)
            reference = framed_hash(DOMAINS["genesis_reference"], transcript).hex()
            expected_reference = record["genesisReferenceHex"]
        elif record["kind"] == "APPLICATION_EVENT":
            fields = parse_event(transcript)
            reference = framed_hash(DOMAINS["event_reference"], transcript).hex()
            expected_reference = record["eventReferenceHex"]
        else:
            raise ProtocolError("OBJECT_KIND_UNKNOWN")
    except (ProtocolError, ValueError, KeyError):
        return reject("STRUCTURAL_REJECTION", "S3_KERNEL_STRUCTURAL", transcript_status="REJECTED")
    if reference != expected_reference:
        return reject("REFERENCE_COLLISION_UNSUPPORTED", "S3_KERNEL_STRUCTURAL")
    public_key = bytes.fromhex(record["binding"]["verificationKeyHex"])
    signature = bytes.fromhex(record["signatureHex"])
    if not ed25519_verify(public_key, signature, transcript):
        result["signatureVerification"] = "REJECTED"
        return reject("INVALID", "S3_KERNEL_STRUCTURAL")
    result["signatureVerification"] = "VALID"
    if record["kind"] == "APPLICATION_EVENT":
        binding = record["binding"]
        if (
            binding["contextIdentifierHex"] != fields["contextIdentifierHex"]
            or binding["credentialIdentifierHex"] != fields["credentialIdentifierHex"]
        ):
            return reject("CREDENTIAL_BINDING_MISMATCH", "S3_KERNEL_STRUCTURAL")
        content = fields["content"]
        if content["class"] != "NONE":
            opening = record.get("opening")
            if opening is None:
                result["commitmentVerification"] = "PENDING"
                return reject("OPENING_MISSING", "EVENT_LOCAL")
            supplied = bytes.fromhex(opening["contentHex"])
            randomizer = bytes.fromhex(opening["randomizerHex"])
            commitment = encode_commitment(
                profile_id=fields["applicationProfileId"],
                profile_version=fields["applicationProfileVersion"],
                context=bytes.fromhex(fields["contextIdentifierHex"]),
                credential=bytes.fromhex(fields["credentialIdentifierHex"]),
                sequence=fields["authorSequence"],
                content_type=content["contentType"],
                content=supplied,
                randomizer=randomizer,
                chunk_size=(content.get("geometry") or {}).get("chunkSize"),
            )
            if (
                len(supplied) != content["exactLength"]
                or commitment["commitmentHex"] != content["commitmentHex"]
            ):
                result["commitmentVerification"] = "REJECTED"
                return reject("COMMITMENT_MISMATCH", "S3_KERNEL_STRUCTURAL")
            result["commitmentVerification"] = "VALID"
    conditions = record.get("conditions", {})
    precedence = (
        ("resourceFailure", "CURRENT_OBJECT_OUT_OF_PROFILE", "S3_KERNEL_STRUCTURAL"),
        ("duplicate", "DUPLICATE", "S3_KERNEL_STRUCTURAL"),
        ("missingDependency", "PENDING_ANCESTOR", "S4_GRAPH_ADMISSION"),
        ("fork", "FORK_EVIDENCE", "EVENT_LOCAL"),
        ("postRevocation", "POST_REVOCATION", "EVENT_LOCAL"),
        ("authorized", "AUTHENTIC_BUT_UNAUTHORIZED", "EVENT_LOCAL"),
    )
    for key, outcome, stage in precedence:
        if key == "authorized":
            matched = conditions.get(key) is False
        else:
            matched = bool(conditions.get(key))
        if matched:
            return reject(outcome, stage)
    result["postStateDigest"] = sha256(
        bytes.fromhex(state_digest) + bytes.fromhex(reference)
    ).hexdigest()
    return result


@dataclass(frozen=True)
class BaseReader:
    repo_root: Path
    base: str = BASE_SHA

    def read(self, path: str) -> bytes:
        if path.startswith("/") or ".." in Path(path).parts:
            raise CorpusModelError(f"unsafe repository path: {path}")
        result = subprocess.run(
            ["git", "show", f"{self.base}:{path}"],
            cwd=self.repo_root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode:
            raise CorpusModelError(f"missing Base blob: {path}")
        return result.stdout

    def json(self, path: str) -> Any:
        try:
            return json.loads(self.read(path))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise CorpusModelError(f"invalid Base JSON: {path}") from error


def sha256_hex(data: bytes) -> str:
    return sha256(data).hexdigest()


def load_local_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise CorpusModelError(f"invalid tooling JSON: {path}") from error
    if not isinstance(value, dict):
        raise CorpusModelError(f"tooling JSON must be an object: {path}")
    return value


def _ids(records: Any, label: str) -> list[str]:
    if not isinstance(records, list):
        raise CorpusModelError(f"{label} must be a list")
    values = [record.get("id") for record in records if isinstance(record, dict)]
    if len(values) != len(records) or any(not isinstance(value, str) for value in values):
        raise CorpusModelError(f"{label} has a malformed identifier")
    if len(set(values)) != len(values):
        raise CorpusModelError(f"{label} identifiers are not unique")
    return values


def validate_sources(repo_root: Path) -> dict[str, Any]:
    tool_root = repo_root / "tools/causal-flow-simulator/c03"
    source_map = load_local_json(tool_root / "corpus-source-map.json")
    if source_map.get("schema") != "styx-c03-corpus-source-map/v1":
        raise CorpusModelError("source-map schema mismatch")
    if source_map.get("base") != BASE_SHA:
        raise CorpusModelError("source-map Base mismatch")
    reader = BaseReader(repo_root)
    seen_ids: set[str] = set()
    for source in source_map.get("direct_sources", []):
        if not isinstance(source, dict) or set(source) != {"anchors", "id", "path", "sha256"}:
            raise CorpusModelError("direct source schema mismatch")
        identifier = source["id"]
        if identifier in seen_ids:
            raise CorpusModelError(f"duplicate direct source: {identifier}")
        seen_ids.add(identifier)
        data = reader.read(source["path"])
        if sha256_hex(data) != source["sha256"]:
            raise CorpusModelError(f"Base source digest mismatch: {source['path']}")
        text = data.decode("utf-8")
        for anchor in source["anchors"]:
            if not isinstance(anchor, str) or not anchor or text.count(anchor) != 1:
                raise CorpusModelError(
                    f"source anchor is missing or ambiguous: {identifier}:{anchor}"
                )

    model = reader.json("docs/protocol/review/styx-app-kernel-v0-review-model.json")
    model_sources = model.get("sources")
    if not isinstance(model_sources, list):
        raise CorpusModelError("review-model source registry is missing")
    source_registry: dict[str, tuple[str, str]] = {}
    source_text: dict[str, str] = {}
    for source in model_sources:
        if not isinstance(source, dict):
            raise CorpusModelError("malformed review-model source")
        identifier = source.get("id")
        path = source.get("path")
        digest = source.get("sha256")
        if not all(isinstance(value, str) and value for value in (identifier, path, digest)):
            raise CorpusModelError("incomplete review-model source")
        if identifier in source_registry:
            raise CorpusModelError(f"duplicate review-model source: {identifier}")
        data = reader.read(path)
        if sha256_hex(data) != digest:
            raise CorpusModelError(f"review-model source digest mismatch: {path}")
        source_registry[identifier] = (path, digest)
        source_text[identifier] = data.decode("utf-8")
    if set(source_registry) != set(
        load_local_json(tool_root / "corpus-inventory.json")[
            "expected_review_model_ids"
        ]["sources"]
    ):
        raise CorpusModelError("review-model source set mismatch")
    for family, records in model.items():
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            for citation in record.get("citations", []):
                if not isinstance(citation, dict):
                    raise CorpusModelError(f"malformed citation in {family}")
                source_id = citation.get("source_id")
                anchor = citation.get("anchor")
                if source_id not in source_text or not isinstance(anchor, str) or not anchor:
                    raise CorpusModelError(f"invalid citation in {family}")
                if source_text[source_id].count(anchor) != 1:
                    raise CorpusModelError(
                        f"review-model anchor is missing or ambiguous: {source_id}:{anchor}"
                    )
    return source_map


def validate_inventory(repo_root: Path) -> dict[str, Any]:
    tool_root = repo_root / "tools/causal-flow-simulator/c03"
    inventory = load_local_json(tool_root / "corpus-inventory.json")
    if inventory.get("schema") != "styx-c03-corpus-inventory/v1":
        raise CorpusModelError("inventory schema mismatch")
    reader = BaseReader(repo_root)
    model = reader.json("docs/protocol/review/styx-app-kernel-v0-review-model.json")
    expected_ids = inventory.get("expected_review_model_ids")
    if not isinstance(expected_ids, dict) or set(expected_ids) != set(EXPECTED_COUNTS):
        raise CorpusModelError("review-model inventory keys mismatch")
    for key, count in EXPECTED_COUNTS.items():
        actual = _ids(model.get(key), key)
        if len(actual) != count or actual != expected_ids[key]:
            raise CorpusModelError(f"closed review-model set mismatch: {key}")

    envelope = reader.json("tools/causal-flow-simulator/o08/resource-envelope.candidate.json")
    entries = envelope.get("entries")
    if not isinstance(entries, dict):
        raise CorpusModelError("O-08 entries are missing")
    role_map = inventory.get("o08_roles")
    if not isinstance(role_map, dict):
        raise CorpusModelError("O-08 role inventory is missing")
    for role, expected in role_map.items():
        actual = sorted(
            identifier
            for identifier, entry in entries.items()
            if isinstance(entry, dict) and entry.get("role") == role
        )
        if actual != expected:
            raise CorpusModelError(f"O-08 role partition mismatch: {role}")
    if sum(len(role_map[role]) for role in ENTRY_ROLES) != 53:
        raise CorpusModelError("O-08 C0.3 entry cardinality mismatch")

    taxonomy = reader.json("tools/causal-flow-simulator/o10/outcome-taxonomy.json")
    if _ids(taxonomy.get("primaries"), "O-10 primaries") != inventory["o10_primaries"]:
        raise CorpusModelError("O-10 primary inventory mismatch")
    if taxonomy.get("post_c03_markers") != inventory["o10_post_c03_markers"]:
        raise CorpusModelError("O-10 post-marker inventory mismatch")
    if taxonomy.get("alias") != inventory["o10_alias"]:
        raise CorpusModelError("O-10 alias mismatch")

    o10_sources = reader.json("tools/causal-flow-simulator/o10/source-inventory.json")
    if len(o10_sources.get("rows", [])) != inventory["o10_source_row_count"]:
        raise CorpusModelError("O-10 source-row cardinality mismatch")
    o07 = reader.json("tools/causal-flow-simulator/o07/required_atom_instances_v1.json")
    if (
        o07.get("relation_count") != inventory["o07_relation_count"]
        or len(o07.get("rows", [])) != inventory["o07_relation_count"]
    ):
        raise CorpusModelError("O-07 relation cardinality mismatch")
    return inventory


def validate_base_inputs(repo_root: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Fail closed before any corpus generation is attempted."""

    if subprocess.run(
        ["git", "cat-file", "-e", f"{BASE_SHA}^{{commit}}"], cwd=repo_root
    ).returncode:
        raise CorpusModelError("exact Base commit is unavailable")
    return validate_sources(repo_root), validate_inventory(repo_root)
