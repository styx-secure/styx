"""Closed Base-relative source and inventory model for C0.3 corpus generation."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from typing import Any

from canonical_json import dumps


BASE_SHA = "0fbba871130e4e100558030837e03dd609128976"
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

    def __init__(
        self,
        code: str,
        stage: str = "S3_KERNEL_STRUCTURAL",
        *,
        observations: dict[str, str] | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.stage = stage
        self.observations = observations or {}


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
O08_LIMITS = {
    "AP_TRANSITION_BLOCK_OCTETS": 4096,
    "CHUNKS_PER_CONTENT": 64,
    "CONTENT_EXACT_OCTETS": 262144,
    "FRAMING_OBJECT_OCTETS": 8192,
    "GENESIS_BODY_OCTETS": 8192,
    "GENESIS_POLICY_OCTETS": 4096,
    "PARENTS_PER_EVENT": 8,
    "SEQUENCE_VALUE": 4095,
}
O08_CHUNK_OCTETS = frozenset({4096, 16384})
PRODUCED_K_PRIMARIES = frozenset(
    {
        "COMMITMENT_MISMATCH",
        "CONTEXT_CAPACITY_EXHAUSTED",
        "CREDENTIAL_BINDING_MISMATCH",
        "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED",
        "CURRENT_OBJECT_OUT_OF_PROFILE",
        "DEPENDENCY_DEFERRED",
        "DUPLICATE",
        "FORK_EVIDENCE",
        "INVALID",
        "LENGTH_MISMATCH",
        "OPENING_MISSING",
        "PENDING_ANCESTOR",
        "PENDING_OPENING",
        "REFERENCE_COLLISION_UNSUPPORTED",
        "STRUCTURAL_REJECTION",
        "UNRESOLVED_CREDENTIAL_BINDING",
    }
)
AP_OWNED_EXCLUSIONS = frozenset(
    {
        "APPLIED",
        "AUTHENTIC_BUT_UNAUTHORIZED",
        "AUTHORITY_PROJECTION_UNAVAILABLE",
        "LINEAGE_QUARANTINED",
        "POST_REVOCATION",
    }
)
TRANSCRIPT_PROFILE_UNREACHABLE = frozenset(
    {
        "PROFILE_ACTIVATION_UNSUPPORTED",
        "REMOVAL_INAPPLICABLE",
        "STALE_EVIDENCE",
        "UNRESOLVABLE_CREDENTIAL",
    }
)
AP_EXPECTATION_ONLY_STEP_LOCATORS = frozenset(
    {
        "scenario-counterexample-ce_bounded_contested_standing:2",
        "scenario-counterexample-ce_grant_revoke_laundering_order_a:2",
        "scenario-counterexample-ce_grant_revoke_laundering_order_b:2",
        "scenario-counterexample-ce_mutual_reduction_no_authority:1",
        "scenario-counterexample-ce_mutual_reduction_no_authority:2",
        "scenario-counterexample-ce_self_lineage_reduction:1",
        "scenario-counterexample-ce_single_authority_takeover:1",
        "scenario-counterexample-ce_subtree_amplification:2",
        "scenario-history-revocation-effect:1",
        "scenario-history-rotation-effect:1",
        "scenario-invariant-inv_auth_not_key:0",
        "scenario-invariant-inv_lineage_containment:0",
        "scenario-invariant-inv_self_lineage_reduction:0",
        "scenario-vector-inv-post-revocation:0",
        "scenario-vector-inv-self-lineage:0",
        "scenario-vector-inv-unauthorized:0",
    }
)
O10_TAXONOMY_PATH = (
    Path(__file__).resolve().parents[1] / "o10" / "outcome-taxonomy.json"
)
NONEXECUTABLE_INVARIANTS = frozenset(
    {
        "INV_C0_3_NO_GO",
        "INV_SOURCE_AUTHORITY",
    }
)
SEMANTIC_OBSERVATION_FIELDS = (
    "apAuthorityResult",
    "commitmentMatchVerification",
    "commitmentVerification",
    "dependencyStatus",
    "executed",
    "externalEffects",
    "inputDigest",
    "kBindingAdmission",
    "outcomeEvaluated",
    "geometryPredicate1",
    "geometryPredicate2",
    "geometryPredicate3",
    "geometryPredicate4",
    "geometryPredicate5",
    "geometryPredicate6",
    "geometryPredicate7",
    "signatureVerification",
    "stage",
    "suppliedLengthVerification",
    "transcriptVerification",
)
OPTIONAL_SEMANTIC_OBSERVATION_FIELDS = ("localOutcome", "remoteClass")
NONSEMANTIC_VECTOR_FIELDS = frozenset(
    {"citations", "expected", "id", "mutation", "sourceVectorId", "synthetic", "testOnly"}
)


def semantic_input_digest(vector: dict[str, Any]) -> str:
    """Bind the complete candidate input while excluding corpus bookkeeping."""

    projection = {
        key: value
        for key, value in vector.items()
        if key not in NONSEMANTIC_VECTOR_FIELDS
    }
    return sha256(dumps(projection)).hexdigest()


def semantic_observation_digest(steps: list[dict[str, Any]]) -> str:
    """Hash only computed protocol observations, never scenario identity."""

    projection = []
    for step in steps:
        observation = {
            field: step[field] for field in SEMANTIC_OBSERVATION_FIELDS
        }
        for field in OPTIONAL_SEMANTIC_OBSERVATION_FIELDS:
            present = field in step
            observation[f"{field}Present"] = present
            if present:
                observation[field] = step[field]
        projection.append(observation)
    return sha256(dumps(projection)).hexdigest()


def transition_input_is_compatible(result: dict[str, Any]) -> bool:
    """A model transition may refine only a fully admitted transcript input."""

    return (
        result.get("kBindingAdmission") == "ADMITTED"
        and result.get("apAuthorityResult") == "AP_FOLD_NOT_EXECUTED"
        and result.get("outcomeEvaluated") is False
        and "localOutcome" not in result
        and "remoteClass" not in result
        and result.get("transcriptVerification") == "VALID"
        and result.get("signatureVerification") == "VALID"
    )


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
    if body_length > O08_LIMITS["GENESIS_BODY_OCTETS"]:
        raise ProtocolError("GENESIS_BODY_OCTETS_LIMIT")
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
    if len(policy) > O08_LIMITS["GENESIS_POLICY_OCTETS"]:
        raise ProtocolError("GENESIS_POLICY_OCTETS_LIMIT")
    if protocol != 1 or profile != 1 or version != 1 or suite != 1 or len(key) != 32 or not policy:
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


def _geometry_observations() -> dict[str, str]:
    return {f"geometryPredicate{index}": "NOT_EVALUATED" for index in range(1, 8)}


def validate_geometry_predicates(
    exact_length: int,
    shape: str,
    geometry: dict[str, int] | None,
) -> dict[str, str]:
    """Evaluate commitment-profile section 4.1 predicates 1-7 in order.

    Closed-set membership and the smaller selected O-08 envelope are checked
    only after this function succeeds.  This preserves R6's distinction
    between malformed geometry and a well-formed unsupported chunk size.
    """

    observations = _geometry_observations()

    def fail(index: int, code: str = "CHUNK_GEOMETRY_INVALID") -> None:
        observations[f"geometryPredicate{index}"] = "FAIL"
        raise ProtocolError(code, observations=observations)

    if shape == "SINGLE":
        observations["geometryPredicate1"] = "PASS"
        if exact_length > MAX_U32 - 132:
            fail(2, "CONTENT_GEOMETRY_INVALID")
        observations["geometryPredicate2"] = "PASS"
        for index in range(3, 8):
            observations[f"geometryPredicate{index}"] = "NOT_APPLICABLE"
        return observations

    if shape != "TREE" or geometry is None:
        fail(1, "CONTENT_GEOMETRY_INVALID")
    if exact_length == 0:
        fail(1)
    observations["geometryPredicate1"] = "PASS"
    observations["geometryPredicate2"] = "NOT_APPLICABLE"

    chunk_size = geometry["chunkSize"]
    chunk_count = geometry["chunkCount"]
    final_length = geometry["finalChunkLength"]
    if not 1 <= chunk_size <= MAX_U32 - 132:
        fail(3)
    observations["geometryPredicate3"] = "PASS"
    if chunk_size >= exact_length or chunk_count < 2:
        fail(4)
    observations["geometryPredicate4"] = "PASS"
    expected_count = 1 + ((exact_length - 1) // chunk_size)
    if chunk_count != expected_count:
        fail(5)
    observations["geometryPredicate5"] = "PASS"
    if chunk_count - 1 > MAX_U64 // chunk_size:
        fail(6)
    consumed = chunk_size * (chunk_count - 1)
    if consumed >= exact_length or final_length != exact_length - consumed:
        fail(6)
    observations["geometryPredicate6"] = "PASS"
    if not 0 < final_length <= chunk_size:
        fail(7)
    observations["geometryPredicate7"] = "PASS"
    return observations


def parse_event(transcript: bytes) -> dict[str, Any]:
    """Parse and canonically re-encode a corpus event."""

    outer = ByteReader(transcript)
    if outer.take(16, "domain") != DOMAINS["application"]:
        raise ProtocolError("WRONG_DOMAIN")
    body_length = outer.integer(4, "body_length")
    if body_length > MAX_U32 - 20:
        raise ProtocolError("FRAMING_OBJECT_LIMIT")
    if body_length > O08_LIMITS["FRAMING_OBJECT_OCTETS"]:
        raise ProtocolError("FRAMING_OBJECT_OCTETS_LIMIT")
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
    if len(transition) > O08_LIMITS["AP_TRANSITION_BLOCK_OCTETS"]:
        raise ProtocolError("AP_TRANSITION_BLOCK_OCTETS_LIMIT")
    credential = body.take(32, "credential")
    sequence = body.integer(8, "sequence")
    if sequence > O08_LIMITS["SEQUENCE_VALUE"]:
        raise ProtocolError("SEQUENCE_VALUE_LIMIT")
    presence = body.integer(1, "predecessor_presence")
    if presence not in (0, 1):
        raise ProtocolError("PREDECESSOR_PRESENCE_INVALID")
    predecessor = body.take(32, "predecessor") if presence else None
    parent_count = body.integer(4, "parent_count")
    if parent_count > O08_LIMITS["PARENTS_PER_EVENT"]:
        raise ProtocolError("PARENTS_PER_EVENT_LIMIT", "S4_GRAPH_ADMISSION")
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
        predicate_results = validate_geometry_predicates(exact_length, shape, geometry)
        if geometry is not None and geometry["chunkSize"] not in O08_CHUNK_OCTETS:
            raise ProtocolError("CHUNK_OCTETS_LIMIT", observations=predicate_results)
        if geometry is not None and geometry["chunkCount"] > O08_LIMITS["CHUNKS_PER_CONTENT"]:
            raise ProtocolError("CHUNKS_PER_CONTENT_LIMIT", observations=predicate_results)
        if exact_length > O08_LIMITS["CONTENT_EXACT_OCTETS"]:
            raise ProtocolError("CONTENT_EXACT_OCTETS_LIMIT", observations=predicate_results)
        content.update(
            {
                "commitmentHex": commitment.hex(),
                "contentType": content_type,
                "geometryPredicateResults": predicate_results,
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
    if protocol != 1 or profile != 1 or profile_version != 1 or object_kind != 1 or min(event_type, schema, schema_version) <= 0:
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
        "apAuthorityResult": "AP_FOLD_NOT_EXECUTED",
        "commitmentMatchVerification": "NOT_EVALUATED",
        "commitmentVerification": "NOT_PRESENT",
        "externalEffects": [],
        **_geometry_observations(),
        "kBindingAdmission": "ADMITTED",
        "outcomeEvaluated": False,
        "postStateDigest": None,
        "preStateDigest": state_digest,
        "signatureVerification": "NOT_EVALUATED",
        "stage": "FINAL_AFTER_S6",
        "suppliedLengthVerification": "NOT_EVALUATED",
        "transcriptVerification": "VALID",
    }

    def reject(
        outcome: str | list[tuple[str, str]],
        stage: str | None = None,
        *,
        admitted: bool = False,
        transcript_status: str = "VALID",
    ) -> dict[str, Any]:
        if isinstance(outcome, list):
            if stage is not None:
                raise ProtocolError("O-10 candidate set cannot override stage")
            candidates = outcome
        else:
            selected_stage = stage or str(
                next(
                    row["stage"]
                    for row in load_local_json(O10_TAXONOMY_PATH)["primaries"]
                    if row["id"] == outcome
                )
            ).split("|")[0]
            candidates = [(outcome, selected_stage)]
        result.update(select_o10_result(candidates))
        result.update(
            {
                "apAuthorityResult": (
                    "REJECTED_OR_DEFERRED" if admitted else "NOT_REACHED"
                ),
                "kBindingAdmission": "ADMITTED" if admitted else "REJECTED",
                "outcomeEvaluated": True,
                "postStateDigest": state_digest,
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
    except ProtocolError as error:
        result.update(error.observations)
        if error.code == "PARENTS_PER_EVENT_LIMIT":
            return reject(
                "CONTEXT_CAPACITY_EXHAUSTED",
                error.stage,
                transcript_status="REJECTED",
            )
        if error.code.endswith("_LIMIT"):
            return reject(
                "CURRENT_OBJECT_OUT_OF_PROFILE",
                error.stage,
                transcript_status="REJECTED",
            )
        return reject("STRUCTURAL_REJECTION", error.stage, transcript_status="REJECTED")
    except (ValueError, KeyError):
        return reject("STRUCTURAL_REJECTION", "S3_KERNEL_STRUCTURAL", transcript_status="REJECTED")
    if reference != expected_reference:
        return reject("REFERENCE_COLLISION_UNSUPPORTED", "S3_KERNEL_STRUCTURAL")

    admission = record.get("admissionContext", {})
    if admission and not isinstance(admission, dict):
        return reject("STRUCTURAL_REJECTION", "S3_KERNEL_STRUCTURAL")
    checkpoint_refs = admission.get("checkpointEvidenceReferences", [])
    if checkpoint_refs:
        return reject("CURRENT_OBJECT_OUT_OF_PROFILE", "S3_KERNEL_STRUCTURAL")

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
        if content["class"] == "NONE":
            result.update(
                {f"geometryPredicate{index}": "NOT_APPLICABLE" for index in range(1, 8)}
            )
            result["suppliedLengthVerification"] = "NOT_APPLICABLE"
            result["commitmentMatchVerification"] = "NOT_APPLICABLE"
        if content["class"] != "NONE":
            result.update(content["geometryPredicateResults"])
            opening = record.get("opening")
            if opening is None:
                result["commitmentVerification"] = "PENDING"
                result["suppliedLengthVerification"] = "NOT_EVALUATED"
                result["commitmentMatchVerification"] = "NOT_EVALUATED"
                if content["class"] == "REQUIRED":
                    return reject("PENDING_OPENING", "EVENT_LOCAL", admitted=True)
                return reject("OPENING_MISSING", "S3_KERNEL_STRUCTURAL")
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
            failures: list[tuple[str, str]] = []
            if len(supplied) != content["exactLength"]:
                result["commitmentVerification"] = "REJECTED"
                result["suppliedLengthVerification"] = "REJECTED"
                failures.append(("LENGTH_MISMATCH", "S3_KERNEL_STRUCTURAL"))
            else:
                result["suppliedLengthVerification"] = "VALID"
            if commitment["commitmentHex"] != content["commitmentHex"]:
                result["commitmentVerification"] = "REJECTED"
                result["commitmentMatchVerification"] = "REJECTED"
                failures.append(("COMMITMENT_MISMATCH", "S3_KERNEL_STRUCTURAL"))
            else:
                result["commitmentMatchVerification"] = "VALID"
            if failures:
                return reject(failures)
            result["commitmentVerification"] = "VALID"
            result["commitmentMatchVerification"] = "VALID"
    else:
        result.update(
            {f"geometryPredicate{index}": "NOT_APPLICABLE" for index in range(1, 8)}
        )
        result["suppliedLengthVerification"] = "NOT_APPLICABLE"
        result["commitmentMatchVerification"] = "NOT_APPLICABLE"

    if admission:
        if reference in admission.get("seenEventReferences", []):
            return reject("DUPLICATE", "S3_KERNEL_STRUCTURAL", admitted=True)
        sibling_refs = admission.get("sameAuthorSequenceReferences", [])
        if any(candidate != reference for candidate in sibling_refs):
            return reject("FORK_EVIDENCE", "EVENT_LOCAL", admitted=True)
        if record["kind"] == "APPLICATION_EVENT":
            parents = set(fields["causalParents"])
            if fields["directPredecessorHex"] is not None:
                parents.add(fields["directPredecessorHex"])
            available = set(admission.get("availableDependencyReferences", parents))
            if not parents <= available:
                missing = parents - available
                pending_roots = set(admission.get("knownPendingOpeningRoots", []))
                pending_descendants = set(
                    admission.get("pendingOpeningDescendantReferences", [])
                )
                outcome = (
                    "PENDING_ANCESTOR"
                    if missing <= pending_roots | pending_descendants
                    else "DEPENDENCY_DEFERRED"
                )
                stage = "EVENT_LOCAL" if outcome == "PENDING_ANCESTOR" else "S4_GRAPH_ADMISSION"
                return reject(outcome, stage, admitted=True)

            if admission.get("credentialIdentifierCollision") is True:
                return reject(
                    "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED",
                    "S3_KERNEL_STRUCTURAL",
                )
            if (
                fields["eventRole"] != "CREDENTIAL"
                or fields.get("tail", {}).get("kind") != "GRANT"
            ) and admission.get("credentialBindingMatchCount") not in (None, 1):
                return reject(
                    "UNRESOLVED_CREDENTIAL_BINDING",
                    "S3_KERNEL_STRUCTURAL",
                )
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


def o10_result(primary: str, stage: str | None = None) -> dict[str, str]:
    """Select a K result only from the ratified O-10 registry."""

    taxonomy = load_local_json(O10_TAXONOMY_PATH)
    rows = {
        row.get("id"): row
        for row in taxonomy.get("primaries", [])
        if isinstance(row, dict)
    }
    row = rows.get(primary)
    if row is None or row.get("owner") != "K":
        raise CorpusModelError(f"non-K or unknown O-10 primary: {primary}")
    allowed_stages = str(row.get("stage", "")).split("|")
    selected_stage = stage or allowed_stages[0]
    if selected_stage not in allowed_stages:
        raise CorpusModelError(
            f"O-10 stage mismatch: {primary}:{selected_stage}"
        )
    remote = taxonomy.get("remote_collapse")
    if not isinstance(remote, str) or not remote:
        raise CorpusModelError(f"missing O-10 remote collapse: {primary}")
    return {
        "localOutcome": primary,
        "remoteClass": remote,
        "stage": selected_stage,
    }


def select_o10_result(candidates: list[tuple[str, str]]) -> dict[str, str]:
    """Select one applicable K primary using only the ratified O-10 registry.

    A multi-candidate call is accepted only when the registry publishes one
    closed precedence list containing every candidate.  This deliberately
    fails closed instead of inventing fallback precedence in the evaluator.
    """

    if not candidates:
        raise CorpusModelError("empty O-10 candidate set")
    normalized = sorted(set(candidates))
    results = [o10_result(primary, stage) for primary, stage in normalized]
    if len(results) == 1:
        return results[0]
    taxonomy = load_local_json(O10_TAXONOMY_PATH)
    identifiers = {result["localOutcome"] for result in results}
    for key in ("k_precedence", "event_precedence"):
        precedence = taxonomy.get(key)
        if (
            isinstance(precedence, list)
            and all(isinstance(value, str) for value in precedence)
            and identifiers <= set(precedence)
        ):
            selected = min(results, key=lambda result: precedence.index(result["localOutcome"]))
            return selected
    raise CorpusModelError(
        "O-10 candidates lack one closed precedence relation: "
        + ",".join(sorted(identifiers))
    )


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

    invariant_witnesses = inventory.get("invariant_witness_vectors")
    executable_invariants = set(expected_ids["invariants"]) - NONEXECUTABLE_INVARIANTS
    if (
        not isinstance(invariant_witnesses, dict)
        or set(invariant_witnesses) != executable_invariants
        or not all(isinstance(value, str) and value for value in invariant_witnesses.values())
        or len(set(invariant_witnesses.values())) != len(invariant_witnesses)
    ):
        raise CorpusModelError("invariant witness-vector relation mismatch")

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
    source_rows = o10_sources.get("rows", [])
    if len(source_rows) != inventory["o10_source_row_count"]:
        raise CorpusModelError("O-10 source-row cardinality mismatch")
    source_by_id = {row.get("row_id"): row for row in source_rows}
    if len(source_by_id) != len(source_rows) or None in source_by_id:
        raise CorpusModelError("O-10 source-row identifier mismatch")
    witness_map = inventory.get("o10_produced_source_row_witnesses")
    if not isinstance(witness_map, dict) or not witness_map:
        raise CorpusModelError("O-10 produced-row witness map missing")
    if not set(witness_map) <= set(source_by_id):
        raise CorpusModelError("O-10 produced-row witness references unknown row")
    for row_id, witnesses in witness_map.items():
        source = source_by_id[row_id]
        mapping = source.get("mapping")
        if not isinstance(mapping, dict):
            raise CorpusModelError(f"produced forbidden O-10 row: {row_id}")
        primary = next(
            (item for item in taxonomy["primaries"] if item["id"] == mapping["primary"]),
            None,
        )
        if primary is None or primary.get("owner") != "K":
            raise CorpusModelError(f"produced non-K O-10 row: {row_id}")
        if not isinstance(witnesses, list) or not witnesses:
            raise CorpusModelError(f"empty O-10 row witness set: {row_id}")
        seen_inputs: set[str] = set()
        for witness in witnesses:
            if not isinstance(witness, dict) or set(witness) != {
                "inputId",
                "jointSourceRowIds",
            }:
                raise CorpusModelError(f"malformed O-10 row witness: {row_id}")
            input_id = witness["inputId"]
            joint = witness["jointSourceRowIds"]
            if (
                not isinstance(input_id, str)
                or not input_id
                or input_id in seen_inputs
                or not isinstance(joint, list)
                or not joint
                or row_id not in joint
                or joint != sorted(set(joint))
                or not set(joint) <= set(source_by_id)
            ):
                raise CorpusModelError(f"invalid O-10 row witness relation: {row_id}")
            seen_inputs.add(input_id)
            mapped = [source_by_id[identifier].get("mapping") for identifier in joint]
            if any(
                not isinstance(item, dict)
                or item.get("primary") != mapping.get("primary")
                or item.get("stage") != mapping.get("stage")
                for item in mapped
            ):
                raise CorpusModelError(f"incompatible joint O-10 witness: {row_id}")
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
