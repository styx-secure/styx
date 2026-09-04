"""Closed Base-relative source and inventory model for C0.3 corpus generation."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from typing import Any, Mapping

from canonical_json import dumps


BASE_SHA = "a4fa1286b57b2ee79b3c580fdce0d1fb3bf9cd40"
BASE_REVIEW_MODEL_DIGEST_RECONCILIATIONS = {
    "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md": (
        "fc8cbef3f492fc0004f13c98128b9569f913348ec1e1fd42608cf316fd83e03e",
        "1f40fde4b8912766eb586d56f4e72f8c040448e74bc3e6503ed25787abbb7e8f",
    ),
    "docs/security/STYX-THREAT-MODEL.md": (
        "e4a003e55022ff2c0c31a5ac0dafb93482fb76585f379c8af18842f8407c03f8",
        "53ff40c30155b3c7607493c0fb100430904ccf9bfe0c68c95557b94d5dd2674d",
    ),
}
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
        admitted: bool = False,
        observations: dict[str, str] | None = None,
    ) -> None:
        super().__init__(code)
        self.admitted = admitted
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
    "VERIFICATION_KEY_OCTETS": 32,
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
        "UNRESOLVABLE_CREDENTIAL",
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


def semantic_k_graph_input_digest(
    genesis_record: dict[str, Any],
    records: list[dict[str, Any]],
    target_record_id: str,
) -> str:
    """Hash one connected K witness without scenario or expected-result data."""

    def project(record: dict[str, Any]) -> dict[str, Any]:
        return {
            key: value
            for key, value in record.items()
            if key not in NONSEMANTIC_VECTOR_FIELDS
        }

    return sha256(
        dumps(
            {
                "acceptedGenesis": project(genesis_record),
                "records": sorted(
                    (project(record) for record in records),
                    key=lambda record: record["eventReferenceHex"],
                ),
                "targetRecordId": target_record_id,
            }
        )
    ).hexdigest()


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


def _genesis_profile_failure(
    transcript: bytes,
    fields: Mapping[str, Any],
) -> ProtocolError | None:
    """Return the first selected-envelope failure after a valid inverse."""

    body_length = int.from_bytes(transcript[16:20], "big")
    if body_length > O08_LIMITS["GENESIS_BODY_OCTETS"]:
        return ProtocolError("GENESIS_BODY_OCTETS_LIMIT")
    policy_octets = len(bytes.fromhex(str(fields["initialAuthorityPolicyHex"])))
    if policy_octets > O08_LIMITS["GENESIS_POLICY_OCTETS"]:
        return ProtocolError("GENESIS_POLICY_OCTETS_LIMIT")
    return None


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
    # Parsing proves canonical framing. A non-zero AP tuple that differs from
    # the receiver-selected tuple is still parseable; the selected-profile
    # admission check below owns CURRENT_OBJECT_OUT_OF_PROFILE. Treating that
    # mismatch as malformed input would collapse transcript conformance into
    # local profile selection.
    if protocol != 1 or profile <= 0 or profile_version <= 0 or object_kind != 1 or min(event_type, schema, schema_version) <= 0:
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
            grantee_key = body.opaque("grantee_key")
            # Suite 0x0001 has a fixed-width Ed25519 verification key.  A
            # short key is not a locally unsupported profile choice: it is an
            # invalid transcript grammar instance and must fail before the
            # candidate reference is computed.  Overlong keys remain
            # canonically parseable so the selected O-08 envelope owns their
            # fail-closed S3 classification after reference verification.
            if len(grantee_key) < O08_LIMITS["VERIFICATION_KEY_OCTETS"]:
                raise ProtocolError("GRANTEE_KEY_LENGTH_INVALID")
            tail["granteeVerificationKeyHex"] = grantee_key.hex()
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


def _event_profile_failures(
    transcript: bytes,
    fields: Mapping[str, Any],
) -> tuple[ProtocolError | None, ProtocolError | None]:
    """Return first S3 and S4 envelope failures for a valid transcript.

    Parsing establishes canonical written-inverse conformance.  These checks
    deliberately execute afterwards so an O-08 admission failure cannot be
    misreported as malformed transcript bytes.  The selected enforcement stage
    still controls when protected work may begin.
    """

    if (
        int(fields["applicationProfileId"]) != 1
        or int(fields["applicationProfileVersion"]) != 1
    ):
        return ProtocolError("APPLICATION_PROFILE_MISMATCH"), None
    body_length = int.from_bytes(transcript[16:20], "big")
    if body_length > O08_LIMITS["FRAMING_OBJECT_OCTETS"]:
        return ProtocolError("FRAMING_OBJECT_OCTETS_LIMIT"), None
    if len(bytes.fromhex(str(fields["transitionBlockHex"]))) > O08_LIMITS[
        "AP_TRANSITION_BLOCK_OCTETS"
    ]:
        return ProtocolError("AP_TRANSITION_BLOCK_OCTETS_LIMIT"), None
    tail = fields.get("tail", {})
    if (
        fields.get("eventRole") == "CREDENTIAL"
        and tail.get("kind") == "GRANT"
        and len(bytes.fromhex(str(tail["granteeVerificationKeyHex"])))
        > O08_LIMITS["VERIFICATION_KEY_OCTETS"]
    ):
        return ProtocolError("VERIFICATION_KEY_OCTETS_LIMIT"), None
    if int(fields["authorSequence"]) > O08_LIMITS["SEQUENCE_VALUE"]:
        return ProtocolError("SEQUENCE_VALUE_LIMIT"), None
    content = fields["content"]
    geometry = content.get("geometry")
    observations = content.get("geometryPredicateResults", {})
    if geometry is not None and geometry["chunkSize"] not in O08_CHUNK_OCTETS:
        return ProtocolError(
            "CHUNK_OCTETS_LIMIT", observations=observations
        ), None
    if geometry is not None and geometry["chunkCount"] > O08_LIMITS[
        "CHUNKS_PER_CONTENT"
    ]:
        return ProtocolError(
            "CHUNKS_PER_CONTENT_LIMIT", observations=observations
        ), None
    if int(content["exactLength"]) > O08_LIMITS["CONTENT_EXACT_OCTETS"]:
        return ProtocolError(
            "CONTENT_EXACT_OCTETS_LIMIT", observations=observations
        ), None
    if len(fields["causalParents"]) > O08_LIMITS["PARENTS_PER_EVENT"]:
        return None, ProtocolError(
            "PARENTS_PER_EVENT_LIMIT", "S4_GRAPH_ADMISSION"
        )
    return None, None


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
_ED25519_EVIDENCE_COUNTS = {"boundaryInvocations": 0, "equationInvocations": 0}


def _ed_extended(point: tuple[int, int]) -> tuple[int, int, int, int]:
    x, y = point
    return x, y, 1, x * y % _P


def _ed_extended_add(
    left: tuple[int, int, int, int],
    right: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * _D * t1 * t2 % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = (b - a) % _P, (d - c) % _P, (d + c) % _P, (b + a) % _P
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _ed_extended_double(
    point: tuple[int, int, int, int],
) -> tuple[int, int, int, int]:
    x, y, z, _ = point
    a, b, c = x * x % _P, y * y % _P, 2 * z * z % _P
    d = -a % _P
    e = ((x + y) ** 2 - a - b) % _P
    g, f, h = (d + b) % _P, (d + b - c) % _P, (d - b) % _P
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _ed_affine(point: tuple[int, int, int, int]) -> tuple[int, int]:
    x, y, z, _ = point
    inverse = pow(z, _P - 2, _P)
    return x * inverse % _P, y * inverse % _P


def _ed_add(left: tuple[int, int], right: tuple[int, int]) -> tuple[int, int]:
    return _ed_affine(_ed_extended_add(_ed_extended(left), _ed_extended(right)))


def _ed_mul(scalar: int, point: tuple[int, int] = _B) -> tuple[int, int]:
    result = (0, 1, 1, 0)
    addend = _ed_extended(point)
    while scalar:
        if scalar & 1:
            result = _ed_extended_add(result, addend)
        addend = _ed_extended_double(addend)
        scalar >>= 1
    return _ed_affine(result)


def _ed_encode(point: tuple[int, int]) -> bytes:
    x, y = point
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _ed_decode(
    encoded: bytes, *, enforce_canonical: bool = True
) -> tuple[int, int]:
    if len(encoded) != 32:
        raise ProtocolError("SIGNATURE_POINT_LENGTH")
    raw = int.from_bytes(encoded, "little")
    sign = raw >> 255
    y = raw & ((1 << 255) - 1)
    if enforce_canonical and y >= _P:
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


def ed25519_verify_detailed(
    public: bytes, signature: bytes, message: bytes
) -> dict[str, Any]:
    """Apply the selected C0.3 Ed25519 guard and equation exactly once.

    The guard code and invocation count are evidence-only observations.  They
    are deliberately kept out of the protocol result vocabulary.
    """

    from hashlib import sha512

    if len(public) != 32:
        return {
            "accepted": False,
            "equationInvocations": 0,
            "guardCode": "PUBLIC_KEY_LENGTH",
        }
    if len(signature) != 64:
        return {
            "accepted": False,
            "equationInvocations": 0,
            "guardCode": "SIGNATURE_LENGTH",
        }
    try:
        point_a = _ed_decode(public)
    except ProtocolError as error:
        return {
            "accepted": False,
            "equationInvocations": 0,
            "guardCode": (
                "NON_CANONICAL_POINT"
                if error.code == "SIGNATURE_POINT_NONCANONICAL"
                else "OFF_CURVE_POINT"
            ),
        }
    try:
        point_r = _ed_decode(signature[:32])
    except ProtocolError as error:
        return {
            "accepted": False,
            "equationInvocations": 0,
            "guardCode": (
                "NON_CANONICAL_POINT"
                if error.code == "SIGNATURE_POINT_NONCANONICAL"
                else "OFF_CURVE_POINT"
            ),
        }
    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= _L:
        return {
            "accepted": False,
            "equationInvocations": 0,
            "guardCode": "NON_CANONICAL_SCALAR",
        }
    identity = (0, 1)
    if point_a == identity or _ed_mul(_L, point_a) != identity:
        return {
            "accepted": False,
            "equationInvocations": 0,
            "guardCode": "PUBLIC_KEY_NOT_PRIME_ORDER",
        }
    if point_r == identity or _ed_mul(_L, point_r) != identity:
        return {
            "accepted": False,
            "equationInvocations": 0,
            "guardCode": "R_NOT_PRIME_ORDER",
        }
    challenge = int.from_bytes(sha512(signature[:32] + public + message).digest(), "little") % _L
    equation_invocations = 0

    def selected_equation() -> bool:
        nonlocal equation_invocations
        equation_invocations += 1
        return _ed_mul(scalar) == _ed_add(
            point_r, _ed_mul(challenge, point_a)
        )

    accepted = selected_equation()
    return {
        "accepted": accepted,
        "equationInvocations": equation_invocations,
        "guardCode": "GUARD_ACCEPTED",
    }


def ed25519_verify(public: bytes, signature: bytes, message: bytes) -> bool:
    observed = ed25519_verify_detailed(public, signature, message)
    _ED25519_EVIDENCE_COUNTS["boundaryInvocations"] += 1
    _ED25519_EVIDENCE_COUNTS["equationInvocations"] += int(
        observed["equationInvocations"]
    )
    return bool(observed["accepted"])


def reset_ed25519_evidence_counts() -> None:
    _ED25519_EVIDENCE_COUNTS.update(
        {"boundaryInvocations": 0, "equationInvocations": 0}
    )


def ed25519_evidence_counts() -> dict[str, int]:
    return dict(_ED25519_EVIDENCE_COUNTS)


def evaluate_vector(record: dict[str, Any]) -> dict[str, Any]:
    """Independently evaluate ordinary corpus inputs without expected-result fields."""

    transcript = bytes.fromhex(record["transcriptHex"])
    state_digest = sha256(b"styx-c03/evaluation/initial").hexdigest()
    result: dict[str, Any] = {
        "apAuthorityResult": "AP_FOLD_NOT_EXECUTED",
        "commitmentMatchVerification": "NOT_EVALUATED",
        "commitmentVerification": "NOT_EVALUATED",
        "externalEffects": [],
        **_geometry_observations(),
        "kBindingAdmission": "ADMITTED",
        "outcomeEvaluated": False,
        "postStateDigest": None,
        "preStateDigest": state_digest,
        "referenceVerification": "NOT_REACHED",
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
                "apAuthorityResult": "NOT_REACHED",
                "kBindingAdmission": "ADMITTED" if admitted else "REJECTED",
                "outcomeEvaluated": True,
                "postStateDigest": state_digest,
                "transcriptVerification": transcript_status,
            }
        )
        return result

    s3_profile_failure: ProtocolError | None = None
    s4_profile_failure: ProtocolError | None = None
    try:
        if record["kind"] == "GENESIS":
            fields = parse_genesis(transcript)
            reference = framed_hash(DOMAINS["genesis_reference"], transcript).hex()
            expected_reference = record["genesisReferenceHex"]
            s3_profile_failure = _genesis_profile_failure(transcript, fields)
        elif record["kind"] == "APPLICATION_EVENT":
            fields = parse_event(transcript)
            reference = framed_hash(DOMAINS["event_reference"], transcript).hex()
            expected_reference = record["eventReferenceHex"]
            s3_profile_failure, s4_profile_failure = _event_profile_failures(
                transcript, fields
            )
        else:
            raise ProtocolError("OBJECT_KIND_UNKNOWN")
    except ProtocolError as error:
        result.update(error.observations)
        return reject("STRUCTURAL_REJECTION", error.stage, transcript_status="REJECTED")
    except (ValueError, KeyError):
        return reject("STRUCTURAL_REJECTION", "S3_KERNEL_STRUCTURAL", transcript_status="REJECTED")
    if record["kind"] == "APPLICATION_EVENT":
        content = fields["content"]
        if content["class"] == "NONE":
            result.update(
                {f"geometryPredicate{index}": "NOT_APPLICABLE" for index in range(1, 8)}
            )
            result["commitmentVerification"] = "NOT_PRESENT"
            result["suppliedLengthVerification"] = "NOT_APPLICABLE"
            result["commitmentMatchVerification"] = "NOT_APPLICABLE"
        else:
            result.update(content["geometryPredicateResults"])
    else:
        result.update(
            {f"geometryPredicate{index}": "NOT_APPLICABLE" for index in range(1, 8)}
        )
        result["commitmentVerification"] = "NOT_PRESENT"
        result["suppliedLengthVerification"] = "NOT_APPLICABLE"
        result["commitmentMatchVerification"] = "NOT_APPLICABLE"

    admission = record.get("admissionContext", {})
    if admission and not isinstance(admission, dict):
        return reject("STRUCTURAL_REJECTION", "S3_KERNEL_STRUCTURAL")
    if reference != expected_reference:
        result["referenceVerification"] = "REJECTED"
        collision_history = set(admission.get("seenEventReferences", []))
        return reject(
            "REFERENCE_COLLISION_UNSUPPORTED"
            if expected_reference in collision_history
            else "INVALID",
            "S3_KERNEL_STRUCTURAL",
        )
    result["referenceVerification"] = "VALID"

    checkpoint_refs = admission.get("checkpointEvidenceReferences", [])
    if checkpoint_refs:
        return reject("CURRENT_OBJECT_OUT_OF_PROFILE", "S3_KERNEL_STRUCTURAL")
    if s3_profile_failure is not None:
        result.update(s3_profile_failure.observations)
        return reject("CURRENT_OBJECT_OUT_OF_PROFILE", s3_profile_failure.stage)

    supplied_key_hex = record["binding"]["verificationKeyHex"]
    if (
        record["kind"] == "GENESIS"
        and supplied_key_hex != fields["rootVerificationKeyHex"]
    ):
        return reject("CREDENTIAL_BINDING_MISMATCH", "S3_KERNEL_STRUCTURAL")
    public_key = bytes.fromhex(
        fields["rootVerificationKeyHex"]
        if record["kind"] == "GENESIS"
        else supplied_key_hex
    )
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
        if content["class"] != "NONE":
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
    if admission:
        if reference in admission.get("admittedEventReferences", []):
            return reject("DUPLICATE", "S3_KERNEL_STRUCTURAL", admitted=True)
        if s4_profile_failure is not None:
            return reject(
                "CONTEXT_CAPACITY_EXHAUSTED",
                s4_profile_failure.stage,
            )
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
    if s4_profile_failure is not None:
        return reject(
            "CONTEXT_CAPACITY_EXHAUSTED",
            s4_profile_failure.stage,
        )
    result["postStateDigest"] = sha256(
        bytes.fromhex(state_digest) + bytes.fromhex(reference)
    ).hexdigest()
    return result


def evaluate_k_admission_scenario(
    genesis_record: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    known_fork_references: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    """Evaluate one connected descendant-admission history.

    ``genesis_record`` identifies a genesis projection that the harness declares
    preaccepted.  This function verifies its transcript, reference and
    signature, but deliberately does not model or claim the O-07 ceremony
    transition which created the replica-owned state.
    """

    if genesis_record.get("kind") != "GENESIS":
        raise ProtocolError("PREACCEPTED_GENESIS_KIND_INVALID")
    genesis_transcript = bytes.fromhex(genesis_record["transcriptHex"])
    genesis_fields = parse_genesis(genesis_transcript)
    genesis_reference = framed_hash(
        DOMAINS["genesis_reference"], genesis_transcript
    ).hex()
    if genesis_reference != genesis_record.get("genesisReferenceHex"):
        raise ProtocolError("PREACCEPTED_GENESIS_REFERENCE_INVALID")
    genesis_key = bytes.fromhex(genesis_fields["rootVerificationKeyHex"])
    if not ed25519_verify(
        genesis_key,
        bytes.fromhex(genesis_record["signatureHex"]),
        genesis_transcript,
    ):
        raise ProtocolError("PREACCEPTED_GENESIS_SIGNATURE_INVALID")

    context = genesis_fields["contextIdentifierHex"]
    admitted: dict[str, dict[str, Any]] = {}
    bindings: dict[str, dict[str, Any]] = {
        genesis_reference: {
            "grantReferenceHex": None,
            "issuerCredentialHex": None,
            "verificationKeyHex": genesis_fields["rootVerificationKeyHex"],
        }
    }
    observations: list[dict[str, Any]] = []

    def ancestors(reference: str) -> frozenset[str]:
        values: set[str] = set()
        frontier = [reference]
        while frontier:
            current = frontier.pop()
            if current in values:
                continue
            values.add(current)
            event = admitted.get(current)
            if event is None:
                continue
            fields = event["fields"]
            predecessor = fields["directPredecessorHex"]
            if predecessor is not None:
                frontier.append(predecessor)
            frontier.extend(fields["causalParents"])
        values.discard(reference)
        return frozenset(values)

    for record in records:
        if record.get("kind") != "APPLICATION_EVENT":
            raise ProtocolError("SCENARIO_EVENT_KIND_INVALID")
        transcript = bytes.fromhex(record["transcriptHex"])
        fields = parse_event(transcript)
        reference = framed_hash(DOMAINS["event_reference"], transcript).hex()
        if reference != record.get("eventReferenceHex"):
            raise ProtocolError("SCENARIO_EVENT_REFERENCE_INVALID")
        if fields["contextIdentifierHex"] != context:
            raise ProtocolError(
                "CREDENTIAL_BINDING_MISMATCH", "S3_KERNEL_STRUCTURAL"
            )
        if fields["genesisReferenceHex"] != genesis_reference:
            raise ProtocolError(
                "CREDENTIAL_BINDING_MISMATCH", "S3_KERNEL_STRUCTURAL"
            )

        actor = fields["credentialIdentifierHex"]
        binding = bindings.get(actor)
        if binding is None:
            raise ProtocolError("UNRESOLVED_CREDENTIAL_BINDING")

        # Re-run the complete transcript/commitment checks with a binding
        # derived from accepted genesis/GRANT state.  Candidate-carried
        # ``binding`` and ``admissionContext`` metadata are deliberately not a
        # trust input for connected K admission.
        local_record = dict(record)
        local_record.pop("admissionContext", None)
        local_record["binding"] = {
            "contextIdentifierHex": context,
            "credentialIdentifierHex": actor,
            "verificationKeyHex": binding["verificationKeyHex"],
        }
        local_observation = evaluate_vector(local_record)
        if not transition_input_is_compatible(local_observation):
            raise ProtocolError(
                local_observation.get("localOutcome", "INVALID"),
                local_observation.get("stage", "S3_KERNEL_STRUCTURAL"),
                admitted=local_observation.get("kBindingAdmission") == "ADMITTED",
            )
        predecessor = fields["directPredecessorHex"]
        parents = tuple(fields["causalParents"])
        same_slot_references = {
            admitted_reference
            for admitted_reference, admitted_record in admitted.items()
            if admitted_record["fields"]["credentialIdentifierHex"] == actor
            and admitted_record["fields"]["authorSequence"]
            == fields["authorSequence"]
        }
        if same_slot_references and not (
            reference in known_fork_references
            and same_slot_references <= known_fork_references
        ):
            raise ProtocolError("FORK_EVIDENCE", "EVENT_LOCAL", admitted=True)
        dependencies = ({predecessor} if predecessor is not None else set()) | set(parents)
        if not dependencies <= set(admitted):
            raise ProtocolError("DEPENDENCY_DEFERRED", "S4_GRAPH_ADMISSION")
        if fields["authorSequence"] == 0:
            if predecessor is not None:
                raise ProtocolError("STRUCTURAL_REJECTION")
        else:
            previous = admitted.get(predecessor or "")
            if (
                previous is None
                or previous["fields"]["credentialIdentifierHex"] != actor
                or previous["fields"]["authorSequence"] + 1
                != fields["authorSequence"]
            ):
                raise ProtocolError("STRUCTURAL_REJECTION")
        predecessor_ancestors = ancestors(predecessor) if predecessor is not None else frozenset()
        if any(parent in predecessor_ancestors for parent in parents):
            raise ProtocolError("STRUCTURAL_REJECTION")
        for index, left in enumerate(parents):
            left_ancestors = ancestors(left)
            for right in parents[index + 1 :]:
                if right in left_ancestors or left in ancestors(right):
                    raise ProtocolError("STRUCTURAL_REJECTION")
        if actor != genesis_reference and binding["grantReferenceHex"] not in ancestors(reference):
            # ``reference`` is not admitted yet, so use the candidate dependency
            # closure directly.
            candidate_ancestors = set(dependencies)
            for dependency in dependencies:
                candidate_ancestors.update(ancestors(dependency))
            if binding["grantReferenceHex"] not in candidate_ancestors:
                raise ProtocolError("UNRESOLVED_CREDENTIAL_BINDING")

        if fields["eventRole"] == "CREDENTIAL":
            tail = fields["tail"]
            kind = tail["kind"]
            candidate_ancestors = set(dependencies)
            for dependency in dependencies:
                candidate_ancestors.update(ancestors(dependency))
            if kind == "GRANT":
                if reference == genesis_reference or reference in bindings:
                    raise ProtocolError("CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED")
            elif kind == "REVOKE":
                target = tail["targetCredentialHex"]
                if target not in bindings:
                    raise ProtocolError("UNRESOLVABLE_CREDENTIAL")
                # O-02 permits a control to name the accepted genesis root
                # directly.  Every non-genesis credential, however, exists
                # only through its admitted GRANT and that binding must be in
                # the candidate's authenticated causal ancestry.
                if target != genesis_reference and target not in candidate_ancestors:
                    raise ProtocolError("STRUCTURAL_REJECTION")
            elif kind == "ROTATE":
                retiring = tail["retiringCredentialHex"]
                replacement = tail["replacementGrantHex"]
                if retiring == actor:
                    raise ProtocolError("STRUCTURAL_REJECTION")
                if retiring not in bindings:
                    raise ProtocolError("UNRESOLVABLE_CREDENTIAL")
                if (
                    retiring != genesis_reference
                    and retiring not in candidate_ancestors
                ):
                    raise ProtocolError("STRUCTURAL_REJECTION")
                replacement_event = admitted.get(replacement)
                if (
                    replacement_event is None
                    or replacement_event["fields"].get("tail", {}).get("kind")
                    != "GRANT"
                    or (replacement != predecessor and replacement not in parents)
                ):
                    raise ProtocolError("STRUCTURAL_REJECTION")
            elif kind == "RECOVER":
                recovery = tail["recoveryGrantHex"]
                recovery_event = admitted.get(recovery)
                if (
                    recovery_event is None
                    or recovery_event["fields"].get("tail", {}).get("kind")
                    != "GRANT"
                    or (recovery != predecessor and recovery not in parents)
                ):
                    raise ProtocolError("STRUCTURAL_REJECTION")

        admitted[reference] = {**record, "fields": fields}
        if fields["eventRole"] == "CREDENTIAL" and fields["tail"]["kind"] == "GRANT":
            bindings[reference] = {
                "grantReferenceHex": reference,
                "issuerCredentialHex": actor,
                "verificationKeyHex": fields["tail"]["granteeVerificationKeyHex"],
            }
        observations.append(
            {
                "eventReferenceHex": reference,
                "id": record["id"],
                **{
                    key: value
                    for key, value in local_observation.items()
                    if key not in {"preStateDigest", "postStateDigest"}
                },
                "protocolErrorCode": None,
            }
        )
    return observations


def _classify_reference_identities(
    identities: list[tuple[str, bytes]],
) -> dict[tuple[str, bytes], str]:
    """Classify already-computed logical identities without a digest override."""

    transcripts_by_reference: dict[str, set[bytes]] = {}
    for reference, transcript in identities:
        transcripts_by_reference.setdefault(reference, set()).add(transcript)
    return {
        (reference, transcript): (
            "REFERENCE_COLLISION_UNSUPPORTED"
            if len(transcripts_by_reference[reference]) > 1
            else "UNIQUE"
        )
        for reference, transcript in identities
    }


def evaluate_k_admission_graph(
    genesis_record: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    presentation_evidence: bool = False,
) -> list[dict[str, Any]]:
    """Evaluate K0/K1/K2/K3 over one complete bounded candidate set."""

    if genesis_record.get("kind") != "GENESIS":
        raise ProtocolError("PREACCEPTED_GENESIS_KIND_INVALID")
    try:
        genesis_transcript = bytes.fromhex(genesis_record["transcriptHex"])
        genesis_fields = parse_genesis(genesis_transcript)
    except (KeyError, ValueError, ProtocolError) as error:
        raise ProtocolError("PREACCEPTED_GENESIS_TRANSCRIPT_INVALID") from error
    genesis_reference = framed_hash(
        DOMAINS["genesis_reference"], genesis_transcript
    ).hex()
    if genesis_reference != genesis_record.get("genesisReferenceHex"):
        raise ProtocolError("PREACCEPTED_GENESIS_REFERENCE_INVALID")
    if not ed25519_verify(
        bytes.fromhex(genesis_fields["rootVerificationKeyHex"]),
        bytes.fromhex(genesis_record["signatureHex"]),
        genesis_transcript,
    ):
        raise ProtocolError("PREACCEPTED_GENESIS_SIGNATURE_INVALID")

    context = genesis_fields["contextIdentifierHex"]
    presentations: dict[str, dict[str, Any]] = {}
    presentation_rejected: dict[str, ProtocolError] = {}
    encoded_by_identifier: dict[str, bytes] = {}
    for record in records:
        try:
            transcript = bytes.fromhex(record["transcriptHex"])
            reference = framed_hash(DOMAINS["event_reference"], transcript).hex()
            identifier = str(record["id"])
        except (KeyError, ValueError, TypeError) as error:
            raise ProtocolError("STRUCTURAL_REJECTION") from error
        encoded_input = dumps(record)
        if identifier in encoded_by_identifier:
            if encoded_by_identifier[identifier] == encoded_input:
                continue
            raise ProtocolError("STRUCTURAL_REJECTION")
        encoded_by_identifier[identifier] = encoded_input
        presentations[identifier] = {
            "record": record,
            "reference": reference,
            "transcript": transcript,
        }
        try:
            fields = parse_event(transcript)
            if reference != record.get("eventReferenceHex"):
                raise ProtocolError("REFERENCE_COLLISION_UNSUPPORTED")
            if fields["contextIdentifierHex"] != context:
                raise ProtocolError("CREDENTIAL_BINDING_MISMATCH")
            if fields["genesisReferenceHex"] != genesis_reference:
                raise ProtocolError("CREDENTIAL_BINDING_MISMATCH")
            presentations[identifier]["fields"] = fields
        except (KeyError, ValueError, ProtocolError) as error:
            code = (
                error.code
                if isinstance(error, ProtocolError)
                and error.code
                in {"REFERENCE_COLLISION_UNSUPPORTED", "CREDENTIAL_BINDING_MISMATCH"}
                else "STRUCTURAL_REJECTION"
            )
            presentation_rejected[identifier] = ProtocolError(
                code, "S3_KERNEL_STRUCTURAL"
            )

    classified = _classify_reference_identities(
        [
            (value["reference"], value["transcript"])
            for identifier, value in presentations.items()
            if identifier not in presentation_rejected
        ]
    )
    logical_groups: dict[str, dict[str, Any]] = {}
    for identifier, presentation in presentations.items():
        if identifier in presentation_rejected:
            continue
        identity = (presentation["reference"], presentation["transcript"])
        if classified[identity] == "REFERENCE_COLLISION_UNSUPPORTED":
            presentation_rejected[identifier] = ProtocolError(
                "REFERENCE_COLLISION_UNSUPPORTED", "S3_KERNEL_STRUCTURAL"
            )
            continue
        group = logical_groups.setdefault(
            presentation["reference"],
            {
                "fields": presentation["fields"],
                "presentationIds": [],
                "transcript": presentation["transcript"],
            },
        )
        group["presentationIds"].append(identifier)

    def dependencies(fields: Mapping[str, Any]) -> set[str]:
        values = set(fields["causalParents"])
        if fields["directPredecessorHex"] is not None:
            values.add(fields["directPredecessorHex"])
        return values

    admitted: dict[str, dict[str, Any]] = {}
    logical_rejected: dict[str, ProtocolError] = {}
    local_results: dict[str, tuple[dict[str, Any], bool]] = {}
    bindings: dict[str, dict[str, Any]] = {
        genesis_reference: {
            "grantReferenceHex": None,
            "issuerCredentialHex": None,
            "verificationKeyHex": genesis_fields["rootVerificationKeyHex"],
        }
    }

    def ancestors(reference: str) -> frozenset[str]:
        values: set[str] = set()
        frontier = [reference]
        while frontier:
            current = frontier.pop()
            if current in values:
                continue
            values.add(current)
            event = admitted.get(current)
            if event is None:
                continue
            frontier.extend(dependencies(event["fields"]))
        values.discard(reference)
        return frozenset(values)

    pending = set(logical_groups)
    while pending:
        progress = False
        for reference in sorted(tuple(pending)):
            group = logical_groups[reference]
            fields = group["fields"]
            actor = fields["credentialIdentifierHex"]
            binding = bindings.get(actor)
            if binding is None:
                continue
            required = dependencies(fields)
            eligible: list[str] = []
            ready: list[str] = []
            for identifier in sorted(group["presentationIds"]):
                if identifier not in local_results:
                    local_record = dict(presentations[identifier]["record"])
                    local_record.pop("admissionContext", None)
                    local_record["binding"] = {
                        "contextIdentifierHex": context,
                        "credentialIdentifierHex": actor,
                        "verificationKeyHex": binding["verificationKeyHex"],
                    }
                    local = evaluate_vector(local_record)
                    local_code = local.get("localOutcome")
                    local_pending = (
                        local_code == "PENDING_OPENING"
                        and local.get("kBindingAdmission") == "ADMITTED"
                    )
                    local_results[identifier] = (local, local_pending)
                    if (
                        not transition_input_is_compatible(local)
                        and not local_pending
                    ):
                        presentation_rejected[identifier] = ProtocolError(
                            str(local_code or "INVALID"),
                            str(local.get("stage", "S3_KERNEL_STRUCTURAL")),
                        )
                if identifier not in presentation_rejected:
                    eligible.append(identifier)
                    if not local_results[identifier][1]:
                        ready.append(identifier)
            if not eligible:
                first = sorted(group["presentationIds"])[0]
                logical_rejected[reference] = presentation_rejected[first]
                pending.remove(reference)
                progress = True
                continue

            absent = required - set(logical_groups)
            failed = required & set(logical_rejected)
            if absent or failed:
                logical_rejected[reference] = ProtocolError(
                    "DEPENDENCY_DEFERRED", "S4_GRAPH_ADMISSION"
                )
                pending.remove(reference)
                progress = True
                continue
            if not required <= set(admitted):
                continue

            predecessor = fields["directPredecessorHex"]
            parents = tuple(fields["causalParents"])
            try:
                if fields["authorSequence"] == 0:
                    if predecessor is not None:
                        raise ProtocolError("STRUCTURAL_REJECTION")
                else:
                    previous = admitted.get(predecessor or "")
                    if (
                        previous is None
                        or previous["fields"]["credentialIdentifierHex"] != actor
                        or previous["fields"]["authorSequence"] + 1
                        != fields["authorSequence"]
                    ):
                        raise ProtocolError("STRUCTURAL_REJECTION")
                predecessor_ancestors = (
                    ancestors(predecessor) if predecessor is not None else frozenset()
                )
                if any(parent in predecessor_ancestors for parent in parents):
                    raise ProtocolError("STRUCTURAL_REJECTION")
                for index, left in enumerate(parents):
                    left_ancestors = ancestors(left)
                    for right in parents[index + 1 :]:
                        if right in left_ancestors or left in ancestors(right):
                            raise ProtocolError("STRUCTURAL_REJECTION")
                candidate_ancestors = set(required)
                for dependency in required:
                    candidate_ancestors.update(ancestors(dependency))
                if (
                    actor != genesis_reference
                    and binding["grantReferenceHex"] not in candidate_ancestors
                ):
                    raise ProtocolError("UNRESOLVED_CREDENTIAL_BINDING")
                if fields["eventRole"] == "CREDENTIAL":
                    tail = fields["tail"]
                    kind = tail["kind"]
                    if kind == "GRANT":
                        if reference == genesis_reference or reference in bindings:
                            raise ProtocolError(
                                "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED"
                            )
                    elif kind == "REVOKE":
                        target = tail["targetCredentialHex"]
                        if target not in bindings:
                            raise ProtocolError("UNRESOLVABLE_CREDENTIAL")
                        if (
                            target != genesis_reference
                            and target not in candidate_ancestors
                        ):
                            raise ProtocolError("STRUCTURAL_REJECTION")
                    elif kind == "ROTATE":
                        retiring = tail["retiringCredentialHex"]
                        replacement = tail["replacementGrantHex"]
                        if retiring == actor:
                            raise ProtocolError("STRUCTURAL_REJECTION")
                        if retiring not in bindings:
                            raise ProtocolError("UNRESOLVABLE_CREDENTIAL")
                        if (
                            retiring != genesis_reference
                            and retiring not in candidate_ancestors
                        ):
                            raise ProtocolError("STRUCTURAL_REJECTION")
                        replacement_event = admitted.get(replacement)
                        if (
                            replacement_event is None
                            or replacement_event["fields"].get("tail", {}).get("kind")
                            != "GRANT"
                            or (replacement != predecessor and replacement not in parents)
                        ):
                            raise ProtocolError("STRUCTURAL_REJECTION")
                    elif kind == "RECOVER":
                        recovery = tail["recoveryGrantHex"]
                        recovery_event = admitted.get(recovery)
                        if (
                            recovery_event is None
                            or recovery_event["fields"].get("tail", {}).get("kind")
                            != "GRANT"
                            or (recovery != predecessor and recovery not in parents)
                        ):
                            raise ProtocolError("STRUCTURAL_REJECTION")
            except ProtocolError as error:
                logical_rejected[reference] = error
                pending.remove(reference)
                progress = True
                continue

            dependency_pending = any(
                admitted[value]["pendingLineage"] for value in required
            )
            admitted[reference] = {
                "fields": fields,
                "k1PresentationIds": tuple(eligible),
                "localPending": not ready,
                "logicalEventEffectCount": 1,
                "pendingLineage": (not ready) or dependency_pending,
                "record": presentations[(ready or eligible)[0]]["record"],
            }
            if fields["eventRole"] == "CREDENTIAL" and fields["tail"]["kind"] == "GRANT":
                bindings[reference] = {
                    "grantReferenceHex": reference,
                    "issuerCredentialHex": actor,
                    "verificationKeyHex": fields["tail"]["granteeVerificationKeyHex"],
                }
            pending.remove(reference)
            progress = True
        if progress:
            continue
        for reference in sorted(pending):
            fields = logical_groups[reference]["fields"]
            code = (
                "UNRESOLVED_CREDENTIAL_BINDING"
                if fields["credentialIdentifierHex"] not in bindings
                else "DEPENDENCY_DEFERRED"
            )
            stage = (
                "S3_KERNEL_STRUCTURAL"
                if code == "UNRESOLVED_CREDENTIAL_BINDING"
                else "S4_GRAPH_ADMISSION"
            )
            logical_rejected[reference] = ProtocolError(code, stage)
        pending.clear()

    slots: dict[tuple[str, str, int], list[str]] = {}
    for reference, event in admitted.items():
        fields = event["fields"]
        slot = (
            fields["contextIdentifierHex"],
            fields["credentialIdentifierHex"],
            fields["authorSequence"],
        )
        slots.setdefault(slot, []).append(reference)
    forced_forks = {
        reference
        for members in slots.values()
        if len(members) > 1
        for reference in members
    }

    observations = []
    for identifier, presentation in sorted(
        presentations.items(), key=lambda item: (item[1]["reference"], item[0])
    ):
        reference = presentation["reference"]
        error = presentation_rejected.get(identifier)
        logical = admitted.get(reference)
        if error is None:
            error = logical_rejected.get(reference)
        if error is None and reference in forced_forks:
            error = ProtocolError("FORK_EVIDENCE", "EVENT_LOCAL", admitted=True)
        elif error is None and logical["localPending"]:
            error = ProtocolError("PENDING_OPENING", "EVENT_LOCAL", admitted=True)
        elif error is None and logical["pendingLineage"]:
            error = ProtocolError("PENDING_ANCESTOR", "EVENT_LOCAL", admitted=True)
        k_admitted = error is None or error.admitted
        coalesced = (
            len(logical["k1PresentationIds"])
            if k_admitted and logical is not None
            else 0
        )
        observations.append(
            {
                "coalescedPresentationCount": coalesced,
                "eventReferenceHex": reference,
                "id": identifier,
                "kBindingAdmission": (
                    "ADMITTED" if k_admitted else "REJECTED"
                ),
                "logicalEventEffectCount": (
                    logical["logicalEventEffectCount"]
                    if k_admitted and logical is not None
                    else 0
                ),
                "logicalEventReferenceHex": reference,
                "protocolErrorCode": error.code if error else None,
                "stage": error.stage if error else "FINAL_AFTER_S6",
            }
        )
    if presentation_evidence:
        return observations
    evidence_fields = {
        "coalescedPresentationCount",
        "logicalEventEffectCount",
        "logicalEventReferenceHex",
    }
    return [
        {key: value for key, value in row.items() if key not in evidence_fields}
        for row in observations
    ]


def evaluate_transcript_conformance(record: dict[str, Any]) -> dict[str, Any]:
    """Evaluate one disconnected byte fixture without claiming K admission.

    Historical C0.3 fixtures carry synthetic local context so that negative
    branches remain reproducible.  When all local checks pass, that context is
    insufficient to prove a real genesis/GRANT chain; the only honest terminal
    result is transcript conformance with K left unevaluated.
    """

    observed = evaluate_vector(record)
    result = dict(observed)
    result["apAuthorityResult"] = "NOT_REACHED"
    result["kBindingAdmission"] = "NOT_EVALUATED"
    if transition_input_is_compatible(observed):
        result["postStateDigest"] = result["preStateDigest"]
        result["stage"] = "TRANSCRIPT_CONFORMANCE_COMPLETE"
    return result


def public_transcript_observation(record: dict[str, Any]) -> dict[str, Any]:
    """Project one disconnected fixture to the oracle-free public vocabulary."""

    observed = evaluate_transcript_conformance(record)
    result = {
        "apAuthorityResult": observed["apAuthorityResult"],
        "commitmentMatchVerification": observed[
            "commitmentMatchVerification"
        ],
        "commitmentVerification": observed["commitmentVerification"],
        **{
            f"geometryPredicate{index}": observed[f"geometryPredicate{index}"]
            for index in range(1, 8)
        },
        "kBindingAdmission": observed["kBindingAdmission"],
        "localOutcomePresent": "localOutcome" in observed,
        "outcomeEvaluated": observed["outcomeEvaluated"],
        "referenceVerification": observed["referenceVerification"],
        "remoteClassPresent": "remoteClass" in observed,
        "signatureVerification": observed["signatureVerification"],
        "stage": observed["stage"],
        "suppliedLengthVerification": observed[
            "suppliedLengthVerification"
        ],
        "transcriptVerification": observed["transcriptVerification"],
    }
    if "localOutcome" in observed:
        result["localOutcome"] = observed["localOutcome"]
    if "remoteClass" in observed:
        result["remoteClass"] = observed["remoteClass"]
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
        actual_digest = sha256_hex(data)
        if actual_digest != digest:
            reconciliation = BASE_REVIEW_MODEL_DIGEST_RECONCILIATIONS.get(path)
            if reconciliation != (digest, actual_digest):
                raise CorpusModelError(f"review-model source digest mismatch: {path}")
            digest = actual_digest
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
    if inventory.get("schema") != "styx-c03-corpus-inventory/v2":
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
            if not isinstance(witness, dict):
                raise CorpusModelError(f"malformed O-10 row witness: {row_id}")
            vector_witness = set(witness) == {"inputId", "jointSourceRowIds"}
            graph_witness = set(witness) == {
                "inputKAdmissionRecordId",
                "inputKAdmissionScenarioId",
                "jointSourceRowIds",
            }
            if not (vector_witness or graph_witness):
                raise CorpusModelError(f"malformed O-10 row witness: {row_id}")
            input_id = (
                witness["inputId"]
                if vector_witness
                else f"{witness['inputKAdmissionScenarioId']}:{witness['inputKAdmissionRecordId']}"
            )
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
