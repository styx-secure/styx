"""Executable O-07 genesis and checkpoint-boundary evidence model.

This module is specification evidence only.  It is deliberately isolated from
product code and instantiates the already-selected O-06b-1 and O-14 boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import sys


SIMULATOR_ROOT = Path(__file__).resolve().parent.parent
if str(SIMULATOR_ROOT) not in sys.path:
    sys.path.insert(0, str(SIMULATOR_ROOT))

from o14.ed25519_reference import selected_verify, sign_from_seed


D_GENESIS_SIG = 0x0002
D_EVENT_REF = 0x0003
D_GENESIS_REF = 0x0004
PROTOCOL_VERSION = 0x0001
SIGNATURE_SUITE = 0x0001
REFERENCE_OCTETS = 32
KEY_OCTETS = 32
SIGNATURE_OCTETS = 64
FIXED_BODY_OCTETS = 84
MAX_BODY_OCTETS = (2**32) - 21
MAX_AP_BLOCK_OCTETS = MAX_BODY_OCTETS - FIXED_BODY_OCTETS


class GenesisError(ValueError):
    """Typed O-10-placeholder rejection used by hostile evidence."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ContextTuple:
    protocol_version: int
    application_profile_id: int
    application_profile_version: int
    context_identifier: bytes


@dataclass(frozen=True)
class GenesisBody:
    context: ContextTuple
    signature_suite_id: int
    root_verification_key: bytes
    initial_authority_policy: bytes


@dataclass(frozen=True)
class GenesisCandidate:
    transcript: bytes
    signature: bytes


@dataclass(frozen=True)
class CeremonyRecord:
    context: ContextTuple
    expected_genesis_reference: bytes
    explicit_authorization_decision: bool
    authenticated_provenance: bool


@dataclass(frozen=True)
class AcceptedGenesis:
    ceremony: CeremonyRecord
    body: GenesisBody
    transcript: bytes
    signature: bytes
    genesis_reference: bytes


@dataclass(frozen=True)
class AcceptanceResult:
    state: AcceptedGenesis | None
    disposition: str
    changed: bool


def _u16(value: int) -> bytes:
    if not 0 <= value <= 0xFFFF:
        raise GenesisError("INTEGER_OUT_OF_RANGE")
    return value.to_bytes(2, "big")


def _u32(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise GenesisError("INTEGER_OUT_OF_RANGE")
    return value.to_bytes(4, "big")


def _opaque_u32(value: bytes) -> bytes:
    return _u32(len(value)) + value


def _validate_body(body: GenesisBody, allowed_profiles: frozenset[int]) -> None:
    context = body.context
    if context.protocol_version != PROTOCOL_VERSION:
        raise GenesisError("PROTOCOL_VERSION_REJECTED")
    if context.application_profile_id == 0 or context.application_profile_id not in allowed_profiles:
        raise GenesisError("APPLICATION_PROFILE_REJECTED")
    if context.application_profile_version == 0:
        raise GenesisError("APPLICATION_PROFILE_VERSION_REJECTED")
    if len(context.context_identifier) != REFERENCE_OCTETS:
        raise GenesisError("CONTEXT_IDENTIFIER_LENGTH")
    if body.signature_suite_id != SIGNATURE_SUITE:
        raise GenesisError("SIGNATURE_SUITE_REJECTED")
    if len(body.root_verification_key) != KEY_OCTETS:
        raise GenesisError("ROOT_KEY_LENGTH")
    if not body.initial_authority_policy:
        raise GenesisError("INITIAL_AUTHORITY_POLICY_EMPTY")
    if len(body.initial_authority_policy) > MAX_AP_BLOCK_OCTETS:
        raise GenesisError("INITIAL_AUTHORITY_POLICY_LENGTH")


def encode_body(body: GenesisBody, *, allowed_profiles: frozenset[int]) -> bytes:
    _validate_body(body, allowed_profiles)
    context = body.context
    encoded = b"".join(
        (
            _u16(context.protocol_version),
            _u32(context.application_profile_id),
            _u32(context.application_profile_version),
            context.context_identifier,
            _u16(body.signature_suite_id),
            _opaque_u32(body.root_verification_key),
            _opaque_u32(body.initial_authority_policy),
        )
    )
    if len(encoded) > MAX_BODY_OCTETS:
        raise GenesisError("GENESIS_BODY_LENGTH")
    return encoded


def encode_transcript(body: GenesisBody, *, allowed_profiles: frozenset[int]) -> bytes:
    encoded_body = encode_body(body, allowed_profiles=allowed_profiles)
    return _u16(D_GENESIS_SIG) + _u32(len(encoded_body)) + encoded_body


class _Reader:
    def __init__(self, value: bytes):
        self.value = value
        self.offset = 0

    def take(self, length: int, code: str) -> bytes:
        if length < 0 or self.offset + length > len(self.value):
            raise GenesisError(code)
        result = self.value[self.offset : self.offset + length]
        self.offset += length
        return result

    def u16(self, code: str) -> int:
        return int.from_bytes(self.take(2, code), "big")

    def u32(self, code: str) -> int:
        return int.from_bytes(self.take(4, code), "big")

    def opaque_u32(self, *, maximum: int, length_code: str, truncation_code: str) -> bytes:
        length = self.u32(length_code)
        if length > maximum:
            raise GenesisError(length_code)
        return self.take(length, truncation_code)

    def exact_end(self) -> None:
        if self.offset != len(self.value):
            raise GenesisError("TRAILING_GENESIS_BYTES")


def parse_transcript(
    transcript: bytes,
    *,
    allowed_profiles: frozenset[int],
    runtime_body_limit: int,
) -> GenesisBody:
    outer = _Reader(transcript)
    if outer.u16("TRUNCATED_GENESIS_DOMAIN") != D_GENESIS_SIG:
        raise GenesisError("GENESIS_DOMAIN_REJECTED")
    body_length = outer.u32("TRUNCATED_GENESIS_BODY_LENGTH")
    if body_length > MAX_BODY_OCTETS or body_length > runtime_body_limit:
        raise GenesisError("GENESIS_BODY_LENGTH")
    if body_length != len(transcript) - 6:
        raise GenesisError("GENESIS_BODY_LENGTH_MISMATCH")
    body_reader = _Reader(outer.take(body_length, "TRUNCATED_GENESIS_BODY"))
    context = ContextTuple(
        body_reader.u16("TRUNCATED_PROTOCOL_VERSION"),
        body_reader.u32("TRUNCATED_APPLICATION_PROFILE_ID"),
        body_reader.u32("TRUNCATED_APPLICATION_PROFILE_VERSION"),
        body_reader.take(REFERENCE_OCTETS, "TRUNCATED_CONTEXT_IDENTIFIER"),
    )
    suite = body_reader.u16("TRUNCATED_SIGNATURE_SUITE")
    key = body_reader.opaque_u32(
        maximum=KEY_OCTETS,
        length_code="ROOT_KEY_LENGTH",
        truncation_code="TRUNCATED_ROOT_KEY",
    )
    policy = body_reader.opaque_u32(
        maximum=min(MAX_AP_BLOCK_OCTETS, runtime_body_limit),
        length_code="INITIAL_AUTHORITY_POLICY_LENGTH",
        truncation_code="TRUNCATED_INITIAL_AUTHORITY_POLICY",
    )
    body_reader.exact_end()
    outer.exact_end()
    decoded = GenesisBody(context, suite, key, policy)
    _validate_body(decoded, allowed_profiles)
    if encode_transcript(decoded, allowed_profiles=allowed_profiles) != transcript:
        raise GenesisError("NON_CANONICAL_GENESIS_ENCODING")
    return decoded


def derive_genesis_reference(transcript: bytes) -> bytes:
    return sha256(_u16(D_GENESIS_REF) + _u32(len(transcript)) + transcript).digest()


def derive_event_reference(transcript: bytes) -> bytes:
    return sha256(_u16(D_EVENT_REF) + _u32(len(transcript)) + transcript).digest()


def make_candidate(
    body: GenesisBody,
    seed: bytes,
    *,
    allowed_profiles: frozenset[int],
) -> GenesisCandidate:
    transcript = encode_transcript(body, allowed_profiles=allowed_profiles)
    public_key, signature = sign_from_seed(seed, transcript)
    if public_key != body.root_verification_key:
        raise GenesisError("CREATOR_ROOT_KEY_MISMATCH")
    return GenesisCandidate(transcript, signature)


def validate_candidate(
    candidate: GenesisCandidate,
    ceremony: CeremonyRecord | None,
    *,
    allowed_profiles: frozenset[int],
    runtime_body_limit: int,
) -> tuple[GenesisBody, bytes]:
    if ceremony is None or not ceremony.authenticated_provenance:
        raise GenesisError("AUTHENTICATED_CEREMONY_REQUIRED")
    if not ceremony.explicit_authorization_decision:
        raise GenesisError("ROOT_AUTHORIZATION_REJECTED")
    if len(candidate.signature) != SIGNATURE_OCTETS:
        raise GenesisError("GENESIS_SIGNATURE_LENGTH")
    body = parse_transcript(
        candidate.transcript,
        allowed_profiles=allowed_profiles,
        runtime_body_limit=runtime_body_limit,
    )
    reference = derive_genesis_reference(candidate.transcript)
    if reference != ceremony.expected_genesis_reference:
        raise GenesisError("GENESIS_REFERENCE_MISMATCH")
    if body.context != ceremony.context:
        raise GenesisError("GENESIS_CONTEXT_TUPLE_MISMATCH")
    if not selected_verify(candidate.signature, candidate.transcript, body.root_verification_key):
        raise GenesisError("GENESIS_SIGNATURE_INVALID")
    return body, reference


def accept_genesis(
    current: AcceptedGenesis | None,
    candidate: GenesisCandidate,
    ceremony: CeremonyRecord | None,
    *,
    allowed_profiles: frozenset[int],
    runtime_body_limit: int,
) -> AcceptanceResult:
    body, reference = validate_candidate(
        candidate,
        ceremony,
        allowed_profiles=allowed_profiles,
        runtime_body_limit=runtime_body_limit,
    )
    assert ceremony is not None
    if current is None:
        accepted = AcceptedGenesis(
            ceremony, body, candidate.transcript, candidate.signature, reference
        )
        return AcceptanceResult(accepted, "GENESIS_ACCEPTED", True)
    if (
        current.genesis_reference == reference
        and current.transcript == candidate.transcript
        and current.signature == candidate.signature
        and current.ceremony == ceremony
    ):
        return AcceptanceResult(current, "GENESIS_DUPLICATE_IDEMPOTENT", False)
    raise GenesisError("DISTINCT_SAME_CONTEXT_GENESIS")


def require_descendant_binding(state: AcceptedGenesis, genesis_reference: bytes) -> None:
    if genesis_reference != state.genesis_reference:
        raise GenesisError("DESCENDANT_GENESIS_REFERENCE_MISMATCH")


def reject_grant_identifier_collision(
    accepted_genesis_reference: bytes,
    computed_grant_reference: bytes,
) -> None:
    if computed_grant_reference == accepted_genesis_reference:
        raise GenesisError("GRANT_REFERENCE_EQUALS_GENESIS_CREDENTIAL")


def evaluate_checkpoint_boundary(
    *, checkpoint_evidence_refs: frozenset[bytes], replay_dependency_refs: frozenset[bytes]
) -> str:
    if checkpoint_evidence_refs:
        raise GenesisError("CHECKPOINT_EVIDENCE_UNSUPPORTED_V0")
    if not replay_dependency_refs:
        raise GenesisError("VACUOUS_CHECKPOINT_EVIDENCE")
    return "LIVE_REPLAY_REQUIRED"
