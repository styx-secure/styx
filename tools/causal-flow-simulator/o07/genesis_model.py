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
class CreatorLocalGenesisState:
    """Self-certifying creator state; never acceptor authority evidence."""

    body: GenesisBody
    candidate: GenesisCandidate
    genesis_reference: bytes


@dataclass(frozen=True)
class CeremonyAssertion:
    """The three semantic values authenticated outside candidate delivery.

    This value is input to a ceremony boundary.  It is deliberately not
    accepted by ``accept_genesis`` and is not itself proof that the ceremony
    was authenticated.
    """

    context: ContextTuple
    expected_genesis_reference: bytes
    explicit_authorization_decision: bool


@dataclass(frozen=True)
class AcceptedCeremony:
    """The immutable semantic R binding retained after local verification."""

    context: ContextTuple
    expected_genesis_reference: bytes
    explicit_authorization_decision: bool


_CAPABILITY_CONSTRUCTION_SEAL = object()
_DOMAIN_CONSTRUCTION_SEAL = object()
_TEST_BOUNDARY_ACCESS_SEAL = object()


class VerifiedCeremonyCapability:
    """Opaque, local handle issued by one ceremony boundary for one domain.

    Python object opacity is not an authentication primitive.  The evidence
    claim assumes the boundary, runtime and accepted-state store are outside
    the adversary's control, as required by the ratified O-07 contract.
    """

    __slots__ = (
        "__boundary_witness",
        "__domain_witness",
        "__assertion",
        "__handle_witness",
    )

    def __init__(
        self,
        construction_seal: object,
        boundary_witness: object,
        domain_witness: object,
        assertion: CeremonyAssertion,
        handle_witness: object,
    ) -> None:
        if construction_seal is not _CAPABILITY_CONSTRUCTION_SEAL:
            raise GenesisError("CEREMONY_CAPABILITY_CONSTRUCTION_FORBIDDEN")
        object.__setattr__(self, "_VerifiedCeremonyCapability__boundary_witness", boundary_witness)
        object.__setattr__(self, "_VerifiedCeremonyCapability__domain_witness", domain_witness)
        object.__setattr__(self, "_VerifiedCeremonyCapability__assertion", assertion)
        object.__setattr__(self, "_VerifiedCeremonyCapability__handle_witness", handle_witness)

    def __repr__(self) -> str:
        return "<VerifiedCeremonyCapability local opaque handle>"

    def __copy__(self):
        raise TypeError("VerifiedCeremonyCapability cannot be copied")

    def __deepcopy__(self, memo):
        del memo
        raise TypeError("VerifiedCeremonyCapability cannot be copied")

    def __reduce__(self):
        raise TypeError("VerifiedCeremonyCapability cannot be serialized")

    def _binding_for(
        self,
        *,
        boundary_witness: object,
        domain_witness: object,
        issued_handles: set[object],
    ) -> AcceptedCeremony:
        if self.__domain_witness is not domain_witness:
            raise GenesisError("FOREIGN_ACCEPTANCE_DOMAIN")
        if self.__boundary_witness is not boundary_witness:
            raise GenesisError("FOREIGN_CEREMONY_BOUNDARY")
        if self.__handle_witness not in issued_handles:
            raise GenesisError("CEREMONY_CAPABILITY_INVALID")
        assertion = self.__assertion
        if not assertion.explicit_authorization_decision:
            raise GenesisError("ROOT_AUTHORIZATION_REJECTED")
        return AcceptedCeremony(
            assertion.context,
            assertion.expected_genesis_reference,
            assertion.explicit_authorization_decision,
        )


class _CeremonyBoundary:
    __slots__ = (
        "__boundary_witness",
        "__domain_witness",
        "__expected_context",
        "__expected_reference",
        "__issued_handles",
    )

    def __init__(
        self,
        domain_witness: object,
        expected_context: ContextTuple,
        expected_reference: bytes,
    ) -> None:
        self.__boundary_witness = object()
        self.__domain_witness = domain_witness
        self.__expected_context = expected_context
        self.__expected_reference = expected_reference
        self.__issued_handles: set[object] = set()

    def _issue(self, assertion: CeremonyAssertion) -> VerifiedCeremonyCapability:
        if not assertion.explicit_authorization_decision:
            raise GenesisError("ROOT_AUTHORIZATION_REJECTED")
        if len(assertion.expected_genesis_reference) != REFERENCE_OCTETS:
            raise GenesisError("CEREMONY_REFERENCE_LENGTH")
        if assertion.context != self.__expected_context:
            raise GenesisError("CEREMONY_CONTEXT_MISMATCH")
        if assertion.expected_genesis_reference != self.__expected_reference:
            raise GenesisError("CEREMONY_REFERENCE_MISMATCH")
        handle_witness = object()
        self.__issued_handles.add(handle_witness)
        return VerifiedCeremonyCapability(
            _CAPABILITY_CONSTRUCTION_SEAL,
            self.__boundary_witness,
            self.__domain_witness,
            assertion,
            handle_witness,
        )

    def validate(self, capability: object) -> AcceptedCeremony:
        if capability is None:
            raise GenesisError("VERIFIED_CEREMONY_CAPABILITY_REQUIRED")
        if not isinstance(capability, VerifiedCeremonyCapability):
            raise GenesisError("CEREMONY_CAPABILITY_INVALID")
        return capability._binding_for(
            boundary_witness=self.__boundary_witness,
            domain_witness=self.__domain_witness,
            issued_handles=self.__issued_handles,
        )


class AcceptanceDomain:
    """One local acceptance domain with a non-replaceable ceremony boundary."""

    __slots__ = ("__domain_witness", "__boundary")

    def __init__(
        self,
        construction_seal: object,
        domain_witness: object,
        boundary: _CeremonyBoundary,
    ) -> None:
        if construction_seal is not _DOMAIN_CONSTRUCTION_SEAL:
            raise GenesisError("ACCEPTANCE_DOMAIN_CONSTRUCTION_FORBIDDEN")
        self.__domain_witness = domain_witness
        self.__boundary = boundary

    def _validate_capability(self, capability: object) -> AcceptedCeremony:
        return self.__boundary.validate(capability)

    def _test_domain_witness(self, access_seal: object) -> object:
        if access_seal is not _TEST_BOUNDARY_ACCESS_SEAL:
            raise GenesisError("TEST_BOUNDARY_ACCESS_FORBIDDEN")
        return self.__domain_witness


class _TestBoundaryController:
    """Internal issuance controller exposed only through test helper modules."""

    __slots__ = ("__boundary",)

    def __init__(self, boundary: _CeremonyBoundary) -> None:
        self.__boundary = boundary

    def issue_affirmative(
        self, context: ContextTuple, expected_genesis_reference: bytes
    ) -> VerifiedCeremonyCapability:
        return self.__boundary._issue(
            CeremonyAssertion(context, expected_genesis_reference, True)
        )


def _new_test_acceptance_domain(
    expected_context: ContextTuple,
    expected_genesis_reference: bytes,
) -> tuple[AcceptanceDomain, _TestBoundaryController]:
    """Create isolated test state; production ceremony construction is unselected."""

    domain_witness = object()
    boundary = _CeremonyBoundary(
        domain_witness, expected_context, expected_genesis_reference
    )
    domain = AcceptanceDomain(_DOMAIN_CONSTRUCTION_SEAL, domain_witness, boundary)
    return domain, _TestBoundaryController(boundary)


def _new_test_foreign_boundary_controller(
    domain: AcceptanceDomain,
    expected_context: ContextTuple,
    expected_genesis_reference: bytes,
) -> _TestBoundaryController:
    """Create a second test-only Boundary in an existing local domain."""

    domain_witness = domain._test_domain_witness(_TEST_BOUNDARY_ACCESS_SEAL)
    boundary = _CeremonyBoundary(
        domain_witness, expected_context, expected_genesis_reference
    )
    return _TestBoundaryController(boundary)


@dataclass(frozen=True)
class AcceptedGenesis:
    ceremony: AcceptedCeremony
    body: GenesisBody
    transcript: bytes
    signature: bytes
    genesis_reference: bytes


@dataclass(frozen=True)
class AcceptanceResult:
    state: AcceptedGenesis | None
    disposition: str
    changed: bool


@dataclass(frozen=True)
class LineageProjection:
    """Minimal O-07 lineage state; it does not model profile-owned AP internals."""

    genesis_reference: bytes
    terminated: bool = False
    termination_reason: str | None = None


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


def evaluate_body_length_bounds(declared_length: int, runtime_body_limit: int) -> str:
    """Evaluate declared body length before any body allocation or slice."""

    if not 0 <= declared_length <= 0xFFFFFFFF:
        raise GenesisError("INTEGER_OUT_OF_RANGE")
    if declared_length > MAX_BODY_OCTETS:
        raise GenesisError("GENESIS_BODY_LENGTH")
    if declared_length > runtime_body_limit:
        raise GenesisError("GENESIS_BODY_RUNTIME_LIMIT")
    return "NORMATIVE_BODY_LENGTH_ACCEPTED"


def evaluate_ap_block_length_bounds(declared_length: int, runtime_body_limit: int) -> str:
    """Evaluate declared AP-block length before any AP allocation or slice."""

    if not 0 <= declared_length <= 0xFFFFFFFF:
        raise GenesisError("INTEGER_OUT_OF_RANGE")
    if declared_length > MAX_AP_BLOCK_OCTETS:
        raise GenesisError("INITIAL_AUTHORITY_POLICY_LENGTH")
    if declared_length > runtime_body_limit:
        raise GenesisError("INITIAL_AUTHORITY_POLICY_RUNTIME_LIMIT")
    return "NORMATIVE_AP_BLOCK_LENGTH_ACCEPTED"


def _validate_body(
    body: GenesisBody,
    allowed_profiles: frozenset[tuple[int, int]],
) -> None:
    context = body.context
    if context.protocol_version != PROTOCOL_VERSION:
        raise GenesisError("PROTOCOL_VERSION_REJECTED")
    selected_profile = (
        context.application_profile_id,
        context.application_profile_version,
    )
    if context.application_profile_id == 0 or selected_profile not in allowed_profiles:
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


def encode_body(
    body: GenesisBody, *, allowed_profiles: frozenset[tuple[int, int]]
) -> bytes:
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


def encode_transcript(
    body: GenesisBody, *, allowed_profiles: frozenset[tuple[int, int]]
) -> bytes:
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
    allowed_profiles: frozenset[tuple[int, int]],
    runtime_body_limit: int,
) -> GenesisBody:
    outer = _Reader(transcript)
    if outer.u16("TRUNCATED_GENESIS_DOMAIN") != D_GENESIS_SIG:
        raise GenesisError("GENESIS_DOMAIN_REJECTED")
    body_length = outer.u32("TRUNCATED_GENESIS_BODY_LENGTH")
    evaluate_body_length_bounds(body_length, runtime_body_limit)
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
    policy_length = body_reader.u32("INITIAL_AUTHORITY_POLICY_LENGTH")
    evaluate_ap_block_length_bounds(policy_length, runtime_body_limit)
    policy = body_reader.take(
        policy_length,
        "TRUNCATED_INITIAL_AUTHORITY_POLICY",
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


def enforce_frozen_signature_suite(
    transcript_suite: int,
    *,
    event_suite: int | None = None,
    ambient_suite: int | None = None,
    fallback_requested: bool = False,
) -> None:
    if transcript_suite != SIGNATURE_SUITE:
        raise GenesisError("SIGNATURE_SUITE_REJECTED")
    if event_suite is not None and event_suite != transcript_suite:
        raise GenesisError("EVENT_SUITE_SUBSTITUTION_REJECTED")
    if ambient_suite is not None and ambient_suite != transcript_suite:
        raise GenesisError("AMBIENT_SUITE_SUBSTITUTION_REJECTED")
    if fallback_requested:
        raise GenesisError("SIGNATURE_SUITE_FALLBACK_REJECTED")


def enforce_transcript_root_key(
    transcript_key: bytes,
    *,
    event_key: bytes | None = None,
    ambient_key: bytes | None = None,
    fallback_requested: bool = False,
) -> None:
    if event_key is not None and event_key != transcript_key:
        raise GenesisError("EVENT_KEY_SUBSTITUTION_REJECTED")
    if ambient_key is not None and ambient_key != transcript_key:
        raise GenesisError("AMBIENT_KEY_SUBSTITUTION_REJECTED")
    if fallback_requested:
        raise GenesisError("ROOT_KEY_FALLBACK_REJECTED")


def make_candidate(
    body: GenesisBody,
    seed: bytes,
    *,
    allowed_profiles: frozenset[tuple[int, int]],
) -> GenesisCandidate:
    transcript = encode_transcript(body, allowed_profiles=allowed_profiles)
    public_key, signature = sign_from_seed(seed, transcript)
    if public_key != body.root_verification_key:
        raise GenesisError("CREATOR_ROOT_KEY_MISMATCH")
    return GenesisCandidate(transcript, signature)


def create_local_genesis(
    body: GenesisBody,
    seed: bytes,
    *,
    allowed_profiles: frozenset[tuple[int, int]],
) -> CreatorLocalGenesisState:
    candidate = make_candidate(body, seed, allowed_profiles=allowed_profiles)
    return CreatorLocalGenesisState(
        body,
        candidate,
        derive_genesis_reference(candidate.transcript),
    )


def validate_candidate(
    domain: AcceptanceDomain,
    candidate: GenesisCandidate,
    capability: object,
    *,
    allowed_profiles: frozenset[tuple[int, int]],
    runtime_body_limit: int,
) -> tuple[GenesisBody, bytes, AcceptedCeremony]:
    ceremony = domain._validate_capability(capability)
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
    return body, reference, ceremony


def accept_genesis(
    domain: AcceptanceDomain,
    current: AcceptedGenesis | None,
    candidate: GenesisCandidate,
    capability: object,
    *,
    allowed_profiles: frozenset[tuple[int, int]],
    runtime_body_limit: int,
) -> AcceptanceResult:
    body, reference, ceremony = validate_candidate(
        domain,
        candidate,
        capability,
        allowed_profiles=allowed_profiles,
        runtime_body_limit=runtime_body_limit,
    )
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


def evaluate_acceptance_gates(
    *,
    authenticated_possession: bool,
    cryptographic_validity: bool,
    kernel_binding: bool,
    application_authority: bool,
    acceptance_transition: bool,
) -> str:
    """Require each independently owned gate; no true gate substitutes another."""

    gates = (
        (authenticated_possession, "AUTHENTICATED_POSSESSION_REQUIRED"),
        (cryptographic_validity, "CRYPTOGRAPHIC_VALIDITY_REQUIRED"),
        (kernel_binding, "KERNEL_BINDING_REQUIRED"),
        (application_authority, "APPLICATION_AUTHORITY_REQUIRED"),
        (acceptance_transition, "ACCEPTANCE_TRANSITION_REQUIRED"),
    )
    for passed, code in gates:
        if not passed:
            raise GenesisError(code)
    return "ALL_INDEPENDENT_GATES_PASSED"


_GATE_NAMES = frozenset({"P", "C", "K", "A", "R"})
_NON_AUTHORITY_FACTS = frozenset(
    {
        "PV_DISCLOSURE",
        "SESSION_IDENTITY",
        "TRANSPORT_IDENTITY",
        "RUNTIME_IDENTITY",
        "STORAGE_ORDER",
        "UI_STATE",
        "FIELD_BYTE_EQUALITY",
        "LOCAL_PREFERENCE",
        "LEXICAL_ORDER",
    }
)


def reject_gate_substitution(source_gate: str, target_gate: str) -> None:
    """Reject one independently named gate being used as another gate's proof."""

    if source_gate not in _GATE_NAMES or target_gate not in _GATE_NAMES:
        raise GenesisError("UNKNOWN_ACCEPTANCE_GATE")
    if source_gate == target_gate:
        raise GenesisError("GATE_SELF_SUBSTITUTION_FIXTURE_INVALID")
    raise GenesisError(f"GATE_SUBSTITUTION_{source_gate}_FOR_{target_gate}")


def reject_application_authority_substitution(source_fact: str) -> None:
    """Reject ambient/application facts that do not constitute AP authority."""

    if source_fact not in _NON_AUTHORITY_FACTS:
        raise GenesisError("UNKNOWN_NON_AUTHORITY_FACT")
    raise GenesisError(f"APPLICATION_AUTHORITY_SUBSTITUTION_{source_fact}")


def validate_single_root_shape(
    *, root_count: int, threshold: int, additional_cosigners: int
) -> None:
    if additional_cosigners:
        raise GenesisError("UNAUTHORIZED_COSIGNER")
    if threshold != 1:
        raise GenesisError("THRESHOLD_ROOT_NOT_SELECTABLE_V0")
    if root_count != 1:
        raise GenesisError("MULTI_ROOT_NOT_SELECTABLE_V0")


def reject_initial_ap_self_reference(
    initial_authority_policy: bytes, genesis_reference: bytes
) -> None:
    if genesis_reference in initial_authority_policy:
        raise GenesisError("GENESIS_SELF_REFERENCE_FORBIDDEN")


def new_lineage_projection(state: AcceptedGenesis) -> LineageProjection:
    return LineageProjection(state.genesis_reference)


def terminate_root_lineage(
    projection: LineageProjection, *, event_kind: str
) -> LineageProjection:
    reasons = {
        "REVOKE": "ROOT_REVOKED",
        "ROTATE": "ROOT_ROTATED_NO_SUCCESSOR",
        "FORK": "ROOT_EQUIVOCATION",
    }
    try:
        reason = reasons[event_kind]
    except KeyError as error:
        raise GenesisError("UNKNOWN_ROOT_CONTROL_EVENT") from error
    if projection.terminated:
        return projection
    return LineageProjection(projection.genesis_reference, True, reason)


def admit_lineage_descendant(
    projection: LineageProjection,
    *,
    field16_reference: bytes | None,
    causally_descends: bool,
) -> str:
    if projection.terminated:
        raise GenesisError("DESCENDANT_AFTER_ROOT_TERMINATION")
    if field16_reference is None:
        raise GenesisError("GENESIS_AUTHORED_FIELD16_REQUIRED")
    if field16_reference != projection.genesis_reference:
        raise GenesisError("DESCENDANT_GENESIS_REFERENCE_MISMATCH")
    if not causally_descends:
        raise GenesisError("GENESIS_DESCENT_REQUIRED")
    return "GENESIS_DESCENT_AND_FIELD16_BOUND"


def reject_same_context_root_recovery(projection: LineageProjection) -> None:
    if not projection.terminated:
        raise GenesisError("ROOT_RECOVERY_FIXTURE_REQUIRES_TERMINATION")
    raise GenesisError("SAME_CONTEXT_ROOT_RECOVERY_UNSUPPORTED")


_UNSUPPORTED_CHECKPOINT_ASSERTIONS = frozenset(
    {
        "PRODUCER_ELIGIBILITY",
        "SIGNER_AUTHORITY",
        "THRESHOLD_AUTHORITY",
        "AP_STATE",
        "CONTENT_RECONSTRUCTION",
        "OPENING_RECONSTRUCTION",
        "FRESHNESS",
        "FINALITY",
        "HORIZON_AUTHORITY",
        "RETENTION_SUMMARY_GRANT_SIDE",
    }
)
_UNREACHABLE_CHECKPOINT_INPUTS = frozenset(
    {"UNREGISTERED_DOMAIN", "NO_V0_OBJECT", "NO_V0_COMPACTION"}
)


def evaluate_checkpoint_assertion(assertion_kind: str) -> str:
    if assertion_kind not in _UNSUPPORTED_CHECKPOINT_ASSERTIONS:
        raise GenesisError("UNKNOWN_CHECKPOINT_ASSERTION")
    return "CHECKPOINT_ASSERTION_UNSUPPORTED_V0"


def evaluate_checkpoint_input_reachability(input_kind: str) -> str:
    if input_kind not in _UNREACHABLE_CHECKPOINT_INPUTS:
        raise GenesisError("UNKNOWN_CHECKPOINT_INPUT")
    return "CHECKPOINT_INPUT_UNREACHABLE_V0"


def reject_checkpoint_evidence_smuggling(source: str) -> None:
    allowed_sources = frozenset(
        {"STRUCTURAL_MATERIAL", "SIGNED_MATERIAL", "STALENESS_ASSERTION",
         "ADMITTED_REFERENCE", "RUNTIME_PEER", "RETENTION_SUMMARY",
         "CALLER_FLAG", "FIXTURE_SYNTHETIC"}
    )
    if source not in allowed_sources:
        raise GenesisError("UNKNOWN_CHECKPOINT_SMUGGLING_SOURCE")
    raise GenesisError(f"CHECKPOINT_EVIDENCE_SMUGGLING_{source}")


def evaluate_checkpoint_boundary(
    *, checkpoint_evidence_refs: frozenset[bytes], replay_dependency_refs: frozenset[bytes]
) -> str:
    if checkpoint_evidence_refs:
        raise GenesisError("CHECKPOINT_EVIDENCE_UNSUPPORTED_V0")
    if not replay_dependency_refs:
        raise GenesisError("VACUOUS_CHECKPOINT_EVIDENCE")
    return "LIVE_REPLAY_REQUIRED"
