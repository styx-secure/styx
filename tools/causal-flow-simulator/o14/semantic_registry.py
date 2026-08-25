"""Closed O-14 registry and verification-boundary evidence model."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256

from ed25519_reference import (
    PointDecodeError,
    decode,
    is_small_order,
    is_torsion_free,
    selected_guard,
    selected_verify,
    verify as reference_verify,
    verify_with_scalar_reduction,
)


SUITE_ID = 0x0001
RESERVED_SUITE_IDS = frozenset({0x0000, 0xFFFF})
SUITE_NAME = "STYX-ED25519-PRIMEORDER-RFC8032-V1"


@dataclass(frozen=True)
class SuiteDefinition:
    identifier: int
    signing_mode: str
    verification_equation: str
    public_key_encoding: str
    public_key_octets: int
    signature_encoding: str
    signature_octets: int
    transcript_input: str
    malformed_behavior: str


SELECTED_SUITE = SuiteDefinition(
    identifier=SUITE_ID,
    signing_mode="pure-ed25519-sha512",
    verification_equation=(
        "canonical-prime-order A and R; S<L; one RFC8032 cofactored verifier "
        "invocation (equivalent to cofactorless after the prime-order guards)"
    ),
    public_key_encoding="RFC8032 canonical compressed Edwards y plus x-sign",
    public_key_octets=32,
    signature_encoding="R(32) || S-little-endian(32), canonical R and S<L",
    signature_octets=64,
    transcript_input="complete regenerated O-06b-1 application-event transcript",
    malformed_behavior="terminal typed rejection before AP; no fallback",
)


class VerificationError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class CredentialBinding:
    context: bytes
    credential_identifier: bytes
    suite_id: int
    verification_key: bytes
    authority_state: str = "ACTIVE"
    expected_author_sequence: int = 1


@dataclass(frozen=True)
class EventInput:
    # Event-carried inputs. The transcript regenerates from authenticated event
    # fields; suite/key selection still comes only from ``binding``.
    context: bytes
    credential_identifier: bytes
    author_sequence: int
    transcript: bytes
    signature: bytes
    binding: CredentialBinding | None
    event_suite_override: int | None = None
    event_key_override: bytes | None = None
    # Trusted verifier-context inputs. These values are never decoded from the
    # event or transport envelope and remain independently fail-closed.
    transport_valid: bool = False
    session_valid: bool = False
    grant_suite_id: int | None = None
    grant_verification_key: bytes | None = None
    ap_authorized: bool = True
    declared_key_length: int | None = None
    declared_signature_length: int | None = None
    historical_evidence: bool = False


@dataclass(frozen=True)
class Mutation:
    identifier: str = "NONE"
    allowlist_fingerprints: frozenset[str] = field(default_factory=frozenset)
    special_case_fingerprint: str | None = None


@dataclass(frozen=True)
class VerificationResult:
    accepted: bool
    code: str
    verifier_invocations: int
    ap_exposed: bool
    executed_branches: tuple[str, ...] = field(default_factory=tuple)


def _reject(code: str, branches: list[str], invocations: int = 0, ap: bool = False) -> VerificationResult:
    return VerificationResult(False, code, invocations, ap, tuple(branches))


def _point_error_code(error: PointDecodeError) -> str:
    raw_code = str(error)
    if raw_code in {
        "PUBLIC_KEY_LENGTH",
        "SIGNATURE_LENGTH",
        "NON_CANONICAL_SCALAR",
        "PUBLIC_KEY_NOT_PRIME_ORDER",
        "R_NOT_PRIME_ORDER",
    }:
        return raw_code
    if raw_code in {"non-canonical y", "invalid sign for x=0"}:
        return "NON_CANONICAL_POINT"
    if raw_code == "off-curve point":
        return "OFF_CURVE_POINT"
    return "INVALID_POINT_ENCODING"


def event_fingerprint(event: EventInput, key: bytes) -> str:
    """Identify one complete evidence input for test-only hostile mutations."""

    fields = (
        event.context,
        event.credential_identifier,
        event.author_sequence.to_bytes(8, "big"),
        key,
        event.transcript,
        event.signature,
    )
    framed = b"".join(len(field).to_bytes(8, "big") + field for field in fields)
    return sha256(b"STYX-O14-EVIDENCE-FINGERPRINT-V1" + framed).hexdigest()


def _guard_points_only(public_key: bytes, signature: bytes) -> None:
    """Test-only mutant boundary retaining every guard except S < L."""

    if len(public_key) != 32:
        raise PointDecodeError("PUBLIC_KEY_LENGTH")
    if len(signature) != 64:
        raise PointDecodeError("SIGNATURE_LENGTH")
    a_point = decode(public_key, zip215=False)
    r_point = decode(signature[:32], zip215=False)
    if is_small_order(a_point) or not is_torsion_free(a_point):
        raise PointDecodeError("PUBLIC_KEY_NOT_PRIME_ORDER")
    if is_small_order(r_point) or not is_torsion_free(r_point):
        raise PointDecodeError("R_NOT_PRIME_ORDER")


def _batch_verify_twice(signature: bytes, transcript: bytes, key: bytes) -> tuple[bool, int]:
    """Test-only prohibited multi-call verifier used to falsify the one-call rule."""

    outcomes = (
        selected_verify(signature, transcript, key),
        selected_verify(signature, transcript, key),
    )
    return all(outcomes), len(outcomes)


def verify_event(event: EventInput, mutation: Mutation = Mutation()) -> VerificationResult:
    branches: list[str] = []
    ap_exposed = mutation.identifier == "M_AP_BEFORE_VERIFY"
    if ap_exposed:
        branches.append("mutant:ap-before-verify")

    binding = event.binding
    if binding is None:
        branches.append("binding:missing")
        if mutation.identifier != "M_ACCEPT_MISSING_BINDING":
            return _reject("CREDENTIAL_BINDING_MISSING", branches, ap=ap_exposed)
        branches.append("mutant:missing-binding-accepted")
        suite_id = event.event_suite_override or SUITE_ID
        key = event.event_key_override or bytes(32)
    else:
        branches.append("binding:resolved")
        suite_id = binding.suite_id
        key = binding.verification_key

    if mutation.identifier == "M_TRUST_EVENT_SUITE" and event.event_suite_override is not None:
        branches.append("mutant:event-suite")
        suite_id = event.event_suite_override
    if mutation.identifier == "M_TRUST_EVENT_KEY" and event.event_key_override is not None:
        branches.append("mutant:event-key")
        key = event.event_key_override
    if mutation.identifier == "M_TRUST_GRANT_FIELDS" and event.grant_suite_id is not None:
        branches.append("mutant:grant-fields")
        suite_id = event.grant_suite_id
        key = event.grant_verification_key or key

    if binding is not None:
        if event.context != binding.context:
            branches.append("state:context-mismatch")
            if mutation.identifier != "M_BYPASS_CONTEXT":
                return _reject("CREDENTIAL_CONTEXT_MISMATCH", branches, ap=ap_exposed)
            branches.append("mutant:context-bypassed")
        if event.credential_identifier != binding.credential_identifier:
            branches.append("state:credential-mismatch")
            if mutation.identifier != "M_BYPASS_CREDENTIAL_ID":
                return _reject("CREDENTIAL_IDENTIFIER_MISMATCH", branches, ap=ap_exposed)
            branches.append("mutant:credential-id-bypassed")
        if binding.authority_state != "ACTIVE":
            branches.append(f"state:{binding.authority_state.lower()}")
            if event.historical_evidence:
                branches.append("state:historical-evidence")
            elif mutation.identifier != "M_BYPASS_REVOCATION":
                return _reject("CREDENTIAL_INACTIVE", branches, ap=ap_exposed)
            else:
                branches.append("mutant:inactive-state-bypassed")
        if event.author_sequence != binding.expected_author_sequence:
            branches.append("state:sequence-mismatch")
            if mutation.identifier != "M_BYPASS_SEQUENCE":
                return _reject("AUTHOR_SEQUENCE_MISMATCH", branches, ap=ap_exposed)
            branches.append("mutant:sequence-bypassed")

    if suite_id != SUITE_ID:
        branches.append(
            "suite:reserved" if suite_id in RESERVED_SUITE_IDS else "suite:unknown"
        )
        if mutation.identifier == "M_ACCEPT_UNKNOWN_SUITE":
            branches.append("mutant:unknown-suite-accepted")
            suite_id = SUITE_ID
        elif mutation.identifier == "M_RETRY_FALLBACK":
            branches.append("mutant:fallback-retry")
            # A prohibited default attempt followed by the selected suite is a
            # real two-verifier retry, not a relabelled dispatch outcome.
            first = reference_verify(
                event.signature, event.transcript, key, zip215=True, cofactored=True
            )
            second = selected_verify(event.signature, event.transcript, key)
            branches.extend(("verifier:default-invoked", "verifier:selected-invoked"))
            if first or second:
                branches.append("verifier:true")
                return VerificationResult(True, "ACCEPTED", 2, True, tuple(branches))
            return _reject("SIGNATURE_INVALID", branches, invocations=2, ap=ap_exposed)
        else:
            return _reject("UNKNOWN_SIGNATURE_SUITE", branches, ap=ap_exposed)
    branches.append("suite:selected")

    declared_key = len(key) if event.declared_key_length is None else event.declared_key_length
    declared_sig = len(event.signature) if event.declared_signature_length is None else event.declared_signature_length
    if mutation.identifier == "M_REMOVE_KEY_LENGTH":
        branches.append("mutant:key-length-removed")
    elif declared_key != 32 or len(key) != 32:
        branches.append("length:key")
        return _reject("PUBLIC_KEY_LENGTH", branches, ap=ap_exposed)
    if mutation.identifier == "M_REMOVE_SIGNATURE_LENGTH":
        branches.append("mutant:signature-length-removed")
    elif declared_sig != 64 or len(event.signature) != 64:
        branches.append("length:signature")
        return _reject("SIGNATURE_LENGTH", branches, ap=ap_exposed)
    branches.append("lengths:valid")

    transcript = event.transcript
    if mutation.identifier == "M_VERIFY_EVENT_REFERENCE":
        transcript = sha256(event.transcript).digest()
        branches.append("mutant:event-reference")

    if mutation.identifier == "M_TRUST_TRANSPORT" and event.transport_valid:
        branches.append("mutant:transport-substitution")
        verified = True
        invocations = 0
    elif mutation.identifier == "M_TRUST_SESSION" and event.session_valid:
        branches.append("mutant:session-substitution")
        verified = True
        invocations = 0
    else:
        invocations = 1
        if mutation.identifier == "M_LIBRARY_DEFAULT_ZIP215":
            verified = reference_verify(
                event.signature, transcript, key, zip215=True, cofactored=True
            )
            branches.append("mutant:zip215-default")
            branches.append("verifier:invoked")
        elif mutation.identifier == "M_REMOVE_PRIME_ORDER_GUARD":
            verified = reference_verify(
                event.signature, transcript, key, zip215=False, cofactored=True
            )
            branches.append("mutant:no-prime-order-guard")
            branches.append("verifier:invoked")
        elif mutation.identifier == "M_REMOVE_SCALAR_GUARD":
            try:
                _guard_points_only(key, event.signature)
            except PointDecodeError as error:
                branches.append("guard:rejected")
                return _reject(_point_error_code(error), branches, ap=ap_exposed)
            verified = verify_with_scalar_reduction(event.signature, transcript, key)
            branches.append("mutant:scalar-reduced")
            branches.append("verifier:invoked")
        elif mutation.identifier == "M_REUSE_SUITE_ID_SEMANTICS":
            # Same 0x0001 identifier, deliberately changed to ZIP-215 semantics.
            verified = reference_verify(
                event.signature, transcript, key, zip215=True, cofactored=True
            )
            branches.extend(("mutant:reuse-suite-id-semantics", "verifier:invoked"))
        elif mutation.identifier == "M_ALLOWLIST_GUARD":
            branches.append("mutant:allowlist-guard")
            if event_fingerprint(event, key) not in mutation.allowlist_fingerprints:
                return _reject("ALLOWLIST_MISS", branches, ap=ap_exposed)
            verified = selected_verify(event.signature, transcript, key)
            branches.append("verifier:invoked")
        elif (
            mutation.identifier == "M_PER_VECTOR_SPECIAL_CASE"
            and event_fingerprint(event, key) == mutation.special_case_fingerprint
        ):
            branches.extend(("mutant:per-vector-special-case", "verifier:invoked"))
            verified = reference_verify(
                event.signature, transcript, key, zip215=False, cofactored=True
            )
        else:
            try:
                selected_guard(key, event.signature)
            except PointDecodeError as error:
                branches.append("guard:rejected")
                return _reject(
                    _point_error_code(error), branches, invocations=0, ap=ap_exposed
                )
            branches.append("guard:accepted")
            if mutation.identifier == "M_BATCH_VERIFIER":
                branches.append("mutant:batch-verifier")
                verified, invocations = _batch_verify_twice(
                    event.signature, transcript, key
                )
            else:
                branches.append("verifier:invoked")
                verified = selected_verify(event.signature, transcript, key)

    if not verified:
        branches.append("verifier:false")
        return _reject("SIGNATURE_INVALID", branches, invocations, ap_exposed)
    branches.append("verifier:true")

    if event.historical_evidence and binding is not None and binding.authority_state != "ACTIVE":
        branches.append("historical:verified-no-authority")
        return _reject(
            "HISTORICAL_SIGNATURE_VALID_NO_AUTHORITY",
            branches,
            invocations=invocations,
            ap=False,
        )

    if not event.ap_authorized:
        branches.append("ap:unauthorized")
        if mutation.identifier != "M_TREAT_VERIFY_AS_AUTHORIZATION":
            return _reject("AP_UNAUTHORIZED", branches, invocations, ap_exposed)
        branches.append("mutant:authorization-bypassed")
    branches.append("ap:authorized")
    return VerificationResult(True, "ACCEPTED", invocations, True, tuple(branches))
