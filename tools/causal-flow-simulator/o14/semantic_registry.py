"""Closed O-14 registry and verification-boundary evidence model."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256

from ed25519_reference import (
    PointDecodeError,
    selected_guard,
    selected_verify,
    verify as reference_verify,
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
    active: bool = True
    expected_author_sequence: int = 1


@dataclass(frozen=True)
class EventInput:
    context: bytes
    credential_identifier: bytes
    author_sequence: int
    transcript: bytes
    signature: bytes
    binding: CredentialBinding | None
    event_suite_override: int | None = None
    event_key_override: bytes | None = None
    transport_valid: bool = False
    session_valid: bool = False
    grant_suite_id: int | None = None
    grant_verification_key: bytes | None = None
    ap_authorized: bool = True
    declared_key_length: int | None = None
    declared_signature_length: int | None = None


@dataclass(frozen=True)
class Mutation:
    identifier: str = "NONE"


@dataclass(frozen=True)
class VerificationResult:
    accepted: bool
    code: str
    verifier_invocations: int
    ap_exposed: bool
    executed_branches: tuple[str, ...] = field(default_factory=tuple)


def _reject(code: str, branches: list[str], invocations: int = 0, ap: bool = False) -> VerificationResult:
    return VerificationResult(False, code, invocations, ap, tuple(branches))


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

    if suite_id != SUITE_ID:
        branches.append("suite:unknown")
        if mutation.identifier == "M_ACCEPT_UNKNOWN_SUITE":
            branches.append("mutant:unknown-suite-accepted")
            suite_id = SUITE_ID
        elif mutation.identifier == "M_RETRY_FALLBACK":
            branches.append("mutant:fallback")
            suite_id = SUITE_ID
        else:
            return _reject("UNKNOWN_SIGNATURE_SUITE", branches, ap=ap_exposed)
    branches.append("suite:selected")

    if binding is not None:
        if event.context != binding.context:
            branches.append("state:context-mismatch")
            if mutation.identifier != "M_BYPASS_CONTEXT":
                return _reject("CREDENTIAL_CONTEXT_MISMATCH", branches, ap=ap_exposed)
        if event.credential_identifier != binding.credential_identifier:
            branches.append("state:credential-mismatch")
            if mutation.identifier != "M_BYPASS_CREDENTIAL_ID":
                return _reject("CREDENTIAL_IDENTIFIER_MISMATCH", branches, ap=ap_exposed)
        if not binding.active:
            branches.append("state:inactive")
            if mutation.identifier != "M_BYPASS_REVOCATION":
                return _reject("CREDENTIAL_INACTIVE", branches, ap=ap_exposed)
        if event.author_sequence != binding.expected_author_sequence:
            branches.append("state:sequence-mismatch")
            if mutation.identifier != "M_BYPASS_SEQUENCE":
                return _reject("AUTHOR_SEQUENCE_MISMATCH", branches, ap=ap_exposed)

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
        elif mutation.identifier == "M_REMOVE_PRIME_ORDER_GUARD":
            verified = reference_verify(
                event.signature, transcript, key, zip215=False, cofactored=True
            )
            branches.append("mutant:no-prime-order-guard")
        elif mutation.identifier == "M_REMOVE_SCALAR_GUARD":
            signature = event.signature
            if len(signature) == 64:
                scalar = int.from_bytes(signature[32:], "little")
                signature = signature[:32] + (scalar % (2**252 + 27742317777372353535851937790883648493)).to_bytes(32, "little")
            verified = selected_verify(signature, transcript, key)
            branches.append("mutant:scalar-reduced")
        else:
            try:
                selected_guard(key, event.signature)
            except PointDecodeError as error:
                branches.append("guard:rejected")
                raw_code = str(error)
                code = (
                    raw_code
                    if raw_code
                    in {
                        "PUBLIC_KEY_LENGTH",
                        "SIGNATURE_LENGTH",
                        "NON_CANONICAL_SCALAR",
                        "PUBLIC_KEY_NOT_PRIME_ORDER",
                        "R_NOT_PRIME_ORDER",
                    }
                    else "INVALID_POINT_ENCODING"
                )
                return _reject(code, branches, invocations=0, ap=ap_exposed)
            branches.append("guard:accepted")
            if mutation.identifier == "M_BATCH_VERIFIER":
                branches.append("mutant:batch-verifier")
            else:
                branches.append("verifier:invoked")
            verified = selected_verify(event.signature, transcript, key)

    if not verified:
        branches.append("verifier:false")
        return _reject("SIGNATURE_INVALID", branches, invocations, ap_exposed)
    branches.append("verifier:true")

    if not event.ap_authorized and mutation.identifier != "M_TREAT_VERIFY_AS_AUTHORIZATION":
        branches.append("ap:unauthorized")
        return _reject("AP_UNAUTHORIZED", branches, invocations, ap_exposed)
    branches.append("ap:authorized")
    return VerificationResult(True, "ACCEPTED", invocations, True, tuple(branches))
