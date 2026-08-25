"""Closed O-14 witness and mutant registry."""

from __future__ import annotations

from dataclasses import dataclass, replace

from ed25519_reference import (
    L,
    P,
    mixed_order_cofactorless_valid,
    mixed_order_forgery,
    sign_from_seed,
    small_order_r_forgery,
    zip215_noncanonical_key_forgery,
)
from semantic_registry import (
    CredentialBinding,
    EventInput,
    Mutation,
    SUITE_ID,
    event_fingerprint,
    verify_event,
)


SEED_A = bytes(range(32))
SEED_B = bytes(reversed(range(32)))
CONTEXT = bytes.fromhex("10" * 32)
CREDENTIAL_A = bytes.fromhex("20" * 32)
CREDENTIAL_B = bytes.fromhex("21" * 32)
CREDENTIAL_ROTATED = bytes.fromhex("22" * 32)
CREDENTIAL_RECOVERED = bytes.fromhex("23" * 32)
TRANSCRIPT_PREFIX = b"STYX-O06B1-APPLICATION-EVENT-TRANSCRIPT-V1"
TRANSCRIPT = TRANSCRIPT_PREFIX + CREDENTIAL_A
EXPECTED_WITNESS_COUNT = 53
EXPECTED_RUNTIME_VECTOR_COUNT = 29


@dataclass(frozen=True)
class Witness:
    identifier: str
    event: EventInput
    expected: bool
    expected_code: str
    runtime: bool = False
    guard_must_not_run: bool = False
    single_verifier_required: bool = False


def _baseline() -> EventInput:
    key, signature = sign_from_seed(SEED_A, TRANSCRIPT)
    binding = CredentialBinding(CONTEXT, CREDENTIAL_A, 0x0001, key)
    return EventInput(CONTEXT, CREDENTIAL_A, 1, TRANSCRIPT, signature, binding)


def required_witnesses() -> tuple[Witness, ...]:
    base = _baseline()
    key_b, sig_b = sign_from_seed(SEED_B, TRANSCRIPT)
    changed_message = TRANSCRIPT + b"!"
    _, changed_signature = sign_from_seed(SEED_A, changed_message)
    mixed_key, mixed_signature = mixed_order_forgery(SEED_A, TRANSCRIPT)
    mixed_key_2, mixed_signature_2 = mixed_order_forgery(SEED_B, TRANSCRIPT + b"-2")
    mixed_valid_key, mixed_valid_signature = mixed_order_cofactorless_valid(
        SEED_A, TRANSCRIPT + b"-cofactorless-valid"
    )
    small_r_key, small_r_signature = small_order_r_forgery(SEED_A, TRANSCRIPT)
    zip_key, zip_signature = zip215_noncanonical_key_forgery(TRANSCRIPT)
    scalar = int.from_bytes(base.signature[32:], "little")
    same_key_transcript = TRANSCRIPT_PREFIX + CREDENTIAL_B
    _, same_key_signature = sign_from_seed(SEED_A, same_key_transcript)
    rotated_transcript = TRANSCRIPT_PREFIX + CREDENTIAL_ROTATED
    rotated_key, rotated_signature = sign_from_seed(SEED_B, rotated_transcript)
    recovered_transcript = TRANSCRIPT_PREFIX + CREDENTIAL_RECOVERED
    recovered_key, recovered_signature = sign_from_seed(SEED_B, recovered_transcript)
    noncanonical_r = (P + 1).to_bytes(32, "little") + base.signature[32:]
    return (
        Witness("positive", base, True, "ACCEPTED", True, False, True),
        Witness(
            "novel-positive",
            replace(
                base,
                transcript=TRANSCRIPT + b"-novel",
                signature=sign_from_seed(SEED_B, TRANSCRIPT + b"-novel")[1],
                binding=replace(
                    base.binding,
                    verification_key=sign_from_seed(SEED_B, TRANSCRIPT + b"-novel")[0],
                ),
            ),
            True,
            "ACCEPTED",
            True,
        ),
        Witness("empty-transcript", replace(base, transcript=b"", signature=sign_from_seed(SEED_A, b"")[1]), True, "ACCEPTED", True),
        Witness("one-octet-transcript", replace(base, transcript=b"x", signature=sign_from_seed(SEED_A, b"x")[1]), True, "ACCEPTED", True),
        Witness("max-representative-transcript", replace(base, transcript=b"z" * 4096, signature=sign_from_seed(SEED_A, b"z" * 4096)[1]), True, "ACCEPTED", True),
        Witness("unknown-suite", replace(base, binding=replace(base.binding, suite_id=2)), False, "UNKNOWN_SIGNATURE_SUITE"),
        Witness("zero-suite", replace(base, binding=replace(base.binding, suite_id=0)), False, "UNKNOWN_SIGNATURE_SUITE"),
        Witness("max-suite", replace(base, binding=replace(base.binding, suite_id=65535)), False, "UNKNOWN_SIGNATURE_SUITE"),
        Witness("missing-binding", replace(base, binding=None), False, "CREDENTIAL_BINDING_MISSING"),
        Witness("wrong-context", replace(base, context=bytes.fromhex("11" * 32)), False, "CREDENTIAL_CONTEXT_MISMATCH"),
        Witness("wrong-credential", replace(base, credential_identifier=CREDENTIAL_B), False, "CREDENTIAL_IDENTIFIER_MISMATCH"),
        Witness("wrong-sequence", replace(base, author_sequence=2), False, "AUTHOR_SEQUENCE_MISMATCH"),
        Witness("revoked", replace(base, binding=replace(base.binding, authority_state="REVOKED")), False, "CREDENTIAL_INACTIVE"),
        Witness("rotated-predecessor", replace(base, binding=replace(base.binding, authority_state="ROTATED")), False, "CREDENTIAL_INACTIVE"),
        Witness("recovered-predecessor", replace(base, binding=replace(base.binding, authority_state="RECOVERY_RETIRED")), False, "CREDENTIAL_INACTIVE"),
        Witness(
            "historical-revoked",
            replace(
                base,
                binding=replace(base.binding, authority_state="REVOKED"),
                historical_evidence=True,
            ),
            False,
            "HISTORICAL_SIGNATURE_VALID_NO_AUTHORITY",
            False,
            False,
            True,
        ),
        Witness(
            "historical-rotated",
            replace(
                base,
                binding=replace(base.binding, authority_state="ROTATED"),
                historical_evidence=True,
            ),
            False,
            "HISTORICAL_SIGNATURE_VALID_NO_AUTHORITY",
            False,
            False,
            True,
        ),
        Witness(
            "rotation-successor",
            EventInput(
                CONTEXT,
                CREDENTIAL_ROTATED,
                1,
                rotated_transcript,
                rotated_signature,
                CredentialBinding(
                    CONTEXT, CREDENTIAL_ROTATED, SUITE_ID, rotated_key
                ),
            ),
            True,
            "ACCEPTED",
        ),
        Witness(
            "recovery-successor",
            EventInput(
                CONTEXT,
                CREDENTIAL_RECOVERED,
                1,
                recovered_transcript,
                recovered_signature,
                CredentialBinding(
                    CONTEXT, CREDENTIAL_RECOVERED, SUITE_ID, recovered_key
                ),
            ),
            True,
            "ACCEPTED",
        ),
        Witness("ap-denied", replace(base, ap_authorized=False), False, "AP_UNAUTHORIZED", single_verifier_required=True),
        Witness("altered-transcript", replace(base, transcript=changed_message), False, "SIGNATURE_INVALID", True, single_verifier_required=True),
        Witness("other-key", replace(base, binding=replace(base.binding, verification_key=key_b)), False, "SIGNATURE_INVALID", True, single_verifier_required=True),
        Witness("other-signature", replace(base, signature=sig_b), False, "SIGNATURE_INVALID", True, single_verifier_required=True),
        Witness("zero-length-key", replace(base, binding=replace(base.binding, verification_key=b"")), False, "PUBLIC_KEY_LENGTH", True, True),
        Witness("truncated-key", replace(base, binding=replace(base.binding, verification_key=base.binding.verification_key[:-1])), False, "PUBLIC_KEY_LENGTH", True, True),
        Witness("extended-key", replace(base, binding=replace(base.binding, verification_key=base.binding.verification_key + b"x")), False, "PUBLIC_KEY_LENGTH", True, True),
        Witness("oversized-declared-key", replace(base, declared_key_length=2**32 - 1), False, "PUBLIC_KEY_LENGTH", False, True),
        Witness("zero-length-signature", replace(base, signature=b""), False, "SIGNATURE_LENGTH", True, True),
        Witness("truncated-signature", replace(base, signature=base.signature[:-1]), False, "SIGNATURE_LENGTH", True, True),
        Witness("extended-signature", replace(base, signature=base.signature + b"x"), False, "SIGNATURE_LENGTH", True, True),
        Witness("oversized-declared-signature", replace(base, declared_signature_length=2**32 - 1), False, "SIGNATURE_LENGTH", False, True),
        Witness("scalar-equals-l", replace(base, signature=base.signature[:32] + L.to_bytes(32, "little")), False, "NON_CANONICAL_SCALAR", True),
        Witness("scalar-greater-l", replace(base, signature=base.signature[:32] + (L + 1).to_bytes(32, "little")), False, "NON_CANONICAL_SCALAR", True),
        Witness("scalar-plus-l", replace(base, signature=base.signature[:32] + (scalar + L).to_bytes(32, "little")), False, "NON_CANONICAL_SCALAR", True),
        Witness("bitflip-r", replace(base, signature=bytes([base.signature[0] ^ 1]) + base.signature[1:]), False, "OFF_CURVE_POINT", True),
        Witness("noncanonical-r", replace(base, signature=noncanonical_r), False, "NON_CANONICAL_POINT", True),
        Witness("bitflip-s", replace(base, signature=base.signature[:40] + bytes([base.signature[40] ^ 1]) + base.signature[41:]), False, "SIGNATURE_INVALID", True, single_verifier_required=True),
        Witness("reverse-signature", replace(base, signature=base.signature[::-1]), False, "OFF_CURVE_POINT", True),
        Witness("all-zero-key", replace(base, binding=replace(base.binding, verification_key=bytes(32))), False, "PUBLIC_KEY_NOT_PRIME_ORDER", True),
        Witness("identity-key", replace(base, binding=replace(base.binding, verification_key=b"\x01" + bytes(31))), False, "PUBLIC_KEY_NOT_PRIME_ORDER", True),
        Witness("noncanonical-key", replace(base, binding=replace(base.binding, verification_key=zip_key), signature=zip_signature), False, "NON_CANONICAL_POINT", True),
        Witness("off-curve-key", replace(base, binding=replace(base.binding, verification_key=bytes.fromhex("02" * 32))), False, "OFF_CURVE_POINT", True),
        Witness("mixed-order-key", replace(base, binding=replace(base.binding, verification_key=mixed_key), signature=mixed_signature), False, "PUBLIC_KEY_NOT_PRIME_ORDER", True),
        Witness("mixed-order-key-2", replace(base, transcript=TRANSCRIPT + b"-2", binding=replace(base.binding, verification_key=mixed_key_2), signature=mixed_signature_2), False, "PUBLIC_KEY_NOT_PRIME_ORDER", True),
        Witness("mixed-order-cofactorless-valid", replace(base, transcript=TRANSCRIPT + b"-cofactorless-valid", binding=replace(base.binding, verification_key=mixed_valid_key), signature=mixed_valid_signature), False, "PUBLIC_KEY_NOT_PRIME_ORDER", True),
        Witness("small-order-r", replace(base, binding=replace(base.binding, verification_key=small_r_key), signature=small_r_signature), False, "R_NOT_PRIME_ORDER", True),
        Witness("event-suite-override", replace(base, event_suite_override=2), True, "ACCEPTED"),
        Witness("event-key-override", replace(base, event_key_override=key_b), True, "ACCEPTED"),
        Witness("grant-carrying-override", replace(base, grant_suite_id=2, grant_verification_key=key_b), True, "ACCEPTED"),
        Witness("transport-substitution", replace(base, signature=changed_signature, transport_valid=True), False, "SIGNATURE_INVALID", single_verifier_required=True),
        Witness("session-substitution", replace(base, signature=changed_signature, session_valid=True), False, "SIGNATURE_INVALID", single_verifier_required=True),
        Witness("same-key-distinct-credential", replace(base, binding=replace(base.binding, credential_identifier=CREDENTIAL_B), credential_identifier=CREDENTIAL_B, transcript=TRANSCRIPT_PREFIX + CREDENTIAL_B), False, "SIGNATURE_INVALID", single_verifier_required=True),
        Witness(
            "same-key-distinct-credential-positive",
            replace(
                base,
                binding=replace(base.binding, credential_identifier=CREDENTIAL_B),
                credential_identifier=CREDENTIAL_B,
                transcript=same_key_transcript,
                signature=same_key_signature,
            ),
            True,
            "ACCEPTED",
        ),
    )


REQUIRED_MUTANTS = frozenset(
    {
        "M_ACCEPT_UNKNOWN_SUITE",
        "M_TRUST_EVENT_SUITE",
        "M_TRUST_EVENT_KEY",
        "M_TRUST_GRANT_FIELDS",
        "M_RETRY_FALLBACK",
        "M_REMOVE_KEY_LENGTH",
        "M_REMOVE_SIGNATURE_LENGTH",
        "M_REMOVE_SCALAR_GUARD",
        "M_LIBRARY_DEFAULT_ZIP215",
        "M_REMOVE_PRIME_ORDER_GUARD",
        "M_VERIFY_EVENT_REFERENCE",
        "M_BYPASS_CONTEXT",
        "M_BYPASS_CREDENTIAL_ID",
        "M_BYPASS_SEQUENCE",
        "M_BYPASS_REVOCATION",
        "M_TRUST_TRANSPORT",
        "M_TRUST_SESSION",
        "M_AP_BEFORE_VERIFY",
        "M_TREAT_VERIFY_AS_AUTHORIZATION",
        "M_ACCEPT_MISSING_BINDING",
        "M_REUSE_SUITE_ID_SEMANTICS",
        "M_STATUS_WITHOUT_EVIDENCE",
        "M_C03_DEPENDENCY_DRIFT",
        "M_ALLOWLIST_GUARD",
        "M_PER_VECTOR_SPECIAL_CASE",
        "M_BATCH_VERIFIER",
    }
)


DECLARED_DETECTORS: dict[str, tuple[str, ...]] = {
    "M_ACCEPT_MISSING_BINDING": ("missing-binding",),
    "M_ACCEPT_UNKNOWN_SUITE": ("max-suite", "unknown-suite", "zero-suite"),
    "M_ALLOWLIST_GUARD": (
        "all-zero-key", "bitflip-r", "identity-key",
        "mixed-order-cofactorless-valid", "mixed-order-key", "mixed-order-key-2",
        "noncanonical-key", "noncanonical-r", "novel-positive", "off-curve-key",
        "reverse-signature", "scalar-equals-l", "scalar-greater-l",
        "scalar-plus-l", "small-order-r",
    ),
    "M_AP_BEFORE_VERIFY": (
        "all-zero-key", "altered-transcript", "ap-denied", "bitflip-r",
        "bitflip-s", "extended-key", "extended-signature", "identity-key",
        "max-suite", "missing-binding", "mixed-order-cofactorless-valid",
        "mixed-order-key", "mixed-order-key-2", "noncanonical-key",
        "noncanonical-r", "off-curve-key", "other-key", "other-signature",
        "oversized-declared-key", "oversized-declared-signature",
        "recovered-predecessor", "reverse-signature", "revoked",
        "rotated-predecessor", "same-key-distinct-credential", "scalar-equals-l",
        "scalar-greater-l", "scalar-plus-l", "session-substitution",
        "small-order-r", "transport-substitution", "truncated-key",
        "truncated-signature", "unknown-suite", "wrong-context",
        "wrong-credential", "wrong-sequence", "zero-length-key",
        "zero-length-signature", "zero-suite",
    ),
    "M_BATCH_VERIFIER": (
        "altered-transcript", "ap-denied", "bitflip-s", "empty-transcript",
        "event-key-override", "event-suite-override", "grant-carrying-override",
        "historical-revoked", "historical-rotated", "max-representative-transcript",
        "novel-positive", "one-octet-transcript", "other-key", "other-signature",
        "positive", "recovery-successor", "rotation-successor",
        "same-key-distinct-credential", "same-key-distinct-credential-positive",
        "session-substitution", "transport-substitution",
    ),
    "M_BYPASS_CONTEXT": ("wrong-context",),
    "M_BYPASS_CREDENTIAL_ID": ("wrong-credential",),
    "M_BYPASS_REVOCATION": (
        "recovered-predecessor", "revoked", "rotated-predecessor",
    ),
    "M_BYPASS_SEQUENCE": ("wrong-sequence",),
    "M_C03_DEPENDENCY_DRIFT": ("c03-dependency-set-fixed",),
    "M_LIBRARY_DEFAULT_ZIP215": (
        "all-zero-key", "bitflip-r", "identity-key",
        "mixed-order-cofactorless-valid", "mixed-order-key", "mixed-order-key-2",
        "noncanonical-key", "noncanonical-r", "off-curve-key",
        "reverse-signature", "scalar-equals-l", "scalar-greater-l",
        "scalar-plus-l", "small-order-r",
    ),
    "M_PER_VECTOR_SPECIAL_CASE": ("mixed-order-key-2",),
    "M_REMOVE_KEY_LENGTH": (
        "extended-key", "oversized-declared-key", "truncated-key", "zero-length-key",
    ),
    "M_REMOVE_PRIME_ORDER_GUARD": (
        "all-zero-key", "bitflip-r", "identity-key",
        "mixed-order-cofactorless-valid", "mixed-order-key", "mixed-order-key-2",
        "noncanonical-key", "noncanonical-r", "off-curve-key",
        "reverse-signature", "scalar-equals-l", "scalar-greater-l",
        "scalar-plus-l", "small-order-r",
    ),
    "M_REMOVE_SCALAR_GUARD": (
        "scalar-equals-l", "scalar-greater-l", "scalar-plus-l",
    ),
    "M_REMOVE_SIGNATURE_LENGTH": (
        "extended-signature", "oversized-declared-signature",
        "truncated-signature", "zero-length-signature",
    ),
    "M_RETRY_FALLBACK": ("max-suite", "unknown-suite", "zero-suite"),
    "M_REUSE_SUITE_ID_SEMANTICS": (
        "all-zero-key", "bitflip-r", "identity-key",
        "mixed-order-cofactorless-valid", "mixed-order-key", "mixed-order-key-2",
        "noncanonical-key", "noncanonical-r", "off-curve-key",
        "reverse-signature", "scalar-equals-l", "scalar-greater-l",
        "scalar-plus-l", "small-order-r",
    ),
    "M_STATUS_WITHOUT_EVIDENCE": ("decided-requires-evidence",),
    "M_TREAT_VERIFY_AS_AUTHORIZATION": ("ap-denied",),
    "M_TRUST_EVENT_KEY": ("event-key-override",),
    "M_TRUST_EVENT_SUITE": ("event-suite-override",),
    "M_TRUST_GRANT_FIELDS": ("grant-carrying-override",),
    "M_TRUST_SESSION": ("session-substitution",),
    "M_TRUST_TRANSPORT": ("transport-substitution",),
    "M_VERIFY_EVENT_REFERENCE": (
        "ap-denied", "empty-transcript", "event-key-override",
        "event-suite-override", "grant-carrying-override", "historical-revoked",
        "historical-rotated", "max-representative-transcript", "novel-positive",
        "one-octet-transcript", "positive", "recovery-successor",
        "rotation-successor", "same-key-distinct-credential-positive",
    ),
}


def execute_suite(mutation: Mutation = Mutation()) -> tuple[dict[str, object], ...]:
    results = []
    witnesses = required_witnesses()
    if mutation.identifier == "M_ALLOWLIST_GUARD":
        allowlisted = frozenset(
            event_fingerprint(item.event, item.event.binding.verification_key)
            for item in witnesses
            if item.identifier != "novel-positive" and item.event.binding is not None
        )
        mutation = replace(mutation, allowlist_fingerprints=allowlisted)
    elif mutation.identifier == "M_PER_VECTOR_SPECIAL_CASE":
        target = next(item for item in witnesses if item.identifier == "mixed-order-key-2")
        mutation = replace(
            mutation,
            special_case_fingerprint=event_fingerprint(
                target.event, target.event.binding.verification_key
            ),
        )
    for witness in witnesses:
        actual = verify_event(witness.event, mutation)
        passed = (
            actual.accepted == witness.expected
            and actual.code == witness.expected_code
        )
        if witness.guard_must_not_run:
            passed = passed and not any(
                branch.startswith("guard:") for branch in actual.executed_branches
            )
        if witness.expected or witness.single_verifier_required:
            passed = (
                passed
                and actual.verifier_invocations == 1
                and "verifier:invoked" in actual.executed_branches
                and "mutant:batch-verifier" not in actual.executed_branches
            )
        if mutation.identifier == "M_AP_BEFORE_VERIFY" and not witness.expected:
            passed = passed and not actual.ap_exposed
        results.append(
            {
                "id": witness.identifier,
                "passed": passed,
                "expected_accept": witness.expected,
                "expected_code": witness.expected_code,
                "actual_accept": actual.accepted,
                "actual_code": actual.code,
                "verifier_invocations": actual.verifier_invocations,
                "ap_exposed": actual.ap_exposed,
                "executed_branches": list(actual.executed_branches),
            }
        )
    return tuple(results)
