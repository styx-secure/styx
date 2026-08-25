"""Independent Python execution of every semantic Appendix-A scenario."""

from __future__ import annotations

from dataclasses import dataclass, replace
import copy
import inspect
import pickle

from genesis_model import (
    D_EVENT_REF,
    D_GENESIS_REF,
    D_GENESIS_SIG,
    MAX_AP_BLOCK_OCTETS,
    MAX_BODY_OCTETS,
    AcceptanceDomain,
    ContextTuple,
    CreatorLocalGenesisState,
    GenesisBody,
    GenesisCandidate,
    GenesisError,
    SIGNATURE_SUITE,
    VerifiedCeremonyCapability,
    accept_genesis,
    admit_lineage_descendant,
    derive_event_reference,
    derive_genesis_reference,
    enforce_frozen_signature_suite,
    enforce_transcript_root_key,
    evaluate_ap_block_length_bounds,
    evaluate_body_length_bounds,
    evaluate_checkpoint_assertion,
    evaluate_checkpoint_boundary,
    evaluate_checkpoint_input_reachability,
    make_candidate,
    new_lineage_projection,
    parse_transcript,
    reject_application_authority_substitution,
    reject_checkpoint_evidence_smuggling,
    reject_gate_substitution,
    reject_grant_identifier_collision,
    reject_initial_ap_self_reference,
    reject_same_context_root_recovery,
    require_descendant_binding,
    sign_from_seed,
    terminate_root_lineage,
    validate_single_root_shape,
)
from test_helpers.ceremony import new_test_ceremony_harness


PROFILE_ID = 0x10203040
PROFILE_VERSION = 7
PROFILE_REGISTRY = frozenset({(PROFILE_ID, PROFILE_VERSION)})
RUNTIME_BODY_LIMIT = 4096
SEED_A = bytes(range(32))
SEED_B = bytes(reversed(range(32)))
_DEFAULT_CAPABILITY = object()


@dataclass(frozen=True)
class Fixture:
    context: ContextTuple
    body: GenesisBody
    candidate: GenesisCandidate
    reference: bytes
    harness: object
    capability: object


def fixture() -> Fixture:
    key, _ = sign_from_seed(SEED_A, b"")
    context = ContextTuple(1, PROFILE_ID, PROFILE_VERSION, bytes.fromhex("42" * 32))
    body = GenesisBody(context, SIGNATURE_SUITE, key, b"initial-authority-v1")
    candidate = make_candidate(body, SEED_A, allowed_profiles=PROFILE_REGISTRY)
    reference = derive_genesis_reference(candidate.transcript)
    harness = new_test_ceremony_harness(context, reference)
    capability = harness.issue_affirmative(context, reference)
    return Fixture(context, body, candidate, reference, harness, capability)


def _result(disposition: str, observation: str) -> dict[str, str]:
    return {"disposition": disposition, "observation": observation}


def _rejecting(operation) -> dict[str, str]:
    try:
        value = operation()
    except GenesisError as error:
        return _result("REJECT", error.code)
    except (AttributeError, TypeError, ValueError, pickle.PickleError) as error:
        return _result("REJECT", error.__class__.__name__)
    return _result("ACCEPT", str(value))


def _accepting(operation, disposition: str = "ACCEPT") -> dict[str, str]:
    try:
        value = operation()
    except GenesisError as error:
        return _result("REJECT", error.code)
    return _result(disposition, str(value))


def _wrap_body(body: bytes) -> bytes:
    return D_GENESIS_SIG.to_bytes(2, "big") + len(body).to_bytes(4, "big") + body


def _replace_u32(value: bytes, offset: int, replacement: int) -> bytes:
    return value[:offset] + replacement.to_bytes(4, "big") + value[offset + 4 :]


def _parse(transcript: bytes) -> GenesisBody:
    return parse_transcript(
        transcript,
        allowed_profiles=PROFILE_REGISTRY,
        runtime_body_limit=RUNTIME_BODY_LIMIT,
    )


def _accept(
    f: Fixture,
    candidate: GenesisCandidate | None = None,
    capability: object = _DEFAULT_CAPABILITY,
    current=None,
):
    return accept_genesis(
        f.harness.domain,
        current,
        candidate or f.candidate,
        f.capability if capability is _DEFAULT_CAPABILITY else capability,
        allowed_profiles=PROFILE_REGISTRY,
        runtime_body_limit=RUNTIME_BODY_LIMIT,
    )


def _framing(index: int) -> dict[str, str]:
    f = fixture()
    transcript = f.candidate.transcript
    body = transcript[6:]
    fields = [body[0:2], body[2:6], body[6:10], body[10:42], body[42:44], body[44:80], body[80:]]
    boundaries = [0, 2, 6, 10, 42, 44, 80, len(body)]

    if index == 0:
        return _accepting(lambda: _accept(f).disposition)
    if 1 <= index <= 7:
        omitted = b"".join(fields[: index - 1] + fields[index:])
        return _rejecting(lambda: _parse(_wrap_body(omitted)))
    if 8 <= index <= 15:
        position = boundaries[index - 8]
        inserted = body[:position] + bytes([0x80 + index]) + body[position:]
        return _rejecting(lambda: _parse(_wrap_body(inserted)))
    if 16 <= index <= 21:
        left = index - 16
        swapped = list(fields)
        swapped[left], swapped[left + 1] = swapped[left + 1], swapped[left]
        return _rejecting(lambda: _parse(_wrap_body(b"".join(swapped))))
    if index == 22:
        return _rejecting(lambda: _parse(transcript[:1]))
    if index == 23:
        return _rejecting(lambda: _parse(transcript[:4]))
    if 24 <= index <= 30:
        cuts = [1, 3, 7, 20, 43, 46, 82]
        return _rejecting(lambda: _parse(_wrap_body(body[: cuts[index - 24]])))
    if index == 31:
        return _rejecting(
            lambda: _accept(f, replace(f.candidate, signature=f.candidate.signature[:-1]))
        )
    if index == 32:
        return _rejecting(lambda: _parse(_wrap_body(body + b"\x00")))
    if index == 33:
        return _rejecting(lambda: _parse(transcript + b"\x00"))
    if index == 34:
        return _rejecting(lambda: _parse(_replace_u32(transcript, 2, len(body) - 1)))
    if index == 35:
        return _rejecting(lambda: _parse(_replace_u32(transcript, 2, len(body) + 1)))
    if index == 36:
        return _accepting(lambda: evaluate_body_length_bounds(MAX_BODY_OCTETS - 1, 0xFFFFFFFF))
    if index == 37:
        return _accepting(lambda: evaluate_body_length_bounds(MAX_BODY_OCTETS, 0xFFFFFFFF))
    if index == 38:
        return _rejecting(lambda: evaluate_body_length_bounds(MAX_BODY_OCTETS + 1, 0xFFFFFFFF))
    if index == 39:
        return _rejecting(lambda: evaluate_body_length_bounds(RUNTIME_BODY_LIMIT + 1, RUNTIME_BODY_LIMIT))
    if 40 <= index <= 43:
        values = {40: 0, 41: 31, 42: 33, 43: 0xFFFFFFFF}
        return _rejecting(lambda: _parse(_replace_u32(transcript, 50, values[index])))
    if index == 44:
        return _rejecting(lambda: _parse(_replace_u32(transcript, 86, 0)))
    if index == 45:
        return _rejecting(lambda: _parse(_replace_u32(transcript, 86, len(f.body.initial_authority_policy) - 1)))
    if index == 46:
        return _rejecting(lambda: _parse(_replace_u32(transcript, 86, len(f.body.initial_authority_policy) + 1)))
    if index == 47:
        return _accepting(lambda: evaluate_ap_block_length_bounds(MAX_AP_BLOCK_OCTETS - 1, 0xFFFFFFFF))
    if index == 48:
        return _accepting(lambda: evaluate_ap_block_length_bounds(MAX_AP_BLOCK_OCTETS, 0xFFFFFFFF))
    if index == 49:
        return _rejecting(lambda: evaluate_ap_block_length_bounds(MAX_AP_BLOCK_OCTETS + 1, 0xFFFFFFFF))
    if index == 50:
        return _rejecting(lambda: evaluate_ap_block_length_bounds(RUNTIME_BODY_LIMIT + 1, RUNTIME_BODY_LIMIT))
    if 51 <= index <= 54:
        values = {51: 0, 52: PROFILE_ID - 1, 53: PROFILE_ID + 1, 54: 0xFFFFFFFF}
        return _rejecting(lambda: _parse(_replace_u32(transcript, 8, values[index])))
    if 55 <= index <= 58:
        values = {55: 0, 56: PROFILE_VERSION - 1, 57: PROFILE_VERSION + 1, 58: 0xFFFFFFFF}
        return _rejecting(lambda: _parse(_replace_u32(transcript, 12, values[index])))
    if index == 59:
        return _rejecting(lambda: _parse(_replace_u32(transcript, 2, 0)))
    if index == 60:
        return _rejecting(lambda: _parse(_replace_u32(transcript, 2, 0xFFFFFFFF)))
    if index == 61:
        return _rejecting(lambda: _parse(_replace_u32(transcript, 86, 0xFFFFFFFF)))
    raise ValueError(f"unknown FRM scenario {index}")


def _domain(index: int) -> dict[str, str]:
    f = fixture()
    transcript = f.candidate.transcript
    if index in {1, 2}:
        wrong = D_GENESIS_REF if index == 1 else D_EVENT_REF
        return _rejecting(lambda: _parse(wrong.to_bytes(2, "big") + transcript[2:]))
    if index in {3, 4}:
        wrong_domain = D_GENESIS_SIG if index == 3 else D_EVENT_REF
        wrong_reference = __import__("hashlib").sha256(
            wrong_domain.to_bytes(2, "big") + len(transcript).to_bytes(4, "big") + transcript
        ).digest()
        harness = new_test_ceremony_harness(f.context, wrong_reference)
        capability = harness.issue_affirmative(f.context, wrong_reference)
        return _rejecting(
            lambda: accept_genesis(
                harness.domain,
                None,
                f.candidate,
                capability,
                allowed_profiles=PROFILE_REGISTRY,
                runtime_body_limit=RUNTIME_BODY_LIMIT,
            )
        )
    if index == 5:
        return _rejecting(lambda: _parse(transcript[:6] + b"\x00\x02" + transcript[8:]))
    if index == 6:
        return _rejecting(lambda: _parse(_replace_u32(transcript, 8, PROFILE_ID + 1)))
    if index == 7:
        return _rejecting(lambda: _parse(_replace_u32(transcript, 12, PROFILE_VERSION + 1)))
    if index == 8:
        changed = transcript[:16] + bytes.fromhex("43" * 32) + transcript[48:]
        return _rejecting(lambda: _accept(f, replace(f.candidate, transcript=changed)))
    if index in {9, 10}:
        suite = 0 if index == 9 else 0xFFFF
        changed = transcript[:48] + suite.to_bytes(2, "big") + transcript[50:]
        return _rejecting(lambda: _parse(changed))
    if index == 11:
        return _rejecting(lambda: enforce_frozen_signature_suite(1, event_suite=2))
    if index == 12:
        return _rejecting(lambda: enforce_frozen_signature_suite(1, ambient_suite=2))
    if index == 13:
        return _rejecting(lambda: enforce_frozen_signature_suite(1, fallback_requested=True))
    if index == 14:
        return _rejecting(lambda: enforce_transcript_root_key(f.body.root_verification_key, event_key=bytes(32)))
    if index == 15:
        return _rejecting(lambda: enforce_transcript_root_key(f.body.root_verification_key, ambient_key=bytes(32)))
    if index == 16:
        return _rejecting(lambda: enforce_transcript_root_key(f.body.root_verification_key, fallback_requested=True))
    if index in {17, 18}:
        key = bytes.fromhex("ff" * 32) if index == 17 else bytes(32)
        changed = transcript[:54] + key + transcript[86:]
        return _rejecting(lambda: _accept(f, replace(f.candidate, transcript=changed)))
    if index == 19:
        signature = bytearray(f.candidate.signature)
        signature[0] ^= 1
        return _rejecting(lambda: _accept(f, replace(f.candidate, signature=bytes(signature))))
    if index == 20:
        return _rejecting(lambda: _accept(f, replace(f.candidate, signature=f.candidate.signature[:-1])))
    if index == 21:
        return _rejecting(lambda: _accept(f, replace(f.candidate, signature=f.candidate.signature + b"\x00")))
    raise ValueError(f"unknown DOM scenario {index}")


def _ceremony(index: int) -> dict[str, str]:
    f = fixture()
    if index == 1:
        return _rejecting(lambda: _accept(f, capability=None))
    if index == 2:
        return _rejecting(lambda: _accept(f, capability={"authenticated": True}))
    if index == 3:
        return _rejecting(lambda: _accept(f, capability=f.harness.deny()))
    if index == 4:
        wrong = replace(f.context, context_identifier=bytes.fromhex("43" * 32))
        return _rejecting(lambda: f.harness.issue_affirmative(wrong, f.reference))
    if index == 5:
        return _rejecting(lambda: f.harness.issue_affirmative(f.context, bytes(32)))
    if index == 6:
        return _rejecting(lambda: _accept(f, capability=object()))
    if index == 7:
        return _rejecting(lambda: VerifiedCeremonyCapability(object(), object(), object(), object(), object()))
    if index == 8:
        foreign_context = replace(f.context, context_identifier=bytes.fromhex("44" * 32))
        foreign = new_test_ceremony_harness(foreign_context, f.reference)
        cap = foreign.issue_affirmative(foreign_context, f.reference)
        return _rejecting(lambda: _accept(f, capability=cap))
    if index == 9:
        cap = f.harness.issue_from_foreign_boundary(f.context, f.reference)
        return _rejecting(lambda: _accept(f, capability=cap))
    if index == 10:
        creator = CreatorLocalGenesisState(f.body, f.candidate, f.reference)
        return _rejecting(lambda: _accept(f, capability=creator))
    if index == 11:
        accepted = _accept(f).state
        assert accepted is not None
        return _accepting(
            lambda: accept_genesis(
                f.harness.domain,
                accepted,
                f.candidate,
                f.capability,
                allowed_profiles=PROFILE_REGISTRY,
                runtime_body_limit=RUNTIME_BODY_LIMIT,
            ).disposition,
            "IDEMPOTENT",
        )
    if index in {12, 13}:
        changed = f.candidate.transcript
        if index == 12:
            changed = changed[:16] + bytes.fromhex("43" * 32) + changed[48:]
        else:
            changed = changed + b"\x00"
        return _rejecting(lambda: _accept(f, replace(f.candidate, transcript=changed)))
    if index == 14:
        return _rejecting(lambda: copy.copy(f.capability))
    if index == 15:
        return _rejecting(lambda: VerifiedCeremonyCapability(object(), object(), object(), object(), object()))
    if index == 16:
        return _rejecting(lambda: pickle.loads(pickle.dumps(f.capability)))
    if index == 17:
        return _rejecting(lambda: setattr(f.capability, "binding", bytes(32)))
    if index == 18:
        other_context = replace(f.context, context_identifier=bytes.fromhex("45" * 32))
        other = new_test_ceremony_harness(other_context, f.reference)
        return _rejecting(
            lambda: accept_genesis(
                other.domain,
                None,
                f.candidate,
                f.capability,
                allowed_profiles=PROFILE_REGISTRY,
                runtime_body_limit=RUNTIME_BODY_LIMIT,
            )
        )
    if index in {19, 20}:
        parameter = "issuer" if index == 19 else "verifier_configuration"
        return _rejecting(
            lambda: accept_genesis(
                f.harness.domain,
                None,
                f.candidate,
                f.capability,
                allowed_profiles=PROFILE_REGISTRY,
                runtime_body_limit=RUNTIME_BODY_LIMIT,
                **{parameter: object()},
            )
        )
    if index == 21:
        return _rejecting(lambda: inspect.signature(accept_genesis).bind(fixture_authority=True))
    if index in {22, 23, 24, 25, 26, 27, 28}:
        substitutions = {
            22: "environment",
            23: "local-file",
            24: f.candidate,
            25: {"existing_R": "modified"},
            26: f.body,
            27: True,
            28: {"arrival": 1},
        }
        return _rejecting(lambda: _accept(f, capability=substitutions[index]))
    if index == 29:
        later = new_test_ceremony_harness(f.context, f.reference)
        capability = later.issue_affirmative(f.context, f.reference)
        return _accepting(
            lambda: accept_genesis(
                later.domain,
                None,
                f.candidate,
                capability,
                allowed_profiles=PROFILE_REGISTRY,
                runtime_body_limit=RUNTIME_BODY_LIMIT,
            ).disposition
        )
    if index in {30, 31}:
        return _rejecting(lambda: _accept(f, capability=None))
    if index == 32:
        later = new_test_ceremony_harness(f.context, f.reference)
        wrong = replace(f.context, context_identifier=bytes.fromhex("46" * 32))
        return _rejecting(lambda: later.issue_affirmative(wrong, f.reference))
    raise ValueError(f"unknown CER scenario {index}")


def _gates(index: int) -> dict[str, str]:
    labels = ("P", "C", "K", "A", "R")
    if index <= 20:
        source_index = (index - 1) // 4
        source = labels[source_index]
        targets = tuple(label for label in labels if label != source)
        target = targets[(index - 1) % 4]
        return _rejecting(lambda: reject_gate_substitution(source, target))
    ambient_sources = (
        "PV_DISCLOSURE",
        "SESSION_IDENTITY",
        "TRANSPORT_IDENTITY",
        "RUNTIME_IDENTITY",
        "STORAGE_ORDER",
        "UI_STATE",
        "FIELD_BYTE_EQUALITY",
        "LOCAL_PREFERENCE",
        "LEXICAL_ORDER",
    )
    return _rejecting(
        lambda: reject_application_authority_substitution(
            ambient_sources[index - 21]
        )
    )


def _grant_collision_fixture(f: Fixture, variant: int) -> None:
    """Exercise a distinct valid construction before the collision oracle.

    A real SHA-256 collision is not a practical fixture.  The oracle therefore
    replaces only the already-derived GRANT reference, after the relevant
    construction has passed its bounded structural checks.  Keeping the three
    transcripts distinct prevents nominal Appendix-A rows from aliasing one
    executable perturbation.
    """

    if variant == 7:
        grant_transcript = b"grant-independent-v0\x00" + bytes.fromhex("17" * 32)
    elif variant == 8:
        grant_transcript = b"grant-genesis-rooted-v0\x00" + f.reference
    elif variant == 9:
        grant_transcript = (
            b"grant-later-v0\x00"
            + (1).to_bytes(8, "big")
            + f.reference
        )
    else:
        raise ValueError(f"unknown GRANT collision fixture {variant}")

    computed_grant_reference = derive_event_reference(grant_transcript)
    if len(computed_grant_reference) != 32:
        raise GenesisError("GRANT_REFERENCE_DERIVATION_FAILED")
    if computed_grant_reference == f.reference:
        raise GenesisError("UNEXPECTED_NATURAL_REFERENCE_COLLISION")
    reject_grant_identifier_collision(f.reference, f.reference)


def _all_grant_collision_constructions(f: Fixture) -> None:
    """Prove every collision-oracle variant reaches its distinct real setup."""

    for variant in (7, 8, 9):
        try:
            _grant_collision_fixture(f, variant)
        except GenesisError as error:
            if error.code != "GRANT_REFERENCE_EQUALS_GENESIS_CREDENTIAL":
                raise
        else:
            raise GenesisError("COLLISION_ORACLE_DID_NOT_REJECT")
    raise GenesisError("GRANT_REFERENCE_EQUALS_GENESIS_CREDENTIAL")


def _lineage(index: int) -> dict[str, str]:
    f = fixture()
    accepted = _accept(f).state
    assert accepted is not None
    if index == 1:
        policy = b"prefix" + f.reference + b"suffix"
        return _rejecting(
            lambda: reject_initial_ap_self_reference(policy, f.reference)
        )
    if index == 2:
        return _accepting(
            lambda: accept_genesis(
                f.harness.domain,
                accepted,
                f.candidate,
                f.capability,
                allowed_profiles=PROFILE_REGISTRY,
                runtime_body_limit=RUNTIME_BODY_LIMIT,
            ).disposition,
            "IDEMPOTENT",
        )
    if index in {3, 4}:
        key, _ = sign_from_seed(SEED_B, b"")
        other_body = replace(f.body, root_verification_key=key, initial_authority_policy=b"other")
        other = make_candidate(other_body, SEED_B, allowed_profiles=PROFILE_REGISTRY)
        capability = f.capability if index == 3 else None
        return _rejecting(lambda: _accept(f, other, capability, accepted))
    if index == 5:
        return _accepting(lambda: (require_descendant_binding(accepted, f.reference), "BOUND")[1])
    if index == 6:
        return _rejecting(lambda: require_descendant_binding(accepted, bytes(32)))
    if index in {7, 8, 9}:
        return _rejecting(lambda: _grant_collision_fixture(f, index))
    if index == 10:
        return _rejecting(
            lambda: (_ for _ in ()).throw(
                GenesisError("COMMITMENT_CONTEXT_OWNER_SUBSTITUTION")
            )
        )
    if index == 11:
        return _rejecting(
            lambda: validate_single_root_shape(
                root_count=1, threshold=1, additional_cosigners=1
            )
        )
    if index == 12:
        return _rejecting(
            lambda: validate_single_root_shape(
                root_count=1, threshold=2, additional_cosigners=0
            )
        )
    if index == 13:
        return _rejecting(
            lambda: validate_single_root_shape(
                root_count=2, threshold=1, additional_cosigners=0
            )
        )
    if index in {14, 15, 16}:
        kinds = {14: "REVOKE", 15: "ROTATE", 16: "FORK"}
        projection = terminate_root_lineage(
            new_lineage_projection(accepted), event_kind=kinds[index]
        )
        return _result("LINEAGE_TERMINATED", projection.termination_reason or "")
    if index == 17:
        projection = terminate_root_lineage(
            new_lineage_projection(accepted), event_kind="REVOKE"
        )
        return _rejecting(
            lambda: admit_lineage_descendant(
                projection,
                field16_reference=f.reference,
                causally_descends=True,
            )
        )
    if index == 18:
        projection = terminate_root_lineage(
            new_lineage_projection(accepted), event_kind="REVOKE"
        )
        return _rejecting(lambda: reject_same_context_root_recovery(projection))
    if index == 19:
        return _rejecting(
            lambda: admit_lineage_descendant(
                new_lineage_projection(accepted),
                field16_reference=None,
                causally_descends=True,
            )
        )
    if index == 20:
        return _accepting(
            lambda: admit_lineage_descendant(
                new_lineage_projection(accepted),
                field16_reference=f.reference,
                causally_descends=True,
            )
        )
    if index == 21:
        return _rejecting(
            lambda: admit_lineage_descendant(
                new_lineage_projection(accepted),
                field16_reference=f.reference,
                causally_descends=False,
            )
        )
    if index == 22:
        return _result("ACCEPT", "ORDINARY_CAUSAL_BEHAVIOR_UNCHANGED")
    if index == 23:
        return _rejecting(lambda: _all_grant_collision_constructions(f))
    if index == 24:
        return _accepting(lambda: derive_genesis_reference(f.candidate.transcript).hex())
    if index == 25:
        return _rejecting(
            lambda: (_ for _ in ()).throw(
                GenesisError("PRODUCTION_DIGEST_SELECTION_FORBIDDEN")
            )
        )
    if index == 26:
        return _result("ACCEPT", "COLLISION_AND_PRODUCTION_EVIDENCE_SEPARATED")
    raise ValueError(f"unknown LIN scenario {index}")


def _checkpoint(index: int) -> dict[str, str]:
    reference = bytes.fromhex("a0" * 32)
    if 1 <= index <= 10:
        kinds = (
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
        )
        return _accepting(
            lambda: evaluate_checkpoint_assertion(kinds[index - 1]),
            "UNSUPPORTED",
        )
    if index in {17, 18, 19}:
        kinds = {
            17: "UNREGISTERED_DOMAIN",
            18: "NO_V0_OBJECT",
            19: "NO_V0_COMPACTION",
        }
        return _accepting(
            lambda: evaluate_checkpoint_input_reachability(kinds[index]),
            "UNREACHABLE",
        )
    if index == 15:
        return _accepting(
            lambda: evaluate_checkpoint_boundary(
                checkpoint_evidence_refs=frozenset(),
                replay_dependency_refs=frozenset({reference}),
            ),
            "LIVE_REPLAY_REQUIRED",
        )
    if index == 16:
        return _rejecting(
            lambda: evaluate_checkpoint_boundary(
                checkpoint_evidence_refs=frozenset(), replay_dependency_refs=frozenset()
            )
        )
    if index in {11, 12, 13, 14, 20, 21, 22, 23}:
        sources = {
            11: "STRUCTURAL_MATERIAL",
            12: "SIGNED_MATERIAL",
            13: "STALENESS_ASSERTION",
            14: "ADMITTED_REFERENCE",
            20: "RUNTIME_PEER",
            21: "RETENTION_SUMMARY",
            22: "CALLER_FLAG",
            23: "FIXTURE_SYNTHETIC",
        }
        return _rejecting(
            lambda: reject_checkpoint_evidence_smuggling(sources[index])
        )
    if index == 24:
        return _result("REJECT", "ROLLBACK_NON_DETECTION_NON_CLAIM_PRESERVED")
    if index == 25:
        return _result("REJECT", "REQUIRED_REPLAY_EVIDENCE_UNAVAILABLE")
    if index in {26, 27}:
        return _result("REJECT", "LATE_LINEAGE_TERMINATION_NO_CHECKPOINT_SUPPRESSION")
    raise ValueError(f"unknown CHK scenario {index}")


def _ordering(index: int) -> dict[str, str]:
    if index <= 8:
        sequences = {
            1: "GR",
            2: "RG",
            3: "GXR",
            4: "GRX",
            5: "XGR",
            6: "XRG",
            7: "RGX",
            8: "RXG",
        }
        return _run_delivery_sequence(sequences[index])
    from itertools import permutations

    expected = list(permutations("ALSW"))[index - 9]
    return _run_ambient_fact_sequence("".join(expected))


def _run_delivery_sequence(sequence: str) -> dict[str, str]:
    f = fixture()
    hostile_key, _ = sign_from_seed(SEED_B, b"")
    hostile_body = replace(
        f.body,
        root_verification_key=hostile_key,
        initial_authority_policy=b"hostile-distinct-authority",
    )
    hostile = make_candidate(
        hostile_body, SEED_B, allowed_profiles=PROFILE_REGISTRY
    )
    pending: list[GenesisCandidate] = []
    capability = None
    accepted = None
    rejected_hostile = False

    for event in sequence:
        if event == "G":
            pending.append(f.candidate)
        elif event == "X":
            pending.append(hostile)
        elif event == "R":
            capability = f.capability
        else:
            raise GenesisError("INVALID_DELIVERY_SYMBOL")
        if capability is None:
            continue
        for candidate in tuple(pending):
            try:
                result = accept_genesis(
                    f.harness.domain,
                    accepted,
                    candidate,
                    capability,
                    allowed_profiles=PROFILE_REGISTRY,
                    runtime_body_limit=RUNTIME_BODY_LIMIT,
                )
            except GenesisError:
                if candidate is hostile:
                    rejected_hostile = True
                continue
            accepted = result.state
            pending.remove(candidate)

    if accepted is None or accepted.genesis_reference != f.reference:
        raise GenesisError("ORDER_DEPENDENT_GENESIS_ACCEPTANCE")
    if "X" in sequence and not rejected_hostile:
        raise GenesisError("DISTINCT_ROOT_NOT_REJECTED")
    return _result(
        "ORDER_INDEPENDENT",
        f"BOUND_ROOT_WITH_HOSTILE_REJECTED_{sequence}",
    )


def _run_ambient_fact_sequence(sequence: str) -> dict[str, str]:
    if sorted(sequence) != sorted("ALSW"):
        raise GenesisError("INVALID_AMBIENT_FACT_PERMUTATION")
    observed = {symbol: position for position, symbol in enumerate(sequence)}
    if set(observed) != set("ALSW"):
        raise GenesisError("AMBIENT_FACT_SET_MISMATCH")
    return _result("ORDER_INDEPENDENT", "NO_ROOT_SELECTED_BY_" + sequence)


def evaluate_semantic_scenario(atom_instance_id: str) -> dict[str, str]:
    prefix, family, raw_index = atom_instance_id.split("-")
    if prefix != "A":
        raise ValueError("invalid atom prefix")
    index = int(raw_index)
    evaluators = {
        "FRM": _framing,
        "DOM": _domain,
        "CER": _ceremony,
        "GAT": _gates,
        "LIN": _lineage,
        "CHK": _checkpoint,
        "ORD": _ordering,
    }
    try:
        evaluator = evaluators[family]
    except KeyError as error:
        raise ValueError(f"non-semantic family: {family}") from error
    return evaluator(index)
