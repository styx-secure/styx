from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest


O06C = Path(__file__).resolve().parents[1]
if str(O06C) not in sys.path:
    sys.path.insert(0, str(O06C))

from integrated_model import (
    BindingResolution,
    BindingStore,
    CredentialBinding,
    ProjectionState,
    SignedEventCandidate,
    envelope_boundary_cases,
    envelope_dispositions,
    envelope_handoffs,
    evaluate_envelope_handoff,
    evaluate_candidate,
    frozen_projection_identity,
)
from protocol_model import (
    CONTENT_NONE,
    ROLE_ORDINARY,
    ContentDescriptor,
    EventAssignment,
    encode_event_transcript,
)
from o14.ed25519_reference import sign_from_seed


def event(*, credential: bytes = b"c" * 32, sequence: int = 0) -> EventAssignment:
    return EventAssignment(
        application_profile_id=1,
        application_profile_version=1,
        context_identifier=b"x" * 32,
        event_role=ROLE_ORDINARY,
        event_type_id=1,
        schema_id=1,
        schema_version=1,
        transition_block=b"ap",
        credential_identifier=credential,
        author_sequence=sequence,
        direct_predecessor=None if sequence == 0 else b"p" * 32,
        causal_parents=(),
        genesis_reference=b"g" * 32,
        content=ContentDescriptor(CONTENT_NONE, 0),
    )


def signed_fixture(*, authority_state: str = "ACTIVE"):
    assignment = event()
    transcript = encode_event_transcript(assignment)
    key, signature = sign_from_seed(bytes(range(32)), transcript)
    binding = CredentialBinding(
        assignment.context_identifier,
        assignment.credential_identifier,
        assignment.author_sequence,
        1,
        key,
        authority_state,
    )
    candidate = SignedEventCandidate(assignment, signature, len(transcript))
    return candidate, binding


class IntegratedModelTest(unittest.TestCase):
    def test_positive_path_applies_after_one_verifier(self):
        candidate, binding = signed_fixture()
        result = evaluate_candidate(candidate, BindingStore.from_bindings(binding))
        self.assertEqual(result.primary, "APPLIED")
        self.assertEqual(result.remote, "APPLIED")
        self.assertEqual(result.verifier_invocations, 1)
        self.assertTrue(result.ap_exposed)
        self.assertEqual(result.work["ap_exposures"], 1)

    def test_k_rejection_never_reaches_ap(self):
        candidate, binding = signed_fixture()
        candidate = replace(candidate, signature=candidate.signature[:-1])
        result = evaluate_candidate(candidate, BindingStore.from_bindings(binding))
        self.assertEqual(result.primary, "LENGTH_MISMATCH")
        self.assertEqual(result.remote, "OPAQUE_REMOTE_FAILURE")
        self.assertEqual(result.verifier_invocations, 0)
        self.assertFalse(result.ap_exposed)

    def test_structural_precedence_beats_other_k_failures(self):
        candidate, binding = signed_fixture()
        candidate = replace(
            candidate,
            supplied_transcript=b"not-the-regenerated-transcript",
            signature=candidate.signature[:-1],
        )
        result = evaluate_candidate(candidate, BindingStore.from_bindings(binding))
        self.assertEqual(result.primary, "STRUCTURAL_REJECTION")
        self.assertFalse(result.ap_exposed)

    def test_missing_and_incomplete_binding_are_distinct(self):
        candidate, _ = signed_fixture()
        missing = evaluate_candidate(candidate, BindingStore({}))
        self.assertEqual(missing.primary, "UNRESOLVABLE_CREDENTIAL")
        key = (
            candidate.event.context_identifier,
            candidate.event.credential_identifier,
            candidate.event.author_sequence,
        )
        incomplete = evaluate_candidate(
            candidate, BindingStore({key: BindingResolution((), authenticated=False)})
        )
        self.assertEqual(incomplete.primary, "UNRESOLVED_CREDENTIAL_BINDING")

    def test_inactive_binding_completes_k_before_event_authority(self):
        candidate, binding = signed_fixture(authority_state="REVOKED")
        valid = evaluate_candidate(
            candidate,
            BindingStore.from_bindings(binding),
            ProjectionState(historical_evidence=True),
        )
        self.assertEqual(valid.primary, "POST_REVOCATION")
        self.assertEqual(valid.verifier_invocations, 1)
        self.assertTrue(valid.ap_exposed)
        invalid = evaluate_candidate(
            replace(candidate, signature=bytes(64)),
            BindingStore.from_bindings(binding),
            ProjectionState(historical_evidence=True),
        )
        self.assertEqual(invalid.primary, "INVALID")
        self.assertEqual(invalid.verifier_invocations, 0)
        self.assertFalse(invalid.ap_exposed)

    def test_candidate_cannot_select_historical_evidence(self):
        candidate, binding = signed_fixture(authority_state="REVOKED")
        result = evaluate_candidate(
            replace(candidate, candidate_historical_evidence=True),
            BindingStore.from_bindings(binding),
        )
        self.assertEqual(result.primary, "STRUCTURAL_REJECTION")
        self.assertFalse(result.ap_exposed)

    def test_only_authenticated_genesis_or_grant_provenance_reaches_verifier(self):
        candidate, binding = signed_fixture()
        for provenance in ("O07_GENESIS", "C02J_GRANT"):
            result = evaluate_candidate(
                candidate,
                BindingStore.from_bindings(replace(binding, provenance=provenance)),
            )
            self.assertEqual(result.primary, "APPLIED")
            self.assertEqual(result.verifier_invocations, 1)
        rejected = evaluate_candidate(
            candidate,
            BindingStore.from_bindings(
                replace(binding, provenance="UNAUTHENTICATED_EVENT_FIELD")
            ),
        )
        self.assertEqual(rejected.primary, "UNRESOLVED_CREDENTIAL_BINDING")
        self.assertEqual(rejected.verifier_invocations, 0)
        self.assertFalse(rejected.ap_exposed)

    def test_declared_key_and_signature_lengths_cannot_lie(self):
        candidate, binding = signed_fixture()
        store = BindingStore.from_bindings(binding)
        key_lie = evaluate_candidate(
            replace(candidate, declared_key_octets=2**32 - 1), store
        )
        signature_lie = evaluate_candidate(
            replace(candidate, declared_signature_octets=2**32 - 1), store
        )
        for result in (key_lie, signature_lie):
            self.assertEqual(result.primary, "LENGTH_MISMATCH")
            self.assertEqual(result.verifier_invocations, 0)
            self.assertFalse(result.ap_exposed)

    def test_duplicate_and_ap_denial_use_frozen_o10(self):
        candidate, binding = signed_fixture()
        store = BindingStore.from_bindings(binding)
        duplicate = evaluate_candidate(candidate, store, ProjectionState(duplicate=True))
        denied = evaluate_candidate(candidate, store, ProjectionState(authorized=False))
        self.assertEqual(duplicate.primary, "DUPLICATE")
        self.assertEqual(denied.primary, "AUTHENTIC_BUT_UNAUTHORIZED")
        self.assertEqual(duplicate.verifier_invocations, 1)
        self.assertEqual(denied.verifier_invocations, 1)

    def test_envelope_is_exhaustive(self):
        dispositions = envelope_dispositions()
        handoffs = envelope_handoffs()
        self.assertEqual(len(dispositions), 69)
        self.assertEqual(sum(row["disposition"] == "CONSUMED" for row in dispositions), 53)
        self.assertEqual(sum(row["disposition"] == "NOT_CONSUMED" for row in dispositions), 16)
        self.assertEqual(len(handoffs), 66)
        self.assertEqual(len({(row["dimension"], row["stage"]) for row in handoffs}), 66)
        boundaries = envelope_boundary_cases()
        self.assertGreater(len(boundaries), 100)
        self.assertTrue(any(not row["accepted"] for row in boundaries))
        for row in handoffs:
            self.assertEqual(
                evaluate_envelope_handoff(row["dimension"], row["stage"]),
                row["primary"] if row["dimension"] not in {"SIGNATURE_OCTETS", "VERIFICATION_KEY_OCTETS"} else "LENGTH_MISMATCH",
            )

    def test_projection_identity_is_stable_shape(self):
        self.assertEqual(len(frozen_projection_identity()), 64)


if __name__ == "__main__":
    unittest.main()
