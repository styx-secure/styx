from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest


O07_ROOT = Path(__file__).resolve().parents[1]
if str(O07_ROOT) not in sys.path:
    sys.path.insert(0, str(O07_ROOT))

from genesis_model import (
    AcceptanceDomain,
    ContextTuple,
    CreatorLocalGenesisState,
    GenesisBody,
    GenesisCandidate,
    GenesisError,
    SIGNATURE_SUITE,
    accept_genesis,
    create_local_genesis,
    derive_genesis_reference,
    encode_transcript,
    evaluate_ap_block_length_bounds,
    evaluate_body_length_bounds,
    evaluate_checkpoint_boundary,
    make_candidate,
    parse_transcript,
    reject_grant_identifier_collision,
    require_descendant_binding,
)
from test_helpers.ceremony import new_test_ceremony_harness


PROFILE_REGISTRY = frozenset({(0x10203040, 7)})
SEED_A = bytes(range(32))
SEED_B = bytes(reversed(range(32)))
RUNTIME_LIMIT = 4096


class GenesisModelTest(unittest.TestCase):
    def setUp(self) -> None:
        from genesis_model import sign_from_seed

        root_key, _ = sign_from_seed(SEED_A, b"")
        self.context = ContextTuple(1, 0x10203040, 7, bytes.fromhex("42" * 32))
        self.body = GenesisBody(
            self.context,
            SIGNATURE_SUITE,
            root_key,
            b"canonical-profile-owned-initial-authority",
        )
        self.candidate = make_candidate(
            self.body, SEED_A, allowed_profiles=PROFILE_REGISTRY
        )
        self.reference = derive_genesis_reference(self.candidate.transcript)
        self.harness = new_test_ceremony_harness(self.context, self.reference)
        self.capability = self.harness.issue_affirmative(self.context, self.reference)

    def test_round_trip_and_acceptance(self) -> None:
        decoded = parse_transcript(
            self.candidate.transcript,
            allowed_profiles=PROFILE_REGISTRY,
            runtime_body_limit=RUNTIME_LIMIT,
        )
        self.assertEqual(decoded, self.body)
        result = accept_genesis(
            self.harness.domain,
            None,
            self.candidate,
            self.capability,
            allowed_profiles=PROFILE_REGISTRY,
            runtime_body_limit=RUNTIME_LIMIT,
        )
        self.assertTrue(result.changed)
        self.assertEqual(result.disposition, "GENESIS_ACCEPTED")
        duplicate = accept_genesis(
            self.harness.domain,
            result.state,
            self.candidate,
            self.capability,
            allowed_profiles=PROFILE_REGISTRY,
            runtime_body_limit=RUNTIME_LIMIT,
        )
        self.assertFalse(duplicate.changed)
        self.assertIs(duplicate.state, result.state)

    def test_external_ceremony_is_not_substitutable(self) -> None:
        foreign_harness = new_test_ceremony_harness(self.context, self.reference)
        hostile = (
            None,
            object(),
            foreign_harness.issue_affirmative(self.context, self.reference),
        )
        expected = (
            "VERIFIED_CEREMONY_CAPABILITY_REQUIRED",
            "CEREMONY_CAPABILITY_INVALID",
            "FOREIGN_ACCEPTANCE_DOMAIN",
        )
        for capability, code in zip(hostile, expected, strict=True):
            with self.subTest(code=code), self.assertRaisesRegex(GenesisError, code):
                accept_genesis(
                    self.harness.domain,
                    None,
                    self.candidate,
                    capability,
                    allowed_profiles=PROFILE_REGISTRY,
                    runtime_body_limit=RUNTIME_LIMIT,
                )

    def test_malformed_transcripts_fail_closed(self) -> None:
        valid = self.candidate.transcript
        mutants = {
            "GENESIS_DOMAIN_REJECTED": b"\x00\x03" + valid[2:],
            "GENESIS_BODY_LENGTH_MISMATCH": valid[:2] + (len(valid)).to_bytes(4, "big") + valid[6:],
            "TRUNCATED_GENESIS_BODY": valid[:-1],
            "GENESIS_BODY_LENGTH": valid[:2] + (RUNTIME_LIMIT + 1).to_bytes(4, "big") + valid[6:],
        }
        for code, mutant in mutants.items():
            with self.subTest(code=code), self.assertRaises(GenesisError):
                parse_transcript(
                    mutant,
                    allowed_profiles=PROFILE_REGISTRY,
                    runtime_body_limit=RUNTIME_LIMIT,
                )

    def test_normative_u32_bounds_precede_runtime_and_allocation(self) -> None:
        from genesis_model import MAX_AP_BLOCK_OCTETS, MAX_BODY_OCTETS

        large_runtime = 0xFFFFFFFF
        self.assertEqual(
            evaluate_body_length_bounds(MAX_BODY_OCTETS - 1, large_runtime),
            "NORMATIVE_BODY_LENGTH_ACCEPTED",
        )
        self.assertEqual(
            evaluate_body_length_bounds(MAX_BODY_OCTETS, large_runtime),
            "NORMATIVE_BODY_LENGTH_ACCEPTED",
        )
        with self.assertRaisesRegex(GenesisError, "GENESIS_BODY_LENGTH"):
            evaluate_body_length_bounds(MAX_BODY_OCTETS + 1, large_runtime)
        with self.assertRaisesRegex(GenesisError, "GENESIS_BODY_LENGTH"):
            evaluate_body_length_bounds(0xFFFFFFFF, large_runtime)
        self.assertEqual(
            evaluate_ap_block_length_bounds(MAX_AP_BLOCK_OCTETS - 1, large_runtime),
            "NORMATIVE_AP_BLOCK_LENGTH_ACCEPTED",
        )
        self.assertEqual(
            evaluate_ap_block_length_bounds(MAX_AP_BLOCK_OCTETS, large_runtime),
            "NORMATIVE_AP_BLOCK_LENGTH_ACCEPTED",
        )
        with self.assertRaisesRegex(GenesisError, "INITIAL_AUTHORITY_POLICY_LENGTH"):
            evaluate_ap_block_length_bounds(MAX_AP_BLOCK_OCTETS + 1, large_runtime)
        with self.assertRaisesRegex(GenesisError, "INITIAL_AUTHORITY_POLICY_LENGTH"):
            evaluate_ap_block_length_bounds(0xFFFFFFFF, large_runtime)

    def test_signature_is_checked_before_acceptance(self) -> None:
        changed = bytearray(self.candidate.signature)
        changed[0] ^= 1
        with self.assertRaisesRegex(GenesisError, "GENESIS_SIGNATURE_INVALID"):
            accept_genesis(
                self.harness.domain,
                None,
                replace(self.candidate, signature=bytes(changed)),
                self.capability,
                allowed_profiles=PROFILE_REGISTRY,
                runtime_body_limit=RUNTIME_LIMIT,
            )

    def test_distinct_same_context_does_not_replace_state(self) -> None:
        accepted = accept_genesis(
            self.harness.domain,
            None,
            self.candidate,
            self.capability,
            allowed_profiles=PROFILE_REGISTRY,
            runtime_body_limit=RUNTIME_LIMIT,
        ).state
        self.assertIsNotNone(accepted)
        other_key, _ = __import__("genesis_model").sign_from_seed(SEED_B, b"")
        other_body = replace(
            self.body,
            root_verification_key=other_key,
            initial_authority_policy=b"different-authority",
        )
        other_candidate = make_candidate(other_body, SEED_B, allowed_profiles=PROFILE_REGISTRY)
        other_reference = derive_genesis_reference(other_candidate.transcript)
        with self.assertRaisesRegex(GenesisError, "GENESIS_REFERENCE_MISMATCH"):
            accept_genesis(
                self.harness.domain,
                accepted,
                other_candidate,
                self.capability,
                allowed_profiles=PROFILE_REGISTRY,
                runtime_body_limit=RUNTIME_LIMIT,
            )
        require_descendant_binding(accepted, self.reference)
        with self.assertRaisesRegex(GenesisError, "DESCENDANT_GENESIS_REFERENCE_MISMATCH"):
            require_descendant_binding(accepted, other_reference)

    def test_domain_and_capability_are_not_caller_constructible_or_transferable(self) -> None:
        with self.assertRaisesRegex(GenesisError, "ACCEPTANCE_DOMAIN_CONSTRUCTION_FORBIDDEN"):
            AcceptanceDomain(object(), object(), object())
        foreign_harness = new_test_ceremony_harness(self.context, self.reference)
        foreign_capability = foreign_harness.issue_affirmative(self.context, self.reference)
        with self.assertRaisesRegex(GenesisError, "FOREIGN_ACCEPTANCE_DOMAIN"):
            accept_genesis(
                self.harness.domain,
                None,
                self.candidate,
                foreign_capability,
                allowed_profiles=PROFILE_REGISTRY,
                runtime_body_limit=RUNTIME_LIMIT,
            )
        same_domain_foreign_boundary = self.harness.issue_from_foreign_boundary(
            self.context, self.reference
        )
        with self.assertRaisesRegex(GenesisError, "FOREIGN_CEREMONY_BOUNDARY"):
            accept_genesis(
                self.harness.domain,
                None,
                self.candidate,
                same_domain_foreign_boundary,
                allowed_profiles=PROFILE_REGISTRY,
                runtime_body_limit=RUNTIME_LIMIT,
            )

    def test_wrong_ceremony_binding_issues_no_capability(self) -> None:
        with self.assertRaisesRegex(GenesisError, "CEREMONY_REFERENCE_MISMATCH"):
            self.harness.issue_affirmative(self.context, bytes(32))
        with self.assertRaisesRegex(GenesisError, "CEREMONY_CONTEXT_MISMATCH"):
            self.harness.issue_affirmative(
                replace(
                    self.context,
                    context_identifier=bytes.fromhex("43" * 32),
                ),
                self.reference,
            )

    def test_creator_local_state_is_not_acceptor_authority(self) -> None:
        creator_state = create_local_genesis(
            self.body, SEED_A, allowed_profiles=PROFILE_REGISTRY
        )
        self.assertIsInstance(creator_state, CreatorLocalGenesisState)
        self.assertEqual(creator_state.genesis_reference, self.reference)
        with self.assertRaisesRegex(GenesisError, "CEREMONY_CAPABILITY_INVALID"):
            accept_genesis(
                self.harness.domain,
                None,
                self.candidate,
                creator_state,
                allowed_profiles=PROFILE_REGISTRY,
                runtime_body_limit=RUNTIME_LIMIT,
            )

    def test_capability_cannot_be_copied_or_serialized(self) -> None:
        import copy
        import pickle

        with self.assertRaises(TypeError):
            copy.copy(self.capability)
        with self.assertRaises(TypeError):
            copy.deepcopy(self.capability)
        with self.assertRaises(TypeError):
            pickle.dumps(self.capability)

    def test_grant_collision_boundary_uses_injected_post_derivation_value(self) -> None:
        with self.assertRaisesRegex(GenesisError, "GRANT_REFERENCE_EQUALS_GENESIS_CREDENTIAL"):
            reject_grant_identifier_collision(self.reference, self.reference)
        reject_grant_identifier_collision(self.reference, bytes.fromhex("99" * 32))

    def test_checkpoint_input_is_structurally_unreachable(self) -> None:
        dependency = bytes.fromhex("a0" * 32)
        self.assertEqual(
            evaluate_checkpoint_boundary(
                checkpoint_evidence_refs=frozenset(),
                replay_dependency_refs=frozenset({dependency}),
            ),
            "LIVE_REPLAY_REQUIRED",
        )
        with self.assertRaisesRegex(GenesisError, "CHECKPOINT_EVIDENCE_UNSUPPORTED_V0"):
            evaluate_checkpoint_boundary(
                checkpoint_evidence_refs=frozenset({dependency}),
                replay_dependency_refs=frozenset({dependency}),
            )
        with self.assertRaisesRegex(GenesisError, "VACUOUS_CHECKPOINT_EVIDENCE"):
            evaluate_checkpoint_boundary(
                checkpoint_evidence_refs=frozenset(), replay_dependency_refs=frozenset()
            )


if __name__ == "__main__":
    unittest.main()
