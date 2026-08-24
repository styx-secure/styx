from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys
import unittest
from unittest.mock import patch


O06C_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(O06C_ROOT))

from protocol_model import (  # noqa: E402
    CONTENT_DETACHABLE,
    CONTENT_NONE,
    CONTENT_REQUIRED,
    COMMITMENT_SUITE,
    CONTROL_POLICY,
    CommitmentContext,
    CredentialTail,
    DOMAINS,
    EventAssignment,
    Geometry,
    MAX_U64,
    ModelError,
    RemovalTail,
    ROLE_CREDENTIAL,
    ROLE_ORDINARY,
    ROLE_REMOVAL,
    ContentDescriptor,
    SHAPE_TREE,
    WorkCounter,
    build_commitment,
    descriptor_from_commitment,
    encode_content_descriptor,
    encode_event_transcript,
    event_reference,
    make_grant,
    parse_commitment_preimage,
    parse_event_reference_preimage,
    parse_event_transcript,
    parse_leaf_preimage,
    parse_node_preimage,
    u32,
    validate_event_body_length,
    verify_opening,
)


CTX_ID = bytes.fromhex("11" * 32)
GENESIS = bytes.fromhex("22" * 32)
ISSUER = bytes.fromhex("33" * 32)
RANDOMIZER = bytes.fromhex("44" * 32)


class ProtocolModelTests(unittest.TestCase):
    def test_event_body_framing_ceiling_is_shared_by_encoder_and_parser(self) -> None:
        self.assertEqual(validate_event_body_length((1 << 32) - 21), (1 << 32) - 21)
        with self.assertRaisesRegex(ModelError, "event body framing length"):
            validate_event_body_length((1 << 32) - 20)

        event = make_grant(
            issuer_credential=ISSUER,
            context_identifier=CTX_ID,
            genesis_reference=GENESIS,
            transition_block=b"shared-framing-ceiling",
            verification_key=b"shared-framing-key",
        )
        with patch(
            "protocol_model.validate_event_body_length",
            wraps=validate_event_body_length,
        ) as validator:
            transcript = encode_event_transcript(event)
            self.assertEqual(parse_event_transcript(transcript), event)
        body_length = len(transcript) - 20
        self.assertEqual(validator.call_count, 3)
        self.assertEqual(
            [call.args for call in validator.call_args_list],
            [(body_length,), (body_length,), (body_length,)],
        )

    def test_domains_are_closed_and_distinct(self) -> None:
        self.assertEqual(len(DOMAINS), 7)
        self.assertEqual(len(set(DOMAINS.values())), 7)
        self.assertTrue(all(len(value) == 16 for value in DOMAINS.values()))

    def test_grant_reference_is_non_circular_and_propagates(self) -> None:
        grant = make_grant(
            issuer_credential=ISSUER,
            context_identifier=CTX_ID,
            genesis_reference=GENESIS,
            transition_block=b"grant-profile-input",
            verification_key=b"verification-key-a",
        )
        grant_transcript = encode_event_transcript(grant)
        credential_id = event_reference(grant)
        self.assertNotIn(credential_id, grant_transcript)
        changed = replace(grant, genesis_reference=bytes.fromhex("23" * 32))
        changed_id = event_reference(changed)
        self.assertNotEqual(credential_id, changed_id)

        first_context = CommitmentContext(1, 1, CTX_ID, credential_id, 0)
        second_context = replace(first_context, credential_identifier=changed_id)
        first = build_commitment(first_context, 7, b"grant-rooted content", RANDOMIZER)
        second = build_commitment(second_context, 7, b"grant-rooted content", RANDOMIZER)
        self.assertNotEqual(first.leaf_preimages, second.leaf_preimages)
        self.assertNotEqual(first.commitment_preimage, second.commitment_preimage)
        self.assertNotEqual(first.commitment_value, second.commitment_value)

    def test_single_and_tree_exact_widths_and_inverses(self) -> None:
        context = CommitmentContext(1, 1, CTX_ID, ISSUER, 0)
        single = build_commitment(context, 9, b"abc", RANDOMIZER)
        tree = build_commitment(context, 9, b"abcdefghijk", RANDOMIZER, chunk_size=4)
        self.assertEqual(len(context.encode()), 84)
        self.assertEqual(len(single.leaf_preimages[0]), 155)
        self.assertEqual(len(single.commitment_preimage), 181)
        self.assertEqual(len(tree.commitment_preimage), 197)
        self.assertEqual(len(tree.leaf_digests), 3)
        self.assertEqual(len(tree.node_preimages), 2)
        self.assertEqual(parse_leaf_preimage(single.leaf_preimages[0])["leaf_octets"], b"abc")
        self.assertEqual(parse_commitment_preimage(single.commitment_preimage)["root"], single.root)
        self.assertEqual(parse_commitment_preimage(tree.commitment_preimage)["geometry"], tree.geometry)
        self.assertTrue(all(parse_node_preimage(value)["subtree_leaf_count"] >= 2 for value in tree.node_preimages))

    def test_credential_and_sequence_bind_every_leaf_and_outer_commitment(self) -> None:
        base = CommitmentContext(1, 1, CTX_ID, ISSUER, 0)
        by_credential = replace(base, credential_identifier=bytes.fromhex("34" * 32))
        by_sequence = replace(base, author_sequence=1)
        for chunk_size in (None, 4):
            content = b"abcdefghijk" if chunk_size else b"abc"
            original = build_commitment(base, 5, content, RANDOMIZER, chunk_size=chunk_size)
            changed_credential = build_commitment(
                by_credential, 5, content, RANDOMIZER, chunk_size=chunk_size
            )
            changed_sequence = build_commitment(
                by_sequence, 5, content, RANDOMIZER, chunk_size=chunk_size
            )
            self.assertTrue(
                all(a != b for a, b in zip(original.leaf_digests, changed_credential.leaf_digests))
            )
            self.assertTrue(
                all(a != b for a, b in zip(original.leaf_digests, changed_sequence.leaf_digests))
            )
            self.assertNotEqual(original.commitment_value, changed_credential.commitment_value)
            self.assertNotEqual(original.commitment_value, changed_sequence.commitment_value)

    def test_descriptor_roundtrip_and_cross_slot_rejection(self) -> None:
        context = CommitmentContext(1, 1, CTX_ID, ISSUER, 0)
        commitment = build_commitment(context, 4, b"abcdefghijk", RANDOMIZER, chunk_size=4)
        descriptor = descriptor_from_commitment(CONTENT_DETACHABLE, commitment)
        verified = verify_opening(descriptor, context, b"abcdefghijk", RANDOMIZER)
        self.assertEqual(verified.commitment_value, commitment.commitment_value)
        with self.assertRaisesRegex(ModelError, "commitment mismatch"):
            verify_opening(
                descriptor,
                replace(context, author_sequence=1),
                b"abcdefghijk",
                RANDOMIZER,
            )

    def test_geometry_guard_measures_constant_work_before_splitting(self) -> None:
        small_work = WorkCounter()
        inflated_work = WorkCounter()
        common = dict(
            content_class=CONTENT_REQUIRED,
            exact_content_length=9,
            content_type_id=7,
            commitment_suite_id=COMMITMENT_SUITE,
            commitment_shape=SHAPE_TREE,
            commitment_value=bytes.fromhex("99" * 32),
        )
        with self.assertRaisesRegex(ModelError, "chunk count"):
            encode_content_descriptor(
                ContentDescriptor(**common, geometry=Geometry(1, 2, 1)),
                small_work,
            )
        with self.assertRaisesRegex(ModelError, "chunk count"):
            encode_content_descriptor(
                ContentDescriptor(**common, geometry=Geometry(1, MAX_U64, 1)),
                inflated_work,
            )
        self.assertEqual(small_work.geometry_checks, 1)
        self.assertEqual(inflated_work.geometry_checks, 1)
        self.assertEqual(small_work.content_split_chunks, 0)
        self.assertEqual(inflated_work.content_split_chunks, 0)
        self.assertEqual(small_work.hashed_octets, 0)
        self.assertEqual(inflated_work.hashed_octets, 0)

    def test_application_transcript_binds_descriptor(self) -> None:
        context = CommitmentContext(1, 1, CTX_ID, ISSUER, 0)
        commitment = build_commitment(context, 4, b"abc", RANDOMIZER)
        descriptor = descriptor_from_commitment(CONTENT_DETACHABLE, commitment)
        event = EventAssignment(
            application_profile_id=1,
            application_profile_version=1,
            context_identifier=CTX_ID,
            event_role=ROLE_ORDINARY,
            event_type_id=1,
            schema_id=1,
            schema_version=1,
            transition_block=b"canonical-ap-block",
            credential_identifier=ISSUER,
            author_sequence=0,
            direct_predecessor=None,
            causal_parents=(),
            genesis_reference=GENESIS,
            content=descriptor,
        )
        transcript = encode_event_transcript(event)
        self.assertEqual(transcript[:16], DOMAINS["application"])
        self.assertEqual(int.from_bytes(transcript[16:20], "big"), len(transcript) - 20)
        self.assertEqual(len(event_reference(event)), 32)
        self.assertEqual(parse_event_transcript(transcript), event)

        reference_preimage = DOMAINS["event_reference"] + u32(len(transcript)) + transcript
        parsed_reference = parse_event_reference_preimage(reference_preimage)
        self.assertEqual(parsed_reference["event"], event)
        self.assertEqual(parsed_reference["reference"], event_reference(event))

    def test_complete_inverse_covers_each_role_tail(self) -> None:
        none = ContentDescriptor(CONTENT_NONE, 0)
        common = dict(
            application_profile_id=1,
            application_profile_version=1,
            context_identifier=CTX_ID,
            event_type_id=2,
            schema_id=3,
            schema_version=4,
            transition_block=b"control",
            credential_identifier=ISSUER,
            author_sequence=1,
            direct_predecessor=bytes.fromhex("55" * 32),
            causal_parents=(bytes.fromhex("66" * 32),),
            genesis_reference=GENESIS,
            content=none,
        )
        removal = EventAssignment(
            event_role=ROLE_REMOVAL,
            tail=RemovalTail(bytes.fromhex("77" * 32), bytes.fromhex("88" * 32)),
            **common,
        )
        policy = EventAssignment(
            event_role=ROLE_CREDENTIAL,
            tail=CredentialTail(CONTROL_POLICY),
            **common,
        )
        for event in (removal, policy):
            self.assertEqual(parse_event_transcript(encode_event_transcript(event)), event)

        grant = make_grant(
            issuer_credential=ISSUER,
            context_identifier=CTX_ID,
            genesis_reference=GENESIS,
            transition_block=b"grant",
            verification_key=b"key",
        )
        self.assertEqual(parse_event_transcript(encode_event_transcript(grant)), grant)

    def test_complete_inverse_rejects_noncanonical_framing_and_presence(self) -> None:
        grant = make_grant(
            issuer_credential=ISSUER,
            context_identifier=CTX_ID,
            genesis_reference=GENESIS,
            transition_block=b"grant",
            verification_key=b"key",
        )
        transcript = encode_event_transcript(grant)
        with self.assertRaisesRegex(ModelError, "truncated event body"):
            parse_event_transcript(
                transcript[:16] + u32(len(transcript) - 19) + transcript[20:]
            )
        with self.assertRaisesRegex(ModelError, "trailing octets"):
            parse_event_transcript(
                transcript[:16] + u32(len(transcript) - 19) + transcript[20:] + b"x"
            )

        # Presence sits after the fixed common prefix and the framed transition.
        presence_offset = 20 + (2 + 4 + 4 + 32 + 2 + 1 + 4 + 4 + 4) + 4 + len(b"grant") + 32 + 8
        malformed = bytearray(transcript)
        malformed[presence_offset] = 2
        with self.assertRaisesRegex(ModelError, "invalid predecessor presence"):
            parse_event_transcript(bytes(malformed))


if __name__ == "__main__":
    unittest.main()
