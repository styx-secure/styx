from __future__ import annotations

from pathlib import Path
import sys
import unittest


C02K_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(C02K_ROOT))

from commitment_context_model import (  # noqa: E402
    COMMIT_BODY_SINGLE_OCTETS,
    COMMIT_BODY_TREE_OCTETS,
    COMMIT_PREIMAGE_SINGLE_OCTETS,
    COMMIT_PREIMAGE_TREE_OCTETS,
    CONTEXT_OCTETS,
    LEGACY_CONTEXT_OCTETS,
    LEAF_FIXED_PREFIX_OCTETS,
    LEAF_PREIMAGE_OVERHEAD,
    MAX_LEAF_OCTETS,
    MAX_U64,
    NODE_BODY_OCTETS,
    NODE_PREIMAGE_OCTETS,
    CommitmentContext,
    ModelInputError,
    build_commitment,
    derive_geometry,
    encode_context,
    leaf_preimage_lengths,
    node_preimage,
    parse_commitment_preimage,
    parse_context,
    parse_leaf_preimage,
    parse_node_preimage,
    verifies,
)
from scenarios_c02k import context  # noqa: E402


class CommitmentContextModelTests(unittest.TestCase):
    RANDOMIZER = bytes.fromhex("a5" * 32)
    EXPECTED_CONTEXT = bytes.fromhex(
        "000100010102030405060708"
        + "22" * 32
        + "33" * 32
        + "0000000000000007"
    )

    def test_exact_context_vector_and_inverse(self) -> None:
        encoded = encode_context(context())
        self.assertEqual(len(encoded), CONTEXT_OCTETS)
        self.assertEqual(encoded, self.EXPECTED_CONTEXT)
        self.assertEqual(parse_context(encoded), context())

    def test_context_rejects_legacy_extension_and_untrusted_suite(self) -> None:
        cases = (
            self.EXPECTED_CONTEXT[:LEGACY_CONTEXT_OCTETS],
            self.EXPECTED_CONTEXT + b"\x00",
            b"\x00\x02" + self.EXPECTED_CONTEXT[2:],
        )
        for value in cases:
            with self.subTest(length=len(value), prefix=value[:2].hex()):
                with self.assertRaises(ModelInputError):
                    parse_context(value)

    def test_integer_and_identifier_boundaries_are_exact(self) -> None:
        for sequence in (0, MAX_U64):
            value = context(0, sequence)
            self.assertEqual(parse_context(encode_context(value)), value)
        with self.assertRaisesRegex(ModelInputError, "INTEGER_RANGE"):
            encode_context(context(sequence=MAX_U64 + 1))
        with self.assertRaisesRegex(ModelInputError, "INVALID_WIDTH"):
            encode_context(
                CommitmentContext(1, 1, bytes(32), bytes(31), 0)
            )

    def test_derived_widths_and_len32_ceiling(self) -> None:
        self.assertEqual(CONTEXT_OCTETS, 84)
        self.assertEqual(LEAF_FIXED_PREFIX_OCTETS, 132)
        self.assertEqual(LEAF_PREIMAGE_OVERHEAD, 152)
        self.assertEqual(COMMIT_BODY_SINGLE_OCTETS, 161)
        self.assertEqual(COMMIT_BODY_TREE_OCTETS, 177)
        self.assertEqual(COMMIT_PREIMAGE_SINGLE_OCTETS, 181)
        self.assertEqual(COMMIT_PREIMAGE_TREE_OCTETS, 197)
        self.assertEqual(NODE_BODY_OCTETS, 74)
        self.assertEqual(NODE_PREIMAGE_OCTETS, 94)
        self.assertEqual(MAX_LEAF_OCTETS, 4_294_967_163)
        self.assertEqual(
            leaf_preimage_lengths(MAX_LEAF_OCTETS),
            (2**32 - 1, 2**32 + 19),
        )
        with self.assertRaisesRegex(ModelInputError, "LEAF_LENGTH"):
            leaf_preimage_lengths(MAX_LEAF_OCTETS + 1)

    def test_node_inverse_requires_exact_end(self) -> None:
        preimage = node_preimage(2, bytes.fromhex("11" * 32), bytes.fromhex("22" * 32))
        parsed = parse_node_preimage(preimage)
        self.assertEqual(parsed["subtree_leaf_count"], 2)
        self.assertEqual(parsed["left_child"], bytes.fromhex("11" * 32))
        self.assertEqual(parsed["right_child"], bytes.fromhex("22" * 32))
        with self.assertRaisesRegex(ModelInputError, "TRAILING_BYTES"):
            parse_node_preimage(preimage + b"\x00")

    def test_single_vector_and_inverse(self) -> None:
        result = build_commitment(context(), 9, b"abc", self.RANDOMIZER)
        self.assertEqual(
            result.root.hex(),
            "651bc044c78b402ad50571fed096c62dd0e72267f452793cfaf491b28f9d504f",
        )
        self.assertEqual(
            result.commitment_value.hex(),
            "e17bd20d80e677091d867a1c18e09128c0a44966d3e54f899fb3a59c7c86875d",
        )
        self.assertEqual(len(result.leaf_preimages[0]), LEAF_PREIMAGE_OVERHEAD + 3)
        self.assertEqual(len(result.commitment_preimage), COMMIT_PREIMAGE_SINGLE_OCTETS)
        self.assertEqual(parse_leaf_preimage(result.leaf_preimages[0])["leaf_octets"], b"abc")
        self.assertEqual(parse_commitment_preimage(result.commitment_preimage)["root"], result.root)
        self.assertTrue(verifies(result, context(), b"abc"))

    def test_tree_vector_geometry_inverse_and_work(self) -> None:
        result = build_commitment(
            context(), 9, b"abcdefghi", self.RANDOMIZER, chunk_size=4
        )
        self.assertEqual(
            result.root.hex(),
            "01ec644c584a2638379efacc03b158063d722ce33a6e96d3fe4d251bd7a01c0c",
        )
        self.assertEqual(
            result.commitment_value.hex(),
            "199c8be2813a7e9a77d5c0198bcb8951c2c51a46b19d30e9ee8135f170cf5e50",
        )
        self.assertEqual(result.geometry, derive_geometry(9, 4))
        self.assertEqual((result.geometry.chunk_count, result.geometry.final_chunk_length), (3, 1))
        self.assertEqual(len(result.node_preimages), 2)
        self.assertTrue(all(len(item) == NODE_PREIMAGE_OCTETS for item in result.node_preimages))
        self.assertEqual(len(result.commitment_preimage), COMMIT_PREIMAGE_TREE_OCTETS)
        self.assertEqual(result.counters.digest_invocations, 6)
        self.assertEqual(result.counters.leaf_visits, 3)
        self.assertEqual(result.counters.node_visits, 2)
        self.assertEqual(result.counters.bytes_hashed, 850)
        self.assertTrue(verifies(result, context(), b"abcdefghi"))

        malformed = (
            result.commitment_preimage[:121]
            + bytes(8)
            + result.commitment_preimage[129:]
        )
        with self.assertRaisesRegex(ModelInputError, "GEOMETRY"):
            parse_commitment_preimage(malformed)

    def test_maximum_u64_geometry_avoids_addition_overflow(self) -> None:
        geometry = derive_geometry(MAX_U64, MAX_LEAF_OCTETS)
        expected_count, remainder = divmod(MAX_U64, MAX_LEAF_OCTETS)
        expected_count += 1 if remainder else 0
        self.assertEqual(geometry.chunk_count, expected_count)
        self.assertEqual(
            geometry.final_chunk_length,
            MAX_U64 - MAX_LEAF_OCTETS * (expected_count - 1),
        )

    def test_unchanged_opening_fails_across_credential_and_sequence(self) -> None:
        result = build_commitment(context(), 9, b"payload", self.RANDOMIZER)
        self.assertFalse(verifies(result, context(0x44), b"payload"))
        self.assertFalse(verifies(result, context(sequence=8), b"payload"))
        self.assertTrue(
            verifies(
                build_commitment(context(0x44), 9, b"payload", self.RANDOMIZER),
                context(0x44),
                b"payload",
            )
        )


if __name__ == "__main__":
    unittest.main()
