"""Closed hostile-witness suite for the C0.2k exact-byte model."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Callable

from commitment_context_model import (
    COMMIT_BODY_SINGLE_OCTETS,
    COMMIT_BODY_TREE_OCTETS,
    COMMIT_PREIMAGE_SINGLE_OCTETS,
    COMMIT_PREIMAGE_TREE_OCTETS,
    CONTEXT_OCTETS,
    D_COMMIT,
    D_LEAF,
    LEAF_FIXED_PREFIX_OCTETS,
    LEAF_PREIMAGE_OVERHEAD,
    MAX_LEN32,
    MAX_LEAF_OCTETS,
    MAX_U64,
    NODE_BODY_OCTETS,
    NODE_PREIMAGE_OCTETS,
    SHAPE_SINGLE,
    SHAPE_TREE,
    CommitmentContext,
    Geometry,
    ModelInputError,
    Mutation,
    build_commitment,
    commitment_body,
    commitment_required_for_content_class,
    derived_widths,
    derive_geometry,
    encode_context,
    frame,
    leaf_body,
    leaf_preimage_lengths,
    node_preimage,
    node_preimage_for_mutation,
    parse_node_preimage,
    parse_commitment_preimage,
    parse_context,
    parse_leaf_preimage,
    partial_verification_supported,
    same_slot_relationship,
    successful_verification_claims,
    verifies,
)


REQUIRED_MUTANTS = frozenset(
    {
        "M01_OMIT_CREDENTIAL",
        "M02_OMIT_SEQUENCE",
        "M03_REORDER_FIELDS",
        "M04_LITTLE_ENDIAN_SEQUENCE",
        "M05_TRUNCATE_SEQUENCE_U32",
        "M06_ACCEPT_SEQUENCE_WRAP",
        "M07_ACCEPT_LEGACY_CONTEXT",
        "M08_BIND_ONLY_COMMITMENT",
        "M09_BIND_ONLY_LEAF",
        "M10_BIND_ONLY_SINGLE",
        "M11_BIND_ONLY_TREE",
        "M12_RETAIN_OLD_WIDTHS",
        "M13_ACCEPT_TRAILING_BYTES",
        "M14_EQUAL_COMMITMENT_IS_DUPLICATE",
        "M15_CHANGE_NODE_FORMAT",
        "M16_INFER_AUTHORSHIP_ORIGINALITY",
        "M17_SELECT_UNTRUSTED_SUITE",
        "M18_CONTROL_NONE_HAS_COMMITMENT",
    }
)


REQUIRED_WITNESSES = frozenset(
    {
        "exact-context-and-inverse",
        "credential-and-sequence-binding",
        "legacy-downgrade-rejection",
        "role-and-shape-completeness",
        "exact-widths-and-ceilings",
        "single-and-tree-roundtrip",
        "same-slot-fork-boundary",
        "malicious-recomputation-boundary",
        "sequence-and-credential-boundaries",
        "geometry-and-work-bounds",
        "interior-node-invariance",
        "control-and-removal-non-expansion",
        "suite-selection-fail-closed",
    }
)


@dataclass(frozen=True)
class Check:
    identifier: str
    family: str
    passed: bool
    assertion: str
    detail: str
    kills: tuple[str, ...] = ()

    def record(self) -> dict[str, object]:
        return {
            "id": self.identifier,
            "family": self.family,
            "passed": self.passed,
            "assertion": self.assertion,
            "detail": self.detail,
            "kills": list(self.kills),
        }


@dataclass(frozen=True)
class Suite:
    checks: tuple[Check, ...]

    @property
    def witnesses(self) -> frozenset[str]:
        return frozenset(item.family for item in self.checks)


def context(
    credential_octet: int = 0x33,
    sequence: int = 7,
    *,
    context_octet: int = 0x22,
    suite: int = 1,
) -> CommitmentContext:
    return CommitmentContext(
        application_profile_id=0x01020304,
        application_profile_version=0x05060708,
        context_identifier=bytes((context_octet,)) * 32,
        credential_identifier=bytes((credential_octet,)) * 32,
        author_sequence=sequence,
        commitment_suite_id=suite,
    )


def _passes(operation: Callable[[], object]) -> tuple[bool, str]:
    try:
        value = operation()
    except Exception as error:  # the report records unexpected model failures
        return False, f"{type(error).__name__}: {error}"
    return bool(value), repr(value)


def _rejects(operation: Callable[[], object], code: str | None = None) -> tuple[bool, str]:
    try:
        operation()
    except ModelInputError as error:
        return (code is None or error.code == code), f"{error.code}: {error.detail}"
    except Exception as error:
        return False, f"unexpected {type(error).__name__}: {error}"
    return False, "accepted"


def run_required_suite(mutation: Mutation = Mutation()) -> Suite:
    checks: list[Check] = []

    def add(
        identifier: str,
        family: str,
        assertion: str,
        result: tuple[bool, str],
        *kills: str,
    ) -> None:
        checks.append(Check(identifier, family, result[0], assertion, result[1], tuple(kills)))

    base = context()
    other_credential = context(0x44)
    other_sequence = context(sequence=8)
    high_sequence = context(sequence=2**32 + 7)
    randomizer = bytes.fromhex("a5" * 32)
    content = b"c0.2k exact commitment context"

    expected_context = bytes.fromhex(
        "000100010102030405060708" + "22" * 32 + "33" * 32 + "0000000000000007"
    )
    add(
        "C01-CANONICAL-CONTEXT",
        "exact-context-and-inverse",
        "CTX is the one exact 84-octet big-endian field sequence",
        _passes(lambda: encode_context(base, mutation) == expected_context),
        "M01_OMIT_CREDENTIAL",
        "M02_OMIT_SEQUENCE",
        "M03_REORDER_FIELDS",
        "M04_LITTLE_ENDIAN_SEQUENCE",
        "M05_TRUNCATE_SEQUENCE_U32",
    )
    add(
        "C02-CONTEXT-INVERSE",
        "exact-context-and-inverse",
        "the exact context round-trips with exact end",
        _passes(lambda: parse_context(encode_context(base, mutation), mutation) == base),
    )
    add(
        "C03-CREDENTIAL-BINDING",
        "credential-and-sequence-binding",
        "different credential identifiers produce different context bytes",
        _passes(lambda: encode_context(base, mutation) != encode_context(other_credential, mutation)),
        "M01_OMIT_CREDENTIAL",
    )
    add(
        "C04-SEQUENCE-BINDING",
        "credential-and-sequence-binding",
        "different u64 sequences, including equal low u32 limbs, remain distinct",
        _passes(lambda: encode_context(base, mutation) != encode_context(high_sequence, mutation)),
        "M02_OMIT_SEQUENCE",
        "M05_TRUNCATE_SEQUENCE_U32",
    )
    add(
        "C05-LEGACY-REJECTED",
        "legacy-downgrade-rejection",
        "the superseded 44-octet context is rejected without fallback",
        _rejects(lambda: parse_context(expected_context[:44], mutation), "CONTEXT_LENGTH"),
        "M07_ACCEPT_LEGACY_CONTEXT",
    )
    add(
        "C06-TRAILING-CONTEXT-REJECTED",
        "legacy-downgrade-rejection",
        "the context parser rejects extension bytes",
        _rejects(lambda: parse_context(expected_context + b"\x00", mutation), "CONTEXT_LENGTH"),
    )

    invalid_sequence = context(sequence=MAX_U64 + 1)
    add(
        "C07-SEQUENCE-WRAP-REJECTED",
        "sequence-and-credential-boundaries",
        "author sequence never wraps beyond u64",
        _rejects(lambda: encode_context(invalid_sequence, mutation), "INTEGER_RANGE"),
        "M06_ACCEPT_SEQUENCE_WRAP",
    )
    add(
        "C08-ZERO-AND-MAX-SEQUENCE",
        "sequence-and-credential-boundaries",
        "zero and 2^64-1 are structurally representable without signed reinterpretation",
        _passes(
            lambda: parse_context(encode_context(context(sequence=0))).author_sequence == 0
            and parse_context(encode_context(context(sequence=MAX_U64))).author_sequence == MAX_U64
        ),
    )
    add(
        "C09-CREDENTIAL-OCTET-BOUNDARIES",
        "sequence-and-credential-boundaries",
        "all-zero and zero-edged credential identifiers retain exact width and identity",
        _passes(
            lambda: parse_context(encode_context(context(0))).credential_identifier == bytes(32)
            and parse_context(
                encode_context(
                    CommitmentContext(
                        1,
                        1,
                        bytes(32),
                        b"\x00" + b"\x7f" * 30 + b"\x00",
                        0,
                    )
                )
            ).credential_identifier
            == b"\x00" + b"\x7f" * 30 + b"\x00"
        ),
    )

    def leaf_diff(left: CommitmentContext, right: CommitmentContext, shape: int) -> bool:
        return leaf_body(left, 9, 0, b"x", randomizer, shape=shape, mutation=mutation) != leaf_body(
            right, 9, 0, b"x", randomizer, shape=shape, mutation=mutation
        )

    def commit_diff(left: CommitmentContext, right: CommitmentContext, shape: int) -> bool:
        geometry = None if shape == SHAPE_SINGLE else Geometry(1, 2, 1)
        return commitment_body(
            left, 9, 2 if geometry else 1, shape, geometry, bytes(32), randomizer, mutation
        ) != commitment_body(
            right, 9, 2 if geometry else 1, shape, geometry, bytes(32), randomizer, mutation
        )

    add(
        "C10-LEAF-BINDS-CREDENTIAL-SINGLE",
        "role-and-shape-completeness",
        "B_L binds credential identity for SINGLE",
        _passes(lambda: leaf_diff(base, other_credential, SHAPE_SINGLE)),
        "M01_OMIT_CREDENTIAL",
        "M08_BIND_ONLY_COMMITMENT",
        "M11_BIND_ONLY_TREE",
    )
    add(
        "C11-LEAF-BINDS-CREDENTIAL-TREE",
        "role-and-shape-completeness",
        "B_L binds credential identity for TREE",
        _passes(lambda: leaf_diff(base, other_credential, SHAPE_TREE)),
        "M01_OMIT_CREDENTIAL",
        "M08_BIND_ONLY_COMMITMENT",
        "M10_BIND_ONLY_SINGLE",
    )
    add(
        "C12-LEAF-BINDS-SEQUENCE",
        "role-and-shape-completeness",
        "B_L binds the full author sequence",
        _passes(lambda: leaf_diff(base, other_sequence, SHAPE_SINGLE)),
        "M02_OMIT_SEQUENCE",
    )
    add(
        "C13-COMMITMENT-BINDS-CREDENTIAL-SINGLE",
        "role-and-shape-completeness",
        "B_C binds credential identity for SINGLE independently of the root",
        _passes(lambda: commit_diff(base, other_credential, SHAPE_SINGLE)),
        "M01_OMIT_CREDENTIAL",
        "M09_BIND_ONLY_LEAF",
        "M11_BIND_ONLY_TREE",
    )
    add(
        "C14-COMMITMENT-BINDS-CREDENTIAL-TREE",
        "role-and-shape-completeness",
        "B_C binds credential identity for TREE independently of the root",
        _passes(lambda: commit_diff(base, other_credential, SHAPE_TREE)),
        "M01_OMIT_CREDENTIAL",
        "M09_BIND_ONLY_LEAF",
        "M10_BIND_ONLY_SINGLE",
    )
    add(
        "C15-COMMITMENT-BINDS-SEQUENCE",
        "role-and-shape-completeness",
        "B_C binds the full author sequence independently of the root",
        _passes(lambda: commit_diff(base, other_sequence, SHAPE_SINGLE)),
        "M02_OMIT_SEQUENCE",
    )

    widths = derived_widths(mutation)
    expected_widths = {
        "context": CONTEXT_OCTETS,
        "leaf_body_prefix": LEAF_FIXED_PREFIX_OCTETS,
        "leaf_preimage_overhead": LEAF_PREIMAGE_OVERHEAD,
        "commit_body_single": COMMIT_BODY_SINGLE_OCTETS,
        "commit_body_tree": COMMIT_BODY_TREE_OCTETS,
        "commit_preimage_single": COMMIT_PREIMAGE_SINGLE_OCTETS,
        "commit_preimage_tree": COMMIT_PREIMAGE_TREE_OCTETS,
        "max_leaf_octets": MAX_LEAF_OCTETS,
    }
    add(
        "C16-DERIVED-WIDTHS",
        "exact-widths-and-ceilings",
        "every mechanically dependent width and len32 ceiling is updated",
        _passes(lambda: widths == expected_widths),
        "M12_RETAIN_OLD_WIDTHS",
    )

    single = build_commitment(base, 9, content, randomizer, mutation=mutation)
    tree = build_commitment(base, 9, content, randomizer, chunk_size=7, mutation=mutation)
    add(
        "C17-SINGLE-ROUNDTRIP",
        "single-and-tree-roundtrip",
        "single leaf and commitment preimages have exact inverses",
        _passes(
            lambda: parse_leaf_preimage(single.leaf_preimages[0], mutation)["leaf_octets"] == content
            and parse_commitment_preimage(single.commitment_preimage, mutation)["root"] == single.root
            and verifies(single, base, content, mutation=mutation)
        ),
    )
    add(
        "C18-TREE-ROUNDTRIP",
        "single-and-tree-roundtrip",
        "tree leaf and commitment preimages have exact inverses",
        _passes(
            lambda: all(parse_leaf_preimage(value, mutation)["leaf_octets"] for value in tree.leaf_preimages)
            and parse_commitment_preimage(tree.commitment_preimage, mutation)["geometry"] == tree.geometry
            and verifies(tree, base, content, mutation=mutation)
        ),
    )
    add(
        "C19-TRAILING-PREIMAGE-REJECTED",
        "exact-context-and-inverse",
        "leaf framing requires exact end",
        _rejects(lambda: parse_leaf_preimage(single.leaf_preimages[0] + b"\x00", mutation), "TRAILING_BYTES"),
        "M13_ACCEPT_TRAILING_BYTES",
    )

    base_single = build_commitment(base, 9, content, randomizer, mutation=mutation)
    base_tree = build_commitment(base, 9, content, randomizer, chunk_size=7, mutation=mutation)
    add(
        "C20-CROSS-CREDENTIAL-COPY-SINGLE",
        "credential-and-sequence-binding",
        "an unchanged SINGLE opening cannot verify under another credential",
        _passes(lambda: not verifies(base_single, other_credential, content, mutation=mutation)),
    )
    add(
        "C21-CROSS-CREDENTIAL-COPY-TREE",
        "credential-and-sequence-binding",
        "an unchanged TREE opening cannot verify under another credential",
        _passes(lambda: not verifies(base_tree, other_credential, content, mutation=mutation)),
    )
    add(
        "C22-CROSS-SEQUENCE-COPY-SINGLE",
        "credential-and-sequence-binding",
        "an unchanged SINGLE opening cannot verify at another author sequence",
        _passes(lambda: not verifies(base_single, other_sequence, content, mutation=mutation)),
    )
    add(
        "C23-CROSS-SEQUENCE-COPY-TREE",
        "credential-and-sequence-binding",
        "an unchanged TREE opening cannot verify at another author sequence",
        _passes(lambda: not verifies(base_tree, other_sequence, content, mutation=mutation)),
    )

    left_reference = sha256(b"left transcript" + base_single.commitment_value).digest()
    right_reference = sha256(b"right transcript" + base_single.commitment_value).digest()
    add(
        "C24-SAME-SLOT-IS-FORK",
        "same-slot-fork-boundary",
        "equal commitment at one credential/sequence does not collapse distinct event references",
        _passes(
            lambda: left_reference != right_reference
            and same_slot_relationship(
                base.credential_identifier,
                base.author_sequence,
                left_reference,
                right_reference,
                mutation,
            )
            == "FORK_EVIDENCE"
        ),
        "M14_EQUAL_COMMITMENT_IS_DUPLICATE",
    )
    add(
        "C25-RECOMPUTATION-NONCLAIM",
        "malicious-recomputation-boundary",
        "a peer can recompute a different valid commitment; verification adds no truth claim",
        _passes(
            lambda: build_commitment(other_credential, 9, content, randomizer, mutation=mutation).commitment_value
            != base_single.commitment_value
            and verifies(
                build_commitment(other_credential, 9, content, randomizer, mutation=mutation),
                other_credential,
                content,
                mutation=mutation,
            )
            and successful_verification_claims(mutation) == {"CONTEXT_BOUND_COMMITMENT"}
        ),
        "M16_INFER_AUTHORSHIP_ORIGINALITY",
    )

    node = node_preimage_for_mutation(2, bytes.fromhex("11" * 32), bytes.fromhex("22" * 32), mutation)
    add(
        "C26-NODE-UNCHANGED",
        "interior-node-invariance",
        "B_N remains 74 octets and its complete preimage remains 94 octets",
        _passes(
            lambda: len(node) == NODE_PREIMAGE_OCTETS
            and int.from_bytes(node[16:20], "big") == NODE_BODY_OCTETS
        ),
        "M15_CHANGE_NODE_FORMAT",
    )

    geometry = derive_geometry(MAX_U64, MAX_LEAF_OCTETS)
    add(
        "C27-GEOMETRY-BOUNDARY",
        "geometry-and-work-bounds",
        "u64 maximum geometry is derived with checked arithmetic and no payload allocation",
        _passes(
            lambda: geometry.chunk_count >= 2
            and 1 <= geometry.final_chunk_length <= geometry.chunk_size
            and geometry.chunk_size * (geometry.chunk_count - 1) <= MAX_U64
        ),
    )
    add(
        "C28-MALFORMED-GEOMETRY",
        "geometry-and-work-bounds",
        "zero, oversize, one-chunk and authenticated inconsistent tree geometries reject before content allocation",
        _passes(
            lambda: _rejects(lambda: derive_geometry(10, 0))[0]
            and _rejects(lambda: derive_geometry(10, 10))[0]
            and _rejects(lambda: derive_geometry(10, MAX_LEAF_OCTETS + 1))[0]
            and _rejects(
                lambda: parse_commitment_preimage(
                    tree.commitment_preimage[:121]
                    + bytes(8)
                    + tree.commitment_preimage[129:]
                ),
                "GEOMETRY",
            )[0]
        ),
    )
    add(
        "C29-WORK-COUNTERS",
        "geometry-and-work-bounds",
        "measured work uses digest invocations, bytes hashed, leaf visits and node visits",
        _passes(
            lambda: single.counters.digest_invocations == 2
            and single.counters.leaf_visits == 1
            and single.counters.node_visits == 0
            and tree.counters.digest_invocations == 2 * len(tree.leaf_preimages)
            and tree.counters.node_visits == len(tree.leaf_preimages) - 1
            and tree.counters.bytes_hashed > 0
        ),
    )
    add(
        "C30-NONE-CONTROL-NO-CONTENT",
        "control-and-removal-non-expansion",
        "NONE control/removal events acquire no hidden content commitment",
        _passes(lambda: not commitment_required_for_content_class("NONE", mutation)),
        "M18_CONTROL_NONE_HAS_COMMITMENT",
    )

    unknown_suite = bytearray(expected_context)
    unknown_suite[0:2] = b"\x00\x02"
    add(
        "C31-UNTRUSTED-SUITE-REJECTED",
        "suite-selection-fail-closed",
        "untrusted carried suite cannot select a parser profile",
        _rejects(lambda: parse_context(bytes(unknown_suite), mutation), "UNKNOWN_SUITE"),
        "M17_SELECT_UNTRUSTED_SUITE",
    )
    add(
        "C32-EMPTY-SINGLE",
        "single-and-tree-roundtrip",
        "empty content uses a valid single commitment with one empty leaf",
        _passes(
            lambda: build_commitment(base, 9, b"", randomizer).shape == SHAPE_SINGLE
            and parse_leaf_preimage(
                build_commitment(base, 9, b"", randomizer).leaf_preimages[0]
            )["leaf_octets"]
            == b""
        ),
    )
    add(
        "C33-FINAL-SHORT-CHUNK",
        "single-and-tree-roundtrip",
        "the final tree chunk may be shorter and remains exactly derived",
        _passes(lambda: tree.geometry is not None and tree.geometry.final_chunk_length == len(content) % 7),
    )

    def every_context_octet_is_bound() -> bool:
        baseline_leaf = leaf_body(
            base, 9, 0, b"x", randomizer, shape=SHAPE_SINGLE
        )
        baseline_commitment = commitment_body(
            base, 9, 1, SHAPE_SINGLE, None, bytes(32), randomizer
        )
        for offset in range(CONTEXT_OCTETS):
            altered = bytearray(expected_context)
            altered[offset] ^= 0x01
            try:
                parsed = parse_context(bytes(altered))
            except ModelInputError:
                if offset >= 4:
                    return False
                continue
            if encode_context(parsed) != bytes(altered):
                return False
            if leaf_body(parsed, 9, 0, b"x", randomizer, shape=SHAPE_SINGLE) == baseline_leaf:
                return False
            if (
                commitment_body(
                    parsed, 9, 1, SHAPE_SINGLE, None, bytes(32), randomizer
                )
                == baseline_commitment
            ):
                return False
        return True

    add(
        "C34-EVERY-CONTEXT-OCTET-BOUND",
        "exact-context-and-inverse",
        "independent mutation of every context octet rejects or changes both B_L and B_C",
        _passes(every_context_octet_is_bound),
    )
    add(
        "C35-EVERY-TRUNCATION-REJECTED",
        "exact-context-and-inverse",
        "every strict context prefix is rejected rather than padded or defaulted",
        _passes(
            lambda: all(
                _rejects(lambda cut=cut: parse_context(expected_context[:cut]), "CONTEXT_LENGTH")[0]
                for cut in range(CONTEXT_OCTETS)
            )
        ),
    )

    def reordered_fields_are_distinct_or_rejected() -> bool:
        fields = [
            expected_context[0:2],
            expected_context[2:4],
            expected_context[4:8],
            expected_context[8:12],
            expected_context[12:44],
            expected_context[44:76],
            expected_context[76:84],
        ]
        for index in range(len(fields) - 1):
            reordered = list(fields)
            reordered[index], reordered[index + 1] = reordered[index + 1], reordered[index]
            candidate = b"".join(reordered)
            if candidate == expected_context:
                continue
            try:
                parsed = parse_context(candidate)
            except ModelInputError:
                continue
            if encode_context(parsed) != candidate:
                return False
        return True

    add(
        "C36-FIELD-ORDER-IS-FIXED",
        "exact-context-and-inverse",
        "every semantically distinct adjacent field reordering rejects or decodes only at fixed positions",
        _passes(reordered_fields_are_distinct_or_rejected),
        "M03_REORDER_FIELDS",
    )
    add(
        "C37-NEGATIVE-SEQUENCE-REJECTED",
        "sequence-and-credential-boundaries",
        "negative author sequence is rejected rather than signed-reinterpreted",
        _rejects(lambda: encode_context(context(sequence=-1)), "INTEGER_RANGE"),
    )

    unknown_protocol = bytearray(expected_context)
    unknown_protocol[2:4] = b"\x00\x02"
    add(
        "C38-UNKNOWN-PROTOCOL-REJECTED",
        "suite-selection-fail-closed",
        "an unknown carried protocol version cannot select a parser profile",
        _rejects(lambda: parse_context(bytes(unknown_protocol)), "UNKNOWN_PROTOCOL"),
    )

    legacy_leaf = frame(
        D_LEAF,
        leaf_body(
            base,
            9,
            0,
            b"x",
            randomizer,
            shape=SHAPE_SINGLE,
            mutation=Mutation("M08_BIND_ONLY_COMMITMENT"),
        ),
    )
    legacy_commitment = frame(
        D_COMMIT,
        commitment_body(
            base,
            9,
            1,
            SHAPE_SINGLE,
            None,
            bytes(32),
            randomizer,
            Mutation("M09_BIND_ONLY_LEAF"),
        ),
    )
    add(
        "C39-MIXED-PROFILE-REJECTED",
        "legacy-downgrade-rejection",
        "legacy leaf or commitment bodies cannot be mixed into the selected profile",
        _passes(
            lambda: _rejects(lambda: parse_leaf_preimage(legacy_leaf))[0]
            and _rejects(lambda: parse_commitment_preimage(legacy_commitment))[0]
        ),
    )

    canonical_node = node_preimage(2, bytes.fromhex("11" * 32), bytes.fromhex("22" * 32))
    add(
        "C40-NODE-INVERSE-EXACT-END",
        "interior-node-invariance",
        "the unchanged interior-node form round-trips and rejects trailing bytes",
        _passes(
            lambda: parse_node_preimage(canonical_node)["subtree_leaf_count"] == 2
            and parse_node_preimage(canonical_node)["left_child"] == bytes.fromhex("11" * 32)
            and _rejects(lambda: parse_node_preimage(canonical_node + b"\x00"), "TRAILING_BYTES")[0]
        ),
    )
    add(
        "C41-LEN32-BOUNDARY-NO-ALLOCATION",
        "exact-widths-and-ceilings",
        "leaf length arithmetic accepts below/at the ceiling and rejects above it without allocation",
        _passes(
            lambda: leaf_preimage_lengths(MAX_LEAF_OCTETS - 1)
            == (MAX_LEN32 - 1, MAX_LEN32 + 19)
            and leaf_preimage_lengths(MAX_LEAF_OCTETS)
            == (MAX_LEN32, MAX_LEN32 + 20)
            and _rejects(
                lambda: leaf_preimage_lengths(MAX_LEAF_OCTETS + 1), "LEAF_LENGTH"
            )[0]
        ),
    )
    add(
        "C42-MINIMUM-TWO-LEAF-TREE",
        "single-and-tree-roundtrip",
        "the minimum TREE has exactly two leaves and one interior node",
        _passes(
            lambda: len(build_commitment(base, 9, b"ab", randomizer, chunk_size=1).leaf_preimages)
            == 2
            and len(build_commitment(base, 9, b"ab", randomizer, chunk_size=1).node_preimages)
            == 1
        ),
    )
    add(
        "C43-COMPLETE-OBJECT-AND-REMOVAL-BOUNDARY",
        "control-and-removal-non-expansion",
        "C0.2k exposes no inclusion proof or removal/destruction authority",
        _passes(
            lambda: not partial_verification_supported()
            and successful_verification_claims()
            == {"CONTEXT_BOUND_COMMITMENT"}
            and not commitment_required_for_content_class("NONE")
        ),
    )

    return Suite(tuple(checks))


def declared_mutation_coverage() -> dict[str, tuple[str, ...]]:
    suite = run_required_suite()
    result: dict[str, list[str]] = {identifier: [] for identifier in REQUIRED_MUTANTS}
    for check in suite.checks:
        for identifier in check.kills:
            result[identifier].append(check.identifier)
    return {identifier: tuple(sorted(values)) for identifier, values in result.items()}
