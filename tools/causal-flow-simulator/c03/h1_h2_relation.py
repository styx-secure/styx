#!/usr/bin/env python3
"""Package-A H1/H2 hostile relation and executable evidence entry point."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import dataclass
import getpass
from hashlib import new as new_hash
from hashlib import sha256, sha512
import os
import json
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from typing import Final


ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[2]
O14 = ROOT.parent / "o14"
BASE_SHA = "16274cc194cd2f8f7b631332687a252bad92ce02"
sys.path.insert(0, str(O14))

from canonical_json import dumps, loads, store  # noqa: E402
from corpus_model import (  # noqa: E402
    DOMAINS,
    _L,
    ed25519_evidence_counts,
    ed25519_sign,
    ed25519_verify_detailed,
    encode_commitment,
    encode_event,
    encode_genesis,
    evaluate_k_admission_graph,
    evaluate_vector,
    framed_hash,
    reset_ed25519_evidence_counts,
    synthetic_octets,
    _classify_reference_identities,
)
from ed25519_reference import (  # noqa: E402
    BASE,
    P,
    Point,
    add,
    challenge,
    decode,
    encode,
    scalar_mult,
)
from generate_corpus import (  # noqa: E402
    _application_vector,
    _event_fields,
    _k_admission_vectors,
)
from scenarios import required_witnesses  # noqa: E402


class RelationError(ValueError):
    """The literal Package-A evidence relation is incomplete or ambiguous."""


@dataclass(frozen=True)
class RelationRow:
    row_id: str
    scenario_id: str
    expected: str
    order: tuple[str, ...] = ()


@dataclass(frozen=True)
class MutationSpec:
    identifier: str
    python_anchor: str
    python_replacement: str
    javascript_anchor: str
    javascript_replacement: str


@dataclass(frozen=True)
class IssueAppendixAuthority:
    slot_rows: tuple[tuple[str, str, str, str], ...]
    mutant_rows: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class V4Authority:
    slot_rows: tuple[tuple[str, str, str, str], ...]
    mutant_rows: tuple[tuple[str, str], ...]
    mutant_kill_rows: tuple[tuple[str, tuple[str, ...]], ...]
    documentation_blocks: tuple[tuple[str, bytes], ...]
    historical_insert_anchor: bytes
    historical_insert_block: bytes
    historical_replacements: tuple[tuple[bytes, bytes], ...]
    reconstructed_pins: tuple[tuple[str, str], ...]
    tep_filenames: tuple[str, ...]
    tep_argument_names: tuple[str, ...]
    tool_names: tuple[str, ...]
    environment_spec: tuple[str, ...]
    command_ids: tuple[str, ...]


H1_BOUNDARY: Final = (
    RelationRow("H1-BND-001", "positive", "ACCEPTED"),
    RelationRow("H1-BND-002", "novel-positive", "ACCEPTED"),
    RelationRow("H1-BND-003", "empty-transcript", "ACCEPTED"),
    RelationRow("H1-BND-004", "one-octet-transcript", "ACCEPTED"),
    RelationRow("H1-BND-005", "max-representative-transcript", "ACCEPTED"),
    RelationRow("H1-BND-006", "altered-transcript", "SIGNATURE_INVALID"),
    RelationRow("H1-BND-007", "other-key", "SIGNATURE_INVALID"),
    RelationRow("H1-BND-008", "other-signature", "SIGNATURE_INVALID"),
    RelationRow("H1-BND-009", "zero-length-key", "PUBLIC_KEY_LENGTH"),
    RelationRow("H1-BND-010", "truncated-key", "PUBLIC_KEY_LENGTH"),
    RelationRow("H1-BND-011", "extended-key", "PUBLIC_KEY_LENGTH"),
    RelationRow("H1-BND-012", "zero-length-signature", "SIGNATURE_LENGTH"),
    RelationRow("H1-BND-013", "truncated-signature", "SIGNATURE_LENGTH"),
    RelationRow("H1-BND-014", "extended-signature", "SIGNATURE_LENGTH"),
    RelationRow("H1-BND-015", "scalar-equals-l", "NON_CANONICAL_SCALAR"),
    RelationRow("H1-BND-016", "scalar-greater-l", "NON_CANONICAL_SCALAR"),
    RelationRow("H1-BND-017", "scalar-plus-l", "NON_CANONICAL_SCALAR"),
    RelationRow("H1-BND-018", "bitflip-r", "OFF_CURVE_POINT"),
    RelationRow("H1-BND-019", "noncanonical-r", "NON_CANONICAL_POINT"),
    RelationRow("H1-BND-020", "bitflip-s", "SIGNATURE_INVALID"),
    RelationRow("H1-BND-021", "reverse-signature", "OFF_CURVE_POINT"),
    RelationRow(
        "H1-BND-022", "all-zero-key", "PUBLIC_KEY_NOT_PRIME_ORDER"
    ),
    RelationRow("H1-BND-023", "identity-key", "PUBLIC_KEY_NOT_PRIME_ORDER"),
    RelationRow("H1-BND-024", "noncanonical-key", "NON_CANONICAL_POINT"),
    RelationRow("H1-BND-025", "off-curve-key", "OFF_CURVE_POINT"),
    RelationRow(
        "H1-BND-026", "mixed-order-key", "PUBLIC_KEY_NOT_PRIME_ORDER"
    ),
    RelationRow(
        "H1-BND-027", "mixed-order-key-2", "PUBLIC_KEY_NOT_PRIME_ORDER"
    ),
    RelationRow(
        "H1-BND-028",
        "mixed-order-cofactorless-valid",
        "PUBLIC_KEY_NOT_PRIME_ORDER",
    ),
    RelationRow("H1-BND-029", "small-order-r", "R_NOT_PRIME_ORDER"),
)


_CONNECTED_ROWS: Final = (
    ("valid-genesis", "GENESIS_ACCEPTED_EQ1"),
    ("valid-root-ordinary", "ADMITTED_EQ1"),
    ("valid-root-grant", "GRANT_ADMITTED_BINDING_1"),
    ("valid-grantee-descendant", "ADMITTED_UNDER_GRANTEE_EQ1"),
    ("valid-nonroot-grant-descendant", "NONROOT_GRANT_CHAIN_ADMITTED"),
    ("identity-genesis-key", "PREACCEPTED_GENESIS_INVALID_EQ0"),
    ("all-zero-genesis-key", "PREACCEPTED_GENESIS_INVALID_EQ0"),
    ("mixed-order-genesis-key", "PREACCEPTED_GENESIS_INVALID_EQ0"),
    ("noncanonical-genesis-key", "PREACCEPTED_GENESIS_INVALID_EQ0"),
    ("off-curve-genesis-key", "PREACCEPTED_GENESIS_INVALID_EQ0"),
    ("identity-event-r", "INVALID_S3_EQ0"),
    ("small-order-event-r", "INVALID_S3_EQ0"),
    ("mixed-order-event-r", "INVALID_S3_EQ0"),
    ("noncanonical-event-r", "INVALID_S3_EQ0"),
    ("off-curve-event-r", "INVALID_S3_EQ0"),
    ("event-s-equals-l", "INVALID_S3_EQ0"),
    ("event-s-greater-l", "INVALID_S3_EQ0"),
    ("event-s-plus-l", "INVALID_S3_EQ0"),
    ("guard-valid-bad-equation", "INVALID_S3_EQ1"),
    ("truncated-event-signature", "INVALID_S3_EQ0"),
    ("extended-event-signature", "INVALID_S3_EQ0"),
    ("grant-identity-key-with-descendant", "LAZY_GRANT_DESCENDANT_INVALID"),
    ("grant-all-zero-key-with-descendant", "LAZY_GRANT_DESCENDANT_INVALID"),
    ("grant-mixed-order-key-with-descendant", "LAZY_GRANT_DESCENDANT_INVALID"),
    ("grant-noncanonical-key-with-descendant", "LAZY_GRANT_DESCENDANT_INVALID"),
    ("grant-off-curve-key-with-descendant", "LAZY_GRANT_DESCENDANT_INVALID"),
    ("valid-grant-invalid-descendant-r", "GRANT_RETAINED_DESCENDANT_INVALID"),
    ("grant-short-key", "STRUCTURAL_REJECTION_S3"),
    ("grant-overlong-key", "CURRENT_OBJECT_OUT_OF_PROFILE_S3"),
    ("disconnected-identity-genesis-key", "INVALID_S3_EQ0"),
    ("disconnected-all-zero-genesis-key", "INVALID_S3_EQ0"),
    ("disconnected-mixed-order-genesis-key", "INVALID_S3_EQ0"),
    ("disconnected-noncanonical-genesis-key", "INVALID_S3_EQ0"),
    ("disconnected-off-curve-genesis-key", "INVALID_S3_EQ0"),
    ("disconnected-small-order-binding-key", "INVALID_S3_EQ0"),
)
H1_CONNECTED: Final = tuple(
    RelationRow(f"H1-CON-{index:03d}", scenario, expected)
    for index, (scenario, expected) in enumerate(_CONNECTED_ROWS, 1)
)


_SLOT_ROWS: Final = (
    ("required-missing-siblings-01", "A>B", "A,B:FORK_EVIDENCE"),
    ("required-missing-siblings-02", "B>A", "A,B:FORK_EVIDENCE"),
    ("pending-parent-siblings-01", "P>A>B", "P:PENDING_OPENING;A,B:FORK_EVIDENCE"),
    ("pending-parent-siblings-02", "P>B>A", "P:PENDING_OPENING;A,B:FORK_EVIDENCE"),
    ("pending-parent-siblings-03", "A>P>B", "P:PENDING_OPENING;A,B:FORK_EVIDENCE"),
    ("pending-parent-siblings-04", "A>B>P", "P:PENDING_OPENING;A,B:FORK_EVIDENCE"),
    ("pending-parent-siblings-05", "B>P>A", "P:PENDING_OPENING;A,B:FORK_EVIDENCE"),
    ("pending-parent-siblings-06", "B>A>P", "P:PENDING_OPENING;A,B:FORK_EVIDENCE"),
    ("mixed-ready-pending-siblings-01", "READY>PENDING", "READY,PENDING:FORK_EVIDENCE"),
    ("mixed-ready-pending-siblings-02", "PENDING>READY", "READY,PENDING:FORK_EVIDENCE"),
    ("three-way-slot-01", "A>B>C", "A,B,C:FORK_EVIDENCE"),
    ("three-way-slot-02", "A>C>B", "A,B,C:FORK_EVIDENCE"),
    ("three-way-slot-03", "B>A>C", "A,B,C:FORK_EVIDENCE"),
    ("three-way-slot-04", "B>C>A", "A,B,C:FORK_EVIDENCE"),
    ("three-way-slot-05", "C>A>B", "A,B,C:FORK_EVIDENCE"),
    ("three-way-slot-06", "C>B>A", "A,B,C:FORK_EVIDENCE"),
    ("invalid-signature-would-be-sibling-01", "VALID>BAD_SIG", "VALID:ADMITTED;BAD_SIG:INVALID"),
    ("invalid-signature-would-be-sibling-02", "BAD_SIG>VALID", "VALID:ADMITTED;BAD_SIG:INVALID"),
    ("lazy-bad-grantee-key-sibling-01", "VALID>BAD_GRANTEE_KEY", "VALID,BAD_GRANTEE_KEY:FORK_EVIDENCE"),
    ("lazy-bad-grantee-key-sibling-02", "BAD_GRANTEE_KEY>VALID", "VALID,BAD_GRANTEE_KEY:FORK_EVIDENCE"),
    ("distinct-credential-same-sequence-01", "CRED_A>CRED_B", "CRED_A,CRED_B:ADMITTED"),
    ("distinct-credential-same-sequence-02", "CRED_B>CRED_A", "CRED_A,CRED_B:ADMITTED"),
    ("duplicate-exact-reference-01", "A>A", "A:DUPLICATE_LOGICAL"),
    ("presented-reference-collision-01", "VALID>COLLISION", "VALID:ADMITTED;COLLISION:REFERENCE_COLLISION_UNSUPPORTED"),
    ("presented-reference-collision-02", "COLLISION>VALID", "VALID:ADMITTED;COLLISION:REFERENCE_COLLISION_UNSUPPORTED"),
    ("fork-descendant-independent-01", "A>B>D>I", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-02", "A>B>I>D", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-03", "A>D>B>I", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-04", "A>D>I>B", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-05", "A>I>B>D", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-06", "A>I>D>B", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-07", "B>A>D>I", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-08", "B>A>I>D", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-09", "B>D>A>I", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-10", "B>D>I>A", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-11", "B>I>A>D", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-12", "B>I>D>A", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-13", "D>A>B>I", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-14", "D>A>I>B", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-15", "D>B>A>I", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-16", "D>B>I>A", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-17", "D>I>A>B", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-18", "D>I>B>A", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-19", "I>A>B>D", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-20", "I>A>D>B", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-21", "I>B>A>D", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-22", "I>B>D>A", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-23", "I>D>A>B", "A,B:FORK;D,I:ADMITTED"),
    ("fork-descendant-independent-24", "I>D>B>A", "A,B:FORK;D,I:ADMITTED"),
    ("pending-parent-invalid-descendant", "P>X_BAD_SIG", "P:PENDING_OPENING;X_BAD_SIG:INVALID"),
    ("authenticated-pending-chain", "P>X>Y", "P:PENDING_OPENING;X,Y:PENDING_ANCESTOR"),
    ("pending-plus-rejected-dependency", "P>BAD_DEP>X", "P:PENDING_OPENING;BAD_DEP:REJECTED;X:DEPENDENCY_DEFERRED"),
    ("detachable-missing-opening-would-be-sibling", "VALID>BAD", "VALID:ADMITTED;BAD:OPENING_MISSING"),
    ("commitment-mismatch-would-be-sibling", "VALID>BAD", "VALID:ADMITTED;BAD:COMMITMENT_MISMATCH"),
    ("length-mismatch-would-be-sibling", "VALID>BAD", "VALID:ADMITTED;BAD:LENGTH_MISMATCH"),
    ("unresolved-binding-would-be-sibling", "VALID>BAD", "VALID:ADMITTED;BAD:UNRESOLVED_CREDENTIAL_BINDING"),
    ("structural-failure-would-be-sibling", "VALID>BAD", "VALID:ADMITTED;BAD:STRUCTURAL_REJECTION"),
    ("absent-dependency-would-be-sibling", "VALID>BAD", "VALID:ADMITTED;BAD:DEPENDENCY_DEFERRED"),
    ("capacity-failure-would-be-sibling", "VALID>BAD", "VALID:ADMITTED;BAD:CONTEXT_CAPACITY_EXHAUSTED"),
    ("fork-under-fork", "A>B>D1>D2", "A,B,D1,D2:FORK_EVIDENCE"),
    ("pending-fork-sibling-descendant", "A>B>D", "A,B:FORK_EVIDENCE;D:PENDING_ANCESTOR"),
    ("pending-plus-absent-dependency", "P>X", "P:PENDING_OPENING;X:DEPENDENCY_DEFERRED"),
    ("valid-signature-alias-01", "V>A>I", "V,A:ADMITTED_COALESCED_2_EFFECT_1;I:ADMITTED_COALESCED_1_EFFECT_1"),
    ("valid-signature-alias-02", "V>I>A", "V,A:ADMITTED_COALESCED_2_EFFECT_1;I:ADMITTED_COALESCED_1_EFFECT_1"),
    ("valid-signature-alias-03", "A>V>I", "V,A:ADMITTED_COALESCED_2_EFFECT_1;I:ADMITTED_COALESCED_1_EFFECT_1"),
    ("valid-signature-alias-04", "A>I>V", "V,A:ADMITTED_COALESCED_2_EFFECT_1;I:ADMITTED_COALESCED_1_EFFECT_1"),
    ("valid-signature-alias-05", "I>V>A", "V,A:ADMITTED_COALESCED_2_EFFECT_1;I:ADMITTED_COALESCED_1_EFFECT_1"),
    ("valid-signature-alias-06", "I>A>V", "V,A:ADMITTED_COALESCED_2_EFFECT_1;I:ADMITTED_COALESCED_1_EFFECT_1"),
    ("invalid-signature-alias-01", "V>B>I", "B:INVALID_0_0;V,I:ADMITTED_1_1"),
    ("invalid-signature-alias-02", "V>I>B", "B:INVALID_0_0;V,I:ADMITTED_1_1"),
    ("invalid-signature-alias-03", "B>V>I", "B:INVALID_0_0;V,I:ADMITTED_1_1"),
    ("invalid-signature-alias-04", "B>I>V", "B:INVALID_0_0;V,I:ADMITTED_1_1"),
    ("invalid-signature-alias-05", "I>V>B", "B:INVALID_0_0;V,I:ADMITTED_1_1"),
    ("invalid-signature-alias-06", "I>B>V", "B:INVALID_0_0;V,I:ADMITTED_1_1"),
    ("verified-opening-alias-01", "O>M>I", "O,M:ADMITTED_COALESCED_2_EFFECT_1;I:ADMITTED_1_1"),
    ("verified-opening-alias-02", "O>I>M", "O,M:ADMITTED_COALESCED_2_EFFECT_1;I:ADMITTED_1_1"),
    ("verified-opening-alias-03", "M>O>I", "O,M:ADMITTED_COALESCED_2_EFFECT_1;I:ADMITTED_1_1"),
    ("verified-opening-alias-04", "M>I>O", "O,M:ADMITTED_COALESCED_2_EFFECT_1;I:ADMITTED_1_1"),
    ("verified-opening-alias-05", "I>O>M", "O,M:ADMITTED_COALESCED_2_EFFECT_1;I:ADMITTED_1_1"),
    ("verified-opening-alias-06", "I>M>O", "O,M:ADMITTED_COALESCED_2_EFFECT_1;I:ADMITTED_1_1"),
    ("wrong-opening-alias-01", "O>W>I", "W:COMMITMENT_MISMATCH_0_0;O,I:ADMITTED_1_1"),
    ("wrong-opening-alias-02", "O>I>W", "W:COMMITMENT_MISMATCH_0_0;O,I:ADMITTED_1_1"),
    ("wrong-opening-alias-03", "W>O>I", "W:COMMITMENT_MISMATCH_0_0;O,I:ADMITTED_1_1"),
    ("wrong-opening-alias-04", "W>I>O", "W:COMMITMENT_MISMATCH_0_0;O,I:ADMITTED_1_1"),
    ("wrong-opening-alias-05", "I>O>W", "W:COMMITMENT_MISMATCH_0_0;O,I:ADMITTED_1_1"),
    ("wrong-opening-alias-06", "I>W>O", "W:COMMITMENT_MISMATCH_0_0;O,I:ADMITTED_1_1"),
    ("true-reference-collision-01", "C1>C2>I", "C1,C2:REFERENCE_COLLISION_UNSUPPORTED;I:UNIQUE"),
    ("true-reference-collision-02", "C2>C1>I", "C1,C2:REFERENCE_COLLISION_UNSUPPORTED;I:UNIQUE"),
    ("unauthenticated-correct-opening-01", "M>B_OPEN>I", "M:PENDING_1_1;B_OPEN:INVALID_0_0;I:ADMITTED_1_1"),
    ("unauthenticated-correct-opening-02", "M>I>B_OPEN", "M:PENDING_1_1;B_OPEN:INVALID_0_0;I:ADMITTED_1_1"),
    ("unauthenticated-correct-opening-03", "B_OPEN>M>I", "M:PENDING_1_1;B_OPEN:INVALID_0_0;I:ADMITTED_1_1"),
    ("unauthenticated-correct-opening-04", "B_OPEN>I>M", "M:PENDING_1_1;B_OPEN:INVALID_0_0;I:ADMITTED_1_1"),
    ("unauthenticated-correct-opening-05", "I>M>B_OPEN", "M:PENDING_1_1;B_OPEN:INVALID_0_0;I:ADMITTED_1_1"),
    ("unauthenticated-correct-opening-06", "I>B_OPEN>M", "M:PENDING_1_1;B_OPEN:INVALID_0_0;I:ADMITTED_1_1"),
    ("wrong-opening-cannot-supply-01", "M>W>I", "M:PENDING_1_1;W:COMMITMENT_MISMATCH_0_0;I:ADMITTED_1_1"),
    ("wrong-opening-cannot-supply-02", "M>I>W", "M:PENDING_1_1;W:COMMITMENT_MISMATCH_0_0;I:ADMITTED_1_1"),
    ("wrong-opening-cannot-supply-03", "W>M>I", "M:PENDING_1_1;W:COMMITMENT_MISMATCH_0_0;I:ADMITTED_1_1"),
    ("wrong-opening-cannot-supply-04", "W>I>M", "M:PENDING_1_1;W:COMMITMENT_MISMATCH_0_0;I:ADMITTED_1_1"),
    ("wrong-opening-cannot-supply-05", "I>M>W", "M:PENDING_1_1;W:COMMITMENT_MISMATCH_0_0;I:ADMITTED_1_1"),
    ("wrong-opening-cannot-supply-06", "I>W>M", "M:PENDING_1_1;W:COMMITMENT_MISMATCH_0_0;I:ADMITTED_1_1"),
)
H2_SLOTS: Final = tuple(
    RelationRow(
        f"H2-SLT-{index:03d}",
        scenario,
        expected,
        tuple(order.split(">")),
    )
    for index, (scenario, order, expected) in enumerate(_SLOT_ROWS, 1)
)


MUTANTS: Final = (
    "M-H1-A-CANONICAL",
    "M-H1-A-ORDER",
    "M-H1-R-CANONICAL",
    "M-H1-R-ORDER",
    "M-H1-S-BOUND",
    "M-H1-EARLY-EQUATION",
    "M-H1-GUARD-ONLY-ACCEPT",
    "M-H1-DOUBLE-VERIFY",
    "M-H1-RAW-FALLBACK",
    "M-H2-OPENING-FIRST",
    "M-H2-INCLUDE-K-REJECTED",
    "M-H2-ARRIVAL-WINNER",
    "M-H2-CROSS-CREDENTIAL",
    "M-H2-PREDECESSOR-IN-KEY",
    "M-H2-PENDING-OUTRANKS-FORK",
    "M-H2-PENDING-AS-MISSING",
    "M-H2-SKIP-AUTH-UNDER-PENDING",
    "M-H2-ANY-PENDING-DEP",
    "M-H1-GENESIS-BYPASS-BOUNDARY",
    "M-H1-GRANT-KEY-EAGER-REJECT",
    "M-H2-GLOBAL-REFERENCE-ABORT",
    "M-H2-ALIAS-BEFORE-AUTH",
    "M-H2-ALIAS-POISON",
    "M-H2-ALIAS-MULTI-EFFECT",
)

# Exact Appendix-A prose is provider-owned input, not an oracle generated by
# the candidate.  These closed translations make the final gate bind every
# ratified observation and mutant description to the executable relation while
# keeping the runtime reports on their compact evidence-only vocabulary.
APPENDIX_CONNECTED_OBSERVATIONS: Final = {
    "preaccepted genesis accepted; one equation call": "GENESIS_ACCEPTED_EQ1",
    "root-authored NONE event K-admitted; one equation call": "ADMITTED_EQ1",
    "valid GRANT creates exactly one binding": "GRANT_ADMITTED_BINDING_1",
    "descendant verifies under the admitted GRANT key": "ADMITTED_UNDER_GRANTEE_EQ1",
    "non-root issuer GRANT and descendant both remain K-valid": "NONROOT_GRANT_CHAIN_ADMITTED",
    "graph precondition fails; zero equation calls": "PREACCEPTED_GENESIS_INVALID_EQ0",
    "INVALID at S3; zero equation calls": "INVALID_S3_EQ0",
    "INVALID at S3; exactly one equation call": "INVALID_S3_EQ1",
    "lazy rule: GRANT admitted; attempted descendant INVALID at S3; zero equations; no fork": "LAZY_GRANT_DESCENDANT_INVALID",
    "GRANT admitted; descendant INVALID at S3; binding unchanged": "GRANT_RETAINED_DESCENDANT_INVALID",
    "carrying GRANT STRUCTURAL_REJECTION at S3 before binding": "STRUCTURAL_REJECTION_S3",
    "canonically framed carrying GRANT CURRENT_OBJECT_OUT_OF_PROFILE at S3 before binding": "CURRENT_OBJECT_OUT_OF_PROFILE_S3",
    "evaluate_vector GENESIS INVALID at S3; zero equations": "INVALID_S3_EQ0",
    "evaluate_vector APPLICATION_EVENT INVALID at S3; zero equations": "INVALID_S3_EQ0",
}

APPENDIX_SLOT_OBSERVATIONS: Final = {
    "A,B => FORK_EVIDENCE": "A,B:FORK_EVIDENCE",
    "P => PENDING_OPENING; A,B => FORK_EVIDENCE": "P:PENDING_OPENING;A,B:FORK_EVIDENCE",
    "READY,PENDING => FORK_EVIDENCE": "READY,PENDING:FORK_EVIDENCE",
    "A,B,C => FORK_EVIDENCE as one complete slot": "A,B,C:FORK_EVIDENCE",
    "VALID admitted without fork; BAD_SIG => INVALID": "VALID:ADMITTED;BAD_SIG:INVALID",
    "lazy rule: both authenticated carrying events => FORK_EVIDENCE; bad carried key creates no usable signer": "VALID,BAD_GRANTEE_KEY:FORK_EVIDENCE",
    "both admitted; no fork": "CRED_A,CRED_B:ADMITTED",
    "same bytes, reference and id presented twice; one logical event; duplicate/idempotent; no fork": "A:DUPLICATE_LOGICAL",
    "COLLISION has different bytes but declares VALID's reference; COLLISION => REFERENCE_COLLISION_UNSUPPORTED S3; VALID unaffected; no fork": "VALID:ADMITTED;COLLISION:REFERENCE_COLLISION_UNSUPPORTED",
    "A,B => FORK_EVIDENCE; D remains authenticated dependency evidence; I admitted independently": "A,B:FORK;D,I:ADMITTED",
    "P => PENDING_OPENING; X_BAD_SIG => INVALID S3 and not admitted": "P:PENDING_OPENING;X_BAD_SIG:INVALID",
    "P => PENDING_OPENING; independently authenticated X,Y => PENDING_ANCESTOR": "P:PENDING_OPENING;X,Y:PENDING_ANCESTOR",
    "P => PENDING_OPENING; BAD_DEP permanently rejected; X => DEPENDENCY_DEFERRED S4, not PENDING_ANCESTOR": "P:PENDING_OPENING;BAD_DEP:REJECTED;X:DEPENDENCY_DEFERRED",
    "VALID admitted without fork; BAD => OPENING_MISSING S3": "VALID:ADMITTED;BAD:OPENING_MISSING",
    "VALID admitted without fork; BAD => COMMITMENT_MISMATCH S3": "VALID:ADMITTED;BAD:COMMITMENT_MISMATCH",
    "VALID admitted without fork; BAD => LENGTH_MISMATCH S3": "VALID:ADMITTED;BAD:LENGTH_MISMATCH",
    "VALID admitted without fork; BAD => UNRESOLVED_CREDENTIAL_BINDING S3": "VALID:ADMITTED;BAD:UNRESOLVED_CREDENTIAL_BINDING",
    "VALID admitted without fork; BAD => STRUCTURAL_REJECTION S3": "VALID:ADMITTED;BAD:STRUCTURAL_REJECTION",
    "VALID admitted without fork; BAD => DEPENDENCY_DEFERRED S4": "VALID:ADMITTED;BAD:DEPENDENCY_DEFERRED",
    "VALID admitted without fork; BAD => CONTEXT_CAPACITY_EXHAUSTED at S4_GRAPH_ADMISSION": "VALID:ADMITTED;BAD:CONTEXT_CAPACITY_EXHAUSTED",
    "A,B fork at sequence 1; D1 predecessor A and D2 predecessor B share the credential/sequence-2 slot; A,B,D1,D2 => FORK_EVIDENCE": "A,B,D1,D2:FORK_EVIDENCE",
    "A REQUIRED without opening and B is its sibling; A,B => FORK_EVIDENCE; authenticated D depending on A => PENDING_ANCESTOR": "A,B:FORK_EVIDENCE;D:PENDING_ANCESTOR",
    "P => PENDING_OPENING; independently authenticated X names P and one never-presented dependency; X => DEPENDENCY_DEFERRED S4, not PENDING_ANCESTOR": "P:PENDING_OPENING;X:DEPENDENCY_DEFERRED",
    "valid signature alias coalesces once": "V,A:ADMITTED_COALESCED_2_EFFECT_1;I:ADMITTED_COALESCED_1_EFFECT_1",
    "invalid signature alias cannot poison": "B:INVALID_0_0;V,I:ADMITTED_1_1",
    "verified opening alias supplies the logical event": "O,M:ADMITTED_COALESCED_2_EFFECT_1;I:ADMITTED_1_1",
    "wrong opening alias cannot poison": "W:COMMITMENT_MISMATCH_0_0;O,I:ADMITTED_1_1",
    "true collision is privately classified": "C1,C2:REFERENCE_COLLISION_UNSUPPORTED;I:UNIQUE",
    "unauthenticated opening supplies nothing": "M:PENDING_1_1;B_OPEN:INVALID_0_0;I:ADMITTED_1_1",
    "wrong opening supplies nothing": "M:PENDING_1_1;W:COMMITMENT_MISMATCH_0_0;I:ADMITTED_1_1",
}

APPENDIX_MUTANT_DESCRIPTIONS: Final = {
    "M-H1-A-CANONICAL": "remove canonical A decode",
    "M-H1-A-ORDER": "remove nonidentity/prime-order A guard",
    "M-H1-R-CANONICAL": "remove canonical R decode",
    "M-H1-R-ORDER": "remove nonidentity/prime-order R guard",
    "M-H1-S-BOUND": "reduce or omit S < L",
    "M-H1-EARLY-EQUATION": "invoke equation before all guards",
    "M-H1-GUARD-ONLY-ACCEPT": "accept guard-valid input without equation",
    "M-H1-DOUBLE-VERIFY": "invoke selected equation twice or batch-retry",
    "M-H1-RAW-FALLBACK": "accept through raw/default/fallback verifier",
    "M-H2-OPENING-FIRST": "remove pending candidates or construct slots only from ready/effective records before complete-slot classification",
    "M-H2-INCLUDE-K-REJECTED": "allow a K-rejected candidate to create a fork",
    "M-H2-ARRIVAL-WINNER": "retain first-arriving sibling as winner",
    "M-H2-CROSS-CREDENTIAL": "omit credential identifier from slot key",
    "M-H2-PREDECESSOR-IN-KEY": "include predecessor in slot identity",
    "M-H2-PENDING-OUTRANKS-FORK": "select pending outcome above fork",
    "M-H2-PENDING-AS-MISSING": "treat a K-admitted pending dependency as absent/S4 rejected",
    "M-H2-SKIP-AUTH-UNDER-PENDING": "classify a descendant PENDING_ANCESTOR without authenticating its signature, binding and structure",
    "M-H2-ANY-PENDING-DEP": "let one pending dependency hide another permanently rejected or absent dependency",
    "M-H1-GENESIS-BYPASS-BOUNDARY": "verify preaccepted or disconnected GENESIS without the selected guarded boundary",
    "M-H1-GRANT-KEY-EAGER-REJECT": "reject an authenticated exact-width GRANT solely because its carried grantee key fails point-membership guards under the selected lazy rule",
    "M-H2-GLOBAL-REFERENCE-ABORT": "abort connected evaluation instead of attributing each multi-presentation outcome per record",
    "M-H2-ALIAS-BEFORE-AUTH": "let one presentation authenticate another before all wrapper predicates are checked",
    "M-H2-ALIAS-POISON": "let an invalid signature or wrong opening suppress a valid presentation of the same event",
    "M-H2-ALIAS-MULTI-EFFECT": "insert one K-admitted logical reference or fork member more than once because it has valid aliases",
}

DETECTORS: Final = {
    "M-H1-A-CANONICAL": ("boundary", 23),
    "M-H1-A-ORDER": ("boundary", 22),
    "M-H1-R-CANONICAL": ("boundary", 18),
    "M-H1-R-ORDER": ("boundary", 28),
    "M-H1-S-BOUND": ("boundary", 14),
    "M-H1-EARLY-EQUATION": ("boundary", 14),
    "M-H1-GUARD-ONLY-ACCEPT": ("boundary", 5),
    "M-H1-DOUBLE-VERIFY": ("connected", 1),
    "M-H1-RAW-FALLBACK": ("connected", 5),
    "M-H2-OPENING-FIRST": ("slot", 0),
    "M-H2-INCLUDE-K-REJECTED": ("slot", 16),
    "M-H2-ARRIVAL-WINNER": ("slot", 0),
    "M-H2-CROSS-CREDENTIAL": ("slot", 20),
    "M-H2-PREDECESSOR-IN-KEY": ("slot", 59),
    "M-H2-PENDING-OUTRANKS-FORK": ("slot", 0),
    "M-H2-PENDING-AS-MISSING": ("slot", 50),
    "M-H2-SKIP-AUTH-UNDER-PENDING": ("slot", 49),
    "M-H2-ANY-PENDING-DEP": ("slot", 61),
    "M-H1-GENESIS-BYPASS-BOUNDARY": ("connected", 5),
    "M-H1-GRANT-KEY-EAGER-REJECT": ("connected", 21),
    "M-H2-GLOBAL-REFERENCE-ABORT": ("slot", 62),
    "M-H2-ALIAS-BEFORE-AUTH": ("slot", 68),
    "M-H2-ALIAS-POISON": ("slot", 68),
    "M-H2-ALIAS-MULTI-EFFECT": ("slot", 62),
}


_H1_MUTATION_SPECS: Final = (
    MutationSpec(
        "M-H1-A-CANONICAL",
        "        point_a = _ed_decode(public)\n",
        "        point_a = _ed_decode(public, enforce_canonical=False)\n",
        "  try { pointA = edDecode(publicKey); }\n",
        "  try { pointA = edDecode(publicKey, false); }\n",
    ),
    MutationSpec(
        "M-H1-A-ORDER",
        "    if point_a == identity or _ed_mul(_L, point_a) != identity:\n",
        "    if False and (point_a == identity or _ed_mul(_L, point_a) != identity):\n",
        "  if (edEqual(pointA, ED_IDENTITY) || !edEqual(edScalarMult(ED_L, pointA), ED_IDENTITY)) {\n",
        "  if (false && (edEqual(pointA, ED_IDENTITY) || !edEqual(edScalarMult(ED_L, pointA), ED_IDENTITY))) {\n",
    ),
    MutationSpec(
        "M-H1-R-CANONICAL",
        "        point_r = _ed_decode(signature[:32])\n",
        "        point_r = _ed_decode(signature[:32], enforce_canonical=False)\n",
        "  try { pointR = edDecode(signature.subarray(0, 32)); }\n",
        "  try { pointR = edDecode(signature.subarray(0, 32), false); }\n",
    ),
    MutationSpec(
        "M-H1-R-ORDER",
        "    if point_r == identity or _ed_mul(_L, point_r) != identity:\n",
        "    if False and (point_r == identity or _ed_mul(_L, point_r) != identity):\n",
        "  if (edEqual(pointR, ED_IDENTITY) || !edEqual(edScalarMult(ED_L, pointR), ED_IDENTITY)) {\n",
        "  if (false && (edEqual(pointR, ED_IDENTITY) || !edEqual(edScalarMult(ED_L, pointR), ED_IDENTITY))) {\n",
    ),
    MutationSpec(
        "M-H1-S-BOUND",
        "    if scalar >= _L:\n",
        "    if scalar >= 1 << 256:\n",
        "  if (scalar >= ED_L) return { accepted: false, equationInvocations: 0, guardCode: \"NON_CANONICAL_SCALAR\" };\n",
        "  if (scalar >= (1n << 256n)) return { accepted: false, equationInvocations: 0, guardCode: \"NON_CANONICAL_SCALAR\" };\n",
    ),
    MutationSpec(
        "M-H1-EARLY-EQUATION",
        """    scalar = int.from_bytes(signature[32:], "little")
    if scalar >= _L:
        return {
            "accepted": False,
            "equationInvocations": 0,
            "guardCode": "NON_CANONICAL_SCALAR",
        }
""",
        """    scalar = int.from_bytes(signature[32:], "little")
    early_challenge = int.from_bytes(
        sha512(signature[:32] + public + message).digest(), "little"
    ) % _L
    _ = _ed_mul(scalar) == _ed_add(
        point_r, _ed_mul(early_challenge, point_a)
    )
    if scalar >= _L:
        return {
            "accepted": False,
            "equationInvocations": 1,
            "guardCode": "NON_CANONICAL_SCALAR",
        }
""",
        """  const scalar = littleEndianInteger(signature.subarray(32));
  if (scalar >= ED_L) return { accepted: false, equationInvocations: 0, guardCode: "NON_CANONICAL_SCALAR" };
""",
        """  const scalar = littleEndianInteger(signature.subarray(32));
  const earlyPrefix = Buffer.from("302a300506032b6570032100", "hex");
  try {
    verifySignature(null, message, createPublicKey({ key: Buffer.concat([earlyPrefix, publicKey]), format: "der", type: "spki" }), signature);
  } catch {}
  if (scalar >= ED_L) return { accepted: false, equationInvocations: 1, guardCode: "NON_CANONICAL_SCALAR" };
""",
    ),
    MutationSpec(
        "M-H1-GUARD-ONLY-ACCEPT",
        "    accepted = selected_equation()\n",
        "    accepted = True\n",
        "    const accepted = selectedEquation();\n",
        "    const accepted = true;\n",
    ),
    MutationSpec(
        "M-H1-DOUBLE-VERIFY",
        "    observed = ed25519_verify_detailed(public, signature, message)\n",
        "    first = ed25519_verify_detailed(public, signature, message)\n    observed = ed25519_verify_detailed(public, signature, message)\n    observed[\"equationInvocations\"] += first[\"equationInvocations\"]\n",
        "  const observed = ed25519VerifyDetailed(publicKey, signature, message);\n",
        "  const first = ed25519VerifyDetailed(publicKey, signature, message);\n  const observed = ed25519VerifyDetailed(publicKey, signature, message);\n  observed.equationInvocations += first.equationInvocations;\n",
    ),
    MutationSpec(
        "M-H1-RAW-FALLBACK",
        "    return bool(observed[\"accepted\"])\n",
        "    return bool(observed[\"accepted\"]) or observed[\"guardCode\"] != \"GUARD_ACCEPTED\"\n",
        "  return observed.accepted;\n",
        "  return observed.accepted || observed.guardCode !== \"GUARD_ACCEPTED\";\n",
    ),
    MutationSpec(
        "M-H1-GENESIS-BYPASS-BOUNDARY",
        """    if not ed25519_verify(
        bytes.fromhex(genesis_fields["rootVerificationKeyHex"]),
        bytes.fromhex(genesis_record["signatureHex"]),
        genesis_transcript,
    ):
""",
        """    if False and not ed25519_verify(
        bytes.fromhex(genesis_fields["rootVerificationKeyHex"]),
        bytes.fromhex(genesis_record["signatureHex"]),
        genesis_transcript,
    ):
""",
        "  require(ed25519Verify(\n",
        "  require(true || ed25519Verify(\n",
    ),
)


_H2_MUTATION_SPECS: Final = (
    MutationSpec(
        "M-H2-OPENING-FIRST",
        """    for reference, event in admitted.items():
        fields = event["fields"]
""",
        """    for reference, event in admitted.items():
        if event["localPending"]:
            continue
        fields = event["fields"]
""",
        """  for (const [reference, event] of admitted) {
    const fields = event.fields;
""",
        """  for (const [reference, event] of admitted) {
    if (event.localPending) continue;
    const fields = event.fields;
""",
    ),
    MutationSpec(
        "M-H2-INCLUDE-K-REJECTED",
        """                if not transition_input_is_compatible(local) and not local_pending:
                    rejected[reference] = ProtocolError(
                        str(local_code or "INVALID"),
                        str(local.get("stage", "S3_KERNEL_STRUCTURAL")),
                    )
                    pending.remove(reference)
                    progress = True
                    continue
""",
        """                if not transition_input_is_compatible(local) and not local_pending:
                    admitted[reference] = {
                        "fields": fields,
                        "localPending": False,
                        "pendingLineage": False,
                        "record": record,
                    }
                    pending.remove(reference)
                    progress = True
                    continue
""",
        """        if (!transitionInputIsCompatible(local) && !localPending) {
          rejected.set(reference, {
            admitted: false,
            code: local.localOutcome ?? "INVALID",
            stage: local.stage ?? "S3_KERNEL_STRUCTURAL",
          });
          pending.delete(reference); progress = true; continue;
        }
""",
        """        if (!transitionInputIsCompatible(local) && !localPending) {
          admitted.set(reference, { fields, localPending: false, pendingLineage: false, record });
          pending.delete(reference); progress = true; continue;
        }
""",
    ),
    MutationSpec(
        "M-H2-ARRIVAL-WINNER",
        "        if error is None and reference in forced_forks:\n",
        "        if error is None and reference in forced_forks and reference != next(iter(record_order)):\n",
        "    if (error === undefined && forcedForks.has(reference)) {\n",
        "    if (error === undefined && forcedForks.has(reference) && reference !== identifiers.keys().next().value) {\n",
    ),
    MutationSpec(
        "M-H2-CROSS-CREDENTIAL",
        """        slot = (
            fields["contextIdentifierHex"],
            fields["credentialIdentifierHex"],
            fields["authorSequence"],
        )
""",
        """        slot = (
            fields["contextIdentifierHex"],
            fields["authorSequence"],
        )
""",
        "    const slot = `${fields.contextIdentifierHex}:${fields.credentialIdentifierHex}:${fields.authorSequence}`;\n",
        "    const slot = `${fields.contextIdentifierHex}:${fields.authorSequence}`;\n",
    ),
    MutationSpec(
        "M-H2-PREDECESSOR-IN-KEY",
        """        slot = (
            fields["contextIdentifierHex"],
            fields["credentialIdentifierHex"],
            fields["authorSequence"],
        )
""",
        """        slot = (
            fields["contextIdentifierHex"],
            fields["credentialIdentifierHex"],
            fields["authorSequence"],
            fields["directPredecessorHex"],
        )
""",
        "    const slot = `${fields.contextIdentifierHex}:${fields.credentialIdentifierHex}:${fields.authorSequence}`;\n",
        "    const slot = `${fields.contextIdentifierHex}:${fields.credentialIdentifierHex}:${fields.authorSequence}:${fields.directPredecessorHex}`;\n",
    ),
    MutationSpec(
        "M-H2-PENDING-OUTRANKS-FORK",
        """        if error is None and reference in forced_forks:
            error = ProtocolError("FORK_EVIDENCE", "EVENT_LOCAL", admitted=True)
        elif error is None and admitted[reference]["localPending"]:
            error = ProtocolError("PENDING_OPENING", "EVENT_LOCAL", admitted=True)
""",
        """        if error is None and admitted[reference]["localPending"]:
            error = ProtocolError("PENDING_OPENING", "EVENT_LOCAL", admitted=True)
        elif error is None and reference in forced_forks:
            error = ProtocolError("FORK_EVIDENCE", "EVENT_LOCAL", admitted=True)
""",
        """    if (error === undefined && forcedForks.has(reference)) {
      error = { admitted: true, code: "FORK_EVIDENCE", stage: "EVENT_LOCAL" };
    } else if (error === undefined && admitted.get(reference).localPending) {
      error = { admitted: true, code: "PENDING_OPENING", stage: "EVENT_LOCAL" };
""",
        """    if (error === undefined && admitted.get(reference).localPending) {
      error = { admitted: true, code: "PENDING_OPENING", stage: "EVENT_LOCAL" };
    } else if (error === undefined && forcedForks.has(reference)) {
      error = { admitted: true, code: "FORK_EVIDENCE", stage: "EVENT_LOCAL" };
""",
    ),
    MutationSpec(
        "M-H2-PENDING-AS-MISSING",
        "            absent = required - set(parsed)\n",
        "            absent = (required - set(parsed)) | {value for value in required if value in admitted and admitted[value][\"pendingLineage\"]}\n",
        "      const absent = [...required].some(value => !parsed.has(value));\n",
        "      const absent = [...required].some(value => !parsed.has(value) || admitted.get(value)?.pendingLineage === true);\n",
    ),
    MutationSpec(
        "M-H2-SKIP-AUTH-UNDER-PENDING",
        """            required = dependencies(fields)
            if reference not in local_results:
""",
        """            required = dependencies(fields)
            if any(value in admitted and admitted[value]["pendingLineage"] for value in required):
                admitted[reference] = {
                    "fields": fields,
                    "localPending": False,
                    "pendingLineage": True,
                    "record": record,
                }
                pending.remove(reference)
                progress = True
                continue
            if reference not in local_results:
""",
        """      const required = dependencies(fields);
      if (!localResults.has(reference)) {
""",
        """      const required = dependencies(fields);
      if ([...required].some(value => admitted.get(value)?.pendingLineage === true)) {
        admitted.set(reference, { fields, localPending: false, pendingLineage: true, record });
        pending.delete(reference); progress = true; continue;
      }
      if (!localResults.has(reference)) {
""",
    ),
    MutationSpec(
        "M-H2-ANY-PENDING-DEP",
        """            absent = required - set(parsed)
            failed = required & set(rejected)
            if absent or failed:
""",
        """            absent = required - set(parsed)
            failed = required & set(rejected)
            if any(value in admitted and admitted[value]["pendingLineage"] for value in required):
                admitted[reference] = {
                    "fields": fields,
                    "localPending": local_pending,
                    "pendingLineage": True,
                    "record": record,
                }
                pending.remove(reference)
                progress = True
                continue
            if absent or failed:
""",
        """      const absent = [...required].some(value => !parsed.has(value));
      const failed = [...required].some(value => rejected.has(value));
      if (absent || failed) {
""",
        """      const absent = [...required].some(value => !parsed.has(value));
      const failed = [...required].some(value => rejected.has(value));
      if ([...required].some(value => admitted.get(value)?.pendingLineage === true)) {
        admitted.set(reference, { fields, localPending, pendingLineage: true, record });
        pending.delete(reference); progress = true; continue;
      }
      if (absent || failed) {
""",
    ),
    MutationSpec(
        "M-H1-GRANT-KEY-EAGER-REJECT",
        """                    if kind == "GRANT":
                        if reference == genesis_reference or reference in bindings:
""",
        """                    if kind == "GRANT":
                        try:
                            carried = _ed_decode(bytes.fromhex(tail["granteeVerificationKeyHex"]))
                            if carried == (0, 1) or _ed_mul(_L, carried) != (0, 1):
                                raise ProtocolError("STRUCTURAL_REJECTION")
                        except (ValueError, ProtocolError) as error:
                            raise ProtocolError("STRUCTURAL_REJECTION") from error
                        if reference == genesis_reference or reference in bindings:
""",
        """          if (tail.kind === "GRANT") {
            require(reference !== genesisReference && !bindings.has(reference), "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED");
""",
        """          if (tail.kind === "GRANT") {
            let carried;
            try { carried = edDecode(Buffer.from(tail.granteeVerificationKeyHex, "hex")); }
            catch { throw new ProtocolError("STRUCTURAL_REJECTION"); }
            require(!edEqual(carried, ED_IDENTITY) && edEqual(edScalarMult(ED_L, carried), ED_IDENTITY), "STRUCTURAL_REJECTION");
            require(reference !== genesisReference && !bindings.has(reference), "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED");
""",
    ),
)

# V4 supersedes the six source anchors affected by presentation-indexed graph
# processing and appends four independently killed alias/collision mutants.
_V4_SUPERSEDED_MUTANTS: Final = frozenset(
    {
        "M-H2-INCLUDE-K-REJECTED",
        "M-H2-ARRIVAL-WINNER",
        "M-H2-PENDING-OUTRANKS-FORK",
        "M-H2-PENDING-AS-MISSING",
        "M-H2-SKIP-AUTH-UNDER-PENDING",
        "M-H2-ANY-PENDING-DEP",
    }
)
_H2_MUTATION_SPECS = tuple(
    spec for spec in _H2_MUTATION_SPECS
    if spec.identifier not in _V4_SUPERSEDED_MUTANTS
) + (
    MutationSpec(
        "M-H2-INCLUDE-K-REJECTED",
        """                    if (
                        not transition_input_is_compatible(local)
                        and not local_pending
                    ):
                        presentation_rejected[identifier] = ProtocolError(
                            str(local_code or "INVALID"),
                            str(local.get("stage", "S3_KERNEL_STRUCTURAL")),
                        )
""",
        """                    if (
                        not transition_input_is_compatible(local)
                        and not local_pending
                    ):
                        pass
""",
        """          if (!transitionInputIsCompatible(local) && !localPending) {
            presentationRejected.set(identifier, {
              admitted: false,
              code: local.localOutcome ?? "INVALID",
              stage: local.stage ?? "S3_KERNEL_STRUCTURAL",
            });
          }
""",
        """          if (!transitionInputIsCompatible(local) && !localPending) {
            // Mutant: include this K-rejected presentation.
          }
""",
    ),
    MutationSpec(
        "M-H2-ARRIVAL-WINNER",
        "        if error is None and reference in forced_forks:\n",
        "        if error is None and reference in forced_forks and identifier != next(iter(presentations)):\n",
        "      if (error === undefined && forcedForks.has(reference)) {\n",
        "      if (error === undefined && forcedForks.has(reference) && identifier !== presentations.keys().next().value) {\n",
    ),
    MutationSpec(
        "M-H2-PENDING-OUTRANKS-FORK",
        """        if error is None and reference in forced_forks:
            error = ProtocolError("FORK_EVIDENCE", "EVENT_LOCAL", admitted=True)
        elif error is None and logical["localPending"]:
            error = ProtocolError("PENDING_OPENING", "EVENT_LOCAL", admitted=True)
""",
        """        if error is None and logical["localPending"]:
            error = ProtocolError("PENDING_OPENING", "EVENT_LOCAL", admitted=True)
        elif error is None and reference in forced_forks:
            error = ProtocolError("FORK_EVIDENCE", "EVENT_LOCAL", admitted=True)
""",
        """      if (error === undefined && forcedForks.has(reference)) {
        error = { admitted: true, code: "FORK_EVIDENCE", stage: "EVENT_LOCAL" };
      } else if (error === undefined && logical.localPending) {
        error = { admitted: true, code: "PENDING_OPENING", stage: "EVENT_LOCAL" };
""",
        """      if (error === undefined && logical.localPending) {
        error = { admitted: true, code: "PENDING_OPENING", stage: "EVENT_LOCAL" };
      } else if (error === undefined && forcedForks.has(reference)) {
        error = { admitted: true, code: "FORK_EVIDENCE", stage: "EVENT_LOCAL" };
""",
    ),
    MutationSpec(
        "M-H2-PENDING-AS-MISSING",
        "            absent = required - set(logical_groups)\n",
        "            absent = (required - set(logical_groups)) | {value for value in required if value in admitted and admitted[value][\"pendingLineage\"]}\n",
        "      const absent = [...required].some(value => !logicalGroups.has(value));\n",
        "      const absent = [...required].some(value => !logicalGroups.has(value) || admitted.get(value)?.pendingLineage === true);\n",
    ),
    MutationSpec(
        "M-H2-SKIP-AUTH-UNDER-PENDING",
        """            for identifier in sorted(group["presentationIds"]):
                if identifier not in local_results:
""",
        """            for identifier in sorted(group["presentationIds"]):
                if any(value in admitted and admitted[value]["pendingLineage"] for value in required):
                    local_results[identifier] = ({"localOutcome": None}, False)
                if identifier not in local_results:
""",
        """      for (const identifier of [...group.presentationIds].sort()) {
        if (!localResults.has(identifier)) {
""",
        """      for (const identifier of [...group.presentationIds].sort()) {
        if ([...required].some(value => admitted.get(value)?.pendingLineage === true)) {
          localResults.set(identifier, { local: { localOutcome: null }, localPending: false });
        }
        if (!localResults.has(identifier)) {
""",
    ),
    MutationSpec(
        "M-H2-ANY-PENDING-DEP",
        """            absent = required - set(logical_groups)
            failed = required & set(logical_rejected)
            if absent or failed:
""",
        """            absent = required - set(logical_groups)
            failed = required & set(logical_rejected)
            if any(value in admitted and admitted[value]["pendingLineage"] for value in required):
                candidate_event = {
                    "fields": fields,
                    "k1PresentationIds": tuple(eligible),
                    "localPending": not ready,
                    "pendingLineage": True,
                    "record": presentations[(ready or eligible)[0]]["record"],
                }
                commit_admitted(reference, candidate_event)
                pending.remove(reference)
                progress = True
                continue
            if absent or failed:
""",
        """      const absent = [...required].some(value => !logicalGroups.has(value));
      const failed = [...required].some(value => logicalRejected.has(value));
      if (absent || failed) {
""",
        """      const absent = [...required].some(value => !logicalGroups.has(value));
      const failed = [...required].some(value => logicalRejected.has(value));
      if ([...required].some(value => admitted.get(value)?.pendingLineage === true)) {
        const candidateEvent = {
          fields, k1PresentationIds: eligible, localPending: ready.length === 0,
          pendingLineage: true,
          record: presentations.get((ready.length > 0 ? ready : eligible)[0]).record,
        };
        commitAdmitted(reference, candidateEvent);
        pending.delete(reference); progress = true; continue;
      }
      if (absent || failed) {
""",
    ),
    MutationSpec(
        "M-H2-GLOBAL-REFERENCE-ABORT",
        "        group[\"presentationIds\"].append(identifier)\n",
        "        if group[\"presentationIds\"]:\n            raise ProtocolError(\"REFERENCE_COLLISION_UNSUPPORTED\")\n        group[\"presentationIds\"].append(identifier)\n",
        "    logicalGroups.get(presentation.reference).presentationIds.push(identifier);\n",
        "    if (logicalGroups.get(presentation.reference).presentationIds.length > 0) throw new ProtocolError(\"REFERENCE_COLLISION_UNSUPPORTED\");\n    logicalGroups.get(presentation.reference).presentationIds.push(identifier);\n",
    ),
    MutationSpec(
        "M-H2-ALIAS-BEFORE-AUTH",
        """                    if (
                        not transition_input_is_compatible(local)
                        and not local_pending
                    ):
""",
        """                    if (
                        not transition_input_is_compatible(local)
                        and not local_pending
                        and len(group["presentationIds"]) == 1
                    ):
""",
        "          if (!transitionInputIsCompatible(local) && !localPending) {\n",
        "          if (!transitionInputIsCompatible(local) && !localPending && group.presentationIds.length === 1) {\n",
    ),
    MutationSpec(
        "M-H2-ALIAS-POISON",
        """            if not eligible:
                first = sorted(group["presentationIds"])[0]
""",
        """            if any(value in presentation_rejected for value in group["presentationIds"]):
                first = next(value for value in sorted(group["presentationIds"]) if value in presentation_rejected)
                logical_rejected[reference] = presentation_rejected[first]
                pending.remove(reference)
                progress = True
                continue
            if not eligible:
                first = sorted(group["presentationIds"])[0]
""",
        """      if (eligible.length === 0) {
        logicalRejected.set(reference, presentationRejected.get([...group.presentationIds].sort()[0]));
""",
        """      if (group.presentationIds.some(value => presentationRejected.has(value))) {
        const firstRejected = [...group.presentationIds].sort().find(value => presentationRejected.has(value));
        logicalRejected.set(reference, presentationRejected.get(firstRejected));
        pending.delete(reference); progress = true; continue;
      }
      if (eligible.length === 0) {
        logicalRejected.set(reference, presentationRejected.get([...group.presentationIds].sort()[0]));
""",
    ),
    MutationSpec(
        "M-H2-ALIAS-MULTI-EFFECT",
        "            commit_admitted(reference, candidate_event)\n",
        "            commit_admitted(reference, candidate_event)\n            commit_admitted(reference, candidate_event)\n",
        "      commitAdmitted(reference, candidateEvent);\n",
        "      commitAdmitted(reference, candidateEvent);\n      commitAdmitted(reference, candidateEvent);\n",
    ),
)

MUTATION_SPECS: Final = {
    spec.identifier: spec for spec in (*_H1_MUTATION_SPECS, *_H2_MUTATION_SPECS)
}

FROZEN_CORPUS_SHA256: Final = {
    "adversarial-mutations.json": "a1464c018b37272da5cee7afcb6e6f6c9f03a11b5c74173a559dc931fcf8cb94",
    "expected-traces.json": "33eb07a0f5911926cd458cfa1f3e790a535942058e9bd7ef309860236b99765d",
    "invalid-transcript-vectors.json": "6e5d9c4e9100be721651312fe5900fae640560b232588d4838142c2bd22889d4",
    "manifest.json": "e0fe763ed1e2e8a032b0aa6ed495f57ce808ed17d3156d6a08e4da2048b78eb0",
    "state-machine-scenarios.json": "ea07798d2fc2a95dc95f1d0a06300ef9b548a3eb13fbef6a59958d680b0842b3",
    "valid-transcript-vectors.json": "8dc607acff6b0f9c4942834acce3d5004594a8b9b8169edd5b346b53cc6955cb",
}

FROZEN_O14_SHA256: Final = {
    "ed25519_reference.py": "e2ed8c97da836d39fece580f2cd81c155059e92fb65a3a5bc2357e05a59fb598",
    "semantic_registry.py": "0c18394d713367efb9d95aa325b050be0fbc06031528d8fabe7006427bf3ff88",
    "scenarios.py": "fdedde56409d7b6d74e9ce3bcdf372e9c3e7d66a60dba85e37d949e6913e451b",
}
RATIFIED_ISSUE_BODY_SHA256: Final = (
    "493eb32b811505bb148a16d216bc8c61036abf043d51dbae988685e00ff75148"
)
RATIFICATION_COMMENT_ID: Final = 5539629327
RATIFICATION_COMMENT_BODY_SHA256: Final = (
    "ded887f1eaa945b76e3daa6023e6046ee5bad5a86a48b59f79c6ae30f0028951"
)
RATIFICATION_V4_SHA256: Final = (
    "ff4eb914e3381540d1a104dc11b5c172c6854d161cf59494fb2ea3eaa6c539e8"
)
EVIDENCE_FILENAMES: Final = (
    "h1h2-python.json",
    "h1h2-javascript.json",
    "h1h2-mutations-python.json",
    "h1h2-mutations-javascript.json",
    "h1h2-regression.json",
    "scope.json",
)
PACKAGE_A_BASE_PINS: Final = {
    "tools/causal-flow-simulator/c03/corpus_model.py": "c5fae0f950cc8f9691a95d8231cc88e6c43c5e1e74b797d716928b6c8f5b1558",
    "tools/causal-flow-simulator/c03/node_adapter.mjs": "fc52c0800fab4c7cf75785b962ba09ffd67d06cb0b7bd02e850d6f13b0868da0",
    "tools/causal-flow-simulator/c03/README.md": "bd7f0459836c07d849780789b7ba7b11107cd853921b185838c3a7b9db575d3c",
    "tools/causal-flow-simulator/c03/scope_guard.py": "434c0b5276a0aba79cfc8d2b3cc56c4e337c58c6415db0ced2f9f9339aed4c66",
    "tools/causal-flow-simulator/c03/tests/test_scope_guard.py": "208dd5995f2518bd1245cc6968bc6acc9c0d8686d620352d16006c8c12846011",
    "tools/causal-flow-simulator/c03/tests/test_replay.py": "f1566d7412b16f3210b17c8e076c7d836e7693b7404c9af14a6ac1e6293b56ab",
    "docs/protocol/protocol-hardening-plan.md": "21033486045cfcfc0947b8b516489d1683fe2ec3b48a184faa068bf1777ad0bf",
    "docs/protocol/review/README.md": "d355ad16b2025240dadedbf2ca6ca1b78a5036c8ff2a727cf19d48414299b050",
}
EXACT_RECONSTRUCTED_PINS: Final = {
    "tools/causal-flow-simulator/c03/README.md": "5f81a81f17e1e3ec4dd06a0e898730920bebb41a5def6bd53c716710a6921262",
    "docs/protocol/protocol-hardening-plan.md": "2488352936788767341d8e2c902d6faabe22a3d5b30aa49b3b0af2c3e478b39c",
    "docs/protocol/review/README.md": "749dd8869f437b58b0b090df50974afe40759e8e9759d120e2089c6cef705e9a",
    "tools/causal-flow-simulator/c03/scope_guard.py": "659174150266eee3c3b82048c146fdc3cef3b7a2aba48206443c210922d12975",
    "tools/causal-flow-simulator/c03/tests/test_scope_guard.py": "555d222f39f55549919ce2e46081011c92ae1a7f5cd4d072795f1c2e8fe5bbff",
}
PACKAGE_A_NEW: Final = frozenset(
    {
        "tools/causal-flow-simulator/c03/h1_h2_relation.py",
        "tools/causal-flow-simulator/c03/tests/test_h1_h2_relation.py",
    }
)
PACKAGE_A_ALLOWED: Final = frozenset(PACKAGE_A_BASE_PINS) | PACKAGE_A_NEW
TEP_FILENAMES: Final = (
    "ISSUE_297_REST.json",
    "ISSUE_297_BODY.txt",
    "RATIFICATION_COMMENT_REST.json",
    "RATIFICATION_COMMENT_BODY.txt",
    "DRAFT_PR_REST.json",
    "DRAFT_PR_BODY.txt",
    "CANDIDATE.bundle",
    "CANDIDATE.diff",
    "TOOL_VERSIONS.txt",
    "SCOPE_PREFLIGHT_1.log",
    "SCOPE_PREFLIGHT_2.log",
    "REQUIRED_COMMANDS_1.log",
    "REQUIRED_COMMANDS_2.log",
    "MUTATIONS_PYTHON_1.log",
    "MUTATIONS_PYTHON_2.log",
    "MUTATIONS_JAVASCRIPT_1.log",
    "MUTATIONS_JAVASCRIPT_2.log",
    "FINAL_GATE.log",
    "FINAL_GATE.json",
    "H1H2_PYTHON_1.json",
    "H1H2_PYTHON_2.json",
    "H1H2_JAVASCRIPT_1.json",
    "H1H2_JAVASCRIPT_2.json",
    "H1H2_MUTATIONS_PYTHON_1.json",
    "H1H2_MUTATIONS_PYTHON_2.json",
    "H1H2_MUTATIONS_JAVASCRIPT_1.json",
    "H1H2_MUTATIONS_JAVASCRIPT_2.json",
    "H1H2_REGRESSION_1.json",
    "H1H2_REGRESSION_2.json",
    "SCOPE_1.json",
    "SCOPE_2.json",
    "CODEX_RECONCILIATION.md",
    "PACKAGE_SCHEMA.txt",
    "SHA256SUMS.txt",
)
TOOL_NAMES: Final = ("git", "python3", "node", "diff", "sha256sum")
REQUIRED_COMMAND_IDS: Final = (
    "PREFLIGHT",
    "VALIDATE_RELATION",
    "UNITTEST_C03",
    "RUN_H1H2_PYTHON",
    "RUN_H1H2_JAVASCRIPT",
    "RUN_H1H2_MUTATIONS_PYTHON",
    "RUN_H1H2_MUTATIONS_JAVASCRIPT",
    "RUN_H1H2_REGRESSION",
    "GENERATE_CORPUS",
    "VALIDATE_CORPUS",
    "REPLAY_CORPUS",
    "NODE_CORPUS",
    "CROSS_RUNTIME",
    "CORPUS_MUTATIONS",
    "VALIDATE_REVIEW_MODEL",
    "DIFF_GENERATED_CORPUS",
    "GIT_DIFF_CHECK",
    "FINAL_GATE",
)

V4_SLOT_OBSERVATIONS: Final = {
    "V,A ADMITTED, same logical ref, coalesced=2, effect=1; I ADMITTED, coalesced=1, effect=1":
        "V,A:ADMITTED_COALESCED_2_EFFECT_1;I:ADMITTED_COALESCED_1_EFFECT_1",
    "B INVALID S3, coalesced=0/effect=0; V,I each ADMITTED, coalesced=1/effect=1":
        "B:INVALID_0_0;V,I:ADMITTED_1_1",
    "O,M ADMITTED via O opening, same ref, coalesced=2/effect=1; I ADMITTED coalesced=1/effect=1":
        "O,M:ADMITTED_COALESCED_2_EFFECT_1;I:ADMITTED_1_1",
    "W COMMITMENT_MISMATCH S3 coalesced=0/effect=0; O,I each ADMITTED coalesced=1/effect=1":
        "W:COMMITMENT_MISMATCH_0_0;O,I:ADMITTED_1_1",
    "C1,C2 classified REFERENCE_COLLISION_UNSUPPORTED S3; I classified unique":
        "C1,C2:REFERENCE_COLLISION_UNSUPPORTED;I:UNIQUE",
    "M PENDING_OPENING coalesced=1/effect=1; B_OPEN INVALID S3 coalesced=0/effect=0; I ADMITTED coalesced=1/effect=1":
        "M:PENDING_1_1;B_OPEN:INVALID_0_0;I:ADMITTED_1_1",
    "M PENDING_OPENING coalesced=1/effect=1; W COMMITMENT_MISMATCH S3 coalesced=0/effect=0; I ADMITTED coalesced=1/effect=1":
        "M:PENDING_1_1;W:COMMITMENT_MISMATCH_0_0;I:ADMITTED_1_1",
}
V4_TEP_ARGUMENT_NAMES: Final = (
    "--build-tep",
    "--base",
    "--candidate",
    "--bundle",
    "--issue-rest",
    "--ratification-comment-rest",
    "--pr-rest",
    "--checkout-1",
    "--checkout-2",
    "--evidence-1",
    "--evidence-2",
    "--codex-reconciliation",
    "--output-dir",
    "--verify-tep",
    "--package",
)
V4_ENVIRONMENT_SPEC: Final = (
    "PATH=<ordered unique parent directories of the five resolved executables>",
    "LANG=C.UTF-8",
    "LC_ALL=C.UTF-8",
    "TZ=UTC",
    "HOME=<gate-owned empty temp directory>",
    "TMPDIR=<gate-owned empty temp directory outside checkouts/evidence>",
    "PYTHONDONTWRITEBYTECODE=1",
    "GIT_CONFIG_NOSYSTEM=1",
    "GIT_CONFIG_GLOBAL=/dev/null",
    "GIT_NO_REPLACE_OBJECTS=1",
)
V4_INVALID_KILL_SENTENCE: Final = (
    b"Crash, syntax/import failure, timeout, generic\n"
    b"snapshot failure, equivalent/unreachable mutant or wrong detector fails."
)


def _witnesses() -> dict[str, object]:
    return {witness.identifier: witness for witness in required_witnesses()}


def _boundary_observation(row: RelationRow, witness: object) -> dict:
    event = witness.event
    key = event.binding.verification_key if event.binding else b""
    observed = ed25519_verify_detailed(key, event.signature, event.transcript)
    expected_guard = (
        "GUARD_ACCEPTED"
        if row.expected in {"ACCEPTED", "SIGNATURE_INVALID"}
        else row.expected
    )
    expected_equations = 1 if expected_guard == "GUARD_ACCEPTED" else 0
    _require(observed["guardCode"] == expected_guard, f"{row.row_id} guard")
    _require(
        observed["equationInvocations"] == expected_equations,
        f"{row.row_id} equation count",
    )
    _require(
        observed["accepted"] == (row.expected == "ACCEPTED"),
        f"{row.row_id} accepted result",
    )
    return {
        **observed,
        "rowId": row.row_id,
        "scenarioId": row.scenario_id,
    }


def run_python_boundary() -> dict:
    witnesses = _witnesses()
    rows = [
        _boundary_observation(row, witnesses[row.scenario_id])
        for row in H1_BOUNDARY
    ]
    return {
        "result": "PASS",
        "rows": rows,
        "schema": "styx-c03-h1-boundary-observations/v1",
    }


def run_javascript_boundary() -> dict:
    witnesses = _witnesses()
    records = []
    for row in H1_BOUNDARY:
        event = witnesses[row.scenario_id].event
        key = event.binding.verification_key if event.binding else b""
        records.append(
            {
                "id": row.scenario_id,
                "messageHex": event.transcript.hex(),
                "publicKeyHex": key.hex(),
                "signatureHex": event.signature.hex(),
            }
        )
    with tempfile.TemporaryDirectory(prefix="styx-c03-h1-boundary-") as tmp:
        input_path = Path(tmp) / "input.json"
        output_path = Path(tmp) / "output.json"
        input_path.write_bytes(
            dumps(
                {
                    "records": records,
                    "schema": "styx-c03-h1-boundary-input/v1",
                }
            )
        )
        completed = subprocess.run(
            [
                "node",
                str(ROOT / "node_adapter.mjs"),
                "--h1-input",
                str(input_path),
                "--output",
                str(output_path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        _require(completed.returncode == 0, "JavaScript boundary adapter")
        observed = loads(output_path.read_bytes())["observations"]
    by_id = {row["id"]: row for row in observed}
    expected = run_python_boundary()["rows"]
    rows = []
    for relation, python_row in zip(H1_BOUNDARY, expected, strict=True):
        node_row = dict(by_id[relation.scenario_id])
        node_row.pop("id")
        projected = {
            **node_row,
            "rowId": relation.row_id,
            "scenarioId": relation.scenario_id,
        }
        _require(projected == python_row, f"{relation.row_id} cross-runtime")
        rows.append(projected)
    return {
        "result": "PASS",
        "rows": rows,
        "schema": "styx-c03-h1-boundary-observations/v1",
    }


def _genesis_with_key(source: dict, identifier: str, key: bytes) -> dict:
    value = deepcopy(source)
    value["id"] = identifier
    value["fields"]["rootVerificationKeyHex"] = key.hex()
    transcript = encode_genesis(value["fields"])
    value["binding"]["verificationKeyHex"] = key.hex()
    value["genesisReferenceHex"] = framed_hash(
        DOMAINS["genesis_reference"], transcript
    ).hex()
    value["signatureHex"] = source["signatureHex"]
    value["transcriptHex"] = transcript.hex()
    return value


def _event_with_signature(source: dict, identifier: str, signature: bytes) -> dict:
    value = deepcopy(source)
    value["id"] = identifier
    value["signatureHex"] = signature.hex()
    return value


def _grant_with_key(source: dict, identifier: str, key: bytes) -> dict:
    fields = deepcopy(source["fields"])
    fields["tail"]["granteeVerificationKeyHex"] = key.hex()
    return _application_vector(identifier, fields, "k-join/root")


def _grantee_event(
    genesis: dict,
    grant: dict,
    identifier: str,
    seed_label: str,
    *,
    sequence: int = 0,
    predecessor: str | None = None,
) -> dict:
    return _application_vector(
        identifier,
        _event_fields(
            identifier,
            sequence=sequence,
            predecessor=predecessor,
            parents=[grant["eventReferenceHex"]] if predecessor is None else [],
            credential=bytes.fromhex(grant["eventReferenceHex"]),
            context=bytes.fromhex(genesis["fields"]["contextIdentifierHex"]),
            genesis_reference=bytes.fromhex(genesis["genesisReferenceHex"]),
        ),
        seed_label,
    )


def _graph_case(
    row: RelationRow,
    genesis: dict,
    records: list[dict],
    expected_codes: dict[str, str | None],
    *,
    boundary_invocations: int,
    equation_invocations: int,
    harness_error: str | None = None,
) -> dict:
    return {
        "boundaryInvocations": boundary_invocations,
        "equationInvocations": equation_invocations,
        "expectedCodes": expected_codes,
        "genesis": genesis,
        "harnessError": harness_error,
        "mode": "graph",
        "records": records,
        "row": row,
    }


def _vector_case(row: RelationRow, record: dict) -> dict:
    return {
        "boundaryInvocations": 1,
        "equationInvocations": 0,
        "expectedCode": "INVALID",
        "mode": "vector",
        "record": record,
        "row": row,
    }


def connected_cases() -> tuple[dict, ...]:
    records, scenarios = _k_admission_vectors()
    by_id = {record["id"]: record for record in records}
    by_scenario = {scenario["id"]: scenario for scenario in scenarios}
    linear = by_scenario["k-admission-linear-controls"]
    join = by_scenario["k-admission-grant-rooted-join"]
    linear_genesis = by_id[linear["acceptedGenesisRecordId"]]
    linear_records = [by_id[value] for value in linear["recordIds"]]
    join_genesis = by_id[join["acceptedGenesisRecordId"]]
    join_records = [by_id[value] for value in join["recordIds"]]
    root_event = linear_records[0]
    grant_a, _, actor_a = join_records[:3]
    witness = _witnesses()

    cases: list[dict] = []
    cases.append(
        _graph_case(H1_CONNECTED[0], linear_genesis, [], {},
                    boundary_invocations=1, equation_invocations=1)
    )
    cases.append(
        _graph_case(H1_CONNECTED[1], linear_genesis, [root_event],
                    {root_event["id"]: None}, boundary_invocations=2,
                    equation_invocations=2)
    )
    cases.append(
        _graph_case(H1_CONNECTED[2], join_genesis, [grant_a],
                    {grant_a["id"]: None}, boundary_invocations=2,
                    equation_invocations=2)
    )
    cases.append(
        _graph_case(H1_CONNECTED[3], join_genesis, [grant_a, actor_a],
                    {grant_a["id"]: None, actor_a["id"]: None},
                    boundary_invocations=3, equation_invocations=3)
    )

    nested_key, _ = ed25519_sign(synthetic_octets("package-a/nested", 32), b"")
    nested_grant = _application_vector(
        "package-a-nonroot-grant",
        _event_fields(
            "package-a-nonroot-grant",
            role="CREDENTIAL",
            sequence=1,
            predecessor=actor_a["eventReferenceHex"],
            credential=bytes.fromhex(grant_a["eventReferenceHex"]),
            context=bytes.fromhex(join_genesis["fields"]["contextIdentifierHex"]),
            genesis_reference=bytes.fromhex(join_genesis["genesisReferenceHex"]),
            tail={"granteeVerificationKeyHex": nested_key.hex(), "kind": "GRANT"},
        ),
        "k-join/actor-a",
    )
    nested_event = _grantee_event(
        join_genesis, nested_grant, "package-a-nested-event", "package-a/nested"
    )
    nested_records = [grant_a, actor_a, nested_grant, nested_event]
    cases.append(
        _graph_case(
            H1_CONNECTED[4], join_genesis, nested_records,
            {record["id"]: None for record in nested_records},
            boundary_invocations=5, equation_invocations=5,
        )
    )

    bad_keys = {
        "identity": witness["identity-key"].event.binding.verification_key,
        "all-zero": witness["all-zero-key"].event.binding.verification_key,
        "mixed-order": witness["mixed-order-key"].event.binding.verification_key,
        "noncanonical": witness["noncanonical-key"].event.binding.verification_key,
        "off-curve": witness["off-curve-key"].event.binding.verification_key,
    }
    for offset, (label, key) in enumerate(bad_keys.items(), 5):
        invalid_genesis = _genesis_with_key(
            linear_genesis, f"package-a-{label}-genesis", key
        )
        cases.append(
            _graph_case(
                H1_CONNECTED[offset], invalid_genesis, [], {},
                boundary_invocations=1, equation_invocations=0,
                harness_error="PREACCEPTED_GENESIS_SIGNATURE_INVALID",
            )
        )

    base_signature = bytes.fromhex(root_event["signatureHex"])
    mixed_r = encode(
        add(decode(base_signature[:32]), Point(0, P - 1))
    ) + base_signature[32:]
    alternate_signature = ed25519_sign(
        synthetic_octets("package-a/other-event-key", 32),
        bytes.fromhex(root_event["transcriptHex"]),
    )[1]
    scalar = int.from_bytes(base_signature[32:], "little")
    signature_variants = (
        b"\x01" + bytes(31) + base_signature[32:],
        witness["small-order-r"].event.signature,
        mixed_r,
        (P + 1).to_bytes(32, "little") + base_signature[32:],
        bytes.fromhex("02" * 32) + base_signature[32:],
        base_signature[:32] + _L.to_bytes(32, "little"),
        base_signature[:32] + (_L + 1).to_bytes(32, "little"),
        base_signature[:32] + (scalar + _L).to_bytes(32, "little"),
        alternate_signature,
        base_signature[:-1],
        base_signature + b"x",
    )
    for index, signature in enumerate(signature_variants, 10):
        candidate = _event_with_signature(
            root_event, f"package-a-connected-negative-{index + 1:02d}", signature
        )
        equation_count = 1 if index == 18 else 0
        cases.append(
            _graph_case(
                H1_CONNECTED[index], linear_genesis, [candidate],
                {candidate["id"]: "INVALID"}, boundary_invocations=2,
                equation_invocations=1 + equation_count,
            )
        )

    for index, (label, key) in enumerate(bad_keys.items(), 21):
        grant = _grant_with_key(grant_a, f"package-a-{label}-grant", key)
        child = _grantee_event(
            join_genesis, grant, f"package-a-{label}-child", "package-a/bad-child"
        )
        cases.append(
            _graph_case(
                H1_CONNECTED[index], join_genesis, [grant, child],
                {grant["id"]: None, child["id"]: "INVALID"},
                boundary_invocations=3, equation_invocations=2,
            )
        )

    grantee_key, _ = ed25519_sign(
        synthetic_octets("package-a/valid-grantee", 32), b""
    )
    valid_grant = _grant_with_key(
        grant_a, "package-a-valid-grant-invalid-child", grantee_key
    )
    invalid_child = _grantee_event(
        join_genesis,
        valid_grant,
        "package-a-valid-grant-invalid-child-r",
        "package-a/valid-grantee",
    )
    child_signature = bytes.fromhex(invalid_child["signatureHex"])
    invalid_child["signatureHex"] = (
        b"\x01" + bytes(31) + child_signature[32:]
    ).hex()
    cases.append(
        _graph_case(
            H1_CONNECTED[26], join_genesis, [valid_grant, invalid_child],
            {valid_grant["id"]: None, invalid_child["id"]: "INVALID"},
            boundary_invocations=3, equation_invocations=2,
        )
    )
    for index, width in ((27, 31), (28, 33)):
        grant = _grant_with_key(
            grant_a, f"package-a-grant-width-{width}", bytes(width)
        )
        expected = (
            "STRUCTURAL_REJECTION"
            if width == 31
            else "CURRENT_OBJECT_OUT_OF_PROFILE"
        )
        cases.append(
            _graph_case(
                H1_CONNECTED[index], join_genesis, [grant],
                {grant["id"]: expected}, boundary_invocations=1,
                equation_invocations=1,
            )
        )

    for offset, (label, key) in enumerate(bad_keys.items(), 29):
        disconnected = _genesis_with_key(
            linear_genesis, f"package-a-disconnected-{label}-genesis", key
        )
        cases.append(_vector_case(H1_CONNECTED[offset], disconnected))
    small_binding = deepcopy(root_event)
    small_binding["id"] = "package-a-disconnected-small-binding"
    small_binding["binding"]["verificationKeyHex"] = bad_keys["identity"].hex()
    cases.append(_vector_case(H1_CONNECTED[34], small_binding))
    return tuple(cases)


def _validate_candidate_set_wrapper_identities(
    genesis: dict, records: list[dict]
) -> None:
    complete_by_identifier: dict[str, bytes] = {}
    identifier_by_wrapper: dict[bytes, str] = {}
    for record in (genesis, *records):
        _require(isinstance(record, dict), "candidate-set record must be an object")
        identifier = record.get("id")
        _require(
            isinstance(identifier, str) and bool(identifier),
            "candidate-set stable ID must be a non-empty string",
        )
        complete = dumps(record)
        wrapper = dict(record)
        del wrapper["id"]
        wrapper_bytes = dumps(wrapper)
        previous_complete = complete_by_identifier.get(identifier)
        _require(
            previous_complete is None or previous_complete == complete,
            "stable ID names different wrapper bytes within one candidate set",
        )
        previous_identifier = identifier_by_wrapper.get(wrapper_bytes)
        _require(
            previous_identifier is None or previous_identifier == identifier,
            "byte-identical wrappers use different stable IDs within one candidate set",
        )
        complete_by_identifier[identifier] = complete
        identifier_by_wrapper[wrapper_bytes] = identifier


def _project_graph_case(case: dict) -> dict:
    _validate_candidate_set_wrapper_identities(case["genesis"], case["records"])
    reset_ed25519_evidence_counts()
    harness_error = None
    try:
        observations = evaluate_k_admission_graph(
            case["genesis"], case["records"], presentation_evidence=True
        )
    except Exception as error:  # bounded harness evidence, normalized below
        observations = []
        harness_error = str(error)
    counts = ed25519_evidence_counts()
    _require(harness_error == case["harnessError"], f"{case['row'].row_id} harness")
    _require(
        counts
        == {
            "boundaryInvocations": case["boundaryInvocations"],
            "equationInvocations": case["equationInvocations"],
        },
        f"{case['row'].row_id} verification counts",
    )
    observed_codes = {row["id"]: row["protocolErrorCode"] for row in observations}
    _require(
        observed_codes == case["expectedCodes"],
        f"{case['row'].row_id} graph observation",
    )
    return {
        "harnessError": harness_error,
        "observations": observations,
        "rowId": case["row"].row_id,
        "scenarioId": case["row"].scenario_id,
        "verificationBoundary": counts,
    }


def _project_vector_case(case: dict) -> dict:
    reset_ed25519_evidence_counts()
    observation = evaluate_vector(case["record"])
    counts = ed25519_evidence_counts()
    _require(
        observation.get("localOutcome") == case["expectedCode"]
        and observation.get("stage") == "S3_KERNEL_STRUCTURAL",
        f"{case['row'].row_id} vector observation",
    )
    _require(
        counts
        == {
            "boundaryInvocations": case["boundaryInvocations"],
            "equationInvocations": case["equationInvocations"],
        },
        f"{case['row'].row_id} vector counts",
    )
    return {
        "observation": observation,
        "rowId": case["row"].row_id,
        "scenarioId": case["row"].scenario_id,
        "verificationBoundary": counts,
    }


def run_python_connected() -> dict:
    rows = [
        _project_graph_case(case)
        if case["mode"] == "graph"
        else _project_vector_case(case)
        for case in connected_cases()
    ]
    _require(len(rows) == 35, "connected Python observation count")
    return {
        "result": "PASS",
        "rows": rows,
        "schema": "styx-c03-h1-connected-observations/v1",
    }


def run_javascript_connected() -> dict:
    cases = connected_cases()
    graph_cases = [case for case in cases if case["mode"] == "graph"]
    vector_cases = [case for case in cases if case["mode"] == "vector"]
    for case in graph_cases:
        _validate_candidate_set_wrapper_identities(case["genesis"], case["records"])
    with tempfile.TemporaryDirectory(prefix="styx-c03-h1-connected-") as tmp:
        workspace = Path(tmp)
        graph_input = workspace / "graph-input.json"
        graph_output = workspace / "graph-output.json"
        vector_input = workspace / "vector-input.json"
        vector_output = workspace / "vector-output.json"
        graph_input.write_bytes(
            dumps(
                {
                    "scenarios": [
                        {
                            "acceptedGenesisRecord": case["genesis"],
                            "graphEvaluation": True,
                            "id": case["row"].scenario_id,
                            "records": case["records"],
                        }
                        for case in graph_cases
                    ],
                    "schema": "styx-c03-h1h2-connected-input/v1",
                }
            )
        )
        vector_records = []
        for case in vector_cases:
            record = deepcopy(case["record"])
            record["id"] = case["row"].scenario_id
            vector_records.append(record)
        vector_input.write_bytes(
            dumps(
                {
                    "records": vector_records,
                    "schema": "styx-c03-h1h2-vector-input/v1",
                }
            )
        )
        for input_path, output_path, option in (
            (graph_input, graph_output, "--k-scenario-input"),
            (vector_input, vector_output, "--c03-vector-input"),
        ):
            completed = subprocess.run(
                [
                    "node",
                    str(ROOT / "node_adapter.mjs"),
                    option,
                    str(input_path),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            _require(completed.returncode == 0, "JavaScript connected adapter")
        graph_rows = {
            row["id"]: row for row in loads(graph_output.read_bytes())["observations"]
        }
        vector_rows = {
            row["id"]: row for row in loads(vector_output.read_bytes())["observations"]
        }

    python_rows = {row["scenarioId"]: row for row in run_python_connected()["rows"]}
    rows = []
    for case in cases:
        scenario = case["row"].scenario_id
        expected = python_rows[scenario]
        if case["mode"] == "graph":
            observed = graph_rows[scenario]
            projected = {
                "harnessError": observed.get("harnessError"),
                "observations": observed["observations"],
                "rowId": case["row"].row_id,
                "scenarioId": scenario,
                "verificationBoundary": observed["verificationBoundary"],
            }
        else:
            observed = vector_rows[scenario]
            projected = {
                "observation": observed["observation"],
                "rowId": case["row"].row_id,
                "scenarioId": scenario,
                "verificationBoundary": observed["verificationBoundary"],
            }
        _require(projected == expected, f"{case['row'].row_id} cross-runtime")
        rows.append(projected)
    return {
        "result": "PASS",
        "rows": rows,
        "schema": "styx-c03-h1-connected-observations/v1",
    }


def _root_event(
    genesis: dict,
    identifier: str,
    *,
    sequence: int = 0,
    predecessor: str | None = None,
    parents: tuple[str, ...] = (),
    role: str = "ORDINARY",
    tail: dict | None = None,
    content: dict | None = None,
) -> dict:
    return _application_vector(
        identifier,
        _event_fields(
            identifier,
            role=role,
            sequence=sequence,
            predecessor=predecessor,
            parents=list(parents),
            content=content,
            tail=tail,
            credential=bytes.fromhex(genesis["genesisReferenceHex"]),
            context=bytes.fromhex(genesis["fields"]["contextIdentifierHex"]),
            genesis_reference=bytes.fromhex(genesis["genesisReferenceHex"]),
        ),
        "k-linear/root" if genesis["id"].startswith("k-linear") else "k-join/root",
    )


def _pending_root_event(
    genesis: dict,
    source: dict,
    identifier: str,
    *,
    sequence: int = 0,
    predecessor: str | None = None,
    parents: tuple[str, ...] = (),
) -> dict:
    fields = deepcopy(source["fields"])
    fields.update(
        {
            "authorSequence": sequence,
            "causalParents": sorted(parents),
            "directPredecessorHex": predecessor,
            "transitionBlockHex": synthetic_octets(
                f"transition/{identifier}", 8
            ).hex(),
        }
    )
    return _application_vector(identifier, fields, "k-linear/root")


def _slot_case(
    row: RelationRow,
    genesis: dict,
    setup: list[dict],
    named: dict[str, dict],
    expected: dict[str, str | None],
) -> dict:
    ordered = [named[label] for label in row.order]
    targets = {record["id"] for record in ordered}
    return {
        "expected": expected,
        "genesis": genesis,
        "labelIds": {label: record["id"] for label, record in named.items()},
        "lexicalSchedule": "NOT_APPLICABLE",
        "records": [*setup, *ordered],
        "row": row,
        "targets": targets,
    }


def _signer_seed(record: dict) -> str:
    candidates = (
        "k-linear/root",
        "k-join/root",
        "k-join/actor-a",
        "k-join/actor-b",
        "slot/valid-grantee",
    )
    supplied = record["binding"]["verificationKeyHex"]
    for label in candidates:
        public, _ = ed25519_sign(synthetic_octets(label, 32), b"")
        if public.hex() == supplied:
            return label
    raise RelationError(f"unknown test signer:{record['id']}")


def _rewrite_reference_fields(fields: dict, replacements: dict[str, str]) -> None:
    predecessor = fields["directPredecessorHex"]
    if predecessor in replacements:
        fields["directPredecessorHex"] = replacements[predecessor]
    fields["causalParents"] = sorted(
        replacements.get(value, value) for value in fields["causalParents"]
    )
    credential = fields["credentialIdentifierHex"]
    if credential in replacements:
        fields["credentialIdentifierHex"] = replacements[credential]
    tail = fields.get("tail", {})
    for key, value in tuple(tail.items()):
        if isinstance(value, str) and value in replacements:
            tail[key] = replacements[value]


def _retag_slot_case(
    case: dict, left_label: str, right_label: str, *, left_first: bool
) -> dict:
    original = deepcopy(case)
    records_by_id = {record["id"]: record for record in original["records"]}
    target_by_id = {
        identifier: records_by_id[identifier] for identifier in original["targets"]
    }
    old_reference = {
        identifier: record["eventReferenceHex"]
        for identifier, record in target_by_id.items()
    }

    for nonce in range(1024):
        replacements: dict[str, str] = {}
        rebuilt: dict[str, dict] = {}
        remaining = set(target_by_id)
        while remaining:
            progress = False
            for identifier in sorted(tuple(remaining)):
                source = target_by_id[identifier]
                target_dependencies = {
                    value
                    for value in (
                        [source["fields"]["directPredecessorHex"]]
                        + list(source["fields"]["causalParents"])
                    )
                    if value in set(old_reference.values())
                }
                if not target_dependencies <= set(replacements):
                    continue
                value = deepcopy(source)
                fields = value["fields"]
                _rewrite_reference_fields(fields, replacements)
                fields["transitionBlockHex"] = synthetic_octets(
                    f"package-a/scheduler/{case['row'].row_id}/{nonce}/{identifier}",
                    12,
                ).hex()
                transcript = encode_event(fields)
                public, signature = ed25519_sign(
                    synthetic_octets(_signer_seed(source), 32), transcript
                )
                value["binding"]["contextIdentifierHex"] = fields[
                    "contextIdentifierHex"
                ]
                value["binding"]["credentialIdentifierHex"] = fields[
                    "credentialIdentifierHex"
                ]
                value["binding"]["verificationKeyHex"] = public.hex()
                value["transcriptHex"] = transcript.hex()
                value["eventReferenceHex"] = framed_hash(
                    DOMAINS["event_reference"], transcript
                ).hex()
                if original["expected"].get(identifier) == "INVALID":
                    damaged = bytearray(signature)
                    damaged[-1] ^= 1
                    signature = bytes(damaged)
                value["signatureHex"] = signature.hex()
                replacements[old_reference[identifier]] = value[
                    "eventReferenceHex"
                ]
                rebuilt[identifier] = value
                remaining.remove(identifier)
                progress = True
            _require(progress, f"{case['row'].row_id} scheduler dependency cycle")

        left = rebuilt[original["labelIds"][left_label]]["eventReferenceHex"]
        right = rebuilt[original["labelIds"][right_label]]["eventReferenceHex"]
        if (left < right) != left_first:
            continue
        result = deepcopy(original)
        result["records"] = [
            rebuilt.get(record["id"], record) for record in original["records"]
        ]
        result["lexicalSchedule"] = (
            "LEFT_LT_RIGHT" if left_first else "LEFT_GT_RIGHT"
        )
        return result
    raise RelationError(f"{case['row'].row_id} lexical scheduler exhausted")


def _alternate_valid_signature(record: dict, seed_label: str) -> str:
    seed = synthetic_octets(seed_label, 32)
    message = bytes.fromhex(record["transcriptHex"])
    expanded = sha512(seed).digest()
    clamped = bytearray(expanded[:32])
    clamped[0] &= 248
    clamped[31] &= 63
    clamped[31] |= 64
    secret = int.from_bytes(clamped, "little")
    public = encode(scalar_mult(secret, BASE))
    r_rfc8032 = int.from_bytes(
        sha512(expanded[32:] + message).digest(), "little"
    ) % _L
    r_alias = (r_rfc8032 + 1) % _L
    _require(r_alias not in {0, r_rfc8032}, "invalid deterministic alias nonce")
    encoded_r = encode(scalar_mult(r_alias, BASE))
    scalar = (
        r_alias + challenge(encoded_r, public, message) * secret
    ) % _L
    signature = encoded_r + scalar.to_bytes(32, "little")
    _require(
        public.hex() == record["binding"]["verificationKeyHex"]
        and signature.hex() != record["signatureHex"]
        and ed25519_verify_detailed(public, signature, message)["accepted"],
        "deterministic alias signature",
    )
    return signature.hex()


def _new_presentation_case(
    row: RelationRow,
    genesis: dict,
    setup: list[dict],
    actor_a: dict,
    actor_b: dict,
    grant_a: dict,
    grant_b: dict,
    required_source: dict,
    family: str,
    *,
    left_first: bool,
) -> dict:
    for nonce in range(1024):
        logical_fields = _event_fields(
            f"{row.scenario_id}-logical",
            sequence=1,
            predecessor=actor_a["eventReferenceHex"],
            credential=bytes.fromhex(grant_a["eventReferenceHex"]),
            context=bytes.fromhex(genesis["fields"]["contextIdentifierHex"]),
            genesis_reference=bytes.fromhex(genesis["genesisReferenceHex"]),
        )
        if family in {
            "opening",
            "wrong-opening-alias",
            "unauthenticated-opening",
            "wrong-opening",
        }:
            source_content = required_source["fields"]["content"]
            source_opening = required_source["opening"]
            supplied = bytes.fromhex(source_opening["contentHex"])
            computed = encode_commitment(
                profile_id=logical_fields["applicationProfileId"],
                profile_version=logical_fields["applicationProfileVersion"],
                context=bytes.fromhex(logical_fields["contextIdentifierHex"]),
                credential=bytes.fromhex(logical_fields["credentialIdentifierHex"]),
                sequence=logical_fields["authorSequence"],
                content_type=source_content["contentType"],
                content=supplied,
                randomizer=bytes.fromhex(source_opening["randomizerHex"]),
                chunk_size=(source_content.get("geometry") or {}).get("chunkSize"),
            )
            logical_fields["content"] = {
                "class": "REQUIRED",
                "commitmentHex": computed["commitmentHex"],
                "contentType": source_content["contentType"],
                "exactLength": len(supplied),
                "geometry": computed["geometry"],
                "shape": computed["shape"],
            }
        logical_fields["transitionBlockHex"] = synthetic_octets(
            f"package-a/presentation/{row.row_id}/{nonce}/logical", 12
        ).hex()
        logical = _application_vector(
            f"{row.scenario_id}-logical", logical_fields, "k-join/actor-a"
        )
        independent_fields = _event_fields(
            f"{row.scenario_id}-independent",
            sequence=1,
            predecessor=actor_b["eventReferenceHex"],
            credential=bytes.fromhex(grant_b["eventReferenceHex"]),
            context=bytes.fromhex(genesis["fields"]["contextIdentifierHex"]),
            genesis_reference=bytes.fromhex(genesis["genesisReferenceHex"]),
        )
        independent_fields["transitionBlockHex"] = synthetic_octets(
            f"package-a/presentation/{row.row_id}/{nonce}/independent", 12
        ).hex()
        independent = _application_vector(
            f"{row.scenario_id}-I", independent_fields, "k-join/actor-b"
        )
        if (
            (logical["eventReferenceHex"] < independent["eventReferenceHex"])
            != left_first
        ):
            continue

        named: dict[str, dict]
        expected: dict[str, str | None]
        if family == "valid-alias":
            valid = deepcopy(logical)
            valid["id"] = f"{row.scenario_id}-V"
            alias = deepcopy(logical)
            alias["id"] = f"{row.scenario_id}-A"
            alias["signatureHex"] = _alternate_valid_signature(
                alias, "k-join/actor-a"
            )
            named = {"V": valid, "A": alias, "I": independent}
            expected = {valid["id"]: None, alias["id"]: None, independent["id"]: None}
        elif family == "invalid-alias":
            valid = deepcopy(logical)
            valid["id"] = f"{row.scenario_id}-V"
            bad = deepcopy(logical)
            bad["id"] = f"{row.scenario_id}-B"
            damaged = bytearray.fromhex(bad["signatureHex"])
            damaged[-1] ^= 1
            bad["signatureHex"] = damaged.hex()
            named = {"V": valid, "B": bad, "I": independent}
            expected = {valid["id"]: None, bad["id"]: "INVALID", independent["id"]: None}
        else:
            missing = deepcopy(logical)
            missing["id"] = f"{row.scenario_id}-M"
            opened = deepcopy(logical)
            opened["id"] = f"{row.scenario_id}-O"
            opened["opening"] = deepcopy(required_source["opening"])
            if family == "opening":
                named = {"O": opened, "M": missing, "I": independent}
                expected = {opened["id"]: None, missing["id"]: None, independent["id"]: None}
            elif family == "wrong-opening-alias":
                hostile = deepcopy(opened)
                hostile["id"] = f"{row.scenario_id}-W"
                damaged = bytearray.fromhex(hostile["opening"]["contentHex"])
                damaged[0] ^= 1
                hostile["opening"]["contentHex"] = damaged.hex()
                named = {"O": opened, "W": hostile, "I": independent}
                expected = {
                    opened["id"]: None,
                    hostile["id"]: "COMMITMENT_MISMATCH",
                    independent["id"]: None,
                }
            else:
                hostile = deepcopy(opened)
                if family == "unauthenticated-opening":
                    hostile["id"] = f"{row.scenario_id}-B_OPEN"
                    damaged = bytearray.fromhex(hostile["signatureHex"])
                    damaged[-1] ^= 1
                    hostile["signatureHex"] = damaged.hex()
                    label, code = "B_OPEN", "INVALID"
                else:
                    hostile["id"] = f"{row.scenario_id}-W"
                    damaged = bytearray.fromhex(hostile["opening"]["contentHex"])
                    damaged[0] ^= 1
                    hostile["opening"]["contentHex"] = damaged.hex()
                    label, code = "W", "COMMITMENT_MISMATCH"
                named = {"M": missing, label: hostile, "I": independent}
                expected = {
                    missing["id"]: "PENDING_OPENING",
                    hostile["id"]: code,
                    independent["id"]: None,
                }
        ordered = [named[label] for label in row.order]
        return {
            "expected": expected,
            "genesis": genesis,
            "labelIds": {label: value["id"] for label, value in named.items()},
            "lexicalSchedule": "LEFT_LT_RIGHT" if left_first else "LEFT_GT_RIGHT",
            "records": [*setup, *ordered],
            "row": row,
            "targets": {value["id"] for value in ordered},
        }
    raise RelationError(f"{row.row_id} presentation scheduler exhausted")


def slot_cases() -> tuple[dict, ...]:
    connected, scenarios = _k_admission_vectors()
    by_id = {record["id"]: record for record in connected}
    scenario_by_id = {scenario["id"]: scenario for scenario in scenarios}
    linear = scenario_by_id["k-admission-linear-controls"]
    join = scenario_by_id["k-admission-grant-rooted-join"]
    linear_genesis = by_id[linear["acceptedGenesisRecordId"]]
    root_zero = by_id[linear["recordIds"][0]]
    join_genesis = by_id[join["acceptedGenesisRecordId"]]
    grant_a, grant_b, actor_a, actor_b = [
        by_id[value] for value in join["recordIds"][:4]
    ]
    cases: list[dict] = []

    # 001-002: two distinct REQUIRED events remain K-admitted without openings.
    required_a = _pending_root_event(
        linear_genesis, root_zero, "slot-required-a"
    )
    required_b = _pending_root_event(
        linear_genesis, root_zero, "slot-required-b"
    )
    for row in H2_SLOTS[:2]:
        cases.append(
            _slot_case(
                row, linear_genesis, [], {"A": required_a, "B": required_b},
                {required_a["id"]: "FORK_EVIDENCE", required_b["id"]: "FORK_EVIDENCE"},
            )
        )

    # 003-008: presentation order cannot hide siblings behind a pending parent.
    pending_parent = _pending_root_event(
        linear_genesis, root_zero, "slot-pending-parent"
    )
    side_pending_fields = deepcopy(root_zero["fields"])
    side_pending_fields.update(
        {
            "authorSequence": 0,
            "causalParents": [grant_a["eventReferenceHex"]],
            "contextIdentifierHex": join_genesis["fields"]["contextIdentifierHex"],
            "credentialIdentifierHex": grant_a["eventReferenceHex"],
            "directPredecessorHex": None,
            "genesisReferenceHex": join_genesis["genesisReferenceHex"],
            "transitionBlockHex": synthetic_octets(
                "transition/slot-side-pending", 8
            ).hex(),
        }
    )
    side_pending = _application_vector(
        "slot-side-pending", side_pending_fields, "k-join/actor-a"
    )
    pending_a = _root_event(
        join_genesis, "slot-pending-child-a", sequence=2,
        predecessor=grant_b["eventReferenceHex"],
        parents=(side_pending["eventReferenceHex"],),
    )
    pending_b = _root_event(
        join_genesis, "slot-pending-child-b", sequence=2,
        predecessor=grant_b["eventReferenceHex"],
        parents=(side_pending["eventReferenceHex"],),
    )
    for row in H2_SLOTS[2:8]:
        cases.append(
            _slot_case(
                row, join_genesis, [grant_a, grant_b],
                {"P": side_pending, "A": pending_a, "B": pending_b},
                {
                    side_pending["id"]: "PENDING_OPENING",
                    pending_a["id"]: "FORK_EVIDENCE",
                    pending_b["id"]: "FORK_EVIDENCE",
                },
            )
        )

    ready = _root_event(linear_genesis, "slot-ready")
    pending = _pending_root_event(linear_genesis, root_zero, "slot-pending")
    for row in H2_SLOTS[8:10]:
        cases.append(
            _slot_case(
                row, linear_genesis, [], {"READY": ready, "PENDING": pending},
                {ready["id"]: "FORK_EVIDENCE", pending["id"]: "FORK_EVIDENCE"},
            )
        )

    three = {
        label: _root_event(linear_genesis, f"slot-three-{label.lower()}")
        for label in ("A", "B", "C")
    }
    for row in H2_SLOTS[10:16]:
        cases.append(
            _slot_case(
                row, linear_genesis, [], three,
                {record["id"]: "FORK_EVIDENCE" for record in three.values()},
            )
        )

    valid = _root_event(linear_genesis, "slot-valid")
    bad_signature = _root_event(linear_genesis, "slot-bad-signature")
    signature = bytearray.fromhex(bad_signature["signatureHex"])
    signature[-1] ^= 1
    bad_signature["signatureHex"] = bytes(signature).hex()
    for row in H2_SLOTS[16:18]:
        cases.append(
            _slot_case(
                row, linear_genesis, [],
                {"VALID": valid, "BAD_SIG": bad_signature},
                {valid["id"]: None, bad_signature["id"]: "INVALID"},
            )
        )

    valid_key, _ = ed25519_sign(synthetic_octets("slot/valid-grantee", 32), b"")
    valid_grant = _root_event(
        linear_genesis, "slot-valid-grant", role="CREDENTIAL", sequence=1,
        predecessor=root_zero["eventReferenceHex"],
        tail={"granteeVerificationKeyHex": valid_key.hex(), "kind": "GRANT"},
    )
    bad_grant = _root_event(
        linear_genesis, "slot-bad-key-grant", role="CREDENTIAL", sequence=1,
        predecessor=root_zero["eventReferenceHex"],
        tail={"granteeVerificationKeyHex": (b"\x01" + bytes(31)).hex(), "kind": "GRANT"},
    )
    for row in H2_SLOTS[18:20]:
        cases.append(
            _slot_case(
                row, linear_genesis, [root_zero],
                {"VALID": valid_grant, "BAD_GRANTEE_KEY": bad_grant},
                {valid_grant["id"]: "FORK_EVIDENCE", bad_grant["id"]: "FORK_EVIDENCE"},
            )
        )

    for row in H2_SLOTS[20:22]:
        cases.append(
            _slot_case(
                row, join_genesis, [grant_a, grant_b],
                {"CRED_A": actor_a, "CRED_B": actor_b},
                {actor_a["id"]: None, actor_b["id"]: None},
            )
        )

    duplicate = _root_event(linear_genesis, "slot-duplicate")
    cases.append(
        _slot_case(
            H2_SLOTS[22], linear_genesis, [], {"A": duplicate},
            {duplicate["id"]: None},
        )
    )

    collision_valid = _root_event(linear_genesis, "slot-collision-valid")
    collision = _root_event(linear_genesis, "slot-collision-declared")
    collision["eventReferenceHex"] = collision_valid["eventReferenceHex"]
    for row in H2_SLOTS[23:25]:
        cases.append(
            _slot_case(
                row, linear_genesis, [],
                {"VALID": collision_valid, "COLLISION": collision},
                {
                    collision_valid["id"]: None,
                    collision["id"]: "REFERENCE_COLLISION_UNSUPPORTED",
                },
            )
        )

    fork_a = _root_event(
        join_genesis, "slot-fork-a", sequence=2,
        predecessor=grant_b["eventReferenceHex"],
    )
    fork_b = _root_event(
        join_genesis, "slot-fork-b", sequence=2,
        predecessor=grant_b["eventReferenceHex"],
    )
    dependent = _application_vector(
        "slot-fork-dependent",
        _event_fields(
            "slot-fork-dependent", sequence=1,
            predecessor=actor_a["eventReferenceHex"],
            parents=[fork_a["eventReferenceHex"], fork_b["eventReferenceHex"]],
            credential=bytes.fromhex(grant_a["eventReferenceHex"]),
            context=bytes.fromhex(join_genesis["fields"]["contextIdentifierHex"]),
            genesis_reference=bytes.fromhex(join_genesis["genesisReferenceHex"]),
        ),
        "k-join/actor-a",
    )
    independent = _application_vector(
        "slot-fork-independent",
        _event_fields(
            "slot-fork-independent", sequence=1,
            predecessor=actor_b["eventReferenceHex"],
            credential=bytes.fromhex(grant_b["eventReferenceHex"]),
            context=bytes.fromhex(join_genesis["fields"]["contextIdentifierHex"]),
            genesis_reference=bytes.fromhex(join_genesis["genesisReferenceHex"]),
        ),
        "k-join/actor-b",
    )
    fork_named = {"A": fork_a, "B": fork_b, "D": dependent, "I": independent}
    fork_expected = {
        fork_a["id"]: "FORK_EVIDENCE", fork_b["id"]: "FORK_EVIDENCE",
        dependent["id"]: None, independent["id"]: None,
    }
    for row in H2_SLOTS[25:49]:
        cases.append(
            _slot_case(
                row, join_genesis, [grant_a, grant_b, actor_a, actor_b],
                fork_named, fork_expected,
            )
        )

    invalid_descendant = _root_event(
        linear_genesis, "slot-pending-invalid-child", sequence=1,
        predecessor=pending_parent["eventReferenceHex"],
    )
    invalid_signature = bytearray.fromhex(invalid_descendant["signatureHex"])
    invalid_signature[-1] ^= 1
    invalid_descendant["signatureHex"] = bytes(invalid_signature).hex()
    cases.append(
        _slot_case(
            H2_SLOTS[49], linear_genesis, [],
            {"P": pending_parent, "X_BAD_SIG": invalid_descendant},
            {pending_parent["id"]: "PENDING_OPENING", invalid_descendant["id"]: "INVALID"},
        )
    )

    chain_x = _root_event(
        linear_genesis, "slot-pending-chain-x", sequence=1,
        predecessor=pending_parent["eventReferenceHex"],
    )
    chain_y = _root_event(
        linear_genesis, "slot-pending-chain-y", sequence=2,
        predecessor=chain_x["eventReferenceHex"],
    )
    cases.append(
        _slot_case(
            H2_SLOTS[50], linear_genesis, [],
            {"P": pending_parent, "X": chain_x, "Y": chain_y},
            {
                pending_parent["id"]: "PENDING_OPENING",
                chain_x["id"]: "PENDING_ANCESTOR",
                chain_y["id"]: "PENDING_ANCESTOR",
            },
        )
    )

    bad_dependency = _root_event(linear_genesis, "slot-bad-dependency")
    bad_dep_signature = bytearray.fromhex(bad_dependency["signatureHex"])
    bad_dep_signature[-1] ^= 1
    bad_dependency["signatureHex"] = bytes(bad_dep_signature).hex()
    mixed_dependency = _root_event(
        linear_genesis, "slot-pending-rejected-child", sequence=1,
        predecessor=pending_parent["eventReferenceHex"],
        parents=(bad_dependency["eventReferenceHex"],),
    )
    cases.append(
        _slot_case(
            H2_SLOTS[51], linear_genesis, [],
            {"P": pending_parent, "BAD_DEP": bad_dependency, "X": mixed_dependency},
            {
                pending_parent["id"]: "PENDING_OPENING",
                bad_dependency["id"]: "INVALID",
                mixed_dependency["id"]: "DEPENDENCY_DEFERRED",
            },
        )
    )

    detachable_fields = deepcopy(root_zero["fields"])
    detachable_fields["transitionBlockHex"] = synthetic_octets(
        "transition/slot-detachable-missing", 8
    ).hex()
    detachable_fields["content"]["class"] = "DETACHABLE"
    detachable_missing = _application_vector(
        "slot-detachable-missing", detachable_fields, "k-linear/root"
    )
    cases.append(
        _slot_case(
            H2_SLOTS[52], linear_genesis, [],
            {"VALID": valid, "BAD": detachable_missing},
            {valid["id"]: None, detachable_missing["id"]: "OPENING_MISSING"},
        )
    )

    commitment_bad = deepcopy(root_zero)
    commitment_bad["id"] = "slot-commitment-mismatch"
    content = bytearray.fromhex(commitment_bad["opening"]["contentHex"])
    content[0] ^= 1
    commitment_bad["opening"]["contentHex"] = bytes(content).hex()
    cases.append(
        _slot_case(
            H2_SLOTS[53], linear_genesis, [],
            {"VALID": valid, "BAD": commitment_bad},
            {valid["id"]: None, commitment_bad["id"]: "COMMITMENT_MISMATCH"},
        )
    )
    length_bad = deepcopy(root_zero)
    length_bad["id"] = "slot-length-mismatch"
    length_bad["opening"]["contentHex"] += "00"
    cases.append(
        _slot_case(
            H2_SLOTS[54], linear_genesis, [],
            {"VALID": valid, "BAD": length_bad},
            {valid["id"]: None, length_bad["id"]: "LENGTH_MISMATCH"},
        )
    )

    unresolved_valid = actor_a
    unresolved_bad = _application_vector(
        "slot-unresolved-binding",
        _event_fields(
            "slot-unresolved-binding", sequence=0,
            credential=bytes.fromhex(grant_a["eventReferenceHex"]),
            context=bytes.fromhex(join_genesis["fields"]["contextIdentifierHex"]),
            genesis_reference=bytes.fromhex(join_genesis["genesisReferenceHex"]),
        ),
        "k-join/actor-a",
    )
    cases.append(
        _slot_case(
            H2_SLOTS[55], join_genesis, [grant_a],
            {"VALID": unresolved_valid, "BAD": unresolved_bad},
            {unresolved_valid["id"]: None, unresolved_bad["id"]: "UNRESOLVED_CREDENTIAL_BINDING"},
        )
    )

    structural_valid = _root_event(
        join_genesis, "slot-structural-valid", sequence=2,
        predecessor=grant_b["eventReferenceHex"],
    )
    structural_bad = _root_event(
        join_genesis, "slot-structural-bad", sequence=2,
        predecessor=actor_a["eventReferenceHex"],
    )
    cases.append(
        _slot_case(
            H2_SLOTS[56], join_genesis, [grant_a, grant_b, actor_a],
            {"VALID": structural_valid, "BAD": structural_bad},
            {structural_valid["id"]: None, structural_bad["id"]: "STRUCTURAL_REJECTION"},
        )
    )

    absent_bad = _root_event(
        linear_genesis, "slot-absent-dependency", parents=("ab" * 32,)
    )
    cases.append(
        _slot_case(
            H2_SLOTS[57], linear_genesis, [],
            {"VALID": valid, "BAD": absent_bad},
            {valid["id"]: None, absent_bad["id"]: "DEPENDENCY_DEFERRED"},
        )
    )
    capacity_bad = _root_event(
        linear_genesis, "slot-capacity-failure",
        parents=tuple(f"{index:064x}" for index in range(1, 10)),
    )
    cases.append(
        _slot_case(
            H2_SLOTS[58], linear_genesis, [],
            {"VALID": valid, "BAD": capacity_bad},
            {valid["id"]: None, capacity_bad["id"]: "CONTEXT_CAPACITY_EXHAUSTED"},
        )
    )

    under_a = _root_event(
        linear_genesis, "slot-under-fork-a", sequence=1,
        predecessor=root_zero["eventReferenceHex"],
    )
    under_b = _root_event(
        linear_genesis, "slot-under-fork-b", sequence=1,
        predecessor=root_zero["eventReferenceHex"],
    )
    under_d1 = _root_event(
        linear_genesis, "slot-under-fork-d1", sequence=2,
        predecessor=under_a["eventReferenceHex"],
    )
    under_d2 = _root_event(
        linear_genesis, "slot-under-fork-d2", sequence=2,
        predecessor=under_b["eventReferenceHex"],
    )
    under_records = (under_a, under_b, under_d1, under_d2)
    cases.append(
        _slot_case(
            H2_SLOTS[59], linear_genesis, [root_zero],
            {"A": under_a, "B": under_b, "D1": under_d1, "D2": under_d2},
            {record["id"]: "FORK_EVIDENCE" for record in under_records},
        )
    )

    pending_sibling = _root_event(linear_genesis, "slot-pending-sibling")
    pending_descendant = _root_event(
        linear_genesis, "slot-pending-fork-descendant", sequence=1,
        predecessor=pending_parent["eventReferenceHex"],
    )
    cases.append(
        _slot_case(
            H2_SLOTS[60], linear_genesis, [],
            {"A": pending_parent, "B": pending_sibling, "D": pending_descendant},
            {
                pending_parent["id"]: "FORK_EVIDENCE",
                pending_sibling["id"]: "FORK_EVIDENCE",
                pending_descendant["id"]: "PENDING_ANCESTOR",
            },
        )
    )
    absent_descendant = _root_event(
        linear_genesis, "slot-pending-absent-descendant", sequence=1,
        predecessor=pending_parent["eventReferenceHex"],
        parents=("cd" * 32,),
    )
    cases.append(
        _slot_case(
            H2_SLOTS[61], linear_genesis, [],
            {"P": pending_parent, "X": absent_descendant},
            {pending_parent["id"]: "PENDING_OPENING", absent_descendant["id"]: "DEPENDENCY_DEFERRED"},
        )
    )
    lexical_families = (
        (0, 2, "A", "B"),
        (2, 8, "A", "B"),
        (8, 10, "READY", "PENDING"),
        (10, 16, "A", "B"),
        (16, 18, "VALID", "BAD_SIG"),
        (18, 20, "VALID", "BAD_GRANTEE_KEY"),
        (20, 22, "CRED_A", "CRED_B"),
        (25, 49, "A", "B"),
    )
    for start, stop, left, right in lexical_families:
        for offset, index in enumerate(range(start, stop)):
            cases[index] = _retag_slot_case(
                cases[index], left, right, left_first=offset % 2 == 0
            )
        schedules = {
            cases[index]["lexicalSchedule"] for index in range(start, stop)
        }
        _require(
            schedules == {"LEFT_LT_RIGHT", "LEFT_GT_RIGHT"},
            f"{H2_SLOTS[start].scenario_id} lexical coverage",
        )

    presentation_families = (
        (62, 68, "valid-alias"),
        (68, 74, "invalid-alias"),
        (74, 80, "opening"),
        (80, 86, "wrong-opening-alias"),
        (88, 94, "unauthenticated-opening"),
        (94, 100, "wrong-opening"),
    )
    setup = [grant_a, grant_b, actor_a, actor_b]
    for start, stop, family in presentation_families:
        for offset, row in enumerate(H2_SLOTS[start:stop]):
            cases.append(
                _new_presentation_case(
                    row,
                    join_genesis,
                    setup,
                    actor_a,
                    actor_b,
                    grant_a,
                    grant_b,
                    root_zero,
                    family,
                    left_first=offset % 2 == 0,
                )
            )

    for offset, row in enumerate(H2_SLOTS[86:88]):
        shared = ("00" if offset == 0 else "ff") * 32
        independent_reference = ("ff" if offset == 0 else "00") * 32
        identities = {
            "C1": {"reference": shared, "transcriptHex": "01"},
            "C2": {"reference": shared, "transcriptHex": "02"},
            "I": {"reference": independent_reference, "transcriptHex": "03"},
        }
        cases.append(
            {
                "classifierIdentities": [identities[label] for label in row.order],
                "expectedClassifications": {
                    shared: "REFERENCE_COLLISION_UNSUPPORTED",
                    independent_reference: "UNIQUE",
                },
                "labelIds": {label: label for label in identities},
                "lexicalSchedule": (
                    "LEFT_LT_RIGHT" if offset == 0 else "LEFT_GT_RIGHT"
                ),
                "mode": "classifier",
                "row": row,
                "targets": set(identities),
            }
        )

    cases.sort(key=lambda case: case["row"].row_id)
    return tuple(cases)


def _project_slot_case(case: dict) -> dict:
    if case.get("mode") == "classifier":
        identities = [
            (value["reference"], bytes.fromhex(value["transcriptHex"]))
            for value in case["classifierIdentities"]
        ]
        classified = _classify_reference_identities(identities)
        observations = [
            {
                "classification": classified[(reference, transcript)],
                "reference": reference,
                "transcriptHex": transcript.hex(),
            }
            for reference, transcript in identities
        ]
        observed = {
            row["reference"]: row["classification"] for row in observations
        }
        _require(
            observed == case["expectedClassifications"],
            f"{case['row'].row_id} classifier result",
        )
        return {
            "lexicalSchedule": case["lexicalSchedule"],
            "observations": observations,
            "order": list(case["row"].order),
            "rowId": case["row"].row_id,
            "scenarioId": case["row"].scenario_id,
        }
    _validate_candidate_set_wrapper_identities(case["genesis"], case["records"])
    try:
        observations = evaluate_k_admission_graph(
            case["genesis"], case["records"], presentation_evidence=True
        )
    except Exception as error:
        raise RelationError(
            f"{case['row'].row_id} graph evaluation: {error}"
        ) from error
    by_id = {row["id"]: row for row in observations}
    admitted_per_reference: dict[str, int] = {}
    for observation in observations:
        if observation["kBindingAdmission"] == "ADMITTED":
            reference = observation["eventReferenceHex"]
            admitted_per_reference[reference] = (
                admitted_per_reference.get(reference, 0) + 1
            )
    for observation in observations:
        admitted = observation["kBindingAdmission"] == "ADMITTED"
        reference = observation["eventReferenceHex"]
        _require(
            observation["logicalEventReferenceHex"] == reference
            and observation["coalescedPresentationCount"]
            == (admitted_per_reference.get(reference, 0) if admitted else 0)
            and observation["logicalEventEffectCount"] == (1 if admitted else 0),
            f"{case['row'].row_id} logical-event evidence",
        )
    observed = {
        identifier: by_id[identifier]["protocolErrorCode"]
        for identifier in case["targets"]
    }
    _require(observed == case["expected"], f"{case['row'].row_id} slot result")
    for row in observations:
        if row["id"] not in case["targets"]:
            _require(
                row["kBindingAdmission"] == "ADMITTED"
                and row["protocolErrorCode"] is None,
                f"{case['row'].row_id} setup admission",
            )
    projected = [by_id[identifier] for identifier in sorted(case["targets"])]
    return {
        "lexicalSchedule": case["lexicalSchedule"],
        "observations": projected,
        "order": list(case["row"].order),
        "rowId": case["row"].row_id,
        "scenarioId": case["row"].scenario_id,
    }


def run_python_slots() -> dict:
    rows = [_project_slot_case(case) for case in slot_cases()]
    _require(len(rows) == 100, "slot Python observation count")
    return {
        "result": "PASS",
        "rows": rows,
        "schema": "styx-c03-h2-slot-observations/v1",
    }


def run_javascript_slots() -> dict:
    cases = slot_cases()
    graph_cases = [case for case in cases if case.get("mode") != "classifier"]
    classifier_cases = [case for case in cases if case.get("mode") == "classifier"]
    for case in graph_cases:
        _validate_candidate_set_wrapper_identities(case["genesis"], case["records"])
    with tempfile.TemporaryDirectory(prefix="styx-c03-h2-slots-") as tmp:
        input_path = Path(tmp) / "input.json"
        output_path = Path(tmp) / "output.json"
        input_path.write_bytes(
            dumps(
                {
                    "scenarios": [
                        {
                            "acceptedGenesisRecord": case["genesis"],
                            "graphEvaluation": True,
                            "id": case["row"].scenario_id,
                            "records": case["records"],
                        }
                        for case in graph_cases
                    ],
                    "schema": "styx-c03-h1h2-connected-input/v1",
                }
            )
        )
        completed = subprocess.run(
            [
                "node",
                str(ROOT / "node_adapter.mjs"),
                "--k-scenario-input",
                str(input_path),
                "--output",
                str(output_path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        _require(completed.returncode == 0, "JavaScript slot adapter")
        node_rows = {
            row["id"]: row for row in loads(output_path.read_bytes())["observations"]
        }
        classifier_rows = {}
        for case in classifier_cases:
            classifier_input = Path(tmp) / f"{case['row'].row_id}-input.json"
            classifier_output = Path(tmp) / f"{case['row'].row_id}-output.json"
            classifier_input.write_bytes(
                dumps(
                    {
                        "identities": case["classifierIdentities"],
                        "schema": "styx-c03-reference-identities/v1",
                    }
                )
            )
            completed = subprocess.run(
                [
                    "node",
                    str(ROOT / "node_adapter.mjs"),
                    "--classify-reference-identities",
                    str(classifier_input),
                    "--output",
                    str(classifier_output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            _require(completed.returncode == 0, "JavaScript classifier adapter")
            classifier_rows[case["row"].scenario_id] = loads(
                classifier_output.read_bytes()
            )["observations"]

    rows = []
    for case in cases:
        scenario = case["row"].scenario_id
        if case.get("mode") == "classifier":
            projected = {
                "lexicalSchedule": case["lexicalSchedule"],
                "observations": classifier_rows[scenario],
                "order": list(case["row"].order),
                "rowId": case["row"].row_id,
                "scenarioId": scenario,
            }
            _require(
                projected == _project_slot_case(case),
                f"{case['row'].row_id} cross-runtime classifier",
            )
            rows.append(projected)
            continue
        node = node_rows[scenario]
        expected_full = evaluate_k_admission_graph(
            case["genesis"], case["records"], presentation_evidence=True
        )
        _require(
            node["observations"] == expected_full,
            f"{case['row'].row_id} cross-runtime slot",
        )
        by_id = {row["id"]: row for row in node["observations"]}
        rows.append(
            {
                "lexicalSchedule": case["lexicalSchedule"],
                "observations": [
                    by_id[identifier] for identifier in sorted(case["targets"])
                ],
                "order": list(case["row"].order),
                "rowId": case["row"].row_id,
                "scenarioId": scenario,
            }
        )
    _require(rows == run_python_slots()["rows"], "slot report runtime parity")
    return {
        "result": "PASS",
        "rows": rows,
        "schema": "styx-c03-h2-slot-observations/v1",
    }


def _javascript_single(option: str, payload: dict) -> dict:
    with tempfile.TemporaryDirectory(prefix="styx-c03-detector-") as tmp:
        input_path = Path(tmp) / "input.json"
        output_path = Path(tmp) / "output.json"
        input_path.write_bytes(dumps(payload))
        completed = subprocess.run(
            [
                "node",
                str(ROOT / "node_adapter.mjs"),
                option,
                str(input_path),
                "--output",
                str(output_path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        _require(
            completed.returncode == 0,
            f"detector adapter exit:{completed.returncode}",
        )
        return loads(output_path.read_bytes())


def _run_boundary_detector(runtime: str, index: int) -> None:
    row = H1_BOUNDARY[index]
    witness = _witnesses()[row.scenario_id]
    if runtime == "python":
        _boundary_observation(row, witness)
        return
    event = witness.event
    key = event.binding.verification_key if event.binding else b""
    output = _javascript_single(
        "--h1-input",
        {
            "records": [
                {
                    "id": row.scenario_id,
                    "messageHex": event.transcript.hex(),
                    "publicKeyHex": key.hex(),
                    "signatureHex": event.signature.hex(),
                }
            ],
            "schema": "styx-c03-h1-boundary-input/v1",
        },
    )
    observed = output["observations"][0]
    accepted = row.expected == "ACCEPTED"
    guard = (
        "GUARD_ACCEPTED"
        if row.expected in {"ACCEPTED", "SIGNATURE_INVALID"}
        else row.expected
    )
    _require(
        observed
        == {
            "accepted": accepted,
            "equationInvocations": 1 if guard == "GUARD_ACCEPTED" else 0,
            "guardCode": guard,
            "id": row.scenario_id,
        },
        f"{row.row_id} boundary observation",
    )


def _run_connected_detector(runtime: str, index: int) -> None:
    case = connected_cases()[index]
    if runtime == "python":
        if case["mode"] == "graph":
            _project_graph_case(case)
        else:
            _project_vector_case(case)
        return
    if case["mode"] == "graph":
        output = _javascript_single(
            "--k-scenario-input",
            {
                "scenarios": [
                    {
                        "acceptedGenesisRecord": case["genesis"],
                        "graphEvaluation": True,
                        "id": case["row"].scenario_id,
                        "records": case["records"],
                    }
                ],
                "schema": "styx-c03-h1h2-connected-input/v1",
            },
        )["observations"][0]
        expected = _project_graph_case(case)
        projected = {
            "harnessError": output.get("harnessError"),
            "observations": output["observations"],
            "rowId": case["row"].row_id,
            "scenarioId": case["row"].scenario_id,
            "verificationBoundary": output["verificationBoundary"],
        }
    else:
        record = deepcopy(case["record"])
        record["id"] = case["row"].scenario_id
        output = _javascript_single(
            "--c03-vector-input",
            {
                "records": [record],
                "schema": "styx-c03-h1h2-vector-input/v1",
            },
        )["observations"][0]
        expected = _project_vector_case(case)
        projected = {
            "observation": output["observation"],
            "rowId": case["row"].row_id,
            "scenarioId": case["row"].scenario_id,
            "verificationBoundary": output["verificationBoundary"],
        }
    _require(projected == expected, f"{case['row'].row_id} cross-runtime")


def _run_slot_detector(runtime: str, index: int) -> None:
    case = slot_cases()[index]
    if index == 49:
        case = _retag_slot_case(
            case, "P", "X_BAD_SIG", left_first=True
        )
    cases = [case]
    if index == 61:
        cases = [
            _retag_slot_case(case, "P", "X", left_first=left_first)
            for left_first in (True, False)
        ]
    if runtime == "python":
        for value in cases:
            _project_slot_case(value)
        return
    for value in cases:
        output = _javascript_single(
            "--k-scenario-input",
            {
                "scenarios": [
                    {
                        "acceptedGenesisRecord": value["genesis"],
                        "graphEvaluation": True,
                        "id": value["row"].scenario_id,
                        "records": value["records"],
                    }
                ],
                "schema": "styx-c03-h1h2-connected-input/v1",
            },
        )["observations"][0]
        expected = _project_slot_case(value)
        _require(
            output.get("harnessError") is None,
            f"{value['row'].row_id} JavaScript harness",
        )
        _require(
            output["observations"]
            == evaluate_k_admission_graph(
                value["genesis"], value["records"], presentation_evidence=True
            ),
            f"{value['row'].row_id} cross-runtime slot",
        )
        by_id = {row["id"]: row for row in output["observations"]}
        projected = {
            "lexicalSchedule": value["lexicalSchedule"],
            "observations": [
                by_id[identifier] for identifier in sorted(value["targets"])
            ],
            "order": list(value["row"].order),
            "rowId": value["row"].row_id,
            "scenarioId": value["row"].scenario_id,
        }
        _require(projected == expected, f"{value['row'].row_id} slot projection")


def run_detector(mutant: str, runtime: str) -> None:
    _require(mutant in DETECTORS, "unknown mutant detector")
    _require(runtime in {"python", "javascript"}, "unknown detector runtime")
    family, index = DETECTORS[mutant]
    if family == "boundary":
        _run_boundary_detector(runtime, index)
    elif family == "connected":
        _run_connected_detector(runtime, index)
    else:
        _run_slot_detector(runtime, index)


def _detector_marker(mutant: str) -> str:
    family, index = DETECTORS[mutant]
    rows = {
        "boundary": H1_BOUNDARY,
        "connected": H1_CONNECTED,
        "slot": H2_SLOTS,
    }[family]
    return rows[index].row_id


def _invoke_detector(source_root: Path, mutant: str, runtime: str) -> subprocess.CompletedProcess:
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [
            sys.executable,
            str(source_root / "c03/h1_h2_relation.py"),
            "--run-detector",
            mutant,
            "--runtime",
            runtime,
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=environment,
    )


def _copy_mutation_sources(destination: Path) -> None:
    for name in ("c03", "o10", "o14"):
        source = ROOT.parent / name
        shutil.copytree(
            source,
            destination / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )


def _apply_mutation(source_root: Path, spec: MutationSpec, runtime: str) -> tuple[str, str]:
    if runtime == "python":
        path = source_root / "c03/corpus_model.py"
        anchor = spec.python_anchor
        replacement = spec.python_replacement
    else:
        path = source_root / "c03/node_adapter.mjs"
        anchor = spec.javascript_anchor
        replacement = spec.javascript_replacement
    source = path.read_text(encoding="utf-8")
    _require(source.count(anchor) == 1, f"{spec.identifier} source anchor")
    before = sha256(source.encode()).hexdigest()
    mutated = source.replace(anchor, replacement, 1)
    _require(mutated != source, f"{spec.identifier} no-op mutation")
    path.write_text(mutated, encoding="utf-8")
    after = sha256(path.read_bytes()).hexdigest()
    _require(before != after, f"{spec.identifier} unchanged digest")
    return before, after


def _run_one_mutation(mutant: str, runtime: str) -> dict:
    _require(runtime in {"python", "javascript"}, "unknown mutation runtime")
    _require(mutant in MUTATION_SPECS, "unknown mutation")
    spec = MUTATION_SPECS[mutant]
    with tempfile.TemporaryDirectory(prefix=f"styx-c03-{runtime}-mutant-") as tmp:
        source_root = Path(tmp) / "tools/causal-flow-simulator"
        source_root.mkdir(parents=True)
        _copy_mutation_sources(source_root)
        control = _invoke_detector(source_root, mutant, runtime)
        _require(
            control.returncode == 0
            and f"detector_pass={mutant}:{runtime}" in control.stdout,
            f"{mutant} unmutated detector",
        )
        before, after = _apply_mutation(source_root, spec, runtime)
        mutated = _invoke_detector(source_root, mutant, runtime)
        marker = _detector_marker(mutant)
        _require(
            mutated.returncode == 2
            and "semantic_detector_failure=" in mutated.stderr
            and marker in mutated.stderr
            and "detector adapter exit:" not in mutated.stderr,
            f"{mutant} wrong-detector or non-semantic kill",
        )
        return {
            "detectorId": marker,
            "mutantId": mutant,
            "result": "KILLED",
            "runtime": runtime,
            "sourceDigestChanged": before != after,
        }


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    _require(not path.exists(), "JSONL output already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join(dumps(row) for row in rows))


def run_mutations(
    runtime: str,
    *,
    mutation_log: Path | None = None,
    checkout_role: str | None = None,
) -> dict:
    _require(runtime in {"python", "javascript"}, "unknown mutation runtime")
    if mutation_log is not None:
        _require(
            checkout_role in {"CHECKOUT_1", "CHECKOUT_2"},
            "mutation log requires checkout role",
        )
    rows = []
    command_rows = []
    for mutant in MUTANTS:
        with tempfile.TemporaryDirectory(prefix="styx-c03-mutation-result-") as tmp:
            output = Path(tmp) / "result.json"
            argv = [
                sys.executable,
                str(Path(__file__).resolve()),
                "--run-one-mutation",
                mutant,
                "--runtime",
                runtime,
                "--output",
                str(output),
            ]
            completed = subprocess.run(
                argv,
                cwd=REPO,
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
                env=dict(os.environ),
            )
            _require(completed.returncode == 0, f"{mutant} mutation command failed")
            row = loads(output.read_bytes())
            _require(isinstance(row, dict), f"{mutant} mutation result")
            rows.append(row)
            if mutation_log is not None:
                command_rows.append(
                    {
                        "argv": argv,
                        "checkoutRole": checkout_role,
                        "commandId": mutant,
                        "exitStatus": completed.returncode,
                        "stderrUtf8": completed.stderr,
                        "stdoutUtf8": completed.stdout,
                    }
                )
    _require(len(rows) == 24, "mutation kill count")
    if mutation_log is not None:
        _write_jsonl(mutation_log, command_rows)
    return {
        "killed": 24,
        "result": "PASS",
        "rows": rows,
        "runtime": runtime,
        "schema": "styx-c03-h1h2-mutation-observations/v1",
    }


def _run_regression_command(command: list[str], output: Path) -> None:
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [*command, "--output", str(output)],
        cwd=REPO,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
        env=environment,
    )
    _require(completed.returncode == 0, "historical producer failed")
    expected_kind = output.is_dir() if output.name == "generated" else output.is_file()
    _require(expected_kind and not output.is_symlink(), "historical output missing")


def run_regression() -> dict:
    corpus = REPO / "conformance/application-protocol/c03"
    for name, expected in FROZEN_CORPUS_SHA256.items():
        path = corpus / name
        _require(
            path.is_file() and sha256(path.read_bytes()).hexdigest() == expected,
            f"frozen corpus drift:{name}",
        )

    with tempfile.TemporaryDirectory(prefix="styx-c03-regression-") as tmp:
        workspace = Path(tmp)
        generated = workspace / "generated"
        commands = (
            (
                "generate",
                [
                    sys.executable,
                    str(ROOT / "generate_corpus.py"),
                    "--repo-root",
                    str(REPO),
                ],
                generated,
            ),
            (
                "validate",
                [
                    sys.executable,
                    str(ROOT / "validate_corpus.py"),
                    "--repo-root",
                    str(REPO),
                    "--corpus",
                    str(corpus),
                ],
                workspace / "validate.json",
            ),
            (
                "replay",
                [
                    sys.executable,
                    str(ROOT / "replay_corpus.py"),
                    "--repo-root",
                    str(REPO),
                    "--corpus",
                    str(corpus),
                ],
                workspace / "replay.json",
            ),
            (
                "node",
                [
                    "node",
                    str(ROOT / "node_adapter.mjs"),
                    "--repo-root",
                    str(REPO),
                    "--corpus",
                    str(corpus),
                ],
                workspace / "node.json",
            ),
            (
                "cross-runtime",
                [
                    sys.executable,
                    str(ROOT / "run_cross_runtime.py"),
                    "--repo-root",
                    str(REPO),
                    "--corpus",
                    str(corpus),
                ],
                workspace / "cross.json",
            ),
            (
                "historical-mutations",
                [
                    sys.executable,
                    str(ROOT / "run_mutations.py"),
                    "--repo-root",
                    str(REPO),
                    "--corpus",
                    str(corpus),
                ],
                workspace / "mutations.json",
            ),
        )
        completed_ids = []
        for identifier, command, output in commands:
            _run_regression_command(command, output)
            completed_ids.append(identifier)

        generated_files = {
            path.name: path.read_bytes()
            for path in generated.iterdir()
            if path.is_file() and not path.is_symlink()
        }
        corpus_files = {
            path.name: path.read_bytes()
            for path in corpus.iterdir()
            if path.is_file() and not path.is_symlink()
        }
        _require(generated_files == corpus_files, "generated corpus drift")

    return {
        "checks": [
            {"id": identifier, "result": "PASS"}
            for identifier in completed_ids
        ],
        "frozenCorpusFiles": len(FROZEN_CORPUS_SHA256),
        "result": "PASS",
        "schema": "styx-c03-h1h2-regression-observations/v1",
    }


def _validate_issue_appendix(issue_body: bytes) -> IssueAppendixAuthority:
    _require(
        sha256(issue_body).hexdigest() == RATIFIED_ISSUE_BODY_SHA256,
        "ratified Issue body mismatch",
    )
    text = issue_body.decode("utf-8")
    _require("## Appendix A — literal Package-A hostile relation" in text, "Appendix A missing")
    appendix = text.split("## Appendix A — literal Package-A hostile relation", 1)[1]
    boundary = re.findall(
        r"^\| `(H1-BND-\d{3})` \| `([^`]+)` \| `([^`]+)` \|$",
        appendix,
        re.MULTILINE,
    )
    connected_raw = re.findall(
        r"^\| `(H1-CON-\d{3})` \| `([^`]+)` \| (.*?) \|$",
        appendix,
        re.MULTILINE,
    )
    slots_raw = re.findall(
        r"^\| `(H2-SLT-\d{3})` / `([^`]+)` \| `([^`]+)` \| (.*?) \|$",
        appendix,
        re.MULTILINE,
    )
    mutants = re.findall(
        r"^\| `(M-(?:H1|H2)-[^`]+)` \| (.*?) \|$",
        appendix,
        re.MULTILINE,
    )
    _require(
        boundary
        == [(row.row_id, row.scenario_id, row.expected) for row in H1_BOUNDARY],
        "Appendix A boundary relation mismatch",
    )
    try:
        connected = [
            (row_id, scenario_id, APPENDIX_CONNECTED_OBSERVATIONS[observation])
            for row_id, scenario_id, observation in connected_raw
        ]
    except KeyError as error:
        raise RelationError("Appendix A connected observation mismatch") from error
    _require(
        connected
        == [(row.row_id, row.scenario_id, row.expected) for row in H1_CONNECTED],
        "Appendix A connected relation mismatch",
    )
    try:
        slots = [
            (
                row_id,
                scenario_id,
                order,
                APPENDIX_SLOT_OBSERVATIONS[observation],
            )
            for row_id, scenario_id, order, observation in slots_raw
        ]
    except KeyError as error:
        raise RelationError("Appendix A slot observation mismatch") from error
    executable_slots = {
        row.row_id: (row.row_id, row.scenario_id, ">".join(row.order), row.expected)
        for row in H2_SLOTS
    }
    _require(
        all(row_id in executable_slots for row_id, *_ in slots)
        and slots == [executable_slots[row_id] for row_id, *_ in slots]
        and tuple(row_id for row_id, *_ in slots)
        == tuple(f"H2-SLT-{index:03d}" for index in range(1, 63)),
        "Appendix A slot relation mismatch",
    )
    executable_mutants = {
        identifier: (identifier, APPENDIX_MUTANT_DESCRIPTIONS[identifier])
        for identifier in MUTANTS
    }
    _require(
        all(identifier in executable_mutants for identifier, _ in mutants)
        and mutants == [executable_mutants[identifier] for identifier, _ in mutants]
        and len(mutants) == 20,
        "Appendix A mutant relation mismatch",
    )
    return IssueAppendixAuthority(tuple(slots), tuple(mutants))


def _v4_sections(incorporated: bytes) -> dict[int, bytes]:
    try:
        incorporated.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RelationError("incorporated V4 is not UTF-8") from error
    matches = list(
        re.finditer(rb"^## (\d+)\. ([^\n]+)\n", incorporated, re.MULTILINE)
    )
    _require(
        [int(match.group(1)) for match in matches] == list(range(1, 11)),
        "incorporated V4 section relation mismatch",
    )
    expected_titles = {
        2: b"Exact supersession and parsing sources",
        3: b"Exact documentation reconstruction",
        4: b"Historical guard exact reconstruction",
        6: b"Literal additional relation rows",
        7: b"Additional mutants and closed counts",
        8: b"Exact non-circular evidence package",
    }
    for number, title in expected_titles.items():
        _require(matches[number - 1].group(2) == title, f"V4 section {number} heading")
    sections = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(incorporated)
        sections[int(match.group(1))] = incorporated[match.end():end]
    return sections


def _fenced_blocks(section: bytes) -> tuple[tuple[str, bytes], ...]:
    rows = re.findall(
        rb"^```([a-z0-9_-]*)\n(.*?)^```\n",
        section,
        re.MULTILINE | re.DOTALL,
    )
    return tuple((language.decode("ascii"), body) for language, body in rows)


def _parse_pin_block(block: bytes) -> tuple[tuple[str, str], ...]:
    rows = []
    for line in block.decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^\s]+)", line)
        _require(match is not None, "V4 reconstruction pin row mismatch")
        rows.append((match.group(2), match.group(1)))
    _require(len(rows) == len(set(path for path, _ in rows)), "duplicate V4 pin path")
    return tuple(rows)


def _parse_v4_structure(incorporated: bytes) -> V4Authority:
    sections = _v4_sections(incorporated)

    document_matches = re.findall(
        rb"^`([^`\n]+)`:\n\n```markdown\n(.*?)^```\n",
        sections[3],
        re.MULTILINE | re.DOTALL,
    )
    _require(len(document_matches) == 3, "V4 documentation block relation")
    documentation_blocks = tuple(
        (path.decode("utf-8"), block) for path, block in document_matches
    )
    section_3_fences = _fenced_blocks(sections[3])
    _require(
        tuple(language for language, _ in section_3_fences)
        == ("markdown", "markdown", "markdown", "text"),
        "V4 documentation fence relation",
    )
    documentation_pins = _parse_pin_block(section_3_fences[-1][1])
    _require(
        tuple(path for path, _ in documentation_blocks)
        == tuple(path for path, _ in documentation_pins),
        "V4 documentation path relation",
    )

    section_4_fences = _fenced_blocks(sections[4])
    _require(
        tuple(language for language, _ in section_4_fences)
        == ("python", "text", "text"),
        "V4 historical-guard fence relation",
    )
    anchor_match = re.search(
        rb"inserted immediately after the Base line containing\n`([^`\n]+)`:",
        sections[4],
    )
    _require(anchor_match is not None, "V4 historical insertion anchor")
    replacement_chunks = section_4_fences[1][1].decode("utf-8").strip("\n").split("\n\n")
    replacements = []
    for chunk in replacement_chunks:
        pieces = chunk.split("\n-> ")
        _require(len(pieces) == 2 and all(pieces), "V4 historical replacement row")
        replacements.append((pieces[0].encode("utf-8"), pieces[1].encode("utf-8")))
    _require(len(replacements) == 2, "V4 historical replacement count")
    historical_pins = _parse_pin_block(section_4_fences[-1][1])
    _require(len(historical_pins) == 2, "V4 historical pin count")

    slot_matches = re.findall(
        rb"^\| `(H2-SLT-\d{3})` / `([^`]+)` \| `([^`]+)` \| (.*?) \|$",
        sections[6],
        re.MULTILINE,
    )
    _require(len(slot_matches) == 38, "V4 slot-row count")
    reverse_observations = {value: key for key, value in V4_SLOT_OBSERVATIONS.items()}
    _require(
        len(reverse_observations) == len(V4_SLOT_OBSERVATIONS),
        "V4 observation grammar is not injective",
    )
    slot_rows = []
    for row_id_raw, scenario_raw, order_raw, observation_raw in slot_matches:
        row_id = row_id_raw.decode("ascii")
        scenario = scenario_raw.decode("utf-8")
        order = order_raw.decode("ascii")
        observation = observation_raw.decode("utf-8")
        try:
            expected = V4_SLOT_OBSERVATIONS[observation]
        except KeyError as error:
            raise RelationError("V4 slot observation grammar mismatch") from error
        _require(
            reverse_observations[expected] == observation,
            "V4 slot observation round-trip mismatch",
        )
        slot_rows.append((row_id, scenario, order, expected))
    _require(
        tuple(row_id for row_id, *_ in slot_rows)
        == tuple(f"H2-SLT-{index:03d}" for index in range(63, 101))
        and len({scenario for _, scenario, _, _ in slot_rows}) == 38,
        "V4 slot identifier relation",
    )
    _require(
        tuple(slot_rows)
        == tuple(
            (row.row_id, row.scenario_id, ">".join(row.order), row.expected)
            for row in H2_SLOTS[62:]
        ),
        "V4 slot executable mirror mismatch",
    )

    mutant_matches = re.findall(
        rb"^\| `(M-H2-[^`]+)` \| (.*?) \|$", sections[7], re.MULTILINE
    )
    mutant_rows = tuple(
        (identifier.decode("ascii"), description.decode("utf-8"))
        for identifier, description in mutant_matches
    )
    _require(
        mutant_rows
        == tuple(
            (identifier, APPENDIX_MUTANT_DESCRIPTIONS[identifier])
            for identifier in MUTANTS[20:]
        ),
        "V4 mutant executable mirror mismatch",
    )
    normalized_7 = " ".join(sections[7].decode("utf-8").split())
    kill_sentences = {
        "M-H2-GLOBAL-REFERENCE-ABORT":
            "`M-H2-GLOBAL-REFERENCE-ABORT` is killed by connected row 063, not solely by the private classifier.",
        "M-H2-ALIAS-BEFORE-AUTH":
            "`M-H2-ALIAS-BEFORE-AUTH` is killed by row 069;",
        "M-H2-ALIAS-POISON":
            "`M-H2-ALIAS-POISON` by rows 069 and 081;",
        "M-H2-ALIAS-MULTI-EFFECT":
            "`M-H2-ALIAS-MULTI-EFFECT` by row 063 and the measured commit counter.",
    }
    for sentence in kill_sentences.values():
        _require(normalized_7.count(sentence) == 1, "V4 mutant kill relation")
    mutant_kill_rows = (
        ("M-H2-GLOBAL-REFERENCE-ABORT", ("H2-SLT-063",)),
        ("M-H2-ALIAS-BEFORE-AUTH", ("H2-SLT-069",)),
        ("M-H2-ALIAS-POISON", ("H2-SLT-069", "H2-SLT-081")),
        ("M-H2-ALIAS-MULTI-EFFECT", ("H2-SLT-063",)),
    )
    for identifier, row_ids in mutant_kill_rows:
        _require(
            _detector_marker(identifier) in row_ids,
            f"V4 detector mismatch:{identifier}",
        )
    _require(
        sections[7].count(V4_INVALID_KILL_SENTENCE) == 1,
        "V4 invalid-kill sentence mismatch",
    )
    section_7_fences = _fenced_blocks(sections[7])
    _require(
        tuple(language for language, _ in section_7_fences) == ("text",),
        "V4 count fence relation",
    )
    count_rows = {}
    for line in section_7_fences[0][1].decode("utf-8").splitlines():
        match = re.fullmatch(r"([^:]+): (\d+)", line)
        _require(match is not None, "V4 closed-count row mismatch")
        count_rows[match.group(1)] = int(match.group(2))
    _require(
        count_rows
        == {
            "H1 boundary rows": len(H1_BOUNDARY),
            "connected/disconnected rows": len(H1_CONNECTED),
            "slot/readiness/presentation rows": len(H2_SLOTS),
            "logical scenarios per runtime": len(H1_BOUNDARY) + len(H1_CONNECTED) + len(H2_SLOTS),
            "cross-runtime observations": 2 * (len(H1_BOUNDARY) + len(H1_CONNECTED) + len(H2_SLOTS)),
            "real source mutants": len(MUTANTS),
            "required mutant/runtime kills": 2 * len(MUTANTS),
        },
        "V4 closed-count relation mismatch",
    )

    section_8_fences = _fenced_blocks(sections[8])
    _require(
        len(section_8_fences) == 5
        and all(language == "text" for language, _ in section_8_fences),
        "V4 package fence relation",
    )
    tep_filenames = tuple(section_8_fences[0][1].decode("ascii").splitlines())
    tep_argument_names = tuple(
        value.decode("ascii")
        for value in re.findall(rb"--[a-z0-9-]+", section_8_fences[1][1])
    )
    tool_names = tuple(
        line.split("<TAB>", 1)[0]
        for line in section_8_fences[2][1].decode("ascii").splitlines()
    )
    environment_spec = tuple(section_8_fences[3][1].decode("ascii").splitlines())
    command_ids = tuple(section_8_fences[4][1].decode("ascii").splitlines())
    _require(tep_filenames == TEP_FILENAMES, "V4 TEP filename relation")
    _require(tep_argument_names == V4_TEP_ARGUMENT_NAMES, "V4 TEP argument relation")
    _require(tool_names == TOOL_NAMES, "V4 tool-name relation")
    _require(environment_spec == V4_ENVIRONMENT_SPEC, "V4 environment relation")
    _require(command_ids == REQUIRED_COMMAND_IDS, "V4 command-ID relation")

    pins = (*documentation_pins, *historical_pins)
    _require(dict(pins) == EXACT_RECONSTRUCTED_PINS, "V4 reconstruction pin mirror")
    return V4Authority(
        slot_rows=tuple(slot_rows),
        mutant_rows=mutant_rows,
        mutant_kill_rows=mutant_kill_rows,
        documentation_blocks=documentation_blocks,
        historical_insert_anchor=anchor_match.group(1),
        historical_insert_block=section_4_fences[0][1],
        historical_replacements=tuple(replacements),
        reconstructed_pins=tuple(pins),
        tep_filenames=tep_filenames,
        tep_argument_names=tep_argument_names,
        tool_names=tool_names,
        environment_spec=environment_spec,
        command_ids=command_ids,
    )


def _parse_v4_authority(incorporated: bytes) -> V4Authority:
    _require(
        sha256(incorporated).hexdigest() == RATIFICATION_V4_SHA256,
        "incorporated V4 identity mismatch",
    )
    return _parse_v4_structure(incorporated)


def _validate_provider_authority(
    issue_body: bytes, incorporated: bytes
) -> V4Authority:
    issue = _validate_issue_appendix(issue_body)
    v4 = _parse_v4_authority(incorporated)
    executable_slots = tuple(
        (row.row_id, row.scenario_id, ">".join(row.order), row.expected)
        for row in H2_SLOTS
    )
    _require(
        issue.slot_rows + v4.slot_rows == executable_slots,
        "provider-owned complete slot relation mismatch",
    )
    executable_mutants = tuple(
        (identifier, APPENDIX_MUTANT_DESCRIPTIONS[identifier])
        for identifier in MUTANTS
    )
    _require(
        issue.mutant_rows + v4.mutant_rows == executable_mutants,
        "provider-owned complete mutant relation mismatch",
    )
    kill_rows = dict(v4.mutant_kill_rows)
    for identifier, _ in v4.mutant_rows:
        detector = _detector_marker(identifier)
        _require(detector in kill_rows[identifier], f"V4 detector mismatch:{identifier}")
        if len(kill_rows[identifier]) == 1:
            _require(detector == kill_rows[identifier][0], f"V4 detector mismatch:{identifier}")
    return v4


def _validate_v4_reconstruction(
    checkout: Path, base: str, candidate: str, authority: V4Authority
) -> None:
    pins = dict(authority.reconstructed_pins)
    for path, block in authority.documentation_blocks:
        base_blob = _git_bytes(checkout, "show", f"{base}:{path}")
        candidate_blob = _git_bytes(checkout, "show", f"{candidate}:{path}")
        _require(
            candidate_blob == base_blob + b"\n" + block
            and sha256(candidate_blob).hexdigest() == pins[path],
            f"provider-owned documentation reconstruction mismatch:{path}",
        )

    scope_path = "tools/causal-flow-simulator/c03/scope_guard.py"
    scope_base = _git_bytes(checkout, "show", f"{base}:{scope_path}")
    lines = scope_base.splitlines(keepends=True)
    matches = [
        index for index, line in enumerate(lines)
        if authority.historical_insert_anchor in line
    ]
    _require(len(matches) == 1, "provider-owned historical insertion anchor")
    insert_at = matches[0] + 1
    scope_expected = b"".join(
        (*lines[:insert_at], authority.historical_insert_block, *lines[insert_at:])
    )
    scope_candidate = _git_bytes(checkout, "show", f"{candidate}:{scope_path}")
    _require(
        scope_candidate == scope_expected
        and sha256(scope_candidate).hexdigest() == pins[scope_path],
        "provider-owned historical scope reconstruction mismatch",
    )

    test_path = "tools/causal-flow-simulator/c03/tests/test_scope_guard.py"
    test_expected = _git_bytes(checkout, "show", f"{base}:{test_path}")
    for before, after in authority.historical_replacements:
        _require(test_expected.count(before) == 1, "provider-owned historical replacement anchor")
        test_expected = test_expected.replace(before, after, 1)
    test_candidate = _git_bytes(checkout, "show", f"{candidate}:{test_path}")
    _require(
        test_candidate == test_expected
        and sha256(test_candidate).hexdigest() == pins[test_path],
        "provider-owned historical test reconstruction mismatch",
    )


def _load_provider_object(path: Path) -> dict:
    _require(path.is_file() and not path.is_symlink(), "invalid provider object")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RelationError("invalid provider JSON") from error
    _require(isinstance(value, dict), "provider object is not an object")
    return value


def _validate_issue_rest(path: Path) -> tuple[dict, bytes]:
    issue = _load_provider_object(path)
    _require(
        issue.get("number") == 297
        and issue.get("repository_url")
        == "https://api.github.com/repos/styx-secure/styx"
        and issue.get("html_url")
        == "https://github.com/styx-secure/styx/issues/297",
        "Issue provider identity mismatch",
    )
    body = issue.get("body")
    _require(isinstance(body, str), "Issue body missing")
    body_bytes = body.encode("utf-8")
    _require(
        sha256(body_bytes).hexdigest() == RATIFIED_ISSUE_BODY_SHA256,
        "Issue body identity mismatch",
    )
    _validate_issue_appendix(body_bytes)
    return issue, body_bytes


def _validate_ratification_comment_rest(path: Path) -> tuple[dict, bytes, bytes]:
    comment = _load_provider_object(path)
    _require(
        comment.get("id") == RATIFICATION_COMMENT_ID
        and comment.get("url")
        == f"https://api.github.com/repos/styx-secure/styx/issues/comments/{RATIFICATION_COMMENT_ID}"
        and comment.get("issue_url")
        == "https://api.github.com/repos/styx-secure/styx/issues/297"
        and comment.get("user", {}).get("login") == "maverde73"
        and comment.get("user", {}).get("id") == 141346846
        and comment.get("created_at") == comment.get("updated_at"),
        "ratification-comment provider identity mismatch",
    )
    body = comment.get("body")
    _require(isinstance(body, str), "ratification-comment body missing")
    body_bytes = body.encode("utf-8")
    _require(
        sha256(body_bytes).hexdigest() == RATIFICATION_COMMENT_BODY_SHA256,
        "ratification-comment body identity mismatch",
    )
    start = b"<!-- styx-c03-package-a-remediation-v4:incorporated:start -->\n"
    end = b"<!-- styx-c03-package-a-remediation-v4:incorporated:end -->"
    _require(
        body_bytes.count(start) == 1 and body_bytes.count(end) == 1,
        "ratification-comment incorporated markers mismatch",
    )
    incorporated = body_bytes.split(start, 1)[1].split(end, 1)[0]
    _require(
        sha256(incorporated).hexdigest() == RATIFICATION_V4_SHA256,
        "incorporated V4 identity mismatch",
    )
    return comment, body_bytes, incorporated


def _validate_pr_rest(path: Path, candidate: str) -> tuple[dict, bytes]:
    pull = _load_provider_object(path)
    _require(
        pull.get("state") == "open"
        and pull.get("draft") is True
        and pull.get("merged") is False
        and isinstance(pull.get("number"), int)
        and pull.get("head", {}).get("sha") == candidate
        and pull.get("head", {}).get("ref")
        == "task/297-c03-k-h1-h2-package-a"
        and pull.get("head", {}).get("repo", {}).get("full_name")
        == "styx-secure/styx"
        and pull.get("base", {}).get("ref") == "main"
        and pull.get("base", {}).get("repo", {}).get("full_name")
        == "styx-secure/styx",
        "Draft PR provider identity mismatch",
    )
    body = pull.get("body")
    _require(isinstance(body, str), "Draft PR body missing")
    return pull, body.encode("utf-8")


def _write_new_bytes(path: Path, payload: bytes) -> None:
    _require(not path.exists(), f"output already exists:{path.name}")
    path.write_bytes(payload)


def _resolve_toolchain() -> tuple[dict[str, str], bytes]:
    commands = {
        "git": ("--version",),
        "python3": ("--version",),
        "node": ("--version",),
        "diff": ("--version",),
        "sha256sum": ("--version",),
    }
    tools: dict[str, str] = {}
    for name in TOOL_NAMES:
        located = shutil.which(name)
        _require(located is not None, f"required tool unavailable:{name}")
        executable = Path(located).resolve()
        _require(
            executable.is_absolute()
            and executable.is_file()
            and os.access(executable, os.X_OK),
            f"invalid tool executable:{name}",
        )
        tools[name] = str(executable)
    rows = []
    with tempfile.TemporaryDirectory(prefix="styx-c03-tool-versions-") as tmp:
        environment = _closed_environment(tools, Path(tmp) / "environment")
        for name in TOOL_NAMES:
            completed = subprocess.run(
                [tools[name], *commands[name]],
                check=False,
                capture_output=True,
                env=environment,
            )
            _require(completed.returncode == 0, f"tool version failed:{name}")
            try:
                stdout = completed.stdout.decode("utf-8")
            except UnicodeDecodeError as error:
                raise RelationError(f"tool version is not UTF-8:{name}") from error
            lines = stdout.splitlines()
            _require(lines and lines[0], f"tool version missing:{name}")
            rows.append(f"{name}\t{tools[name]}\t{lines[0]}\n")
    return tools, "".join(rows).encode("utf-8")


def _closed_environment(tools: dict[str, str], root: Path) -> dict[str, str]:
    _require(not root.exists(), "environment root already exists")
    root.mkdir()
    home = root / "home"
    temporary = root / "tmp"
    home.mkdir()
    temporary.mkdir()
    directories = []
    for name in TOOL_NAMES:
        parent = str(Path(tools[name]).parent)
        if parent not in directories:
            directories.append(parent)
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.pathsep.join(directories),
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(temporary),
        "TZ": "UTC",
    }


@contextmanager
def _process_environment(environment: dict[str, str]):
    original = dict(os.environ)
    original_tempdir = tempfile.tempdir
    os.environ.clear()
    os.environ.update(environment)
    tempfile.tempdir = None
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(original)
        tempfile.tempdir = original_tempdir


def _command_row(
    command_id: str,
    argv: list[str],
    checkout_role: str,
    completed: subprocess.CompletedProcess,
) -> dict:
    try:
        stdout = completed.stdout.decode("utf-8")
        stderr = completed.stderr.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RelationError(f"non-UTF-8 command output:{command_id}") from error
    return {
        "argv": argv,
        "checkoutRole": checkout_role,
        "commandId": command_id,
        "exitStatus": completed.returncode,
        "stderrUtf8": stderr,
        "stdoutUtf8": stdout,
    }


def _run_logged_command(
    *,
    command_id: str,
    argv: list[str],
    checkout: Path,
    candidate: str,
    checkout_role: str,
    environment: dict[str, str],
    timeout: int = 300,
) -> dict:
    _clean_checkout(checkout, candidate)
    completed = subprocess.run(
        argv,
        cwd=checkout,
        check=False,
        capture_output=True,
        timeout=timeout,
        env=environment,
    )
    row = _command_row(command_id, argv, checkout_role, completed)
    _require(completed.returncode == 0, f"required command failed:{command_id}")
    _clean_checkout(checkout, candidate)
    return row


def _issue_scope_preflight(issue_body: bytes) -> str:
    text = issue_body.decode("utf-8")
    marker = "Before importing or executing candidate code"
    _require(text.count(marker) == 1, "Issue scope-preflight marker mismatch")
    suffix = text.split(marker, 1)[1]
    match = re.search(
        r"```bash\npython3 - <<'PY'\n(.*?)\nPY\n```",
        suffix,
        re.DOTALL,
    )
    _require(match is not None, "Issue scope-preflight script missing")
    return match.group(1) + "\n"


def _validate_jsonl(
    payload: bytes,
    *,
    expected_ids: tuple[str, ...],
    checkout_role: str,
) -> list[dict]:
    _require(payload.endswith(b"\n"), "JSONL requires final LF")
    rows = []
    for raw in payload.splitlines():
        row = loads(raw + b"\n")
        _require(
            isinstance(row, dict)
            and set(row)
            == {
                "argv",
                "checkoutRole",
                "commandId",
                "exitStatus",
                "stderrUtf8",
                "stdoutUtf8",
            }
            and isinstance(row["argv"], list)
            and all(isinstance(value, str) for value in row["argv"])
            and row["checkoutRole"] == checkout_role
            and row["exitStatus"] == 0
            and isinstance(row["stdoutUtf8"], str)
            and isinstance(row["stderrUtf8"], str),
            "invalid command-ledger row",
        )
        rows.append(row)
    _require(
        tuple(row["commandId"] for row in rows) == expected_ids,
        "command-ledger ID relation mismatch",
    )
    return rows


def _flat_regular_files(root: Path) -> dict[str, Path]:
    _require(root.is_dir() and not root.is_symlink(), "invalid flat package")
    result: dict[str, Path] = {}
    for path in root.iterdir():
        metadata = path.lstat()
        _require(
            stat.S_ISREG(metadata.st_mode)
            and not path.is_symlink()
            and metadata.st_nlink == 1
            and "/" not in path.name
            and "\\" not in path.name,
            f"invalid package artifact:{path.name}",
        )
        _require(path.name not in result, "duplicate package artifact")
        result[path.name] = path
    return result


def _manifest_bytes(root: Path) -> bytes:
    rows = []
    for name in sorted(value for value in TEP_FILENAMES if value != "SHA256SUMS.txt"):
        rows.append(f"{sha256((root / name).read_bytes()).hexdigest()}  {name}\n")
    return "".join(rows).encode("ascii")


def _git_environment() -> dict[str, str]:
    """Return a deterministic Git environment that cannot replace objects."""
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
    )
    return environment


def _git_command(checkout: Path, *arguments: str) -> list[str]:
    return [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        "-C",
        str(checkout),
        *arguments,
    ]


def _git_text(checkout: Path, *arguments: str) -> str:
    completed = subprocess.run(
        _git_command(checkout, *arguments),
        check=False,
        capture_output=True,
        text=True,
        env=_git_environment(),
    )
    _require(completed.returncode == 0, "Git evidence command failed")
    return completed.stdout.strip()


def _git_bytes(checkout: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        _git_command(checkout, *arguments),
        check=False,
        capture_output=True,
        env=_git_environment(),
    )
    _require(completed.returncode == 0, "Git evidence command failed")
    return completed.stdout


def run_package_a_scope(
    checkout: Path, base: str, candidate: str
) -> dict:
    _require(base == BASE_SHA, "scope Base mismatch")
    _require(
        _git_text(checkout, "rev-parse", f"{base}^{{commit}}") == base
        and _git_text(checkout, "rev-parse", f"{candidate}^{{commit}}")
        == candidate,
        "scope commit identity mismatch",
    )
    _require(
        _git_text(checkout, "merge-base", base, candidate) == base,
        "scope Base ancestry mismatch",
    )
    for path, expected in PACKAGE_A_BASE_PINS.items():
        _require(
            sha256(_git_bytes(checkout, "show", f"{base}:{path}")).hexdigest()
            == expected,
            f"scope Base pin mismatch:{path}",
        )
    for path in PACKAGE_A_NEW:
        completed = subprocess.run(
            _git_command(checkout, "cat-file", "-e", f"{base}:{path}"),
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_git_environment(),
        )
        _require(completed.returncode != 0, f"new endpoint exists at Base:{path}")
    fields = _git_bytes(
        checkout, "diff", "--name-status", "-z", "--no-renames", base, candidate
    ).split(b"\0")
    if fields and not fields[-1]:
        fields.pop()
    _require(len(fields) % 2 == 0, "malformed scope relation")
    rows = []
    changed = set()
    for index in range(0, len(fields), 2):
        status = fields[index].decode("ascii")
        path = fields[index + 1].decode("utf-8")
        _require(status in {"A", "M"}, f"forbidden endpoint status:{status}")
        _require(path in PACKAGE_A_ALLOWED, f"out-of-scope endpoint:{path}")
        _require(path not in changed, f"duplicate endpoint:{path}")
        _require(
            (status == "A") == (path in PACKAGE_A_NEW),
            f"wrong endpoint state:{path}",
        )
        changed.add(path)
        rows.append({"paths": [path], "status": status})
    _require(PACKAGE_A_NEW <= changed, "missing Package-A evidence endpoint")
    copy_fields = _git_bytes(
        checkout,
        "diff",
        "--name-status",
        "-z",
        "--find-copies-harder",
        "--find-copies=50%",
        "--find-renames=50%",
        "-l0",
        base,
        candidate,
    ).split(b"\0")
    _require(
        not any(value[:1] in {b"C", b"R"} for value in copy_fields if value),
        "copy/rename relation forbidden",
    )
    for path, expected in EXACT_RECONSTRUCTED_PINS.items():
        _require(
            sha256(_git_bytes(checkout, "show", f"{candidate}:{path}")).hexdigest()
            == expected,
            f"exact reconstruction mismatch:{path}",
        )
    for name, expected in FROZEN_CORPUS_SHA256.items():
        path = f"conformance/application-protocol/c03/{name}"
        _require(
            sha256(_git_bytes(checkout, "show", f"{candidate}:{path}")).hexdigest()
            == expected,
            f"frozen corpus mismatch:{name}",
        )
    return {
        "changedRelation": rows,
        "copyThresholdPercent": 50,
        "endpointCount": len(rows),
        "result": "PASS",
    }


def _git_diff_sha256(checkout: Path, base: str, candidate: str) -> str:
    completed = subprocess.run(
        [
            *_git_command(checkout),
            "diff",
            "--no-ext-diff",
            "--binary",
            "--full-index",
            base,
            candidate,
            "--",
        ],
        check=False,
        capture_output=True,
        env=_git_environment(),
    )
    _require(completed.returncode == 0, "Git diff evidence command failed")
    return sha256(completed.stdout).hexdigest()


def _git_blob_identity(payload: bytes, algorithm: str) -> str:
    digest = new_hash(algorithm)
    digest.update(f"blob {len(payload)}\0".encode("ascii"))
    digest.update(payload)
    return digest.hexdigest()


def _verify_checkout_tree_bytes(checkout: Path, candidate: str) -> None:
    algorithm = _git_text(checkout, "rev-parse", "--show-object-format")
    _require(algorithm in {"sha1", "sha256"}, "unsupported Git object format")
    completed = subprocess.run(
        _git_command(
            checkout,
            "ls-tree",
            "-rz",
            "--full-tree",
            candidate,
        ),
        check=False,
        capture_output=True,
        env=_git_environment(),
    )
    _require(completed.returncode == 0, "candidate tree is unavailable")
    for record in completed.stdout.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        mode, kind, expected = metadata.split(b" ", 2)
        path = checkout / os.fsdecode(raw_path)
        if kind == b"commit":
            continue
        _require(kind == b"blob", "unsupported candidate tree entry")
        if mode == b"120000":
            _require(path.is_symlink(), "tracked symlink mismatch")
            payload = os.fsencode(os.readlink(path))
        else:
            _require(
                mode in {b"100644", b"100755"}
                and path.is_file()
                and not path.is_symlink(),
                "tracked file kind mismatch",
            )
            executable = bool(path.stat().st_mode & stat.S_IXUSR)
            _require(
                executable == (mode == b"100755"),
                "tracked executable mode mismatch",
            )
            payload = path.read_bytes()
        _require(
            _git_blob_identity(payload, algorithm) == expected.decode("ascii"),
            "tracked checkout bytes mismatch",
        )


def _clean_checkout(checkout: Path, candidate: str) -> None:
    _require(checkout.is_dir() and not checkout.is_symlink(), "invalid checkout root")
    _require(_git_text(checkout, "rev-parse", "HEAD^{commit}") == candidate, "checkout HEAD mismatch")
    _verify_checkout_tree_bytes(checkout, candidate)
    status = _git_text(
        checkout,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=matching",
    )
    _require(status == "", "checkout is not clean")
    submodules = _git_text(checkout, "submodule", "status", "--recursive")
    _require(
        not any(line[:1] in {"-", "+", "U"} for line in submodules.splitlines()),
        "submodule state mismatch",
    )


def _outside(value: Path, roots: tuple[Path, ...]) -> bool:
    resolved = value.resolve()
    return all(resolved != root and root not in resolved.parents for root in roots)


def _verify_bundle(
    bundle: Path, expected_sha256: str, base: str, candidate: str
) -> tuple[str, str]:
    _require(bundle.is_file() and not bundle.is_symlink(), "invalid bundle")
    _require(sha256(bundle.read_bytes()).hexdigest() == expected_sha256, "bundle digest mismatch")
    listed = subprocess.run(
        ["git", "bundle", "list-heads", str(bundle)],
        check=False,
        capture_output=True,
        text=True,
        env=_git_environment(),
    )
    _require(listed.returncode == 0, "bundle heads unavailable")
    _require(
        any(line.split(maxsplit=1)[0] == candidate for line in listed.stdout.splitlines()),
        "candidate is not advertised by bundle",
    )
    with tempfile.TemporaryDirectory(prefix="styx-c03-bundle-clone-") as tmp:
        clone = Path(tmp) / "clone"
        completed = subprocess.run(
            ["git", "clone", "--no-checkout", str(bundle), str(clone)],
            check=False,
            capture_output=True,
            text=True,
            env=_git_environment(),
        )
        _require(completed.returncode == 0, "bundle is not independently cloneable")
        for identity in (base, candidate):
            _require(
                _git_text(clone, "cat-file", "-t", identity) == "commit",
                "bundle commit missing",
            )
        _require(
            _git_text(clone, "merge-base", base, candidate) == base,
            "bundle Base ancestry mismatch",
        )
        return (
            _git_text(clone, "rev-parse", f"{candidate}^{{tree}}"),
            _git_diff_sha256(clone, base, candidate),
        )


def _validate_evidence_set(root: Path) -> dict[str, bytes]:
    _require(root.is_dir() and not root.is_symlink(), "invalid evidence root")
    entries = tuple(root.iterdir())
    _require(
        all(path.is_file() and not path.is_symlink() for path in entries),
        "non-regular evidence artifact",
    )
    regular = {
        path.name: path.read_bytes()
        for path in entries
    }
    _require(set(regular) == set(EVIDENCE_FILENAMES), "evidence artifact set mismatch")
    parsed = {name: loads(value) for name, value in regular.items()}

    def exact_keys(value: object, expected: set[str], label: str) -> None:
        _require(
            isinstance(value, dict) and set(value) == expected,
            f"unknown or missing canonical report field:{label}",
        )

    runtime_python = loads(regular["h1h2-python.json"])
    runtime_javascript = loads(regular["h1h2-javascript.json"])
    runtime_keys = {
        "boundaryRows",
        "connectedRows",
        "result",
        "scenarioCount",
        "schema",
        "slotRows",
    }
    for runtime_name, runtime in (
        ("python", runtime_python),
        ("javascript", runtime_javascript),
    ):
        exact_keys(runtime, runtime_keys, f"runtime-{runtime_name}")
        for index, row in enumerate(runtime.get("boundaryRows", [])):
            exact_keys(
                row,
                {
                    "accepted",
                    "equationInvocations",
                    "guardCode",
                    "rowId",
                    "scenarioId",
                },
                f"runtime-{runtime_name}.boundaryRows[{index}]",
            )
        for index, row in enumerate(runtime.get("connectedRows", [])):
            expected = {
                "rowId",
                "scenarioId",
                "verificationBoundary",
            }
            _require(isinstance(row, dict), "invalid connected report row")
            if "observations" in row:
                expected |= {"harnessError", "observations"}
                for observation_index, observation in enumerate(row["observations"]):
                    exact_keys(
                        observation,
                        {
                            "coalescedPresentationCount",
                            "eventReferenceHex",
                            "id",
                            "kBindingAdmission",
                            "logicalEventEffectCount",
                            "logicalEventReferenceHex",
                            "protocolErrorCode",
                            "stage",
                        },
                        f"runtime-{runtime_name}.connectedRows[{index}].observations[{observation_index}]",
                    )
            else:
                expected.add("observation")
                exact_keys(
                    row.get("observation"),
                    {
                        "apAuthorityResult",
                        "commitmentMatchVerification",
                        "commitmentVerification",
                        "externalEffects",
                        "geometryPredicate1",
                        "geometryPredicate2",
                        "geometryPredicate3",
                        "geometryPredicate4",
                        "geometryPredicate5",
                        "geometryPredicate6",
                        "geometryPredicate7",
                        "kBindingAdmission",
                        "localOutcome",
                        "outcomeEvaluated",
                        "postStateDigest",
                        "preStateDigest",
                        "referenceVerification",
                        "remoteClass",
                        "signatureVerification",
                        "stage",
                        "suppliedLengthVerification",
                        "transcriptVerification",
                    },
                    f"runtime-{runtime_name}.connectedRows[{index}].observation",
                )
            exact_keys(row, expected, f"runtime-{runtime_name}.connectedRows[{index}]")
            exact_keys(
                row.get("verificationBoundary"),
                {"boundaryInvocations", "equationInvocations"},
                f"runtime-{runtime_name}.connectedRows[{index}].verificationBoundary",
            )
        for index, row in enumerate(runtime.get("slotRows", [])):
            exact_keys(
                row,
                {"lexicalSchedule", "observations", "order", "rowId", "scenarioId"},
                f"runtime-{runtime_name}.slotRows[{index}]",
            )
            for observation_index, observation in enumerate(row["observations"]):
                expected_observation_keys = (
                    {"classification", "reference", "transcriptHex"}
                    if row["rowId"] in {"H2-SLT-087", "H2-SLT-088"}
                    else {
                        "coalescedPresentationCount",
                        "eventReferenceHex",
                        "id",
                        "kBindingAdmission",
                        "logicalEventEffectCount",
                        "logicalEventReferenceHex",
                        "protocolErrorCode",
                        "stage",
                    }
                )
                exact_keys(
                    observation,
                    expected_observation_keys,
                    f"runtime-{runtime_name}.slotRows[{index}].observations[{observation_index}]",
                )
    _require(runtime_python == runtime_javascript, "runtime evidence mismatch")
    _require(
        runtime_python.get("scenarioCount") == 164
        and len(runtime_python.get("boundaryRows", [])) == 29
        and len(runtime_python.get("connectedRows", [])) == 35
        and len(runtime_python.get("slotRows", [])) == 100,
        "runtime evidence cardinality mismatch",
    )
    for runtime in ("python", "javascript"):
        mutation = parsed[f"h1h2-mutations-{runtime}.json"]
        exact_keys(
            mutation,
            {"killed", "result", "rows", "runtime", "schema"},
            f"mutations-{runtime}",
        )
        for index, row in enumerate(mutation.get("rows", [])):
            exact_keys(
                row,
                {
                    "detectorId",
                    "mutantId",
                    "result",
                    "runtime",
                    "sourceDigestChanged",
                },
                f"mutations-{runtime}.rows[{index}]",
            )
        _require(
            mutation.get("runtime") == runtime
            and mutation.get("killed") == 24
            and [row.get("mutantId") for row in mutation.get("rows", [])]
            == list(MUTANTS)
            and all(row.get("result") == "KILLED" for row in mutation.get("rows", [])),
            "mutation evidence mismatch",
        )
    regression = parsed["h1h2-regression.json"]
    exact_keys(
        regression,
        {"checks", "frozenCorpusFiles", "result", "schema"},
        "regression",
    )
    for index, row in enumerate(regression.get("checks", [])):
        exact_keys(row, {"id", "result"}, f"regression.checks[{index}]")
    _require(
        regression.get("result") == "PASS"
        and regression.get("frozenCorpusFiles") == 6
        and [row.get("id") for row in regression.get("checks", [])]
        == ["generate", "validate", "replay", "node", "cross-runtime", "historical-mutations"],
        "regression evidence mismatch",
    )
    scope = parsed["scope.json"]
    exact_keys(
        scope,
        {"changedRelation", "copyThresholdPercent", "endpointCount", "result"},
        "scope",
    )
    for index, row in enumerate(scope.get("changedRelation", [])):
        exact_keys(row, {"paths", "status"}, f"scope.changedRelation[{index}]")
    _require(
        scope.get("result") == "PASS"
        and scope.get("copyThresholdPercent") == 50,
        "scope evidence mismatch",
    )
    return regular


def _walk_strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _walk_strings(item)


def _validate_report_hygiene(
    reports: dict[str, bytes], forbidden_identities: tuple[str, ...]
) -> None:
    absolute_path = re.compile(
        r"(?<![A-Za-z0-9_.-])(?:/|\\|[A-Za-z]:[\\/]|\\\\[^\\\s]+[\\/][^\\\s]+)"
    )
    measurement = re.compile(
        r"(?i)(?:elapsed|duration|runtime)\s*[:=]\s*\d|\bpid\s*[:=]\s*\d"
    )
    timestamp = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
    runtime_values = tuple(
        value for value in {socket.gethostname(), getpass.getuser()} if value
    )
    identity_needles = tuple(
        needle
        for identity in forbidden_identities
        for needle in {identity, identity[:7]}
        if len(needle) >= 7
    )
    for raw in reports.values():
        for value in _walk_strings(loads(raw)):
            _require(not absolute_path.search(value), "canonical report contains absolute path")
            _require(not measurement.search(value), "canonical report contains runtime measurement")
            _require(not timestamp.search(value), "canonical report contains timestamp")
            _require(
                not any(needle in value for needle in identity_needles),
                "canonical report contains repository identity",
            )
            for runtime_value in runtime_values:
                tagged = re.search(
                    rf"(?:^|[=:/\\\s]){re.escape(runtime_value)}(?:$|[=:/\\\s])",
                    value,
                )
                _require(tagged is None, "canonical report contains runtime identity")


def _run_checkout_producer(
    checkout: Path,
    candidate: str,
    command: list[str],
    output: Path,
) -> None:
    _clean_checkout(checkout, candidate)
    environment = _git_environment()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment.pop("PYTHONOPTIMIZE", None)
    completed = subprocess.run(
        [*command, "--output", str(output)],
        cwd=checkout,
        check=False,
        capture_output=True,
        text=True,
        timeout=180,
        env=environment,
    )
    _require(completed.returncode == 0, "final-gate producer failed")
    _clean_checkout(checkout, candidate)


def _produce_evidence(checkout: Path, destination: Path, base: str, candidate: str) -> None:
    relation = checkout / "tools/causal-flow-simulator/c03/h1_h2_relation.py"
    commands = (
        ("h1h2-python.json", [sys.executable, str(relation), "--run-python"]),
        ("h1h2-javascript.json", [sys.executable, str(relation), "--run-javascript"]),
        (
            "h1h2-mutations-python.json",
            [sys.executable, str(relation), "--run-mutations", "--runtime", "python"],
        ),
        (
            "h1h2-mutations-javascript.json",
            [sys.executable, str(relation), "--run-mutations", "--runtime", "javascript"],
        ),
        ("h1h2-regression.json", [sys.executable, str(relation), "--run-regression"]),
        (
            "scope.json",
            [
                sys.executable,
                str(relation),
                "--scope",
                "--base",
                base,
                "--candidate",
                candidate,
                "--mode",
                "strict",
            ],
        ),
    )
    for name, command in commands:
        _run_checkout_producer(checkout, candidate, command, destination / name)


def run_final_gate(
    *,
    base: str,
    candidate: str,
    bundle: Path,
    bundle_sha256: str,
    issue_body: Path,
    issue_body_sha256: str,
    ratification_comment_rest: Path,
    checkout_1: Path,
    checkout_2: Path,
    evidence_1: Path,
    evidence_2: Path,
) -> dict:
    _require(base == BASE_SHA, "final-gate Base mismatch")
    _require(re.fullmatch(r"[0-9a-f]{40}", candidate) is not None, "invalid candidate identity")
    _require(
        issue_body.is_file()
        and not issue_body.is_symlink()
        and sha256(issue_body.read_bytes()).hexdigest() == issue_body_sha256
        and issue_body_sha256 == RATIFIED_ISSUE_BODY_SHA256,
        "Issue body identity mismatch",
    )
    _validate_issue_appendix(issue_body.read_bytes())
    _, _, incorporated = _validate_ratification_comment_rest(
        ratification_comment_rest
    )
    authority = _validate_provider_authority(issue_body.read_bytes(), incorporated)
    bundle_tree, bundle_diff_digest = _verify_bundle(
        bundle, bundle_sha256, base, candidate
    )

    checkouts = (checkout_1.resolve(), checkout_2.resolve())
    _require(checkouts[0] != checkouts[1], "checkout roots are not distinct")
    metadata = tuple(
        (checkout / _git_text(checkout, "rev-parse", "--git-dir")).resolve()
        for checkout in checkouts
    )
    evidence = (evidence_1.resolve(), evidence_2.resolve())
    _require(evidence[0] != evidence[1], "evidence roots are not distinct")
    for root in evidence:
        _require(_outside(root, (*checkouts, *metadata)), "evidence root overlaps checkout")
    for checkout in checkouts:
        _clean_checkout(checkout, candidate)
        _require(
            _git_text(checkout, "merge-base", base, candidate) == base,
            "checkout Base ancestry mismatch",
        )
        _validate_v4_reconstruction(checkout, base, candidate, authority)
    trees = {_git_text(checkout, "rev-parse", "HEAD^{tree}") for checkout in checkouts}
    _require(
        trees == {bundle_tree},
        "checkout tree does not match the independently verified bundle",
    )
    diff_digests = {
        _git_diff_sha256(checkout, base, candidate) for checkout in checkouts
    }
    _require(
        diff_digests == {bundle_diff_digest},
        "checkout diff does not match the independently verified bundle",
    )

    submitted_1 = _validate_evidence_set(evidence[0])
    submitted_2 = _validate_evidence_set(evidence[1])
    forbidden_identities = (
        base,
        candidate,
        bundle_sha256,
        issue_body_sha256,
        *tuple(trees),
        *tuple(diff_digests),
    )
    _validate_report_hygiene(submitted_1, forbidden_identities)
    _validate_report_hygiene(submitted_2, forbidden_identities)
    _require(submitted_1 == submitted_2, "two-checkout submitted evidence mismatch")
    with tempfile.TemporaryDirectory(prefix="styx-c03-final-gate-") as tmp:
        regenerated = (Path(tmp) / "one", Path(tmp) / "two")
        for root in regenerated:
            root.mkdir()
        _produce_evidence(checkouts[0], regenerated[0], base, candidate)
        _produce_evidence(checkouts[1], regenerated[1], base, candidate)
        regenerated_1 = _validate_evidence_set(regenerated[0])
        regenerated_2 = _validate_evidence_set(regenerated[1])
        _validate_report_hygiene(regenerated_1, forbidden_identities)
        _validate_report_hygiene(regenerated_2, forbidden_identities)
        _require(regenerated_1 == regenerated_2, "regenerated evidence mismatch")
        _require(regenerated_1 == submitted_1, "submitted evidence is not reproducible")
    return {
        "artifactCountPerCheckout": len(EVIDENCE_FILENAMES),
        "mutantRuntimeKills": 48,
        "result": "PASS",
        "runtimeScenarioCount": 164,
        "schema": "styx-c03-h1h2-final-gate/v1",
    }


def _run_required_commands(
    *,
    checkout: Path,
    role: str,
    base: str,
    candidate: str,
    issue_body: bytes,
    tools: dict[str, str],
    environment: dict[str, str],
    workspace: Path,
) -> tuple[list[dict], dict[str, Path], dict[str, Path]]:
    python = tools["python3"]
    node = tools["node"]
    relation = checkout / "tools/causal-flow-simulator/c03/h1_h2_relation.py"
    corpus_root = checkout / "conformance/application-protocol/c03"
    report_root = workspace / "evidence"
    report_root.mkdir()
    reports = {
        "h1h2-python.json": report_root / "h1h2-python.json",
        "h1h2-javascript.json": report_root / "h1h2-javascript.json",
        "h1h2-mutations-python.json": report_root / "h1h2-mutations-python.json",
        "h1h2-mutations-javascript.json": report_root / "h1h2-mutations-javascript.json",
        "h1h2-regression.json": report_root / "h1h2-regression.json",
        "scope.json": report_root / "scope.json",
    }
    mutation_logs = {
        "python": workspace / "mutations-python.jsonl",
        "javascript": workspace / "mutations-javascript.jsonl",
    }
    generated = workspace / "generated"
    commands: tuple[tuple[str, list[str]], ...] = (
        (
            "PREFLIGHT",
            [python, "-c", _issue_scope_preflight(issue_body)],
        ),
        ("VALIDATE_RELATION", [python, str(relation), "--validate-relation"]),
        (
            "UNITTEST_C03",
            [
                python,
                "-m",
                "unittest",
                "discover",
                "-s",
                "tools/causal-flow-simulator/c03/tests",
                "-p",
                "test_*.py",
            ],
        ),
        (
            "RUN_H1H2_PYTHON",
            [python, str(relation), "--run-python", "--output", str(reports["h1h2-python.json"])],
        ),
        (
            "RUN_H1H2_JAVASCRIPT",
            [python, str(relation), "--run-javascript", "--output", str(reports["h1h2-javascript.json"])],
        ),
        (
            "RUN_H1H2_MUTATIONS_PYTHON",
            [
                python,
                str(relation),
                "--run-mutations",
                "--runtime",
                "python",
                "--mutation-log",
                str(mutation_logs["python"]),
                "--checkout-role",
                role,
                "--output",
                str(reports["h1h2-mutations-python.json"]),
            ],
        ),
        (
            "RUN_H1H2_MUTATIONS_JAVASCRIPT",
            [
                python,
                str(relation),
                "--run-mutations",
                "--runtime",
                "javascript",
                "--mutation-log",
                str(mutation_logs["javascript"]),
                "--checkout-role",
                role,
                "--output",
                str(reports["h1h2-mutations-javascript.json"]),
            ],
        ),
        (
            "RUN_H1H2_REGRESSION",
            [python, str(relation), "--run-regression", "--output", str(reports["h1h2-regression.json"])],
        ),
        (
            "GENERATE_CORPUS",
            [python, "tools/causal-flow-simulator/c03/generate_corpus.py", "--repo-root", ".", "--output", str(generated)],
        ),
        (
            "VALIDATE_CORPUS",
            [python, "tools/causal-flow-simulator/c03/validate_corpus.py", "--repo-root", ".", "--corpus", "conformance/application-protocol/c03", "--output", str(workspace / "validate.json")],
        ),
        (
            "REPLAY_CORPUS",
            [python, "tools/causal-flow-simulator/c03/replay_corpus.py", "--repo-root", ".", "--corpus", "conformance/application-protocol/c03", "--output", str(workspace / "replay.json")],
        ),
        (
            "NODE_CORPUS",
            [node, "tools/causal-flow-simulator/c03/node_adapter.mjs", "--repo-root", ".", "--corpus", "conformance/application-protocol/c03", "--output", str(workspace / "node.json")],
        ),
        (
            "CROSS_RUNTIME",
            [python, "tools/causal-flow-simulator/c03/run_cross_runtime.py", "--repo-root", ".", "--corpus", "conformance/application-protocol/c03", "--output", str(workspace / "cross.json")],
        ),
        (
            "CORPUS_MUTATIONS",
            [python, "tools/causal-flow-simulator/c03/run_mutations.py", "--repo-root", ".", "--corpus", "conformance/application-protocol/c03", "--output", str(workspace / "mutations.json")],
        ),
        (
            "VALIDATE_REVIEW_MODEL",
            [python, "tools/protocol-review-model/validate.py", "--repo-root", ".", "--schema", "docs/protocol/review/styx-app-kernel-v0-review-model.schema.json", "--model", "docs/protocol/review/styx-app-kernel-v0-review-model.json", "--output", str(workspace / "review-model.json")],
        ),
        (
            "DIFF_GENERATED_CORPUS",
            [tools["diff"], "-ru", str(corpus_root), str(generated)],
        ),
        ("GIT_DIFF_CHECK", [tools["git"], "diff", "--check"]),
    )
    rows = []
    for command_id, argv in commands:
        rows.append(
            _run_logged_command(
                command_id=command_id,
                argv=argv,
                checkout=checkout,
                candidate=candidate,
                checkout_role=role,
                environment=environment,
                timeout=900 if "MUTATION" in command_id else 300,
            )
        )
    _require(
        rows[0]["stdoutUtf8"] == "PACKAGE_A_SCOPE_OK\n",
        "scope preflight output mismatch",
    )
    scope_argv = [
        python,
        str(relation),
        "--scope",
        "--base",
        base,
        "--candidate",
        candidate,
        "--mode",
        "strict",
        "--output",
        str(reports["scope.json"]),
    ]
    _run_logged_command(
        command_id="PREFLIGHT",
        argv=scope_argv,
        checkout=checkout,
        candidate=candidate,
        checkout_role=role,
        environment=environment,
    )
    return rows, reports, mutation_logs


def _copy_verified_evidence(
    source: Path, produced: dict[str, Path], output: Path, suffix: str
) -> None:
    submitted = _validate_evidence_set(source)
    generated = _validate_evidence_set(produced["scope.json"].parent)
    _require(submitted == generated, "submitted evidence differs from required run")
    mapping = {
        "h1h2-python.json": f"H1H2_PYTHON_{suffix}.json",
        "h1h2-javascript.json": f"H1H2_JAVASCRIPT_{suffix}.json",
        "h1h2-mutations-python.json": f"H1H2_MUTATIONS_PYTHON_{suffix}.json",
        "h1h2-mutations-javascript.json": f"H1H2_MUTATIONS_JAVASCRIPT_{suffix}.json",
        "h1h2-regression.json": f"H1H2_REGRESSION_{suffix}.json",
        "scope.json": f"SCOPE_{suffix}.json",
    }
    for source_name, destination_name in mapping.items():
        _write_new_bytes(output / destination_name, submitted[source_name])


def _verify_tep_structure(package: Path) -> dict[str, Path]:
    artifacts = _flat_regular_files(package)
    _require(set(artifacts) == set(TEP_FILENAMES), "TEP artifact set mismatch")
    _require(
        artifacts["PACKAGE_SCHEMA.txt"].read_bytes()
        == "".join(f"{name}\n" for name in TEP_FILENAMES).encode("ascii"),
        "TEP schema mismatch",
    )
    manifest = artifacts["SHA256SUMS.txt"].read_bytes()
    _require(manifest == _manifest_bytes(package), "TEP manifest mismatch")
    return artifacts


def build_tep(
    *,
    base: str,
    candidate: str,
    bundle: Path,
    issue_rest: Path,
    ratification_comment_rest: Path,
    pr_rest: Path,
    checkout_1: Path,
    checkout_2: Path,
    evidence_1: Path,
    evidence_2: Path,
    codex_reconciliation: Path,
    output_dir: Path,
) -> dict:
    _require(base == BASE_SHA, "TEP Base mismatch")
    _require(re.fullmatch(r"[0-9a-f]{40}", candidate) is not None, "invalid TEP candidate")
    issue, issue_body = _validate_issue_rest(issue_rest)
    comment, comment_body, incorporated = _validate_ratification_comment_rest(
        ratification_comment_rest
    )
    authority = _validate_provider_authority(issue_body, incorporated)
    pull, pull_body = _validate_pr_rest(pr_rest, candidate)
    _require(
        codex_reconciliation.is_file()
        and not codex_reconciliation.is_symlink(),
        "invalid Codex reconciliation",
    )
    tools, tool_versions = _resolve_toolchain()
    bundle_digest = sha256(bundle.read_bytes()).hexdigest()
    checkouts = (checkout_1.resolve(), checkout_2.resolve())
    _require(checkouts[0] != checkouts[1], "TEP checkouts are not distinct")
    with tempfile.TemporaryDirectory(prefix="styx-c03-tep-preflight-") as tmp:
        preflight_environment = _closed_environment(
            tools, Path(tmp) / "environment"
        )
        with _process_environment(preflight_environment):
            bundle_tree, bundle_diff = _verify_bundle(
                bundle, bundle_digest, base, candidate
            )
            for checkout in checkouts:
                _clean_checkout(checkout, candidate)
                _require(
                    _git_text(checkout, "rev-parse", "HEAD^{tree}") == bundle_tree
                    and _git_diff_sha256(checkout, base, candidate) == bundle_diff,
                    "TEP checkout differs from bundle",
                )
                _validate_v4_reconstruction(checkout, base, candidate, authority)
    _require(not output_dir.exists(), "TEP output directory already exists")
    output_dir.mkdir()
    try:
        _write_new_bytes(output_dir / "ISSUE_297_REST.json", issue_rest.read_bytes())
        _write_new_bytes(output_dir / "ISSUE_297_BODY.txt", issue_body)
        _write_new_bytes(
            output_dir / "RATIFICATION_COMMENT_REST.json",
            ratification_comment_rest.read_bytes(),
        )
        _write_new_bytes(output_dir / "RATIFICATION_COMMENT_BODY.txt", comment_body)
        _write_new_bytes(output_dir / "DRAFT_PR_REST.json", pr_rest.read_bytes())
        _write_new_bytes(output_dir / "DRAFT_PR_BODY.txt", pull_body)
        _write_new_bytes(output_dir / "CANDIDATE.bundle", bundle.read_bytes())
        _write_new_bytes(output_dir / "TOOL_VERSIONS.txt", tool_versions)
        _write_new_bytes(
            output_dir / "CODEX_RECONCILIATION.md",
            codex_reconciliation.read_bytes(),
        )
        with tempfile.TemporaryDirectory(prefix="styx-c03-tep-build-") as tmp:
            workspace = Path(tmp)
            environment = _closed_environment(tools, workspace / "environment")
            run_roots = (workspace / "run-1", workspace / "run-2")
            for root in run_roots:
                root.mkdir()
            with _process_environment(environment):
                candidate_diff = _git_bytes(
                    checkouts[0],
                    "diff",
                    "--no-ext-diff",
                    "--binary",
                    "--full-index",
                    base,
                    candidate,
                    "--",
                )
                _require(
                    sha256(candidate_diff).hexdigest() == bundle_diff,
                    "TEP diff mismatch",
                )
                _write_new_bytes(output_dir / "CANDIDATE.diff", candidate_diff)
                first = _run_required_commands(
                    checkout=checkouts[0], role="CHECKOUT_1", base=base,
                    candidate=candidate, issue_body=issue_body, tools=tools,
                    environment=environment, workspace=run_roots[0],
                )
                second = _run_required_commands(
                    checkout=checkouts[1], role="CHECKOUT_2", base=base,
                    candidate=candidate, issue_body=issue_body, tools=tools,
                    environment=environment, workspace=run_roots[1],
                )
                for index, (rows, reports, mutation_logs) in enumerate(
                    (first, second), 1
                ):
                    _write_new_bytes(
                        output_dir / f"SCOPE_PREFLIGHT_{index}.log",
                        dumps(rows[0]),
                    )
                    _copy_verified_evidence(
                        (evidence_1, evidence_2)[index - 1],
                        reports,
                        output_dir,
                        str(index),
                    )
                    for runtime, label in (
                        ("python", "PYTHON"),
                        ("javascript", "JAVASCRIPT"),
                    ):
                        payload = mutation_logs[runtime].read_bytes()
                        _validate_jsonl(
                            payload,
                            expected_ids=MUTANTS,
                            checkout_role=f"CHECKOUT_{index}",
                        )
                        _write_new_bytes(
                            output_dir / f"MUTATIONS_{label}_{index}.log",
                            payload,
                        )
                final_output = workspace / "final-gate.json"
                final_argv = [
                    tools["python3"],
                    str(checkouts[0] / "tools/causal-flow-simulator/c03/h1_h2_relation.py"),
                    "--final-gate", "--base", base, "--candidate", candidate,
                    "--bundle", str(bundle), "--bundle-sha256", bundle_digest,
                    "--issue-body", str(output_dir / "ISSUE_297_BODY.txt"),
                    "--issue-body-sha256", RATIFIED_ISSUE_BODY_SHA256,
                    "--ratification-comment-rest",
                    str(output_dir / "RATIFICATION_COMMENT_REST.json"),
                    "--checkout-1", str(checkouts[0]), "--checkout-2", str(checkouts[1]),
                    "--evidence-1", str(evidence_1), "--evidence-2", str(evidence_2),
                    "--output", str(final_output),
                ]
                final_completed = subprocess.run(
                    final_argv, cwd=checkouts[0], check=False, capture_output=True,
                    timeout=1800, env=environment,
                )
                final_row = _command_row(
                    "FINAL_GATE", final_argv, "CHECKOUT_1", final_completed
                )
                _require(final_completed.returncode == 0, "TEP final gate failed")
                final_value = loads(final_output.read_bytes())
                _require(final_value.get("result") == "PASS", "TEP final result")
                _write_new_bytes(output_dir / "FINAL_GATE.log", dumps(final_row))
                _write_new_bytes(output_dir / "FINAL_GATE.json", final_output.read_bytes())
                for index, (rows, _, _) in enumerate((first, second), 1):
                    recorded = dict(final_row)
                    recorded["checkoutRole"] = f"CHECKOUT_{index}"
                    complete_rows = [*rows, recorded]
                    _require(
                        tuple(row["commandId"] for row in complete_rows)
                        == REQUIRED_COMMAND_IDS,
                        "required command sequence mismatch",
                    )
                    _write_new_bytes(
                        output_dir / f"REQUIRED_COMMANDS_{index}.log",
                        b"".join(dumps(row) for row in complete_rows),
                    )
        _write_new_bytes(
            output_dir / "PACKAGE_SCHEMA.txt",
            "".join(f"{name}\n" for name in TEP_FILENAMES).encode("ascii"),
        )
        _write_new_bytes(output_dir / "SHA256SUMS.txt", _manifest_bytes(output_dir))
        artifacts = _verify_tep_structure(output_dir)
        return {
            "artifactCount": len(artifacts),
            "bundleSha256": bundle_digest,
            "candidate": candidate,
            "diffSha256": bundle_diff,
            "issueNumber": issue["number"],
            "prNumber": pull["number"],
            "ratificationCommentId": comment["id"],
            "result": "PASS",
        }
    except Exception:
        # Leave the incomplete directory for diagnosis; it can never pass the
        # exact-set verifier and is not evidence.
        raise


def verify_tep(package: Path) -> dict:
    artifacts = _verify_tep_structure(package)
    issue, issue_body = _validate_issue_rest(artifacts["ISSUE_297_REST.json"])
    _require(
        issue_body == artifacts["ISSUE_297_BODY.txt"].read_bytes(),
        "TEP Issue body mismatch",
    )
    comment, comment_body, incorporated = _validate_ratification_comment_rest(
        artifacts["RATIFICATION_COMMENT_REST.json"]
    )
    authority = _validate_provider_authority(issue_body, incorporated)
    _require(
        comment_body == artifacts["RATIFICATION_COMMENT_BODY.txt"].read_bytes(),
        "TEP ratification body mismatch",
    )
    pull = _load_provider_object(artifacts["DRAFT_PR_REST.json"])
    candidate = pull.get("head", {}).get("sha")
    _require(isinstance(candidate, str), "TEP candidate missing")
    _, pull_body = _validate_pr_rest(artifacts["DRAFT_PR_REST.json"], candidate)
    _require(
        pull_body == artifacts["DRAFT_PR_BODY.txt"].read_bytes(),
        "TEP PR body mismatch",
    )
    tools, current_versions = _resolve_toolchain()
    _require(
        current_versions == artifacts["TOOL_VERSIONS.txt"].read_bytes(),
        "TEP toolchain mismatch",
    )
    for index in (1, 2):
        _validate_jsonl(
            artifacts[f"SCOPE_PREFLIGHT_{index}.log"].read_bytes(),
            expected_ids=("PREFLIGHT",),
            checkout_role=f"CHECKOUT_{index}",
        )
        _validate_jsonl(
            artifacts[f"REQUIRED_COMMANDS_{index}.log"].read_bytes(),
            expected_ids=REQUIRED_COMMAND_IDS,
            checkout_role=f"CHECKOUT_{index}",
        )
        for runtime in ("PYTHON", "JAVASCRIPT"):
            _validate_jsonl(
                artifacts[f"MUTATIONS_{runtime}_{index}.log"].read_bytes(),
                expected_ids=MUTANTS,
                checkout_role=f"CHECKOUT_{index}",
            )
    bundle_digest = sha256(artifacts["CANDIDATE.bundle"].read_bytes()).hexdigest()
    tree, diff_digest = _verify_bundle(
        artifacts["CANDIDATE.bundle"], bundle_digest, BASE_SHA, candidate
    )
    _require(
        sha256(artifacts["CANDIDATE.diff"].read_bytes()).hexdigest() == diff_digest,
        "TEP candidate diff mismatch",
    )
    final_value = loads(artifacts["FINAL_GATE.json"].read_bytes())
    _require(final_value.get("result") == "PASS", "TEP recorded final gate failed")
    _validate_jsonl(
        artifacts["FINAL_GATE.log"].read_bytes(),
        expected_ids=("FINAL_GATE",),
        checkout_role="CHECKOUT_1",
    )
    _require(
        artifacts["CODEX_RECONCILIATION.md"].read_bytes().strip(),
        "TEP Codex reconciliation is empty",
    )
    evidence_mapping = {
        "h1h2-python.json": "H1H2_PYTHON_{index}.json",
        "h1h2-javascript.json": "H1H2_JAVASCRIPT_{index}.json",
        "h1h2-mutations-python.json": "H1H2_MUTATIONS_PYTHON_{index}.json",
        "h1h2-mutations-javascript.json": "H1H2_MUTATIONS_JAVASCRIPT_{index}.json",
        "h1h2-regression.json": "H1H2_REGRESSION_{index}.json",
        "scope.json": "SCOPE_{index}.json",
    }
    with tempfile.TemporaryDirectory(prefix="styx-c03-tep-verify-") as tmp:
        workspace = Path(tmp)
        checkouts = (workspace / "checkout-1", workspace / "checkout-2")
        evidences = (workspace / "evidence-1", workspace / "evidence-2")
        environment = _closed_environment(tools, workspace / "environment")
        for index, evidence in enumerate(evidences, 1):
            evidence.mkdir()
            for destination, source_pattern in evidence_mapping.items():
                _write_new_bytes(
                    evidence / destination,
                    artifacts[source_pattern.format(index=index)].read_bytes(),
                )
            _validate_evidence_set(evidence)
        with _process_environment(environment):
            for checkout in checkouts:
                completed = subprocess.run(
                    [tools["git"], "clone", str(artifacts["CANDIDATE.bundle"]), str(checkout)],
                    check=False,
                    capture_output=True,
                    env=environment,
                )
                _require(completed.returncode == 0, "TEP verifier clone failed")
                completed = subprocess.run(
                    [tools["git"], "-C", str(checkout), "checkout", "--detach", candidate],
                    check=False,
                    capture_output=True,
                    env=environment,
                )
                _require(completed.returncode == 0, "TEP verifier checkout failed")
                _validate_v4_reconstruction(
                    checkout, BASE_SHA, candidate, authority
                )
            exact_diff = _git_bytes(
                checkouts[0],
                "diff",
                "--no-ext-diff",
                "--binary",
                "--full-index",
                BASE_SHA,
                candidate,
                "--",
            )
            _require(
                exact_diff == artifacts["CANDIDATE.diff"].read_bytes(),
                "TEP diff bytes mismatch",
            )
            regenerated = run_final_gate(
                base=BASE_SHA,
                candidate=candidate,
                bundle=artifacts["CANDIDATE.bundle"],
                bundle_sha256=bundle_digest,
                issue_body=artifacts["ISSUE_297_BODY.txt"],
                issue_body_sha256=RATIFIED_ISSUE_BODY_SHA256,
                ratification_comment_rest=artifacts[
                    "RATIFICATION_COMMENT_REST.json"
                ],
                checkout_1=checkouts[0],
                checkout_2=checkouts[1],
                evidence_1=evidences[0],
                evidence_2=evidences[1],
            )
            _require(regenerated == final_value, "TEP final gate is not reproducible")
    return {
        "artifactCount": len(artifacts),
        "bundleSha256": bundle_digest,
        "candidate": candidate,
        "candidateTree": tree,
        "diffSha256": diff_digest,
        "issueNumber": issue["number"],
        "prNumber": pull["number"],
        "ratificationCommentId": comment["id"],
        "result": "PASS",
    }


def run_runtime(runtime: str) -> dict:
    _require(runtime in {"python", "javascript"}, "unknown runtime")
    if runtime == "python":
        boundary = run_python_boundary()
        connected = run_python_connected()
        slots = run_python_slots()
    else:
        boundary = run_javascript_boundary()
        connected = run_javascript_connected()
        slots = run_javascript_slots()
    _require(
        len(boundary["rows"]) + len(connected["rows"]) + len(slots["rows"])
        == 164,
        "runtime scenario count",
    )
    return {
        "boundaryRows": boundary["rows"],
        "connectedRows": connected["rows"],
        "result": "PASS",
        "scenarioCount": 164,
        "schema": "styx-c03-h1h2-runtime-observations/v1",
        "slotRows": slots["rows"],
    }


def _store_new(path: Path, value: dict) -> None:
    _require(not path.exists(), "output already exists")
    store(path, value)


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise RelationError(message)


def validate_relation() -> None:
    groups = (
        (H1_BOUNDARY, "H1-BND", 29),
        (H1_CONNECTED, "H1-CON", 35),
        (H2_SLOTS, "H2-SLT", 100),
    )
    all_rows = []
    for rows, prefix, count in groups:
        _require(len(rows) == count, f"{prefix} row count")
        _require(
            tuple(row.row_id for row in rows)
            == tuple(f"{prefix}-{index:03d}" for index in range(1, count + 1)),
            f"{prefix} identifiers are not continuous",
        )
        all_rows.extend(rows)
    _require(len(all_rows) == 164, "logical scenario count")
    _require(
        len({row.row_id for row in all_rows}) == len(all_rows),
        "duplicate row identifier",
    )
    _require(
        len({row.scenario_id for row in all_rows}) == len(all_rows),
        "duplicate scenario identifier",
    )
    _require(len(MUTANTS) == 24 and len(set(MUTANTS)) == 24, "mutant relation")
    _require(set(MUTATION_SPECS) == set(MUTANTS), "mutation specification set")
    _require(
        set(APPENDIX_MUTANT_DESCRIPTIONS) == set(MUTANTS),
        "Appendix A mutant-description set",
    )
    _require(
        {row.expected for row in H1_CONNECTED}
        <= set(APPENDIX_CONNECTED_OBSERVATIONS.values()),
        "Appendix A connected-observation translation",
    )
    _require(
        {row.expected for row in H2_SLOTS}
        <= set(APPENDIX_SLOT_OBSERVATIONS.values()),
        "Appendix A slot-observation translation",
    )
    python_source = (ROOT / "corpus_model.py").read_text(encoding="utf-8")
    javascript_source = (ROOT / "node_adapter.mjs").read_text(encoding="utf-8")
    for mutant in MUTANTS:
        spec = MUTATION_SPECS[mutant]
        _require(
            python_source.count(spec.python_anchor) == 1,
            f"{mutant} Python source anchor",
        )
        _require(
            javascript_source.count(spec.javascript_anchor) == 1,
            f"{mutant} JavaScript source anchor",
        )
    for name, expected in FROZEN_O14_SHA256.items():
        path = O14 / name
        _require(
            path.is_file() and sha256(path.read_bytes()).hexdigest() == expected,
            f"frozen O-14 drift:{name}",
        )
    corpus = REPO / "conformance/application-protocol/c03"
    for name, expected in FROZEN_CORPUS_SHA256.items():
        path = corpus / name
        _require(
            path.is_file() and sha256(path.read_bytes()).hexdigest() == expected,
            f"frozen C0.3 drift:{name}",
        )
    runtime = {
        witness.identifier: witness.expected_code
        for witness in required_witnesses()
        if witness.runtime
    }
    _require(
        runtime == {row.scenario_id: row.expected for row in H1_BOUNDARY},
        "frozen O-14 boundary relation drift",
    )
    for case in connected_cases():
        if case["mode"] == "graph":
            _validate_candidate_set_wrapper_identities(
                case["genesis"], case["records"]
            )
    for case in slot_cases():
        if case.get("mode") != "classifier":
            _validate_candidate_set_wrapper_identities(
                case["genesis"], case["records"]
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--validate-relation", action="store_true")
    action.add_argument("--run-python", action="store_true")
    action.add_argument("--run-javascript", action="store_true")
    action.add_argument("--run-detector", metavar="MUTANT")
    action.add_argument("--run-one-mutation", metavar="MUTANT")
    action.add_argument("--run-mutations", action="store_true")
    action.add_argument("--run-regression", action="store_true")
    action.add_argument("--scope", action="store_true")
    action.add_argument("--final-gate", action="store_true")
    action.add_argument("--build-tep", action="store_true")
    action.add_argument("--verify-tep", action="store_true")
    parser.add_argument("--runtime", choices=("python", "javascript"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--base")
    parser.add_argument("--candidate")
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--bundle-sha256")
    parser.add_argument("--issue-body", type=Path)
    parser.add_argument("--issue-body-sha256")
    parser.add_argument("--checkout-1", type=Path)
    parser.add_argument("--checkout-2", type=Path)
    parser.add_argument("--evidence-1", type=Path)
    parser.add_argument("--evidence-2", type=Path)
    parser.add_argument("--issue-rest", type=Path)
    parser.add_argument("--ratification-comment-rest", type=Path)
    parser.add_argument("--pr-rest", type=Path)
    parser.add_argument("--codex-reconciliation", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--package", type=Path)
    parser.add_argument("--mode", choices=("strict",))
    parser.add_argument("--mutation-log", type=Path)
    parser.add_argument(
        "--checkout-role", choices=("CHECKOUT_1", "CHECKOUT_2")
    )
    args = parser.parse_args(argv)
    if not args.run_detector:
        validate_relation()
    if args.validate_relation:
        _require(
            args.output is None and args.runtime is None,
            "validation does not accept runtime or output",
        )
        print("Package-A relation PASS scenarios=164 mutants=24")
        return 0
    if args.run_detector:
        _require(args.output is None, "detector does not accept output")
        _require(args.runtime is not None, "detector runtime is required")
        run_detector(args.run_detector, args.runtime)
        print(f"detector_pass={args.run_detector}:{args.runtime}")
        return 0
    if args.run_one_mutation:
        _require(args.output is not None, "single mutation output is required")
        _require(args.runtime is not None, "single mutation runtime is required")
        _store_new(
            args.output,
            _run_one_mutation(args.run_one_mutation, args.runtime),
        )
        return 0
    if args.run_mutations:
        _require(args.output is not None, "mutation output is required")
        _require(args.runtime is not None, "mutation runtime is required")
        _store_new(
            args.output,
            run_mutations(
                args.runtime,
                mutation_log=args.mutation_log,
                checkout_role=args.checkout_role,
            ),
        )
        return 0
    if args.run_regression:
        _require(args.output is not None, "regression output is required")
        _require(args.runtime is None, "regression does not accept runtime")
        _store_new(args.output, run_regression())
        return 0
    if args.scope:
        _require(args.output is not None, "scope output is required")
        _require(args.base is not None and args.candidate is not None, "scope identities are required")
        _store_new(args.output, run_package_a_scope(REPO, args.base, args.candidate))
        return 0
    if args.build_tep:
        required = (
            args.base,
            args.candidate,
            args.bundle,
            args.issue_rest,
            args.ratification_comment_rest,
            args.pr_rest,
            args.checkout_1,
            args.checkout_2,
            args.evidence_1,
            args.evidence_2,
            args.codex_reconciliation,
            args.output_dir,
        )
        _require(all(value is not None for value in required), "TEP builder argument missing")
        result = build_tep(
            base=args.base,
            candidate=args.candidate,
            bundle=args.bundle,
            issue_rest=args.issue_rest,
            ratification_comment_rest=args.ratification_comment_rest,
            pr_rest=args.pr_rest,
            checkout_1=args.checkout_1,
            checkout_2=args.checkout_2,
            evidence_1=args.evidence_1,
            evidence_2=args.evidence_2,
            codex_reconciliation=args.codex_reconciliation,
            output_dir=args.output_dir,
        )
        print(dumps(result).decode("utf-8"), end="")
        return 0
    if args.verify_tep:
        _require(args.package is not None, "TEP package is required")
        print(dumps(verify_tep(args.package)).decode("utf-8"), end="")
        return 0
    if args.final_gate:
        required = (
            args.base,
            args.candidate,
            args.bundle,
            args.bundle_sha256,
            args.issue_body,
            args.issue_body_sha256,
            args.ratification_comment_rest,
            args.checkout_1,
            args.checkout_2,
            args.evidence_1,
            args.evidence_2,
            args.output,
        )
        _require(all(value is not None for value in required), "final-gate argument missing")
        _require(args.runtime is None, "final gate does not accept runtime")
        _store_new(
            args.output,
            run_final_gate(
                base=args.base,
                candidate=args.candidate,
                bundle=args.bundle,
                bundle_sha256=args.bundle_sha256,
                issue_body=args.issue_body,
                issue_body_sha256=args.issue_body_sha256,
                ratification_comment_rest=args.ratification_comment_rest,
                checkout_1=args.checkout_1,
                checkout_2=args.checkout_2,
                evidence_1=args.evidence_1,
                evidence_2=args.evidence_2,
            ),
        )
        return 0
    _require(args.runtime is None, "runtime belongs only to detector mode")
    _require(args.output is not None, "runtime output is required")
    runtime = "python" if args.run_python else "javascript"
    _store_new(args.output, run_runtime(runtime))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RelationError as error:
        print(f"semantic_detector_failure={error}", file=sys.stderr)
        raise SystemExit(2) from None
