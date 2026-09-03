#!/usr/bin/env python3
"""Package-A H1/H2 hostile relation and executable evidence entry point."""

from __future__ import annotations

import argparse
from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import os
from pathlib import Path
import re
import shutil
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
    encode_event,
    encode_genesis,
    evaluate_k_admission_graph,
    evaluate_vector,
    framed_hash,
    reset_ed25519_evidence_counts,
    synthetic_octets,
)
from ed25519_reference import P, Point, add, decode, encode  # noqa: E402
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
)

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
}


_H1_MUTATION_SPECS: Final = (
    MutationSpec(
        "M-H1-A-CANONICAL",
        "        point_a = _ed_decode(public)\n",
        "        point_a = _ed_decode(public if int.from_bytes(public, \"little\") < _P else bytes(32))\n",
        "  try { pointA = edDecode(publicKey); }\n",
        "  try { pointA = edDecode(littleEndianInteger(publicKey) >= ED_P ? Buffer.alloc(32) : publicKey); }\n",
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
        "        point_r = _ed_decode(signature[:32] if int.from_bytes(signature[:32], \"little\") < _P else bytes(32))\n",
        "  try { pointR = edDecode(signature.subarray(0, 32)); }\n",
        "  try { pointR = edDecode(littleEndianInteger(signature.subarray(0, 32)) >= ED_P ? Buffer.alloc(32) : signature.subarray(0, 32)); }\n",
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
    _ = _ed_mul(scalar) == _ed_add(point_r, _ed_mul(1, point_a))
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
  const earlyBase = edPoint(15112221349535400772501151409588531511454012693041857206046113283949847762202n, 46316835694926478169428394003475163141307993866256225615783033603165251855960n);
  void edEqual(edScalarMult(scalar, earlyBase), edAdd(pointR, edScalarMult(1n, pointA)));
  if (scalar >= ED_L) return { accepted: false, equationInvocations: 1, guardCode: "NON_CANONICAL_SCALAR" };
""",
    ),
    MutationSpec(
        "M-H1-GUARD-ONLY-ACCEPT",
        "    accepted = _ed_mul(scalar) == _ed_add(point_r, _ed_mul(challenge, point_a))\n",
        "    accepted = True\n",
        "    const accepted = verifySignature(null, message, createPublicKey({ key: Buffer.concat([prefix, publicKey]), format: \"der\", type: \"spki\" }), signature);\n",
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
EVIDENCE_FILENAMES: Final = (
    "h1h2-python.json",
    "h1h2-javascript.json",
    "h1h2-mutations-python.json",
    "h1h2-mutations-javascript.json",
    "h1h2-regression.json",
    "scope.json",
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


def _project_graph_case(case: dict) -> dict:
    reset_ed25519_evidence_counts()
    harness_error = None
    try:
        observations = evaluate_k_admission_graph(case["genesis"], case["records"])
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
    return tuple(cases)


def _project_slot_case(case: dict) -> dict:
    observations = evaluate_k_admission_graph(case["genesis"], case["records"])
    by_id = {row["id"]: row for row in observations}
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
    _require(len(rows) == 62, "slot Python observation count")
    return {
        "result": "PASS",
        "rows": rows,
        "schema": "styx-c03-h2-slot-observations/v1",
    }


def run_javascript_slots() -> dict:
    cases = slot_cases()
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
                        for case in cases
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

    rows = []
    for case in cases:
        scenario = case["row"].scenario_id
        node = node_rows[scenario]
        expected_full = evaluate_k_admission_graph(case["genesis"], case["records"])
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
    if runtime == "python":
        _project_slot_case(case)
        return
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
    expected = _project_slot_case(case)
    _require(
        output.get("harnessError") is None,
        f"{case['row'].row_id} JavaScript harness",
    )
    _require(
        output["observations"]
        == evaluate_k_admission_graph(case["genesis"], case["records"]),
        f"{case['row'].row_id} cross-runtime slot",
    )
    by_id = {row["id"]: row for row in output["observations"]}
    projected = {
        "lexicalSchedule": case["lexicalSchedule"],
        "observations": [
            by_id[identifier] for identifier in sorted(case["targets"])
        ],
        "order": list(case["row"].order),
        "rowId": case["row"].row_id,
        "scenarioId": case["row"].scenario_id,
    }
    _require(projected == expected, f"{case['row'].row_id} slot projection")


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


def run_mutations(runtime: str) -> dict:
    _require(runtime in {"python", "javascript"}, "unknown mutation runtime")
    rows = []
    for mutant in MUTANTS:
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
            rows.append(
                {
                    "detectorId": marker,
                    "mutantId": mutant,
                    "result": "KILLED",
                    "runtime": runtime,
                    "sourceDigestChanged": before != after,
                }
            )
    _require(len(rows) == 20, "mutation kill count")
    return {
        "killed": 20,
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


def _validate_issue_appendix(issue_body: bytes) -> None:
    _require(
        sha256(issue_body).hexdigest() == RATIFIED_ISSUE_BODY_SHA256,
        "ratified Issue body mismatch",
    )
    text = issue_body.decode("utf-8")
    _require("## Appendix A — literal Package-A hostile relation" in text, "Appendix A missing")
    appendix = text.split("## Appendix A — literal Package-A hostile relation", 1)[1]
    boundary = re.findall(
        r"^\| `(H1-BND-\d{3})` \| `([^`]+)` \|", appendix, re.MULTILINE
    )
    connected = re.findall(
        r"^\| `(H1-CON-\d{3})` \| `([^`]+)` \|", appendix, re.MULTILINE
    )
    slots = re.findall(
        r"^\| `(H2-SLT-\d{3})` / `([^`]+)` \| `([^`]+)` \|",
        appendix,
        re.MULTILINE,
    )
    mutants = re.findall(
        r"^\| `(M-(?:H1|H2)-[^`]+)` \|", appendix, re.MULTILINE
    )
    _require(
        boundary == [(row.row_id, row.scenario_id) for row in H1_BOUNDARY],
        "Appendix A boundary relation mismatch",
    )
    _require(
        connected == [(row.row_id, row.scenario_id) for row in H1_CONNECTED],
        "Appendix A connected relation mismatch",
    )
    _require(
        slots
        == [
            (row.row_id, row.scenario_id, ">".join(row.order))
            for row in H2_SLOTS
        ],
        "Appendix A slot relation mismatch",
    )
    _require(mutants == list(MUTANTS), "Appendix A mutant relation mismatch")


def _git_text(checkout: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(checkout), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    _require(completed.returncode == 0, "Git evidence command failed")
    return completed.stdout.strip()


def _clean_checkout(checkout: Path, candidate: str) -> None:
    _require(checkout.is_dir() and not checkout.is_symlink(), "invalid checkout root")
    _require(_git_text(checkout, "rev-parse", "HEAD^{commit}") == candidate, "checkout HEAD mismatch")
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


def _verify_bundle(bundle: Path, expected_sha256: str, base: str, candidate: str) -> None:
    _require(bundle.is_file() and not bundle.is_symlink(), "invalid bundle")
    _require(sha256(bundle.read_bytes()).hexdigest() == expected_sha256, "bundle digest mismatch")
    listed = subprocess.run(
        ["git", "bundle", "list-heads", str(bundle)],
        check=False,
        capture_output=True,
        text=True,
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
    for value in regular.values():
        loads(value)
    runtime_python = loads(regular["h1h2-python.json"])
    runtime_javascript = loads(regular["h1h2-javascript.json"])
    _require(runtime_python == runtime_javascript, "runtime evidence mismatch")
    _require(
        runtime_python.get("scenarioCount") == 126
        and len(runtime_python.get("boundaryRows", [])) == 29
        and len(runtime_python.get("connectedRows", [])) == 35
        and len(runtime_python.get("slotRows", [])) == 62,
        "runtime evidence cardinality mismatch",
    )
    for runtime in ("python", "javascript"):
        mutation = loads(regular[f"h1h2-mutations-{runtime}.json"])
        _require(
            mutation.get("runtime") == runtime
            and mutation.get("killed") == 20
            and [row.get("mutantId") for row in mutation.get("rows", [])]
            == list(MUTANTS)
            and all(row.get("result") == "KILLED" for row in mutation.get("rows", [])),
            "mutation evidence mismatch",
        )
    regression = loads(regular["h1h2-regression.json"])
    _require(
        regression.get("result") == "PASS"
        and regression.get("frozenCorpusFiles") == 6
        and [row.get("id") for row in regression.get("checks", [])]
        == ["generate", "validate", "replay", "node", "cross-runtime", "historical-mutations"],
        "regression evidence mismatch",
    )
    scope = loads(regular["scope.json"])
    _require(
        scope.get("result") == "PASS"
        and scope.get("copyThresholdPercent") == 50,
        "scope evidence mismatch",
    )
    return regular


def _run_checkout_producer(
    checkout: Path,
    candidate: str,
    command: list[str],
    output: Path,
) -> None:
    _clean_checkout(checkout, candidate)
    environment = dict(os.environ)
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
    scope = checkout / "tools/causal-flow-simulator/c03/scope_guard.py"
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
                str(scope),
                "--repo-root",
                str(checkout),
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
    _verify_bundle(bundle, bundle_sha256, base, candidate)

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
    trees = {_git_text(checkout, "rev-parse", "HEAD^{tree}") for checkout in checkouts}
    _require(len(trees) == 1, "checkout tree mismatch")

    submitted_1 = _validate_evidence_set(evidence[0])
    submitted_2 = _validate_evidence_set(evidence[1])
    _require(submitted_1 == submitted_2, "two-checkout submitted evidence mismatch")
    with tempfile.TemporaryDirectory(prefix="styx-c03-final-gate-") as tmp:
        regenerated = (Path(tmp) / "one", Path(tmp) / "two")
        for root in regenerated:
            root.mkdir()
        _produce_evidence(checkouts[0], regenerated[0], base, candidate)
        _produce_evidence(checkouts[1], regenerated[1], base, candidate)
        regenerated_1 = _validate_evidence_set(regenerated[0])
        regenerated_2 = _validate_evidence_set(regenerated[1])
        _require(regenerated_1 == regenerated_2, "regenerated evidence mismatch")
        _require(regenerated_1 == submitted_1, "submitted evidence is not reproducible")
    return {
        "artifactCountPerCheckout": len(EVIDENCE_FILENAMES),
        "mutantRuntimeKills": 40,
        "result": "PASS",
        "runtimeScenarioCount": 126,
        "schema": "styx-c03-h1h2-final-gate/v1",
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
        == 126,
        "runtime scenario count",
    )
    return {
        "boundaryRows": boundary["rows"],
        "connectedRows": connected["rows"],
        "result": "PASS",
        "scenarioCount": 126,
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
        (H2_SLOTS, "H2-SLT", 62),
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
    _require(len(all_rows) == 126, "logical scenario count")
    _require(
        len({row.row_id for row in all_rows}) == len(all_rows),
        "duplicate row identifier",
    )
    _require(
        len({row.scenario_id for row in all_rows}) == len(all_rows),
        "duplicate scenario identifier",
    )
    _require(len(MUTANTS) == 20 and len(set(MUTANTS)) == 20, "mutant relation")
    _require(set(MUTATION_SPECS) == set(MUTANTS), "mutation specification set")
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
    runtime = {
        witness.identifier: witness.expected_code
        for witness in required_witnesses()
        if witness.runtime
    }
    _require(
        runtime == {row.scenario_id: row.expected for row in H1_BOUNDARY},
        "frozen O-14 boundary relation drift",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--validate-relation", action="store_true")
    action.add_argument("--run-python", action="store_true")
    action.add_argument("--run-javascript", action="store_true")
    action.add_argument("--run-detector", metavar="MUTANT")
    action.add_argument("--run-mutations", action="store_true")
    action.add_argument("--run-regression", action="store_true")
    action.add_argument("--final-gate", action="store_true")
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
    args = parser.parse_args(argv)
    if not args.run_detector:
        validate_relation()
    if args.validate_relation:
        _require(
            args.output is None and args.runtime is None,
            "validation does not accept runtime or output",
        )
        print("Package-A relation PASS scenarios=126 mutants=20")
        return 0
    if args.run_detector:
        _require(args.output is None, "detector does not accept output")
        _require(args.runtime is not None, "detector runtime is required")
        run_detector(args.run_detector, args.runtime)
        print(f"detector_pass={args.run_detector}:{args.runtime}")
        return 0
    if args.run_mutations:
        _require(args.output is not None, "mutation output is required")
        _require(args.runtime is not None, "mutation runtime is required")
        _store_new(args.output, run_mutations(args.runtime))
        return 0
    if args.run_regression:
        _require(args.output is not None, "regression output is required")
        _require(args.runtime is None, "regression does not accept runtime")
        _store_new(args.output, run_regression())
        return 0
    if args.final_gate:
        required = (
            args.base,
            args.candidate,
            args.bundle,
            args.bundle_sha256,
            args.issue_body,
            args.issue_body_sha256,
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
