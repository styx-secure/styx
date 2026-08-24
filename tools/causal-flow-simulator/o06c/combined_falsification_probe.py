#!/usr/bin/env python3
"""Bounded adversarial probe for the exact combined O-06c construction."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from common import canonical_bytes, sha256_hex, write_report
from exhaustive_mutations import run_exhaustive
from policy_guards import (
    C03_BLOCKED_CAPABILITIES,
    C03_DEPENDENCIES,
    RemovalTarget,
    c03_blocked_capabilities,
    detects_collapsed_removal_identity,
    lineage_scoped_quarantine,
    project_removal_directive,
    reject_any_must0_bypass,
    retain_k_evidence,
)
from protocol_model import (
    COMMITMENT_SUITE,
    CONTENT_DETACHABLE,
    CONTENT_NONE,
    CONTENT_REQUIRED,
    DOMAINS,
    MAX_U64,
    ROLE_ORDINARY,
    ROLE_REMOVAL,
    SHAPE_SINGLE,
    SHAPE_TREE,
    CommitmentContext,
    ContentDescriptor,
    EventAssignment,
    Geometry,
    ModelError,
    RemovalTail,
    WorkCounter,
    build_commitment,
    descriptor_from_commitment,
    encode_content_descriptor,
    encode_event_transcript,
    event_reference,
    make_grant,
    parse_commitment_preimage,
    parse_event_transcript,
    parse_leaf_preimage,
    parse_node_preimage,
    u8,
    u16,
    u32,
    u64,
    verify_opening,
)


SCHEMA = "styx-o06c-combined-falsification-report/v1"
EXPECTED_SEED = "o06c-v1-deterministic-test-seed"

# This is a coverage registry, not a claim that every directed assertion is a
# source-mutant detector.  build_witnesses() verifies the registry against the
# actually executed witness records before a verdict can be emitted.
WITNESS_ASSERTION_REGISTRY = {
    "capability-gate": ("W-C03-01",),
    "closed-agility": ("W-CLOSED-01",),
    "complete-opening": ("M08",),
    "control-none": ("W-CONTROL-01",),
    "domain-separation": ("W-FRAME-02",),
    "exhaustive-octets": ("W-EXHAUSTIVE-01",),
    "fork-scope": ("W-FORK-01",),
    "framing-injectivity": ("W-FRAME-01",),
    "geometry": ("W-GEOMETRY-01",),
    "grant-rooted-opening": ("W-BIND-01",),
    "hash-assumption": ("W-HASH-01",),
    "leaf-separation": ("W-BIND-02",),
    "legacy-rejection": ("W-LEGACY-01",),
    "outer-commitment": ("M09",),
    "pending-authority": ("W-PENDING-01",),
    "pinned-authority": ("W-AUTH-08",),
    "prefix-freeness": ("W-PREFIX-01",),
    "removal-tail-variance": (
        "W-REMOVAL-01",
        "W-REMOVAL-02",
        "W-REMOVAL-03",
        "W-REMOVAL-04",
    ),
    "same-slot-equivocation": ("W-FORK-05",),
    "shape-boundary": ("W-SHAPE-01",),
    "tree-integrity": ("W-TREE-01",),
    "work-accounting": ("W-WORK-01", "W-WORK-02"),
    "zero-content": ("W-SHAPE-02",),
}


class ProbeError(ValueError):
    pass


@dataclass(frozen=True)
class Witness:
    identifier: str
    family: str
    assertion: str
    passed: bool
    detectors: tuple[str, ...]

    def record(self) -> dict[str, object]:
        return {
            "id": self.identifier,
            "family": self.family,
            "assertion": self.assertion,
            "detectors": list(self.detectors),
            "status": "PASS" if self.passed else "FAIL",
        }


def deterministic(label: str, length: int = 32) -> bytes:
    seed = os.environ.get("O06C_MODEL_SEED")
    if seed != EXPECTED_SEED:
        raise ProbeError("O06C_MODEL_SEED mismatch")
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(f"{seed}|{label}|{counter}".encode()).digest())
        counter += 1
    return bytes(output[:length])


def expect_error(call, contains: str) -> bool:
    try:
        call()
    except (ModelError, ProbeError) as error:
        return contains in str(error)
    return False


def fixed_root_commitment(context: CommitmentContext, content_type: int, length: int, shape: int, root: bytes, randomizer: bytes, geometry: Geometry | None) -> bytes:
    body = b"".join(
        (
            context.encode(), u32(content_type), u64(length), u8(shape),
            geometry.encode() if geometry is not None else b"", root, randomizer,
        )
    )
    preimage = DOMAINS["commitment"] + u32(len(body)) + body
    return hashlib.sha256(preimage).digest()


def base_event(
    credential: bytes,
    descriptor: ContentDescriptor,
    *,
    sequence: int = 0,
    transition: bytes = b"ap",
) -> EventAssignment:
    return EventAssignment(
        application_profile_id=1,
        application_profile_version=1,
        context_identifier=deterministic("context"),
        event_role=ROLE_ORDINARY,
        event_type_id=1,
        schema_id=1,
        schema_version=1,
        transition_block=transition,
        credential_identifier=credential,
        author_sequence=sequence,
        direct_predecessor=None if sequence == 0 else deterministic(f"predecessor:{sequence}"),
        causal_parents=(),
        genesis_reference=deterministic("genesis"),
        content=descriptor,
    )


def checked_randomizer(source) -> bytes:
    try:
        value = source(32)
    except Exception as error:
        raise ProbeError("CSPRNG_FAILURE") from error
    if not isinstance(value, bytes) or len(value) != 32:
        raise ProbeError("CSPRNG_FAILURE")
    return value


def pending_closure(
    events: dict[str, tuple[str, ...]], roots: set[str], work: WorkCounter
) -> set[str]:
    work.graph_construction += len(events) + sum(len(parents) for parents in events.values())
    pending = set(roots)
    changed = True
    while changed:
        work.replay += 1
        changed = False
        for identifier, parents in events.items():
            if identifier not in pending and any(parent in pending for parent in parents):
                pending.add(identifier)
                changed = True
    return pending


def reject_digest_alias(
    preimage_a: bytes, preimage_b: bytes, digest_a: bytes, digest_b: bytes
) -> None:
    if preimage_a != preimage_b and digest_a == digest_b:
        raise ProbeError("HASH_COLLISION_FINDING")


def _c03_record(review_model: dict[str, object]) -> dict[str, object]:
    blockers = review_model.get("blockers")
    if not isinstance(blockers, list):
        raise ProbeError("review model has no blocker registry")
    matches = [
        item
        for item in blockers
        if isinstance(item, dict) and item.get("id") == "C0.3"
    ]
    if len(matches) != 1:
        raise ProbeError("review model must contain exactly one C0.3 blocker")
    return matches[0]


def build_witnesses(
    review_model: dict[str, object],
) -> tuple[list[Witness], dict[str, object]]:
    witnesses: list[Witness] = []
    add = witnesses.append
    credential = deterministic("credential")
    other_credential = deterministic("credential-other")
    context = CommitmentContext(1, 1, deterministic("context"), credential, 0)
    randomizer = deterministic("randomizer")
    content = b"abcdefghijklmno"
    stage_work = WorkCounter()

    # 1: exact framing, inverse parsing and domain separation.
    single = build_commitment(context, 7, content, randomizer)
    event = base_event(credential, descriptor_from_commitment(CONTENT_REQUIRED, single))
    transcript = encode_event_transcript(event, stage_work)
    measured_reference = event_reference(event, stage_work)
    inverse_ok = (
        parse_event_transcript(transcript, stage_work) == event
        and len(measured_reference) == 32
        and parse_leaf_preimage(single.leaf_preimages[0], stage_work)["leaf_octets"] == content
        and parse_commitment_preimage(single.commitment_preimage, stage_work)["root"] == single.root
    )
    add(Witness("W-FRAME-01", "framing-injectivity", "all complete selected inverses round-trip", inverse_ok, ("TRANSCRIPT_INVERSE", "PREIMAGE_INVERSE")))
    add(Witness("W-FRAME-02", "domain-separation", "all seven registered domains are fixed-width and distinct", len(DOMAINS) == 7 and len(set(DOMAINS.values())) == 7 and all(len(value) == 16 for value in DOMAINS.values()), ("DOMAIN_REGISTRY",)))

    # 2: grant-rooted credential and context/leaf separation.
    grant = make_grant(
        issuer_credential=deterministic("issuer"),
        context_identifier=context.context_identifier,
        genesis_reference=deterministic("genesis"),
        transition_block=b"grant",
        verification_key=deterministic("verification-key", 48),
    )
    grant_id = event_reference(grant)
    rooted = replace(context, credential_identifier=grant_id)
    rooted_commitment = build_commitment(rooted, 7, content, randomizer, chunk_size=4)
    cross_context = replace(rooted, context_identifier=deterministic("other-context"))
    cross_event = replace(rooted, author_sequence=1)
    cross_credential = replace(rooted, credential_identifier=other_credential)
    separation = all(
        expect_error(lambda candidate=candidate: verify_opening(descriptor_from_commitment(CONTENT_REQUIRED, rooted_commitment), candidate, content, randomizer), "commitment mismatch")
        for candidate in (cross_context, cross_event, cross_credential)
    )
    intra_leaf = len(set(rooted_commitment.leaf_digests)) == len(rooted_commitment.leaf_digests)
    add(Witness("W-BIND-01", "grant-rooted-opening", "openings do not transfer across context, credential or sequence", grant_id not in encode_event_transcript(grant) and separation, ("CONTEXT_BINDING", "CREDENTIAL_BINDING", "SEQUENCE_BINDING")))
    add(Witness("W-BIND-02", "leaf-separation", "ordinals separate leaves within one event", intra_leaf, ("LEAF_ORDINAL",)))

    # 3: shape separation and the zero-length/NONE boundary.
    tree = build_commitment(context, 7, content, randomizer, chunk_size=4)
    empty = build_commitment(context, 7, b"", randomizer)
    none_descriptor = ContentDescriptor(CONTENT_NONE, 0)
    shape_ok = single.commitment_value != tree.commitment_value
    one_leaf_rejected = expect_error(lambda: build_commitment(context, 7, b"abc", randomizer, chunk_size=4), "at least two chunks")
    zero_distinct = encode_content_descriptor(descriptor_from_commitment(CONTENT_REQUIRED, empty)) != encode_content_descriptor(none_descriptor)
    add(Witness("W-SHAPE-01", "shape-boundary", "SINGLE/TREE do not alias and one-leaf TREE is invalid", shape_ok and one_leaf_rejected, ("SHAPE_BINDING", "TREE_CARDINALITY")))
    add(Witness("W-SHAPE-02", "zero-content", "zero-length content-bearing SINGLE remains distinct from NONE", zero_distinct, ("CONTENT_CLASS",)))

    # 4: geometry rejection is measured before content splitting/hashing.  A
    # small inconsistent count and MAX_U64 consume the same fixed guard work.
    small_geometry_work = WorkCounter()
    inflated_geometry_work = WorkCounter()
    outside_set_work = WorkCounter()
    small_inconsistent = ContentDescriptor(
        CONTENT_REQUIRED,
        9,
        7,
        COMMITMENT_SUITE,
        SHAPE_TREE,
        deterministic("fake-commitment"),
        Geometry(1, 2, 1),
    )
    inflated = replace(
        small_inconsistent,
        geometry=Geometry(1, MAX_U64, 1),
    )
    small_rejected = expect_error(
        lambda: encode_content_descriptor(small_inconsistent, small_geometry_work),
        "chunk count",
    )
    geometry_rejected = expect_error(
        lambda: encode_content_descriptor(inflated, inflated_geometry_work),
        "chunk count",
    )
    outside_set = expect_error(
        lambda: build_commitment(
            context,
            7,
            bytes(130),
            randomizer,
            chunk_size=65,
            work=outside_set_work,
        ),
        "outside test-only",
    )
    fixed_guard_work = (
        small_geometry_work.geometry_checks
        == inflated_geometry_work.geometry_checks
        == outside_set_work.geometry_checks
        == 1
    )
    no_proportional_work = all(
        counter.content_split_chunks == 0
        and counter.leaf_hashes == 0
        and counter.node_hashes == 0
        and counter.commitment_hashes == 0
        and counter.hashed_octets == 0
        for counter in (
            small_geometry_work,
            inflated_geometry_work,
            outside_set_work,
        )
    )
    add(Witness("W-GEOMETRY-01", "geometry", "small and MAX_U64 inconsistent geometry plus out-of-envelope chunk size reject after equal fixed guard work and before proportional splitting or hashing", small_rejected and geometry_rejected and outside_set and fixed_guard_work and no_proportional_work, ("GEOMETRY_CHECK", "PREALLOCATION_REJECT", "MEASURED_FIXED_WORK")))

    # 5: grafting or duplicate-last-leaf changes the authenticated root.
    grafted_content = content[:4] + b"WXYZ" + content[8:]
    duplicated_content = content + content[-3:]
    grafted = build_commitment(context, 7, grafted_content, randomizer, chunk_size=4)
    duplicated = build_commitment(context, 7, duplicated_content, randomizer, chunk_size=4)
    add(Witness("W-TREE-01", "tree-integrity", "subtree grafting and duplicate-last-leaf attempts alter root and commitment", len({tree.root, grafted.root, duplicated.root}) == 3 and len({tree.commitment_value, grafted.commitment_value, duplicated.commitment_value}) == 3, ("TREE_ROOT", "COMMITMENT_OBJECT")))

    # 6: framing rejects append/truncate; length extension is not an alternate parse.
    prefix_ok = expect_error(lambda: parse_event_transcript(transcript + b"x"), "trailing octets") and expect_error(lambda: parse_event_transcript(transcript[:-1]), "truncated event body")
    add(Witness("W-PREFIX-01", "prefix-freeness", "append and truncation cannot parse as the same transcript", prefix_ok, ("OUTER_LENGTH", "TRAILING_OCTETS")))

    # 7: randomizer, entropy failure and closed suite/shape rules fail closed.
    randomizer_width = expect_error(lambda: build_commitment(context, 7, content, b"short"), "32 octets")
    entropy_failure = expect_error(lambda: checked_randomizer(lambda _length: (_ for _ in ()).throw(RuntimeError("rng"))), "CSPRNG_FAILURE")
    unknown_suite = expect_error(lambda: encode_content_descriptor(replace(descriptor_from_commitment(CONTENT_REQUIRED, single), commitment_suite_id=2)), "unsupported commitment suite")
    unknown_shape = expect_error(lambda: encode_content_descriptor(replace(descriptor_from_commitment(CONTENT_REQUIRED, single), commitment_shape=2)), "unknown shape")
    add(Witness("W-CLOSED-01", "closed-agility", "bad randomizer, entropy failure and unknown suite/shape never fall back", randomizer_width and entropy_failure and unknown_suite and unknown_shape, ("RANDOMIZER_WIDTH", "CSPRNG_FAILURE", "SUITE_REJECT", "SHAPE_REJECT")))

    # 8 and C0.2k M08/M09: complete verification and fixed-root outer binding.
    descriptor = descriptor_from_commitment(CONTENT_REQUIRED, tree)
    equality = verify_opening(descriptor, context, content, randomizer).commitment_value == tree.commitment_value
    stage_work.opening_verification += 1
    mismatch = expect_error(lambda: verify_opening(descriptor, context, content + b"x", randomizer), "length mismatch")
    contexts = (context, replace(context, credential_identifier=other_credential), replace(context, author_sequence=1))
    fixed_root_values = [fixed_root_commitment(candidate, 7, len(content), SHAPE_TREE, tree.root, randomizer, tree.geometry) for candidate in contexts]
    m08 = all(a != b for a, b in zip(tree.leaf_digests, build_commitment(contexts[1], 7, content, randomizer, chunk_size=4).leaf_digests)) and all(a != b for a, b in zip(tree.leaf_digests, build_commitment(contexts[2], 7, content, randomizer, chunk_size=4).leaf_digests))
    add(Witness("M08", "complete-opening", "every leaf binds credential and author sequence", equality and mismatch and m08, ("OPENING_VERIFY", "LEAF_CONTEXT")))
    add(Witness("M09", "outer-commitment", "fixed supplied root still binds credential and author sequence", len(set(fixed_root_values)) == 3, ("OUTER_CONTEXT",)))

    # 9: independently reach both encoded order directions and exercise guards
    # around explicitly pinned C0.2j outcomes.  The outcomes are not rederived
    # by this package and are therefore not counted as executable witnesses.
    pinned = {
        "W-AUTH-08": {"grant_before_revoke": True, "grant_after_revoke": True, "must0_bypass": False},
        "W-PENDING-01": {"k_evidence_retained": True, "ap_filters_k_evidence": False},
        "W-FORK-01": {"scope": "credential-lineage", "authority_expansion": False},
    }
    peer = event_reference(base_event(credential, none_descriptor, transition=b"peer"))
    variants = []
    for index in range(512):
        directive = replace(
            base_event(credential, none_descriptor, transition=b"remove"),
            event_role=ROLE_REMOVAL,
            tail=RemovalTail(deterministic("target"), hashlib.sha256(f"tail:{index}".encode()).digest()),
        )
        variants.append(event_reference(directive))
    both_directions = any(value < peer for value in variants) and any(value > peer for value in variants)
    graph = {"root": (), "child": ("root",), "independent": ()}
    pending = pending_closure(graph, {"root"}, stage_work)
    pending_exact = pending == {"root", "child"}
    must0_guard = (
        reject_any_must0_bypass((False, False))
        and not reject_any_must0_bypass((False, True))
    )
    retained_evidence = retain_k_evidence(("grant", "revoke"), ap_pending=True)
    scoped_authority = lineage_scoped_quarantine(
        frozenset({"forked", "independent"}), frozenset({"forked"})
    )
    add(Witness("W-AUTH-08", "pinned-authority", "both K-06 reference-order directions are reachable and the fail-closed guard rejects an injected Must0-bypass input; C0.2j outcomes remain pinned, not rederived", both_directions and must0_guard, ("K06_BOTH_DIRECTIONS", "PINNED_INPUT_GUARD")))
    add(Witness("W-PENDING-01", "pending-authority", "pending is exact causal closure and AP pending state never filters K-admitted evidence", pending_exact and "independent" not in pending and retained_evidence == ("grant", "revoke"), ("PENDING_CLOSURE", "K_EVIDENCE_RETENTION")))
    add(Witness("W-FORK-01", "fork-scope", "the bounded quarantine guard removes only the named lineage and cannot add or clear unrelated authority", scoped_authority == frozenset({"independent"}), ("LINEAGE_SCOPE",)))

    # 10: content-bearing control is rejected structurally before opening work.
    bad_removal = replace(event, event_role=ROLE_REMOVAL, tail=RemovalTail(deterministic("target"), deterministic("target-commitment")))
    control_rejected = expect_error(lambda: encode_event_transcript(bad_removal), "removal requires NONE")
    add(Witness("W-CONTROL-01", "control-none", "control-role/NONE is enforced before opening or AP work", control_rejected, ("ROLE_CONTENT_CROSS_FIELD",)))

    # 11: old context width fails; copied openings fail across slots; same-slot siblings stay distinct.
    old_leaf = single.leaf_preimages[0][:20] + single.leaf_preimages[0][60:]
    old_context_rejected = expect_error(lambda: parse_leaf_preimage(old_leaf), "truncated") or expect_error(lambda: parse_leaf_preimage(old_leaf), "unsupported")
    copied_rejected = separation
    sibling_a = base_event(credential, none_descriptor, transition=b"sibling-a")
    sibling_b = base_event(credential, none_descriptor, transition=b"sibling-b")
    sibling_refs = (event_reference(sibling_a), event_reference(sibling_b))
    siblings_are_fork_evidence = sibling_refs[0] != sibling_refs[1] and sibling_a.author_sequence == sibling_b.author_sequence
    add(Witness("W-LEGACY-01", "legacy-rejection", "44-octet grammar and cross-slot opening copy reject", old_context_rejected and copied_rejected, ("CTX84_REQUIRED", "OPENING_SLOT")))
    add(Witness("W-FORK-05", "same-slot-equivocation", "same-credential/same-sequence siblings remain distinct fork evidence", siblings_are_fork_evidence, ("SAME_SLOT_SIBLINGS",)))

    # 11.1: evaluate full bounded AP projections for every vacuous target class,
    # then force the retained-DETACHABLE positive arm and both polarities of the
    # identity-collapse guard.  The positive arm uses two distinct directive
    # events carrying the same matching removal tail, so AP invariance is not a
    # consequence of evaluating only inapplicable inputs.
    none_target_ref = deterministic("removal-target-none")
    required_target_ref = deterministic("removal-target-required")
    detachable_target_ref = deterministic("removal-target-detachable")
    unretained_target_ref = deterministic("removal-target-unretained")
    required_descriptor = (
        "REQUIRED",
        len(content),
        7,
        tree.shape,
        tree.commitment_value,
    )
    detachable_commitment = build_commitment(
        context, 8, b"detachable-content", randomizer, chunk_size=4
    )
    detachable_descriptor = (
        "DETACHABLE",
        detachable_commitment.exact_content_length,
        8,
        detachable_commitment.shape,
        detachable_commitment.commitment_value,
    )
    ambient = (
        RemovalTarget(
            none_target_ref,
            "NONE",
            ("NONE", 0),
            None,
            True,
            True,
            "BOUND",
            "VISIBLE",
        ),
        RemovalTarget(
            required_target_ref,
            "REQUIRED",
            required_descriptor,
            tree.commitment_value,
            True,
            True,
            "BOUND",
            "VISIBLE",
        ),
        RemovalTarget(
            detachable_target_ref,
            "DETACHABLE",
            detachable_descriptor,
            detachable_commitment.commitment_value,
            True,
            True,
            "BOUND",
            "VISIBLE",
        ),
        RemovalTarget(
            unretained_target_ref,
            "DETACHABLE",
            ("DETACHABLE", 4, 9, SHAPE_SINGLE, deterministic("unretained-value")),
            deterministic("unretained-value"),
            False,
            False,
            "BOUND",
            "WITHHELD",
        ),
    )
    mismatching_tail_a = deterministic("tail-a")
    mismatching_tail_b = deterministic("tail-b")
    vacuous_targets = (
        ("NONE", none_target_ref),
        ("REQUIRED", required_target_ref),
        ("ABSENT", deterministic("removal-target-absent")),
        ("NOT_RETAINED", unretained_target_ref),
    )
    projection_pairs = []
    for label, target_reference in vacuous_targets:
        first = project_removal_directive(
            ambient,
            target_reference=target_reference,
            target_commitment=mismatching_tail_a,
        )
        second = project_removal_directive(
            ambient,
            target_reference=target_reference,
            target_commitment=mismatching_tail_b,
        )
        projection_pairs.append((label, first, second))
    ap_invariant = all(
        first == second and first.removal_effect == "NONE"
        for _label, first, second in projection_pairs
    )

    retained_tail = RemovalTail(
        detachable_target_ref,
        detachable_commitment.commitment_value,
    )
    retained_directive_a = replace(
        base_event(credential, none_descriptor, transition=b"retained-removal-a"),
        event_role=ROLE_REMOVAL,
        tail=retained_tail,
    )
    retained_directive_b = replace(
        base_event(credential, none_descriptor, transition=b"retained-removal-b"),
        event_role=ROLE_REMOVAL,
        tail=retained_tail,
    )
    retained_projection_a = project_removal_directive(
        ambient,
        target_reference=retained_directive_a.tail.target_event_reference,
        target_commitment=retained_directive_a.tail.target_commitment,
    )
    retained_projection_b = project_removal_directive(
        ambient,
        target_reference=retained_directive_b.tail.target_event_reference,
        target_commitment=retained_directive_b.tail.target_commitment,
    )
    retained_vacuous_projection = project_removal_directive(
        ambient,
        target_reference=detachable_target_ref,
        target_commitment=mismatching_tail_a,
    )
    retained_target_projection = next(
        row
        for row in retained_projection_a.ambient_projection
        if row[0] == detachable_target_ref
    )
    changed_ambient_rows = tuple(
        (before, after)
        for before, after in zip(
            retained_vacuous_projection.ambient_projection,
            retained_projection_a.ambient_projection,
            strict=True,
        )
        if before != after
    )
    retained_projection_nonvacuous = (
        encode_event_transcript(retained_directive_a)
        != encode_event_transcript(retained_directive_b)
        and event_reference(retained_directive_a)
        != event_reference(retained_directive_b)
        and retained_projection_a == retained_projection_b
        and retained_projection_a.classification == "REMOVAL_APPLIED"
        and retained_projection_a.removal_effect == "LOGICAL_DETACH"
        and retained_projection_a.target_validity == "VALIDATED"
        and retained_projection_a.target_retention == "RETAINED"
        and retained_projection_a.target_presentation == "REMOVED"
        and retained_target_projection[6] == "REMOVED"
        and retained_projection_a != retained_vacuous_projection
        and len(changed_ambient_rows) == 1
        and changed_ambient_rows[0][0][0] == detachable_target_ref
        and changed_ambient_rows[0][0][:6] == changed_ambient_rows[0][1][:6]
        and changed_ambient_rows[0][0][6] == "VISIBLE"
        and changed_ambient_rows[0][1][6] == "REMOVED"
        and changed_ambient_rows[0][0][7:] == changed_ambient_rows[0][1][7:]
    )

    removal_variants = []
    for index in range(512):
        candidate = replace(
            base_event(credential, none_descriptor, transition=b"removal"),
            event_role=ROLE_REMOVAL,
            tail=RemovalTail(
                none_target_ref,
                hashlib.sha256(f"removal-tail:{index}".encode()).digest(),
            ),
        )
        removal_variants.append((candidate, event_reference(candidate)))
    lower = next((item for item in removal_variants if item[1] < peer), None)
    higher = next((item for item in removal_variants if item[1] > peer), None)
    if lower is None or higher is None:
        raise ProbeError("bounded removal-tail search did not span K-06 peer order")
    removal_a, ref_a = lower
    removal_b, ref_b = higher
    transcript_a = encode_event_transcript(removal_a)
    transcript_b = encode_event_transcript(removal_b)
    order_projection_a = project_removal_directive(
        ambient,
        target_reference=none_target_ref,
        target_commitment=removal_a.tail.target_commitment,
    )
    order_projection_b = project_removal_directive(
        ambient,
        target_reference=none_target_ref,
        target_commitment=removal_b.tail.target_commitment,
    )
    identity_and_order_variance = (
        transcript_a != transcript_b
        and ref_a != ref_b
        and ref_a < peer < ref_b
        and order_projection_a == order_projection_b
    )
    collapsed_key_a = (
        removal_a.credential_identifier,
        removal_a.author_sequence,
        removal_a.tail.target_event_reference,
    )
    collapsed_key_b = (
        removal_b.credential_identifier,
        removal_b.author_sequence,
        removal_b.tail.target_event_reference,
    )
    collapse_detected = detects_collapsed_removal_identity(
        ref_a,
        ref_b,
        collapsed_key_a,
        collapsed_key_b,
    )
    collapse_false_positive_rejected = (
        not detects_collapsed_removal_identity(
            ref_a,
            ref_a,
            collapsed_key_a,
            collapsed_key_b,
        )
        and not detects_collapsed_removal_identity(
            ref_a,
            ref_b,
            collapsed_key_a,
            (
                removal_b.credential_identifier,
                removal_b.author_sequence,
                deterministic("different-removal-target"),
            ),
        )
    )
    removal_pending_graph = {
        "pending-root": (),
        "directive": ("pending-root",),
        "child": ("directive",),
        "independent": (),
    }
    pending_a = pending_closure(removal_pending_graph, {"pending-root"}, stage_work)
    pending_b = pending_closure(removal_pending_graph, {"pending-root"}, stage_work)
    pending_invariant = (
        pending_a == pending_b == {"pending-root", "directive", "child"}
        and "independent" not in pending_a
    )
    add(Witness("W-REMOVAL-01", "removal-tail-variance", "NONE, REQUIRED, absent and non-retained targets retain byte-identical full bounded AP projections across distinct target-commitment tails", ap_invariant, ("AP_PROJECTION_INVARIANCE", "REMOVAL_INAPPLICABLE_OR_DEFERRED")))
    add(Witness("W-REMOVAL-02", "removal-tail-variance", "tail variants change transcript, event identity and K-06 order while their vacuous AP projection remains invariant; both positive and false-positive identity-collapse cases are detected", identity_and_order_variance and collapse_detected and collapse_false_positive_rejected, ("TAIL_BYTES", "EVENT_IDENTITY", "K06_ORDER_VARIANCE", "COLLAPSED_IDENTITY_POSITIVE", "COLLAPSED_IDENTITY_FALSE_POSITIVE_REJECT")))
    add(Witness("W-REMOVAL-03", "removal-tail-variance", "both tail variants remain in the same pending causal subtree while the independent event remains outside it", pending_invariant, ("PENDING_SUBTREE_INVARIANCE",)))
    add(Witness("W-REMOVAL-04", "removal-tail-variance", "two distinct directives with the same matching retained-DETACHABLE tail produce the same non-vacuous AP projection and logically detach only the target", retained_projection_nonvacuous, ("RETAINED_DETACHABLE_APPLIED", "LOGICAL_DETACH", "AP_PROJECTION_POSITIVE_CONTROL")))

    # 13: deterministic stage accounting and measured rehash amplification.
    sequence_changed_single = build_commitment(replace(context, author_sequence=1), 7, content, randomizer)
    sequence_changed_tree = build_commitment(replace(context, author_sequence=1), 7, content, randomizer, chunk_size=4)
    counters = {
        "single": single.work,
        "single_sequence_change": sequence_changed_single.work,
        "tree": tree.work,
        "tree_sequence_change": sequence_changed_tree.work,
    }
    counter_ok = (
        single.work["leaf_hashes"] == 1
        and single.work["node_hashes"] == 0
        and single.work["commitment_hashes"] == 1
        and tree.work["leaf_hashes"] == len(tree.leaf_digests)
        and tree.work["node_hashes"] == len(tree.leaf_digests) - 1
        and tree.work["commitment_hashes"] == 1
        and sequence_changed_single.work == single.work
        and sequence_changed_tree.work == tree.work
    )
    add(Witness("W-WORK-01", "work-accounting", "SINGLE/TREE rehash amplification is deterministic and complete", counter_ok, ("WORK_COUNTERS",)))

    # A distinct-preimage/equal-digest injection is a blocking assumption finding.
    collision_a = deterministic("collision-a")
    collision_b = deterministic("collision-b")
    collision_injection_rejected = expect_error(
        lambda: reject_digest_alias(collision_a, collision_b, bytes(32), bytes(32)),
        "HASH_COLLISION_FINDING",
    )
    add(Witness("W-HASH-01", "hash-assumption", "distinct-preimage/equal-digest injection is classified as a collision finding, never a winner", collision_injection_rejected, ("COLLISION_ASSUMPTION",)))
    c03 = _c03_record(review_model)
    c03_dependencies = frozenset(c03.get("depends_on", ()))
    c03_declared_blocks = frozenset(c03.get("blocks", ()))
    c03_blocked = c03_blocked_capabilities(
        str(c03.get("status")),
        c03_dependencies,
        c03_declared_blocks,
    )
    add(Witness("W-C03-01", "capability-gate", "the actual derived-review-model C0.3 record is NO_GO, retains the exact dependency set and blocks exactly five capabilities", c03_blocked == C03_BLOCKED_CAPABILITIES and len(c03_blocked) == 5, ("C03_MODEL_RECORD", "C03_NO_GO")))
    aggregate = stage_work.record()
    for commitment in (single, tree, sequence_changed_single, sequence_changed_tree):
        for name, value in commitment.work.items():
            aggregate[name] += value
    required_nonzero = (
        "parsing", "inverse", "serialization", "transcript_regeneration",
        "leaf_hashes", "node_hashes", "commitment_hashes", "reference_hashes",
        "graph_construction", "opening_verification", "replay", "hashed_octets",
    )
    add(Witness("W-WORK-02", "work-accounting", "every required deterministic stage counter is exercised", all(aggregate[name] > 0 for name in required_nonzero), ("STAGE_COVERAGE",)))
    return witnesses, {
        "pinned_c02j": {
            "execution_status": "PINNED_NOT_REDERIVED",
            "reason": "O-06c executes fail-closed boundary guards but is forbidden to create a second C0.2j authority oracle",
            "outcomes": pinned,
        },
        "removal_tail_variance": {
            "vacuous_target_cases": [label for label, _first, _second in projection_pairs],
            "full_ap_projection_equal": ap_invariant,
            "retained_detachable_applied": retained_projection_a.classification == "REMOVAL_APPLIED",
            "retained_detachable_projection_equal": retained_projection_a == retained_projection_b,
            "retained_detachable_differs_from_vacuous": retained_projection_a != retained_vacuous_projection,
            "retained_detachable_only_target_changed": len(changed_ambient_rows) == 1,
            "k06_order_spanned": identity_and_order_variance,
            "collapsed_identity_positive_detected": collapse_detected,
            "collapsed_identity_false_positive_rejected": collapse_false_positive_rejected,
            "pending_subtree_equal": pending_invariant,
        },
        "c03_model_record": {
            "status": c03.get("status"),
            "depends_on": sorted(c03_dependencies),
            "blocks": sorted(c03_declared_blocks),
        },
        "work_counters": counters,
        "aggregate_stage_counters": aggregate,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", required=True, choices=("required",))
    parser.add_argument("--frozen-report", required=True, type=Path)
    parser.add_argument(
        "--review-model",
        type=Path,
        default=(
            Path(__file__).resolve().parents[3]
            / "docs/protocol/review/styx-app-kernel-v0-review-model.json"
        ),
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        frozen_bytes = args.frozen_report.read_bytes()
        frozen = json.loads(frozen_bytes)
        if frozen.get("schema") != "styx-o06c-frozen-section-report/v1" or frozen.get("verdict") != "PASS":
            raise ProbeError("frozen-section report is not PASS")
        review_model_bytes = args.review_model.read_bytes()
        review_model = json.loads(review_model_bytes)
        if not isinstance(review_model, dict):
            raise ProbeError("review model root must be an object")
        witnesses, evidence = build_witnesses(review_model)
        exhaustive = run_exhaustive()
        witnesses.append(
            Witness(
                "W-EXHAUSTIVE-01",
                "exhaustive-octets",
                "every selected octet and frozen scalar has only a typed rejection or canonical distinct reassignment",
                exhaustive["verdict"] == "PASS",
                ("EXHAUSTIVE_OCTETS", "SCALAR_BOUNDARIES"),
            )
        )
        actual_coverage: dict[str, list[str]] = {}
        for witness in witnesses:
            actual_coverage.setdefault(witness.family, []).append(witness.identifier)
        expected_coverage = {
            family: list(assertions)
            for family, assertions in WITNESS_ASSERTION_REGISTRY.items()
        }
        if actual_coverage != expected_coverage:
            raise ProbeError(
                "executed witness/assertion coverage differs from closed registry"
            )
        evidence["witness_coverage"] = expected_coverage
        evidence["exhaustive_mutations"] = exhaustive
        failed = [witness.identifier for witness in witnesses if not witness.passed]
        report = {
            "schema": SCHEMA,
            "suite": "required",
            "frozen_report_sha256": sha256_hex(frozen_bytes),
            "c03_record_sha256": sha256_hex(
                canonical_bytes(_c03_record(review_model))
            ),
            "witness_count": len(witnesses),
            "witnesses": [witness.record() for witness in witnesses],
            "evidence": evidence,
            "placeholders": {
                "chunk_sizes": [1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64],
                "classification": "O-08 exploration-only; not production maxima",
            },
            "non_claims": [
                "not a proof of SHA-256 collision or second-preimage resistance",
                "not a production availability or rollback guarantee",
                "not genesis-authored credential evidence; O-07 remains open",
                "not an authorization oracle replacing ratified C0.2j evidence",
            ],
            "failed_witnesses": failed,
            "verdict": "NO_COUNTEREXAMPLE_WITHIN_BOUNDS" if not failed else "COUNTEREXAMPLE",
        }
        write_report(args.output, report)
    except (ProbeError, ModelError, OSError, ValueError) as error:
        print(f"combined falsification failure: {error}", file=sys.stderr)
        return 2
    print(f"O-06c combined verdict={report['verdict']} witnesses={len(witnesses)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
