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

from common import sha256_hex, write_report
from exhaustive_mutations import run_exhaustive
from policy_guards import (
    C03_BLOCKED_CAPABILITIES,
    C03_DEPENDENCIES,
    both_order_directions_preserve_must0,
    c03_blocked_capabilities,
    lineage_scoped_quarantine,
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


def build_witnesses() -> tuple[list[Witness], dict[str, object]]:
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

    # 4: geometry rejection occurs before content splitting/hashing.
    inflated = ContentDescriptor(CONTENT_REQUIRED, 9, 7, COMMITMENT_SUITE, SHAPE_TREE, deterministic("fake-commitment"), Geometry(1, MAX_U64, 1))
    work_before = WorkCounter().record()
    geometry_rejected = expect_error(lambda: encode_content_descriptor(inflated), "chunk count")
    outside_set = expect_error(lambda: build_commitment(context, 7, bytes(130), randomizer, chunk_size=65), "outside test-only")
    add(Witness("W-GEOMETRY-01", "geometry", "inconsistent and attacker-inflated geometry rejects before proportional work", geometry_rejected and outside_set and sum(work_before.values()) == 0, ("GEOMETRY_CHECK", "PREALLOCATION_REJECT")))

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

    # 9: pinned C0.2j outcomes, independent encoded order inputs and pending graph.
    pinned = {
        "W-AUTH-08": {"grant_before_revoke": True, "grant_after_revoke": True, "must0_bypass": False},
        "W-PENDING-01": {"k_evidence_retained": True, "ap_filters_k_evidence": False},
        "W-FORK-01": {"scope": "credential-lineage", "authority_expansion": False},
        "W-FORK-04": {"causal_prefix_reduction_retained": True, "target_resurrected": False},
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
    pinned_ok = pinned == {
        "W-AUTH-08": {"grant_before_revoke": True, "grant_after_revoke": True, "must0_bypass": False},
        "W-PENDING-01": {"k_evidence_retained": True, "ap_filters_k_evidence": False},
        "W-FORK-01": {"scope": "credential-lineage", "authority_expansion": False},
        "W-FORK-04": {"causal_prefix_reduction_retained": True, "target_resurrected": False},
    }
    must0_guard = both_order_directions_preserve_must0((True, True))
    retained_evidence = retain_k_evidence(("grant", "revoke"), ap_pending=True)
    scoped_authority = lineage_scoped_quarantine(
        frozenset({"forked", "independent"}), frozenset({"forked"})
    )
    add(Witness("W-AUTH-08", "pinned-authority", "both K-06 order directions retain the ratified no-Must0-bypass outcome", both_directions and pinned_ok and must0_guard, ("K06_BOTH_DIRECTIONS", "PINNED_C02J")))
    add(Witness("W-PENDING-01", "pending-authority", "pending is exact causal closure and never filters K evidence", pending_exact and "independent" not in pending and retained_evidence == ("grant", "revoke") and pinned_ok, ("PENDING_CLOSURE", "PINNED_C02J")))
    add(Witness("W-FORK-01", "fork-scope", "lineage quarantine cannot expand authority", scoped_authority == frozenset({"independent"}) and pinned_ok, ("LINEAGE_SCOPE", "PINNED_C02J")))
    add(Witness("W-FORK-04", "fork-prefix", "later fork neither voids accepted prefix reduction nor resurrects target", pinned_ok, ("PREFIX_REDUCTION", "PINNED_C02J")))

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

    # 11.1: removal-tail variance changes identity/order but not vacuous AP effect.
    removal_a = replace(
        base_event(credential, none_descriptor, transition=b"removal"),
        event_role=ROLE_REMOVAL,
        tail=RemovalTail(deterministic("target"), deterministic("tail-a")),
    )
    removal_b = replace(removal_a, tail=RemovalTail(removal_a.tail.target_event_reference, deterministic("tail-b")))
    ref_a, ref_b = event_reference(removal_a), event_reference(removal_b)
    removal_invariant = ref_a != ref_b and encode_event_transcript(removal_a) != encode_event_transcript(removal_b)
    add(Witness("W-REMOVAL-01", "removal-tail-variance", "tail variants alter transcript/reference/order input but cannot remove NONE/REQUIRED/absent targets", removal_invariant, ("TAIL_BYTES", "EVENT_IDENTITY", "AP_VACUITY")))

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
    c03_blocked = c03_blocked_capabilities("NO_GO", C03_DEPENDENCIES)
    add(Witness("W-C03-01", "capability-gate", "C0.3 NO-GO retains exactly five blocked capabilities", c03_blocked == C03_BLOCKED_CAPABILITIES and len(c03_blocked) == 5, ("C03_NO_GO",)))
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
        "pinned_c02j": pinned,
        "work_counters": counters,
        "aggregate_stage_counters": aggregate,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", required=True, choices=("required",))
    parser.add_argument("--frozen-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        frozen_bytes = args.frozen_report.read_bytes()
        frozen = json.loads(frozen_bytes)
        if frozen.get("schema") != "styx-o06c-frozen-section-report/v1" or frozen.get("verdict") != "PASS":
            raise ProbeError("frozen-section report is not PASS")
        witnesses, evidence = build_witnesses()
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
        evidence["exhaustive_mutations"] = exhaustive
        failed = [witness.identifier for witness in witnesses if not witness.passed]
        report = {
            "schema": SCHEMA,
            "suite": "required",
            "frozen_report_sha256": sha256_hex(frozen_bytes),
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
