#!/usr/bin/env python3
"""Emit deterministic hostile evidence for the selected O-07 construction."""

from __future__ import annotations

import argparse
from dataclasses import replace
from pathlib import Path
import sys

sys.dont_write_bytecode = True

O07_ROOT = Path(__file__).resolve().parent
SIMULATOR_ROOT = O07_ROOT.parent
for entry in (O07_ROOT, SIMULATOR_ROOT):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from genesis_model import (
    CeremonyRecord,
    ContextTuple,
    GenesisBody,
    GenesisError,
    SIGNATURE_SUITE,
    accept_genesis,
    derive_genesis_reference,
    evaluate_checkpoint_boundary,
    make_candidate,
    reject_grant_identifier_collision,
    require_descendant_binding,
    sign_from_seed,
)
from o14.evidence_io import CanonicalJsonReport, public_failure


SCHEMA = "styx-o07-genesis-checkpoint-probe/v1"
PROFILE_REGISTRY = frozenset({0x10203040})
RUNTIME_BODY_LIMIT = 4096
SEED_A = bytes(range(32))
SEED_B = bytes(reversed(range(32)))


def _fixture():
    key, _ = sign_from_seed(SEED_A, b"")
    context = ContextTuple(1, 0x10203040, 7, bytes.fromhex("42" * 32))
    body = GenesisBody(context, SIGNATURE_SUITE, key, b"initial-authority-v1")
    candidate = make_candidate(body, SEED_A, allowed_profiles=PROFILE_REGISTRY)
    reference = derive_genesis_reference(candidate.transcript)
    ceremony = CeremonyRecord(context, reference, True, True)
    return body, candidate, ceremony


def _capture(identifier: str, expected: str, operation) -> dict[str, object]:
    try:
        observed = str(operation())
    except GenesisError as error:
        observed = error.code
    return {
        "id": identifier,
        "expected": expected,
        "observed": observed,
        "passed": observed == expected,
    }


def build_report() -> tuple[dict[str, object], bool]:
    body, candidate, ceremony = _fixture()
    accepted = accept_genesis(
        None,
        candidate,
        ceremony,
        allowed_profiles=PROFILE_REGISTRY,
        runtime_body_limit=RUNTIME_BODY_LIMIT,
    ).state
    assert accepted is not None
    changed_signature = bytearray(candidate.signature)
    changed_signature[0] ^= 1
    other_key, _ = sign_from_seed(SEED_B, b"")
    other_body = replace(body, root_verification_key=other_key, initial_authority_policy=b"other")
    other_candidate = make_candidate(other_body, SEED_B, allowed_profiles=PROFILE_REGISTRY)
    other_ceremony = replace(
        ceremony,
        expected_genesis_reference=derive_genesis_reference(other_candidate.transcript),
    )
    dependency = bytes.fromhex("a0" * 32)

    cases = [
        _capture(
            "accept-authenticated-genesis",
            "GENESIS_ACCEPTED",
            lambda: accept_genesis(None, candidate, ceremony, allowed_profiles=PROFILE_REGISTRY, runtime_body_limit=RUNTIME_BODY_LIMIT).disposition,
        ),
        _capture(
            "duplicate-is-idempotent",
            "GENESIS_DUPLICATE_IDEMPOTENT",
            lambda: accept_genesis(accepted, candidate, ceremony, allowed_profiles=PROFILE_REGISTRY, runtime_body_limit=RUNTIME_BODY_LIMIT).disposition,
        ),
        _capture("missing-ceremony", "AUTHENTICATED_CEREMONY_REQUIRED", lambda: accept_genesis(None, candidate, None, allowed_profiles=PROFILE_REGISTRY, runtime_body_limit=RUNTIME_BODY_LIMIT)),
        _capture("unauthenticated-provenance", "AUTHENTICATED_CEREMONY_REQUIRED", lambda: accept_genesis(None, candidate, replace(ceremony, authenticated_provenance=False), allowed_profiles=PROFILE_REGISTRY, runtime_body_limit=RUNTIME_BODY_LIMIT)),
        _capture("authorization-denied", "ROOT_AUTHORIZATION_REJECTED", lambda: accept_genesis(None, candidate, replace(ceremony, explicit_authorization_decision=False), allowed_profiles=PROFILE_REGISTRY, runtime_body_limit=RUNTIME_BODY_LIMIT)),
        _capture("reference-substitution", "GENESIS_REFERENCE_MISMATCH", lambda: accept_genesis(None, candidate, replace(ceremony, expected_genesis_reference=bytes(32)), allowed_profiles=PROFILE_REGISTRY, runtime_body_limit=RUNTIME_BODY_LIMIT)),
        _capture("context-substitution", "GENESIS_CONTEXT_TUPLE_MISMATCH", lambda: accept_genesis(None, candidate, replace(ceremony, context=replace(ceremony.context, context_identifier=bytes.fromhex("43" * 32))), allowed_profiles=PROFILE_REGISTRY, runtime_body_limit=RUNTIME_BODY_LIMIT)),
        _capture("signature-substitution", "GENESIS_SIGNATURE_INVALID", lambda: accept_genesis(None, replace(candidate, signature=bytes(changed_signature)), ceremony, allowed_profiles=PROFILE_REGISTRY, runtime_body_limit=RUNTIME_BODY_LIMIT)),
        _capture("wrong-domain", "GENESIS_DOMAIN_REJECTED", lambda: accept_genesis(None, replace(candidate, transcript=b"\x00\x03" + candidate.transcript[2:]), ceremony, allowed_profiles=PROFILE_REGISTRY, runtime_body_limit=RUNTIME_BODY_LIMIT)),
        _capture("truncated-transcript", "GENESIS_BODY_LENGTH_MISMATCH", lambda: accept_genesis(None, replace(candidate, transcript=candidate.transcript[:-1]), ceremony, allowed_profiles=PROFILE_REGISTRY, runtime_body_limit=RUNTIME_BODY_LIMIT)),
        _capture("trailing-transcript", "GENESIS_BODY_LENGTH_MISMATCH", lambda: accept_genesis(None, replace(candidate, transcript=candidate.transcript + b"\x00"), ceremony, allowed_profiles=PROFILE_REGISTRY, runtime_body_limit=RUNTIME_BODY_LIMIT)),
        _capture("distinct-same-context", "DISTINCT_SAME_CONTEXT_GENESIS", lambda: accept_genesis(accepted, other_candidate, other_ceremony, allowed_profiles=PROFILE_REGISTRY, runtime_body_limit=RUNTIME_BODY_LIMIT)),
        _capture("matching-descendant", "DESCENDANT_ACCEPTED", lambda: (require_descendant_binding(accepted, accepted.genesis_reference), "DESCENDANT_ACCEPTED")[1]),
        _capture("foreign-descendant", "DESCENDANT_GENESIS_REFERENCE_MISMATCH", lambda: require_descendant_binding(accepted, other_ceremony.expected_genesis_reference)),
        _capture("grant-reference-collision", "GRANT_REFERENCE_EQUALS_GENESIS_CREDENTIAL", lambda: reject_grant_identifier_collision(accepted.genesis_reference, accepted.genesis_reference)),
        _capture("distinct-grant-reference", "GRANT_BINDING_ALLOWED", lambda: (reject_grant_identifier_collision(accepted.genesis_reference, bytes.fromhex("99" * 32)), "GRANT_BINDING_ALLOWED")[1]),
        _capture("ordinary-live-replay", "LIVE_REPLAY_REQUIRED", lambda: evaluate_checkpoint_boundary(checkpoint_evidence_refs=frozenset(), replay_dependency_refs=frozenset({dependency}))),
        _capture("checkpoint-smuggling", "CHECKPOINT_EVIDENCE_UNSUPPORTED_V0", lambda: evaluate_checkpoint_boundary(checkpoint_evidence_refs=frozenset({dependency}), replay_dependency_refs=frozenset({dependency}))),
        _capture("vacuous-checkpoint-oracle", "VACUOUS_CHECKPOINT_EVIDENCE", lambda: evaluate_checkpoint_boundary(checkpoint_evidence_refs=frozenset(), replay_dependency_refs=frozenset())),
    ]
    failed = [case["id"] for case in cases if not case["passed"]]
    report = {
        "schema": SCHEMA,
        "construction": {
            "genesis_domain": 2,
            "reference_domain": 4,
            "signature_suite": 1,
            "root_mode": "single-root",
            "checkpoint_grant_side": "UNSUPPORTED",
            "checkpoint_suppress_side": "UNREACHABLE",
        },
        "case_count": len(cases),
        "cases": cases,
        "failed": failed,
        "verdict": "PASS" if not failed else "FAIL",
    }
    return report, not failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--suite", required=True, choices=("required",))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report, passed = build_report()
        CanonicalJsonReport.store(args.output, report)
    except (OSError, KeyError, ValueError) as error:
        print(f"O-07 probe failed: {public_failure(error)}", file=sys.stderr)
        return 2
    print(f"O-07 PROBE verdict={report['verdict']} cases={report['case_count']}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
