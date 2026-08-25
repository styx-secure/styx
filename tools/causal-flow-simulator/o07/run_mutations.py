#!/usr/bin/env python3
"""Kill exact source mutations for every selected O-07 security rule."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
from pathlib import Path
import sys
import types

sys.dont_write_bytecode = True

O07_ROOT = Path(__file__).resolve().parent
SIMULATOR_ROOT = O07_ROOT.parent
for entry in (O07_ROOT, SIMULATOR_ROOT):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from o14.evidence_io import CanonicalJsonReport, public_failure


SCHEMA = "styx-o07-source-mutations/v1"


@dataclass(frozen=True)
class SourceMutation:
    identifier: str
    original: str
    replacement: str
    detector: str


MUTATIONS = (
    SourceMutation("M_WRONG_GENESIS_DOMAIN", "D_GENESIS_REF = 0x0004", "D_GENESIS_REF = 0x0003", "reference-domain-separated"),
    SourceMutation("M_ACCEPT_UNAUTHENTICATED_R", "if ceremony is None or not ceremony.authenticated_provenance:", "if ceremony is None:", "authenticated-provenance-required"),
    SourceMutation("M_ACCEPT_DENIED_R", "if not ceremony.explicit_authorization_decision:", "if False and not ceremony.explicit_authorization_decision:", "explicit-decision-required"),
    SourceMutation("M_SKIP_REFERENCE_MATCH", "if reference != ceremony.expected_genesis_reference:", "if False and reference != ceremony.expected_genesis_reference:", "reference-must-match"),
    SourceMutation("M_SKIP_CONTEXT_MATCH", "if body.context != ceremony.context:", "if False and body.context != ceremony.context:", "tuple-must-match"),
    SourceMutation("M_SKIP_SIGNATURE_VERIFY", "if not selected_verify(candidate.signature, candidate.transcript, body.root_verification_key):", "if False and not selected_verify(candidate.signature, candidate.transcript, body.root_verification_key):", "signature-must-verify"),
    SourceMutation("M_ALLOW_SECOND_GENESIS", "raise GenesisError(\"DISTINCT_SAME_CONTEXT_GENESIS\")", "return AcceptanceResult(current, \"GENESIS_REPLACED\", True)", "second-genesis-rejected"),
    SourceMutation("M_SKIP_DESCENDANT_BINDING", "if genesis_reference != state.genesis_reference:", "if False and genesis_reference != state.genesis_reference:", "descendant-binding-required"),
    SourceMutation("M_ALLOW_GRANT_COLLISION", "if computed_grant_reference == accepted_genesis_reference:", "if False and computed_grant_reference == accepted_genesis_reference:", "grant-collision-rejected"),
    SourceMutation("M_ALLOW_CHECKPOINT_SMUGGLING", "if checkpoint_evidence_refs:", "if False and checkpoint_evidence_refs:", "checkpoint-input-unreachable"),
    SourceMutation("M_ALLOW_VACUOUS_CHECKPOINT", "if not replay_dependency_refs:", "if False and not replay_dependency_refs:", "non-vacuous-replay-dependencies"),
)


def _load_mutant(source: str, identifier: str, source_path: Path):
    module = types.ModuleType(f"o07_mutant_{identifier}")
    module.__file__ = str(source_path)
    sys.modules[module.__name__] = module
    exec(compile(source, str(source_path), "exec"), module.__dict__)
    return module


def _fixture(module):
    seed_a = bytes(range(32))
    key, _ = module.sign_from_seed(seed_a, b"")
    context = module.ContextTuple(1, 0x10203040, 7, bytes.fromhex("42" * 32))
    body = module.GenesisBody(context, module.SIGNATURE_SUITE, key, b"initial-authority-v1")
    profiles = frozenset({0x10203040})
    candidate = module.make_candidate(body, seed_a, allowed_profiles=profiles)
    ceremony = module.CeremonyRecord(context, module.derive_genesis_reference(candidate.transcript), True, True)
    accepted = module.accept_genesis(None, candidate, ceremony, allowed_profiles=profiles, runtime_body_limit=4096).state
    return seed_a, body, candidate, ceremony, accepted, profiles


def _raises(module, code: str, operation) -> bool:
    try:
        operation()
    except module.GenesisError as error:
        return error.code == code
    return False


def _detector_passes(module, mutation: SourceMutation) -> bool:
    seed_a, body, candidate, ceremony, accepted, profiles = _fixture(module)
    if mutation.identifier == "M_WRONG_GENESIS_DOMAIN":
        return module.derive_genesis_reference(candidate.transcript).hex() == "5c6841c29fde85a0492a1694dac09c328cd03b4b43365b8ca897a64e7f041c80"
    if mutation.identifier == "M_ACCEPT_UNAUTHENTICATED_R":
        return _raises(module, "AUTHENTICATED_CEREMONY_REQUIRED", lambda: module.accept_genesis(None, candidate, replace(ceremony, authenticated_provenance=False), allowed_profiles=profiles, runtime_body_limit=4096))
    if mutation.identifier == "M_ACCEPT_DENIED_R":
        return _raises(module, "ROOT_AUTHORIZATION_REJECTED", lambda: module.accept_genesis(None, candidate, replace(ceremony, explicit_authorization_decision=False), allowed_profiles=profiles, runtime_body_limit=4096))
    if mutation.identifier == "M_SKIP_REFERENCE_MATCH":
        return _raises(module, "GENESIS_REFERENCE_MISMATCH", lambda: module.accept_genesis(None, candidate, replace(ceremony, expected_genesis_reference=bytes(32)), allowed_profiles=profiles, runtime_body_limit=4096))
    if mutation.identifier == "M_SKIP_CONTEXT_MATCH":
        wrong = replace(ceremony, context=replace(ceremony.context, context_identifier=bytes.fromhex("43" * 32)))
        return _raises(module, "GENESIS_CONTEXT_TUPLE_MISMATCH", lambda: module.accept_genesis(None, candidate, wrong, allowed_profiles=profiles, runtime_body_limit=4096))
    if mutation.identifier == "M_SKIP_SIGNATURE_VERIFY":
        signature = bytearray(candidate.signature); signature[0] ^= 1
        return _raises(module, "GENESIS_SIGNATURE_INVALID", lambda: module.accept_genesis(None, replace(candidate, signature=bytes(signature)), ceremony, allowed_profiles=profiles, runtime_body_limit=4096))
    if mutation.identifier == "M_ALLOW_SECOND_GENESIS":
        seed_b = bytes(reversed(range(32))); key_b, _ = module.sign_from_seed(seed_b, b"")
        body_b = replace(body, root_verification_key=key_b, initial_authority_policy=b"other")
        candidate_b = module.make_candidate(body_b, seed_b, allowed_profiles=profiles)
        ceremony_b = replace(ceremony, expected_genesis_reference=module.derive_genesis_reference(candidate_b.transcript))
        return _raises(module, "DISTINCT_SAME_CONTEXT_GENESIS", lambda: module.accept_genesis(accepted, candidate_b, ceremony_b, allowed_profiles=profiles, runtime_body_limit=4096))
    if mutation.identifier == "M_SKIP_DESCENDANT_BINDING":
        return _raises(module, "DESCENDANT_GENESIS_REFERENCE_MISMATCH", lambda: module.require_descendant_binding(accepted, bytes(32)))
    if mutation.identifier == "M_ALLOW_GRANT_COLLISION":
        return _raises(module, "GRANT_REFERENCE_EQUALS_GENESIS_CREDENTIAL", lambda: module.reject_grant_identifier_collision(accepted.genesis_reference, accepted.genesis_reference))
    if mutation.identifier == "M_ALLOW_CHECKPOINT_SMUGGLING":
        ref = bytes.fromhex("a0" * 32)
        return _raises(module, "CHECKPOINT_EVIDENCE_UNSUPPORTED_V0", lambda: module.evaluate_checkpoint_boundary(checkpoint_evidence_refs=frozenset({ref}), replay_dependency_refs=frozenset({ref})))
    if mutation.identifier == "M_ALLOW_VACUOUS_CHECKPOINT":
        return _raises(module, "VACUOUS_CHECKPOINT_EVIDENCE", lambda: module.evaluate_checkpoint_boundary(checkpoint_evidence_refs=frozenset(), replay_dependency_refs=frozenset()))
    raise ValueError("unknown mutation")


def build_report(repo_root: Path) -> tuple[dict[str, object], bool]:
    source_path = repo_root / "tools/causal-flow-simulator/o07/genesis_model.py"
    original_source = source_path.read_text(encoding="utf-8")
    results = []
    for mutation in MUTATIONS:
        if original_source.count(mutation.original) != 1:
            raise ValueError(f"mutation anchor drift: {mutation.identifier}")
        mutant_source = original_source.replace(mutation.original, mutation.replacement, 1)
        module = _load_mutant(mutant_source, mutation.identifier, source_path)
        detector_survived = _detector_passes(module, mutation)
        results.append({
            "id": mutation.identifier,
            "detector": mutation.detector,
            "mutated_anchor_count": 1,
            "killed": not detector_survived,
        })
    survivors = [item["id"] for item in results if not item["killed"]]
    report = {
        "schema": SCHEMA,
        "required_mutant_count": len(MUTATIONS),
        "results": results,
        "survived": survivors,
        "verdict": "ALL_REQUIRED_MUTANTS_KILLED" if not survivors else "MUTANT_SURVIVED",
    }
    return report, not survivors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--suite", required=True, choices=("required",))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report, passed = build_report(args.repo_root.resolve())
        CanonicalJsonReport.store(args.output, report)
    except (OSError, KeyError, ValueError) as error:
        print(f"O-07 mutations failed: {public_failure(error)}", file=sys.stderr)
        return 2
    print(f"O-07 MUTANTS verdict={report['verdict']} count={report['required_mutant_count']}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
