"""Isolated detector harness for source-mutated O-07 evidence modules."""

from __future__ import annotations

import genesis_model as baseline_model


def _fixture(module):
    seed = bytes(range(32))
    key, _ = module.sign_from_seed(seed, b"")
    context = module.ContextTuple(1, 0x10203040, 7, bytes.fromhex("42" * 32))
    body = module.GenesisBody(
        context, module.SIGNATURE_SUITE, key, b"initial-authority-v1"
    )
    profiles = frozenset({(0x10203040, 7)})
    candidate = module.make_candidate(body, seed, allowed_profiles=profiles)
    reference = module.derive_genesis_reference(candidate.transcript)
    domain, controller = module._new_test_acceptance_domain(context, reference)
    capability = controller.issue_affirmative(context, reference)
    accepted = module.accept_genesis(
        domain,
        None,
        candidate,
        capability,
        allowed_profiles=profiles,
        runtime_body_limit=4096,
    ).state
    assert accepted is not None
    return context, candidate, reference, domain, accepted, profiles


def _rejects(module, operation) -> bool:
    try:
        operation()
    except module.GenesisError:
        return True
    return False


def mutant_still_passes(module, family: str) -> bool:
    """Return true only when the selected source mutant evades its detector."""

    if family == "ORD":
        try:
            result = module.evaluate_semantic_scenario("A-ORD-003")
        except baseline_model.GenesisError:
            return False
        return result["disposition"] == "ORDER_INDEPENDENT"

    context, candidate, reference, domain, accepted, profiles = _fixture(module)
    if family == "FRM":
        changed = bytearray(candidate.transcript)
        changed[8:12] = (0x1020303F).to_bytes(4, "big")
        return _rejects(
            module,
            lambda: module.parse_transcript(
                bytes(changed),
                allowed_profiles=profiles,
                runtime_body_limit=4096,
            ),
        )
    if family == "DOM":
        return module.derive_genesis_reference(
            candidate.transcript
        ) == baseline_model.derive_genesis_reference(candidate.transcript)
    if family == "CER":
        foreign_domain, foreign_controller = module._new_test_acceptance_domain(
            context, reference
        )
        del foreign_domain
        foreign_capability = foreign_controller.issue_affirmative(context, reference)
        return _rejects(
            module,
            lambda: module.accept_genesis(
                domain,
                None,
                candidate,
                foreign_capability,
                allowed_profiles=profiles,
                runtime_body_limit=4096,
            ),
        )
    if family == "GAT":
        return _rejects(module, lambda: module.reject_gate_substitution("P", "C"))
    if family == "LIN":
        projection = module.terminate_root_lineage(
            module.new_lineage_projection(accepted), event_kind="REVOKE"
        )
        return _rejects(
            module,
            lambda: module.admit_lineage_descendant(
                projection,
                field16_reference=reference,
                causally_descends=True,
            ),
        )
    if family == "CHK":
        witness = bytes.fromhex("a0" * 32)
        return _rejects(
            module,
            lambda: module.evaluate_checkpoint_boundary(
                checkpoint_evidence_refs=frozenset({witness}),
                replay_dependency_refs=frozenset({witness}),
            ),
        )
    raise ValueError("unknown mutation family")
