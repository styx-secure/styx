"""Deterministic local ceremony boundary used only by O-07 evidence tests."""

from __future__ import annotations

from dataclasses import dataclass

from genesis_model import (
    AcceptanceDomain,
    ContextTuple,
    GenesisError,
    VerifiedCeremonyCapability,
    _TestBoundaryController,
    _new_test_acceptance_domain,
    _new_test_foreign_boundary_controller,
)


@dataclass(frozen=True)
class TestCeremonyHarness:
    domain: AcceptanceDomain
    _controller: _TestBoundaryController

    def issue_affirmative(
        self, context: ContextTuple, expected_genesis_reference: bytes
    ) -> VerifiedCeremonyCapability:
        return self._controller.issue_affirmative(context, expected_genesis_reference)

    def deny(self) -> None:
        return None

    def reject_malformed(self) -> None:
        raise GenesisError("MALFORMED_CEREMONY_ASSERTION")

    def reject_untrusted_issuer(self) -> None:
        raise GenesisError("UNTRUSTED_CEREMONY_ISSUER")

    def issue_from_foreign_boundary(
        self, context: ContextTuple, expected_genesis_reference: bytes
    ) -> VerifiedCeremonyCapability:
        controller = _new_test_foreign_boundary_controller(
            self.domain, context, expected_genesis_reference
        )
        return controller.issue_affirmative(context, expected_genesis_reference)


def new_test_ceremony_harness(
    expected_context: ContextTuple, expected_genesis_reference: bytes
) -> TestCeremonyHarness:
    domain, controller = _new_test_acceptance_domain(
        expected_context, expected_genesis_reference
    )
    return TestCeremonyHarness(domain, controller)
