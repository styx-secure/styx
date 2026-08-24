"""Small executable guards for O-06c's pinned, non-oracular policy edges."""

from __future__ import annotations


C03_DEPENDENCIES = frozenset(
    {"C0.3_CORPUS_PATH_APPROVAL", "O-06c", "O-07", "O-08", "O-10", "O-14"}
)
C03_BLOCKED_CAPABILITIES = frozenset(
    {"corpus", "implementation_alignment", "demo", "product", "sensitive_use"}
)


def both_order_directions_preserve_must0(results: tuple[bool, bool]) -> bool:
    """True only when both pinned K-06 directions reject the bypass."""

    return len(results) == 2 and all(results)


def retain_k_evidence(evidence: tuple[str, ...], *, ap_pending: bool) -> tuple[str, ...]:
    """AP pending/inapplicable state never filters K-admitted evidence."""

    del ap_pending
    return evidence


def lineage_scoped_quarantine(
    authority: frozenset[str], forked_lineage: frozenset[str]
) -> frozenset[str]:
    """Quarantine can remove one lineage but cannot add or clear unrelated authority."""

    return authority - forked_lineage


def c03_blocked_capabilities(status: str, dependencies: frozenset[str]) -> frozenset[str]:
    """Return the exact fail-closed capability set for the C0.3 gate."""

    if status != "NO_GO" or dependencies != C03_DEPENDENCIES:
        return frozenset()
    return C03_BLOCKED_CAPABILITIES
