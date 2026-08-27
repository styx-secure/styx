"""Small executable guards for O-06c's pinned, non-oracular policy edges."""

from __future__ import annotations

from dataclasses import dataclass


C03_DEPENDENCIES = frozenset(
    {"C0.3_CORPUS_PATH_APPROVAL", "O-06c", "O-07", "O-08", "O-10", "O-14"}
)
C03_BLOCKED_CAPABILITIES = frozenset(
    {"implementation_alignment", "demo", "product", "sensitive_use"}
)


def reject_any_must0_bypass(bypass_observed: tuple[bool, bool]) -> bool:
    """Accept the pinned handoff only when neither K-06 direction bypasses Must0.

    The booleans are explicitly pinned inputs from C0.2j, not a second
    authorization oracle.  O-06c exercises this fail-closed guard and records
    that it did not rederive the inputs.
    """

    return len(bypass_observed) == 2 and not any(bypass_observed)


def retain_k_evidence(evidence: tuple[str, ...], *, ap_pending: bool) -> tuple[str, ...]:
    """AP pending/inapplicable state never filters K-admitted evidence."""

    del ap_pending
    return evidence


def lineage_scoped_quarantine(
    authority: frozenset[str], forked_lineage: frozenset[str]
) -> frozenset[str]:
    """Quarantine can remove one lineage but cannot add or clear unrelated authority."""

    return authority - forked_lineage


def c03_blocked_capabilities(
    status: str,
    dependencies: frozenset[str],
    declared_blocks: frozenset[str],
) -> frozenset[str]:
    """Validate and return the actual fail-closed C0.3 capability set."""

    if (
        status != "NO_GO"
        or dependencies != C03_DEPENDENCIES
        or declared_blocks != C03_BLOCKED_CAPABILITIES
    ):
        return frozenset()
    return declared_blocks


@dataclass(frozen=True)
class RemovalTarget:
    """One fixed ambient AP record used only by the O-06c §11.1 probe."""

    reference: bytes
    content_class: str
    descriptor: tuple[object, ...]
    commitment: bytes | None
    retained: bool
    verified: bool
    binding_status: str
    presentation: str
    parents: tuple[bytes, ...] = ()


@dataclass(frozen=True)
class RemovalProjection:
    """Bounded full AP projection for one removal-directive evaluation."""

    classification: str
    removal_effect: str
    target_validity: str
    target_reference: bytes
    target_descriptor: tuple[object, ...] | None
    target_binding_status: str
    target_retention: str
    target_presentation: str
    graph_causality: tuple[tuple[bytes, tuple[bytes, ...]], ...]
    ambient_projection: tuple[tuple[object, ...], ...]


def project_removal_directive(
    ambient: tuple[RemovalTarget, ...],
    *,
    target_reference: bytes,
    target_commitment: bytes,
) -> RemovalProjection:
    """Evaluate the bounded O-04 removal cases required by O-06c §11.1.

    The function intentionally models no authorization, priority, time,
    finality or irreversible effect.  It exists only to falsify the exact
    octet-variance property against a fixed already-validated ambient set.
    """

    matches = [record for record in ambient if record.reference == target_reference]
    if len(matches) > 1:
        raise ValueError("ambient target references must be unique")
    target = matches[0] if matches else None

    if target is None:
        classification = "REMOVAL_INAPPLICABLE"
        effect = "NONE"
        validity = "ABSENT"
        descriptor = None
        binding = "UNOBSERVED"
        retention = "NOT_RETAINED"
        presentation = "ABSENT"
    else:
        validity = "VALIDATED"
        descriptor = target.descriptor
        binding = target.binding_status
        retention = "RETAINED" if target.retained else "NOT_RETAINED"
        presentation = target.presentation
        if target.content_class in {"NONE", "REQUIRED"}:
            classification = "REMOVAL_INAPPLICABLE"
            effect = "NONE"
        elif target.content_class != "DETACHABLE":
            raise ValueError("unknown ambient content class")
        elif not target.retained:
            classification = "REMOVAL_DEFERRED"
            effect = "NONE"
        elif target.commitment != target_commitment:
            classification = "REMOVAL_INAPPLICABLE"
            effect = "NONE"
        else:
            classification = "REMOVAL_APPLIED"
            effect = "LOGICAL_DETACH"
            presentation = "REMOVED"

    graph = tuple(sorted((record.reference, record.parents) for record in ambient))
    projected = []
    for record in sorted(ambient, key=lambda item: item.reference):
        record_presentation = record.presentation
        if effect == "LOGICAL_DETACH" and record.reference == target_reference:
            record_presentation = "REMOVED"
        projected.append(
            (
                record.reference,
                record.content_class,
                record.descriptor,
                record.retained,
                record.verified,
                record.binding_status,
                record_presentation,
                record.parents,
            )
        )
    return RemovalProjection(
        classification=classification,
        removal_effect=effect,
        target_validity=validity,
        target_reference=target_reference,
        target_descriptor=descriptor,
        target_binding_status=binding,
        target_retention=retention,
        target_presentation=presentation,
        graph_causality=graph,
        ambient_projection=tuple(projected),
    )


def detects_collapsed_removal_identity(
    event_reference_a: bytes,
    event_reference_b: bytes,
    nonconforming_key_a: tuple[object, ...],
    nonconforming_key_b: tuple[object, ...],
) -> bool:
    """Detect an implementation that deduplicates distinct tail variants."""

    return (
        event_reference_a != event_reference_b
        and nonconforming_key_a == nonconforming_key_b
    )
