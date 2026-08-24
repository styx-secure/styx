#!/usr/bin/env python3
"""Fail-closed validator for the derived Styx protocol review model."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True


EXPECTED_REGISTRIES = {
    "confidentiality": [
        "LOCAL_RUNTIME_PROFILE",
        "NONE",
        "PROFILE_DEPENDENT",
        "SECURE_SESSION_PROFILE",
        "UNRESOLVED",
    ],
    "integrity": [
        "COMMITMENT",
        "DIGEST_DERIVED",
        "NONE",
        "PROFILE_DEPENDENT",
        "SESSION_AUTHENTICATED",
        "SIGNED_TRANSCRIPT",
        "UNRESOLVED",
    ],
    "decisions": [
        "O-01",
        "O-02",
        "O-03",
        "O-04",
        "O-05",
        "O-06",
        "O-06a",
        "O-06b-1",
        "O-06b-2",
        "O-06c",
        "O-07",
        "O-08",
        "O-09",
        "O-10",
        "O-11",
        "O-12",
        "O-13",
        "O-14",
        "O-15",
        "O-16",
    ],
    "gated_capabilities": [
        "corpus",
        "demo",
        "destruction_capable_increment",
        "erasure_claim",
        "implementation_alignment",
        "irreversible_effects",
        "product",
        "product_readiness",
        "product_recovery",
        "profile_succession",
        "sensitive_use",
        "time_bearing_profile",
    ],
    "layers": ["AP", "K", "PV", "RS", "SS", "TR"],
    "obligations": [
        *[f"OB-AP{index:02d}" for index in range(1, 11)],
        *[f"OB-K{index:02d}" for index in range(1, 20)],
        *[f"OB-PV{index:02d}" for index in range(1, 12)],
        *[f"OB-RS{index:02d}" for index in range(1, 14)],
        *[f"OB-SS{index:02d}" for index in range(1, 10)],
        *[f"OB-TR{index:02d}" for index in range(1, 11)],
    ],
    "statuses": [
        "DECIDED",
        "DERIVED",
        "EVIDENCE_ONLY",
        "NO_GO",
        "OPEN",
        "PROFILE_DEPENDENT",
        "SYMBOLIC",
        "UNRESOLVED",
    ],
    "trust_classes": [
        "APPLICATION",
        "CRYPTOGRAPHIC",
        "HUMAN",
        "NETWORK",
        "RUNTIME",
        "SESSION",
    ],
    "wire_presence": [
        "DERIVED",
        "NOT_CARRIED",
        "OUT_OF_BAND",
        "PROFILE_DEPENDENT",
        "SIGNED_TRANSCRIPT",
        "SYMBOLIC_INPUT",
    ],
}

EXPECTED_SOURCE_RECORDS = {
    "causal_report": (
        "docs/protocol/styx-app-kernel-v0-causal-falsification-report.md",
        "evidence",
    ),
    "causal_topology": (
        "docs/protocol/styx-app-kernel-v0-causal-topology-analysis.md",
        "evidence",
    ),
    "commitment_context_report": (
        "docs/protocol/styx-app-kernel-v0-commitment-context-falsification-report.md",
        "evidence",
    ),
    "commitment_profile": (
        "docs/protocol/styx-app-kernel-v0-commitment-encoding-profile.md",
        "normative",
    ),
    "credential_analysis": (
        "docs/protocol/styx-app-kernel-v0-credential-succession-analysis.md",
        "evidence",
    ),
    "credential_report": (
        "docs/protocol/styx-app-kernel-v0-credential-succession-falsification-report.md",
        "evidence",
    ),
    "decisions": (
        "docs/protocol/styx-app-kernel-v0-decisions.md",
        "normative",
    ),
    "identity_analysis": (
        "docs/protocol/styx-app-kernel-v0-identity-context-analysis.md",
        "evidence",
    ),
    "identifier_analysis": (
        "docs/protocol/styx-app-kernel-v0-identifier-derivation-analysis.md",
        "evidence",
    ),
    "identifier_commitment_report": (
        "docs/protocol/styx-app-kernel-v0-identifier-commitment-falsification-report.md",
        "evidence",
    ),
    "payload_analysis": (
        "docs/protocol/styx-app-kernel-v0-payload-commitment-analysis.md",
        "evidence",
    ),
    "payload_report": (
        "docs/protocol/styx-app-kernel-v0-payload-state-falsification-report.md",
        "evidence",
    ),
    "pending_report": (
        "docs/protocol/styx-app-kernel-v0-pending-subtree-falsification-report.md",
        "evidence",
    ),
    "responsibility": (
        "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md",
        "normative",
    ),
    "threat_model": ("docs/security/STYX-THREAT-MODEL.md", "normative"),
    "transcript_profile": (
        "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md",
        "normative",
    ),
}

REQUIRED_COUNTEREXAMPLES = {
    "CE_ALIAS_SURVIVAL",
    "CE_AUTHORITY_PROJECTION_EXHAUSTION",
    "CE_BOUNDED_CONTESTED_STANDING",
    "CE_CHECKPOINT_STALE",
    "CE_CREDENTIAL_COLLISION",
    "CE_FORK_CONTEXT_QUARANTINE",
    "CE_GRANT_ROOTED_BINDING",
    "CE_GRANT_REVOKE_LAUNDERING_ORDER_A",
    "CE_GRANT_REVOKE_LAUNDERING_ORDER_B",
    "CE_MISSING_REQUIRED_OPENING",
    "CE_MUTUAL_REDUCTION_NO_AUTHORITY",
    "CE_NONCAUSAL_REDUCTION_TARGET",
    "CE_SELF_LINEAGE_REDUCTION",
    "CE_SELECTIVE_REVEAL",
    "CE_SINGLE_AUTHORITY_TAKEOVER",
    "CE_SUBTREE_AMPLIFICATION",
}

REQUIRED_NON_CLAIMS = {
    "NC_AUDIT_READINESS",
    "NC_AVAILABILITY",
    "NC_COMMITMENT_COPY",
    "NC_ERASURE",
    "NC_FINALITY",
    "NC_GENESIS_CHECKPOINT",
    "NC_HIDING_ASSUMPTION",
    "NC_METADATA_ANONYMITY",
    "NC_REVOCATION_COMPROMISE",
    "NC_SUCCESSION_AVAILABILITY",
    "NC_ROLLBACK_DETECTION",
    "NC_SUPPORTED_ADAPTER",
}

REQUIRED_REVIEW_QUERIES = {
    "RQ_AUTHORIZATION",
    "RQ_BLOCKERS",
    "RQ_COUNTEREXAMPLES",
    "RQ_FIELD_PROTECTION",
    "RQ_REPLAY",
    "RQ_SCOPE",
    "RQ_SOURCE_STALENESS",
    "RQ_STATUS_DISCIPLINE",
    "RQ_VISIBILITY",
}

REQUIRED_INVARIANTS = {
    "INV_AUTHORITY_PROJECTION_LIMITS",
    "INV_AUTH_NOT_KEY",
    "INV_BOUNDED_CONTESTED_STANDING",
    "INV_C0_3_NO_GO",
    "INV_CAUSALITY_TRANSCRIPT_ONLY",
    "INV_CAUSAL_TARGET_AVAILABILITY",
    "INV_COMMITMENT_CONTEXT_BINDING",
    "INV_CONTROL_NONE_CLASS",
    "INV_CROSS_CONTEXT_REJECTION",
    "INV_FORK_QUARANTINE",
    "INV_GRANT_ROOTED_BINDING",
    "INV_LINEAGE_CONTAINMENT",
    "INV_NO_CHECKPOINT_SUBSTITUTION",
    "INV_NO_OPENING_SUBSTITUTION",
    "INV_OUTCOME_PRECEDENCE",
    "INV_PENDING_SELECTIVE_PROGRESS",
    "INV_PROTECTION_SEPARATION",
    "INV_REPLAY_NO_AUTHORITY",
    "INV_SELF_LINEAGE_REDUCTION",
    "INV_SET_RELATIVE_REPLAY",
    "INV_SOURCE_AUTHORITY",
    "INV_TWO_SIDED_AUTHORITY",
}

REQUIRED_RESIDUAL_RISKS = {
    "RR_AUTHORITY_PROJECTION_EXHAUSTION",
    "RR_BOUNDED_DESTRUCTIVE_STANDING",
    "RR_CAUSAL_TARGET_AVAILABILITY",
    "RR_CHECKPOINT_STALENESS",
    "RR_FORK_AVAILABILITY",
    "RR_METADATA_EXPOSURE",
    "RR_NO_FINALITY",
    "RR_OPENING_LOSS",
    "RR_ROLLBACK_LIMIT",
    "RR_SAME_KEY_ALIAS",
    "RR_SECURE_ADAPTER_ABSENT",
    "RR_SINGLE_AUTHORITY_TAKEOVER",
    "RR_TOTAL_AUTHORITY_LOSS",
    "RR_UNAUDITED",
}

REQUIRED_C03_DEPENDENCIES = {
    "C0.3_CORPUS_PATH_APPROVAL",
    "O-06c",
    "O-07",
    "O-08",
    "O-10",
    "O-14",
}

CONTRACT_BASE_COMMIT = "3f439189e0cbe4071f642c693dbb196b477a48ea"

EXPECTED_STATUS_BY_COLLECTION = {
    "blockers": {
        "C0.2j": "DECIDED",
        "C0.2k": "DECIDED",
        "C0.3": "NO_GO",
        "C0.3_CORPUS_PATH_APPROVAL": "OPEN",
        "O-06c": "DECIDED",
        "O-07": "OPEN",
        "O-08": "OPEN",
        "O-10": "OPEN",
        "O-12": "OPEN",
        "O-13": "OPEN",
        "O-14": "OPEN",
        "O-15": "OPEN",
        "O-16": "OPEN",
    },
    "counterexamples": {
        "CE_ALIAS_SURVIVAL": "EVIDENCE_ONLY",
        "CE_AUTHORITY_PROJECTION_EXHAUSTION": "EVIDENCE_ONLY",
        "CE_BOUNDED_CONTESTED_STANDING": "EVIDENCE_ONLY",
        "CE_CHECKPOINT_STALE": "EVIDENCE_ONLY",
        "CE_CREDENTIAL_COLLISION": "EVIDENCE_ONLY",
        "CE_FORK_CONTEXT_QUARANTINE": "EVIDENCE_ONLY",
        "CE_GRANT_ROOTED_BINDING": "EVIDENCE_ONLY",
        "CE_GRANT_REVOKE_LAUNDERING_ORDER_A": "EVIDENCE_ONLY",
        "CE_GRANT_REVOKE_LAUNDERING_ORDER_B": "EVIDENCE_ONLY",
        "CE_MISSING_REQUIRED_OPENING": "EVIDENCE_ONLY",
        "CE_MUTUAL_REDUCTION_NO_AUTHORITY": "EVIDENCE_ONLY",
        "CE_NONCAUSAL_REDUCTION_TARGET": "EVIDENCE_ONLY",
        "CE_SELECTIVE_REVEAL": "EVIDENCE_ONLY",
        "CE_SELF_LINEAGE_REDUCTION": "EVIDENCE_ONLY",
        "CE_SINGLE_AUTHORITY_TAKEOVER": "EVIDENCE_ONLY",
        "CE_SUBTREE_AMPLIFICATION": "EVIDENCE_ONLY",
    },
    "flows": {
        "authority_evidence_replay": "DECIDED",
        "author_application_event": "DECIDED",
        "checkpoint_restore": "SYMBOLIC",
        "credential_succession": "DECIDED",
        "fork_quarantine": "DECIDED",
        "logical_removal": "DECIDED",
        "missing_required_opening": "DECIDED",
        "receive_late_opening": "DECIDED",
        "secure_session_receive": "PROFILE_DEPENDENT",
        "secure_session_send": "PROFILE_DEPENDENT",
        "transport_publish": "PROFILE_DEPENDENT",
        "validate_and_fold": "DECIDED",
    },
    "invariants": {
        "INV_AUTHORITY_PROJECTION_LIMITS": "DECIDED",
        "INV_AUTH_NOT_KEY": "DECIDED",
        "INV_BOUNDED_CONTESTED_STANDING": "DECIDED",
        "INV_C0_3_NO_GO": "NO_GO",
        "INV_CAUSALITY_TRANSCRIPT_ONLY": "DECIDED",
        "INV_CAUSAL_TARGET_AVAILABILITY": "DECIDED",
        "INV_COMMITMENT_CONTEXT_BINDING": "DECIDED",
        "INV_CONTROL_NONE_CLASS": "DECIDED",
        "INV_CROSS_CONTEXT_REJECTION": "DECIDED",
        "INV_FORK_QUARANTINE": "DECIDED",
        "INV_GRANT_ROOTED_BINDING": "DECIDED",
        "INV_LINEAGE_CONTAINMENT": "DECIDED",
        "INV_NO_CHECKPOINT_SUBSTITUTION": "DECIDED",
        "INV_NO_OPENING_SUBSTITUTION": "DECIDED",
        "INV_O06C_BOUNDED_EVIDENCE": "EVIDENCE_ONLY",
        "INV_OUTCOME_PRECEDENCE": "DECIDED",
        "INV_PENDING_SELECTIVE_PROGRESS": "DECIDED",
        "INV_PROTECTION_SEPARATION": "DECIDED",
        "INV_REPLAY_NO_AUTHORITY": "DECIDED",
        "INV_SELF_LINEAGE_REDUCTION": "DECIDED",
        "INV_SET_RELATIVE_REPLAY": "DECIDED",
        "INV_SOURCE_AUTHORITY": "DERIVED",
        "INV_TWO_SIDED_AUTHORITY": "DECIDED",
    },
    "objects": {
        "application_event": "DECIDED",
        "checkpoint_evidence": "SYMBOLIC",
        "content_bytes": "DECIDED",
        "content_descriptor": "DECIDED",
        "genesis": "UNRESOLVED",
        "opening": "DECIDED",
    },
    "outcomes": {
        "APPLIED": "EVIDENCE_ONLY",
        "AUTHENTIC_BUT_UNAUTHORIZED": "EVIDENCE_ONLY",
        "AUTHORITY_PROJECTION_UNAVAILABLE": "EVIDENCE_ONLY",
        "COMMITMENT_MISMATCH": "EVIDENCE_ONLY",
        "CREDENTIAL_BINDING_MISMATCH": "EVIDENCE_ONLY",
        "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED": "EVIDENCE_ONLY",
        "DUPLICATE": "EVIDENCE_ONLY",
        "FORK_EVIDENCE": "EVIDENCE_ONLY",
        "FORK_QUARANTINED": "EVIDENCE_ONLY",
        "INVALID": "EVIDENCE_ONLY",
        "LENGTH_MISMATCH": "EVIDENCE_ONLY",
        "LINEAGE_QUARANTINED": "EVIDENCE_ONLY",
        "OPENING_MISSING": "EVIDENCE_ONLY",
        "PENDING_ANCESTOR": "EVIDENCE_ONLY",
        "PENDING_OPENING": "EVIDENCE_ONLY",
        "POST_REVOCATION": "EVIDENCE_ONLY",
        "REFERENCE_COLLISION_UNSUPPORTED": "EVIDENCE_ONLY",
        "REMOVAL_INAPPLICABLE": "EVIDENCE_ONLY",
        "SESSION_PROFILE_REQUIRED": "PROFILE_DEPENDENT",
        "STALE_EVIDENCE": "SYMBOLIC",
        "STRUCTURAL_REJECTION": "EVIDENCE_ONLY",
        "TRANSPORT_PROFILE_REQUIRED": "PROFILE_DEPENDENT",
        "UNRESOLVABLE_CREDENTIAL": "EVIDENCE_ONLY",
        "UNRESOLVED_CREDENTIAL_BINDING": "EVIDENCE_ONLY",
    },
    "residual_risks": {
        "RR_AUTHORITY_PROJECTION_EXHAUSTION": "OPEN",
        "RR_BOUNDED_DESTRUCTIVE_STANDING": "OPEN",
        "RR_CAUSAL_TARGET_AVAILABILITY": "OPEN",
        "RR_CHECKPOINT_STALENESS": "SYMBOLIC",
        "RR_FORK_AVAILABILITY": "OPEN",
        "RR_METADATA_EXPOSURE": "PROFILE_DEPENDENT",
        "RR_NO_FINALITY": "OPEN",
        "RR_OPENING_LOSS": "OPEN",
        "RR_ROLLBACK_LIMIT": "PROFILE_DEPENDENT",
        "RR_SAME_KEY_ALIAS": "OPEN",
        "RR_SECURE_ADAPTER_ABSENT": "PROFILE_DEPENDENT",
        "RR_SINGLE_AUTHORITY_TAKEOVER": "OPEN",
        "RR_TOTAL_AUTHORITY_LOSS": "OPEN",
        "RR_UNAUDITED": "OPEN",
    },
    "state_models": {
        "ap_projection": "DECIDED",
        "k_admission": "DECIDED",
        "pending_replay": "DECIDED",
    },
}

EXPECTED_FIELD_STATUS = {
    ("application_event", "ap_protocol_version"): "DECIDED",
    ("application_event", "ap_transition_block"): "UNRESOLVED",
    ("application_event", "application_profile_id"): "DECIDED",
    ("application_event", "application_profile_version"): "DECIDED",
    ("application_event", "author_sequence"): "DECIDED",
    ("application_event", "causal_parents"): "DECIDED",
    ("application_event", "content_descriptor_ref"): "DECIDED",
    ("application_event", "context_identifier"): "DECIDED",
    ("application_event", "credential_control_kind"): "DECIDED",
    ("application_event", "credential_identifier"): "DECIDED",
    ("application_event", "direct_predecessor_presence"): "DECIDED",
    ("application_event", "direct_predecessor_reference"): "DECIDED",
    ("application_event", "event_reference"): "DECIDED",
    ("application_event", "event_role"): "DECIDED",
    ("application_event", "event_type_identifier"): "UNRESOLVED",
    ("application_event", "genesis_reference"): "UNRESOLVED",
    ("application_event", "grantee_signature_suite_id"): "DECIDED",
    ("application_event", "grantee_verification_key"): "DECIDED",
    ("application_event", "object_kind"): "DECIDED",
    ("application_event", "removal_tail"): "DECIDED",
    ("application_event", "replacement_grant_reference"): "DECIDED",
    ("application_event", "recovery_grant_reference"): "DECIDED",
    ("application_event", "schema_identifier"): "UNRESOLVED",
    ("application_event", "schema_version"): "UNRESOLVED",
    ("application_event", "signature"): "UNRESOLVED",
    ("application_event", "target_credential_identifier"): "DECIDED",
    ("checkpoint_evidence", "checkpoint_evidence_refs"): "SYMBOLIC",
    ("checkpoint_evidence", "replay_dependency_refs"): "SYMBOLIC",
    ("content_bytes", "content_octets"): "DECIDED",
    ("content_descriptor", "content_class"): "DECIDED",
    ("content_descriptor", "content_commitment"): "DECIDED",
    ("content_descriptor", "content_geometry"): "DECIDED",
    ("content_descriptor", "content_length"): "DECIDED",
    ("content_descriptor", "content_shape"): "DECIDED",
    ("content_descriptor", "content_suite_id"): "DECIDED",
    ("content_descriptor", "content_type_id"): "UNRESOLVED",
    ("genesis", "derived_genesis_reference"): "UNRESOLVED",
    ("genesis", "genesis_body"): "UNRESOLVED",
    ("opening", "opening_randomizer"): "DECIDED",
}

EXPECTED_IDS_BY_COLLECTION = {
    "actors": {
        "application_profile",
        "authorized_endpoint",
        "compromised_credential_holder",
        "kernel",
        "product_operator",
        "recipient_endpoint",
        "relay_observer",
        "runtime_profile",
        "secure_session_adapter",
        "transport_profile",
    },
    "blockers": set(EXPECTED_STATUS_BY_COLLECTION["blockers"]),
    "counterexamples": set(EXPECTED_STATUS_BY_COLLECTION["counterexamples"]),
    "flows": set(EXPECTED_STATUS_BY_COLLECTION["flows"]),
    "invariants": set(EXPECTED_STATUS_BY_COLLECTION["invariants"]),
    "layers": set(EXPECTED_REGISTRIES["layers"]),
    "non_claims": set(REQUIRED_NON_CLAIMS),
    "objects": set(EXPECTED_STATUS_BY_COLLECTION["objects"]),
    "outcomes": set(EXPECTED_STATUS_BY_COLLECTION["outcomes"]),
    "residual_risks": set(EXPECTED_STATUS_BY_COLLECTION["residual_risks"]),
    "review_queries": set(REQUIRED_REVIEW_QUERIES),
    "sources": set(EXPECTED_SOURCE_RECORDS),
    "state_models": set(EXPECTED_STATUS_BY_COLLECTION["state_models"]),
}

EXPECTED_TRANSITION_IDS = {
    "ap_projection": {
        "ap_pending_to_active",
        "ap_recover_active",
        "ap_recover_fork_quarantine",
        "ap_recover_pending",
        "ap_to_authority_unavailable",
        "ap_to_partially_pending",
        "ap_to_stale",
        "ap_to_terminal_fork",
    },
    "k_admission": {
        "k_admit_candidate",
        "k_admit_binding_grant",
        "k_reject_invalid",
        "k_reject_unresolved_binding",
        "k_to_collision",
        "k_to_fork",
    },
    "pending_replay": {
        "replay_apply_candidate",
        "replay_to_pending_descendant",
        "replay_to_pending_root",
        "replay_verified_opening",
    },
}

EXPECTED_TRANSITION_STATUS = {
    (state_model_id, transition_id): "DECIDED"
    for state_model_id, transition_ids in EXPECTED_TRANSITION_IDS.items()
    for transition_id in transition_ids
}

# Digests are over canonical JSON projections of the exact base-model values. They
# are deliberately independent of candidate input and act as reviewed kill-switch
# pins without duplicating unrelated descriptive fields.
EXPECTED_FIELD_SECURITY_DIGEST = {
    ("application_event", "ap_protocol_version"): "972cabfc27fcbe49f33800bc0c7c718db37734889b66b848b82d897ddb3b1b28",
    ("application_event", "ap_transition_block"): "1777b32898466df44ef6bb42921e0d68c76a24cf613611da808249efc1eed213",
    ("application_event", "application_profile_id"): "0bc93f8f8997eb45ec0b1520a704d6fb9f93294a7772f3771eaf660c9ed7b37a",
    ("application_event", "application_profile_version"): "0bc93f8f8997eb45ec0b1520a704d6fb9f93294a7772f3771eaf660c9ed7b37a",
    ("application_event", "author_sequence"): "48a5cb0d57a3faa9458df0354384c13f64f93b15b8a79bd6f1fc8cc335cc9a08",
    ("application_event", "causal_parents"): "48a5cb0d57a3faa9458df0354384c13f64f93b15b8a79bd6f1fc8cc335cc9a08",
    ("application_event", "content_descriptor_ref"): "b1e4af5ea9fa75ddd2836f69b86e750fc3f90430e8147126ab5f2a3110a19338",
    ("application_event", "context_identifier"): "972cabfc27fcbe49f33800bc0c7c718db37734889b66b848b82d897ddb3b1b28",
    ("application_event", "credential_control_kind"): "ef09a263ff778086fb3d4289d121192e211eb3f410aaaebafacffcebe010b168",
    ("application_event", "credential_identifier"): "48a5cb0d57a3faa9458df0354384c13f64f93b15b8a79bd6f1fc8cc335cc9a08",
    ("application_event", "direct_predecessor_presence"): "48a5cb0d57a3faa9458df0354384c13f64f93b15b8a79bd6f1fc8cc335cc9a08",
    ("application_event", "direct_predecessor_reference"): "48a5cb0d57a3faa9458df0354384c13f64f93b15b8a79bd6f1fc8cc335cc9a08",
    ("application_event", "event_reference"): "2b3ce354a9e7e9456c790cb09d077711149de3249003c5bf712e01f851fbddeb",
    ("application_event", "event_role"): "38da6491b60a47152248b077709b2241bb95c00c038076940cbb571ecf440b37",
    ("application_event", "event_type_identifier"): "1777b32898466df44ef6bb42921e0d68c76a24cf613611da808249efc1eed213",
    ("application_event", "genesis_reference"): "972cabfc27fcbe49f33800bc0c7c718db37734889b66b848b82d897ddb3b1b28",
    ("application_event", "grantee_signature_suite_id"): "48a5cb0d57a3faa9458df0354384c13f64f93b15b8a79bd6f1fc8cc335cc9a08",
    ("application_event", "grantee_verification_key"): "48a5cb0d57a3faa9458df0354384c13f64f93b15b8a79bd6f1fc8cc335cc9a08",
    ("application_event", "object_kind"): "972cabfc27fcbe49f33800bc0c7c718db37734889b66b848b82d897ddb3b1b28",
    ("application_event", "recovery_grant_reference"): "38da6491b60a47152248b077709b2241bb95c00c038076940cbb571ecf440b37",
    ("application_event", "removal_tail"): "38da6491b60a47152248b077709b2241bb95c00c038076940cbb571ecf440b37",
    ("application_event", "replacement_grant_reference"): "38da6491b60a47152248b077709b2241bb95c00c038076940cbb571ecf440b37",
    ("application_event", "schema_identifier"): "0bc93f8f8997eb45ec0b1520a704d6fb9f93294a7772f3771eaf660c9ed7b37a",
    ("application_event", "schema_version"): "0bc93f8f8997eb45ec0b1520a704d6fb9f93294a7772f3771eaf660c9ed7b37a",
    ("application_event", "signature"): "d99335723e5383e50b11b6f5c72e06656f804c6a8403fd0c46ce65c18d58148f",
    ("application_event", "target_credential_identifier"): "ef09a263ff778086fb3d4289d121192e211eb3f410aaaebafacffcebe010b168",
    ("checkpoint_evidence", "checkpoint_evidence_refs"): "3a9cccddd6adee69c49da8572eaf6275ec5a7cd465019ba36067c44393a7a512",
    ("checkpoint_evidence", "replay_dependency_refs"): "3a9cccddd6adee69c49da8572eaf6275ec5a7cd465019ba36067c44393a7a512",
    ("content_bytes", "content_octets"): "66f393ab0fb494e973621ad615268ccfa42f638218ddc8071a7cf900388645f8",
    ("content_descriptor", "content_class"): "1777b32898466df44ef6bb42921e0d68c76a24cf613611da808249efc1eed213",
    ("content_descriptor", "content_commitment"): "42f35f6ddcf7532e65b3f6323d272106ecd181d947664f2b8a42c3d041eb807c",
    ("content_descriptor", "content_geometry"): "42f35f6ddcf7532e65b3f6323d272106ecd181d947664f2b8a42c3d041eb807c",
    ("content_descriptor", "content_length"): "42f35f6ddcf7532e65b3f6323d272106ecd181d947664f2b8a42c3d041eb807c",
    ("content_descriptor", "content_shape"): "42f35f6ddcf7532e65b3f6323d272106ecd181d947664f2b8a42c3d041eb807c",
    ("content_descriptor", "content_suite_id"): "910aa0277f89d2489a47d8fe5d4565d38a56ca1d907ddeb2e90f8acef32b91df",
    ("content_descriptor", "content_type_id"): "081ff850f3b50b05e51f337eb89504416d6bd2a67243aadb4fcf7558b2f8e856",
    ("genesis", "derived_genesis_reference"): "2b3ce354a9e7e9456c790cb09d077711149de3249003c5bf712e01f851fbddeb",
    ("genesis", "genesis_body"): "23baf76f9884ccd18b4fb721dd9c83abe06f6496a8afb6be9180f13303f835f0",
    ("opening", "opening_randomizer"): "c5d1c0fa5eb80f9d32ec3b897108f1d462a5abbe9460b39c5a9c3ec9cca37300",
}

EXPECTED_STATE_MODEL_STRUCTURE_DIGEST = {
    "ap_projection": "65ce14337e10d7305a409ef46577a21f2331df0cc7df0c545363592d0b0c4e96",
    "k_admission": "c0f2b6dc8fd68a4f21f4f52625a4f232b7968ea07ac11311e4f632877101a7ad",
    "pending_replay": "d9eedea7a98f44c391d55f15f703fa44d0ed7dc222800f170684be39c447493c",
}

EXPECTED_TRANSITION_STRUCTURE_DIGEST = {
    ("ap_projection", "ap_pending_to_active"): "10c9863489dcea6f57c2cad4eccee92bf1b9bee997c6b421453386794a6e5e91",
    ("ap_projection", "ap_recover_active"): "4e7b81d8cfd39290db7f2afdd5b2ce9b48196a9f797c539146b043a2daa54e09",
    ("ap_projection", "ap_recover_fork_quarantine"): "d5944c2875928e522d0a852e3214311ae2d9962ab0f6a76050f28b5d7ac847f4",
    ("ap_projection", "ap_recover_pending"): "2252c922f81434da6a3e6d0a7dd80904d12835104de86855ee43d27e694e5aa7",
    ("ap_projection", "ap_to_authority_unavailable"): "83120e6c9c5b3c12a8c4e8ff4aa6c0c4b4cec3940ca87cccc98e3ee4f868014e",
    ("ap_projection", "ap_to_partially_pending"): "e93b5f5e9a43e56a12192e128ffc7ab2d80af457ece3e2b06f0692357da7195b",
    ("ap_projection", "ap_to_stale"): "60adb84af20f096bab1c19ab6e2361ffe29a843569febf3bcafefd8dc60b5961",
    ("ap_projection", "ap_to_terminal_fork"): "b095b9d790fb54474b7cea058f2736a5d2bbaa34eeafa26dfacb55afad26fd74",
    ("k_admission", "k_admit_binding_grant"): "9263f1b56c11c85c155cb5a887cc85581973ab2c01ec2591f03dbb777c3e5159",
    ("k_admission", "k_admit_candidate"): "57c5bb63dc7f90a425231fb77291b3b23df0cded2a4d3dbd708273edf194ae45",
    ("k_admission", "k_reject_invalid"): "4d68e7d153b28dc177d3ab4c0bd8f24bb921c6ecbde2dfbff34176f6f46e0730",
    ("k_admission", "k_reject_unresolved_binding"): "0ad68d5d4607fde380b96fcc798a772cc06af03a8b4701bec66a1131d85cc322",
    ("k_admission", "k_to_collision"): "45fed3154aabbd415b12ec711657c2144014d839d3bd775c9d54f7b8fe6aa78d",
    ("k_admission", "k_to_fork"): "0865b092f5682c163d670f0832ffc9d6a35eb3b665ead74fc06d776ce184b717",
    ("pending_replay", "replay_apply_candidate"): "89d5677772ff0f2677574e6e77de282023b28843d0f67fc62fbe9d5e1f6e8399",
    ("pending_replay", "replay_to_pending_descendant"): "9b505d483be8e29dad7e82fcdf186f26156b823f92b9ba1f4b88e5dfbed24ed6",
    ("pending_replay", "replay_to_pending_root"): "2e131619f64ac2edd81e016293550e2481b910f6e4bb189782c12f9819af37d6",
    ("pending_replay", "replay_verified_opening"): "666a00ec99be48b2f4bd0a7f762c4b6dae982ef75164de1a5b76f35d078d3f96",
}

EXPECTED_INVARIANT_REFS_DIGEST = {
    "INV_AUTHORITY_PROJECTION_LIMITS": "8e43f55e666df50281189c672a11211168aec784cb109fdf36948a596279868f",
    "INV_AUTH_NOT_KEY": "78345f1da3d2be3febf7b76534727f01344c2a94aa6652981c1c6de5c263875f",
    "INV_BOUNDED_CONTESTED_STANDING": "c449bea11ce00423f6f2ff7a1338aad12759bf6aa7e569f7afd1c95563e57b92",
    "INV_C0_3_NO_GO": "1855fe83c4c345d85e99ed91532bce2bea1fc6c48b5b2b824bdeb0c664e69bdc",
    "INV_CAUSALITY_TRANSCRIPT_ONLY": "05118f1b57f43cf1db032e2ce84693e1124b3ad6ab12336c48376245f1f0a63c",
    "INV_CAUSAL_TARGET_AVAILABILITY": "1960e2064b8f84d4fc9629b96635d5ec789da182fdafe287a25176aaaf5ccb89",
    "INV_COMMITMENT_CONTEXT_BINDING": "cdc22f973d57fc0e8c49e9cff7c5441e6680f4293290b6a109987729baa9a17b",
    "INV_CONTROL_NONE_CLASS": "6c0a4a6e082957fb09aaa6882cfe069c480ed4e3151bcce1831ab33431c71ed0",
    "INV_CROSS_CONTEXT_REJECTION": "618ccf5160f29b1d94a5a52d52ec1992294968cd01e975f7c794be5488df3a45",
    "INV_FORK_QUARANTINE": "d9b93ef44958bd347bcd1326c9e47916f0662b62dd5c94d674ab929325e7c772",
    "INV_GRANT_ROOTED_BINDING": "85f32fa514f481ea4b11ea4d7c44b066690aa2e45b0602f4190b98cf3f5e6d6e",
    "INV_LINEAGE_CONTAINMENT": "5872b96addc83943978a343a1c39ada6c79aa426d799657d55a2b5f6dd985f6d",
    "INV_NO_CHECKPOINT_SUBSTITUTION": "2cc4af1dc44c0fb942b024017b01e563de214552d732801a24b27dca7a45f145",
    "INV_NO_OPENING_SUBSTITUTION": "be1e44c5e9f95d05177ff8c7035833402ee8042f69d6b12d960a34c3ecd85759",
    "INV_O06C_BOUNDED_EVIDENCE": "63ee449606523f645626b04e412703b6971dadf10eb5b6b74b66b4a6dcce2d71",
    "INV_OUTCOME_PRECEDENCE": "63383d8b4440b25185c44032592610db2c3ab7f924bcb8925854102b4c979af4",
    "INV_PENDING_SELECTIVE_PROGRESS": "f49127738a96641b4dea50b4b03e0b5d2f439d5322e0a58fe1b44b6eace09cba",
    "INV_PROTECTION_SEPARATION": "f3de4e2ffb1f5e5ec6c74039cc78950010031519ca05465c956a8f935a0e9333",
    "INV_REPLAY_NO_AUTHORITY": "703622554da0cd05fbbe9ea93daa7c47753d41b0023c9b76840ad6362373c38d",
    "INV_SELF_LINEAGE_REDUCTION": "d97f746ac83eef0ca68059a429d8296d7a73f6bbf4540dc09c03fdb04fce4e67",
    "INV_SET_RELATIVE_REPLAY": "e7442e5189955ad44d65affbc3a764f88792bd84ed837353c1d5cd1fe4def4f1",
    "INV_SOURCE_AUTHORITY": "3663412201387a656e450c889f87b7c88422c0f6b0aaf8ef6c50bb4b56f5a2ca",
    "INV_TWO_SIDED_AUTHORITY": "0be54e681495b19c823ca361cbe2ef10a26606db4b5f52ae00972a08fbbe1e04",
}

EXPECTED_BLOCKER_EDGES_DIGEST = {
    "C0.2j": "fd582f88a719a75d14a762a9d2a1f62b1da163d455d1f9e4497f93fbb94c2892",
    "C0.2k": "dcf613a0ba08abc1b75668271ff4d8c4f74e50d90cef3afa62819bc57baef990",
    "C0.3": "294c90766317a495004a86e300e1c1b6b81de66b377cefe47676b9e67c1f6d14",
    "C0.3_CORPUS_PATH_APPROVAL": "2f46c5b24abdce4302300f7f2d7b1c5ffb49e96b20529d82185df78cfba48f0f",
    "O-06c": "216def2a5762650aeee985ce998d5670fbefbceb2e297097039a8cbc4796d3a4",
    "O-07": "221bdcaa5b87211fc802a254c7d341fda0cae735ce4bee6d2be5b45bff4e1486",
    "O-08": "221bdcaa5b87211fc802a254c7d341fda0cae735ce4bee6d2be5b45bff4e1486",
    "O-10": "221bdcaa5b87211fc802a254c7d341fda0cae735ce4bee6d2be5b45bff4e1486",
    "O-12": "0ec899aab0c3f8a17bb8d5182cbb50ec77f636e459d03e886453d006d1a60cc6",
    "O-13": "a30dcdb5965e12dec5f6ca4bbda5bfba662a52c32fd8e1ffbaed61b537b28b07",
    "O-14": "221bdcaa5b87211fc802a254c7d341fda0cae735ce4bee6d2be5b45bff4e1486",
    "O-15": "be6b9c15a20507e99a48ba3ab1d9c162a80f989bada035c6517fda9377e5b072",
    "O-16": "32d8dc7cb867ba2a1d2614d2ec7365a48bcee7470f6a50afc0a11eb3ff561e63",
}

EXPECTED_OUTCOME_TRANSITION = {
    outcome_id: outcome_id == "APPLIED"
    for outcome_id in EXPECTED_IDS_BY_COLLECTION["outcomes"]
}

EXPECTED_COUNTEREXAMPLE_BLOCKS = {
    "CE_ALIAS_SURVIVAL": ["C0.2j"],
    "CE_AUTHORITY_PROJECTION_EXHAUSTION": ["O-08"],
    "CE_BOUNDED_CONTESTED_STANDING": ["C0.2j"],
    "CE_CHECKPOINT_STALE": ["O-07"],
    "CE_CREDENTIAL_COLLISION": ["C0.2j"],
    "CE_FORK_CONTEXT_QUARANTINE": ["C0.2j", "O-16"],
    "CE_GRANT_REVOKE_LAUNDERING_ORDER_A": ["C0.2j"],
    "CE_GRANT_REVOKE_LAUNDERING_ORDER_B": ["C0.2j"],
    "CE_GRANT_ROOTED_BINDING": ["C0.2j"],
    "CE_MISSING_REQUIRED_OPENING": ["O-08"],
    "CE_MUTUAL_REDUCTION_NO_AUTHORITY": ["C0.2j"],
    "CE_NONCAUSAL_REDUCTION_TARGET": ["C0.2j"],
    "CE_SELECTIVE_REVEAL": ["O-08"],
    "CE_SELF_LINEAGE_REDUCTION": ["C0.2j"],
    "CE_SINGLE_AUTHORITY_TAKEOVER": ["C0.2j"],
    "CE_SUBTREE_AMPLIFICATION": ["C0.2j"],
}

SUPPORTED_SCHEMA_KEYWORDS = {
    "$defs",
    "$id",
    "$ref",
    "$schema",
    "additionalProperties",
    "const",
    "description",
    "enum",
    "items",
    "minItems",
    "minLength",
    "pattern",
    "properties",
    "required",
    "title",
    "type",
}

SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
EXPECTED_SCHEMA_SHA256 = (
    "efc83b3c3981296a77bf1b6d5592ccfa4a6137691ec8e078d196c2c740a0e82e"
)

PROTECTED_UNRESOLVED_FIELDS = {
    ("application_event", "ap_transition_block"),
    ("application_event", "event_type_identifier"),
    ("application_event", "genesis_reference"),
    ("application_event", "schema_identifier"),
    ("application_event", "schema_version"),
    ("application_event", "signature"),
    ("content_descriptor", "content_type_id"),
    ("genesis", "derived_genesis_reference"),
    ("genesis", "genesis_body"),
}

SORTED_RECORD_ARRAYS = (
    "actors",
    "blockers",
    "counterexamples",
    "flows",
    "invariants",
    "layers",
    "non_claims",
    "objects",
    "outcomes",
    "residual_risks",
    "review_queries",
    "sources",
    "state_models",
)


@dataclass(frozen=True)
class Finding:
    code: str
    path: str
    message: str


class DuplicateKeyError(ValueError):
    pass


def _reject_nonstandard_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def load_json_unique(path: Path) -> Any:
    try:
        raw = path.read_text(encoding="utf-8")
        _reject_pathological_json_nesting(raw)
        return json.loads(
            raw,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_nonstandard_constant,
        )
    except DuplicateKeyError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"cannot parse {path}: {exc}") from exc


def _reject_pathological_json_nesting(raw: str, maximum_depth: int = 256) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in raw:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > maximum_depth:
                raise ValueError(f"JSON nesting exceeds {maximum_depth}")
        elif character in "]}":
            depth -= 1


def _json_type_matches(value: Any, expected: str) -> bool:
    return {
        "array": isinstance(value, list),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "null": value is None,
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "object": isinstance(value, dict),
        "string": isinstance(value, str),
    }.get(expected, False)


def _resolve_ref(schema_root: dict[str, Any], reference: str) -> dict[str, Any]:
    prefix = "#/$defs/"
    if not isinstance(reference, str):
        raise ValueError("schema reference must be a string")
    if not reference.startswith(prefix):
        raise ValueError(f"unsupported schema reference: {reference}")
    name = reference[len(prefix) :]
    definitions = schema_root.get("$defs", {})
    if not isinstance(definitions, dict):
        raise ValueError("schema $defs must be an object")
    target = definitions.get(name)
    if not isinstance(target, dict):
        raise ValueError(f"unknown schema reference: {reference}")
    return target


def _schema_definition_findings(
    schema: Any,
    schema_root: dict[str, Any],
    path: str,
) -> list[Finding]:
    if not isinstance(schema, dict):
        return [Finding("SCHEMA_DEFINITION", path, "schema node must be an object")]

    findings: list[Finding] = []
    for keyword in schema:
        if keyword not in SUPPORTED_SCHEMA_KEYWORDS:
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.{keyword}",
                    "unsupported schema keyword would fail open",
                )
            )

    for keyword in ("$id", "$schema", "description", "title"):
        if keyword in schema and not isinstance(schema[keyword], str):
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.{keyword}",
                    f"{keyword} must be a string",
                )
            )

    reference_is_valid = False
    if "$ref" in schema:
        if set(schema) != {"$ref"}:
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    path,
                    "$ref nodes must not contain ignored sibling keywords",
                )
            )
        try:
            _resolve_ref(schema_root, schema["$ref"])
        except (TypeError, ValueError) as exc:
            findings.append(Finding("SCHEMA_DEFINITION", path, str(exc)))
        else:
            reference_is_valid = set(schema) == {"$ref"}

    enum_is_valid = False
    if "enum" in schema:
        enum_values = schema["enum"]
        if not isinstance(enum_values, list) or not enum_values:
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.enum",
                    "enum must be a non-empty array",
                )
            )
        elif len({json.dumps(value, sort_keys=True) for value in enum_values}) != len(
            enum_values
        ):
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.enum",
                    "enum values must be unique",
                )
            )
        else:
            enum_is_valid = True

    schema_type = schema.get("type")
    type_is_valid = isinstance(schema_type, str) and schema_type in {
        "array",
        "boolean",
        "integer",
        "null",
        "number",
        "object",
        "string",
    }
    if "type" in schema and not type_is_valid:
        findings.append(
            Finding("SCHEMA_DEFINITION", f"{path}.type", "unsupported schema type")
        )

    if not (type_is_valid or reference_is_valid or enum_is_valid or "const" in schema):
        findings.append(
            Finding(
                "SCHEMA_DEFINITION",
                path,
                "schema node must declare type, $ref, non-empty enum or const",
            )
        )

    object_keywords = {"additionalProperties", "properties", "required"}
    if object_keywords.intersection(schema) and schema_type != "object":
        findings.append(
            Finding(
                "SCHEMA_DEFINITION",
                path,
                "object keywords require type object",
            )
        )

    properties = schema.get("properties")
    if schema_type == "object":
        if schema.get("additionalProperties") is not False:
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.additionalProperties",
                    "every object schema must fail closed",
                )
            )
        if not isinstance(properties, dict):
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.properties",
                    "object schema properties must be an object",
                )
            )
        elif not properties:
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.properties",
                    "object schema must declare at least one property",
                )
            )
        required = schema.get("required", [])
        if not isinstance(required, list) or any(
            not isinstance(item, str) for item in required
        ):
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.required",
                    "required must be an array of property names",
                )
            )
        elif isinstance(properties, dict) and not set(required).issubset(properties):
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.required",
                    "required names must exist in properties",
                )
            )

    # Traverse object children even when the parent type or another keyword is
    # malformed, so a parent finding cannot hide an invalid subtree.
    if isinstance(properties, dict):
        for name, child in properties.items():
            if not isinstance(name, str):
                findings.append(
                    Finding(
                        "SCHEMA_DEFINITION",
                        f"{path}.properties",
                        "property names must be strings",
                    )
                )
                continue
            findings.extend(
                _schema_definition_findings(
                    child,
                    schema_root,
                    f"{path}.properties.{name}",
                )
            )

    if schema_type == "array" and "items" not in schema:
        findings.append(
            Finding(
                "SCHEMA_DEFINITION",
                f"{path}.items",
                "array schema must declare an object items schema",
            )
        )

    if "items" in schema and schema_type != "array":
        findings.append(
            Finding(
                "SCHEMA_DEFINITION",
                f"{path}.items",
                "items requires type array",
            )
        )

    if "items" in schema:
        if not isinstance(schema["items"], dict):
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.items",
                    "items must be an object schema",
                )
            )
        else:
            findings.extend(
                _schema_definition_findings(
                    schema["items"], schema_root, f"{path}.items"
                )
            )

    for keyword in ("minItems", "minLength"):
        if keyword in schema and (
            not isinstance(schema[keyword], int)
            or isinstance(schema[keyword], bool)
            or schema[keyword] < 0
        ):
            findings.append(
                Finding(
                    "SCHEMA_DEFINITION",
                    f"{path}.{keyword}",
                    f"{keyword} must be a non-negative integer",
                )
            )

    if "pattern" in schema:
        try:
            re.compile(schema["pattern"])
        except (TypeError, re.error) as exc:
            findings.append(Finding("SCHEMA_DEFINITION", f"{path}.pattern", str(exc)))

    if "$defs" in schema:
        definitions = schema["$defs"]
        if not isinstance(definitions, dict):
            findings.append(
                Finding("SCHEMA_DEFINITION", f"{path}.$defs", "$defs must be an object")
            )
        else:
            for name, child in definitions.items():
                if not isinstance(name, str):
                    findings.append(
                        Finding(
                            "SCHEMA_DEFINITION",
                            f"{path}.$defs",
                            "definition names must be strings",
                        )
                    )
                findings.extend(
                    _schema_definition_findings(child, schema_root, f"{path}.$defs.{name}")
                )
    return findings


def _schema_findings(
    value: Any,
    schema: dict[str, Any],
    schema_root: dict[str, Any],
    path: str,
) -> list[Finding]:
    findings: list[Finding] = []
    if "$ref" in schema:
        try:
            target = _resolve_ref(schema_root, schema["$ref"])
        except ValueError as exc:
            return [Finding("SCHEMA_DEFINITION", path, str(exc))]
        return _schema_findings(value, target, schema_root, path)

    if "type" in schema and not _json_type_matches(value, schema["type"]):
        return [
            Finding(
                "SCHEMA_MISMATCH",
                path,
                f"expected {schema['type']}, got {type(value).__name__}",
            )
        ]
    if "const" in schema and value != schema["const"]:
        findings.append(Finding("SCHEMA_MISMATCH", path, "const value mismatch"))
    if "enum" in schema and value not in schema["enum"]:
        findings.append(Finding("SCHEMA_MISMATCH", path, "value outside enum"))
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            findings.append(Finding("SCHEMA_MISMATCH", path, "string too short"))
        pattern = schema.get("pattern")
        if pattern is not None and re.search(pattern, value) is None:
            findings.append(Finding("SCHEMA_MISMATCH", path, "pattern mismatch"))
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            findings.append(Finding("SCHEMA_MISMATCH", path, "array too short"))
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                findings.extend(
                    _schema_findings(item, item_schema, schema_root, f"{path}[{index}]")
                )
    if isinstance(value, dict):
        required = schema.get("required", [])
        for key in required:
            if key not in value:
                findings.append(
                    Finding("SCHEMA_MISMATCH", f"{path}.{key}", "required key missing")
                )
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in properties:
                    findings.append(
                        Finding("SCHEMA_MISMATCH", f"{path}.{key}", "unknown key")
                    )
        for key, child_schema in properties.items():
            if key in value:
                findings.extend(
                    _schema_findings(
                        value[key], child_schema, schema_root, f"{path}.{key}"
                    )
                )
    return findings


def validate_schema_definition(schema: Any) -> list[Finding]:
    if not isinstance(schema, dict):
        return [Finding("SCHEMA_DEFINITION", "$schema", "schema root must be object")]
    findings: list[Finding] = []
    if schema.get("$schema") != SCHEMA_DRAFT:
        findings.append(
            Finding("SCHEMA_DEFINITION", "$schema.$schema", "unexpected schema draft")
        )
    definition_findings = _schema_definition_findings(schema, schema, "$schema")
    findings.extend(definition_findings)
    return findings


def validate_schema(model: Any, schema: Any) -> list[Finding]:
    findings = validate_schema_definition(schema)
    if findings:
        return findings
    findings.extend(_schema_findings(model, schema, schema, "$model"))
    return findings


def _domain_safe_value(value: Any, schema: dict[str, Any], root: dict[str, Any]) -> Any:
    """Return a typed copy suitable for additive domain checks.

    Schema mismatches remain findings on the original value. Replacing only malformed
    subtrees with deterministic neutral values lets independent domain checks continue
    without treating malformed candidate input as a Python programming error.
    """

    if "$ref" in schema:
        return _domain_safe_value(value, _resolve_ref(root, schema["$ref"]), root)

    expected_type = schema.get("type")
    if isinstance(expected_type, str) and not _json_type_matches(value, expected_type):
        value = {
            "array": [],
            "boolean": False,
            "integer": 0,
            "null": None,
            "number": 0,
            "object": {},
            "string": "",
        }[expected_type]

    if isinstance(value, list):
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            return [_domain_safe_value(item, item_schema, root) for item in value]
        return list(value)
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        safe: dict[str, Any] = {}
        for key, child in value.items():
            child_schema = properties.get(key) if isinstance(properties, dict) else None
            safe[key] = (
                _domain_safe_value(child, child_schema, root)
                if isinstance(child_schema, dict)
                else child
            )
        return safe
    return value


def _unique_ids(records: list[Any], path: str) -> tuple[set[str], list[Finding]]:
    seen: set[str] = set()
    findings: list[Finding] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        record_id = record.get("id")
        if not isinstance(record_id, str):
            continue
        if record_id in seen:
            findings.append(
                Finding("DUPLICATE_ID", f"{path}[{index}].id", f"duplicate id {record_id}")
            )
        seen.add(record_id)
    return seen, findings


def _require_sorted_ids(records: list[Any], path: str) -> list[Finding]:
    ids = [record.get("id") for record in records if isinstance(record, dict)]
    if len(ids) != len(records):
        return []
    if not all(isinstance(value, str) for value in ids):
        return []
    if ids != sorted(ids):
        return [Finding("NONDETERMINISTIC_ORDER", path, "records must be sorted by id")]
    return []


def _require_sorted_unique_strings(values: Any, path: str) -> list[Finding]:
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        return []
    if len(values) != len(set(values)):
        return [Finding("DUPLICATE_ID", path, "set-like array contains duplicate values")]
    if values != sorted(values):
        return [Finding("NONDETERMINISTIC_ORDER", path, "set-like array must be sorted")]
    return []


def _record_map(model: dict[str, Any], name: str) -> dict[str, dict[str, Any]]:
    return {
        record["id"]: record
        for record in model.get(name, [])
        if isinstance(record, dict) and isinstance(record.get("id"), str)
    }


def _projection_digest(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _record_map_with_paths(
    records: list[Any], path: str
) -> dict[str, tuple[dict[str, Any], str]]:
    return {
        record["id"]: (record, f"{path}[{index}]")
        for index, record in enumerate(records)
        if isinstance(record, dict) and isinstance(record.get("id"), str)
    }


def _validate_exact_pins(model: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    object_records = _record_map_with_paths(model.get("objects", []), "$model.objects")
    for object_id, (obj, object_path) in object_records.items():
        if object_id not in EXPECTED_IDS_BY_COLLECTION["objects"]:
            continue
        field_records = _record_map_with_paths(obj.get("fields", []), f"{object_path}.fields")
        for field_id, (field, field_path) in field_records.items():
            locator = (object_id, field_id)
            expected = EXPECTED_FIELD_SECURITY_DIGEST.get(locator)
            if expected is None:
                continue
            projection = {
                key: field.get(key)
                for key in (
                    "owner",
                    "visible_to",
                    "mutable_by",
                    "wire_presence",
                    "confidentiality",
                    "integrity",
                )
            }
            if _projection_digest(projection) != expected:
                findings.append(
                    Finding(
                        "MISSING_PROTECTION_METADATA",
                        field_path,
                        f"security tuple drift for {object_id}/{field_id}",
                    )
                )

    state_records = _record_map_with_paths(
        model.get("state_models", []), "$model.state_models"
    )
    for state_model_id, (state_model, state_path) in state_records.items():
        expected_state = EXPECTED_STATE_MODEL_STRUCTURE_DIGEST.get(state_model_id)
        if expected_state is None:
            continue
        state_projection = {
            key: state_model.get(key)
            for key in ("terminal_states", "states", "precedence")
        }
        if _projection_digest(state_projection) != expected_state:
            findings.append(
                Finding(
                    "PINNED_VALUE_DRIFT",
                    state_path,
                    f"state-model structure drift for {state_model_id}",
                )
            )
        transition_records = _record_map_with_paths(
            state_model.get("transitions", []), f"{state_path}.transitions"
        )
        for transition_id, (transition, transition_path) in transition_records.items():
            locator = (state_model_id, transition_id)
            expected_status = EXPECTED_TRANSITION_STATUS.get(locator)
            if expected_status is None:
                continue
            if transition.get("status") != expected_status:
                findings.append(
                    Finding(
                        "FORBIDDEN_STATUS_PROMOTION",
                        f"{transition_path}.status",
                        f"must remain {expected_status}",
                    )
                )
            transition_projection = {
                key: transition.get(key) for key in ("from", "to", "outcome")
            }
            if (
                _projection_digest(transition_projection)
                != EXPECTED_TRANSITION_STRUCTURE_DIGEST[locator]
            ):
                findings.append(
                    Finding(
                        "PINNED_VALUE_DRIFT",
                        transition_path,
                        f"transition structure drift for {state_model_id}/{transition_id}",
                    )
                )

    for collection, expected_digests, keys, code in (
        (
            "invariants",
            EXPECTED_INVARIANT_REFS_DIGEST,
            ("object_refs", "evidence_refs"),
            "PINNED_VALUE_DRIFT",
        ),
        (
            "blockers",
            EXPECTED_BLOCKER_EDGES_DIGEST,
            ("depends_on", "blocks"),
            "BLOCKER_EDGE_MISMATCH",
        ),
    ):
        records = _record_map_with_paths(model.get(collection, []), f"$model.{collection}")
        for record_id, (record, record_path) in records.items():
            expected = expected_digests.get(record_id)
            if expected is None:
                continue
            projection = {key: record.get(key) for key in keys}
            if _projection_digest(projection) != expected:
                findings.append(
                    Finding(code, record_path, f"pinned {collection} value drift for {record_id}")
                )

    outcome_records = _record_map_with_paths(model.get("outcomes", []), "$model.outcomes")
    for outcome_id, (outcome, outcome_path) in outcome_records.items():
        if outcome_id not in EXPECTED_OUTCOME_TRANSITION:
            continue
        if outcome.get("applies_transition") is not EXPECTED_OUTCOME_TRANSITION[outcome_id]:
            findings.append(
                Finding(
                    "PINNED_VALUE_DRIFT",
                    f"{outcome_path}.applies_transition",
                    f"pinned outcome value drift for {outcome_id}",
                )
            )

    counterexample_records = _record_map_with_paths(
        model.get("counterexamples", []), "$model.counterexamples"
    )
    for counterexample_id, (counterexample, counterexample_path) in counterexample_records.items():
        expected_blocks = EXPECTED_COUNTEREXAMPLE_BLOCKS.get(counterexample_id)
        if expected_blocks is None:
            continue
        if counterexample.get("blocks") != expected_blocks:
            findings.append(
                Finding(
                    "PINNED_VALUE_DRIFT",
                    f"{counterexample_path}.blocks",
                    f"pinned counterexample value drift for {counterexample_id}",
                )
            )
    return findings


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_sources(
    model: dict[str, Any], repo_root: Path
) -> tuple[dict[str, bytes], list[Finding]]:
    findings: list[Finding] = []
    source_bytes: dict[str, bytes] = {}
    paths_seen: set[str] = set()
    root = repo_root.resolve()
    for index, source in enumerate(model.get("sources", [])):
        if not isinstance(source, dict):
            continue
        source_id = source.get("id")
        relative = source.get("path")
        authority = source.get("authority")
        expected = source.get("sha256")
        path_label = f"$model.sources[{index}]"
        if not isinstance(source_id, str) or not isinstance(relative, str):
            continue
        expected_record = EXPECTED_SOURCE_RECORDS.get(source_id)
        if expected_record is not None:
            expected_path, expected_authority = expected_record
            if relative != expected_path:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"{path_label}.path",
                        f"{source_id} must use {expected_path}",
                    )
                )
            if authority != expected_authority:
                findings.append(
                    Finding(
                        "FORBIDDEN_STATUS_PROMOTION",
                        f"{path_label}.authority",
                        f"{source_id} must remain {expected_authority}",
                    )
                )
        if relative in paths_seen:
            findings.append(Finding("DUPLICATE_ID", f"{path_label}.path", relative))
        paths_seen.add(relative)
        relative_path = Path(relative)
        if relative_path.is_absolute() or ".." in relative_path.parts:
            findings.append(
                Finding(
                    "SOURCE_BOUNDARY",
                    f"{path_label}.path",
                    "source path must be repository-relative without traversal",
                )
            )
            continue
        candidate = repo_root / relative
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            findings.append(Finding("SOURCE_MISSING", f"{path_label}.path", str(exc)))
            continue
        if candidate.is_symlink() or resolved == root or root not in resolved.parents:
            findings.append(
                Finding("SOURCE_BOUNDARY", f"{path_label}.path", "source escapes repository")
            )
            continue
        if not resolved.is_file():
            findings.append(Finding("SOURCE_MISSING", f"{path_label}.path", "not a file"))
            continue
        actual = _sha256(resolved)
        if actual != expected:
            findings.append(
                Finding(
                    "SOURCE_DIGEST_MISMATCH",
                    f"{path_label}.sha256",
                    f"expected {expected}, got {actual}",
                )
            )
        try:
            source_bytes[source_id] = resolved.read_bytes()
        except OSError as exc:
            findings.append(Finding("SOURCE_MISSING", f"{path_label}.path", str(exc)))
    return source_bytes, findings


def _iter_cited_records(model: dict[str, Any]):
    for name in (
        "actors",
        "blockers",
        "counterexamples",
        "flows",
        "invariants",
        "layers",
        "non_claims",
        "objects",
        "outcomes",
        "residual_risks",
        "review_queries",
        "state_models",
    ):
        for index, record in enumerate(model.get(name, [])):
            if not isinstance(record, dict):
                continue
            yield f"$model.{name}[{index}]", record
            if name == "objects":
                for field_index, field in enumerate(record.get("fields", [])):
                    if isinstance(field, dict):
                        yield f"$model.{name}[{index}].fields[{field_index}]", field
            if name == "state_models":
                for transition_index, transition in enumerate(record.get("transitions", [])):
                    if isinstance(transition, dict):
                        yield (
                            f"$model.{name}[{index}].transitions[{transition_index}]",
                            transition,
                        )


def _validate_citations(
    model: dict[str, Any],
    source_bytes: dict[str, bytes],
    source_authority: dict[str, str],
) -> list[Finding]:
    findings: list[Finding] = []
    for path, record in _iter_cited_records(model):
        citations = record.get("citations", [])
        if not citations:
            findings.append(Finding("MISSING_CITATION", path, "record has no citation"))
            continue
        if not any(
            source_authority.get(citation.get("source_id")) == "normative"
            for citation in citations
            if isinstance(citation, dict)
        ):
            findings.append(
                Finding(
                    "MISSING_NORMATIVE_CITATION",
                    path,
                    "security-relevant record has no normative source citation",
                )
            )
        for index, citation in enumerate(citations):
            if not isinstance(citation, dict):
                continue
            source_id = citation.get("source_id")
            anchor = citation.get("anchor")
            citation_path = f"{path}.citations[{index}]"
            raw = source_bytes.get(source_id)
            if raw is None:
                findings.append(
                    Finding("DANGLING_REFERENCE", citation_path, f"unknown source {source_id}")
                )
                continue
            try:
                anchor_bytes = anchor.encode("utf-8")
            except (AttributeError, UnicodeError):
                continue
            if len(anchor_bytes) < 16 or b"\n" in anchor_bytes or b"\r" in anchor_bytes:
                findings.append(
                    Finding(
                        "CITATION_ANCHOR_INVALID",
                        citation_path,
                        "anchor must be a single line of at least 16 UTF-8 bytes",
                    )
                )
                continue
            if anchor_bytes not in raw:
                findings.append(
                    Finding(
                        "CITATION_ANCHOR_MISSING",
                        citation_path,
                        f"anchor absent from source {source_id}",
                    )
                )
    return findings


def _validate_blocker_dag(blockers: dict[str, dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> None:
        if node in visited:
            return
        if node in visiting:
            findings.append(Finding("BLOCKER_CYCLE", "$model.blockers", node))
            return
        visiting.add(node)
        for dependency in blockers.get(node, {}).get("depends_on", []):
            if dependency not in blockers:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"$model.blockers.{node}.depends_on",
                        dependency,
                    )
                )
            else:
                visit(dependency)
        visiting.remove(node)
        visited.add(node)

    for blocker_id in blockers:
        visit(blocker_id)
    return findings


def validate_domain(model: dict[str, Any], repo_root: Path) -> list[Finding]:
    findings: list[Finding] = []
    artifact = model.get("artifact", {})
    if not isinstance(artifact, dict):
        return findings
    if artifact.get("normative") is not False:
        findings.append(
            Finding(
                "FORBIDDEN_STATUS_PROMOTION",
                "$model.artifact.normative",
                "must be false",
            )
        )
    if artifact.get("security_proof") is not False:
        findings.append(
            Finding(
                "FORBIDDEN_STATUS_PROMOTION",
                "$model.artifact.security_proof",
                "must be false",
            )
        )
    if artifact.get("implementation_claim") is not False:
        findings.append(
            Finding(
                "FORBIDDEN_STATUS_PROMOTION",
                "$model.artifact.implementation_claim",
                "must be false",
            )
        )
    if artifact.get("c03_verdict") != "NO_GO":
        findings.append(
            Finding(
                "C03_GATE_MISSING",
                "$model.artifact.c03_verdict",
                "must be NO_GO",
            )
        )
    if re.fullmatch(r"[0-9a-f]{40}", str(artifact.get("contract_base_commit"))) is None:
        findings.append(
            Finding(
                "SCHEMA_MISMATCH",
                "$model.artifact.contract_base_commit",
                "must be exactly 40 lowercase hexadecimal characters",
            )
        )
    elif artifact.get("contract_base_commit") != CONTRACT_BASE_COMMIT:
        findings.append(
            Finding(
                "FORBIDDEN_STATUS_PROMOTION",
                "$model.artifact.contract_base_commit",
                f"must remain {CONTRACT_BASE_COMMIT}",
            )
        )

    registries = model.get("registries", {})
    if registries != EXPECTED_REGISTRIES:
        findings.append(
            Finding(
                "UNKNOWN_REGISTRY_VALUE",
                "$model.registries",
                "closed registry mismatch",
            )
        )
    for name, values in registries.items() if isinstance(registries, dict) else []:
        findings.extend(_require_sorted_unique_strings(values, f"$model.registries.{name}"))

    id_sets: dict[str, set[str]] = {}
    for name in SORTED_RECORD_ARRAYS:
        records = model.get(name, [])
        if not isinstance(records, list):
            continue
        ids, duplicate_findings = _unique_ids(records, f"$model.{name}")
        id_sets[name] = ids
        findings.extend(duplicate_findings)
        findings.extend(_require_sorted_ids(records, f"$model.{name}"))

    for collection, expected_ids in EXPECTED_IDS_BY_COLLECTION.items():
        actual_ids = id_sets.get(collection, set())
        if actual_ids != expected_ids:
            missing = sorted(expected_ids - actual_ids)
            unexpected = sorted(actual_ids - expected_ids)
            findings.append(
                Finding(
                    "REQUIRED_RECORD_MISSING",
                    f"$model.{collection}",
                    f"missing={missing}; unexpected={unexpected}",
                )
            )

    for object_index, obj in enumerate(model.get("objects", [])):
        if not isinstance(obj, dict):
            continue
        fields = obj.get("fields", [])
        field_ids, duplicate_findings = _unique_ids(
            fields, f"$model.objects[{object_index}].fields"
        )
        findings.extend(duplicate_findings)
        findings.extend(_require_sorted_ids(fields, f"$model.objects[{object_index}].fields"))
        expected_field_ids = {
            field_id
            for object_id, field_id in EXPECTED_FIELD_STATUS
            if object_id == obj.get("id")
        }
        if field_ids != expected_field_ids:
            findings.append(
                Finding(
                    "REQUIRED_RECORD_MISSING",
                    f"$model.objects[{object_index}].fields",
                    "field inventory differs from the pinned snapshot",
                )
            )
    for state_index, state_model in enumerate(model.get("state_models", [])):
        if not isinstance(state_model, dict):
            continue
        transitions = state_model.get("transitions", [])
        transition_ids, duplicate_findings = _unique_ids(
            transitions, f"$model.state_models[{state_index}].transitions"
        )
        findings.extend(duplicate_findings)
        findings.extend(
            _require_sorted_ids(transitions, f"$model.state_models[{state_index}].transitions")
        )
        expected_transition_ids = EXPECTED_TRANSITION_IDS.get(
            state_model.get("id"), set()
        )
        if transition_ids != expected_transition_ids:
            findings.append(
                Finding(
                    "REQUIRED_RECORD_MISSING",
                    f"$model.state_models[{state_index}].transitions",
                    "transition inventory differs from the pinned snapshot",
                )
            )

    global_ids: dict[str, str] = {}
    for collection in SORTED_RECORD_ARRAYS:
        for index, record in enumerate(model.get(collection, [])):
            if not isinstance(record, dict) or not isinstance(record.get("id"), str):
                continue
            record_id = record["id"]
            location = f"$model.{collection}[{index}].id"
            if record_id in global_ids:
                findings.append(
                    Finding(
                        "DUPLICATE_ID",
                        location,
                        f"global id {record_id} already used at {global_ids[record_id]}",
                    )
                )
            else:
                global_ids[record_id] = location
            if collection == "objects":
                nested = record.get("fields", [])
                nested_name = "fields"
            elif collection == "state_models":
                nested = record.get("transitions", [])
                nested_name = "transitions"
            else:
                nested = []
                nested_name = ""
            for nested_index, child in enumerate(nested):
                if not isinstance(child, dict) or not isinstance(child.get("id"), str):
                    continue
                child_id = child["id"]
                child_location = f"$model.{collection}[{index}].{nested_name}[{nested_index}].id"
                if child_id in global_ids:
                    findings.append(
                        Finding(
                            "DUPLICATE_ID",
                            child_location,
                            f"global id {child_id} already used at {global_ids[child_id]}",
                        )
                    )
                else:
                    global_ids[child_id] = child_location

    if id_sets.get("layers") != set(EXPECTED_REGISTRIES["layers"]):
        findings.append(
            Finding(
                "UNKNOWN_REGISTRY_VALUE",
                "$model.layers",
                "must define exactly six layers",
            )
        )

    source_bytes, source_findings = _validate_sources(model, repo_root)
    findings.extend(source_findings)
    source_authority = {
        source.get("id"): source.get("authority")
        for source in model.get("sources", [])
        if isinstance(source, dict)
    }
    findings.extend(_validate_citations(model, source_bytes, source_authority))

    actors = _record_map(model, "actors")
    objects = _record_map(model, "objects")
    outcomes = _record_map(model, "outcomes")
    blockers = _record_map(model, "blockers")
    counterexamples = _record_map(model, "counterexamples")
    sources = _record_map(model, "sources")
    layers = set(EXPECTED_REGISTRIES["layers"])
    statuses = set(EXPECTED_REGISTRIES["statuses"])
    decisions = set(EXPECTED_REGISTRIES["decisions"])
    obligations = set(EXPECTED_REGISTRIES["obligations"])

    for collection in (
        "blockers",
        "counterexamples",
        "flows",
        "invariants",
        "objects",
        "outcomes",
        "residual_risks",
        "state_models",
    ):
        for index, record in enumerate(model.get(collection, [])):
            if not isinstance(record, dict):
                continue
            if record.get("status") not in statuses:
                findings.append(
                    Finding(
                        "UNKNOWN_REGISTRY_VALUE",
                        f"$model.{collection}[{index}].status",
                        str(record.get("status")),
                    )
                )
            expected_status = EXPECTED_STATUS_BY_COLLECTION.get(collection, {}).get(
                record.get("id")
            )
            if expected_status is not None and record.get("status") != expected_status:
                findings.append(
                    Finding(
                        "FORBIDDEN_STATUS_PROMOTION",
                        f"$model.{collection}[{index}].status",
                        f"{record.get('id')} must remain {expected_status}",
                    )
                )

    for collection in (
        "actors",
        "blockers",
        "counterexamples",
        "flows",
        "invariants",
        "layers",
        "non_claims",
        "objects",
        "outcomes",
        "residual_risks",
        "review_queries",
        "state_models",
    ):
        for index, record in enumerate(model.get(collection, [])):
            if not isinstance(record, dict):
                continue
            path = f"$model.{collection}[{index}]"
            for key, registry in (
                ("decision_refs", decisions),
                ("obligation_refs", obligations),
            ):
                if key not in record:
                    continue
                values = record.get(key, [])
                findings.extend(_require_sorted_unique_strings(values, f"{path}.{key}"))
                for reference in values:
                    if reference not in registry:
                        findings.append(
                            Finding("DANGLING_REFERENCE", f"{path}.{key}", reference)
                        )
            for field_index, field in enumerate(record.get("fields", [])):
                if not isinstance(field, dict):
                    continue
                field_path = f"{path}.fields[{field_index}]"
                for key, registry in (
                    ("decision_refs", decisions),
                    ("obligation_refs", obligations),
                ):
                    if key not in field:
                        continue
                    values = field.get(key, [])
                    findings.extend(
                        _require_sorted_unique_strings(values, f"{field_path}.{key}")
                    )
                    for reference in values:
                        if reference not in registry:
                            findings.append(
                                Finding(
                                    "DANGLING_REFERENCE",
                                    f"{field_path}.{key}",
                                    reference,
                                )
                            )

            for transition_index, transition in enumerate(
                record.get("transitions", [])
            ):
                if not isinstance(transition, dict):
                    continue
                transition_path = f"{path}.transitions[{transition_index}]"
                for key, registry in (
                    ("decision_refs", decisions),
                    ("obligation_refs", obligations),
                ):
                    values = transition.get(key, [])
                    findings.extend(
                        _require_sorted_unique_strings(
                            values, f"{transition_path}.{key}"
                        )
                    )
                    for reference in values:
                        if reference not in registry:
                            findings.append(
                                Finding(
                                    "DANGLING_REFERENCE",
                                    f"{transition_path}.{key}",
                                    reference,
                                )
                            )

    for index, actor in enumerate(model.get("actors", [])):
        if not isinstance(actor, dict):
            continue
        if actor.get("owner") not in layers:
            findings.append(
                Finding(
                    "DANGLING_REFERENCE",
                    f"$model.actors[{index}].owner",
                    str(actor.get("owner")),
                )
            )
        if actor.get("trust_class") not in EXPECTED_REGISTRIES["trust_classes"]:
            findings.append(
                Finding(
                    "UNKNOWN_REGISTRY_VALUE",
                    f"$model.actors[{index}].trust_class",
                    str(actor.get("trust_class")),
                )
            )

    for object_index, obj in enumerate(model.get("objects", [])):
        if not isinstance(obj, dict):
            continue
        owner = obj.get("owner")
        if owner not in layers:
            findings.append(
                Finding(
                    "DANGLING_REFERENCE",
                    f"$model.objects[{object_index}].owner",
                    str(owner),
                )
            )
        if obj.get("status") not in statuses:
            findings.append(
                Finding(
                    "UNKNOWN_REGISTRY_VALUE",
                    f"$model.objects[{object_index}].status",
                    str(obj.get("status")),
                )
            )
        for field_index, field in enumerate(obj.get("fields", [])):
            if not isinstance(field, dict):
                continue
            path = f"$model.objects[{object_index}].fields[{field_index}]"
            if field.get("owner") not in layers:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"{path}.owner",
                        str(field.get("owner")),
                    )
                )
            if field.get("status") not in statuses:
                findings.append(
                    Finding(
                        "UNKNOWN_REGISTRY_VALUE",
                        f"{path}.status",
                        str(field.get("status")),
                    )
                )
            expected_field_status = EXPECTED_FIELD_STATUS.get(
                (obj.get("id"), field.get("id"))
            )
            if (
                expected_field_status is not None
                and field.get("status") != expected_field_status
            ):
                findings.append(
                    Finding(
                        "FORBIDDEN_STATUS_PROMOTION",
                        f"{path}.status",
                        f"must remain {expected_field_status}",
                    )
                )
            if field.get("wire_presence") not in EXPECTED_REGISTRIES["wire_presence"]:
                findings.append(
                    Finding(
                        "MISSING_PROTECTION_METADATA",
                        f"{path}.wire_presence",
                        str(field.get("wire_presence")),
                    )
                )
            if field.get("confidentiality") not in EXPECTED_REGISTRIES["confidentiality"]:
                findings.append(
                    Finding(
                        "MISSING_PROTECTION_METADATA",
                        f"{path}.confidentiality",
                        str(field.get("confidentiality")),
                    )
                )
            integrity = field.get("integrity", [])
            if not integrity or any(
                value not in EXPECTED_REGISTRIES["integrity"] for value in integrity
            ):
                findings.append(
                    Finding(
                        "MISSING_PROTECTION_METADATA",
                        f"{path}.integrity",
                        str(integrity),
                    )
                )
            findings.extend(_require_sorted_unique_strings(integrity, f"{path}.integrity"))
            for key in ("visible_to", "mutable_by"):
                values = field.get(key, [])
                findings.extend(_require_sorted_unique_strings(values, f"{path}.{key}"))
                for actor_id in values:
                    if actor_id not in actors:
                        findings.append(Finding("DANGLING_REFERENCE", f"{path}.{key}", actor_id))
            if not set(field.get("mutable_by", [])).issubset(field.get("visible_to", [])):
                findings.append(
                    Finding(
                        "VISIBILITY_MUTABILITY_MISMATCH",
                        path,
                        "every mutator must be an observer under the declared semantics",
                    )
                )
            wire_presence = field.get("wire_presence")
            integrity_set = set(integrity)
            if wire_presence == "SIGNED_TRANSCRIPT" and "SIGNED_TRANSCRIPT" not in integrity_set:
                findings.append(
                    Finding(
                        "MISSING_PROTECTION_METADATA",
                        f"{path}.integrity",
                        "signed-transcript field lacks signed-transcript integrity",
                    )
                )
            if wire_presence == "DERIVED" and "DIGEST_DERIVED" not in integrity_set:
                findings.append(
                    Finding(
                        "MISSING_PROTECTION_METADATA",
                        f"{path}.integrity",
                        "derived field lacks digest-derived integrity",
                    )
                )
            if wire_presence == "SYMBOLIC_INPUT" and field.get("status") != "SYMBOLIC":
                findings.append(
                    Finding(
                        "FORBIDDEN_STATUS_PROMOTION",
                        f"{path}.status",
                        "symbolic input must remain SYMBOLIC",
                    )
                )
            locator = (obj.get("id"), field.get("id"))
            if locator in PROTECTED_UNRESOLVED_FIELDS and field.get("status") != "UNRESOLVED":
                findings.append(
                    Finding(
                        "FORBIDDEN_STATUS_PROMOTION",
                        path,
                        f"{locator} must remain UNRESOLVED",
                    )
                )

    if "NC_SUPPORTED_ADAPTER" in _record_map(model, "non_claims"):
        for object_index, obj in enumerate(model.get("objects", [])):
            if not isinstance(obj, dict):
                continue
            for field_index, field in enumerate(obj.get("fields", [])):
                if not isinstance(field, dict):
                    continue
                path = f"$model.objects[{object_index}].fields[{field_index}]"
                if (
                    field.get("confidentiality") == "SECURE_SESSION_PROFILE"
                    or "SESSION_AUTHENTICATED" in field.get("integrity", [])
                ):
                    findings.append(
                        Finding(
                            "FORBIDDEN_STATUS_PROMOTION",
                            path,
                            "secure-session protection cannot be claimed before "
                            "a supported adapter is selected",
                        )
                    )

    for flow_index, flow in enumerate(model.get("flows", [])):
        if not isinstance(flow, dict):
            continue
        path = f"$model.flows[{flow_index}]"
        if flow.get("owner") not in layers:
            findings.append(Finding("DANGLING_REFERENCE", f"{path}.owner", str(flow.get("owner"))))
        if flow.get("status") not in statuses:
            findings.append(
                Finding(
                    "UNKNOWN_REGISTRY_VALUE",
                    f"{path}.status",
                    str(flow.get("status")),
                )
            )
        if flow.get("producer") not in actors:
            findings.append(
                Finding(
                    "DANGLING_REFERENCE",
                    f"{path}.producer",
                    str(flow.get("producer")),
                )
            )
        for key in ("consumers", "observers"):
            values = flow.get(key, [])
            findings.extend(_require_sorted_unique_strings(values, f"{path}.{key}"))
            for actor_id in values:
                if actor_id not in actors:
                    findings.append(Finding("DANGLING_REFERENCE", f"{path}.{key}", actor_id))
        for key, registry in (("object_refs", objects), ("outcomes", outcomes)):
            values = flow.get(key, [])
            findings.extend(_require_sorted_unique_strings(values, f"{path}.{key}"))
            for reference in values:
                if reference not in registry:
                    findings.append(Finding("DANGLING_REFERENCE", f"{path}.{key}", reference))
        actions = flow.get("actor_actions", [])
        action_actors = [item.get("actor") for item in actions if isinstance(item, dict)]
        if all(isinstance(actor_id, str) for actor_id in action_actors) and (
            action_actors != sorted(action_actors)
            or len(action_actors) != len(set(action_actors))
        ):
            findings.append(
                Finding(
                    "NONDETERMINISTIC_ORDER",
                    f"{path}.actor_actions",
                    "actor action records must be unique and sorted by actor",
                )
            )
        for action_index, action in enumerate(actions):
            action_path = f"{path}.actor_actions[{action_index}]"
            actor_id = action.get("actor") if isinstance(action, dict) else None
            if actor_id not in actors:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"{action_path}.actor",
                        str(actor_id),
                    )
                )
            findings.extend(
                _require_sorted_unique_strings(
                    action.get("actions", []) if isinstance(action, dict) else [],
                    f"{action_path}.actions",
                )
            )
        findings.extend(
            _require_sorted_unique_strings(
                flow.get("emitted_evidence", []), f"{path}.emitted_evidence"
            )
        )

    for index, outcome in enumerate(model.get("outcomes", [])):
        if not isinstance(outcome, dict):
            continue
        path = f"$model.outcomes[{index}]"
        if outcome.get("owner") not in layers:
            findings.append(
                Finding(
                    "DANGLING_REFERENCE",
                    f"{path}.owner",
                    str(outcome.get("owner")),
                )
            )
        if outcome.get("status") not in statuses:
            findings.append(
                Finding(
                    "UNKNOWN_REGISTRY_VALUE",
                    f"{path}.status",
                    str(outcome.get("status")),
                )
            )

    for index, invariant in enumerate(model.get("invariants", [])):
        if not isinstance(invariant, dict):
            continue
        path = f"$model.invariants[{index}]"
        if invariant.get("owner") not in layers:
            findings.append(
                Finding(
                    "DANGLING_REFERENCE",
                    f"{path}.owner",
                    str(invariant.get("owner")),
                )
            )
        for reference in invariant.get("object_refs", []):
            if reference not in objects:
                findings.append(Finding("DANGLING_REFERENCE", f"{path}.object_refs", reference))
        evidence_registry = set(counterexamples) | set(sources)
        findings.extend(
            _require_sorted_unique_strings(
                invariant.get("object_refs", []), f"{path}.object_refs"
            )
        )
        findings.extend(
            _require_sorted_unique_strings(
                invariant.get("evidence_refs", []), f"{path}.evidence_refs"
            )
        )
        for reference in invariant.get("evidence_refs", []):
            if reference not in evidence_registry:
                findings.append(Finding("DANGLING_REFERENCE", f"{path}.evidence_refs", reference))

    for index, counterexample in enumerate(model.get("counterexamples", [])):
        if not isinstance(counterexample, dict):
            continue
        path = f"$model.counterexamples[{index}]"
        if counterexample.get("owner") not in layers:
            findings.append(
                Finding(
                    "DANGLING_REFERENCE",
                    f"{path}.owner",
                    str(counterexample.get("owner")),
                )
            )
        if counterexample.get("status") not in statuses:
            findings.append(
                Finding(
                    "UNKNOWN_REGISTRY_VALUE",
                    f"{path}.status",
                    str(counterexample.get("status")),
                )
            )
        findings.extend(
            _require_sorted_unique_strings(
                counterexample.get("blocks", []), f"{path}.blocks"
            )
        )
        for reference in counterexample.get("blocks", []):
            if reference not in blockers:
                findings.append(Finding("DANGLING_REFERENCE", f"{path}.blocks", reference))

    for collection in ("blockers", "non_claims", "residual_risks", "review_queries"):
        for index, record in enumerate(model.get(collection, [])):
            if not isinstance(record, dict):
                continue
            path = f"$model.{collection}[{index}]"
            if record.get("owner") not in layers:
                findings.append(
                    Finding("DANGLING_REFERENCE", f"{path}.owner", str(record.get("owner")))
                )
            for key in ("blocks", "depends_on", "record_refs"):
                if key in record:
                    findings.extend(
                        _require_sorted_unique_strings(record.get(key, []), f"{path}.{key}")
                    )

    for index, layer in enumerate(model.get("layers", [])):
        if not isinstance(layer, dict):
            continue
        if layer.get("owner") != layer.get("id"):
            findings.append(
                Finding(
                    "DANGLING_REFERENCE",
                    f"$model.layers[{index}].owner",
                    "a responsibility layer must own its own boundary record",
                )
            )

    findings.extend(_validate_blocker_dag(blockers))
    c03 = blockers.get("C0.3")
    if c03 is None or c03.get("status") != "NO_GO":
        findings.append(
            Finding(
                "C03_GATE_MISSING",
                "$model.blockers.C0.3",
                "missing NO_GO blocker",
            )
        )
    elif not REQUIRED_C03_DEPENDENCIES.issubset(set(c03.get("depends_on", []))):
        findings.append(
            Finding(
                "C03_GATE_MISSING",
                "$model.blockers.C0.3.depends_on",
                "required blocker edge missing",
            )
        )
    if blockers.get("C0.2k", {}).get("depends_on") != ["C0.2j"]:
        findings.append(
            Finding(
                "C03_GATE_MISSING",
                "$model.blockers.C0.2k.depends_on",
                "must depend exactly on C0.2j",
            )
        )
    if blockers.get("O-06c", {}).get("depends_on") != ["C0.2k"]:
        findings.append(
            Finding(
                "C03_GATE_MISSING",
                "$model.blockers.O-06c.depends_on",
                "must depend exactly on C0.2k",
            )
        )
    if not {"C0.2k", "C0.3", "demo", "product", "sensitive_use"}.issubset(
        set(blockers.get("C0.2j", {}).get("blocks", []))
    ):
        findings.append(
            Finding(
                "C03_GATE_MISSING",
                "$model.blockers.C0.2j.blocks",
                "C0.2j must preserve the dependency and downstream safety gates",
            )
        )

    def transitively_depends_on(target: str, dependency: str) -> bool:
        pending = list(blockers.get(target, {}).get("depends_on", []))
        seen: set[str] = set()
        while pending:
            current = pending.pop()
            if current == dependency:
                return True
            if current in seen:
                continue
            seen.add(current)
            pending.extend(blockers.get(current, {}).get("depends_on", []))
        return False

    for blocker_id, blocker in blockers.items():
        for blocked_id in blocker.get("blocks", []):
            if blocked_id not in blockers and blocked_id not in EXPECTED_REGISTRIES[
                "gated_capabilities"
            ]:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"$model.blockers.{blocker_id}.blocks",
                        blocked_id,
                    )
                )
            elif blocked_id in blockers and not transitively_depends_on(
                blocked_id, blocker_id
            ):
                findings.append(
                    Finding(
                        "BLOCKER_EDGE_MISMATCH",
                        f"$model.blockers.{blocker_id}.blocks",
                        f"{blocked_id} does not depend transitively on {blocker_id}",
                    )
                )

    unresolved_gates_by_capability = {
        capability: {
            blocker_id
            for blocker_id, blocker in blockers.items()
            if blocker.get("status") != "DECIDED"
            and capability in blocker.get("blocks", [])
        }
        for capability in EXPECTED_REGISTRIES["gated_capabilities"]
    }
    for capability, unresolved_gates in sorted(
        unresolved_gates_by_capability.items()
    ):
        if not unresolved_gates:
            findings.append(
                Finding(
                    "GATED_CAPABILITY_UNBLOCKED",
                    "$model.registries.gated_capabilities",
                    f"{capability} has no non-DECIDED gate",
                )
            )

    if not REQUIRED_COUNTEREXAMPLES.issubset(id_sets.get("counterexamples", set())):
        findings.append(
            Finding(
                "REQUIRED_RECORD_MISSING",
                "$model.counterexamples",
                "required hostile witness missing",
            )
        )
    if not REQUIRED_NON_CLAIMS.issubset(id_sets.get("non_claims", set())):
        findings.append(
            Finding(
                "REQUIRED_RECORD_MISSING",
                "$model.non_claims",
                "required non-claim missing",
            )
        )
    if not REQUIRED_REVIEW_QUERIES.issubset(id_sets.get("review_queries", set())):
        findings.append(
            Finding(
                "REQUIRED_RECORD_MISSING",
                "$model.review_queries",
                "required review query missing",
            )
        )
    if not REQUIRED_INVARIANTS.issubset(id_sets.get("invariants", set())):
        findings.append(
            Finding(
                "REQUIRED_RECORD_MISSING",
                "$model.invariants",
                "required invariant missing",
            )
        )
    if not REQUIRED_RESIDUAL_RISKS.issubset(id_sets.get("residual_risks", set())):
        findings.append(
            Finding(
                "REQUIRED_RECORD_MISSING",
                "$model.residual_risks",
                "required residual risk missing",
            )
        )

    all_record_ids = set().union(*id_sets.values()) if id_sets else set()
    all_record_ids |= {
        field.get("id")
        for obj in model.get("objects", [])
        if isinstance(obj, dict)
        for field in obj.get("fields", [])
        if isinstance(field, dict) and isinstance(field.get("id"), str)
    }
    for index, query in enumerate(model.get("review_queries", [])):
        if not isinstance(query, dict):
            continue
        for reference in query.get("record_refs", []):
            if reference not in all_record_ids:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"$model.review_queries[{index}].record_refs",
                        reference,
                    )
                )

    for state_index, state_model in enumerate(model.get("state_models", [])):
        if not isinstance(state_model, dict):
            continue
        path = f"$model.state_models[{state_index}]"
        if state_model.get("owner") not in layers:
            findings.append(
                Finding(
                    "DANGLING_REFERENCE",
                    f"{path}.owner",
                    str(state_model.get("owner")),
                )
            )
        states = set(state_model.get("states", []))
        findings.extend(
            _require_sorted_unique_strings(
                state_model.get("states", []), f"{path}.states"
            )
        )
        terminal_states = state_model.get("terminal_states", [])
        findings.extend(_require_sorted_unique_strings(terminal_states, f"{path}.terminal_states"))
        for terminal_state in terminal_states:
            if terminal_state not in states:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"{path}.terminal_states",
                        terminal_state,
                    )
                )
        allowed_precedence = states | set(outcomes)
        for precedence_item in state_model.get("precedence", []):
            if precedence_item not in allowed_precedence:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"{path}.precedence",
                        precedence_item,
                    )
                )
        for transition_index, transition in enumerate(state_model.get("transitions", [])):
            if not isinstance(transition, dict):
                continue
            transition_path = f"{path}.transitions[{transition_index}]"
            if transition.get("owner") != state_model.get("owner"):
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"{transition_path}.owner",
                        "transition owner must match state-model owner",
                    )
                )
            if transition.get("status") not in statuses:
                findings.append(
                    Finding(
                        "UNKNOWN_REGISTRY_VALUE",
                        f"{transition_path}.status",
                        str(transition.get("status")),
                    )
                )
            findings.extend(
                _require_sorted_unique_strings(
                    transition.get("from", []), f"{transition_path}.from"
                )
            )
            for source_state in transition.get("from", []):
                if source_state not in states:
                    findings.append(
                        Finding(
                            "DANGLING_REFERENCE",
                            f"{transition_path}.from",
                            source_state,
                        )
                    )
            if transition.get("to") not in states:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"{transition_path}.to",
                        str(transition.get("to")),
                    )
                )
            if transition.get("outcome") not in outcomes:
                findings.append(
                    Finding(
                        "DANGLING_REFERENCE",
                        f"{transition_path}.outcome",
                        str(transition.get("outcome")),
                    )
                )

    return findings


def validate(model: Any, schema: Any, repo_root: Path) -> list[Finding]:
    findings = validate_schema_definition(schema)
    if findings:
        return sorted(findings, key=lambda item: (item.code, item.path, item.message))
    findings.extend(_schema_findings(model, schema, schema, "$model"))
    safe_model = _domain_safe_value(model, schema, schema)
    if isinstance(safe_model, dict):
        findings.extend(validate_domain(safe_model, repo_root))
        findings.extend(_validate_exact_pins(safe_model))
    return sorted(findings, key=lambda item: (item.code, item.path, item.message))


def validate_model_bytes(model: Any, model_path: Path) -> list[Finding]:
    expected = (
        json.dumps(model, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    try:
        actual = model_path.read_bytes()
    except OSError as exc:
        return [Finding("SOURCE_MISSING", "$model", str(exc))]
    if actual != expected:
        return [
            Finding(
                "NONDETERMINISTIC_ORDER",
                "$model",
                "model bytes must be canonical UTF-8 with LF and sorted keys",
            )
        ]
    return []


def validate_schema_bytes(schema_path: Path) -> list[Finding]:
    try:
        actual = _sha256(schema_path)
    except OSError as exc:
        return [Finding("SCHEMA_SNAPSHOT_DRIFT", "$schema", str(exc))]
    if actual != EXPECTED_SCHEMA_SHA256:
        return [
            Finding(
                "SCHEMA_SNAPSHOT_DRIFT",
                "$schema",
                f"expected {EXPECTED_SCHEMA_SHA256}, got {actual}",
            )
        ]
    return []


def build_report(model_path: Path, schema_path: Path, model: dict[str, Any]) -> dict[str, Any]:
    return {
        "artifact": model["artifact"]["format"],
        "c03_verdict": model["artifact"]["c03_verdict"],
        "counts": {
            "actors": len(model["actors"]),
            "blockers": len(model["blockers"]),
            "counterexamples": len(model["counterexamples"]),
            "fields": sum(len(item["fields"]) for item in model["objects"]),
            "flows": len(model["flows"]),
            "invariants": len(model["invariants"]),
            "objects": len(model["objects"]),
            "residual_risks": len(model["residual_risks"]),
            "review_queries": len(model["review_queries"]),
            "sources": len(model["sources"]),
            "state_models": len(model["state_models"]),
        },
        "model_sha256": _sha256(model_path),
        "result": "PASS",
        "schema_sha256": _sha256(schema_path),
        "source_sha256": {
            source["id"]: source["sha256"] for source in model["sources"]
        },
    }


def write_canonical_json(path: Path, value: Any) -> None:
    payload = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = -1
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _validate_output_boundary(repo_root: Path, output: Path) -> None:
    try:
        root = repo_root.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"cannot resolve --repo-root: {exc}") from exc
    if not root.is_dir():
        raise ValueError("--repo-root must resolve to a directory")
    resolved_output = output.resolve(strict=False)
    if resolved_output == root or root in resolved_output.parents:
        raise ValueError("--output must resolve outside --repo-root")


class _InputParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = _InputParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--schema", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(sys.argv[1:] if argv is None else argv)
        _validate_output_boundary(args.repo_root, args.output)
        model = load_json_unique(args.model)
        schema = load_json_unique(args.schema)
        findings = validate(model, schema, args.repo_root)
        findings.extend(validate_model_bytes(model, args.model))
        findings.extend(validate_schema_bytes(args.schema))
        findings.sort(key=lambda item: (item.code, item.path, item.message))
        if findings:
            for finding in findings:
                print(
                    f"protocol-review-model: {finding.code}: {finding.path}: {finding.message}",
                    file=sys.stderr,
                )
            return 2
        report = build_report(args.model, args.schema, model)
        try:
            write_canonical_json(args.output, report)
        except OSError as exc:
            raise ValueError(f"cannot write --output: {exc}") from exc
        print(f"protocol-review-model: PASS: {args.output}")
        return 0
    except (ValueError, DuplicateKeyError) as exc:
        print(f"protocol-review-model: INPUT_INVALID: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # fail-closed last resort at the CLI trust boundary
        print(
            f"protocol-review-model: INTERNAL_ERROR: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
