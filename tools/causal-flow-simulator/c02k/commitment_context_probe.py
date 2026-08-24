#!/usr/bin/env python3
"""Emit deterministic C0.2k exact-byte falsification evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from commitment_context_model import (
    COMMIT_BODY_SINGLE_OCTETS,
    COMMIT_BODY_TREE_OCTETS,
    COMMIT_PREIMAGE_SINGLE_OCTETS,
    COMMIT_PREIMAGE_TREE_OCTETS,
    CONTEXT_OCTETS,
    LEAF_FIXED_PREFIX_OCTETS,
    LEAF_PREIMAGE_OVERHEAD,
    MAX_LEAF_OCTETS,
    NODE_BODY_OCTETS,
    NODE_PREIMAGE_OCTETS,
    PROFILE_REVISION,
    PROTOCOL_VERSION,
    SUITE_ID,
    build_commitment,
    measure_roundtrip_work,
)
from scenarios_c02k import REQUIRED_WITNESSES, context, run_required_suite


SCHEMA = "styx-commitment-context-falsification-report/v1"
SUITE = "c0.2k-required-v1"


CANDIDATE_ANALYSIS = (
    {
        "id": "CURRENT_44_OCTET_BASELINE",
        "disposition": "REJECTED",
        "reason": "does not bind credential identifier or author sequence",
    },
    {
        "id": "RAW_AUTHENTICATED_FIELDS_84_OCTETS",
        "disposition": "SELECTED",
        "reason": "directly binds exact common fields 11 and 12 with one fixed inverse",
    },
    {
        "id": "CREDENTIAL_ONLY",
        "disposition": "REJECTED",
        "reason": "same-credential cross-sequence copy remains possible",
    },
    {
        "id": "SEQUENCE_ONLY",
        "disposition": "REJECTED",
        "reason": "cross-credential copy at equal sequence remains possible",
    },
    {
        "id": "HASH_COMPRESSED_BINDING",
        "disposition": "REJECTED",
        "reason": "adds an unnecessary derived identifier and assumption surface",
    },
    {
        "id": "COMMITMENT_BODY_ONLY",
        "disposition": "REJECTED",
        "reason": "leaf bytes remain context-copyable and violate role completeness",
    },
    {
        "id": "LEAF_BODY_ONLY",
        "disposition": "REJECTED",
        "reason": "outer commitment body omits the selected context fields",
    },
    {
        "id": "CONTAINING_EVENT_REFERENCE",
        "disposition": "REJECTED",
        "reason": "event reference authenticates the descriptor and creates a cycle",
    },
    {
        "id": "V1_PRE_CORPUS_SUPERSESSION",
        "disposition": "SELECTED",
        "reason": (
            "no released C0.3 corpus or supported consumer exists; the ratified profile "
            "already orders C0.2k before O-06c; after supersession only the 84-octet "
            "grammar is active and 44-octet input is rejected without fallback"
        ),
    },
    {
        "id": "NEW_PROTOCOL_SUITE_DOMAIN_VERSION",
        "disposition": "REJECTED_FOR_PRE_CORPUS_V0",
        "reason": (
            "unnecessary before the first corpus when the historical 44-octet grammar "
            "is never accepted; mandatory for any later incompatible post-corpus change"
        ),
    },
)


def build_report() -> tuple[dict[str, object], bool]:
    suite = run_required_suite()
    missing_witnesses = sorted(REQUIRED_WITNESSES - suite.witnesses)
    failing = [item.identifier for item in suite.checks if not item.passed]
    sample = build_commitment(
        context(),
        9,
        b"c0.2k deterministic work-counter sample",
        bytes.fromhex("a5" * 32),
        chunk_size=7,
    )
    sample_roundtrip_work = measure_roundtrip_work(sample)
    passed = not missing_witnesses and not failing
    return (
        {
            "schema": SCHEMA,
            "suite": SUITE,
            "profile_revision": PROFILE_REVISION,
            "identifier_decision": {
                "protocol_version": f"0x{PROTOCOL_VERSION:04x}",
                "commitment_suite_id": f"0x{SUITE_ID:04x}",
                "legacy_context_accepted": False,
                "mixed_profile_accepted": False,
                "migration_population": False,
            },
            "candidate_analysis": list(CANDIDATE_ANALYSIS),
            "exact_widths": {
                "context": CONTEXT_OCTETS,
                "leaf_body_prefix": LEAF_FIXED_PREFIX_OCTETS,
                "leaf_preimage_overhead": LEAF_PREIMAGE_OVERHEAD,
                "node_body": NODE_BODY_OCTETS,
                "node_preimage": NODE_PREIMAGE_OCTETS,
                "commitment_body_single": COMMIT_BODY_SINGLE_OCTETS,
                "commitment_body_tree": COMMIT_BODY_TREE_OCTETS,
                "commitment_preimage_single": COMMIT_PREIMAGE_SINGLE_OCTETS,
                "commitment_preimage_tree": COMMIT_PREIMAGE_TREE_OCTETS,
                "max_len32_safe_leaf_or_chunk": MAX_LEAF_OCTETS,
            },
            "work_counter_units": {
                "serialization_invocations": "one canonical preimage serialization",
                "parse_invocations": "one canonical preimage parse",
                "inverse_invocations": "one successful parse/inverse validation",
                "digest_invocations": "one SHA-256 call",
                "bytes_hashed": "octets supplied to SHA-256",
                "leaf_visits": "one constructed leaf preimage",
                "node_visits": "one constructed interior-node preimage",
            },
            "sample_work": {
                "serialization_invocations": (
                    sample_roundtrip_work.serialization_invocations
                ),
                "parse_invocations": sample_roundtrip_work.parse_invocations,
                "inverse_invocations": sample_roundtrip_work.inverse_invocations,
                "digest_invocations": sample_roundtrip_work.digest_invocations,
                "bytes_hashed": sample_roundtrip_work.bytes_hashed,
                "leaf_visits": sample_roundtrip_work.leaf_visits,
                "node_visits": sample_roundtrip_work.node_visits,
            },
            "required_witnesses": sorted(REQUIRED_WITNESSES),
            "observed_witnesses": sorted(suite.witnesses),
            "missing_witnesses": missing_witnesses,
            "checks": [item.record() for item in suite.checks],
            "failing_checks": failing,
            "residual_non_claims": [
                "commitment verification does not prove truth or originality",
                "a holder of content and opening can recompute under another context",
                "same-credential same-sequence siblings remain fork evidence",
                "no availability, anonymity, deletion, authority, finality or readiness claim",
            ],
            "verdict": "BOUNDED_FALSIFICATION_PASSED" if passed else "COUNTEREXAMPLE_FOUND",
        },
        passed,
    )


def canonical_bytes(value: dict[str, object]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=("required",), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report, passed = build_report()
    try:
        args.output.write_bytes(canonical_bytes(report))
    except OSError as error:
        print(f"output failure: {error}", file=sys.stderr)
        return 2
    print(
        f"C0.2k verdict={report['verdict']} "
        f"checks={len(report['checks'])} failing={len(report['failing_checks'])}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
