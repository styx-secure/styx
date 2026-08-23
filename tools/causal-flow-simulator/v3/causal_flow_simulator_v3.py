#!/usr/bin/env python3
"""Emit deterministic bounded C0.2j credential-succession evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from protocol_model_v3 import MODEL_ID, SCHEMA_ID
from scenarios_v3 import (
    BOUNDS,
    REQUIRED_MUTANTS,
    REQUIRED_WITNESSES,
    mutation_coverage,
    run_required_suite,
)


BASE_SHA = "8f30f1940e4417fcb47b156b08c2242f405dc09b"


def build_report() -> tuple[dict[str, object], bool]:
    suite = run_required_suite()
    checks = sorted((item.record() for item in suite.checks), key=lambda item: item["id"])
    failures = [item for item in checks if not item["passed"]]
    coverage = mutation_coverage()
    complete = (
        suite.witnesses == REQUIRED_WITNESSES
        and set(coverage) == REQUIRED_MUTANTS
        and all(coverage.values())
    )
    passed = complete and not failures
    report: dict[str, object] = {
        "schema": SCHEMA_ID,
        "model_version": MODEL_ID,
        "exact_base_sha": BASE_SHA,
        "bounded_search_envelope": BOUNDS,
        "replay_strategy": {
            "selected": "FRESH_FULL_REPLAY_ONLY",
            "incremental_reuse": False,
            "reason": "bounded multi-state authority projection invalidates the v2 prefix-cache handoff and v3 does not prove a byte-identical complete authority-state boundary",
        },
        "closed_coverage": {
            "required_witnesses": sorted(REQUIRED_WITNESSES),
            "observed_witnesses": sorted(suite.witnesses),
            "required_mutants": sorted(REQUIRED_MUTANTS),
            "complete_and_non_empty": complete,
        },
        "exploration": {
            "directed_assertions": len(checks),
            "projection_runs": len(suite.projections),
            "maximum_topological_orders": max(
                (projection.explored_orders for projection in suite.projections),
                default=0,
            ),
            "maximum_reachable_authority_states": max(
                (
                    projection.reachable_authority_states
                    for projection in suite.projections
                ),
                default=0,
            ),
            "maximum_authority_transitions": max(
                (projection.authority_transitions for projection in suite.projections),
                default=0,
            ),
            "maximum_replayed_event_work": max(
                (projection.replayed_event_work for projection in suite.projections),
                default=0,
            ),
            "maximum_observed_lineage_depth": max(
                (projection.max_lineage_depth for projection in suite.projections),
                default=0,
            ),
        },
        "witness_to_assertions_and_mutants": {
            witness: {
                "assertions": sorted(
                    item.identifier for item in suite.checks if item.family == witness
                ),
                "mutants": sorted(
                    {
                        mutant
                        for item in suite.checks
                        if item.family == witness
                        for mutant in item.kills
                    }
                ),
            }
            for witness in sorted(REQUIRED_WITNESSES)
        },
        "mutant_to_killing_witnesses": coverage,
        "invariants": checks,
        "smallest_failing_trace": failures[0] if failures else None,
        "superseded_v2_assertions": [
            "whole-context fork quarantine is replaced by credential-lineage quarantine with independent-authority continuation",
            "prefix-local grant-before-revoke authority is replaced by Pass0 Must0 expansion plus bounded first-contested-slot reduction",
            "non-transitive v2 revocation is replaced by bounded provenance termination",
            "ROTATE and RECOVER are no longer modeled as authority-neutral placeholders; they are constrained to fresh-GRANT succession and may never create or resurrect a binding",
            "v2 incremental prefix reuse is not inherited; v3 uses fresh full replay only",
        ],
        "retained_c0_2i_properties": [
            "REQUIRED opening failure marks the event and its causal descendants pending without changing K admission",
            "content bytes never substitute across commitments or events",
            "checkpoint-only evidence remains stale and never substitutes for retained authenticated history",
            "K-admitted authority evidence remains in the authority set even when AP-pending, inapplicable, removed, post-revocation or authentic-but-unauthorized",
        ],
        "non_claims": [
            "Bounded falsification is not a mathematical proof, production implementation, conformance corpus or audit.",
            "The symbolic reference function does not establish SHA-256 collision or second-preimage security.",
            "The selected envelope is a common experiment bound, not a production O-08 limit.",
            "One uncontested compromised authority can still remove every peer and remain sole operational authority.",
            "Revocation of one credential does not revoke an independently granted byte-identical key alias.",
            "Grant-rooted identifiers expose their binding grant and are not unlinkability evidence.",
            "No checkpoint freshness, rollback, finality, irreversible-effect, anonymity or sensitive-use claim is made.",
            "O-07, O-08, O-10, O-14, C0.2k, O-06c and C0.3 remain open or blocked as recorded by the normative registry.",
        ],
        "verdict": "NO_COUNTEREXAMPLE_WITHIN_BOUNDS" if passed else "COUNTEREXAMPLE_FOUND",
    }
    return report, passed


def canonical_bytes(value: dict[str, object]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--suite", choices=("required",), required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    report, passed = build_report()
    try:
        Path(args.output).write_bytes(canonical_bytes(report))
    except OSError as error:
        print(f"output failure: {error}", file=sys.stderr)
        return 2
    print(
        "CREDENTIAL SUCCESSION FALSIFICATION "
        f"verdict={report['verdict']} "
        f"assertions={report['exploration']['directed_assertions']} "
        f"projections={report['exploration']['projection_runs']}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
