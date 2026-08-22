#!/usr/bin/env python3
"""Emit deterministic C0.2i pending-subtree falsification evidence."""

from __future__ import annotations

import sys

sys.dont_write_bytecode = True

import argparse
import json
from pathlib import Path

from kernel_model_v2 import MODEL_ID, SCHEMA_ID
from scenarios_v2 import (
    BOUNDS,
    C0_2D_FAMILIES,
    C0_2F_OBLIGATIONS,
    C0_2I_FAMILIES,
    run_required_suite,
)


BASE_SHA = "468e822d7c7113ccceeea339eede27ec56f12ab3"


def build_report() -> tuple[dict[str, object], bool]:
    suite = run_required_suite()
    failures = [item for item in suite.results if not item["passed"]]
    failures.sort(
        key=lambda item: (
            len(item["trace"]),
            tuple(item["trace"]),
            item["id"],
        )
    )
    complete = (
        set(suite.obligation_counts) == C0_2F_OBLIGATIONS
        and all(suite.obligation_counts.values())
        and (C0_2D_FAMILIES | C0_2I_FAMILIES) <= set(suite.family_counts)
    )
    passed = not failures and complete
    report: dict[str, object] = {
        "schema": SCHEMA_ID,
        "model_version": MODEL_ID,
        "exact_base_sha": BASE_SHA,
        "bounded_search_envelope": BOUNDS,
        "closed_registry": {
            "c0_2d_families": sorted(C0_2D_FAMILIES),
            "c0_2f_obligations": sorted(C0_2F_OBLIGATIONS),
            "c0_2i_families": sorted(C0_2I_FAMILIES),
            "complete_and_non_empty": complete,
        },
        "exploration": {
            "invariant_evaluations": len(suite.results),
            "delivery_traces": suite.explored_traces,
            "scenario_counts": dict(sorted(suite.family_counts.items())),
            "obligation_check_counts": dict(
                sorted(suite.obligation_counts.items())
            ),
        },
        "instrumentation": {
            "maximum_pending_roots": suite.max_pending_roots,
            "maximum_pending_descendants": suite.max_pending_descendants,
            "maximum_replayed_event_work": suite.max_replayed_work,
            "earliest_replay_boundary": suite.earliest_replay_boundary,
        },
        "invariants": sorted(suite.results, key=lambda item: item["id"]),
        "smallest_failing_trace": failures[0] if failures else None,
        "excluded_inputs": [
            {
                "code": "CREDENTIAL_IDENTIFIER_COLLISION_UNSUPPORTED",
                "reason": (
                    "The runtime classification is a declared fail-closed denial "
                    "of service. Inputs with multiple K-valid bindings are rejected "
                    "before positive exploration and are excluded from every "
                    "NO_COUNTEREXAMPLE_WITHIN_BOUNDS claim."
                ),
            }
        ],
        "non_claims": [
            "Bounded falsification is not a proof or conformance corpus.",
            "No production algorithm, bound, stable error code, wire format, cryptographic suite, finality rule, or irreversible-effect authority is selected.",
            "Checkpoint evidence never substitutes for retained authenticated replay history.",
            "Opening withholding or loss can keep a causal subtree pending forever.",
            "Selective opening distribution can create temporary per-replica projection divergence.",
            "The current 44-octet commitment context does not prevent cross-credential descriptor copy or same-credential cross-sequence self-copy.",
            "A verified commitment does not prove possession at commit time, knowledge, truthful authorship, originality, first submission, or semantic truth.",
            "Credential-identifier collision has no safe-continuation claim and blocks C0.3, demo, product, and sensitive pilot work until C0.2j.",
            "C0.2k must amend the commitment context after C0.2j; O-06c remains a later mandatory gate.",
        ],
        "verdict": "NO_COUNTEREXAMPLE_WITHIN_BOUNDS" if passed else "COUNTEREXAMPLE_FOUND",
    }
    return report, passed


def canonical_bytes(report: dict[str, object]) -> bytes:
    return (
        json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


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
    exploration = report["exploration"]
    print(
        "PENDING SUBTREE FALSIFICATION "
        f"verdict={report['verdict']} "
        f"invariants={exploration['invariant_evaluations']} "
        f"traces={exploration['delivery_traces']}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
