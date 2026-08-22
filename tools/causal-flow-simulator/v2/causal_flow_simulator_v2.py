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
    obligation_witnesses = {
        obligation: sorted(
            item["id"]
            for item in suite.results
            if item["obligation"] == obligation
        )
        for obligation in sorted(C0_2F_OBLIGATIONS)
    }
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
        "evidence_accounting": {
            "executable_obligation_witnesses": obligation_witnesses,
            "delivery_permutations_are_independent_semantic_shapes": False,
            "construction_only_properties": [
                "The Python enum and dataclass definitions close the modeled vocabulary but do not prove a production parser is closed.",
                "The fixed simulator constants impose the explored bounds but do not establish safe production limits.",
                "Symbolic cryptographic values are opaque model atoms and do not establish cryptographic security.",
            ],
            "construction_only_properties_counted_as_executable_witnesses": False,
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
            "The checkpoint-evidence/replay-dependency intersection is symbolic and does not implement checkpoint authentication or acceptance.",
            "Opening withholding or loss can keep a causal subtree pending forever.",
            "Selective opening distribution can create temporary per-replica projection divergence.",
            "Any K-admitted same-author fork permanently quarantines the whole v0 AP context; this prevents authority expansion but permits an authenticated availability denial.",
            "Fork-free concurrent grant and revocation can launder successor authority in a grindable reference order; C0.2j must replace this v0 authority model.",
            "ROTATE and RECOVER are symbolic authenticated no-ops and do not model credential succession.",
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
