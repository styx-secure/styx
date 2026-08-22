#!/usr/bin/env python3
"""Prove that the closed C0.2i suite kills its required source mutants."""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap

sys.dont_write_bytecode = True


V2_ROOT = Path(__file__).resolve().parent
SIMULATOR = "causal_flow_simulator_v2.py"
KERNEL = "kernel_model_v2.py"
SCENARIOS = "scenarios_v2.py"
REPORT_SCHEMA = "styx-causal-flow-mutation-report-v2"
SUITE_ID = "c0.2i-required-mutants-v1"


@dataclass(frozen=True)
class Mutant:
    identifier: str
    source: str
    before: str
    after: str
    expected_detector: str


MUTANTS = (
    Mutant(
        identifier="M01_FORK_QUARANTINE_APPLIES_NON_SIBLING",
        source=KERNEL,
        before="""        return outcomes, (), frozenset(), frozenset()\n\n    authorized = set(genesis)\n""",
        after="""        # MUTANT: continue folding non-sibling work under quarantine.\n\n    authorized = set(genesis)\n""",
        expected_detector="required-suite",
    ),
    Mutant(
        identifier="M02_STALE_VIEW_COPIES_AUTHORITY",
        source=KERNEL,
        before="""        return outcomes, (), frozenset(), frozenset()\n\n    if graph.forks:\n""",
        after="""        return outcomes, (), frozenset(genesis), frozenset()\n\n    if graph.forks:\n""",
        expected_detector="required-suite",
    ),
    Mutant(
        identifier="M03_INCREMENTAL_PENDING_DELTA_ONLY",
        source=KERNEL,
        before="""    affected = (prior_pending - updated_pending) | (\n        prior_roots - updated_roots\n    )\n""",
        after="""    affected = prior_pending - updated_pending\n""",
        expected_detector="required-suite",
    ),
    Mutant(
        identifier="M04_RETAINED_CHECKPOINT_TREATED_AS_CHECKPOINT_ONLY",
        source=KERNEL,
        before="""    checkpoint_only = set(scenario.checkpoint_evidence) - set(graph.admitted)\n    stale = bool(checkpoint_only & set(scenario.replay_dependencies))\n""",
        after="""    checkpoint_only = set(scenario.checkpoint_evidence)\n    stale = bool(checkpoint_only & set(scenario.replay_dependencies))\n""",
        expected_detector="required-suite",
    ),
    Mutant(
        identifier="M05_NAMED_ASSERTION_REPLACED_WITH_TAUTOLOGY",
        source=SCENARIOS,
        before="""        converged\n        and count == 120\n        and ordinary_fork.fork_quarantined\n        and ordinary_fork.outcomes[\"member-left\"] is Outcome.FORK_EVIDENCE\n        and ordinary_fork.outcomes[\"member-right\"] is Outcome.FORK_EVIDENCE\n        and ordinary_fork.outcomes[\"member-control\"]\n        is Outcome.FORK_QUARANTINED\n        and ordinary_fork.outcomes[\"recovery-policy\"]\n        is Outcome.FORK_QUARANTINED\n        and not ordinary_fork.authorized_credentials,\n""",
        after="""        True,\n""",
        expected_detector="assertion-registry",
    ),
    Mutant(
        identifier="M06_CURRENT_PROFILE_SILENTLY_BINDS_IDENTITY",
        source=KERNEL,
        before="""    del application_identity
""",
        after="""    commitment = commitment + application_identity
""",
        expected_detector="required-suite",
    ),
    Mutant(
        identifier="M07_NON_ANCESTRAL_GRANT_ACCEPTED",
        source=KERNEL,
        before="""        and binding.subject_credential == event.credential_id
        and binding.reference in _ancestors_of(event.reference, admitted)
""",
        after="""        and binding.subject_credential == event.credential_id
""",
        expected_detector="required-suite",
    ),
    Mutant(
        identifier="M08_STALENESS_HIDES_TERMINAL_FORK",
        source=KERNEL,
        before="""    fork_quarantined = bool(graph.forks)
""",
        after="""    fork_quarantined = bool(graph.forks) and not stale
""",
        expected_detector="required-suite",
    ),
    Mutant(
        identifier="M09_EXPECT_ERROR_CODE_CHECK_TAUTOLOGY",
        source=SCENARIOS,
        before="""            observed == code,
""",
        after="""            True,
""",
        expected_detector="assertion-registry",
    ),
    Mutant(
        identifier="M10_RETIRED_GENESIS_ASSERTION_TAUTOLOGY",
        source=SCENARIOS,
        before="""        converged
        and count == MAX_DELIVERY_PERMUTATIONS
        and takeover.fork_quarantined
        and takeover.graph.forks
        == {"g-succ", "self-revoke", "zz-a0", "zz-a1"}
        and takeover.outcomes["zz-a2"] is Outcome.FORK_QUARANTINED
        and takeover.outcomes["zz-evil0"] is Outcome.FORK_QUARANTINED
        and not takeover.applied_order
        and not takeover.authorized_credentials,
""",
        after="""        True,
""",
        expected_detector="assertion-registry",
    ),
    Mutant(
        identifier="M11_AUTHORITY_LAUNDERING_ASSERTION_TAUTOLOGY",
        source=SCENARIOS,
        before="""        grant_first_converged
        and revoke_first_converged
        and grant_first_count == 6
        and revoke_first_count == 6
        and not grant_first_projection.graph.forks
        and not revoke_first_projection.graph.forks
        and grant_first_projection.outcomes["a-evil-grant"] is Outcome.APPLIED
        and grant_first_projection.outcomes["b-evil-action"] is Outcome.APPLIED
        and grant_first_projection.authorized_credentials == {"evil", "recovery"}
        and revoke_first_projection.outcomes["z-evil-grant"]
        is Outcome.AUTHENTIC_BUT_UNAUTHORIZED
        and revoke_first_projection.outcomes["zz-evil-action"]
        is Outcome.AUTHENTIC_BUT_UNAUTHORIZED
        and revoke_first_projection.authorized_credentials == {"recovery"},
""",
        after="""        True,
""",
        expected_detector="assertion-registry",
    ),
    Mutant(
        identifier="M12_DUPLICATE_GENESIS_BINDING_ACCEPTED",
        source=KERNEL,
        before="""    if len(genesis) != len(scenario.genesis_authority):
""",
        after="""    if False and len(genesis) != len(scenario.genesis_authority):
""",
        expected_detector="required-suite",
    ),
    Mutant(
        identifier="M13_FALSE_CONTROL_ROLE_ACCEPTED",
        source=KERNEL,
        before="""    ) or (event.event_role is EventRole.CONTROL and event.kind not in CONTROL_KINDS)
""",
        after="""    ) or False
""",
        expected_detector="required-suite",
    ),
)

REQUIRED_MUTANT_IDS = frozenset(
    {
        "M01_FORK_QUARANTINE_APPLIES_NON_SIBLING",
        "M02_STALE_VIEW_COPIES_AUTHORITY",
        "M03_INCREMENTAL_PENDING_DELTA_ONLY",
        "M04_RETAINED_CHECKPOINT_TREATED_AS_CHECKPOINT_ONLY",
        "M05_NAMED_ASSERTION_REPLACED_WITH_TAUTOLOGY",
        "M06_CURRENT_PROFILE_SILENTLY_BINDS_IDENTITY",
        "M07_NON_ANCESTRAL_GRANT_ACCEPTED",
        "M08_STALENESS_HIDES_TERMINAL_FORK",
        "M09_EXPECT_ERROR_CODE_CHECK_TAUTOLOGY",
        "M10_RETIRED_GENESIS_ASSERTION_TAUTOLOGY",
        "M11_AUTHORITY_LAUNDERING_ASSERTION_TAUTOLOGY",
        "M12_DUPLICATE_GENESIS_BINDING_ACCEPTED",
        "M13_FALSE_CONTROL_ROLE_ACCEPTED",
    }
)

# This is an independent, reviewable contract for one security-critical named
# assertion.  A test that is silently weakened to ``True`` can leave every
# runtime result green; comparing the parsed predicate against this registry
# makes that source mutation observable.
ASSERTION_CONTRACTS = {
    "ordinary-fork-quarantines-independent-control": """
        converged
        and count == 120
        and ordinary_fork.fork_quarantined
        and ordinary_fork.outcomes["member-left"] is Outcome.FORK_EVIDENCE
        and ordinary_fork.outcomes["member-right"] is Outcome.FORK_EVIDENCE
        and ordinary_fork.outcomes["member-control"] is Outcome.FORK_QUARANTINED
        and ordinary_fork.outcomes["recovery-policy"] is Outcome.FORK_QUARANTINED
        and not ordinary_fork.authorized_credentials
    """,
    "copy-nonprotection": """
        left_application_identity != right_application_identity
        and copied_a_accepted
        and copied_b_accepted
        and copied_descriptor[0] == CURRENT_CTX_OCTETS
    """,
    "retired-genesis-takeover-contained": """
        converged
        and count == MAX_DELIVERY_PERMUTATIONS
        and takeover.fork_quarantined
        and takeover.graph.forks == {"g-succ", "self-revoke", "zz-a0", "zz-a1"}
        and takeover.outcomes["zz-a2"] is Outcome.FORK_QUARANTINED
        and takeover.outcomes["zz-evil0"] is Outcome.FORK_QUARANTINED
        and not takeover.applied_order
        and not takeover.authorized_credentials
    """,
    "concurrent-grant-revoke-both-reference-orders": """
        grant_first_converged
        and revoke_first_converged
        and grant_first_count == 6
        and revoke_first_count == 6
        and not grant_first_projection.graph.forks
        and not revoke_first_projection.graph.forks
        and grant_first_projection.outcomes["a-evil-grant"] is Outcome.APPLIED
        and grant_first_projection.outcomes["b-evil-action"] is Outcome.APPLIED
        and grant_first_projection.authorized_credentials == {"evil", "recovery"}
        and revoke_first_projection.outcomes["z-evil-grant"] is Outcome.AUTHENTIC_BUT_UNAUTHORIZED
        and revoke_first_projection.outcomes["zz-evil-action"] is Outcome.AUTHENTIC_BUT_UNAUTHORIZED
        and revoke_first_projection.authorized_credentials == {"recovery"}
    """,
    "content-class-separation": """
        none_projection.outcomes["class-none"] is Outcome.APPLIED
        and required_projection.outcomes["class-required"] is Outcome.PENDING_OPENING
        and detachable_projection.outcomes["class-detachable"] is Outcome.APPLIED
    """,
    "checkpoint-pending-producer": """
        retained_checkpoint.outcomes["checkpoint-hole"] is Outcome.PENDING_OPENING
        and not retained_checkpoint.stale_evidence
        and not frontier_is_producible(checkpoint_hole, ("checkpoint-hole",))
    """,
    "incremental-full": """
        resumed.semantic_view() == fresh.semantic_view()
        and resumed.metrics.earliest_replay_boundary == 0
    """,
    "independent-closure-outside-pending-subtree": """
        closure_projection.outcomes["closure-hole"] is Outcome.PENDING_OPENING
        and closure_projection.outcomes["independent-closure"] is Outcome.APPLIED
        and closure_projection.applied_order == ("independent-closure",)
    """,
    "binding-axis-closed": """
        all_observation_states == set(OpeningObservation)
    """,
    "detachable-removal": """
        removed.removed_targets == {"detachable"}
    """,
    "structural-grant-ancestry-invalid": """
        invalid_binding.outcomes["z-missing-binding"] is Outcome.INVALID
        and "a-non-ancestor-grant" in invalid_binding.graph.admitted
        and "z-missing-binding" not in invalid_binding.graph.deferred
        and "z-missing-binding" not in invalid_binding.applied_order
    """,
    "post-removal-presentation": """
        presentation_states == {
            PresentationState.REMOVED_PRESENTED_VERIFIED,
            PresentationState.REMOVED_PRESENTED_UNVERIFIABLE,
            PresentationState.REMOVED_SUBSTITUTED_REJECTED,
        }
        and removed.removed_targets == {"detachable"}
    """,
    "custody-frontier": """
        not frontier_is_producible(_scenario(flood), ("hole-9",))
        and frontier_is_producible(
            _scenario(
                flood,
                {
                    item.reference: OpeningObservation.VERIFIED
                    for item in flood
                },
            ),
            ("hole-9",),
        )
    """,
    "prefix-revocation-reconstructed": """
        prefix_incremental.semantic_view() == prefix_oracle.semantic_view()
        and prefix_incremental.outcomes["d-prefix-bob"]
        is Outcome.AUTHENTIC_BUT_UNAUTHORIZED
    """,
    "fork-pending-late-reveal": """
        pending_before.fork_quarantined
        and pending_before.pending_roots == {"pending-left"}
        and pending_before.pending == {"pending-left", "pending-child"}
        and pending_after.semantic_view() == pending_fresh.semantic_view()
        and pending_after.fork_quarantined
        and not pending_after.pending
        and pending_after.metrics.earliest_replay_boundary is None
        and pending_after.metrics.replayed_event_work == 0
    """,
    "stale-outcome-precedes-but-does-not-hide-terminal-fork": """
        stale_fork.stale_evidence
        and stale_fork.fork_quarantined
        and incremental_stale_fork.semantic_view() == stale_fork.semantic_view()
        and incremental_stale_fork.stale_evidence
        and incremental_stale_fork.fork_quarantined
        and all(
            outcome is Outcome.STALE_EVIDENCE
            for reference, outcome in stale_fork.outcomes.items()
            if reference in stale_fork.graph.admitted
        )
        and not stale_fork.applied_order
        and not stale_fork.authorized_credentials
        and not stale_fork.removed_targets
        and not frontier_is_producible(
            stale_fork_scenario, ("stale-fork-independent",)
        )
    """,
    "selective-convergence": """
        selective_a.semantic_view() != selective_b.semantic_view()
        and converged_a.semantic_view() == selective_b.semantic_view()
        and not selective_a.graph.forks
        and not selective_b.graph.forks
        and selective_a.graph.forks == selective_b.graph.forks
    """,
    "control-role-rejects-ordinary-kind": """
        false_control_projection.outcomes["false-control"]
        is Outcome.STRUCTURAL_REJECTION
        and "false-control" not in false_control_projection.pending
    """,
    "removal-target-cases": """
        none_removal.outcomes["remove-none"] is Outcome.REMOVAL_INAPPLICABLE
        and late_removal.outcomes["late-directive"] is Outcome.REMOVAL_INAPPLICABLE
        and repeated_removal.outcomes["repeat-remove"] is Outcome.ALREADY_REMOVED
    """,
    "bounded-hole-count": """
        flooded.metrics.pending_roots == MAX_EVENTS
        and counts == {"admin": MAX_EVENTS}
    """,
}

METHOD_PREDICATE_CONTRACTS = {
    "Suite.expect_error-code-match": "observed == code",
}


def canonical_bytes(value: dict[str, object]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _expression_dump(expression: ast.expr) -> str:
    return ast.dump(expression, annotate_fields=True, include_attributes=False)


def _expected_assertion_dumps() -> dict[str, str]:
    return {
        identifier: _expression_dump(
            ast.parse(f"({textwrap.dedent(source).strip()})", mode="eval").body
        )
        for identifier, source in ASSERTION_CONTRACTS.items()
    }


def _expected_method_predicate_dumps() -> dict[str, str]:
    return {
        identifier: _expression_dump(ast.parse(source, mode="eval").body)
        for identifier, source in METHOD_PREDICATE_CONTRACTS.items()
    }


def assertion_registry_violations(source_path: Path) -> tuple[str, ...]:
    tree = ast.parse(source_path.read_text(encoding="utf-8"), filename=str(source_path))
    observed: dict[str, str] = {}
    duplicates: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or len(node.args) < 2:
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr != "check":
            continue
        identifier_node = node.args[0]
        if not isinstance(identifier_node, ast.Constant) or not isinstance(
            identifier_node.value, str
        ):
            continue
        identifier = identifier_node.value
        if identifier not in ASSERTION_CONTRACTS:
            continue
        if identifier in observed:
            duplicates.add(identifier)
        observed[identifier] = _expression_dump(node.args[1])

    expected = _expected_assertion_dumps()
    violations = set(duplicates)
    violations.update(set(expected) - set(observed))
    violations.update(
        identifier
        for identifier in set(expected) & set(observed)
        if observed[identifier] != expected[identifier]
    )

    method_observed: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or node.name != "Suite":
            continue
        for method in node.body:
            if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            identifier = f"Suite.{method.name}-code-match"
            if identifier not in METHOD_PREDICATE_CONTRACTS:
                continue
            predicates = [
                call.args[1]
                for call in ast.walk(method)
                if isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and isinstance(call.func.value, ast.Name)
                and call.func.value.id == "self"
                and call.func.attr == "check"
                and len(call.args) >= 2
            ]
            if len(predicates) == 1:
                method_observed[identifier] = _expression_dump(predicates[0])

    expected_methods = _expected_method_predicate_dumps()
    violations.update(set(expected_methods) - set(method_observed))
    violations.update(
        identifier
        for identifier in set(expected_methods) & set(method_observed)
        if method_observed[identifier] != expected_methods[identifier]
    )
    return tuple(sorted(violations))


def validate_registry(mutants: tuple[Mutant, ...] = MUTANTS) -> tuple[str, ...]:
    identifiers = [mutant.identifier for mutant in mutants]
    failures: list[str] = []
    if len(identifiers) != len(set(identifiers)):
        failures.append("DUPLICATE_MUTANT_ID")
    missing = REQUIRED_MUTANT_IDS - set(identifiers)
    unknown = set(identifiers) - REQUIRED_MUTANT_IDS
    if missing:
        failures.append(f"MISSING_REQUIRED:{','.join(sorted(missing))}")
    if unknown:
        failures.append(f"UNKNOWN_MUTANT:{','.join(sorted(unknown))}")
    if any(mutant.expected_detector not in {"required-suite", "assertion-registry"} for mutant in mutants):
        failures.append("UNKNOWN_DETECTOR")
    return tuple(failures)


def _copy_and_mutate(destination: Path, mutant: Mutant) -> None:
    shutil.copytree(
        V2_ROOT,
        destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.json"),
    )
    source_path = destination / mutant.source
    source = source_path.read_text(encoding="utf-8")
    count = source.count(mutant.before)
    if count != 1:
        raise ValueError(f"{mutant.identifier}: replacement count={count}")
    source_path.write_text(source.replace(mutant.before, mutant.after, 1), encoding="utf-8")


def _run_mutant_once(mutant: Mutant, root: Path) -> dict[str, object]:
    mutated_root = root / "v2"
    _copy_and_mutate(mutated_root, mutant)
    report_path = root / "suite-report.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(mutated_root / SIMULATOR),
            "--suite",
            "required",
            "--output",
            str(report_path),
        ],
        cwd=mutated_root,
        check=False,
        capture_output=True,
        text=True,
        env={"PYTHONDONTWRITEBYTECODE": "1"},
    )
    violations = assertion_registry_violations(mutated_root / SCENARIOS)
    suite_killed = completed.returncode != 0
    assertion_killed = bool(violations)
    killed = suite_killed or assertion_killed
    detector = (
        "required-suite"
        if suite_killed
        else "assertion-registry"
        if assertion_killed
        else "none"
    )
    report_digest = (
        hashlib.sha256(report_path.read_bytes()).hexdigest()
        if report_path.is_file()
        else None
    )
    return {
        "killed": killed,
        "detector": detector,
        "expected_detector": mutant.expected_detector,
        "simulator_exit_code": completed.returncode,
        "assertion_registry_violations": list(violations),
        "simulator_report_sha256": report_digest,
    }


def build_report() -> tuple[dict[str, object], bool]:
    registry_failures = validate_registry()
    baseline_violations = assertion_registry_violations(V2_ROOT / SCENARIOS)
    results: list[dict[str, object]] = []
    deterministic = True
    execution_failure: str | None = None

    if not registry_failures and not baseline_violations:
        try:
            for mutant in MUTANTS:
                with tempfile.TemporaryDirectory() as first_directory:
                    first = _run_mutant_once(mutant, Path(first_directory))
                with tempfile.TemporaryDirectory() as second_directory:
                    second = _run_mutant_once(mutant, Path(second_directory))
                same = first == second
                deterministic = deterministic and same
                results.append(
                    {
                        "id": mutant.identifier,
                        "source": mutant.source,
                        "killed": bool(first["killed"]),
                        "detector": first["detector"],
                        "expected_detector": mutant.expected_detector,
                        "deterministic": same,
                        "simulator_exit_code": first["simulator_exit_code"],
                        "assertion_registry_violations": first[
                            "assertion_registry_violations"
                        ],
                        "simulator_report_sha256": first[
                            "simulator_report_sha256"
                        ],
                    }
                )
        except (OSError, ValueError) as error:
            execution_failure = str(error)

    killed_ids = {item["id"] for item in results if item["killed"]}
    passed = (
        not registry_failures
        and not baseline_violations
        and execution_failure is None
        and deterministic
        and killed_ids == REQUIRED_MUTANT_IDS
        and len(results) == len(REQUIRED_MUTANT_IDS)
        and all(item["detector"] == item["expected_detector"] for item in results)
    )
    report: dict[str, object] = {
        "schema": REPORT_SCHEMA,
        "suite": SUITE_ID,
        "source_sha256": {
            name: hashlib.sha256((V2_ROOT / name).read_bytes()).hexdigest()
            for name in (SIMULATOR, KERNEL, SCENARIOS)
        },
        "closed_registry": {
            "required_mutants": sorted(REQUIRED_MUTANT_IDS),
            "complete_and_exact": not registry_failures,
            "failures": list(registry_failures),
        },
        "baseline_assertion_registry_violations": list(baseline_violations),
        "results": sorted(results, key=lambda item: str(item["id"])),
        "detector_counts": {
            detector: sum(1 for item in results if item["detector"] == detector)
            for detector in ("required-suite", "assertion-registry", "none")
        },
        "deterministic": deterministic,
        "execution_failure": execution_failure,
        "verdict": "ALL_REQUIRED_MUTANTS_KILLED" if passed else "MUTATION_GATE_FAILED",
    }
    return report, passed


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
        "C0.2i MUTATION GATE "
        f"verdict={report['verdict']} "
        f"killed={sum(1 for item in report['results'] if item['killed'])}/"
        f"{len(REQUIRED_MUTANT_IDS)}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
