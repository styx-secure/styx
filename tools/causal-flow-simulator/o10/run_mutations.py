"""Kill semantic Python and JavaScript mutants for the O-10 taxonomy."""

from __future__ import annotations

import argparse
import ast
import json
import subprocess
import sys
import tempfile
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Callable

import taxonomy
from canonical_report import ReportError, canonical_bytes, store_report
from fixtures import _combine, baseline, primary_scenario
from inventory import InventoryError, load_literal, validate_inventory_value


REPORT_FIELDS = frozenset(
    {"family_counts", "killed_count", "schema", "survivor_count", "verdict"}
)


def _changed(call: Callable[[], dict[str, object]], expected: dict[str, object]) -> bool:
    try:
        return call() != expected
    except (ValueError, RuntimeError, KeyError, TypeError):
        return True


def _python_mutants() -> list[tuple[str, str, bool]]:
    results: list[tuple[str, str, bool]] = []
    for primary in sorted(taxonomy.PRIMARY_ROWS):
        scenario = primary_scenario(primary)
        expected = taxonomy.evaluate(scenario).as_dict()
        original = taxonomy.PRIMARY_ROWS[primary]
        taxonomy.PRIMARY_ROWS[primary] = (
            "K" if original[0] == "AP" else "AP",
            *original[1:],
        )
        killed = _changed(lambda: taxonomy.evaluate(scenario).as_dict(), expected)
        taxonomy.PRIMARY_ROWS[primary] = original
        results.append((f"PY_PRIMARY_{primary}", "primary", killed))

    for family_name, attribute in (
        ("k-edge", "K_PRECEDENCE"),
        ("event-edge", "EVENT_PRECEDENCE"),
    ):
        order = tuple(getattr(taxonomy, attribute))
        for index, (higher, lower) in enumerate(zip(order, order[1:])):
            if family_name == "event-edge":
                scenario = baseline(f"mutant-{family_name}-{index}")
                scenario["event_failures"] = [higher, lower]
                scenario["delivery_order"] = [higher, lower]
            else:
                scenario = _combine(
                    f"mutant-{family_name}-{index}", higher, lower, reverse=False
                )
            expected = taxonomy.evaluate(scenario).as_dict()
            mutated = list(order)
            mutated[index], mutated[index + 1] = mutated[index + 1], mutated[index]
            setattr(taxonomy, attribute, tuple(mutated))
            killed = _changed(lambda: taxonomy.evaluate(scenario).as_dict(), expected)
            setattr(taxonomy, attribute, order)
            results.append((f"PY_EDGE_{family_name}_{index:02d}", "precedence", killed))

    by_recovery: dict[str, str] = {}
    for primary, row in taxonomy.PRIMARY_ROWS.items():
        if row[3] is not None:
            by_recovery.setdefault(row[3], primary)
    for recovery, primary in sorted(by_recovery.items()):
        scenario = primary_scenario(primary)
        expected = taxonomy.evaluate(scenario).as_dict()
        original = taxonomy.PRIMARY_ROWS[primary]
        taxonomy.PRIMARY_ROWS[primary] = (*original[:3], "MUTATED_RECOVERY", *original[4:])
        killed = _changed(lambda: taxonomy.evaluate(scenario).as_dict(), expected)
        taxonomy.PRIMARY_ROWS[primary] = original
        results.append((f"PY_RECOVERY_{recovery}", "recovery", killed))
    return results


def _run_node(executable: str, adapter: Path, scenario: dict[str, object]) -> dict[str, object]:
    completed = subprocess.run(
        [executable, str(adapter)],
        input=canonical_bytes(scenario, allowed_fields=frozenset(scenario)),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=20,
    )
    if completed.returncode != 0:
        raise ValueError("mutated JavaScript adapter failed")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise ValueError("mutated JavaScript output is invalid")
    return value


def _run_python_source(
    executable: str, source: str, scenario: dict[str, object]
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="styx-o10-python-mutant-") as directory:
        root = Path(directory)
        (root / "taxonomy.py").write_text(source, encoding="utf-8")
        completed = subprocess.run(
            [
                executable,
                "-c",
                (
                    "import json,sys; from taxonomy import evaluate; "
                    "print(json.dumps(evaluate(json.load(sys.stdin)).as_dict(), "
                    "sort_keys=True, separators=(',', ':')))"
                ),
            ],
            cwd=root,
            input=canonical_bytes(scenario, allowed_fields=frozenset(scenario)),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=20,
        )
    if completed.returncode != 0:
        raise ValueError("mutated Python classifier failed")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise ValueError("mutated Python output is invalid")
    return value


def _python_stage_mutants(repo: Path) -> list[tuple[str, str, bool]]:
    source = (repo / "tools/causal-flow-simulator/o10/taxonomy.py").read_text(
        encoding="utf-8"
    )
    python = sys.executable

    def scenario(identifier: str, **updates: object) -> dict[str, object]:
        value = baseline(identifier)
        value.update(updates)
        return value

    specifications = (
        (
            "PY_STAGE_S0_K",
            '    if scenario["profile_activation_unsupported"]:\n'
            '        return _outcome("PROFILE_ACTIVATION_UNSUPPORTED", auxiliary)\n'
            "    primary = _choose(K_PRECEDENCE, set(k_failures))\n"
            "    if primary is not None:\n"
            "        return _outcome(primary, auxiliary)\n",
            "    primary = _choose(K_PRECEDENCE, set(k_failures))\n"
            "    if primary is not None:\n"
            "        return _outcome(primary, auxiliary)\n"
            '    if scenario["profile_activation_unsupported"]:\n'
            '        return _outcome("PROFILE_ACTIVATION_UNSUPPORTED", auxiliary)\n',
            scenario(
                "mutant-stage-s0-k",
                profile_activation_unsupported=True,
                k_failures=["STRUCTURAL_REJECTION"],
            ),
        ),
        (
            "PY_STAGE_K_DUPLICATE",
            "    primary = _choose(K_PRECEDENCE, set(k_failures))\n"
            "    if primary is not None:\n"
            "        return _outcome(primary, auxiliary)\n"
            '    if scenario["duplicate"]:\n'
            '        return _outcome("DUPLICATE", auxiliary)\n',
            '    if scenario["duplicate"]:\n'
            '        return _outcome("DUPLICATE", auxiliary)\n'
            "    primary = _choose(K_PRECEDENCE, set(k_failures))\n"
            "    if primary is not None:\n"
            "        return _outcome(primary, auxiliary)\n",
            scenario(
                "mutant-stage-k-duplicate",
                k_failures=["INVALID"],
                duplicate=True,
            ),
        ),
        (
            "PY_STAGE_DUPLICATE_STALE",
            '    if scenario["duplicate"]:\n'
            '        return _outcome("DUPLICATE", auxiliary)\n'
            '    if scenario["stale_evidence"]:\n'
            '        return _outcome("STALE_EVIDENCE", auxiliary)\n',
            '    if scenario["stale_evidence"]:\n'
            '        return _outcome("STALE_EVIDENCE", auxiliary)\n'
            '    if scenario["duplicate"]:\n'
            '        return _outcome("DUPLICATE", auxiliary)\n',
            scenario(
                "mutant-stage-duplicate-stale",
                duplicate=True,
                stale_evidence=True,
            ),
        ),
        (
            "PY_STAGE_STALE_S4",
            '    if scenario["stale_evidence"]:\n'
            '        return _outcome("STALE_EVIDENCE", auxiliary)\n'
            "    if s4:\n",
            "    if False and scenario[\"stale_evidence\"]:\n"
            '        return _outcome("STALE_EVIDENCE", auxiliary)\n'
            "    if s4:\n",
            scenario(
                "mutant-stage-stale-s4",
                stale_evidence=True,
                s4_failures=["CONTEXT_CAPACITY_EXHAUSTED"],
            ),
        ),
        (
            "PY_STAGE_S4_S5",
            "    if s4:\n",
            "    if False and s4:\n",
            scenario(
                "mutant-stage-s4-s5",
                s4_failures=["DEPENDENCY_DEFERRED"],
                authority_projection_unavailable=True,
            ),
        ),
        (
            "PY_STAGE_S5_EVENT",
            '    if scenario["authority_projection_unavailable"]:\n'
            '        return _outcome("AUTHORITY_PROJECTION_UNAVAILABLE", auxiliary)\n',
            '    if False and scenario["authority_projection_unavailable"]:\n'
            '        return _outcome("AUTHORITY_PROJECTION_UNAVAILABLE", auxiliary)\n',
            scenario(
                "mutant-stage-s5-event",
                authority_projection_unavailable=True,
                event_failures=["FORK_EVIDENCE"],
            ),
        ),
        (
            "PY_STAGE_EVENT_AUTHORIZATION",
            "    primary = _choose(EVENT_PRECEDENCE, set(event_failures))\n"
            "    if primary is not None:\n"
            "        return _outcome(primary, auxiliary)\n"
            '    if not scenario["authorized"]:\n'
            '        return _outcome("AUTHENTIC_BUT_UNAUTHORIZED", auxiliary)\n',
            '    if not scenario["authorized"]:\n'
            '        return _outcome("AUTHENTIC_BUT_UNAUTHORIZED", auxiliary)\n'
            "    primary = _choose(EVENT_PRECEDENCE, set(event_failures))\n"
            "    if primary is not None:\n"
            "        return _outcome(primary, auxiliary)\n",
            scenario(
                "mutant-stage-event-authorization",
                event_failures=["LINEAGE_QUARANTINED"],
                authorized=False,
            ),
        ),
        (
            "PY_STAGE_AUTHORIZATION_S6",
            '    if not scenario["authorized"]:\n'
            '        return _outcome("AUTHENTIC_BUT_UNAUTHORIZED", auxiliary)\n'
            "    if s6:\n",
            '    if False and not scenario["authorized"]:\n'
            '        return _outcome("AUTHENTIC_BUT_UNAUTHORIZED", auxiliary)\n'
            "    if s6:\n",
            scenario(
                "mutant-stage-authorization-s6",
                authorized=False,
                s6_failures=["CONTEXT_CAPACITY_EXHAUSTED"],
            ),
        ),
        (
            "PY_STAGE_S6_APPLIED",
            "    if s6:\n",
            "    if False and s6:\n",
            scenario(
                "mutant-stage-s6-applied",
                s6_failures=["DEPENDENCY_DEFERRED"],
            ),
        ),
        (
            "PY_STAGE_S6_RESOURCE_SPLIT",
            '            else "DEPENDENCY_DEFERRED"\n'
            "        )\n"
            "        return _outcome(primary, auxiliary)\n"
            '    return _outcome("APPLIED", auxiliary)\n',
            '            else "CONTEXT_CAPACITY_EXHAUSTED"\n'
            "        )\n"
            "        return _outcome(primary, auxiliary)\n"
            '    return _outcome("APPLIED", auxiliary)\n',
            scenario(
                "mutant-stage-s6-resource-split",
                s6_failures=["DEPENDENCY_DEFERRED"],
            ),
        ),
    )
    results: list[tuple[str, str, bool]] = []
    for identifier, needle, replacement, candidate in specifications:
        if source.count(needle) != 1:
            raise ValueError(f"Python stage mutation anchor drift: {identifier}")
        expected = taxonomy.evaluate(candidate).as_dict()
        mutated = source.replace(needle, replacement)
        ast.parse(mutated)
        killed = _run_python_source(python, mutated, candidate) != expected
        results.append((identifier, "stage-precedence", killed))
    return results


def _base_anchor_mutant(repo: Path) -> tuple[str, str, bool]:
    literal = load_literal(repo)
    mutated = deepcopy(literal)
    row = next(
        item
        for item in mutated["rows"]
        if item["row_id"].startswith("BASE:") and "path" in item["source"]
    )
    row["source"]["anchor"] += " [mutated]"
    try:
        validate_inventory_value(repo, mutated)
    except InventoryError:
        killed = True
    else:
        killed = False
    return ("PY_BASE_SOURCE_ANCHOR", "source-anchor", killed)


def _javascript_mutants(repo: Path, executable: str) -> list[tuple[str, str, bool]]:
    source_path = repo / "tools/causal-flow-simulator/o10/node_adapter.mjs"
    source = source_path.read_text(encoding="utf-8")
    specifications = (
        (
            "JS_K_PRECEDENCE",
            'const kOrder = ["STRUCTURAL_REJECTION", "LENGTH_MISMATCH",',
            'const kOrder = ["LENGTH_MISMATCH", "STRUCTURAL_REJECTION",',
            _combine("js-k", "STRUCTURAL_REJECTION", "LENGTH_MISMATCH", reverse=False),
        ),
        (
            "JS_REMOTE_COLLAPSE",
            '"OPAQUE_REMOTE_FAILURE"',
            '"LEAKED_REMOTE_FAILURE"',
            primary_scenario("OPENING_MISSING", "js-remote"),
        ),
        (
            "JS_RECOVERY",
            '"NO_ACTION_IDEMPOTENT", "NONE"',
            '"RETRY_AFTER_DEPENDENCY_CHANGE", "NONE"',
            primary_scenario("DUPLICATE", "js-recovery"),
        ),
        (
            "JS_S6_RESOURCE_SPLIT",
            'if (s6.length) return outcome(s6.includes("CONTEXT_CAPACITY_EXHAUSTED") ? "CONTEXT_CAPACITY_EXHAUSTED" : "DEPENDENCY_DEFERRED", auxiliary);',
            'if (s6.length) return outcome("CONTEXT_CAPACITY_EXHAUSTED", auxiliary);',
            {
                **baseline("js-s6-resource-split"),
                "s6_failures": ["DEPENDENCY_DEFERRED"],
            },
        ),
    )
    results: list[tuple[str, str, bool]] = []
    with tempfile.TemporaryDirectory(prefix="styx-o10-mutants-") as directory:
        for identifier, needle, replacement, scenario in specifications:
            if source.count(needle) != 1:
                raise ValueError(f"JavaScript mutation anchor drift: {identifier}")
            mutated_path = Path(directory) / f"{identifier}.mjs"
            mutated_path.write_text(source.replace(needle, replacement), encoding="utf-8")
            expected = taxonomy.evaluate(scenario).as_dict()
            killed = _changed(
                lambda p=mutated_path, s=scenario: _run_node(executable, p, s),
                expected,
            )
            results.append((identifier, "javascript", killed))
    return results


def build_report(repo: Path, javascript: str) -> dict[str, object]:
    results = (
        _python_mutants()
        + _python_stage_mutants(repo)
        + [_base_anchor_mutant(repo)]
        + _javascript_mutants(repo, javascript)
    )
    survivors = sorted(identifier for identifier, _, killed in results if not killed)
    if survivors:
        raise ValueError("surviving mutants: " + ",".join(survivors))
    families: Counter[str] = Counter(family for _, family, _ in results)
    return {
        "family_counts": dict(sorted(families.items())),
        "killed_count": len(results),
        "schema": "styx.o10-mutation-report.v1",
        "survivor_count": 0,
        "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--javascript", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_report(args.repo_root.resolve(), args.javascript)
        store_report(args.output, report, allowed_fields=REPORT_FIELDS)
    except (OSError, ValueError, ReportError, subprocess.TimeoutExpired) as exc:
        print(f"O-10 mutations: FAIL: {exc}", file=sys.stderr)
        return 2
    print(f"O-10 mutations: PASS killed={report['killed_count']} survivors=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
