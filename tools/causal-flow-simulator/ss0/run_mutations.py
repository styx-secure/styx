#!/usr/bin/env python3
"""Kill the closed SS-0 source-mutant registry one mutant at a time."""

from __future__ import annotations

import argparse
import sys
import types
from pathlib import Path
from typing import Any

from canonical_report import canonical_bytes, store
from inventory import load_unique, validate_inventory
from model import evaluate


REQUIRED_REQUIREMENTS = frozenset(
    {
        *(f"SSD-{index:02d}" for index in range(1, 12)),
        "X-APPLICATION-SELECTOR",
        "X-APPLY-WITHOUT-ATOMIC",
        "X-CIPHERSUITE-FALLBACK",
        "X-DECRYPTION-AP-AUTHORITY",
        "X-DIAGNOSTIC-LEAKAGE",
        "X-FORK-EXPANSION",
        "X-IANA-STYX-SUITE-SUBSTITUTION",
        "X-INDETERMINATE-COMMITTED",
        "X-INDETERMINATE-NOT-COMMITTED",
        "X-LASTRESORT-ACCEPTANCE",
        "X-LOSER-PROMOTION-RESTART",
        "X-MEMBERSHIP-AP-ROLE",
        "X-PIN-FALLBACK",
        "X-REPLAY-DUPLICATE-OUTPUT",
        "X-RETENTION-OFF-BY-ONE-FIVE",
        "X-RETENTION-OFF-BY-ONE-SIX",
        "X-REUSE-AFTER-REPLAY",
        "X-REUSE-AFTER-ROLLBACK",
        "X-SESSION-EPOCH-K-ORDER",
        "X-TIP-RULE-DELETION",
        "X-WELCOME-MEMBER-MISMATCH",
        "X-WELCOME-PROFILE-MISMATCH",
    }
)


def _mutated_evaluate(source: str, identity: str) -> Any:
    module_name = f"_styx_ss0_mutant_{identity.replace('-', '_')}"
    module = types.ModuleType(module_name)
    module.__file__ = f"{module_name}.py"
    sys.modules[module_name] = module
    try:
        exec(compile(source, module.__file__, "exec"), module.__dict__)
        return module.evaluate
    finally:
        sys.modules.pop(module_name, None)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    root = arguments.root.resolve(strict=True)
    package = root / "tools/causal-flow-simulator/ss0"
    cases = {
        case["id"]: case
        for case in validate_inventory(load_unique(package / "source-inventory.json"))
    }
    registry = load_unique(package / "source-mutants.json")
    if set(registry) != {"mutants", "schema"} or registry["schema"] != "styx.ss0.mutants.v1":
        raise ValueError("mutant registry shape mismatch")
    mutants = registry["mutants"]
    if not isinstance(mutants, list) or [row.get("id") for row in mutants] != sorted(
        row.get("id") for row in mutants
    ):
        raise ValueError("mutant registry order mismatch")
    if {row.get("requirement") for row in mutants} != REQUIRED_REQUIREMENTS:
        raise ValueError("mutant requirement coverage mismatch")
    model_source = (package / "model.py").read_text(encoding="utf-8")
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for mutant in mutants:
        if not isinstance(mutant, dict) or set(mutant) != {
            "detector", "id", "replacement", "requirement", "target"
        }:
            raise ValueError("mutant shape mismatch")
        identity = mutant["id"]
        if identity in seen or mutant["detector"] not in cases:
            raise ValueError("duplicate mutant or missing detector")
        seen.add(identity)
        target = mutant["target"].replace("\\n", "\n")
        replacement = mutant["replacement"].replace("\\n", "\n")
        if model_source.count(target) != 1 or target == replacement:
            raise ValueError(f"mutant anchor mismatch: {identity}")
        detector = cases[mutant["detector"]]
        baseline = evaluate(detector["input"])
        if baseline["disposition"] != detector["expected"]:
            raise ValueError(f"baseline detector mismatch: {identity}")
        mutated_source = model_source.replace(target, replacement, 1)
        mutated = _mutated_evaluate(mutated_source, identity)(detector["input"])
        if mutated == baseline:
            raise ValueError(f"surviving mutant: {identity}")
        try:
            canonical_bytes(
                {
                    "observation": mutated,
                    "result": "MUTANT_OBSERVATION",
                    "schema": "styx.ss0.mutant-observation.v1",
                }
            )
            canonical_boundary = "ACCEPTED"
        except ValueError:
            canonical_boundary = "REJECTED"
        if mutant["requirement"] == "X-DIAGNOSTIC-LEAKAGE" and canonical_boundary != "REJECTED":
            raise ValueError("diagnostic leakage survived canonical boundary")
        rows.append(
            {
                "detector": mutant["detector"],
                "id": identity,
                "killed": True,
                "requirement": mutant["requirement"],
            }
        )
    store(
        {
            "killed": len(rows),
            "mutants": rows,
            "result": "PASS",
            "schema": "styx.ss0.mutation-report.v1",
        },
        arguments.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
