#!/usr/bin/env python3
"""Kill one anchored semantic mutant for every closed O-07 atom family."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import importlib.util
from pathlib import Path
import subprocess
import sys
import types

sys.dont_write_bytecode = True

O07_ROOT = Path(__file__).resolve().parent
SIMULATOR_ROOT = O07_ROOT.parent
for entry in (O07_ROOT, SIMULATOR_ROOT):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from inventory import validate_inventory  # noqa: E402
from o14.evidence_io import CanonicalJsonReport, public_failure  # noqa: E402
from report_schema import (  # noqa: E402
    MUTATION_SCHEMA,
    final_evidence_hygiene_context,
    validate_canonical_report,
)
from test_helpers.mutation_harness import mutant_still_passes  # noqa: E402


SCHEMA = MUTATION_SCHEMA
BASE_SHA = "86c3f2dbd630e445d737a25c09889de2777ee185"


@dataclass(frozen=True)
class SourceMutation:
    identifier: str
    family: str
    source_file: str
    original: str
    replacement: str
    detector_atom: str


MUTATIONS = (
    SourceMutation(
        "M_FRM_CLOSED_PROFILE_REGISTRY",
        "FRM",
        "genesis_model.py",
        "if context.application_profile_id == 0 or selected_profile not in allowed_profiles:\n        raise GenesisError(\"APPLICATION_PROFILE_REJECTED\")",
        "if False and (context.application_profile_id == 0 or selected_profile not in allowed_profiles):\n        raise GenesisError(\"APPLICATION_PROFILE_REJECTED\")",
        "A-FRM-052",
    ),
    SourceMutation(
        "M_DOM_REFERENCE_DOMAIN",
        "DOM",
        "genesis_model.py",
        "D_GENESIS_REF = 0x0004",
        "D_GENESIS_REF = 0x0003",
        "A-DOM-004",
    ),
    SourceMutation(
        "M_CER_FOREIGN_DOMAIN",
        "CER",
        "genesis_model.py",
        "if self.__domain_witness is not domain_witness:\n            raise GenesisError(\"FOREIGN_ACCEPTANCE_DOMAIN\")",
        "if self.__domain_witness is not domain_witness:\n            assertion = self.__assertion\n            return AcceptedCeremony(assertion.context, assertion.expected_genesis_reference, assertion.explicit_authorization_decision)",
        "A-CER-008",
    ),
    SourceMutation(
        "M_GAT_CROSS_GATE_SUBSTITUTION",
        "GAT",
        "genesis_model.py",
        "raise GenesisError(f\"GATE_SUBSTITUTION_{source_gate}_FOR_{target_gate}\")",
        "return None",
        "A-GAT-001",
    ),
    SourceMutation(
        "M_LIN_TERMINATED_DESCENDANT",
        "LIN",
        "genesis_model.py",
        "if projection.terminated:\n        raise GenesisError(\"DESCENDANT_AFTER_ROOT_TERMINATION\")",
        "if False and projection.terminated:\n        raise GenesisError(\"DESCENDANT_AFTER_ROOT_TERMINATION\")",
        "A-LIN-017",
    ),
    SourceMutation(
        "M_CHK_EVIDENCE_SMUGGLING",
        "CHK",
        "genesis_model.py",
        "if checkpoint_evidence_refs:\n        raise GenesisError(\"CHECKPOINT_EVIDENCE_UNSUPPORTED_V0\")",
        "if False and checkpoint_evidence_refs:\n        raise GenesisError(\"CHECKPOINT_EVIDENCE_UNSUPPORTED_V0\")",
        "A-CHK-011",
    ),
    SourceMutation(
        "M_ORD_HOSTILE_CANDIDATE_ALIAS",
        "ORD",
        "test_helpers/scenario_engine.py",
        "elif event == \"X\":\n            pending.append(hostile)",
        "elif event == \"X\":\n            pending.append(f.candidate)",
        "A-ORD-003",
    ),
)


def _load_module(source: str, identifier: str, source_path: Path) -> types.ModuleType:
    module = types.ModuleType(f"o07_mutant_{identifier}")
    module.__file__ = str(source_path)
    sys.modules[module.__name__] = module
    exec(compile(source, str(source_path), "exec"), module.__dict__)
    return module


def _mutated_module(repo_root: Path, mutation: SourceMutation) -> types.ModuleType:
    source_path = O07_ROOT / mutation.source_file
    source = source_path.read_text(encoding="utf-8")
    if source.count(mutation.original) != 1:
        raise ValueError(f"mutation anchor drift: {mutation.identifier}")
    mutated = source.replace(mutation.original, mutation.replacement, 1)
    if mutation.family == "ORD":
        module_name = f"o07_scenario_mutant_{mutation.identifier}"
        spec = importlib.util.spec_from_loader(module_name, loader=None)
        if spec is None:
            raise ValueError("cannot create scenario mutant module")
        return _load_module(mutated, mutation.identifier, source_path)
    return _load_module(mutated, mutation.identifier, source_path)


def build_report(repo_root: Path) -> tuple[dict[str, object], bool]:
    del repo_root
    inventory = validate_inventory()
    mutation_by_family = {mutation.family: mutation for mutation in MUTATIONS}
    if set(mutation_by_family) != {"FRM", "DOM", "CER", "GAT", "LIN", "CHK", "ORD"}:
        raise ValueError("semantic mutation family coverage mismatch")

    results = []
    killed_by_id: dict[str, bool] = {}
    for mutation in MUTATIONS:
        module = _mutated_module(O07_ROOT, mutation)
        survived = mutant_still_passes(module, mutation.family)
        killed = not survived
        killed_by_id[mutation.identifier] = killed
        results.append(
            {
                "mutant_id": mutation.identifier,
                "family": mutation.family,
                "source_file": mutation.source_file,
                "detector_atom": mutation.detector_atom,
                "anchor_count": 1,
                "killed": killed,
            }
        )

    relations = []
    for entry in inventory.semantic_entries:
        family = entry["atom_instance_id"].split("-")[1]
        mutation = mutation_by_family[family]
        relations.append(
            {
                "relation_id": entry["mutation_relation"],
                "atom_instance_id": entry["atom_instance_id"],
                "mutant_id": mutation.identifier,
                "detector_atom": mutation.detector_atom,
                "killed": killed_by_id[mutation.identifier],
            }
        )
    if len(relations) != 229 or len({item["relation_id"] for item in relations}) != 229:
        raise ValueError("semantic mutation relation is not exact")

    survivors = [item["mutant_id"] for item in results if not item["killed"]]
    uncovered = [item["atom_instance_id"] for item in relations if not item["killed"]]
    report = {
        "schema": SCHEMA,
        "registered_mutant_count": len(results),
        "semantic_relation_count": len(relations),
        "mutants": results,
        "relations": relations,
        "survived": survivors,
        "uncovered_atoms": uncovered,
        "verdict": "ALL_REGISTERED_MUTANTS_KILLED" if not survivors else "MUTANT_SURVIVED",
    }
    return report, not survivors and not uncovered


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--suite", required=True, choices=("required",))
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report, passed = build_report(args.repo_root.resolve())
        hygiene = final_evidence_hygiene_context(
            args.repo_root,
            BASE_SHA,
            "HEAD",
            bundle=args.bundle,
            bundle_sha256=args.bundle_sha256,
        )
        validate_canonical_report(report, hygiene_context=hygiene)
        CanonicalJsonReport.store(args.output, report)
    except (OSError, KeyError, ValueError, subprocess.CalledProcessError) as error:
        print(f"O-07 mutations failed: {public_failure(error)}", file=sys.stderr)
        return 2
    print(
        f"O-07 MUTANTS verdict={report['verdict']} "
        f"mutants={report['registered_mutant_count']} relations={report['semantic_relation_count']} "
        f"bundle_sha256={args.bundle_sha256}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
