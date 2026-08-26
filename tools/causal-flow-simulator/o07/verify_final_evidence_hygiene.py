#!/usr/bin/env python3
"""Regenerate and validate two complete O-07 canonical-report runs."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


sys.dont_write_bytecode = True

O07_ROOT = Path(__file__).resolve().parent
if str(O07_ROOT) not in sys.path:
    sys.path.insert(0, str(O07_ROOT))

from inventory import ValidatedInventory, validate_inventory  # noqa: E402
from report_schema import (  # noqa: E402
    CROSS_RUNTIME_SCHEMA,
    MUTATION_SCHEMA,
    PROBE_SCHEMA,
    SCOPE_SCHEMA,
    FinalEvidenceIdentityContext,
    final_evidence_hygiene_context,
    validate_canonical_report,
    verify_clean_checkout,
)
from run_mutations import MUTATIONS  # noqa: E402


BASE_SHA = "86c3f2dbd630e445d737a25c09889de2777ee185"
FAMILIES = ("probe", "runtime", "mutations", "scope")
SCHEMA_BY_FAMILY = {
    "probe": PROBE_SCHEMA,
    "runtime": CROSS_RUNTIME_SCHEMA,
    "mutations": MUTATION_SCHEMA,
    "scope": SCOPE_SCHEMA,
}


@dataclass(frozen=True)
class RunDescriptor:
    """External provenance for one complete report run."""

    repo: Path
    evidence: Path
    probe: Path
    runtime: Path
    mutations: Path
    scope: Path

    def reports(self) -> dict[str, Path]:
        return {family: getattr(self, family) for family in FAMILIES}


def _git(repo: Path, *arguments: str, check: bool = True) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def _canonical_bytes(report: dict[str, object]) -> bytes:
    return (
        json.dumps(report, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def _contained_regular_file(path: Path, root: Path) -> Path:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("evidence root must be a real directory")
    if path.is_symlink():
        raise ValueError("report must not be a symlink")
    resolved_root = root.resolve(strict=True)
    resolved_path = path.resolve(strict=True)
    if not resolved_path.is_relative_to(resolved_root):
        raise ValueError("report is outside its named evidence root")
    if not resolved_path.is_file():
        raise ValueError("report must be a regular file")
    return resolved_path


def _git_directories(repo: Path) -> tuple[Path, Path]:
    git_dir = Path(_git(repo, "rev-parse", "--absolute-git-dir").decode().strip()).resolve()
    common = Path(_git(repo, "rev-parse", "--git-common-dir").decode().strip())
    if not common.is_absolute():
        common = repo / common
    return git_dir, common.resolve()


def _outside(path: Path, boundaries: tuple[Path, ...]) -> bool:
    return all(path != boundary and not path.is_relative_to(boundary) for boundary in boundaries)


def _validate_run_roots(
    run_one: RunDescriptor,
    run_two: RunDescriptor,
    *,
    base: str,
    candidate: str,
) -> tuple[RunDescriptor, RunDescriptor]:
    repos = (verify_clean_checkout(run_one.repo), verify_clean_checkout(run_two.repo))
    if repos[0] == repos[1]:
        raise ValueError("two distinct checkout roots are required")
    script_repo = O07_ROOT.parents[2].resolve()
    if script_repo not in repos:
        raise ValueError("final gate must execute from one named clean checkout")

    expected_base = _git(repos[0], "rev-parse", f"{base}^{{commit}}").decode().strip()
    expected_candidate = _git(repos[0], "rev-parse", f"{candidate}^{{commit}}").decode().strip()
    if expected_base != BASE_SHA:
        raise ValueError("ratified Base mismatch")
    for repo in repos:
        observed_candidate = _git(repo, "rev-parse", "HEAD^{commit}").decode().strip()
        observed_base = _git(repo, "rev-parse", f"{base}^{{commit}}").decode().strip()
        if observed_candidate != expected_candidate or observed_base != expected_base:
            raise ValueError("checkout Base/HEAD mismatch")
        if subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "merge-base",
                "--is-ancestor",
                expected_base,
                expected_candidate,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).returncode != 0:
            raise ValueError("Base is not an ancestor of candidate")

    evidence_roots = (
        run_one.evidence.resolve(strict=True),
        run_two.evidence.resolve(strict=True),
    )
    if evidence_roots[0] == evidence_roots[1]:
        raise ValueError("two distinct evidence roots are required")
    metadata = tuple(item for repo in repos for item in _git_directories(repo))
    boundaries = tuple(dict.fromkeys((*repos, *metadata)))
    for evidence in evidence_roots:
        if not _outside(evidence, boundaries):
            raise ValueError("evidence root overlaps a checkout or Git metadata")

    normalized: list[RunDescriptor] = []
    used_reports: set[Path] = set()
    for descriptor, repo, evidence in zip(
        (run_one, run_two), repos, evidence_roots, strict=True
    ):
        report_paths: dict[str, Path] = {}
        for family, path in descriptor.reports().items():
            report = _contained_regular_file(path, evidence)
            if report in used_reports:
                raise ValueError("report path reused across runs or families")
            used_reports.add(report)
            report_paths[family] = report
        normalized.append(RunDescriptor(repo=repo, evidence=evidence, **report_paths))
    return normalized[0], normalized[1]


def _relation(entry: dict[str, object]) -> tuple[str, str]:
    return str(entry["atom_instance_id"]), str(entry["scenario_instance_id"])


def _validate_probe_content(
    report: dict[str, object], inventory: ValidatedInventory
) -> None:
    expected_semantic = {_relation(entry): entry for entry in inventory.semantic_entries}
    expected_gates = {
        (str(entry["atom_instance_id"]), str(entry["scenario_instance_id"]))
        for entry in inventory.gate_entries
    }
    cases = report["semantic_cases"]
    gates = report["external_gates"]
    assert isinstance(cases, list) and isinstance(gates, list)
    observed_cases = {_relation(item): item for item in cases}
    observed_gates = {
        (str(item["atom_instance_id"]), str(item["gate_instance_id"]))
        for item in gates
    }
    if (
        report["inventory_relation_count"] != 287
        or report["semantic_atom_count"] != 229
        or report["external_gate_count"] != 58
        or len(observed_cases) != len(cases)
        or set(observed_cases) != set(expected_semantic)
        or len(observed_gates) != len(gates)
        or observed_gates != expected_gates
    ):
        raise ValueError("Probe inventory relation is not exact")
    for relation, entry in expected_semantic.items():
        case = observed_cases[relation]
        for field in ("assertion_id", "observation_id", "expected_disposition"):
            if case[field] != entry[field]:
                raise ValueError("Probe semantic metadata mismatch")
        if (
            case["observed_disposition"] != entry["expected_disposition"]
            or case["passed"] is not True
        ):
            raise ValueError("Probe contains a falsified semantic result")
    if (
        report["failed_semantic_atoms"] != []
        or report["semantic_verdict"] != "PASS"
        or report["final_o07_gate"] != "NOT_EVALUATED_BY_THIS_PROBE"
    ):
        raise ValueError("Probe verdict is not passing")


def _validate_runtime_content(
    report: dict[str, object], inventory: ValidatedInventory
) -> None:
    expected = {_relation(entry): entry for entry in inventory.semantic_entries}
    comparisons = report["comparisons"]
    assert isinstance(comparisons, list)
    observed = {_relation(item): item for item in comparisons}
    if (
        report["adapter_count"] != 2
        or report["semantic_atom_count"] != 229
        or len(observed) != len(comparisons)
        or set(observed) != set(expected)
    ):
        raise ValueError("cross-runtime relation is not exact")
    for relation, entry in expected.items():
        comparison = observed[relation]
        for field in ("assertion_id", "observation_id", "expected_disposition"):
            if comparison[field] != entry[field]:
                raise ValueError("cross-runtime semantic metadata mismatch")
        for adapter in ("python", "javascript"):
            result = comparison[adapter]
            if result["disposition"] != entry["expected_disposition"]:
                raise ValueError("cross-runtime disposition is falsified")
        if comparison["exact"] is not True:
            raise ValueError("cross-runtime comparison is not exact")
    if report["failed"] != [] or report["verdict"] != "PASS":
        raise ValueError("cross-runtime verdict is not passing")


def _validate_mutation_content(
    report: dict[str, object], inventory: ValidatedInventory
) -> None:
    expected_mutants = {mutation.identifier: mutation for mutation in MUTATIONS}
    mutants = report["mutants"]
    relations = report["relations"]
    assert isinstance(mutants, list) and isinstance(relations, list)
    observed_mutants = {str(item["mutant_id"]): item for item in mutants}
    observed_relations = {str(item["relation_id"]): item for item in relations}
    expected_relations = {
        str(entry["mutation_relation"]): entry for entry in inventory.semantic_entries
    }
    if (
        report["registered_mutant_count"] != 7
        or report["semantic_relation_count"] != 229
        or len(observed_mutants) != len(mutants)
        or set(observed_mutants) != set(expected_mutants)
        or len(observed_relations) != len(relations)
        or set(observed_relations) != set(expected_relations)
    ):
        raise ValueError("mutation registry relation is not exact")
    for identifier, mutation in expected_mutants.items():
        item = observed_mutants[identifier]
        if (
            item["family"] != mutation.family
            or item["source_file"] != mutation.source_file
            or item["detector_atom"] != mutation.detector_atom
            or item["anchor_count"] != 1
            or item["killed"] is not True
        ):
            raise ValueError("mutant result is falsified")
    mutation_by_family = {mutation.family: mutation for mutation in MUTATIONS}
    for relation_id, entry in expected_relations.items():
        item = observed_relations[relation_id]
        mutation = mutation_by_family[str(entry["atom_instance_id"]).split("-")[1]]
        if (
            item["atom_instance_id"] != entry["atom_instance_id"]
            or item["mutant_id"] != mutation.identifier
            or item["detector_atom"] != mutation.detector_atom
            or item["killed"] is not True
        ):
            raise ValueError("mutation relation result is falsified")
    if (
        report["survived"] != []
        or report["uncovered_atoms"] != []
        or report["verdict"] != "ALL_REGISTERED_MUTANTS_KILLED"
    ):
        raise ValueError("mutation verdict is not passing")


def _load_report(
    path: Path,
    family: str,
    hygiene: FinalEvidenceIdentityContext,
    inventory: ValidatedInventory,
) -> tuple[dict[str, object], bytes]:
    raw = path.read_bytes()
    report = json.loads(raw)
    validated = validate_canonical_report(report, hygiene_context=hygiene)
    if validated["schema"] != SCHEMA_BY_FAMILY[family]:
        raise ValueError("report family/schema substitution")
    if raw != _canonical_bytes(validated):
        raise ValueError("non-canonical report bytes")
    if family == "probe":
        _validate_probe_content(validated, inventory)
    elif family == "runtime":
        _validate_runtime_content(validated, inventory)
    elif family == "mutations":
        _validate_mutation_content(validated, inventory)
    return validated, raw


def _regenerate(
    *,
    repo: Path,
    family: str,
    output: Path,
    workspace_root: Path,
    base: str,
    candidate: str,
    bundle: Path,
    bundle_sha256: str,
) -> None:
    common = [
        "--repo-root",
        str(repo),
        "--bundle",
        str(bundle),
        "--bundle-sha256",
        bundle_sha256,
    ]
    script = repo / "tools/causal-flow-simulator/o07"
    if family == "probe":
        command = [
            sys.executable,
            str(script / "run_genesis_checkpoint_probe.py"),
            *common,
            "--suite",
            "required",
            "--output",
            str(output),
        ]
    elif family == "runtime":
        javascript = shutil.which("node")
        if javascript is None:
            raise ValueError("required JavaScript runtime unavailable")
        command = [
            sys.executable,
            str(script / "run_cross_runtime.py"),
            *common,
            "--suite",
            "required",
            "--javascript",
            javascript,
            "--workspace",
            str(workspace_root / "runtime-workspace"),
            "--output",
            str(output),
        ]
    elif family == "mutations":
        command = [
            sys.executable,
            str(script / "run_mutations.py"),
            *common,
            "--suite",
            "required",
            "--output",
            str(output),
        ]
    elif family == "scope":
        command = [
            sys.executable,
            str(script / "scope_guard_o07.py"),
            *common,
            "--base",
            base,
            "--candidate",
            candidate,
            "--mode",
            "strict",
            "--output",
            str(output),
        ]
    else:
        raise ValueError("unknown report family")
    subprocess.run(command, cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def validate_final_reports(
    *,
    base: str,
    candidate: str,
    bundle: Path,
    bundle_sha256: str,
    run_one: RunDescriptor,
    run_two: RunDescriptor,
) -> str:
    """Require two clean, independently reproducible complete O-07 runs."""

    run_one, run_two = _validate_run_roots(run_one, run_two, base=base, candidate=candidate)
    inventory = validate_inventory()
    submitted: dict[tuple[int, str], bytes] = {}
    for run_index, run in enumerate((run_one, run_two), start=1):
        hygiene = final_evidence_hygiene_context(
            run.repo,
            base,
            candidate,
            bundle=bundle,
            bundle_sha256=bundle_sha256,
        )
        for family, path in run.reports().items():
            _, raw = _load_report(path, family, hygiene, inventory)
            submitted[(run_index, family)] = raw

    for family in FAMILIES:
        if submitted[(1, family)] != submitted[(2, family)]:
            raise ValueError(f"two-checkout report mismatch: {family}")

    with tempfile.TemporaryDirectory(prefix="styx-o07-final-gate-") as temporary:
        gate_root = Path(temporary).resolve()
        boundaries = (run_one.repo, run_two.repo, run_one.evidence, run_two.evidence)
        if not _outside(gate_root, boundaries):
            raise ValueError("gate temporary root overlaps submitted state")
        for run_index, run in enumerate((run_one, run_two), start=1):
            for family in FAMILIES:
                family_root = gate_root / f"run-{run_index}-{family}"
                family_root.mkdir()
                regenerated = family_root / "report.json"
                _regenerate(
                    repo=run.repo,
                    family=family,
                    output=regenerated,
                    workspace_root=family_root,
                    base=base,
                    candidate=candidate,
                    bundle=bundle,
                    bundle_sha256=bundle_sha256,
                )
                if regenerated.read_bytes() != submitted[(run_index, family)]:
                    raise ValueError(f"submitted report is not reproducible: {family}")
            verify_clean_checkout(run.repo)
    return bundle_sha256


def _descriptor(args: argparse.Namespace, prefix: str) -> RunDescriptor:
    return RunDescriptor(
        repo=getattr(args, f"{prefix}_repo"),
        evidence=getattr(args, f"{prefix}_evidence"),
        probe=getattr(args, f"{prefix}_probe"),
        runtime=getattr(args, f"{prefix}_runtime"),
        mutations=getattr(args, f"{prefix}_mutations"),
        scope=getattr(args, f"{prefix}_scope"),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--bundle-sha256", required=True)
    for prefix in ("run_one", "run_two"):
        option = prefix.replace("_", "-")
        parser.add_argument(f"--{option}-repo", required=True, type=Path)
        parser.add_argument(f"--{option}-evidence", required=True, type=Path)
        for family in FAMILIES:
            parser.add_argument(f"--{option}-{family}", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        identity = validate_final_reports(
            base=args.base,
            candidate=args.candidate,
            bundle=args.bundle,
            bundle_sha256=args.bundle_sha256,
            run_one=_descriptor(args, "run_one"),
            run_two=_descriptor(args, "run_two"),
        )
    except (
        OSError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"O-07 final evidence hygiene failed: {error}", file=sys.stderr)
        return 2
    print("O-07 FINAL EVIDENCE HYGIENE verdict=PASS reports=8 " f"bundle_sha256={identity}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
