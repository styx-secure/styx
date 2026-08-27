#!/usr/bin/env python3
"""Regenerate Issue #260 evidence in two exact clean checkouts."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True

from integrated_registry import required_mutants, required_witnesses
from o10.canonical_report import store_report


BASE_SHA = "25be9abc0d8c1bce8821a750616e13d245abc356"
ISSUE_BODY_SHA256 = "1c54acebedf1eef13ddad0416bd192aa074b5b08815eae893ce95f4558bede6a"
INTEGRATED_FILES = {
    "probe": "integrated-probe.json",
    "runtime": "integrated-runtime.json",
    "mutations": "integrated-mutations.json",
    "scope": "integrated-scope.json",
}
SUBMITTED_FILES = frozenset((*INTEGRATED_FILES.values(), "review-model.json"))
SUITES = {
    "o06c": "tools/causal-flow-simulator/o06c/tests",
    "o07": "tools/causal-flow-simulator/o07/tests",
    "o08": "tools/causal-flow-simulator/o08/tests",
    "o10": "tools/causal-flow-simulator/o10/tests",
    "o14": "tools/causal-flow-simulator/o14/tests",
}
INTEGRATED_TEST_MODULES = frozenset(
    {
        "test_integrated_cross_runtime.py",
        "test_integrated_final_gate.py",
        "test_integrated_model.py",
        "test_integrated_mutation_harness.py",
        "test_integrated_probe.py",
        "test_integrated_registry.py",
        "test_integrated_scope_guard.py",
    }
)
REPORT_FIELDS = frozenset(
    {
        "integrated_report_count",
        "pairwise_byte_equal",
        "package_artifact_count",
        "provider_evidence_verified",
        "regenerated_report_count",
        "schema",
        "suite_counts",
        "verdict",
        "worktree_count",
    }
)


class FinalGateError(ValueError):
    """Exact two-checkout evidence could not be regenerated."""


def _run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int = 300,
    allow_empty: bool = False,
) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise FinalGateError("required command timed out") from error
    if completed.returncode != 0:
        command_name = Path(command[1] if len(command) > 1 else command[0]).name
        raise FinalGateError(
            f"required command failed: {command_name} exit={completed.returncode}"
        )
    if not allow_empty and not completed.stdout.strip():
        raise FinalGateError("required command produced no status output")
    if re.search(r"OK \(skipped=[1-9]|skipped\s*=\s*[1-9]", completed.stdout):
        raise FinalGateError("required command skipped tests")
    return completed.stdout


def _git(repo: Path, *arguments: str, allow_empty: bool = False) -> str:
    environment = dict(os.environ)
    return _run(
        ["git", "-C", str(repo), *arguments],
        cwd=repo,
        env=environment,
        allow_empty=allow_empty,
    ).strip()


def _resolved_git_directory(repo: Path, argument: str) -> Path:
    value = _git(repo, "rev-parse", argument)
    path = Path(value)
    return (path if path.is_absolute() else repo / path).resolve()


def verify_worktrees(one: Path, two: Path, base: str, candidate: str) -> None:
    roots = [path.resolve(strict=True) for path in (one, two)]
    if roots[0] == roots[1] or any(path.is_symlink() or not path.is_dir() for path in roots):
        raise FinalGateError("worktree roots are not two distinct directories")
    git_dirs: list[Path] = []
    object_dirs: list[Path] = []
    for repo in roots:
        if _git(repo, "rev-parse", "HEAD") != candidate:
            raise FinalGateError("worktree HEAD mismatch")
        _git(repo, "merge-base", "--is-ancestor", base, candidate, allow_empty=True)
        status = _git(
            repo,
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored",
            allow_empty=True,
        )
        if status:
            raise FinalGateError("worktree is not clean")
        git_dir = _resolved_git_directory(repo, "--git-dir")
        common = _resolved_git_directory(repo, "--git-common-dir")
        objects = common / "objects"
        if (objects / "info/alternates").exists():
            raise FinalGateError("alternate object store is forbidden")
        git_dirs.append(git_dir)
        object_dirs.append(objects.resolve())
    if len(set(git_dirs)) != 2 or len(set(object_dirs)) != 2:
        raise FinalGateError("worktrees do not have separate Git object stores")


def _require_external_root(path: Path, forbidden_roots: tuple[Path, ...]) -> Path:
    resolved = path.resolve(strict=True)
    if resolved.is_symlink() or not resolved.is_dir():
        raise FinalGateError("evidence root is not a regular directory")
    for forbidden in forbidden_roots:
        try:
            resolved.relative_to(forbidden)
        except ValueError:
            continue
        raise FinalGateError("evidence root is inside a checkout or Git directory")
    return resolved


def _regular_file(path: Path) -> bytes:
    resolved = path.resolve(strict=True)
    if path.is_symlink() or not resolved.is_file():
        raise FinalGateError("evidence artifact is not a regular file")
    payload = resolved.read_bytes()
    if not payload:
        raise FinalGateError("evidence artifact is empty")
    return payload


def verify_bundle(bundle: Path, expected: str, repo: Path, candidate: str) -> bytes:
    payload = _regular_file(bundle)
    if sha256(payload).hexdigest() != expected:
        raise FinalGateError("bundle digest mismatch")
    environment = dict(os.environ)
    _run(["git", "bundle", "verify", str(bundle.resolve())], cwd=repo, env=environment)
    advertised = _run(
        ["git", "bundle", "list-heads", str(bundle.resolve()), "HEAD"],
        cwd=repo,
        env=environment,
    ).split()
    if not advertised or advertised[0] != candidate:
        raise FinalGateError("bundle does not advertise the candidate HEAD")
    return payload


def verify_provider_evidence(
    issue_path: Path,
    pr_path: Path,
    base: str,
    candidate: str,
) -> tuple[bytes, bytes]:
    issue_bytes = _regular_file(issue_path)
    pr_bytes = _regular_file(pr_path)
    try:
        issue = json.loads(issue_bytes)
        pull = json.loads(pr_bytes)
    except json.JSONDecodeError as error:
        raise FinalGateError("provider evidence is not JSON") from error
    if (
        not isinstance(issue, dict)
        or issue.get("number") != 260
        or issue.get("url") != "https://api.github.com/repos/styx-secure/styx/issues/260"
        or not isinstance(issue.get("body"), str)
        or sha256(issue["body"].encode("utf-8")).hexdigest() != ISSUE_BODY_SHA256
    ):
        raise FinalGateError("Issue provider evidence mismatch")
    if not isinstance(pull, dict) or pull.get("state") != "open" or pull.get("draft") is not True:
        raise FinalGateError("PR provider evidence is not an open Draft")
    if pull.get("base", {}).get("sha") != base or pull.get("head", {}).get("sha") != candidate:
        raise FinalGateError("PR provider Base or HEAD mismatch")
    body = pull.get("body")
    if not isinstance(body, str) or ISSUE_BODY_SHA256 not in body or base not in body:
        raise FinalGateError("PR body does not bind the ratified Issue and Base")
    return issue_bytes, pr_bytes


def _producer_commands(
    repo: Path,
    output: Path,
    base: str,
    candidate: str,
    bundle: Path,
    bundle_sha256: str,
) -> dict[str, list[str]]:
    python = sys.executable
    common = [
        "--repo-root", ".", "--base", base, "--candidate", candidate,
        "--bundle", str(bundle), "--bundle-sha256", bundle_sha256,
    ]
    return {
        "probe": [python, "tools/causal-flow-simulator/o06c/integrated_probe.py", *common, "--output", str(output / INTEGRATED_FILES["probe"])],
        "runtime": [python, "tools/causal-flow-simulator/o06c/integrated_cross_runtime.py", *common, "--javascript", "node", "--output", str(output / INTEGRATED_FILES["runtime"])],
        "mutations": [python, "tools/causal-flow-simulator/o06c/integrated_mutation_harness.py", *common, "--output", str(output / INTEGRATED_FILES["mutations"])],
        "scope": [python, "tools/causal-flow-simulator/o06c/integrated_scope_guard.py", *common, "--mode", "strict", "--output", str(output / INTEGRATED_FILES["scope"])],
    }


def _run_integrated(
    repo: Path,
    output: Path,
    base: str,
    candidate: str,
    bundle: Path,
    bundle_sha256: str,
    env: dict[str, str],
) -> dict[str, bytes]:
    output.mkdir()
    commands = _producer_commands(repo, output, base, candidate, bundle, bundle_sha256)
    for command in commands.values():
        _run(command, cwd=repo, env=env)
    return {
        name: _regular_file(output / filename)
        for name, filename in INTEGRATED_FILES.items()
    }


def validate_integrated_reports(reports: dict[str, bytes]) -> None:
    if set(reports) != set(INTEGRATED_FILES):
        raise FinalGateError("integrated report family mismatch")
    try:
        values = {name: json.loads(payload) for name, payload in reports.items()}
    except json.JSONDecodeError as error:
        raise FinalGateError("integrated report is invalid JSON") from error
    probe = values["probe"]
    if (
        probe.get("verdict") != "PASS"
        or probe.get("disposition_count") != 69
        or probe.get("handoff_count") != 66
        or len(probe.get("witness_results", ())) + len(probe.get("dispositions", ()))
        + len(probe.get("handoff_results", ())) + len(probe.get("boundary_results", ()))
        != len(required_witnesses())
    ):
        raise FinalGateError("integrated probe is not substantively complete")
    consumed = sum(
        row.get("disposition") == "CONSUMED" for row in probe.get("dispositions", ())
    )
    if consumed != 53:
        raise FinalGateError("integrated probe does not consume 53 entry dimensions")
    mutations = values["mutations"]
    if (
        mutations.get("verdict") != "ALL_REQUIRED_MUTANTS_KILLED"
        or mutations.get("mutant_count") != len(required_mutants())
        or mutations.get("killed_count") != len(required_mutants())
        or mutations.get("survivor_count") != 0
    ):
        raise FinalGateError("integrated mutant relation is incomplete")
    for row in mutations.get("results", ()):
        if not row.get("declared_detectors") or row.get("declared_detectors") != row.get("observed_detectors"):
            raise FinalGateError("integrated detector equality is not exact")
    if values["runtime"].get("verdict") != "PASS" or values["runtime"].get("interchange") != "TEST_ONLY_NOT_O11":
        raise FinalGateError("integrated runtime report overclaims its interchange")
    if values["scope"].get("verdict") != "PASS":
        raise FinalGateError("integrated scope report is not PASS")


def _unittest_count(output: str) -> int:
    match = re.search(r"Ran (\d+) tests?", output)
    if match is None or "OK" not in output:
        raise FinalGateError("unittest suite did not report an unskipped success")
    count = int(match.group(1))
    if count < 1:
        raise FinalGateError("unittest suite collected no tests")
    return count


def _validate_integrated_test_module_inventory(test_root: Path) -> None:
    if test_root.is_symlink() or not test_root.is_dir():
        raise FinalGateError("integrated test root is not a regular directory")
    modules = {
        path.name: path
        for path in test_root.glob("test_integrated_*.py")
        if path.is_file() and not path.is_symlink()
    }
    if set(modules) != INTEGRATED_TEST_MODULES:
        raise FinalGateError("integrated test module set mismatch")
    loader_program = (
        "import pathlib,sys,unittest; "
        "root=pathlib.Path(sys.argv[1]); name=sys.argv[2]; "
        "count=unittest.defaultTestLoader.discover(str(root), pattern=name).countTestCases(); "
        "print(count); raise SystemExit(0 if count > 0 else 1)"
    )
    for name in sorted(INTEGRATED_TEST_MODULES):
        completed = subprocess.run(
            [sys.executable, "-c", loader_program, str(test_root), name],
            cwd=test_root.parent,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise FinalGateError(f"integrated test module collected no tests: {name}")


def _run_suites(repo: Path, output: Path, env: dict[str, str]) -> dict[str, int]:
    _validate_integrated_test_module_inventory(
        repo / "tools/causal-flow-simulator/o06c/tests"
    )
    counts: dict[str, int] = {}
    for name, directory in SUITES.items():
        text = _run(
            [sys.executable, "-m", "unittest", "discover", "-s", directory, "-p", "test_*.py"],
            cwd=repo,
            env=env,
        )
        (output / f"suite-{name}.log").write_text(text, encoding="utf-8")
        counts[name] = _unittest_count(text)
    review = _run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tools/protocol-review-model/tests", "-p", "test_*.py"],
        cwd=repo,
        env=env,
    )
    (output / "suite-review-model.log").write_text(review, encoding="utf-8")
    counts["review-model"] = _unittest_count(review)
    return counts


def _run_review_and_repository_gates(repo: Path, output: Path, base: str, candidate: str, env: dict[str, str]) -> bytes:
    review_path = output / "review-model.json"
    commands = (
        [sys.executable, "tools/protocol-review-model/validate.py", "--repo-root", ".", "--schema", "docs/protocol/review/styx-app-kernel-v0-review-model.schema.json", "--model", "docs/protocol/review/styx-app-kernel-v0-review-model.json", "--output", str(review_path)],
        [sys.executable, "tools/docs-claims-lint/claims_lint.py", "--scan", "docs", "specs", "--exclude", "docs/superpowers", "docs/security", "docs/archive", "docs/piano-utente.md"],
        [sys.executable, "tools/docs-translation-sync/check.py", "--manifest", "docs/platform/translation-pairs.json"],
        ["reuse", "lint"],
        ["git", "diff", "--check", f"{base}...{candidate}"],
    )
    for index, command in enumerate(commands):
        text = _run(command, cwd=repo, env=env, allow_empty=index == 4)
        (output / f"repository-gate-{index}.log").write_text(text or "PASS\n", encoding="utf-8")
    return _regular_file(review_path)


def _selected_envelope_digest(repo: Path) -> str:
    envelope_payload = json.loads(
        (repo / "tools/causal-flow-simulator/o08/resource-envelope.candidate.json").read_bytes()
    )
    envelope_digest = envelope_payload.get("candidate_digest")
    if (
        not isinstance(envelope_digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", envelope_digest) is None
    ):
        raise FinalGateError("frozen O-08 selected-envelope identity is invalid")
    return envelope_digest


def _run_frozen_producers(
    repo: Path,
    output: Path,
    base: str,
    candidate: str,
    bundle: Path,
    bundle_sha256: str,
    env: dict[str, str],
) -> dict[str, bytes]:
    output.mkdir()
    python = sys.executable
    envelope_digest = _selected_envelope_digest(repo)
    commands: dict[str, list[str]] = {
        "o07-probe": [python, "tools/causal-flow-simulator/o07/run_genesis_checkpoint_probe.py", "--repo-root", ".", "--suite", "required", "--bundle", str(bundle), "--bundle-sha256", bundle_sha256],
        "o07-runtime": [python, "tools/causal-flow-simulator/o07/run_cross_runtime.py", "--repo-root", ".", "--suite", "required", "--javascript", "node", "--workspace", str(output / "o07-workspace"), "--bundle", str(bundle), "--bundle-sha256", bundle_sha256],
        "o07-mutations": [python, "tools/causal-flow-simulator/o07/run_mutations.py", "--repo-root", ".", "--suite", "required", "--bundle", str(bundle), "--bundle-sha256", bundle_sha256],
        "o08-inventory": [python, "tools/causal-flow-simulator/o08/validate_inventory.py", "--repo-root", "."],
        "o08-envelope": [python, "tools/causal-flow-simulator/o08/validate_envelope.py", "--repo-root", ".", "--approved-envelope-digest", envelope_digest],
        "o08-boundary": [python, "tools/causal-flow-simulator/o08/run_boundary_probe.py", "--repo-root", "."],
        "o08-combined": [python, "tools/causal-flow-simulator/o08/run_combined_probe.py", "--repo-root", "."],
        "o08-runtime": [python, "tools/causal-flow-simulator/o08/run_cross_runtime.py", "--repo-root", ".", "--javascript", "node"],
        "o08-mutations": [python, "tools/causal-flow-simulator/o08/run_mutations.py", "--repo-root", "."],
        "o08-handoff": [python, "tools/causal-flow-simulator/o08/generate_handoff.py", "--repo-root", "."],
        "o10-probe": [python, "tools/causal-flow-simulator/o10/run_taxonomy_probe.py", "--repo-root", "."],
        "o10-runtime": [python, "tools/causal-flow-simulator/o10/run_cross_runtime.py", "--repo-root", ".", "--javascript", "node"],
        "o10-mutations": [python, "tools/causal-flow-simulator/o10/run_mutations.py", "--repo-root", ".", "--javascript", "node"],
        "o14-probe": [python, "tools/causal-flow-simulator/o14/signature_suite_probe.py", "--repo-root", ".", "--suite", "required"],
        "o14-runtime": [python, "tools/causal-flow-simulator/o14/cross_runtime_gate.py", "--repo-root", ".", "--suite", "required", "--workspace", str(output / "o14-workspace")],
        "o14-mutations": [python, "tools/causal-flow-simulator/o14/mutation_harness_o14.py", "--repo-root", ".", "--suite", "required"],
    }
    reports: dict[str, bytes] = {}
    for name, command in commands.items():
        report_path = output / f"{name}.json"
        command.extend(("--output", str(report_path)))
        _run(command, cwd=repo, env=env)
        reports[name] = _regular_file(report_path)
    return reports


def _exact_submitted(root: Path) -> dict[str, bytes]:
    names = {path.name for path in root.iterdir() if path.is_file() and not path.is_symlink()}
    if names != SUBMITTED_FILES or any(path.is_dir() or path.is_symlink() for path in root.iterdir()):
        raise FinalGateError("submitted evidence set is not exact")
    return {name: _regular_file(root / filename) for name, filename in INTEGRATED_FILES.items()}


def _copy_artifact(source: Path, destination: Path) -> None:
    payload = _regular_file(source)
    if destination.exists():
        raise FinalGateError("duplicate package artifact name")
    destination.write_bytes(payload)


def _populate_package(
    package: Path,
    bundle: Path,
    issue: Path,
    pull: Path,
    one_root: Path,
    two_root: Path,
    regenerated: tuple[Path, Path],
    frozen: tuple[Path, Path],
    diff_bytes: bytes,
) -> None:
    if package.exists():
        if package.is_symlink() or not package.is_dir() or any(package.iterdir()):
            raise FinalGateError("package directory must be empty")
    else:
        package.mkdir(parents=True)
    _copy_artifact(bundle, package / "candidate.bundle")
    _copy_artifact(issue, package / "issue-rest.json")
    _copy_artifact(pull, package / "pr-rest.json")
    (package / "candidate-full-index.diff").write_bytes(diff_bytes)
    for ordinal, root in ((1, one_root), (2, two_root)):
        for name in sorted(SUBMITTED_FILES):
            _copy_artifact(root / name, package / f"submitted-{ordinal}-{name}")
    for ordinal, root in enumerate(regenerated, 1):
        for path in sorted(root.iterdir()):
            if path.is_file() and not path.is_symlink():
                _copy_artifact(path, package / f"regenerated-{ordinal}-{path.name}")
    for ordinal, root in enumerate(frozen, 1):
        for path in sorted(root.iterdir()):
            if path.is_file() and not path.is_symlink():
                _copy_artifact(path, package / f"frozen-{ordinal}-{path.name}")


def write_manifest(package: Path) -> None:
    manifest = package / "SHA256SUMS.txt"
    if manifest.exists():
        raise FinalGateError("package manifest already exists")
    paths = sorted(path for path in package.iterdir() if path.is_file() and not path.is_symlink())
    if any(path.is_dir() or path.is_symlink() for path in package.iterdir()):
        raise FinalGateError("package contains a non-regular artifact")
    manifest.write_text(
        "".join(f"{sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in paths),
        encoding="utf-8",
    )


def build_report(args: argparse.Namespace) -> dict[str, object]:
    one = args.worktree_one.resolve(strict=True)
    two = args.worktree_two.resolve(strict=True)
    if args.base != BASE_SHA:
        raise FinalGateError("contract Base mismatch")
    verify_worktrees(one, two, args.base, args.candidate)
    git_roots = tuple(
        _resolved_git_directory(repo, selector)
        for repo in (one, two)
        for selector in ("--git-dir", "--git-common-dir")
    )
    forbidden = (one, two, *git_roots)
    submitted_one = _require_external_root(args.submitted_one, forbidden)
    submitted_two = _require_external_root(args.submitted_two, forbidden)
    package = _require_external_root(args.package_dir, forbidden)
    if len({submitted_one, submitted_two, package}) != 3:
        raise FinalGateError("submitted and package evidence roots are not distinct")
    verify_bundle(args.bundle, args.bundle_sha256, one, args.candidate)
    verify_provider_evidence(args.issue_rest, args.pr_rest, args.base, args.candidate)
    submitted = (_exact_submitted(submitted_one), _exact_submitted(submitted_two))
    validate_integrated_reports(submitted[0])
    validate_integrated_reports(submitted[1])
    if submitted[0] != submitted[1]:
        raise FinalGateError("submitted canonical reports differ")

    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment.pop("PYTHONPATH", None)
    with tempfile.TemporaryDirectory(prefix="styx-integrated-final-") as directory:
        root = Path(directory)
        regenerated_roots = (root / "integrated-one", root / "integrated-two")
        frozen_roots = (root / "frozen-one", root / "frozen-two")
        regenerated = (
            _run_integrated(one, regenerated_roots[0], args.base, args.candidate, args.bundle, args.bundle_sha256, environment),
            _run_integrated(two, regenerated_roots[1], args.base, args.candidate, args.bundle, args.bundle_sha256, environment),
        )
        for report_set in regenerated:
            validate_integrated_reports(report_set)
        if regenerated[0] != regenerated[1] or regenerated[0] != submitted[0]:
            raise FinalGateError("independently regenerated integrated evidence differs")
        suite_counts = (
            _run_suites(one, regenerated_roots[0], environment),
            _run_suites(two, regenerated_roots[1], environment),
        )
        if suite_counts[0] != suite_counts[1]:
            raise FinalGateError("suite collection differs across worktrees")
        review_reports = (
            _run_review_and_repository_gates(one, regenerated_roots[0], args.base, args.candidate, environment),
            _run_review_and_repository_gates(two, regenerated_roots[1], args.base, args.candidate, environment),
        )
        if review_reports[0] != review_reports[1]:
            raise FinalGateError("review-model reports differ")
        if review_reports[0] != _regular_file(submitted_one / "review-model.json") or review_reports[1] != _regular_file(submitted_two / "review-model.json"):
            raise FinalGateError("submitted review-model evidence differs")
        frozen_reports = (
            _run_frozen_producers(one, frozen_roots[0], args.base, args.candidate, args.bundle, args.bundle_sha256, environment),
            _run_frozen_producers(two, frozen_roots[1], args.base, args.candidate, args.bundle, args.bundle_sha256, environment),
        )
        if frozen_reports[0] != frozen_reports[1]:
            raise FinalGateError("frozen canonical producer evidence differs")
        if _git(one, "status", "--porcelain=v1", "--untracked-files=all", "--ignored", allow_empty=True) or _git(two, "status", "--porcelain=v1", "--untracked-files=all", "--ignored", allow_empty=True):
            raise FinalGateError("a producer changed a clean checkout")
        diff_bytes = subprocess.check_output(
            ["git", "-C", str(one), "diff", "--binary", "--full-index", args.base, args.candidate]
        )
        _populate_package(
            package,
            args.bundle,
            args.issue_rest,
            args.pr_rest,
            submitted_one,
            submitted_two,
            regenerated_roots,
            frozen_roots,
            diff_bytes,
        )
        artifact_count = len(list(package.iterdir())) + 2
        regenerated_count = len(regenerated[0]) + len(frozen_reports[0]) + 1
    return {
        "integrated_report_count": len(INTEGRATED_FILES),
        "pairwise_byte_equal": True,
        "package_artifact_count": artifact_count,
        "provider_evidence_verified": True,
        "regenerated_report_count": regenerated_count,
        "schema": "styx-o14-o06c-integrated-final/v1",
        "suite_counts": dict(sorted(suite_counts[0].items())),
        "verdict": "PASS",
        "worktree_count": 2,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worktree-one", required=True, type=Path)
    parser.add_argument("--worktree-two", required=True, type=Path)
    parser.add_argument("--submitted-one", required=True, type=Path)
    parser.add_argument("--submitted-two", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--bundle-sha256", required=True)
    parser.add_argument("--issue-rest", required=True, type=Path)
    parser.add_argument("--pr-rest", required=True, type=Path)
    parser.add_argument("--package-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_report(args)
        store_report(args.output, report, allowed_fields=REPORT_FIELDS)
        write_manifest(args.package_dir.resolve())
    except (OSError, FinalGateError, subprocess.CalledProcessError, ValueError) as error:
        print(f"integrated final gate failed: {type(error).__name__}", file=sys.stderr)
        return 2
    print(
        f"INTEGRATED FINAL verdict=PASS reports={report['regenerated_report_count']} "
        f"package={report['package_artifact_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
