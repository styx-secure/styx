#!/usr/bin/env python3
"""Regenerate and compare all canonical O-08 evidence in two clean clones."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

sys.dont_write_bytecode = True

from canonical_report import store_report
from semantic_registry import BASE_SHA, canonical_bytes
from validate_envelope import fetch_provider_object, validate_selection
from run_measurements import validate_set


REPORT_SCHEMA = "styx-o08-final-gate-report/v1"
TASK_ISSUE_URL = "https://api.github.com/repos/styx-secure/styx/issues/250"
TASK_ISSUE_BODY_SHA256 = "747b466bfa1542e97c2d48c6b90e716d23677384520da30b7cad8ec2b8970f29"
PRODUCERS = (
    ("inventory", "validate_inventory.py", ()),
    ("envelope", "validate_envelope.py", ("--approved-envelope-digest", "{approved}")),
    ("boundary", "run_boundary_probe.py", ()),
    ("combined", "run_combined_probe.py", ()),
    ("cross-runtime", "run_cross_runtime.py", ("--javascript", "{javascript}")),
    ("mutations", "run_mutations.py", ()),
    ("handoff", "generate_handoff.py", ()),
    ("scope", "scope_guard.py", ("--base", "{base}", "--candidate", "{candidate}", "--mode", "strict")),
    (
        "structural-measurements", "run_measurements.py",
        ("--regenerate-structural-set", "--selection-head", "{selection_head}",
         "--javascript", "{javascript}"),
    ),
)


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _verify_repo(repo: Path, candidate: str) -> None:
    if not repo.is_dir() or repo.is_symlink():
        raise ValueError("invalid checkout root")
    if _git(repo, "rev-parse", "HEAD") != candidate:
        raise ValueError("checkout HEAD mismatch")
    if _git(repo, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("checkout is not clean")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise HTTPError(req.full_url, code, "redirect forbidden", headers, fp)


def _fetch_task_issue_body(output: Path) -> None:
    request = Request(TASK_ISSUE_URL, headers={"Accept": "application/vnd.github+json"})
    try:
        with build_opener(_NoRedirect).open(request, timeout=30) as response:
            value = json.loads(response.read())
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as error:
        raise ValueError(f"task Issue fetch failed: {error}") from error
    if (
        not isinstance(value, dict) or value.get("url") != TASK_ISSUE_URL
        or value.get("number") != 250 or not isinstance(value.get("body"), str)
    ):
        raise ValueError("task Issue provider identity mismatch")
    raw = value["body"].encode("utf-8")
    if sha256(raw).hexdigest() != TASK_ISSUE_BODY_SHA256:
        raise ValueError("task Issue body is not the ratified contract")
    output.write_bytes(raw)


def _run_trusted_task_scope_guard(
    repo: Path, base: str, candidate: str, output_root: Path,
) -> bytes:
    output_root.mkdir(parents=True)
    archive = output_root / "agent-enforcement.tar"
    with archive.open("wb") as stream:
        completed = subprocess.run(
            ["git", "-C", str(repo), "archive", "--format=tar", base, "tools/agent-enforcement"],
            stdout=stream, stderr=subprocess.PIPE, check=False,
        )
    if completed.returncode != 0:
        raise ValueError(f"cannot extract trusted scope guard: {completed.stderr.decode().strip()}")
    trusted = output_root / "trusted-base"
    trusted.mkdir()
    with tarfile.open(archive, "r:") as bundle:
        bundle.extractall(trusted, filter="data")
    issue_body = output_root / "issue-250-body.txt"
    _fetch_task_issue_body(issue_body)
    report = output_root / "task-scope.json"
    completed = subprocess.run(
        [
            sys.executable, str(trusted / "tools/agent-enforcement/scope_guard.py"),
            "--issue-number", "250", "--issue-body-file", str(issue_body),
            "--base-sha", base, "--head-sha", candidate, "--worktree-sha", candidate,
            "--execution-id", "O08_FINAL_GATE", "--output", str(report), "--repo", str(repo),
        ],
        cwd=trusted, capture_output=True, timeout=180,
    )
    if completed.returncode != 0 or not report.is_file():
        raise ValueError(f"trusted task-scope guard failed: {completed.stderr.decode().strip()}")
    value = json.loads(report.read_bytes())
    if (
        value.get("schema") != "styx.task-scope-report/v1"
        or value.get("verdict") != "PASS"
        or value.get("issue_body_sha256") != TASK_ISSUE_BODY_SHA256
    ):
        raise ValueError("trusted task-scope report mismatch")
    return report.read_bytes()


def _run_all(repo: Path, output_root: Path, values: dict[str, str]) -> dict[str, bytes]:
    package = repo / "tools/causal-flow-simulator/o08"
    reports: dict[str, bytes] = {}
    for name, script, template in PRODUCERS:
        output = output_root / f"{name}.json"
        extra = [values.get(item[1:-1], item) if item.startswith("{") else item for item in template]
        completed = subprocess.run(
            [sys.executable, str(package / script), "--repo-root", str(repo), *extra, "--output", str(output)],
            cwd=repo, capture_output=True, text=True, timeout=180,
        )
        if completed.returncode != 0 or not output.is_file():
            raise ValueError(f"producer failed: {name}: {completed.stderr.strip()}")
        reports[name] = output.read_bytes()
    return reports


def _verify_submitted_measurements(
    args: argparse.Namespace, selection: dict[str, object], repo: Path,
) -> dict[str, object]:
    if len(args.measurement_report) != 6:
        raise ValueError("exactly six submitted measurement reports are required")
    paths = [path.resolve(strict=True) for path in args.measurement_report]
    if len(set(paths)) != 6 or any(not path.is_file() or path.is_symlink() for path in paths):
        raise ValueError("submitted measurement report paths are not six distinct regular files")
    comparison_path = args.comparison_report.resolve(strict=True)
    if not comparison_path.is_file() or comparison_path.is_symlink():
        raise ValueError("comparison report is not a regular file")

    provider_reports = {
        (item["candidate_id"], item["capability_profile"]): item["report_sha256"]
        for item in selection["measurement_reports"]
    }
    observed_reports: dict[tuple[str, str], str] = {}
    for path in paths:
        value = json.loads(path.read_bytes())
        pair = (value.get("candidate_id"), value.get("capability_profile"))
        if pair in observed_reports:
            raise ValueError("duplicate submitted measurement pair")
        observed_reports[pair] = sha256(path.read_bytes()).hexdigest()
    if observed_reports != provider_reports:
        raise ValueError("submitted measurement identities differ from provider decision")
    if sha256(comparison_path.read_bytes()).hexdigest() != selection["comparison_report_sha256"]:
        raise ValueError("submitted comparison identity differs from provider decision")

    candidate_set_path = repo / "tools/causal-flow-simulator/o08/resource-envelope.candidates.json"
    regenerated_comparison = validate_set(
        repo, paths, args.selection_head, candidate_set_path, args.javascript,
    )
    if comparison_path.read_bytes() != canonical_bytes(regenerated_comparison):
        raise ValueError("submitted comparison is not derivable from the six reports")
    if regenerated_comparison["selection_head"] != selection["selection_head"]:
        raise ValueError("comparison selection HEAD mismatch")
    if regenerated_comparison["candidate_set_sha256"] != selection["candidate_set_sha256"]:
        raise ValueError("comparison candidate-set digest mismatch")
    if selection["selected_envelope_sha256"] not in set(
        regenerated_comparison["candidate_envelope_digests"].values()
    ):
        raise ValueError("selected envelope is absent from the comparison")
    return regenerated_comparison


def build_report(args: argparse.Namespace) -> dict[str, object]:
    repo_one = args.repo_one.resolve(strict=True)
    repo_two = args.repo_two.resolve(strict=True)
    if repo_one == repo_two:
        raise ValueError("checkout roots must be distinct")
    if args.base != BASE_SHA or len(args.candidate) != 40 or len(args.selection_head) != 40:
        raise ValueError("final identity mismatch")
    for repo in (repo_one, repo_two):
        _verify_repo(repo, args.candidate)
        if _git(repo, "merge-base", args.base, args.candidate) != args.base:
            raise ValueError("Base is not an ancestor")
        if _git(repo, "merge-base", args.selection_head, args.candidate) != args.selection_head:
            raise ValueError("selection HEAD is not an ancestor")
        changed = _git(repo, "diff", "--name-only", f"{args.selection_head}...{args.candidate}", "--", "tools/causal-flow-simulator/o08")
        if changed != "tools/causal-flow-simulator/o08/resource-envelope.candidate.json":
            raise ValueError("post-selection O-08 delta is not exact")
    provider = fetch_provider_object(args.selection_provider_url, args.selection_provider_object_id)
    args.selection_evidence.parent.mkdir(parents=True, exist_ok=True)
    import json
    args.selection_evidence.write_text(json.dumps(provider, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    selection = validate_selection(
        provider, url=args.selection_provider_url, object_id=args.selection_provider_object_id,
        base=args.base, selection_head=args.selection_head,
        candidate_set_path=(
            repo_one / "tools/causal-flow-simulator/o08/resource-envelope.candidates.json"
        ),
    )
    if selection["selected_envelope_sha256"] != args.approved_envelope_digest:
        raise ValueError("approved digest mismatch")
    submitted_comparison = _verify_submitted_measurements(args, selection, repo_one)
    with tempfile.TemporaryDirectory(prefix="styx-o08-final-") as temporary:
        root = Path(temporary)
        values = {
            "approved": args.approved_envelope_digest, "javascript": args.javascript,
            "base": args.base, "candidate": args.candidate,
            "selection_head": args.selection_head,
        }
        one = _run_all(repo_one, root / "one", values)
        two = _run_all(repo_two, root / "two", values)
        task_scope_one = _run_trusted_task_scope_guard(
            repo_one, args.base, args.candidate, root / "task-scope-one"
        )
        task_scope_two = _run_trusted_task_scope_guard(
            repo_two, args.base, args.candidate, root / "task-scope-two"
        )
    if set(one) != set(two) or any(one[name] != two[name] for name in one):
        raise ValueError("canonical evidence differs across clean checkouts")
    if task_scope_one != task_scope_two:
        raise ValueError("trusted task-scope evidence differs across clean checkouts")
    regenerated_structural = json.loads(one["structural-measurements"])
    if regenerated_structural.get("structural_identities") != submitted_comparison.get(
        "deterministic_structural_identities"
    ):
        raise ValueError("independently regenerated structural evidence differs from selection evidence")
    return {
        "schema": REPORT_SCHEMA, "report_families": sorted(one),
        "report_family_count": len(one), "pairwise_byte_equal": True,
        "selection_verified": True, "task_scope_verified": True,
        "task_issue_body_sha256": TASK_ISSUE_BODY_SHA256, "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-one", required=True, type=Path)
    parser.add_argument("--repo-two", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--javascript", required=True)
    parser.add_argument("--selection-head", required=True)
    parser.add_argument("--selection-evidence", required=True, type=Path)
    parser.add_argument("--selection-provider-url", required=True)
    parser.add_argument("--selection-provider-object-id", required=True)
    parser.add_argument("--refresh-selection-evidence", action="store_true")
    parser.add_argument("--approved-envelope-digest", required=True)
    parser.add_argument("--measurement-report", action="append", required=True, type=Path)
    parser.add_argument("--comparison-report", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_report(args)
        store_report(args.output, report, REPORT_SCHEMA)
    except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        print(f"O-08 final gate failed: {error}", file=sys.stderr)
        return 2
    print("O-08 FINAL_GATE verdict=PASS reports=9")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
