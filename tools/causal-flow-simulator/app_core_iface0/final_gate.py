#!/usr/bin/env python3
"""Exact two-checkout Phase-A gate and provider-bound Phase-B entry gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True

from canonical_json import CanonicalJsonError, dumps, loads
from generate_seed_registry import SeedGenerationError, generate_phase_a
from inventory import BASE_SHA, InventoryError, verify_contract_package
from validate_inventory import PhaseAValidationError, validate_phase_a


RATIFIED_V14_SHA256 = "fd17ed39c7288620cd62f132db3fd5a877f6ba1ef0ff3580c9ad745146d85165"
BANNED_PROVIDER_ENVIRONMENT = frozenset(
    {
        "GH_HOST",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GITHUB_API_URL",
    }
)


class FinalGateError(ValueError):
    """A freeze identity, checkout, package, or provider authority failed."""


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _git(repo: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60,
    )
    if completed.returncode != 0:
        raise FinalGateError("required Git query failed")
    return completed.stdout


def _verify_clean_checkout(repo: Path, selection_head: str) -> None:
    root = repo.resolve()
    if not root.is_dir() or root.is_symlink():
        raise FinalGateError("checkout root is invalid")
    if _git(root, "rev-parse", "HEAD").strip() != selection_head:
        raise FinalGateError("checkout HEAD does not equal selectionHead")
    _git(root, "merge-base", "--is-ancestor", BASE_SHA, selection_head)
    status = _git(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignored=matching",
    )
    if status:
        raise FinalGateError("checkout is not clean, including ignored files")


def _tree(root: Path) -> dict[str, bytes]:
    if not root.is_dir() or root.is_symlink():
        raise FinalGateError("evidence root is invalid")
    result: dict[str, bytes] = {}
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            if path.is_dir() and not path.is_symlink():
                continue
            raise FinalGateError("evidence tree contains a non-regular entry")
        relative = path.relative_to(root).as_posix()
        result[relative] = path.read_bytes()
    return result


def _validate_external_root(repo: Path, root: Path) -> dict[str, object]:
    resolved_repo = repo.resolve()
    resolved = root.resolve()
    git_dir = Path(_git(resolved_repo, "rev-parse", "--absolute-git-dir").strip()).resolve()
    if (
        resolved == resolved_repo
        or resolved_repo in resolved.parents
        or resolved in resolved_repo.parents
        or resolved == git_dir
        or git_dir in resolved.parents
        or resolved in git_dir.parents
    ):
        raise FinalGateError("evidence root overlaps checkout or Git metadata")
    contract = resolved_repo / "tools/causal-flow-simulator/app_core_iface0/contract"
    return validate_phase_a(resolved_repo, contract, resolved)


def run_phase_a_gate(
    repo_one: Path,
    repo_two: Path,
    evidence_one: Path,
    evidence_two: Path,
    selection_head: str,
) -> dict[str, object]:
    if len(selection_head) != 40 or any(ch not in "0123456789abcdef" for ch in selection_head):
        raise FinalGateError("selectionHead is not a full lowercase Git identity")
    first = repo_one.resolve()
    second = repo_two.resolve()
    if first == second:
        raise FinalGateError("the two checkout roots are not distinct")
    _verify_clean_checkout(first, selection_head)
    _verify_clean_checkout(second, selection_head)
    first_result = _validate_external_root(first, evidence_one)
    second_result = _validate_external_root(second, evidence_two)
    first_tree = _tree(evidence_one.resolve())
    second_tree = _tree(evidence_two.resolve())
    if first_tree != second_tree or first_result != second_result:
        raise FinalGateError("the two Phase-A evidence sets are not byte-identical")

    with tempfile.TemporaryDirectory(prefix="styx-app-core-phase-a-") as temporary:
        temporary_root = Path(temporary)
        regenerated_one = temporary_root / "checkout-one"
        regenerated_two = temporary_root / "checkout-two"
        contract_one = first / "tools/causal-flow-simulator/app_core_iface0/contract"
        contract_two = second / "tools/causal-flow-simulator/app_core_iface0/contract"
        generate_phase_a(first, contract_one, regenerated_one)
        generate_phase_a(second, contract_two, regenerated_two)
        if _tree(regenerated_one) != first_tree or _tree(regenerated_two) != first_tree:
            raise FinalGateError("independent final-gate regeneration differs")

    _verify_clean_checkout(first, selection_head)
    _verify_clean_checkout(second, selection_head)
    return {
        "verdict": "PASS",
        "caseCount": 80,
        "positiveCarrierInventorySha256": first_result["inventory_sha256"],
        "phaseAPackageReportSha256": first_result["package_report_sha256"],
    }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise FinalGateError("provider redirect is forbidden")


def _fetch_json(url: str) -> tuple[Any, bytes, dict[str, str]]:
    if any(name in os.environ for name in BANNED_PROVIDER_ENVIRONMENT):
        raise FinalGateError("credential or provider override environment is present")
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "styx-app-core-final-gate-v1"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=30) as response:
            if response.status != 200 or response.geturl() != url:
                raise FinalGateError("provider response identity drift")
            raw = response.read()
            headers = {key.lower(): value for key, value in response.headers.items()}
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise FinalGateError("anonymous provider fetch failed") from error
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise FinalGateError("provider returned malformed JSON") from error
    return value, raw, headers


def _next_link(headers: dict[str, str]) -> str | None:
    link = headers.get("link", "")
    for item in link.split(","):
        fields = item.strip().split(";")
        if len(fields) == 2 and fields[1].strip() == 'rel="next"':
            return fields[0].strip().removeprefix("<").removesuffix(">")
    return None


def _validate_provider_authority(comment_id: str, repo: Path, evidence_root: Path) -> dict[str, Any]:
    if not comment_id.isdecimal() or not comment_id:
        raise FinalGateError("provider comment ID is not decimal")
    url = f"https://api.github.com/repos/styx-secure/styx/issues/comments/{comment_id}"
    comment, _raw, _headers = _fetch_json(url)
    if not isinstance(comment, dict):
        raise FinalGateError("provider comment is not a JSON object")
    if (
        comment.get("id") != int(comment_id)
        or comment.get("url") != url
        or comment.get("issue_url") != "https://api.github.com/repos/styx-secure/styx/issues/295"
        or comment.get("user", {}).get("id") != 141346846
        or comment.get("user", {}).get("login") != "maverde73"
        or comment.get("created_at") != comment.get("updated_at")
        or comment.get("performed_via_github_app") is not None
    ):
        raise FinalGateError("provider comment provenance drift")
    body = comment.get("body")
    if not isinstance(body, str):
        raise FinalGateError("provider comment body is absent")
    body_bytes = body.encode("utf-8")
    try:
        decision = loads(body_bytes)
    except CanonicalJsonError as error:
        raise FinalGateError("provider decision is not canonical JSON") from error
    required = {
        "decision",
        "kind",
        "repository",
        "issue",
        "baseSha",
        "selectionHead",
        "closureAmendmentSha256",
        "candidateManifestSha256",
        "positiveCarrierInventorySha256",
        "phaseAPackageReportSha256",
        "caseCount",
        "requestCaseCount",
        "responseCaseCount",
    }
    if not isinstance(decision, dict) or set(decision) != required or dumps(decision) != body_bytes:
        raise FinalGateError("provider decision body shape or final LF drift")
    if (
        decision["decision"] != "RATIFY"
        or decision["kind"] != "APP_CORE_POSITIVE_CARRIER_INVENTORY_RATIFICATION_V1"
        or decision["repository"] != "styx-secure/styx"
        or decision["issue"] != 295
        or decision["baseSha"] != BASE_SHA
        or decision["closureAmendmentSha256"] != RATIFIED_V14_SHA256
        or (decision["caseCount"], decision["requestCaseCount"], decision["responseCaseCount"])
        != (80, 65, 15)
    ):
        raise FinalGateError("provider decision value drift")

    selection_head = decision["selectionHead"]
    _verify_clean_checkout(repo.resolve(), selection_head)
    result = _validate_external_root(repo.resolve(), evidence_root.resolve())
    manifest_sha = _sha256(
        (
            repo.resolve()
            / "tools/causal-flow-simulator/app_core_iface0/contract/APP-CORE-IFACE-0-CANDIDATE-MANIFEST.json"
        ).read_bytes()
    )
    if (
        decision["candidateManifestSha256"] != manifest_sha
        or decision["positiveCarrierInventorySha256"] != result["inventory_sha256"]
        or decision["phaseAPackageReportSha256"] != result["package_report_sha256"]
    ):
        raise FinalGateError("provider decision does not bind regenerated Phase A")

    commit, _commit_raw, _ = _fetch_json(
        f"https://api.github.com/repos/styx-secure/styx/commits/{selection_head}"
    )
    pull, _pull_raw, _ = _fetch_json(
        "https://api.github.com/repos/styx-secure/styx/pulls/296"
    )
    if not isinstance(commit, dict) or not isinstance(pull, dict):
        raise FinalGateError("provider commit or PR is not a JSON object")
    if commit.get("sha") != selection_head:
        raise FinalGateError("provider commit identity drift")
    if (
        pull.get("state") != "open"
        or pull.get("draft") is not True
        or pull.get("base", {}).get("sha") != BASE_SHA
        or pull.get("head", {}).get("sha") != selection_head
    ):
        raise FinalGateError("provider PR freeze identity drift")

    matches = 0
    page_url: str | None = (
        "https://api.github.com/repos/styx-secure/styx/issues/295/comments?per_page=100&page=1"
    )
    seen: set[str] = set()
    while page_url is not None:
        if page_url in seen or not page_url.startswith(
            "https://api.github.com/repos/styx-secure/styx/issues/295/comments?"
        ):
            raise FinalGateError("provider pagination drift")
        seen.add(page_url)
        page, _page_raw, page_headers = _fetch_json(page_url)
        if not isinstance(page, list):
            raise FinalGateError("provider comment page is malformed")
        for row in page:
            candidate_body = row.get("body") if isinstance(row, dict) else None
            if not isinstance(candidate_body, str):
                continue
            try:
                candidate = loads(candidate_body.encode("utf-8"))
            except CanonicalJsonError:
                continue
            if (
                isinstance(candidate, dict)
                and candidate.get("kind") == decision["kind"]
                and candidate.get("selectionHead") == selection_head
                and candidate.get("candidateManifestSha256") == manifest_sha
                and row.get("user", {}).get("id") == 141346846
                and row.get("user", {}).get("login") == "maverde73"
            ):
                matches += 1
                if row.get("id") != int(comment_id):
                    raise FinalGateError("duplicate matching provider authority")
        page_url = _next_link(page_headers)
    if matches != 1:
        raise FinalGateError("provider authority is absent or duplicated")
    return decision


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--phase-a", action="store_true")
    modes.add_argument("--phase-b-entry", action="store_true")
    parser.add_argument("--repo-root-one", required=True, type=Path)
    parser.add_argument("--repo-root-two", type=Path)
    parser.add_argument("--evidence-root-one", required=True, type=Path)
    parser.add_argument("--evidence-root-two", type=Path)
    parser.add_argument("--selection-head")
    parser.add_argument("--provider-comment-id")
    args = parser.parse_args(argv)
    try:
        if args.phase_a:
            if args.repo_root_two is None or args.evidence_root_two is None or args.selection_head is None:
                raise FinalGateError("Phase A requires two roots and selectionHead")
            result = run_phase_a_gate(
                args.repo_root_one,
                args.repo_root_two,
                args.evidence_root_one,
                args.evidence_root_two,
                args.selection_head,
            )
        else:
            if args.provider_comment_id is None:
                raise FinalGateError("Phase B requires a provider comment ID")
            decision = _validate_provider_authority(
                args.provider_comment_id,
                args.repo_root_one,
                args.evidence_root_one,
            )
            result = {
                "verdict": "PASS",
                "selectionHead": decision["selectionHead"],
                "positiveCarrierInventorySha256": decision[
                    "positiveCarrierInventorySha256"
                ],
            }
    except (
        FinalGateError,
        InventoryError,
        OSError,
        PhaseAValidationError,
        SeedGenerationError,
        subprocess.SubprocessError,
    ) as error:
        print(f"APP-core final gate: FAIL: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
