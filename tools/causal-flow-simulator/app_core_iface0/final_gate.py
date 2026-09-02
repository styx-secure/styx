#!/usr/bin/env python3
"""Exact two-checkout Phase-A gate and provider-bound Phase-B entry gate."""

from __future__ import annotations

import argparse
import base64
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
from inventory import BASE_SHA, InventoryError


RATIFIED_V14_SHA256 = "fd17ed39c7288620cd62f132db3fd5a877f6ba1ef0ff3580c9ad745146d85165"
POSITIVE_INVENTORY_RATIFICATION_KIND = (
    "APP_CORE_POSITIVE_CARRIER_INVENTORY_RATIFICATION_V1"
)
POSITIVE_INVENTORY_AUTHORITY_CHANGE_KIND = (
    "APP_CORE_POSITIVE_CARRIER_INVENTORY_AUTHORITY_CHANGE_V1"
)
ISSUE_URL = "https://api.github.com/repos/styx-secure/styx/issues/295"
ISSUE_COMMENTS_URL = ISSUE_URL + "/comments?per_page=100&page=1"
OPERATOR_ID = 141346846
OPERATOR_LOGIN = "maverde73"
SEMANTIC_FIXTURE_SOURCE_COMMIT = "284b9230126cfa70337723c2a9d001800a64804c"
SEMANTIC_FIXTURE_SOURCE_PATH = (
    "tools/causal-flow-simulator/app_core_iface0/generate_seed_registry.py"
)
SEMANTIC_FIXTURE_SOURCE_FIRST_LINE = 971
SEMANTIC_FIXTURE_SOURCE_LAST_LINE = 1162
SEMANTIC_FIXTURE_SOURCE_OCTETS = 7121
SEMANTIC_FIXTURE_SOURCE_SHA256 = (
    "686208b6d1285d42f8ec165fbb511905004eee124a0708207b103b60c561e1ad"
)
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


def _git_bytes(repo: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    if completed.returncode != 0:
        raise FinalGateError("required Git object query failed")
    return completed.stdout


def _frozen_semantic_fixture_slice(source: bytes) -> bytes:
    lines = source.splitlines(keepends=True)
    if len(lines) < SEMANTIC_FIXTURE_SOURCE_LAST_LINE:
        raise FinalGateError("semantic-fixture source is shorter than the ratified slice")
    result = b"".join(
        lines[
            SEMANTIC_FIXTURE_SOURCE_FIRST_LINE - 1 :
            SEMANTIC_FIXTURE_SOURCE_LAST_LINE
        ]
    )
    if (
        len(result) != SEMANTIC_FIXTURE_SOURCE_OCTETS
        or _sha256(result) != SEMANTIC_FIXTURE_SOURCE_SHA256
        or not result.endswith(b"\n")
    ):
        raise FinalGateError("ratified semantic-fixture source slice drift")
    return result


def _local_source_blobs(repo: Path, selection_head: str) -> tuple[bytes, bytes]:
    historical = _git_bytes(
        repo,
        "show",
        f"{SEMANTIC_FIXTURE_SOURCE_COMMIT}:{SEMANTIC_FIXTURE_SOURCE_PATH}",
    )
    frozen = _frozen_semantic_fixture_slice(historical)
    selected = _git_bytes(
        repo,
        "show",
        f"{selection_head}:{SEMANTIC_FIXTURE_SOURCE_PATH}",
    )
    if selected.count(frozen) != 1:
        raise FinalGateError("selectionHead does not contain one exact semantic-fixture slice")
    return historical, selected


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


def _run_checkout_tool(
    repo: Path,
    relative_tool: str,
    arguments: list[str],
    *,
    timeout: int = 180,
) -> subprocess.CompletedProcess[bytes]:
    tool = repo.resolve() / relative_tool
    if not tool.is_file() or tool.is_symlink():
        raise FinalGateError("checkout evidence tool is absent or non-regular")
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, str(tool), *arguments],
        cwd=repo.resolve(),
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise FinalGateError("checkout-owned evidence tool failed")
    return completed


def _generate_phase_a_from_checkout(repo: Path, root: Path) -> None:
    contract = repo.resolve() / "tools/causal-flow-simulator/app_core_iface0/contract"
    _run_checkout_tool(
        repo,
        "tools/causal-flow-simulator/app_core_iface0/generate_seed_registry.py",
        [
            "--repo-root",
            str(repo.resolve()),
            "--contract",
            str(contract),
            "--generate-phase-a",
            "--evidence-root",
            str(root.resolve()),
        ],
    )


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
    with tempfile.TemporaryDirectory(prefix="styx-app-core-validation-") as temporary:
        report_path = Path(temporary) / "report.json"
        contract = resolved_repo / "tools/causal-flow-simulator/app_core_iface0/contract"
        _run_checkout_tool(
            resolved_repo,
            "tools/causal-flow-simulator/app_core_iface0/validate_inventory.py",
            [
                "--repo-root",
                str(resolved_repo),
                "--contract",
                str(contract),
                "--phase-a-evidence-root",
                str(resolved),
                "--output",
                str(report_path),
            ],
        )
        try:
            report = loads(report_path.read_bytes())
        except (CanonicalJsonError, OSError) as error:
            raise FinalGateError("checkout validator report is invalid") from error
    required = {
        "case_count": 80,
        "schema": "styx.app-core-iface0.phase-a-validation.v1",
        "verdict": "PASS",
    }
    if (
        not isinstance(report, dict)
        or any(report.get(key) != value for key, value in required.items())
        or not isinstance(report.get("inventory_sha256"), str)
        or not isinstance(report.get("package_report_sha256"), str)
    ):
        raise FinalGateError("checkout validator report shape drift")
    return report


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
    historical_one, selected_one = _local_source_blobs(first, selection_head)
    historical_two, selected_two = _local_source_blobs(second, selection_head)
    if historical_one != historical_two or selected_one != selected_two:
        raise FinalGateError("the two checkouts disagree on semantic-fixture source bytes")
    _verify_provider_source_slice(selection_head, historical_one, selected_one)
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
        _generate_phase_a_from_checkout(first, regenerated_one)
        _generate_phase_a_from_checkout(second, regenerated_two)
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


def _provider_source_blob(commit: str) -> bytes:
    url = (
        "https://api.github.com/repos/styx-secure/styx/contents/"
        f"{SEMANTIC_FIXTURE_SOURCE_PATH}?ref={commit}"
    )
    value, _raw, _headers = _fetch_json(url)
    if (
        not isinstance(value, dict)
        or value.get("type") != "file"
        or value.get("path") != SEMANTIC_FIXTURE_SOURCE_PATH
        or value.get("encoding") != "base64"
        or not isinstance(value.get("content"), str)
    ):
        raise FinalGateError("provider source object shape drift")
    encoded = "".join(value["content"].split())
    try:
        return base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as error:
        raise FinalGateError("provider source object is not strict base64") from error


def _verify_provider_source_slice(
    selection_head: str,
    local_historical: bytes,
    local_selected: bytes,
) -> None:
    provider_historical = _provider_source_blob(SEMANTIC_FIXTURE_SOURCE_COMMIT)
    provider_selected = _provider_source_blob(selection_head)
    if (
        provider_historical != local_historical
        or provider_selected != local_selected
    ):
        raise FinalGateError("provider and local source blobs differ")
    frozen = _frozen_semantic_fixture_slice(provider_historical)
    if provider_selected.count(frozen) != 1:
        raise FinalGateError("provider selectionHead lost the frozen semantic fixture")


def _next_link(headers: dict[str, str]) -> str | None:
    link = headers.get("link", "")
    for item in link.split(","):
        fields = item.strip().split(";")
        if len(fields) == 2 and fields[1].strip() == 'rel="next"':
            return fields[0].strip().removeprefix("<").removesuffix(">")
    return None


def _operator(row: dict[str, Any]) -> bool:
    user = row.get("user")
    return (
        isinstance(user, dict)
        and user.get("id") == OPERATOR_ID
        and user.get("login") == OPERATOR_LOGIN
    )


def _fetch_issue_comments() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    page_url: str | None = ISSUE_COMMENTS_URL
    seen_pages: set[str] = set()
    seen_ids: set[int] = set()
    previous_id = -1
    while page_url is not None:
        if page_url in seen_pages or not page_url.startswith(ISSUE_URL + "/comments?"):
            raise FinalGateError("provider pagination drift")
        seen_pages.add(page_url)
        page, _page_raw, page_headers = _fetch_json(page_url)
        if not isinstance(page, list):
            raise FinalGateError("provider comment page is malformed")
        for row in page:
            if not isinstance(row, dict) or not isinstance(row.get("id"), int):
                raise FinalGateError("provider comment row is malformed")
            row_id = row["id"]
            if row_id in seen_ids or row_id <= previous_id:
                raise FinalGateError("provider comment order or identity drift")
            seen_ids.add(row_id)
            previous_id = row_id
            result.append(row)
        page_url = _next_link(page_headers)
    return result


def _json_object(body: str) -> dict[str, Any] | None:
    try:
        value = json.loads(body)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _validate_ratification_target(
    target_id: str,
    target_body_sha256: str,
    selection_head: str,
) -> dict[str, Any]:
    if not target_id or not target_id.isdecimal():
        raise FinalGateError("authority change target comment ID is invalid")
    target_url = (
        "https://api.github.com/repos/styx-secure/styx/issues/comments/"
        + target_id
    )
    target, _target_raw, _headers = _fetch_json(target_url)
    if (
        not isinstance(target, dict)
        or target.get("id") != int(target_id)
        or target.get("url") != target_url
        or target.get("issue_url") != ISSUE_URL
        or not _operator(target)
        or target.get("created_at") != target.get("updated_at")
        or target.get("performed_via_github_app") is not None
        or not isinstance(target.get("body"), str)
    ):
        raise FinalGateError("authority change target provenance drift")
    target_body = target["body"].encode("utf-8")
    if _sha256(target_body) != target_body_sha256:
        raise FinalGateError("authority change target body digest drift")
    try:
        target_decision = loads(target_body)
    except CanonicalJsonError as error:
        raise FinalGateError("authority change target is not canonical") from error
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
    if (
        not isinstance(target_decision, dict)
        or set(target_decision) != required
        or dumps(target_decision) != target_body
        or target_decision.get("decision") != "RATIFY"
        or target_decision.get("kind") != POSITIVE_INVENTORY_RATIFICATION_KIND
        or target_decision.get("repository") != "styx-secure/styx"
        or target_decision.get("issue") != 295
        or target_decision.get("baseSha") != BASE_SHA
        or target_decision.get("closureAmendmentSha256") != RATIFIED_V14_SHA256
        or target_decision.get("selectionHead") != selection_head
        or (
            target_decision.get("caseCount"),
            target_decision.get("requestCaseCount"),
            target_decision.get("responseCaseCount"),
        )
        != (80, 65, 15)
        or any(
            not isinstance(target_decision.get(name), str)
            or len(target_decision[name]) != 64
            or any(ch not in "0123456789abcdef" for ch in target_decision[name])
            for name in (
                "candidateManifestSha256",
                "positiveCarrierInventorySha256",
                "phaseAPackageReportSha256",
            )
        )
    ):
        raise FinalGateError("authority change target decision drift")
    return target


def _validate_authority_change(
    row: dict[str, Any],
    selected_comment: dict[str, Any],
) -> tuple[int, bytes, str]:
    row_id = row.get("id")
    selected_id = selected_comment.get("id")
    body = row.get("body")
    if (
        not isinstance(row_id, int)
        or not isinstance(selected_id, int)
        or not isinstance(body, str)
        or row_id <= selected_id
        or not isinstance(row.get("created_at"), str)
        or not isinstance(selected_comment.get("created_at"), str)
        or row["created_at"] <= selected_comment["created_at"]
    ):
        raise FinalGateError("authority change ordering drift")
    url = f"https://api.github.com/repos/styx-secure/styx/issues/comments/{row_id}"
    fetched, fetched_raw, _headers = _fetch_json(url)
    if fetched != row:
        raise FinalGateError("authority change collection/object drift")
    if (
        fetched.get("url") != url
        or fetched.get("issue_url") != ISSUE_URL
        or not _operator(fetched)
        or fetched.get("created_at") != fetched.get("updated_at")
        or fetched.get("performed_via_github_app") is not None
    ):
        raise FinalGateError("authority change provenance drift")
    body_bytes = body.encode("utf-8")
    try:
        change = loads(body_bytes)
    except CanonicalJsonError as error:
        raise FinalGateError("authority change is not canonical JSON") from error
    required = {
        "decision",
        "issue",
        "kind",
        "replacementCommentId",
        "repository",
        "selectionHead",
        "targetCommentBodySha256",
        "targetCommentId",
    }
    if not isinstance(change, dict) or set(change) != required or dumps(change) != body_bytes:
        raise FinalGateError("authority change body shape or final LF drift")
    decision = change["decision"]
    replacement_id = change["replacementCommentId"]
    if (
        decision not in {"WITHDRAW", "SUPERSEDE"}
        or change["kind"] != POSITIVE_INVENTORY_AUTHORITY_CHANGE_KIND
        or change["repository"] != "styx-secure/styx"
        or change["issue"] != 295
        or not isinstance(change["selectionHead"], str)
        or len(change["selectionHead"]) != 40
        or any(ch not in "0123456789abcdef" for ch in change["selectionHead"])
        or not isinstance(change["targetCommentBodySha256"], str)
        or len(change["targetCommentBodySha256"]) != 64
        or any(ch not in "0123456789abcdef" for ch in change["targetCommentBodySha256"])
        or not isinstance(change["targetCommentId"], str)
        or not change["targetCommentId"].isdecimal()
        or (decision == "WITHDRAW" and replacement_id is not None)
        or (
            decision == "SUPERSEDE"
            and (
                not isinstance(replacement_id, str)
                or not replacement_id
                or not replacement_id.isdecimal()
            )
        )
    ):
        raise FinalGateError("authority change value drift")
    target = _validate_ratification_target(
        change["targetCommentId"],
        change["targetCommentBodySha256"],
        change["selectionHead"],
    )
    if row_id <= target["id"] or row["created_at"] <= target["created_at"]:
        raise FinalGateError("authority change does not follow its target")
    return row_id, fetched_raw, change["targetCommentId"]


def _scan_provider_authority(
    decision: dict[str, Any],
    selected_comment: dict[str, Any],
    manifest_sha: str,
) -> tuple[tuple[int, bytes], ...]:
    selected_id = selected_comment.get("id")
    selected_created = selected_comment.get("created_at")
    if not isinstance(selected_id, int) or not isinstance(selected_created, str):
        raise FinalGateError("selected provider authority identity drift")
    matches = 0
    changes: list[tuple[int, bytes]] = []
    for row in _fetch_issue_comments():
        body = row.get("body")
        if not isinstance(body, str):
            continue
        parsed = _json_object(body)
        if (
            _operator(row)
            and isinstance(parsed, dict)
            and parsed.get("kind") == decision["kind"]
            and parsed.get("selectionHead") == decision["selectionHead"]
            and parsed.get("candidateManifestSha256") == manifest_sha
        ):
            matches += 1
            if row.get("id") != selected_id:
                raise FinalGateError("duplicate matching provider authority")

        if (
            _operator(row)
            and isinstance(row.get("id"), int)
            and row["id"] > selected_id
            and isinstance(row.get("created_at"), str)
            and row["created_at"] > selected_created
            and (
                POSITIVE_INVENTORY_AUTHORITY_CHANGE_KIND.encode("utf-8")
                in body.encode("utf-8")
                or (
                    isinstance(parsed, dict)
                    and parsed.get("kind") == POSITIVE_INVENTORY_AUTHORITY_CHANGE_KIND
                )
            )
        ):
            row_id, raw, target_id = _validate_authority_change(row, selected_comment)
            changes.append((row_id, raw))
            if target_id == str(selected_id):
                raise FinalGateError("provider authority was withdrawn or superseded")
    if matches != 1:
        raise FinalGateError("provider authority is absent or duplicated")
    return tuple(changes)


def _validate_provider_authority(comment_id: str, repo: Path) -> dict[str, Any]:
    if not comment_id.isdecimal() or not comment_id:
        raise FinalGateError("provider comment ID is not decimal")
    url = f"https://api.github.com/repos/styx-secure/styx/issues/comments/{comment_id}"
    comment, comment_raw, _headers = _fetch_json(url)
    if not isinstance(comment, dict):
        raise FinalGateError("provider comment is not a JSON object")
    comment_user = comment.get("user")
    if (
        comment.get("id") != int(comment_id)
        or comment.get("url") != url
        or comment.get("issue_url") != "https://api.github.com/repos/styx-secure/styx/issues/295"
        or not isinstance(comment_user, dict)
        or comment_user.get("id") != 141346846
        or comment_user.get("login") != "maverde73"
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
    manifest_sha = _sha256(
        (
            repo.resolve()
            / "tools/causal-flow-simulator/app_core_iface0/contract/APP-CORE-IFACE-0-CANDIDATE-MANIFEST.json"
        ).read_bytes()
    )
    if decision["candidateManifestSha256"] != manifest_sha:
        raise FinalGateError("provider decision does not bind the candidate manifest")

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
    pull_base = pull.get("base")
    pull_head = pull.get("head")
    if (
        pull.get("state") != "open"
        or pull.get("draft") is not True
        or not isinstance(pull_base, dict)
        or not isinstance(pull_head, dict)
        or pull_base.get("sha") != BASE_SHA
        or pull_head.get("sha") != selection_head
    ):
        raise FinalGateError("provider PR freeze identity drift")

    pre_regeneration_scan = _scan_provider_authority(
        decision,
        comment,
        manifest_sha,
    )

    historical, selected = _local_source_blobs(repo.resolve(), selection_head)
    _verify_provider_source_slice(selection_head, historical, selected)

    # Phase B never consumes the reviewed or caller-supplied Phase-A directory.
    # Only after provider authentication does the gate create a fresh private
    # root and independently regenerate the exact carrier population.
    with tempfile.TemporaryDirectory(prefix="styx-app-core-phase-b-entry-") as temporary:
        regenerated = Path(temporary) / "phase-a"
        _generate_phase_a_from_checkout(repo.resolve(), regenerated)
        result = _validate_external_root(repo.resolve(), regenerated)
        if (
            decision["positiveCarrierInventorySha256"]
            != result["inventory_sha256"]
            or decision["phaseAPackageReportSha256"]
            != result["package_report_sha256"]
        ):
            raise FinalGateError("provider decision does not bind regenerated Phase A")

    # Refresh the exact object after regeneration. A modification or deletion
    # during the gate is a fail-closed authority change.
    refreshed, refreshed_raw, _refreshed_headers = _fetch_json(url)
    if refreshed_raw != comment_raw or refreshed != comment:
        raise FinalGateError("provider decision changed during Phase-B entry")
    post_regeneration_scan = _scan_provider_authority(
        decision,
        comment,
        manifest_sha,
    )
    if post_regeneration_scan != pre_regeneration_scan:
        raise FinalGateError("provider authority-change set drifted during Phase-B entry")
    _verify_clean_checkout(repo.resolve(), selection_head)
    return decision


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--phase-a", action="store_true")
    modes.add_argument("--phase-b-entry", action="store_true")
    parser.add_argument("--repo-root-one", required=True, type=Path)
    parser.add_argument("--repo-root-two", type=Path)
    parser.add_argument("--evidence-root-one", type=Path)
    parser.add_argument("--evidence-root-two", type=Path)
    parser.add_argument("--selection-head")
    parser.add_argument("--provider-comment-id")
    args = parser.parse_args(argv)
    try:
        if args.phase_a:
            if (
                args.repo_root_two is None
                or args.evidence_root_one is None
                or args.evidence_root_two is None
                or args.selection_head is None
            ):
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
        subprocess.SubprocessError,
    ) as error:
        print(f"APP-core final gate: FAIL: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
