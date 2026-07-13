#!/usr/bin/env python3
"""Trusted-base CI adapter for non-blocking Styx scope evidence.

The adapter reads a ``pull_request_target`` event, resolves exactly one local
Issue contract, fetches the pull-request head as Git object data without
updating refs or checking it out, invokes the trusted-base scope guard, and
writes a safe job summary.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any, Callable, Mapping, Sequence
import urllib.error
import urllib.parse
import urllib.request

sys.dont_write_bytecode = True

from model import Diagnostic, EXIT_ERROR, EXIT_FAIL, EXIT_PASS, SCHEMA_ID
from report import build_report, canonical_json_bytes, write_report

ALLOWED_ACTIONS = {
    "opened",
    "reopened",
    "synchronize",
    "ready_for_review",
    "converted_to_draft",
    "edited",
}
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
ISSUE_REFERENCE_RE = re.compile(r"^Styx-Task:[ \t]*#([1-9][0-9]*)[ \t]*$")
CROSS_REPOSITORY_REFERENCE_RE = re.compile(
    r"^Styx-Task:[ \t]*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)#[1-9][0-9]*[ \t]*$"
)
DIAGNOSTIC_CODE_RE = re.compile(r"^[EP]_[A-Z0-9_]{1,62}$")

MAX_EVENT_BYTES = 1_048_576
MAX_API_RESPONSE_BYTES = 1_048_576
MAX_ISSUE_BODY_BYTES = 524_288
MAX_REPORT_BYTES = 4_194_304


def _reject_duplicate_json_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CiAdapterError("E_CI_JSON_DUPLICATE", "JSON object contains a duplicate key")
        result[key] = value
    return result


def _decode_json(raw: bytes, code: str, label: str) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8", "strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except CiAdapterError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise CiAdapterError(code, f"{label} is not valid UTF-8 JSON") from exc


class CiAdapterError(Exception):
    """A deterministic fail-closed CI preparation or publication error."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclasses.dataclass(frozen=True)
class ObservationContext:
    repository: str
    pull_number: int
    issue_number: int
    base_sha: str
    head_sha: str
    execution_id: str
    artifact_name: str


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects so the bearer token cannot be forwarded elsewhere."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


def _positive_decimal(value: str, label: str) -> int:
    if not re.fullmatch(r"[1-9][0-9]*", value):
        raise CiAdapterError("E_CI_INPUT", f"{label} must be a positive decimal integer")
    return int(value)


def _load_json_file(path: Path, *, size_limit: int, code: str) -> Any:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise CiAdapterError(code, f"unable to stat {path.name}") from exc
    if size > size_limit:
        raise CiAdapterError(code, f"{path.name} exceeds the size limit")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CiAdapterError(code, f"unable to read {path.name}") from exc
    return _decode_json(raw, code, path.name)


def _require_dict(value: Any, code: str, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CiAdapterError(code, f"{label} must be a JSON object")
    return value


def _require_string(mapping: Mapping[str, Any], key: str, code: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str):
        raise CiAdapterError(code, f"event field {key!r} must be a string")
    return value


def _require_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA_RE.fullmatch(value) is None:
        raise CiAdapterError("E_CI_EVENT_SHA", f"{label} must be a lowercase full 40-hex SHA")
    return value


def parse_issue_reference(pr_body: str) -> int:
    """Resolve exactly one ``Styx-Task: #N`` line from a PR body."""

    candidate_lines = [line for line in pr_body.splitlines() if "Styx-Task:" in line]
    if not candidate_lines:
        raise CiAdapterError("E_CI_ISSUE_REFERENCE_MISSING", "PR body has no Styx task reference")
    if len(candidate_lines) != 1:
        raise CiAdapterError("E_CI_ISSUE_REFERENCE_AMBIGUOUS", "PR body has multiple Styx task references")
    line = candidate_lines[0]
    cross = CROSS_REPOSITORY_REFERENCE_RE.fullmatch(line)
    if cross is not None:
        raise CiAdapterError(
            "E_CI_ISSUE_REFERENCE_CROSS_REPOSITORY",
            "cross-repository Styx task references are not accepted",
        )
    match = ISSUE_REFERENCE_RE.fullmatch(line)
    if match is None:
        raise CiAdapterError("E_CI_ISSUE_REFERENCE_MALFORMED", "Styx task reference is malformed")
    return int(match.group(1))


def validate_event(
    event: Any,
    *,
    repository: str,
    run_id: str,
    run_attempt: str,
) -> ObservationContext:
    """Validate the trusted event envelope and derive deterministic identifiers."""

    if REPOSITORY_RE.fullmatch(repository) is None:
        raise CiAdapterError("E_CI_INPUT", "repository must use owner/name syntax")
    run_id_number = _positive_decimal(run_id, "run ID")
    run_attempt_number = _positive_decimal(run_attempt, "run attempt")

    root = _require_dict(event, "E_CI_EVENT", "event")
    action = root.get("action")
    if action not in ALLOWED_ACTIONS:
        raise CiAdapterError("E_CI_EVENT_ACTION", "event action is not accepted")

    event_repo = _require_dict(root.get("repository"), "E_CI_EVENT", "event.repository")
    if _require_string(event_repo, "full_name", "E_CI_EVENT") != repository:
        raise CiAdapterError("E_CI_EVENT_REPOSITORY", "event repository does not match the workflow repository")

    pull = _require_dict(root.get("pull_request"), "E_CI_EVENT", "event.pull_request")
    pull_number = pull.get("number", root.get("number"))
    if not isinstance(pull_number, int) or isinstance(pull_number, bool) or pull_number < 1:
        raise CiAdapterError("E_CI_EVENT_PULL", "pull-request number must be a positive integer")
    if root.get("number") != pull_number:
        raise CiAdapterError("E_CI_EVENT_PULL", "event and pull-request numbers do not match")

    body = pull.get("body")
    if not isinstance(body, str):
        raise CiAdapterError("E_CI_ISSUE_REFERENCE_MISSING", "PR body is missing")
    issue_number = parse_issue_reference(body)

    base = _require_dict(pull.get("base"), "E_CI_EVENT", "pull_request.base")
    base_repo = _require_dict(base.get("repo"), "E_CI_EVENT", "pull_request.base.repo")
    if _require_string(base_repo, "full_name", "E_CI_EVENT") != repository:
        raise CiAdapterError("E_CI_EVENT_REPOSITORY", "pull-request base repository is not local")
    base_sha = _require_sha(base.get("sha"), "base SHA")

    head = _require_dict(pull.get("head"), "E_CI_EVENT", "pull_request.head")
    head_sha = _require_sha(head.get("sha"), "head SHA")
    head_repo = _require_dict(head.get("repo"), "E_CI_EVENT", "pull_request.head.repo")
    head_full_name = _require_string(head_repo, "full_name", "E_CI_EVENT")
    if REPOSITORY_RE.fullmatch(head_full_name) is None:
        raise CiAdapterError("E_CI_EVENT_REPOSITORY", "pull-request head repository name is malformed")

    execution_id = (
        f"gha-pr-{pull_number}-run-{run_id_number}-attempt-{run_attempt_number}-head-{head_sha}"
    )
    artifact_name = (
        f"styx-scope-pr-{pull_number}-{head_sha}-run-{run_id_number}-attempt-{run_attempt_number}"
    )
    return ObservationContext(
        repository=repository,
        pull_number=pull_number,
        issue_number=issue_number,
        base_sha=base_sha,
        head_sha=head_sha,
        execution_id=execution_id,
        artifact_name=artifact_name,
    )


def _validate_https_base_url(value: str, label: str, *, allow_path: bool) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise CiAdapterError("E_CI_INPUT", f"{label} must be an HTTPS base URL")
    if parsed.query or parsed.fragment:
        raise CiAdapterError("E_CI_INPUT", f"{label} must not contain query or fragment data")
    if not allow_path and parsed.path not in {"", "/"}:
        raise CiAdapterError("E_CI_INPUT", f"{label} must not contain a path")
    return value.rstrip("/")


def _read_limited_response(response, limit: int) -> bytes:
    length = response.headers.get("Content-Length")
    if length is not None:
        try:
            if int(length) > limit:
                raise CiAdapterError("E_CI_ISSUE_RESPONSE", "Issue API response exceeds the size limit")
        except ValueError as exc:
            raise CiAdapterError("E_CI_ISSUE_RESPONSE", "Issue API Content-Length is invalid") from exc
    raw = response.read(limit + 1)
    if len(raw) > limit:
        raise CiAdapterError("E_CI_ISSUE_RESPONSE", "Issue API response exceeds the size limit")
    return raw


def fetch_issue_body(
    context: ObservationContext,
    *,
    api_url: str,
    token: str,
    opener=None,
) -> bytes:
    """Fetch the exact Issue body text through a read-only GitHub REST request."""

    api_base = _validate_https_base_url(api_url, "API URL", allow_path=True)
    if not token or any(ord(char) < 33 or ord(char) == 127 for char in token):
        raise CiAdapterError("E_CI_TOKEN", "ephemeral GitHub token is missing or malformed")

    owner, repo = context.repository.split("/", 1)
    endpoint = (
        f"{api_base}/repos/{urllib.parse.quote(owner, safe='')}/"
        f"{urllib.parse.quote(repo, safe='')}/issues/{context.issue_number}"
    )
    request = urllib.request.Request(
        endpoint,
        method="GET",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "styx-scope-evidence/v1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    client = opener or urllib.request.build_opener(NoRedirectHandler())
    try:
        with client.open(request, timeout=20) as response:
            status = getattr(response, "status", None)
            if status != 200:
                raise CiAdapterError("E_CI_ISSUE_HTTP", "Issue API did not return HTTP 200")
            content_type = response.headers.get("Content-Type", "")
            if "json" not in content_type.lower():
                raise CiAdapterError("E_CI_ISSUE_RESPONSE", "Issue API response is not JSON")
            raw = _read_limited_response(response, MAX_API_RESPONSE_BYTES)
    except CiAdapterError:
        raise
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            code = "E_CI_ISSUE_FORBIDDEN"
        elif exc.code == 404:
            code = "E_CI_ISSUE_NOT_FOUND"
        elif 300 <= exc.code < 400:
            code = "E_CI_ISSUE_REDIRECT"
        else:
            code = "E_CI_ISSUE_HTTP"
        raise CiAdapterError(code, f"Issue API request failed with HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CiAdapterError("E_CI_ISSUE_NETWORK", "Issue API request failed") from exc

    payload = _decode_json(raw, "E_CI_ISSUE_RESPONSE", "Issue API response")
    issue = _require_dict(payload, "E_CI_ISSUE_RESPONSE", "Issue API response")
    if issue.get("number") != context.issue_number:
        raise CiAdapterError("E_CI_ISSUE_RESPONSE", "Issue API returned a different issue number")
    if "pull_request" in issue:
        raise CiAdapterError("E_CI_ISSUE_RESPONSE", "referenced item is a pull request, not an Issue")
    if issue.get("state") != "open":
        raise CiAdapterError("E_CI_ISSUE_STATE", "referenced Issue is not open")
    body = issue.get("body")
    if not isinstance(body, str):
        raise CiAdapterError("E_CI_ISSUE_BODY", "Issue body is missing")
    try:
        body_bytes = body.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise CiAdapterError("E_CI_ISSUE_BODY", "Issue body cannot be encoded as UTF-8") from exc
    if len(body_bytes) > MAX_ISSUE_BODY_BYTES:
        raise CiAdapterError("E_CI_ISSUE_BODY", "Issue body exceeds the size limit")
    return body_bytes


def _atomic_write_bytes(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp_path = Path(raw_temp)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
    except BaseException:
        try:
            temp_path.unlink()
        except FileNotFoundError:
            pass
        raise


def _is_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve(strict=False).relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        return False
    return True


def _sanitized_git_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = os.environ.copy()
    for key in tuple(environment):
        if key in {
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_INDEX_FILE",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_CONFIG_COUNT",
        } or key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
            environment.pop(key, None)
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
            "LC_ALL": "C",
            "LANG": "C",
        }
    )
    if extra:
        environment.update(extra)
    return environment


def _run_git(
    repo: Path,
    arguments: Sequence[str],
    *,
    check: bool = True,
    env_extra: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            [
                "git",
                "-c",
                "core.quotepath=false",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
                "-c",
                "fetch.writeCommitGraph=false",
                *arguments,
            ],
            cwd=repo,
            check=check,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=_sanitized_git_environment(env_extra),
        )
    except FileNotFoundError as exc:
        raise CiAdapterError("E_CI_GIT", "git executable was not found") from exc
    except subprocess.CalledProcessError as exc:
        raise CiAdapterError("E_CI_GIT", "Git object preparation failed") from exc


def fetch_pull_head_object(
    context: ObservationContext,
    *,
    repo: Path,
    server_url: str,
    token: str,
) -> None:
    """Fetch the PR head object without writing FETCH_HEAD or any local ref."""

    server_base = _validate_https_base_url(server_url, "server URL", allow_path=False)
    if not token or any(ord(char) < 33 or ord(char) == 127 for char in token):
        raise CiAdapterError("E_CI_TOKEN", "ephemeral GitHub token is missing or malformed")
    if not repo.is_dir():
        raise CiAdapterError("E_CI_REPOSITORY", "repository path does not exist")

    actual_head = _run_git(repo, ["rev-parse", "HEAD"]).stdout.strip()
    if actual_head != context.base_sha:
        raise CiAdapterError("E_CI_REPOSITORY", "trusted checkout HEAD does not equal the event base SHA")
    if _run_git(repo, ["status", "--porcelain=v1", "--untracked-files=all"]).stdout:
        raise CiAdapterError("E_CI_REPOSITORY", "trusted checkout is dirty before object preparation")
    if _run_git(repo, ["rev-parse", "--is-shallow-repository"]).stdout.strip() == "true":
        raise CiAdapterError("E_CI_REPOSITORY", "trusted checkout is shallow")

    credentials = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("ascii")
    endpoint = f"{server_base}/{context.repository}.git"
    extra = {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": f"http.{server_base}/.extraheader",
        "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {credentials}",
    }
    _run_git(
        repo,
        [
            "fetch",
            "--no-tags",
            "--no-recurse-submodules",
            "--no-write-fetch-head",
            endpoint,
            f"refs/pull/{context.pull_number}/head",
        ],
        env_extra=extra,
    )
    object_check = _run_git(repo, ["cat-file", "-e", f"{context.head_sha}^{{commit}}"], check=False)
    if object_check.returncode != 0:
        raise CiAdapterError("E_CI_GIT", "fetched pull ref does not contain the event head commit")
    ancestry = _run_git(
        repo,
        ["merge-base", "--is-ancestor", context.base_sha, context.head_sha],
        check=False,
    )
    if ancestry.returncode != 0:
        raise CiAdapterError("E_CI_GIT_ANCESTRY", "base SHA is not an ancestor of head SHA")

    final_head = _run_git(repo, ["rev-parse", "HEAD"]).stdout.strip()
    final_status = _run_git(repo, ["status", "--porcelain=v1", "--untracked-files=all"]).stdout
    if final_head != context.base_sha or final_status:
        raise CiAdapterError("E_CI_REPOSITORY_CHANGED", "object preparation changed the checkout")


def _write_error_report(
    report_path: Path,
    *,
    context: ObservationContext | None,
    execution_id: str,
    diagnostic: Diagnostic,
    issue_body_sha256: str | None = None,
) -> None:
    report = build_report(
        issue_number=context.issue_number if context else None,
        execution_id=execution_id,
        base_sha=context.base_sha if context else None,
        head_sha=context.head_sha if context else None,
        issue_body_sha256=issue_body_sha256,
        contract=None,
        entries=(),
        evaluations={},
        diagnostics=(diagnostic,),
        verdict="ERROR",
    )
    write_report(report_path, report)


def _run_guard(
    context: ObservationContext,
    *,
    repo: Path,
    issue_body_path: Path,
    report_path: Path,
) -> int:
    tool = repo / "tools" / "agent-enforcement" / "scope_guard.py"
    if not tool.is_file():
        raise CiAdapterError("E_CI_GUARD_MISSING", "trusted scope guard is missing")
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment.pop("GITHUB_TOKEN", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [
            sys.executable,
            str(tool),
            "--issue-number",
            str(context.issue_number),
            "--issue-body-file",
            str(issue_body_path),
            "--base-sha",
            context.base_sha,
            "--head-sha",
            context.head_sha,
            "--worktree-sha",
            context.base_sha,
            "--execution-id",
            context.execution_id,
            "--output",
            str(report_path),
            "--repo",
            str(repo),
        ],
        cwd=repo,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    return result.returncode


def _validated_report(report_path: Path, context: ObservationContext) -> tuple[dict[str, Any], int]:
    try:
        raw = report_path.read_bytes()
    except OSError as exc:
        raise CiAdapterError("E_CI_REPORT_INVALID", "unable to read scope report") from exc
    if len(raw) > MAX_REPORT_BYTES:
        raise CiAdapterError("E_CI_REPORT_INVALID", "scope report exceeds the size limit")
    report = _decode_json(raw, "E_CI_REPORT_INVALID", "scope report")
    report = _require_dict(report, "E_CI_REPORT_INVALID", "scope report")
    if raw != canonical_json_bytes(report):
        raise CiAdapterError("E_CI_REPORT_INVALID", "scope report is not canonical JSON")
    verdict = report.get("verdict")
    expected_exit = {"PASS": EXIT_PASS, "FAIL": EXIT_FAIL, "ERROR": EXIT_ERROR}.get(verdict)
    if expected_exit is None:
        raise CiAdapterError("E_CI_REPORT_INVALID", "scope report verdict is invalid")
    expected = {
        "schema": SCHEMA_ID,
        "issue_number": context.issue_number,
        "execution_id": context.execution_id,
        "base_sha": context.base_sha,
        "head_sha": context.head_sha,
    }
    for key, value in expected.items():
        if report.get(key) != value:
            raise CiAdapterError("E_CI_REPORT_INVALID", f"scope report field {key!r} is inconsistent")
    return report, expected_exit


def run_observation(
    *,
    event_file: Path,
    repo: Path,
    runner_temp: Path,
    repository: str,
    api_url: str,
    server_url: str,
    run_id: str,
    run_attempt: str,
    report_path: Path,
    token: str,
    issue_fetcher: Callable[..., bytes] = fetch_issue_body,
    head_fetcher: Callable[..., None] = fetch_pull_head_object,
    guard_runner: Callable[..., int] = _run_guard,
) -> int:
    """Run one observation and return the stable PASS/FAIL/ERROR exit class."""

    context: ObservationContext | None = None
    fallback_execution_id = "gha-run-unresolved"
    issue_body_sha256: str | None = None
    report_path_safe = False
    try:
        runner_temp = runner_temp.resolve(strict=True)
        repo = repo.resolve(strict=True)
        report_path = report_path.resolve(strict=False)
        if not _is_within(runner_temp, report_path):
            raise CiAdapterError("E_CI_OUTPUT", "report path must be inside RUNNER_TEMP")
        report_path_safe = True
        event = _load_json_file(event_file, size_limit=MAX_EVENT_BYTES, code="E_CI_EVENT")
        context = validate_event(event, repository=repository, run_id=run_id, run_attempt=run_attempt)
        body = issue_fetcher(context, api_url=api_url, token=token)
        issue_body_sha256 = hashlib.sha256(body).hexdigest()
        issue_body_path = runner_temp / f"styx-issue-{context.issue_number}.md"
        _atomic_write_bytes(issue_body_path, body)
        head_fetcher(context, repo=repo, server_url=server_url, token=token)
        return_code = guard_runner(
            context,
            repo=repo,
            issue_body_path=issue_body_path,
            report_path=report_path,
        )
        if return_code not in {EXIT_PASS, EXIT_FAIL, EXIT_ERROR}:
            raise CiAdapterError("E_CI_GUARD_EXIT", "scope guard returned an undocumented exit code")
        if not report_path.is_file():
            raise CiAdapterError("E_CI_REPORT_MISSING", "scope guard did not write a report")
        _, report_exit = _validated_report(report_path, context)
        if report_exit != return_code:
            raise CiAdapterError("E_CI_REPORT_INVALID", "scope report verdict and process exit code disagree")
        return return_code
    except CiAdapterError as exc:
        execution_id = context.execution_id if context else fallback_execution_id
        try:
            if not report_path_safe:
                return EXIT_ERROR
            _write_error_report(
                report_path,
                context=context,
                execution_id=execution_id,
                diagnostic=Diagnostic(exc.code, exc.message, "error"),
                issue_body_sha256=issue_body_sha256,
            )
        except OSError:
            pass
        return EXIT_ERROR
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError) as exc:
        try:
            if not report_path_safe:
                return EXIT_ERROR
            _write_error_report(
                report_path,
                context=context,
                execution_id=context.execution_id if context else fallback_execution_id,
                diagnostic=Diagnostic("E_CI_INTERNAL", "unexpected CI adapter failure", "error"),
                issue_body_sha256=issue_body_sha256,
            )
        except OSError:
            pass
        return EXIT_ERROR


def _safe_diagnostic_codes(report: Mapping[str, Any]) -> list[str]:
    raw = report.get("diagnostics")
    if not isinstance(raw, list):
        return []
    result: list[str] = []
    for item in raw[:1000]:
        if not isinstance(item, dict):
            continue
        code = item.get("code")
        if isinstance(code, str) and DIAGNOSTIC_CODE_RE.fullmatch(code) and code not in result:
            result.append(code)
        if len(result) == 20:
            break
    return result


def write_safe_summary(report_path: Path, summary_path: Path) -> int:
    """Append a summary containing no raw untrusted Issue, PR, path or message text."""

    try:
        report = _load_json_file(report_path, size_limit=MAX_REPORT_BYTES, code="E_CI_REPORT_INVALID")
        report = _require_dict(report, "E_CI_REPORT_INVALID", "scope report")
        verdict = report.get("verdict")
        exit_code = {"PASS": EXIT_PASS, "FAIL": EXIT_FAIL, "ERROR": EXIT_ERROR}.get(verdict)
        if exit_code is None or report.get("schema") != SCHEMA_ID:
            raise CiAdapterError("E_CI_REPORT_INVALID", "report metadata is invalid")
        issue_number = report.get("issue_number")
        issue_text = str(issue_number) if isinstance(issue_number, int) and issue_number > 0 else "unresolved"
        base_sha = report.get("base_sha")
        head_sha = report.get("head_sha")
        base_text = base_sha if isinstance(base_sha, str) and SHA_RE.fullmatch(base_sha) else "unresolved"
        head_text = head_sha if isinstance(head_sha, str) and SHA_RE.fullmatch(head_sha) else "unresolved"
        entries = report.get("changed_entries")
        diagnostics = report.get("diagnostics")
        entry_count = len(entries) if isinstance(entries, list) else 0
        diagnostic_count = len(diagnostics) if isinstance(diagnostics, list) else 0
        codes = _safe_diagnostic_codes(report)
        code_text = ", ".join(f"`{code}`" for code in codes) if codes else "none"
        lines = [
            "## Styx scope evidence",
            "",
            "| Field | Value |",
            "| --- | --- |",
            f"| Verdict | **{verdict}** |",
            f"| Issue | #{issue_text} |" if issue_text != "unresolved" else "| Issue | unresolved |",
            f"| Base SHA | `{base_text}` |" if base_text != "unresolved" else "| Base SHA | unresolved |",
            f"| Head SHA | `{head_text}` |" if head_text != "unresolved" else "| Head SHA | unresolved |",
            f"| Changed entries | {entry_count} |",
            f"| Diagnostics | {diagnostic_count} |",
            f"| Diagnostic codes | {code_text} |",
            "",
            "Raw Issue text, paths and diagnostic messages are intentionally omitted.",
            "",
        ]
    except CiAdapterError:
        exit_code = EXIT_ERROR
        lines = [
            "## Styx scope evidence",
            "",
            "**ERROR** — the canonical report is missing or invalid.",
            "",
            "No untrusted report content was rendered.",
            "",
        ]
    try:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with summary_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(lines))
    except OSError:
        return EXIT_ERROR
    return exit_code


class AdapterArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:  # type: ignore[override]
        self.print_usage(sys.stderr)
        print(f"{self.prog}: error: {message}", file=sys.stderr)
        raise SystemExit(EXIT_ERROR)


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = AdapterArgumentParser(description="Publish trusted-base Styx scope evidence in CI.")
    subparsers = parser.add_subparsers(dest="command", required=True, parser_class=AdapterArgumentParser)

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--event-file", type=Path, required=True)
    run_parser.add_argument("--repo", type=Path, required=True)
    run_parser.add_argument("--runner-temp", type=Path, required=True)
    run_parser.add_argument("--repository", required=True)
    run_parser.add_argument("--api-url", required=True)
    run_parser.add_argument("--server-url", required=True)
    run_parser.add_argument("--run-id", required=True)
    run_parser.add_argument("--run-attempt", required=True)
    run_parser.add_argument("--report", type=Path, required=True)

    summary_parser = subparsers.add_parser("summarize")
    summary_parser.add_argument("--report", type=Path, required=True)
    summary_parser.add_argument("--summary", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.command == "summarize":
        return write_safe_summary(args.report, args.summary)
    return run_observation(
        event_file=args.event_file,
        repo=args.repo,
        runner_temp=args.runner_temp,
        repository=args.repository,
        api_url=args.api_url,
        server_url=args.server_url,
        run_id=args.run_id,
        run_attempt=args.run_attempt,
        report_path=args.report,
        token=os.environ.get("GITHUB_TOKEN", ""),
    )


if __name__ == "__main__":
    raise SystemExit(main())
