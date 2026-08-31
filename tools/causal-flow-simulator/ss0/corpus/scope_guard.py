#!/usr/bin/env python3
"""Exact-scope and provider-authority guard for SS-CORPUS-0."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CORPUS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(CORPUS_DIR))
from generate_corpus import NORMATIVE_INPUTS, REPRODUCTION_INPUTS  # noqa: E402


BASE_SHA = "28a5e78e80a014a27b94683479d4e82206abac2f"
ISSUE_NUMBER = 293
CONTRACT_SHA256 = "2c7b4eadb90a1435ba9772b48e84ce6d1a0e727959272d78f02d189e3f992e11"
RATIFICATION_COMMENT_ID = 5485961310
OPERATOR_LOGIN = "maverde73"
OPERATOR_ID = 141346846
K11_COMMENT_ID = 5484188019
K11_COMMENT_SHA256 = "c36c62c5130e59b05d70179d04c348b41be172dd34ebc611ddc7608ec13c7e95"
K11_INVENTORY_SHA256 = "61bea8adc1e36af3bc011df2553f634f0eeeae2c2dba01611a426628341b1861"
AUTHORIZED_CHANGE_INPUTS = (
    ("REUSE.toml", "818f56d3e9cf3f51737025aeb97f4f10d92ac46d70f8bd09ff836631b846ea58"),
    ("README.md", "47953cd2427078af3735ff5e755b7689244da48db9734c465fd750c44f37d0e5"),
    ("LICENSING.md", "12d3b8b5ad51bee77e96b5255198d8a8d67e4de1c1a2fe9ab049c3518525465b"),
    ("CONTRIBUTING.md", "97db7406ee745525995aeeaf47f4157a61d93fc32343bc8337a50ddd0b495722"),
    ("docs/architecture/decisions/ADR-0004-licensing-strategy.md", "8272baedb3e2ce793bde354024843db4068978a63fea7df739dbdcfda0277acb"),
    ("docs/protocol/protocol-hardening-plan.md", "b0ca8d06e25c17afb5e1038c1705c9c398a8ea532aba9c2684667c91b63855e2"),
    ("docs/protocol/styx-app-kernel-v0-decisions.md", "b9b1d4f846783dd01290215509aed224d8c0e43174e375125c67304da4b725bc"),
    ("docs/protocol/review/README.md", "15b4019a6547eed37098c72d7c090059eb6775f62dcbf450950a76479175e4c6"),
    ("docs/protocol/review/styx-app-kernel-v0-review-model.json", "39f39e8d45a74e9d2b6c74cb67b1e985b80c9c86869fa3f590c8d7dedbfa00f9"),
    ("tools/protocol-review-model/tests/test_ss0_corpus_path_approval.py", "0fa62b0f6eb9c74a199081002c51298e1e88b8d095461b0db2f213806429ea0f"),
    ("tools/causal-flow-simulator/README.md", "3d3f4fa1e916f8bf00ed2e529e99dc165b41846477033ab0bb527e972fab0b59"),
)
REQUIRED_HISTORY = (
    "fc7d15356f2299e9acd8a106f46d6631d0c66b74",
    "4a4ebc4b8fc91e500ecd8002801896dc73d5073f",
    "d35052dfbf0631c726f250933bc401f424602f31",
    "bd13fac2df51e8585db6487fff7217fb68fb6242",
    "bd9a06f08131c6fcd4edbaa1e0eeae38d8e28eb5",
    "c8430b2fbcb4bd9d0668e5877210d0244ff8bf81",
)
RATIFICATION_BODY = f"""I ratify the exact SS-CORPUS-0 construction contract in Issue #293.
Contract body SHA-256: {CONTRACT_SHA256}
Base SHA: {BASE_SHA}
K11-SS ordered inventory SHA-256: {K11_INVENTORY_SHA256}
The six generated files must remain fully synthetic Styx-generated data with
no upstream bytes. The Apache mutation file contains only abstract IDs,
requirements, detectors and 41/3 coverage classes; AGPL source target and
replacement strings remain outside the corpus. I approve the exact 28-item
corpus-data mutation registry. This authorizes only corpus construction and
evidence; it does not authorize an adapter, persistence, SDK, transport,
product, demo, deployment or sensitive use."""


class ScopeGuardError(ValueError):
    pass


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        raise ScopeGuardError("provider redirect is forbidden")


def _normalize_body(value: str) -> bytes:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    normalized = "\n".join(line.rstrip(" \t") for line in normalized.split("\n"))
    return (normalized.rstrip("\n") + "\n").encode("utf-8")


def _fetch_json(url: str) -> dict[str, Any]:
    expected_prefix = "https://api.github.com/repos/styx-secure/styx/"
    if not url.startswith(expected_prefix):
        raise ScopeGuardError("provider URL mismatch")
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "styx-ss0-corpus-scope-guard",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.build_opener(_RejectRedirect()).open(request, timeout=30) as response:
            if response.status != 200 or response.geturl() != url:
                raise ScopeGuardError("provider response mismatch")
            value = json.loads(response.read())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
        raise ScopeGuardError("provider evidence is unavailable") from error
    if not isinstance(value, dict):
        raise ScopeGuardError("provider response is not an object")
    return value


def _load_contract_module(repo: Path):
    location = str(repo / "tools/agent-enforcement")
    previous = {
        name: sys.modules.pop(name)
        for name in ("contract", "model")
        if name in sys.modules
    }
    sys.path.insert(0, location)
    try:
        module = importlib.import_module("contract")
    finally:
        sys.path.remove(location)
        sys.modules.pop("contract", None)
        sys.modules.pop("model", None)
        sys.modules.update(previous)
    return module


def _git(repo: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repo,
        env={
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": os.devnull,
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        },
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    if completed.returncode != 0:
        raise ScopeGuardError(f"Git command failed: {arguments[0]}")
    return completed.stdout


def _base_digest(repo: Path, base: str, name: str) -> str:
    return hashlib.sha256(_git(repo, "show", f"{base}:{name}")).hexdigest()


def _changed_paths(repo: Path, base: str, head: str) -> list[dict[str, str]]:
    raw = _git(
        repo,
        "diff", "--name-status", "--find-renames=25%", "--find-copies=25%",
        base, head, "--",
    ).decode("utf-8", "strict")
    rows: list[dict[str, str]] = []
    for line in raw.splitlines():
        fields = line.split("\t")
        status = fields[0]
        if status.startswith(("R", "C")) or len(fields) != 2:
            raise ScopeGuardError("rename/copy relation is forbidden")
        if status not in {"A", "M"}:
            raise ScopeGuardError(f"forbidden change status: {status}")
        rows.append({"path": fields[1], "status": status})
    return rows


def _validate_file(repo: Path, head: str, name: str) -> None:
    path = repo / name
    if not path.is_file() or path.is_symlink():
        raise ScopeGuardError(f"changed path is not a regular file: {name}")
    record = _git(repo, "ls-tree", head, "--", name).decode("utf-8", "strict")
    if not record.startswith("100644 blob ") and not record.startswith("100755 blob "):
        raise ScopeGuardError(f"unsupported Git object type: {name}")
    if b"\0" in path.read_bytes():
        raise ScopeGuardError(f"binary file is forbidden: {name}")
    if Path(name).name in {"package-lock.json", "pubspec.lock", "Cargo.lock"}:
        raise ScopeGuardError(f"lockfile is forbidden: {name}")


def _provider_authority() -> bytes:
    issue_url = f"https://api.github.com/repos/styx-secure/styx/issues/{ISSUE_NUMBER}"
    issue = _fetch_json(issue_url)
    if issue.get("number") != ISSUE_NUMBER or issue.get("state") != "open" or issue.get("url") != issue_url:
        raise ScopeGuardError("Issue provider identity mismatch")
    body = issue.get("body")
    if not isinstance(body, str):
        raise ScopeGuardError("Issue body is unavailable")
    normalized = _normalize_body(body)
    if hashlib.sha256(normalized).hexdigest() != CONTRACT_SHA256:
        raise ScopeGuardError("live contract digest mismatch")

    comment_url = f"https://api.github.com/repos/styx-secure/styx/issues/comments/{RATIFICATION_COMMENT_ID}"
    comment = _fetch_json(comment_url)
    user = comment.get("user")
    if (
        comment.get("id") != RATIFICATION_COMMENT_ID
        or comment.get("url") != comment_url
        or comment.get("issue_url") != issue_url
        or not isinstance(user, dict)
        or user.get("login") != OPERATOR_LOGIN
        or user.get("id") != OPERATOR_ID
        or comment.get("body") != RATIFICATION_BODY
    ):
        raise ScopeGuardError("ratification provider identity mismatch")

    k11_url = f"https://api.github.com/repos/styx-secure/styx/issues/comments/{K11_COMMENT_ID}"
    k11 = _fetch_json(k11_url)
    k11_user = k11.get("user")
    k11_body = k11.get("body")
    if (
        k11.get("id") != K11_COMMENT_ID
        or k11.get("issue_url") != "https://api.github.com/repos/styx-secure/styx/issues/291"
        or not isinstance(k11_user, dict)
        or k11_user.get("login") != OPERATOR_LOGIN
        or k11_user.get("id") != OPERATOR_ID
        or not isinstance(k11_body, str)
        or hashlib.sha256(_normalize_body(k11_body)).hexdigest() != K11_COMMENT_SHA256
    ):
        raise ScopeGuardError("K11-SS provider authority mismatch")
    return normalized


def build_report(repo: Path, base: str, head: str, issue_number: int) -> dict[str, Any]:
    repo = repo.resolve(strict=True)
    if base != BASE_SHA or issue_number != ISSUE_NUMBER:
        raise ScopeGuardError("contract identity mismatch")
    if head != "HEAD" and not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ScopeGuardError("HEAD must be HEAD or a full lowercase object identity")
    resolved_head = _git(repo, "rev-parse", f"{head}^{{commit}}").decode().strip()
    if _git(repo, "rev-parse", "HEAD").decode().strip() != resolved_head:
        raise ScopeGuardError("checkout HEAD mismatch")
    if _git(repo, "merge-base", base, resolved_head).decode().strip() != base:
        raise ScopeGuardError("Base is not an ancestor of HEAD")
    for identity in REQUIRED_HISTORY:
        _git(repo, "cat-file", "-e", f"{identity}^{{commit}}")
    live_body = _provider_authority()
    contract_module = _load_contract_module(repo)
    parsed = contract_module.parse_contract(live_body)
    if parsed.base_sha != base or len(parsed.allowed_patterns) != 32:
        raise ScopeGuardError("parsed contract identity mismatch")

    for name, expected in (*NORMATIVE_INPUTS, *REPRODUCTION_INPUTS):
        if _base_digest(repo, base, name) != expected:
            raise ScopeGuardError(f"immutable Base pin mismatch: {name}")
        if hashlib.sha256((repo / name).read_bytes()).hexdigest() != expected:
            raise ScopeGuardError(f"immutable final pin mismatch: {name}")
    for name, expected in AUTHORIZED_CHANGE_INPUTS:
        if _base_digest(repo, base, name) != expected:
            raise ScopeGuardError(f"authorized-change Base pin mismatch: {name}")

    relation = _changed_paths(repo, base, resolved_head)
    if not relation:
        raise ScopeGuardError("candidate has no changed paths")
    for row in relation:
        evaluation = contract_module.evaluate_path(row["path"], parsed)
        if evaluation.violations:
            raise ScopeGuardError(f"path outside contract: {row['path']}")
        _validate_file(repo, resolved_head, row["path"])
    return {
        "base": base,
        "changedRelation": relation,
        "contractBodySha256": CONTRACT_SHA256,
        "head": resolved_head,
        "issue": ISSUE_NUMBER,
        "k11InventorySha256": K11_INVENTORY_SHA256,
        "ratificationCommentId": RATIFICATION_COMMENT_ID,
        "result": "PASS",
        "schema": "styx.ss0.corpus.scope-report.v1",
    }


def _store(value: dict[str, Any], output: Path) -> None:
    data = (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, name = tempfile.mkstemp(dir=output.parent, prefix=f".{output.name}.", suffix=".tmp")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--issue", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    _store(
        build_report(arguments.repo_root, arguments.base, arguments.head, arguments.issue),
        arguments.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
