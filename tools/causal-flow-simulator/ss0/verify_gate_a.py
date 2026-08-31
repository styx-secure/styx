#!/usr/bin/env python3
"""Verify the immutable SS-0 Gate-A provider binding.

This file is the Phase-A trust root.  It deliberately does not import any
other repository module: Phase B may change derived validators, but cannot
change this verifier after the human Gate-A binding.
"""

from __future__ import annotations

import sys as _bootstrap_sys


if not (
    _bootstrap_sys.flags.isolated
    and _bootstrap_sys.flags.no_site
    and _bootstrap_sys.flags.dont_write_bytecode
    and getattr(_bootstrap_sys.flags, "safe_path", 0)
):
    raise RuntimeError(
        "Gate-A verifier requires Python isolated mode (-I -S -B) "
        "with safe-path support"
    )


import os as _bootstrap_os  # noqa: E402 - only after the isolation gate


_BOOTSTRAP_BASE = _bootstrap_os.path.realpath(_bootstrap_sys.base_prefix)


def _trusted_import_path(entry: str) -> bool:
    """Retain only interpreter-owned paths before importing the stdlib."""

    try:
        resolved = _bootstrap_os.path.realpath(entry or _bootstrap_os.getcwd())
        return _bootstrap_os.path.commonpath((resolved, _BOOTSTRAP_BASE)) == _BOOTSTRAP_BASE
    except (OSError, ValueError):
        return False


_bootstrap_sys.path[:] = [entry for entry in _bootstrap_sys.path if _trusted_import_path(entry)]
if not _bootstrap_sys.path:
    raise RuntimeError("no trusted standard-library import path remains")
_BLOCKED_CALLER_ENVIRONMENT = {
    "ALL_PROXY",
    "CURL_CA_BUNDLE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "OPENSSL_CONF",
    "OPENSSL_MODULES",
    "PYTHONHOME",
    "PYTHONPATH",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "SSLKEYLOGFILE",
}
for _environment_name in tuple(_bootstrap_os.environ):
    if _environment_name.upper() in _BLOCKED_CALLER_ENVIRONMENT:
        _bootstrap_os.environ.pop(_environment_name, None)

import argparse
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)


ISSUE_NUMBER = 285
ISSUE_API_URL = "https://api.github.com/repos/styx-secure/styx/issues/285"
COMMENT_API_PREFIX = "https://api.github.com/repos/styx-secure/styx/issues/comments/"
OPERATOR_LOGIN = "maverde73"
OPERATOR_ID = 141346846
BASE_SHA = "bd13fac2df51e8585db6487fff7217fb68fb6242"
ISSUE_BODY_SHA256 = "fe56a2390afc81c8ebcabe957f06e5e83abb04ddeac7e44eec3c72eb751f2df1"
GATE_SCHEMA = "styx-ss0-gate-a/v1"
MODEL_PATH = Path("docs/protocol/review/styx-app-kernel-v0-review-model.json")
SOURCE_PATH = "docs/protocol/styx-secure-session-v0-decisions.md"
SOURCE_ID = "secure_session_decisions"
MAX_PROVIDER_BYTES = 256 * 1024
GIT_EXECUTABLE = "/usr/bin/git"
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
FROZEN_PATHS = (
    "docs/protocol/protocol-hardening-plan.md",
    "docs/protocol/styx-secure-session-v0-decisions.md",
    "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md",
    "docs/security/STYX-THREAT-MODEL.md",
    "tools/causal-flow-simulator/ss0/verify_gate_a.py",
)


class GateAError(ValueError):
    """A fail-closed Gate-A validation error."""


class _RejectRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):  # noqa: ANN001
        raise HTTPError(request.full_url, code, "redirect rejected", headers, file_pointer)


def provider_opener():
    """Build a direct-TLS opener without caller-selected proxy or CA inputs."""

    context = ssl.create_default_context()
    return build_opener(
        ProxyHandler({}),
        HTTPSHandler(context=context),
        _RejectRedirect(),
    )


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateAError(message)


def digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def provider_url(comment_id: str) -> str:
    require(bool(comment_id) and comment_id.isascii() and comment_id.isdecimal(),
            "comment id must be decimal ASCII")
    require(str(int(comment_id)) == comment_id, "comment id must be canonical decimal")
    return COMMENT_API_PREFIX + comment_id


def fetch_comment(comment_id: str) -> tuple[bytes, dict[str, object]]:
    url = provider_url(comment_id)
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "styx-ss0-gate-a-verifier",
        },
    )
    try:
        with provider_opener().open(request, timeout=30) as response:
            require(response.geturl() == url, "provider response URL mismatch")
            length = response.headers.get("Content-Length")
            if length is not None:
                require(int(length) <= MAX_PROVIDER_BYTES, "provider response is oversized")
            raw = response.read(MAX_PROVIDER_BYTES + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as error:
        raise GateAError("provider fetch failed") from error
    require(len(raw) <= MAX_PROVIDER_BYTES, "provider response is oversized")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GateAError("provider response is not valid JSON") from error
    require(isinstance(value, dict), "provider response must be an object")
    return raw, value


def parse_gate_body(body: object) -> dict[str, object]:
    require(isinstance(body, str), "Gate-A comment body is missing")
    try:
        value = json.loads(body)
    except json.JSONDecodeError as error:
        raise GateAError("Gate-A body must be one JSON object") from error
    require(isinstance(value, dict), "Gate-A body must be an object")
    expected_keys = {
        "schema",
        "status",
        "operator",
        "issue_number",
        "issue_body_sha256",
        "base_sha",
        "phase_a_head",
        "frozen_files",
    }
    require(set(value) == expected_keys, "Gate-A body schema mismatch")
    require(value["schema"] == GATE_SCHEMA, "Gate-A schema mismatch")
    require(value["status"] == "accepted", "Gate A was not accepted")
    require(value["operator"] == OPERATOR_LOGIN, "Gate-A operator mismatch")
    require(value["issue_number"] == ISSUE_NUMBER, "Gate-A Issue mismatch")
    require(value["issue_body_sha256"] == ISSUE_BODY_SHA256,
            "ratified Issue-body digest mismatch")
    require(value["base_sha"] == BASE_SHA, "Gate-A Base mismatch")
    require(isinstance(value["phase_a_head"], str)
            and HEX40.fullmatch(value["phase_a_head"]) is not None,
            "Gate-A Phase-A commit is invalid")
    frozen = value["frozen_files"]
    require(isinstance(frozen, dict) and set(frozen) == set(FROZEN_PATHS),
            "Gate-A frozen-file set mismatch")
    for path, expected_digest in frozen.items():
        require(isinstance(path, str) and isinstance(expected_digest, str)
                and HEX64.fullmatch(expected_digest) is not None,
                "Gate-A frozen-file digest is invalid")
    return value


def validate_provider_comment(
    comment: dict[str, object], comment_id: str
) -> dict[str, object]:
    url = provider_url(comment_id)
    user = comment.get("user")
    require(comment.get("id") == int(comment_id), "provider comment id mismatch")
    require(comment.get("url") == url, "provider comment URL mismatch")
    require(comment.get("issue_url") == ISSUE_API_URL, "provider Issue URL mismatch")
    require(isinstance(user, dict), "provider user is missing")
    require(user.get("id") == OPERATOR_ID and user.get("login") == OPERATOR_LOGIN,
            "provider identity mismatch")
    created_at = comment.get("created_at")
    updated_at = comment.get("updated_at")
    require(isinstance(created_at, str) and bool(created_at),
            "provider created_at is missing")
    require(isinstance(updated_at, str) and bool(updated_at),
            "provider updated_at is missing")
    require(created_at == updated_at, "Gate-A comment was edited")
    return parse_gate_body(comment.get("body"))


def git_environment() -> dict[str, str]:
    """Return a closed environment for every trust-root Git invocation."""

    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def run_git_process(repo: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [GIT_EXECUTABLE, "-C", str(repo), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=git_environment(),
    )


def run_git(repo: Path, *arguments: str, allow_failure: bool = False) -> bytes:
    process = run_git_process(repo, *arguments)
    if process.returncode != 0 and not allow_failure:
        raise GateAError("Git validation failed: " + " ".join(arguments))
    return process.stdout


def resolve_commit(repo: Path, revision: str) -> str:
    raw = run_git(repo, "rev-parse", "--verify", revision + "^{commit}")
    value = raw.decode("ascii", "strict").strip()
    require(HEX40.fullmatch(value) is not None, "Git commit identity is invalid")
    return value


def collect_checkout_facts(
    repo: Path, base: str, phase_a_head: str, final_head: str
) -> dict[str, object]:
    root = Path(run_git(repo, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    require(root == repo, "repository root mismatch")
    clean = not bool(run_git(repo, "status", "--porcelain=v1", "--untracked-files=all"))
    require(clean, "checkout is dirty")
    resolved_base = resolve_commit(repo, base)
    resolved_phase = resolve_commit(repo, phase_a_head)
    resolved_final = resolve_commit(repo, final_head)
    resolved_head = resolve_commit(repo, "HEAD")
    base_to_phase = run_git_process(
        repo, "merge-base", "--is-ancestor", resolved_base, resolved_phase,
    ).returncode == 0
    phase_to_final = run_git_process(
        repo, "merge-base", "--is-ancestor", resolved_phase, resolved_final,
    ).returncode == 0
    changed = tuple(sorted(filter(None, run_git(
        repo, "diff", "--name-only", "--no-renames", resolved_base, resolved_phase,
    ).decode("utf-8", "strict").splitlines())))
    phase_digests: dict[str, str] = {}
    working_digests: dict[str, str] = {}
    for relative in FROZEN_PATHS:
        path = repo / relative
        require(path.is_file() and not path.is_symlink(), "frozen path is not a regular file")
        phase_digests[relative] = digest(run_git(repo, "show", resolved_phase + ":" + relative))
        working_digests[relative] = digest(path.read_bytes())
    return {
        "base": resolved_base,
        "phase": resolved_phase,
        "final": resolved_final,
        "head": resolved_head,
        "clean": clean,
        "base_to_phase": base_to_phase,
        "phase_to_final": phase_to_final,
        "changed": changed,
        "phase_digests": phase_digests,
        "working_digests": working_digests,
    }


def validate_checkout_facts(
    facts: dict[str, object], gate: dict[str, object], mode: str
) -> None:
    require(facts.get("clean") is True, "checkout is dirty")
    require(facts.get("base") == BASE_SHA, "checkout Base mismatch")
    require(facts.get("phase") == gate["phase_a_head"], "Phase-A commit mismatch")
    require(facts.get("head") == facts.get("final"), "final HEAD is not checked out")
    require(facts.get("base_to_phase") is True, "Base is not ancestor of Phase A")
    require(facts.get("phase_to_final") is True, "Phase A is not ancestor of final HEAD")
    if mode == "frozen":
        require(facts.get("final") == facts.get("phase"),
                "frozen mode must run at the exact Phase-A commit")
    require(tuple(facts.get("changed", ())) == tuple(sorted(FROZEN_PATHS)),
            "Phase-A path set mismatch")
    phase_digests = facts.get("phase_digests")
    working_digests = facts.get("working_digests")
    require(isinstance(phase_digests, dict) and isinstance(working_digests, dict),
            "frozen digest evidence missing")
    require(phase_digests == gate["frozen_files"], "Phase-A frozen digest mismatch")
    require(working_digests == gate["frozen_files"], "frozen-file byte drift")


def validate_model_value(model: object, expected_source_digest: str) -> None:
    require(isinstance(model, dict), "review model must be an object")
    sources = model.get("sources")
    require(isinstance(sources, list), "review-model sources missing")
    matches = [source for source in sources if isinstance(source, dict)
               and source.get("path") == SOURCE_PATH]
    require(len(matches) == 1, "secure-session model source must occur exactly once")
    source = matches[0]
    require(set(source) == {"authority", "id", "path", "sha256"},
            "secure-session model source schema mismatch")
    require(source.get("authority") == "normative", "secure-session source authority mismatch")
    require(source.get("id") == SOURCE_ID, "secure-session source id mismatch")
    require(source.get("sha256") == expected_source_digest,
            "secure-session model source digest mismatch")


def validate_mode(
    mode: str, model: object | None, expected_source_digest: str
) -> None:
    require(mode in {"frozen", "model-binding"}, "unknown verifier mode")
    if mode == "frozen":
        return
    require(model is not None, "model source is required in model-binding mode")
    validate_model_value(model, expected_source_digest)


def load_and_validate_model(repo: Path, mode: str, gate: dict[str, object]) -> None:
    if mode == "frozen":
        validate_mode(mode, None, gate["frozen_files"][SOURCE_PATH])
        return
    path = repo / MODEL_PATH
    try:
        model = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GateAError("review model is missing or invalid") from error
    actual_source_digest = digest((repo / SOURCE_PATH).read_bytes())
    require(actual_source_digest == gate["frozen_files"][SOURCE_PATH],
            "secure-session source differs from Gate A")
    validate_mode(mode, model, actual_source_digest)


def store_external_evidence(path: Path, value: dict[str, object], repo: Path) -> None:
    target = path.resolve(strict=False)
    require(target != repo and repo not in target.parents,
            "Gate-A evidence must be outside the repository")
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        with target.open("x", encoding="utf-8", newline="\n") as output:
            json.dump(value, output, sort_keys=True, indent=2)
            output.write("\n")
    except FileExistsError as error:
        raise GateAError("refusing to overwrite Gate-A evidence") from error


def self_test() -> None:
    import_root = Path(sys.base_prefix).resolve()
    script_root = Path(__file__).resolve().parent
    require(
        all(name.upper() not in _BLOCKED_CALLER_ENVIRONMENT for name in os.environ),
        "unsafe caller environment survived bootstrap",
    )
    require(
        sys.flags.isolated == 1
        and sys.flags.no_site == 1
        and sys.flags.dont_write_bytecode == 1
        and sys.flags.safe_path == 1,
        "required Python isolation flags are not active",
    )
    require(Path(sys.executable).is_absolute(), "Python executable is not absolute")
    require(Path(GIT_EXECUTABLE).is_absolute(), "Git executable is not absolute")
    for entry in sys.path:
        resolved = Path(entry or ".").resolve()
        require(import_root == resolved or import_root in resolved.parents,
                "non-interpreter import path survived bootstrap")
        require(resolved != script_root, "sibling-module import path survived bootstrap")
    require(git_environment() == {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }, "Git environment is not closed")
    opener = provider_opener()
    proxy_handlers = [handler for handler in opener.handlers
                      if isinstance(handler, ProxyHandler)]
    https_handlers = [handler for handler in opener.handlers
                      if isinstance(handler, HTTPSHandler)]
    require(not proxy_handlers, "provider opener permits a proxy")
    require(len(https_handlers) == 1, "provider opener TLS handler mismatch")
    tls_context = https_handlers[0]._context  # noqa: SLF001 - frozen self-test
    require(tls_context.verify_mode == ssl.CERT_REQUIRED and tls_context.check_hostname,
            "provider TLS verification is not strict")

    repo = Path.cwd().resolve()
    phase = resolve_commit(repo, "HEAD")
    actual_facts = collect_checkout_facts(repo, BASE_SHA, phase, phase)
    require(tuple(actual_facts["changed"]) == tuple(sorted(FROZEN_PATHS)),
            "self-test checkout does not contain the exact Phase-A path set")
    frozen = dict(actual_facts["phase_digests"])
    body = {
        "schema": GATE_SCHEMA,
        "status": "accepted",
        "operator": OPERATOR_LOGIN,
        "issue_number": ISSUE_NUMBER,
        "issue_body_sha256": ISSUE_BODY_SHA256,
        "base_sha": BASE_SHA,
        "phase_a_head": phase,
        "frozen_files": frozen,
    }
    comment_id = "123456789"
    url = provider_url(comment_id)
    comment = {
        "id": int(comment_id),
        "url": url,
        "issue_url": ISSUE_API_URL,
        "user": {"id": OPERATOR_ID, "login": OPERATOR_LOGIN},
        "created_at": "2026-08-30T12:00:00Z",
        "updated_at": "2026-08-30T12:00:00Z",
        "body": json.dumps(body, sort_keys=True, separators=(",", ":")),
    }
    parsed = validate_provider_comment(comment, comment_id)
    require(parsed == body, "valid provider fixture did not round-trip")

    hostile_comments: list[dict[str, object]] = []
    alternate = copy.deepcopy(comment)
    alternate["url"] = "https://example.invalid/issues/comments/123456789"
    hostile_comments.append(alternate)
    wrong_issue = copy.deepcopy(comment)
    wrong_issue["issue_url"] = "https://api.github.com/repos/styx-secure/styx/issues/1"
    hostile_comments.append(wrong_issue)
    wrong_user = copy.deepcopy(comment)
    wrong_user["user"]["id"] = 1  # type: ignore[index]
    hostile_comments.append(wrong_user)
    missing = copy.deepcopy(comment)
    del missing["user"]
    hostile_comments.append(missing)
    missing_gate_field = copy.deepcopy(comment)
    missing_gate_body = copy.deepcopy(body)
    del missing_gate_body["base_sha"]
    missing_gate_field["body"] = json.dumps(
        missing_gate_body, sort_keys=True, separators=(",", ":"),
    )
    hostile_comments.append(missing_gate_field)
    missing_timestamps = copy.deepcopy(comment)
    del missing_timestamps["created_at"]
    del missing_timestamps["updated_at"]
    hostile_comments.append(missing_timestamps)
    edited = copy.deepcopy(comment)
    edited["updated_at"] = "2026-08-30T12:00:01Z"
    hostile_comments.append(edited)
    for hostile in hostile_comments:
        try:
            validate_provider_comment(hostile, comment_id)
        except GateAError:
            pass
        else:
            raise GateAError("hostile provider fixture was accepted")

    request = Request(url)
    try:
        _RejectRedirect().redirect_request(
            request, None, 302, "redirect", {}, "https://example.invalid/"
        )
    except HTTPError:
        pass
    else:
        raise GateAError("redirect fixture was accepted")

    facts = actual_facts
    validate_checkout_facts(facts, body, "frozen")
    for key, value in (
        ("clean", False),
        ("base", "2" * 40),
        ("head", "2" * 40),
        ("base_to_phase", False),
        ("phase_to_final", False),
        ("final", "2" * 40),
        ("changed", tuple(sorted(FROZEN_PATHS[:-1]))),
        ("phase_digests", {**frozen, SOURCE_PATH: "0" * 64}),
        ("working_digests", {**frozen, SOURCE_PATH: "0" * 64}),
    ):
        hostile_facts = copy.deepcopy(facts)
        hostile_facts[key] = value
        try:
            validate_checkout_facts(hostile_facts, body, "frozen")
        except GateAError:
            pass
        else:
            raise GateAError("hostile checkout fixture was accepted: " + key)

    validate_mode("frozen", None, frozen[SOURCE_PATH])
    model = {
        "sources": [{
            "authority": "normative",
            "id": SOURCE_ID,
            "path": SOURCE_PATH,
            "sha256": frozen[SOURCE_PATH],
        }]
    }
    validate_mode("model-binding", model, frozen[SOURCE_PATH])
    for hostile_model in (None, {"sources": []}, {
        "sources": [{
            "authority": "normative",
            "id": SOURCE_ID,
            "path": SOURCE_PATH,
            "sha256": "0" * 64,
        }]
    }):
        try:
            validate_mode("model-binding", hostile_model, frozen[SOURCE_PATH])
        except GateAError:
            pass
        else:
            raise GateAError("hostile model-binding fixture was accepted")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--mode", choices=("frozen", "model-binding"))
    parser.add_argument("--repo", type=Path)
    parser.add_argument("--base")
    parser.add_argument("--phase-a-head")
    parser.add_argument("--final-head")
    parser.add_argument("--issue-number", type=int)
    parser.add_argument("--comment-id")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.self_test:
            self_test()
            print("SS-0 GATE-A SELF-TEST verdict=PASS")
            return 0
        required = (
            args.mode,
            args.repo,
            args.base,
            args.phase_a_head,
            args.final_head,
            args.issue_number,
            args.comment_id,
            args.output,
        )
        require(all(value is not None for value in required), "required argument missing")
        require(args.base == BASE_SHA, "command Base mismatch")
        require(args.issue_number == ISSUE_NUMBER, "command Issue mismatch")
        repo = args.repo.resolve(strict=True)
        raw, comment = fetch_comment(args.comment_id)
        gate = validate_provider_comment(comment, args.comment_id)
        require(gate["phase_a_head"] == args.phase_a_head,
                "command Phase-A commit mismatch")
        facts = collect_checkout_facts(repo, args.base, args.phase_a_head, args.final_head)
        validate_checkout_facts(facts, gate, args.mode)
        load_and_validate_model(repo, args.mode, gate)
        evidence = {
            "schema": "styx-ss0-gate-a-external-evidence/v1",
            "mode": args.mode,
            "provider_url": provider_url(args.comment_id),
            "provider_response_sha256": digest(raw),
            "comment_id": int(args.comment_id),
            "issue_body_sha256": ISSUE_BODY_SHA256,
            "base_sha": facts["base"],
            "phase_a_head": facts["phase"],
            "final_head": facts["final"],
            "frozen_files": gate["frozen_files"],
            "execution_environment": {
                "python_executable": sys.executable,
                "python_flags": {
                    "dont_write_bytecode": sys.flags.dont_write_bytecode,
                    "ignore_environment": sys.flags.ignore_environment,
                    "isolated": sys.flags.isolated,
                    "no_site": sys.flags.no_site,
                    "no_user_site": sys.flags.no_user_site,
                    "safe_path": sys.flags.safe_path,
                },
                "git_executable": GIT_EXECUTABLE,
            },
            "verdict": "PASS",
        }
        store_external_evidence(args.output, evidence, repo)
    except (GateAError, OSError, UnicodeError, json.JSONDecodeError) as error:
        print("SS-0 Gate-A verification failed: " + str(error), file=sys.stderr)
        return 2
    print("SS-0 GATE-A verdict=PASS mode=" + args.mode)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
