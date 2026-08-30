#!/usr/bin/env python3
"""Verify the immutable SS-0 Gate-A provider binding.

This file is the Phase-A trust root.  It deliberately does not import any
other repository module: Phase B may change derived validators, but cannot
change this verifier after the human Gate-A binding.
"""

from __future__ import annotations

import argparse
import copy
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

sys.dont_write_bytecode = True


ISSUE_NUMBER = 285
ISSUE_API_URL = "https://api.github.com/repos/styx-secure/styx/issues/285"
COMMENT_API_PREFIX = "https://api.github.com/repos/styx-secure/styx/issues/comments/"
OPERATOR_LOGIN = "maverde73"
OPERATOR_ID = 141346846
BASE_SHA = "bd13fac2df51e8585db6487fff7217fb68fb6242"
ISSUE_BODY_SHA256 = "99a543bacfe9f0c136d22b976ed5f8f14e66d3df5fb5a1055c6adae83118e03d"
GATE_SCHEMA = "styx-ss0-gate-a/v1"
MODEL_PATH = Path("docs/protocol/review/styx-app-kernel-v0-review-model.json")
SOURCE_PATH = "docs/protocol/styx-secure-session-v0-decisions.md"
SOURCE_ID = "secure_session_decisions"
MAX_PROVIDER_BYTES = 256 * 1024
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
        with build_opener(_RejectRedirect).open(request, timeout=30) as response:
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
    require(comment.get("created_at") == comment.get("updated_at"),
            "Gate-A comment was edited")
    return parse_gate_body(comment.get("body"))


def run_git(repo: Path, *arguments: str, allow_failure: bool = False) -> bytes:
    process = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
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
    require(not run_git(repo, "status", "--porcelain=v1", "--untracked-files=all"),
            "checkout is dirty")
    resolved_base = resolve_commit(repo, base)
    resolved_phase = resolve_commit(repo, phase_a_head)
    resolved_final = resolve_commit(repo, final_head)
    resolved_head = resolve_commit(repo, "HEAD")
    base_to_phase = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", resolved_base, resolved_phase],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0
    phase_to_final = subprocess.run(
        ["git", "-C", str(repo), "merge-base", "--is-ancestor", resolved_phase, resolved_final],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False,
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
        "clean": True,
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
    phase = "1" * 40
    frozen = {path: digest(path.encode("utf-8")) for path in FROZEN_PATHS}
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

    facts = {
        "base": BASE_SHA,
        "phase": phase,
        "final": phase,
        "head": phase,
        "clean": True,
        "base_to_phase": True,
        "phase_to_final": True,
        "changed": tuple(sorted(FROZEN_PATHS)),
        "phase_digests": frozen,
        "working_digests": frozen,
    }
    validate_checkout_facts(facts, body, "frozen")
    for key, value in (
        ("clean", False),
        ("phase_to_final", False),
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
