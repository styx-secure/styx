"""Strict closed-shape binder for the three frozen evidence shapes.

Consumed shapes (documented in docs/governance/restricted-operation-broker.md):
- styx.task-scope-report/v1       (schema file exists at base)
- styx.agent-runner-status/v1     (schema file exists at base)
- styx.agent-hook-attestation/v1  (final form; no schema file at base — the
  exact field set is emitted by .claude/hooks/styx_guard.py::_snapshot and is
  re-bound here without importing that forbidden-path module)

Closed-shape v1 boundary: each document must carry EXACTLY its real top-level key
set (unknown top-level keys are rejected, missing required keys are rejected) and
every field the broker binds is deeply type-checked. Deep validation of fields
that the broker does not consume (e.g. runner ``environment.tools``) is out of
scope for v1 and is documented for the security reviewer.
"""
from __future__ import annotations

import dataclasses
import re

import canonical
import jsonparse
from model import EvidenceBundle, EvidenceError

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA64 = re.compile(r"^[0-9a-f]{64}$")
FINAL_TERMINAL = "BLOCKED_BROKER_UNAVAILABLE"

_SCOPE_KEYS = {
    "schema", "tool_version", "issue_number", "execution_id", "base_sha", "head_sha",
    "issue_body_sha256", "contract_version", "allowed_patterns", "forbidden_patterns",
    "changed_entries", "diagnostics", "generation", "verdict",
}
_RUNNER_KEYS = {
    "schema", "tool_version", "command", "execution_id", "repository", "issue", "base",
    "environment", "worktree", "contract", "tests", "scope_guard", "phase",
    "terminal_status", "blocking", "prohibited_operation_attempts",
}
_ATT_KEYS = {
    "schema", "issue_number", "terminal_status", "active_state_sha256", "status_report",
    "status_report_sha256", "worktree", "branch", "base_sha", "head_sha", "scope_report",
    "scope_report_sha256", "changed_paths",
}


@dataclasses.dataclass(frozen=True)
class EvidenceHashes:
    scope_report_sha256: str
    runner_status_sha256: str
    hook_attestation_sha256: str


@dataclasses.dataclass(frozen=True)
class ValidatedEvidence:
    issue_number: int
    execution_id: str
    base_sha: str
    head_sha: str
    branch: str
    repository: str
    changed_paths: tuple
    hashes: EvidenceHashes


def _fail(msg: str):
    raise EvidenceError(msg)


def _closed(obj: dict, expected: set, where: str) -> None:
    keys = set(obj)
    if keys != expected:
        missing = sorted(expected - keys)
        extra = sorted(keys - expected)
        _fail(f"{where}: closed-shape violation (missing={missing}, unknown={extra})")


def _sha40(value, where):
    if not isinstance(value, str) or not _SHA40.match(value):
        _fail(f"{where} must be a 40-hex sha")
    return value


def _sha64(value, where):
    if not isinstance(value, str) or not _SHA64.match(value):
        _fail(f"{where} must be a 64-hex sha")
    return value


def _str(value, where):
    if not isinstance(value, str) or not value:
        _fail(f"{where} must be a non-empty string")
    return value


def _obj(value, where):
    if not isinstance(value, dict):
        _fail(f"{where} must be an object")
    return value


def validate(bundle: EvidenceBundle) -> ValidatedEvidence:
    scope = jsonparse.load_object(bundle.scope_report)
    runner = jsonparse.load_object(bundle.runner_status)
    att = jsonparse.load_object(bundle.hook_attestation)

    if scope.get("schema") != "styx.task-scope-report/v1":
        _fail("scope report schema mismatch")
    if runner.get("schema") != "styx.agent-runner-status/v1":
        _fail("runner status schema mismatch")
    if att.get("schema") != "styx.agent-hook-attestation/v1":
        _fail("hook attestation schema mismatch")

    _closed(scope, _SCOPE_KEYS, "scope report")
    _closed(runner, _RUNNER_KEYS, "runner status")
    _closed(att, _ATT_KEYS, "hook attestation")

    # --- scope report (consumed fields) ---
    scope_issue = scope["issue_number"]
    if not isinstance(scope_issue, int) or isinstance(scope_issue, bool) or scope_issue < 1:
        _fail("scope.issue_number must be an integer >= 1")
    scope_exec = _str(scope["execution_id"], "scope.execution_id")
    scope_base = _sha40(scope["base_sha"], "scope.base_sha")
    scope_head = _sha40(scope["head_sha"], "scope.head_sha")
    scope_body = _sha64(scope["issue_body_sha256"], "scope.issue_body_sha256")
    if scope["verdict"] != "PASS":
        _fail("scope verdict is not PASS")

    # --- runner status (consumed fields) ---
    issue = _obj(runner["issue"], "runner.issue")
    base = _obj(runner["base"], "runner.base")
    worktree = _obj(runner["worktree"], "runner.worktree")
    repo = _obj(runner["repository"], "runner.repository")
    tests = runner["tests"]
    scope_guard = _obj(runner["scope_guard"], "runner.scope_guard")
    runner_exec = _str(runner["execution_id"], "runner.execution_id")
    if not isinstance(tests, list) or not tests:
        _fail("runner.tests must be a non-empty array")
    if any(not isinstance(t, dict) or t.get("state") != "PASS" for t in tests):
        _fail("runner has non-PASS test evidence")
    if scope_guard.get("verdict") != "PASS":
        _fail("runner scope_guard is not PASS")
    if repo.get("expected") != "styx-secure/styx" or not repo.get("verified"):
        _fail("runner repository not verified as styx-secure/styx")
    if runner["terminal_status"] != FINAL_TERMINAL:
        _fail("runner terminal_status is not the authorized handoff")
    runner_issue = issue.get("number")
    runner_body = _sha64(issue.get("body_sha256"), "runner.issue.body_sha256")
    runner_base = _sha40(base.get("declared_sha"), "runner.base.declared_sha")
    runner_branch = _str(worktree.get("branch"), "runner.worktree.branch")

    # --- attestation final form (consumed fields) ---
    if att["terminal_status"] != FINAL_TERMINAL:
        _fail("attestation is not the final handoff form")
    att_issue = att["issue_number"]
    att_base = _sha40(att["base_sha"], "attestation.base_sha")
    att_head = _sha40(att["head_sha"], "attestation.head_sha")
    att_branch = _str(att["branch"], "attestation.branch")
    att_status_hash = _sha64(att["status_report_sha256"], "attestation.status_report_sha256")
    att_scope_hash = _sha64(att["scope_report_sha256"], "attestation.scope_report_sha256")
    att_changed = att["changed_paths"]
    if not isinstance(att_changed, list) or any(not isinstance(p, str) for p in att_changed):
        _fail("attestation.changed_paths must be an array of strings")

    # --- cross-binding ---
    if not (scope_issue == runner_issue == att_issue):
        _fail("issue number binding mismatch")
    if scope_exec != runner_exec:
        _fail("execution_id binding mismatch")
    if not (scope_base == runner_base == att_base):
        _fail("base_sha binding mismatch")
    if scope_head != att_head:
        _fail("head_sha binding mismatch")
    if runner_branch != att_branch:
        _fail("branch binding mismatch")
    if scope_body != runner_body:
        _fail("issue body hash binding mismatch")
    if att_status_hash != canonical.sha256_hex(bundle.runner_status):
        _fail("attestation status_report hash does not match runner document")
    if att_scope_hash != canonical.sha256_hex(bundle.scope_report):
        _fail("attestation scope_report hash does not match scope document")

    return ValidatedEvidence(
        issue_number=scope_issue,
        execution_id=scope_exec,
        base_sha=scope_base,
        head_sha=scope_head,
        branch=runner_branch,
        repository="styx-secure/styx",
        changed_paths=tuple(att_changed),
        hashes=EvidenceHashes(
            scope_report_sha256=canonical.sha256_hex(bundle.scope_report),
            runner_status_sha256=canonical.sha256_hex(bundle.runner_status),
            hook_attestation_sha256=canonical.sha256_hex(bundle.hook_attestation),
        ),
    )
