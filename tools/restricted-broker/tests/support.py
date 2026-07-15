"""Builders for internally-consistent trusted evidence documents.

Each builder returns a full document carrying exactly the real top-level key set
of its shape, with all cross-bindings satisfied. Tests override one field at a
time to exercise a single failure. The reference evidence is not a weak mock: it
mirrors the frozen shapes so the strict binder in ``evidence.py`` is exercised.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import canonical  # noqa: E402
from model import EvidenceBundle  # noqa: E402

ISSUE = 53
EXEC = "issue-53"
BRANCH = "task/53-restricted-broker"
BASE_SHA = "f5b6e0c70b08b23b3bd299228dd669090546e0e6"
HEAD_SHA = "1111111111111111111111111111111111111111"
BODY_SHA = "a" * 64
WORKTREE = "/work/task-53"
CHANGED = ["tools/restricted-broker/broker.py"]


def make_scope_report(**over):
    doc = {
        "schema": "styx.task-scope-report/v1",
        "tool_version": "0.1.0",
        "issue_number": ISSUE,
        "execution_id": EXEC,
        "base_sha": BASE_SHA,
        "head_sha": HEAD_SHA,
        "issue_body_sha256": BODY_SHA,
        "contract_version": "v1",
        "allowed_patterns": ["tools/restricted-broker/**"],
        "forbidden_patterns": [".github/**"],
        "changed_entries": [],
        "diagnostics": [],
        "generation": {"canonical_json": "RFC8259-sort-keys-utf8-lf", "timestamp_omitted": True},
        "verdict": "PASS",
    }
    doc.update(over)
    return doc


def make_runner_status(**over):
    doc = {
        "schema": "styx.agent-runner-status/v1",
        "tool_version": "0.1.0",
        "command": "run",
        "execution_id": EXEC,
        "repository": {"expected": "styx-secure/styx", "verified": "styx-secure/styx", "source_root": "/work"},
        "issue": {"number": ISSUE, "body_sha256": BODY_SHA},
        "base": {"branch": "main", "declared_sha": BASE_SHA, "verified_sha": BASE_SHA},
        "environment": {"tools": []},
        "worktree": {"path": WORKTREE, "branch": BRANCH},
        "contract": {"valid": True},
        "tests": [{"command": "python3 -m unittest", "state": "PASS", "exit_code": 0,
                   "stdout_sha256": "b" * 64, "stderr_sha256": "c" * 64}],
        "scope_guard": {"exit_code": 0, "verdict": "PASS", "report_path": "/e/scope.json",
                        "report_sha256": "d" * 64},
        "phase": "handoff",
        "terminal_status": "BLOCKED_BROKER_UNAVAILABLE",
        "blocking": None,
        "prohibited_operation_attempts": [],
    }
    doc.update(over)
    return doc


def make_attestation(scope_report=None, runner_status=None, **over):
    scope = make_scope_report() if scope_report is None else scope_report
    runner = make_runner_status() if runner_status is None else runner_status
    doc = {
        "schema": "styx.agent-hook-attestation/v1",
        "issue_number": scope["issue_number"],
        "terminal_status": "BLOCKED_BROKER_UNAVAILABLE",
        "active_state_sha256": "e" * 64,
        "status_report": "/state/runs/status.json",
        "status_report_sha256": canonical.canonical_sha256(runner),
        "worktree": runner["worktree"]["path"],
        "branch": runner["worktree"]["branch"],
        "base_sha": scope["base_sha"],
        "head_sha": scope["head_sha"],
        "scope_report": "/state/evidence/scope.json",
        "scope_report_sha256": canonical.canonical_sha256(scope),
        "changed_paths": list(CHANGED),
    }
    doc.update(over)
    return doc


def make_evidence_bundle(scope=None, runner=None, attestation=None) -> EvidenceBundle:
    scope = make_scope_report() if scope is None else scope
    runner = make_runner_status() if runner is None else runner
    if attestation is None:
        attestation = make_attestation(scope_report=scope, runner_status=runner)
    return EvidenceBundle(
        scope_report=canonical.canonical_bytes(scope),
        runner_status=canonical.canonical_bytes(runner),
        hook_attestation=canonical.canonical_bytes(attestation),
    )
