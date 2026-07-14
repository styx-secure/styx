"""Automatic test planner for the Styx governance pipeline.

The planner derives a closed-shape, exact-HEAD-bound ``styx.test-plan/v1``
from trusted task inputs only: the Issue contract, the scope-guard evidence
and the committed tree at the candidate HEAD. No human-authored plan and no
external planner call are involved. Untrusted generated-test proposals may
be offered, but each one is accepted only when it satisfies the offline
command policy; everything else is recorded as rejected with a redacted
reason.
"""

from __future__ import annotations

from pathlib import Path
import subprocess
from typing import Any, Mapping, Sequence

from contract_inputs import ScopeReport, TaskInputs
from model import (
    DEFAULT_MAX_OUTPUT_BYTES,
    PLAN_SCHEMA_ID,
    PlanError,
    PlannedCheck,
    SHA_RE,
    TOOL_VERSION,
    canonical_json_bytes,
    generation_stanza,
    redact_text,
)
from safety import (
    CommandPolicyError,
    command_policy_sha256,
    default_resource_policy,
    split_shell_command,
    validate_command,
    validate_resource_policy,
)

JSON_CHECK_TIMEOUT_SECONDS = 60
GIT_CHECK_TIMEOUT_SECONDS = 120
MAX_PROPOSAL_REASON_LENGTH = 300
MAX_PROPOSALS = 64


def _run_git(repo: Path, args: Sequence[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=GIT_CHECK_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        raise PlanError(f"git {' '.join(args)} failed: {redact_text(result.stderr.strip())}")
    return result.stdout


def tracked_paths(repo: Path, head_sha: str) -> tuple[str, ...]:
    output = _run_git(repo, ["ls-tree", "-r", "--name-only", "-z", head_sha])
    return tuple(sorted(path for path in output.split("\0") if path))


def _mandatory_checks(inputs: TaskInputs, head_sha: str) -> list[PlannedCheck]:
    checks: list[PlannedCheck] = []
    timeout_seconds, max_output_bytes = default_resource_policy()
    for command_line in inputs.required_tests:
        argv, discard_stdout = split_shell_command(command_line)
        vector = validate_command(argv)
        checks.append(
            PlannedCheck(
                origin="issue-contract",
                purpose=f"Issue #{inputs.issue_number} required test: {command_line}",
                execution_class="MANDATORY",
                head_sha=head_sha,
                command=vector,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                isolation="worktree",
                discard_stdout=discard_stdout,
            )
        )
    if not checks:
        raise PlanError("the Issue contract declares no required tests")
    return checks


def _regression_checks(paths: tuple[str, ...], head_sha: str) -> list[PlannedCheck]:
    suites: set[str] = set()
    for path in paths:
        parts = path.split("/")
        if (
            len(parts) >= 4
            and parts[0] == "tools"
            and parts[2] == "tests"
            and parts[-1].startswith("test_")
            and parts[-1].endswith(".py")
        ):
            suites.add("/".join(parts[:3]))
    timeout_seconds, max_output_bytes = default_resource_policy()
    return [
        PlannedCheck(
            origin="regression-discovery",
            purpose=f"regression suite discovered at HEAD: {suite}",
            execution_class="REGRESSION",
            head_sha=head_sha,
            command=("python3", "-m", "unittest", "discover", "-s", suite, "-p", "test_*.py"),
            timeout_seconds=timeout_seconds,
            max_output_bytes=max_output_bytes,
            isolation="worktree",
        )
        for suite in sorted(suites)
    ]


def _static_checks(paths: tuple[str, ...], scope_report: ScopeReport, head_sha: str) -> list[PlannedCheck]:
    checks: list[PlannedCheck] = []
    for path in paths:
        if path.startswith("docs/governance/schemas/") and path.endswith(".json"):
            checks.append(
                PlannedCheck(
                    origin="planner-builtin",
                    purpose=f"schema is well-formed JSON: {path}",
                    execution_class="STATIC",
                    head_sha=head_sha,
                    command=("python3", "-m", "json.tool", path),
                    timeout_seconds=JSON_CHECK_TIMEOUT_SECONDS,
                    max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES,
                    isolation="worktree",
                    discard_stdout=True,
                )
            )
    tracked = set(paths)
    changed_python = tuple(
        path for path in scope_report.changed_paths() if path.endswith(".py") and path in tracked
    )
    if changed_python:
        checks.append(
            PlannedCheck(
                origin="planner-builtin",
                purpose="changed python files compile",
                execution_class="STATIC",
                head_sha=head_sha,
                command=("python3", "-m", "py_compile", *changed_python),
                timeout_seconds=JSON_CHECK_TIMEOUT_SECONDS,
                max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES,
                isolation="archive",
            )
        )
    return checks


def _adversarial_checks(inputs: TaskInputs, base_sha: str, head_sha: str) -> list[PlannedCheck]:
    checks = [
        PlannedCheck(
            origin="planner-builtin",
            purpose="no whitespace damage or conflict markers between base and HEAD",
            execution_class="ADVERSARIAL",
            head_sha=head_sha,
            command=("git", "diff", "--check", base_sha, head_sha),
            timeout_seconds=GIT_CHECK_TIMEOUT_SECONDS,
            max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES,
            isolation="worktree",
        )
    ]
    for pattern in inputs.forbidden_patterns:
        checks.append(
            PlannedCheck(
                origin="planner-builtin",
                purpose=f"forbidden path pattern is byte-unchanged: {pattern}",
                execution_class="ADVERSARIAL",
                head_sha=head_sha,
                command=("git", "diff", "--quiet", base_sha, head_sha, "--", f":(glob){pattern}"),
                timeout_seconds=GIT_CHECK_TIMEOUT_SECONDS,
                max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES,
                isolation="worktree",
            )
        )
    return checks


def _rollback_checks(base_sha: str, head_sha: str) -> list[PlannedCheck]:
    return [
        PlannedCheck(
            origin="planner-builtin",
            purpose="rollback target commit exists in the repository",
            execution_class="ROLLBACK",
            head_sha=head_sha,
            command=("git", "cat-file", "-e", f"{base_sha}^{{commit}}"),
            timeout_seconds=GIT_CHECK_TIMEOUT_SECONDS,
            max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES,
            isolation="worktree",
        ),
        PlannedCheck(
            origin="planner-builtin",
            purpose="declared base is an ancestor of HEAD, so reverting to base is well-defined",
            execution_class="ROLLBACK",
            head_sha=head_sha,
            command=("git", "merge-base", "--is-ancestor", base_sha, head_sha),
            timeout_seconds=GIT_CHECK_TIMEOUT_SECONDS,
            max_output_bytes=DEFAULT_MAX_OUTPUT_BYTES,
            isolation="worktree",
        ),
    ]


def _generated_checks(
    proposals: Any, head_sha: str
) -> tuple[list[PlannedCheck], list[dict[str, Any]]]:
    if proposals is None:
        return [], []
    if not isinstance(proposals, list):
        raise PlanError("generated-test proposals must be a JSON array")
    if len(proposals) > MAX_PROPOSALS:
        raise PlanError(f"too many generated-test proposals (limit {MAX_PROPOSALS})")
    accepted: list[PlannedCheck] = []
    rejected: list[dict[str, Any]] = []

    def reject(index: int, reason: str) -> None:
        clipped = redact_text(reason)[:MAX_PROPOSAL_REASON_LENGTH]
        rejected.append({"index": index, "reason": clipped or "rejected"})

    for index, proposal in enumerate(proposals):
        if not isinstance(proposal, dict):
            reject(index, "proposal must be a JSON object")
            continue
        unknown = set(proposal) - {"purpose", "command", "timeout_seconds", "max_output_bytes"}
        if unknown:
            reject(index, "proposal has unknown fields: " + ", ".join(sorted(unknown)))
            continue
        purpose = proposal.get("purpose")
        command = proposal.get("command")
        if not isinstance(purpose, str) or not purpose.strip():
            reject(index, "proposal purpose must be a non-empty string")
            continue
        if not isinstance(command, list):
            reject(index, "proposal command must be an argv array")
            continue
        try:
            vector = validate_command(command)
            timeout_seconds, max_output_bytes = validate_resource_policy(
                proposal.get("timeout_seconds", default_resource_policy()[0]),
                proposal.get("max_output_bytes", default_resource_policy()[1]),
            )
        except CommandPolicyError as exc:
            reject(index, exc.message)
            continue
        accepted.append(
            PlannedCheck(
                origin="generated-proposal",
                purpose=purpose.strip(),
                execution_class="GENERATED",
                head_sha=head_sha,
                command=vector,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
                isolation="archive",
            )
        )
    return accepted, rejected


def build_plan(
    *,
    repo: Path,
    inputs: TaskInputs,
    scope_report: ScopeReport,
    base_sha: str,
    head_sha: str,
    execution_id: str,
    proposals: Any = None,
) -> dict[str, Any]:
    if not SHA_RE.fullmatch(base_sha) or not SHA_RE.fullmatch(head_sha):
        raise PlanError("base and head must be full lowercase commit SHAs")
    if scope_report.verdict != "PASS":
        raise PlanError(
            f"scope report verdict is {scope_report.verdict}; an executable plan requires PASS"
        )
    if base_sha != inputs.base_sha:
        raise PlanError("declared base drifted from the Issue contract; renewed authorization is required")
    if scope_report.base_sha != base_sha or scope_report.head_sha != head_sha:
        raise PlanError("scope report is bound to a different base/head than this plan")
    if scope_report.issue_body_sha256 not in (None, inputs.body_sha256):
        raise PlanError("scope report was produced for a different Issue body")
    if not execution_id or execution_id.strip() != execution_id:
        raise PlanError("execution ID must be non-empty and have no surrounding whitespace")

    paths = tracked_paths(repo, head_sha)
    checks: list[PlannedCheck] = []
    checks.extend(_mandatory_checks(inputs, head_sha))
    checks.extend(_regression_checks(paths, head_sha))
    generated, rejected = _generated_checks(proposals, head_sha)
    checks.extend(generated)
    checks.extend(_adversarial_checks(inputs, base_sha, head_sha))
    checks.extend(_static_checks(paths, scope_report, head_sha))
    checks.extend(_rollback_checks(base_sha, head_sha))

    identifiers = [check.identifier() for check in checks]
    if len(identifiers) != len(set(identifiers)):
        raise PlanError("plan contains duplicate deterministic check identifiers")

    return {
        "schema": PLAN_SCHEMA_ID,
        "tool_version": TOOL_VERSION,
        "issue_number": inputs.issue_number,
        "execution_id": execution_id,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "issue_body_sha256": inputs.body_sha256,
        "scope_report_sha256": scope_report.sha256,
        "command_policy_sha256": command_policy_sha256(),
        "checks": [check.as_dict() for check in checks],
        "rejected_proposals": rejected,
        "generation": generation_stanza(),
    }


def plan_bytes(plan: Mapping[str, Any]) -> bytes:
    return canonical_json_bytes(plan)
