"""Trusted task inputs for the automatic test planner.

The planner derives plans only from trusted, already-reviewed inputs:

- the Issue body, parsed by the trusted ``tools/agent-enforcement`` parser
  for allowed/forbidden patterns and by a fence-aware scanner (same rules)
  for the Base and Required tests sections;
- the ``styx.task-scope-report/v1`` evidence produced by the existing scope
  guard, consumed as opaque canonical bytes plus a minimal shape check.
"""

from __future__ import annotations

import hashlib
import importlib
from pathlib import Path
import re
import sys
from typing import Any, Callable

from model import (
    ContractInputError,
    SCOPE_REPORT_SCHEMA_ID,
    SHA256_RE,
    SHA_RE,
    ScopeReportError,
    load_strict_json,
    redact_text,
)

HEADING_RE = re.compile(r"^##[ \t]+(.+?)[ \t]*$")
BACKTICK_FENCE_OPEN_RE = re.compile(r"^ {0,3}(`{3,})[ \t]*[^`]*$")
TILDE_FENCE_OPEN_RE = re.compile(r"^ {0,3}(~{3,}).*$")
INDENTED_CODE_RE = re.compile(r"^(?: {4}|\t)")
BASE_RE = re.compile(r"`([A-Za-z0-9._/-]+) @ ([0-9a-f]{40})`")


class TaskInputs:
    """Immutable view of the trusted planner inputs."""

    def __init__(
        self,
        *,
        issue_number: int,
        body_bytes: bytes,
        allowed_patterns: tuple[str, ...],
        forbidden_patterns: tuple[str, ...],
        base_sha: str,
        required_tests: tuple[str, ...],
    ):
        self.issue_number = issue_number
        self.body_bytes = body_bytes
        self.body_sha256 = hashlib.sha256(body_bytes).hexdigest()
        self.allowed_patterns = allowed_patterns
        self.forbidden_patterns = forbidden_patterns
        self.base_sha = base_sha
        self.required_tests = required_tests


def load_trusted_contract_parser(repo: Path) -> Callable[[bytes], Any]:
    """Load ``parse_contract`` from the existing agent-enforcement tool."""

    module_dir = repo / "tools" / "agent-enforcement"
    if not (module_dir / "contract.py").is_file():
        raise ContractInputError("trusted task-contract parser is missing")
    previous_path = list(sys.path)
    previous_modules = {name: sys.modules.get(name) for name in ("contract", "model")}
    try:
        sys.path.insert(0, str(module_dir))
        for name in ("contract", "model"):
            sys.modules.pop(name, None)
        module = importlib.import_module("contract")
        return module.parse_contract
    except Exception as exc:
        raise ContractInputError(f"unable to load trusted task-contract parser: {redact_text(str(exc))}") from exc
    finally:
        sys.path[:] = previous_path
        for name, old in previous_modules.items():
            sys.modules.pop(name, None)
            if old is not None:
                sys.modules[name] = old


def _scan_sections(body: str) -> dict[str, str]:
    """Fence-aware section scanner using the trusted parser's block rules."""

    sections: dict[str, str] = {}
    current: str | None = None
    lines: list[str] = []
    fence: tuple[str, int] | None = None

    def flush() -> None:
        if current is not None and current not in sections:
            sections[current] = "\n".join(lines)

    for raw in body.splitlines():
        line = raw.rstrip("\r\n")
        if fence is not None:
            char, size = fence
            if re.fullmatch(rf" {{0,3}}{re.escape(char)}{{{size},}}[ \t]*", line):
                fence = None
            if current is not None:
                lines.append(line)
            continue
        if not INDENTED_CODE_RE.match(line):
            opened = BACKTICK_FENCE_OPEN_RE.match(line)
            if opened:
                fence = ("`", len(opened.group(1)))
            else:
                opened = TILDE_FENCE_OPEN_RE.match(line)
                if opened:
                    fence = ("~", len(opened.group(1)))
            if fence is None:
                heading = HEADING_RE.match(line)
                if heading:
                    flush()
                    current = heading.group(1).strip()
                    lines = []
                    continue
        if current is not None:
            lines.append(line)
    flush()
    if fence is not None:
        raise ContractInputError("unterminated fenced code block")
    return sections


def _single_fenced_lines(section: str, heading: str) -> tuple[str, ...]:
    blocks: list[list[str]] = []
    current: list[str] | None = None
    fence: tuple[str, int] | None = None
    for line in section.splitlines():
        if current is None:
            if INDENTED_CODE_RE.match(line):
                continue
            opened = BACKTICK_FENCE_OPEN_RE.match(line) or TILDE_FENCE_OPEN_RE.match(line)
            if opened:
                fence = (opened.group(1)[0], len(opened.group(1)))
                current = []
        else:
            char, size = fence  # type: ignore[misc]
            if re.fullmatch(rf" {{0,3}}{re.escape(char)}{{{size},}}[ \t]*", line):
                blocks.append(current)
                current = None
                fence = None
            else:
                current.append(line)
    if current is not None or len(blocks) != 1:
        raise ContractInputError(f"'{heading}' must contain exactly one closed fenced block")
    values = tuple(line.strip() for line in blocks[0] if line.strip())
    if not values:
        raise ContractInputError(f"'{heading}' must not be empty")
    return values


def load_task_inputs(
    repo: Path,
    issue_number: int,
    body_bytes: bytes,
    *,
    parser: Callable[[bytes], Any] | None = None,
) -> TaskInputs:
    parse = parser or load_trusted_contract_parser(repo)
    try:
        parsed = parse(body_bytes)
    except Exception as exc:
        raise ContractInputError(
            f"trusted contract parser rejected Issue #{issue_number}: {redact_text(str(exc))}"
        ) from exc
    try:
        body = body_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ContractInputError("Issue body is not valid UTF-8") from exc

    sections = _scan_sections(body)
    base_section = sections.get("Base")
    if base_section is None:
        raise ContractInputError("missing Base section")
    base_matches = BASE_RE.findall(base_section)
    if len(base_matches) != 1:
        raise ContractInputError("Base must contain exactly one '`branch @ 40-hex-sha`' declaration")
    base_branch, base_sha = base_matches[0]
    if base_branch != "main" or not SHA_RE.fullmatch(base_sha):
        raise ContractInputError("only exact lowercase full-SHA 'main' bases are supported")

    test_section = sections.get("Required tests") or sections.get("Required verification")
    if test_section is None:
        raise ContractInputError("missing required tests section")
    tests = _single_fenced_lines(test_section, "Required tests")

    return TaskInputs(
        issue_number=issue_number,
        body_bytes=body_bytes,
        allowed_patterns=tuple(parsed.allowed_patterns),
        forbidden_patterns=tuple(parsed.forbidden_patterns),
        base_sha=base_sha,
        required_tests=tests,
    )


class ScopeReport:
    """Minimal trusted view of a ``styx.task-scope-report/v1`` document."""

    def __init__(self, raw_bytes: bytes, document: dict[str, Any]):
        self.raw_bytes = raw_bytes
        self.sha256 = hashlib.sha256(raw_bytes).hexdigest()
        self.document = document

    @property
    def verdict(self) -> str:
        return self.document["verdict"]

    @property
    def base_sha(self) -> str | None:
        return self.document["base_sha"]

    @property
    def head_sha(self) -> str | None:
        return self.document["head_sha"]

    @property
    def issue_body_sha256(self) -> str | None:
        return self.document["issue_body_sha256"]

    def changed_paths(self) -> tuple[str, ...]:
        paths: set[str] = set()
        for entry in self.document["changed_entries"]:
            for evaluation in entry["paths"]:
                paths.add(evaluation["path"])
        return tuple(sorted(paths))


def load_scope_report(raw_bytes: bytes) -> ScopeReport:
    try:
        document = load_strict_json(raw_bytes, source="scope report")
    except Exception as exc:
        raise ScopeReportError(str(exc)) from exc
    if not isinstance(document, dict):
        raise ScopeReportError("scope report must be a JSON object")
    required = (
        "schema",
        "base_sha",
        "head_sha",
        "issue_number",
        "issue_body_sha256",
        "changed_entries",
        "verdict",
    )
    for field in required:
        if field not in document:
            raise ScopeReportError(f"scope report is missing field: {field}")
    if document["schema"] != SCOPE_REPORT_SCHEMA_ID:
        raise ScopeReportError("scope report has an unexpected schema identifier")
    if document["verdict"] not in {"PASS", "FAIL", "ERROR"}:
        raise ScopeReportError("scope report has an unexpected verdict")
    for field in ("base_sha", "head_sha"):
        value = document[field]
        if value is not None and (not isinstance(value, str) or not SHA_RE.fullmatch(value)):
            raise ScopeReportError(f"scope report field is not a commit SHA: {field}")
    body_hash = document["issue_body_sha256"]
    if body_hash is not None and (not isinstance(body_hash, str) or not SHA256_RE.fullmatch(body_hash)):
        raise ScopeReportError("scope report issue_body_sha256 is malformed")
    if not isinstance(document["changed_entries"], list):
        raise ScopeReportError("scope report changed_entries must be an array")
    return ScopeReport(raw_bytes, document)
