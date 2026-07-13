"""Strict parser and path matcher for ``styx-task-contract:v1``."""

from __future__ import annotations

import fnmatch
from pathlib import PurePosixPath
import re
from typing import Iterable

from model import CONTRACT_MARKER, Contract, ContractError, GitInputError, PathEvaluation

HEADING_RE = re.compile(r"^##[ \t]+(.+?)[ \t]*$")
BACKTICK_FENCE_OPEN_RE = re.compile(r"^ {0,3}(`{3,})[ \t]*[^`]*$")
TILDE_FENCE_OPEN_RE = re.compile(r"^ {0,3}(~{3,}).*$")
INDENTED_CODE_RE = re.compile(r"^(?: {4}|\t)")

MAX_PATH_SEGMENTS = 255

REQUIRED_HEADINGS = (
    "Observable outcome",
    "Non-goals",
    "Allowed paths",
    "Forbidden paths",
    "Native dependencies",
    "Frozen shared interfaces",
    "Acceptance criteria",
    "Rollback",
    "Residual risks",
    "Executor and reviewers",
    "Human gates",
    "Base",
)
ALTERNATIVE_TEST_HEADINGS = ("Required tests", "Required verification")


def _fence_open(logical: str) -> tuple[str, int] | None:
    """Return (fence character, fence length) when the line opens a fenced block."""

    match = BACKTICK_FENCE_OPEN_RE.match(logical)
    if match:
        return "`", len(match.group(1))
    match = TILDE_FENCE_OPEN_RE.match(logical)
    if match:
        return "~", len(match.group(1))
    return None


def _fence_close(logical: str, char: str, size: int) -> bool:
    return re.fullmatch(rf" {{0,3}}{re.escape(char)}{{{size},}}[ \t]*", logical) is not None


def _scan_structure(body: str) -> tuple[list[tuple[str, int, int]], list[tuple[str, int]]]:
    """Return headings and contract markers that occur outside code blocks.

    Code blocks are backtick fences, tilde fences and lines indented with at
    least four spaces or one tab. Structure inside them is never structural.
    """

    headings: list[tuple[str, int, int]] = []
    markers: list[tuple[str, int]] = []
    offset = 0
    fence: tuple[str, int] | None = None
    for line_number, line in enumerate(body.splitlines(keepends=True), start=1):
        logical = line.rstrip("\r\n")
        if fence is not None:
            if _fence_close(logical, *fence):
                fence = None
        elif not INDENTED_CODE_RE.match(logical):
            opened = _fence_open(logical)
            if opened:
                fence = opened
            else:
                heading_match = HEADING_RE.match(logical)
                if heading_match:
                    headings.append((heading_match.group(1).strip(), offset, line_number))
                if "styx-task-contract:" in logical:
                    markers.append((logical.strip(), line_number))
        offset += len(line)
    if fence is not None:
        raise ContractError("unterminated fenced code block")
    return headings, markers


def _section_map(body: str) -> tuple[dict[str, str], list[tuple[str, int]], list[tuple[str, int]]]:
    headings, markers = _scan_structure(body)

    occurrences: dict[str, list[tuple[int, int]]] = {}
    for index, (name, start, _) in enumerate(headings):
        section_start = body.find("\n", start)
        section_start = len(body) if section_start == -1 else section_start + 1
        section_end = headings[index + 1][1] if index + 1 < len(headings) else len(body)
        occurrences.setdefault(name, []).append((section_start, section_end))

    missing = [name for name in REQUIRED_HEADINGS if name not in occurrences]
    if missing:
        raise ContractError("missing required heading(s): " + ", ".join(missing))
    duplicates = [name for name in REQUIRED_HEADINGS if len(occurrences.get(name, [])) != 1]
    if duplicates:
        raise ContractError("duplicate required heading(s): " + ", ".join(duplicates))

    alternatives = [name for name in ALTERNATIVE_TEST_HEADINGS if name in occurrences]
    if len(alternatives) != 1:
        raise ContractError("exactly one of 'Required tests' and 'Required verification' must occur")
    chosen = alternatives[0]
    if len(occurrences[chosen]) != 1:
        raise ContractError(f"duplicate required heading: {chosen}")

    sections: dict[str, str] = {}
    for name in (*REQUIRED_HEADINGS, chosen):
        section_start, section_end = occurrences[name][0]
        sections[name] = body[section_start:section_end]
    return sections, [(name, line) for name, _, line in headings], markers


def _extract_single_fenced_block(section: str, heading: str) -> list[str]:
    blocks: list[list[str]] = []
    current: list[str] | None = None
    fence: tuple[str, int] | None = None
    for line in section.splitlines():
        if current is None:
            if INDENTED_CODE_RE.match(line):
                continue
            opened = _fence_open(line)
            if opened:
                fence = opened
                current = []
        else:
            assert fence is not None
            if _fence_close(line, *fence):
                blocks.append(current)
                current = None
                fence = None
            else:
                current.append(line)
    if current is not None:
        raise ContractError(f"unterminated fenced code block in '{heading}'")
    if len(blocks) != 1:
        raise ContractError(f"'{heading}' must contain exactly one fenced code block")
    return blocks[0]


def validate_pattern(pattern: str) -> str:
    if pattern == "":
        raise ContractError("empty path pattern")
    if pattern != pattern.rstrip(" "):
        raise ContractError(f"path pattern has trailing spaces: {pattern!r}")
    if any(ord(char) < 32 or ord(char) == 127 for char in pattern):
        raise ContractError("path pattern contains control characters")
    if "\\" in pattern:
        raise ContractError(f"backslashes are not allowed: {pattern!r}")
    if pattern.startswith("/"):
        raise ContractError(f"absolute path pattern is not allowed: {pattern!r}")
    if pattern.endswith("/") or "//" in pattern:
        raise ContractError(f"path separators are not normalized: {pattern!r}")
    if any(token in pattern for token in ("[", "]", "{", "}")):
        raise ContractError(f"character classes and brace expansion are not allowed: {pattern!r}")
    if pattern.startswith("!") or re.search(r"[@+?!*]\(", pattern):
        raise ContractError(f"negation and extglob are not allowed: {pattern!r}")

    segments = pattern.split("/")
    if len(segments) > MAX_PATH_SEGMENTS:
        raise ContractError(f"path pattern exceeds {MAX_PATH_SEGMENTS} segments")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise ContractError(f"dot or empty path segment is not allowed: {pattern!r}")
    for segment in segments:
        if "**" in segment and segment != "**":
            raise ContractError(f"'**' must occupy an entire segment: {pattern!r}")
    if str(PurePosixPath(pattern)) != pattern:
        raise ContractError(f"path pattern is not normalized: {pattern!r}")
    return pattern


def parse_contract(body_bytes: bytes) -> Contract:
    try:
        body = body_bytes.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise ContractError("Issue body is not valid UTF-8") from exc

    sections, headings, markers = _section_map(body)
    if len(markers) != 1 or markers[0][0] != CONTRACT_MARKER:
        raise ContractError("contract must contain exactly one v1 marker outside fenced blocks")
    first_required_line = min(
        line for name, line in headings if name in REQUIRED_HEADINGS or name in ALTERNATIVE_TEST_HEADINGS
    )
    marker_line = markers[0][1]
    if marker_line >= first_required_line:
        raise ContractError("contract marker must appear before the first required section")

    def parse_patterns(lines: Iterable[str], heading: str) -> tuple[str, ...]:
        patterns = [validate_pattern(line) for line in lines if line != ""]
        if not patterns:
            raise ContractError(f"'{heading}' must contain at least one pattern")
        duplicates = sorted({item for item in patterns if patterns.count(item) > 1})
        if duplicates:
            raise ContractError(f"duplicate pattern(s) in '{heading}': " + ", ".join(duplicates))
        return tuple(patterns)

    return Contract(
        version="v1",
        allowed_patterns=parse_patterns(
            _extract_single_fenced_block(sections["Allowed paths"], "Allowed paths"),
            "Allowed paths",
        ),
        forbidden_patterns=parse_patterns(
            _extract_single_fenced_block(sections["Forbidden paths"], "Forbidden paths"),
            "Forbidden paths",
        ),
    )


def pattern_matches(pattern: str, path: str) -> bool:
    """Iterative segment matcher: no recursion, O(pattern x path) worst case."""

    pattern_segments = pattern.split("/")
    path_segments = path.split("/")
    total = len(path_segments)

    # suffix[j] answers: does pattern_segments[i:] match path_segments[j:]?
    # Start from the empty pattern suffix and fold pattern segments backwards.
    suffix = [j == total for j in range(total + 1)]
    for segment in reversed(pattern_segments):
        if segment == "**":
            reachable = suffix[total]
            folded = [False] * (total + 1)
            folded[total] = reachable
            for j in range(total - 1, -1, -1):
                reachable = reachable or suffix[j]
                folded[j] = reachable
        else:
            folded = [False] * (total + 1)
            for j in range(total):
                folded[j] = suffix[j + 1] and fnmatch.fnmatchcase(path_segments[j], segment)
        suffix = folded
    return suffix[0]


def validate_repo_path(path: str) -> str:
    if path == "" or path.startswith("/") or "\\" in path:
        raise GitInputError(f"invalid repository path: {path!r}")
    if any(ord(char) < 32 or ord(char) == 127 for char in path):
        raise GitInputError("repository path contains control characters")
    segments = path.split("/")
    if len(segments) > MAX_PATH_SEGMENTS:
        raise GitInputError(f"repository path exceeds {MAX_PATH_SEGMENTS} segments")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise GitInputError(f"repository path is not normalized: {path!r}")
    if str(PurePosixPath(path)) != path:
        raise GitInputError(f"repository path is not normalized: {path!r}")
    return path


def evaluate_path(path: str, contract: Contract) -> PathEvaluation:
    validate_repo_path(path)
    allowed = tuple(pattern for pattern in contract.allowed_patterns if pattern_matches(pattern, path))
    forbidden = tuple(pattern for pattern in contract.forbidden_patterns if pattern_matches(pattern, path))
    violations: list[str] = []
    if not allowed:
        violations.append("PATH_NOT_ALLOWED")
    if forbidden:
        violations.append("PATH_FORBIDDEN")
    return PathEvaluation(path, allowed, forbidden, tuple(violations))
