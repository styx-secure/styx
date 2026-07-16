"""Shared data model and deterministic primitives for the Styx review gate.

The review gate is intentionally self-contained: it never imports the test
orchestrator, restricted broker or agent runner, never opens a network
socket, never touches credentials and never executes tests or mutates a git
branch. It only reads already-produced evidence, validates it, and writes a
single canonical evidence document to a caller-chosen output path.

Everything here is pure and deterministic. Timestamps are deliberately
omitted from every output so that identical inputs hash identically.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Iterable, Mapping

REVIEW_REPORT_SCHEMA_ID = "styx.review-report/v1"
REMEDIATION_REQUEST_SCHEMA_ID = "styx.remediation-request/v1"
# Read-only interfaces owned by #54 / #46. Never emitted, only consumed.
TEST_REPORT_SCHEMA_ID = "styx.test-report/v1"
SCOPE_REPORT_SCHEMA_ID = "styx.task-scope-report/v1"

TOOL_VERSION = "0.1.0"

# Exit convention mirrors the repository's other governance tools:
# 0 PASS (accepting review / successful remediation),
# 2 CHANGES (a review that requests changes or blocks),
# 3 ERROR (fail-closed: precondition, validation or I/O failure; no output).
EXIT_PASS = 0
EXIT_CHANGES = 2
EXIT_ERROR = 3

REVIEWER_CLASSES = ("HUMAN", "DELEGATED_AGENT")
VERDICTS = ("GO", "GO_WITH_CONDITIONS", "CHANGES_REQUESTED", "BLOCKED")
ACCEPTANCE_VERDICTS = ("GO", "GO_WITH_CONDITIONS")
SEVERITIES = ("BLOCKER", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERE_SEVERITIES = ("BLOCKER", "HIGH")
LIFECYCLE_STATES = ("OPEN", "ADDRESSED_PENDING_REVERIFY", "RESOLVED", "WAIVED_BY_HUMAN")
# Findings that still demand action before acceptance.
OPEN_LIFECYCLE_STATES = ("OPEN", "ADDRESSED_PENDING_REVERIFY")

EVIDENCE_VERDICTS = ("PASS", "FAIL", "ERROR")
CLASS_VERDICTS = ("PASS", "FAIL", "ERROR", "NOT_RUN")

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Canonical form for every execution and context identifier.
#
# Deliberately narrow: an ASCII alphanumeric first character followed by ASCII
# alphanumerics and the separators '-', '_', '.', up to 128 characters. Every
# other input is rejected outright rather than normalized: empty values,
# leading/trailing whitespace, embedded whitespace or control bytes, and *all*
# non-ASCII text, which is what excludes Unicode confusables such as a Cyrillic
# 'e' (U+0435) or a full-width 'A' (U+FF21). Rejecting is the fail-closed
# choice: a normalizing rule (NFKC, confusable folding, case folding) would map
# genuinely different identities onto one another and could silently merge two
# distinct agents.
CANONICAL_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"
CANONICAL_ID_RE = re.compile(CANONICAL_ID_PATTERN)

# Explicit, shape-specific secret patterns only. No generic entropy heuristics:
# commit SHAs and SHA-256 digests must never be redacted.
SECRET_KEY_RE = re.compile(
    r"(TOKEN|SECRET|PASSWORD|PASSWD|AUTHORIZATION|CREDENTIAL|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY)",
    re.IGNORECASE,
)
SECRET_VALUE_RE = re.compile(
    r"(?i)(authorization:\s*(?:bearer|token)\s+)[^\s]+"
    r"|\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"
    r"|(?-i:\b(?:AKIA|ASIA)[0-9A-Z]{16}\b)"
    r"|(?-i:\bxox[abps]-[0-9A-Za-z-]{10,}\b)"
    r"|(?-i:\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b)"
)


class ReviewGateError(Exception):
    """Base class for deterministic, fail-closed review-gate failures."""

    code = "E_INTERNAL"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class EvidenceError(ReviewGateError):
    code = "E_EVIDENCE"


class PreconditionError(ReviewGateError):
    code = "E_PRECONDITION"


class ReviewInputError(ReviewGateError):
    code = "E_REVIEW_INPUT"


class IdentityError(ReviewGateError):
    code = "E_IDENTITY"


class PathError(ReviewGateError):
    code = "E_PATH"


class OutputError(ReviewGateError):
    code = "E_OUTPUT"


def require(condition: object, message: str, *, error: type[ReviewGateError] = ReviewInputError) -> None:
    """Fail closed unless ``condition`` holds."""

    if not condition:
        raise error(message)


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    """RFC8259 canonical form: sorted keys, compact separators, UTF-8, LF."""

    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def generation_stanza() -> dict[str, Any]:
    return {"canonical_json": "RFC8259-sort-keys-utf8-lf", "timestamp_omitted": True}


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_strict_json(raw: bytes, *, source: str, error: type[ReviewGateError]) -> Any:
    """Parse strict UTF-8 JSON, rejecting duplicate keys and trailing junk."""

    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise error(f"{source} is not strict JSON: {exc}") from exc


def redact_text(value: str, env: Mapping[str, str] | None = None) -> str:
    """Replace secret-looking material with ``[REDACTED]``.

    Applied to every free-text field that reaches an output document so that a
    reviewer cannot leak a token, password or credential URL through a finding.
    """

    if not isinstance(value, str):
        return value
    text = SECRET_VALUE_RE.sub(lambda m: (m.group(1) if m.lastindex else "") + "[REDACTED]", value)
    text = re.sub(
        r"(?i)\b(https?://)[^\s/@:]+:[^\s/@]+@",
        lambda match: match.group(1) + "[REDACTED]@",
        text,
    )
    env = os.environ if env is None else env
    secrets = sorted(
        {v for k, v in env.items() if v and len(v) >= 8 and SECRET_KEY_RE.search(k)},
        key=len,
        reverse=True,
    )
    for secret in secrets:
        text = text.replace(secret, "[REDACTED]")
    return text


def validate_canonical_id(value: object, field: str, *, error: type[ReviewGateError] = IdentityError) -> str:
    """Return ``value`` if it is a canonical identifier, else fail closed.

    Applied to every execution and context identifier, wherever it enters the
    gate, so that identity comparisons are made between well-formed values in a
    single documented form (see ``CANONICAL_ID_PATTERN``).
    """

    require(isinstance(value, str), f"{field} must be a string", error=error)
    text: str = value  # type: ignore[assignment]
    require(text != "", f"{field} must be a non-empty string", error=error)
    require(text == text.strip(), f"{field} must not have leading or trailing whitespace", error=error)
    require(
        CANONICAL_ID_RE.fullmatch(text) is not None,
        f"{field} is not a canonical identifier (must match {CANONICAL_ID_PATTERN})",
        error=error,
    )
    return text


def ids_conflict(left: str, right: str) -> bool:
    """True when two canonical identifiers must be treated as the same identity.

    Used only by checks that require two identities to *differ*. The comparison
    is ASCII-case-insensitive so that a mere case variant of an identifier can
    never be used to slip past a distinctness check: an agent declaring
    ``Issue-55-Implementer-01`` against evidence naming
    ``issue-55-implementer-01`` is treated as a conflict, not as a new party.
    Both operands are canonical (pure ASCII), so ``str.lower`` is unambiguous
    here and none of the Unicode case-folding hazards apply.

    This only ever makes the gate reject more, never accept more: identity
    *bindings* to evidence are compared exactly, never through this helper.
    """

    return left.lower() == right.lower()


def normalize_component_path(value: object) -> str:
    """Normalize and harden a finding's component/path.

    Returns a repository-root-relative POSIX path. Absolute paths,
    home-relative paths, parent traversal, backslashes, control characters
    and empty segments are rejected: a component reference can never escape
    the repository or smuggle path-replacement material into evidence.
    """

    require(isinstance(value, str) and value != "", "component_path must be a non-empty string", error=PathError)
    text = value  # type: ignore[assignment]
    require("\x00" not in text, "component_path contains a NUL byte", error=PathError)
    require(all(ord(ch) >= 32 and ord(ch) != 127 for ch in text), "component_path contains control characters", error=PathError)
    require("\\" not in text, "component_path must use forward slashes", error=PathError)
    require(text == text.strip(), "component_path must not have leading or trailing whitespace", error=PathError)
    require(not text.startswith("/"), "component_path must be repository-relative, not absolute", error=PathError)
    require(not text.startswith("~"), "component_path must not be home-relative", error=PathError)
    parts = text.split("/")
    for part in parts:
        require(part != "", "component_path must not contain empty segments", error=PathError)
        require(part != ".", "component_path must not contain '.' segments", error=PathError)
        require(part != "..", "component_path must not contain parent-directory segments", error=PathError)
    return "/".join(parts)


def read_regular_file(path: Path, *, source: str) -> bytes:
    """Read a file, refusing symlinks (path replacement) and non-regular files."""

    try:
        if path.is_symlink():
            raise PathError(f"{source} must not be a symlink: {path.name}")
        stat = path.lstat()
    except OSError as exc:
        raise PathError(f"{source} cannot be read: {exc}") from exc
    import stat as stat_module

    if not stat_module.S_ISREG(stat.st_mode):
        raise PathError(f"{source} must be a regular file: {path.name}")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise PathError(f"{source} cannot be read: {exc}") from exc


# Marker of a git working tree: a directory in a normal checkout, a file in a
# linked worktree. Detected by inspecting the filesystem only; the gate never
# runs git and never reads repository contents.
GIT_MARKER = ".git"


def enclosing_git_worktree(start: Path) -> Path | None:
    """Return the nearest ancestor of ``start`` that is a git working tree."""

    walk = start
    while True:
        try:
            if (walk / GIT_MARKER).exists():
                return walk
        except OSError:
            return None
        if walk.parent == walk:
            return None
        walk = walk.parent


def ensure_writable_output(output: Path, *, repo_root: Path) -> None:
    """Validate the output target before anything is created.

    The gate never writes inside the reviewed repository (which would be a
    branch modification) and never follows a symlinked path component. This is
    the only place the gate writes at all, and the guarantee is fail-closed and
    unconditional rather than opt-in:

    - ``repo_root`` is mandatory, so the protection cannot be disabled by
      simply omitting it, and every writing subcommand requires the flag;
    - both the root and the output are compared in fully resolved canonical
      form, so the containment test cannot be evaded through a symlink;
    - relative and ``..``-bearing paths are refused instead of being guessed at,
      since their meaning depends on the caller's working directory;
    - independently of the declared root, an output inside *any* detected git
      working tree is refused. This closes the residual case of a caller that
      declares one repo root while writing into a different checkout.

    Nothing is created before every check has passed.
    """

    require(isinstance(repo_root, Path), "a repository root is required before any output may be written", error=OutputError)
    require(repo_root.is_absolute(), "repository root must be an absolute path", error=OutputError)
    require(".." not in repo_root.parts, "repository root must not contain parent-directory segments", error=OutputError)
    root = repo_root.resolve(strict=False)
    require(root.is_dir(), "repository root must be an existing directory", error=OutputError)

    require(output.is_absolute(), "output path must be absolute", error=OutputError)
    require(".." not in output.parts, "output path must not contain parent-directory segments", error=OutputError)

    resolved_output = output.resolve(strict=False)
    if resolved_output == root or resolved_output.is_relative_to(root):
        raise OutputError("output must be written outside the reviewed repository")

    # Reject a symlinked final component or any symlinked ancestor. This walks
    # the literal path: resolve() would have followed the links silently.
    walk = output
    while True:
        if walk.is_symlink():
            raise OutputError("output path must not traverse a symlink")
        if walk.parent == walk:
            break
        walk = walk.parent

    if enclosing_git_worktree(resolved_output.parent) is not None:
        raise OutputError("output must not be written inside a git working tree")


def atomic_write(path: Path, data: bytes) -> None:
    """Write ``data`` atomically via a temp file and ``os.replace``."""

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, raw_temp_path = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp_path = Path(raw_temp_path)
    try:
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


def require_closed_shape(document: Mapping[str, Any], fields: Iterable[str], *, where: str, error: type[ReviewGateError]) -> None:
    """Reject documents whose key set differs from the frozen closed shape."""

    expected = set(fields)
    actual = set(document)
    missing = expected - actual
    unknown = actual - expected
    require(not missing, f"{where} is missing fields: {sorted(missing)}", error=error)
    require(not unknown, f"{where} has unknown fields: {sorted(unknown)}", error=error)
