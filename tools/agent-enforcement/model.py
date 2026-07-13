"""Shared data model for the Styx report-only scope guard."""

from __future__ import annotations

import dataclasses

SCHEMA_ID = "styx.task-scope-report/v1"
TOOL_VERSION = "0.1.0"
CONTRACT_MARKER = "<!-- styx-task-contract:v1 -->"

EXIT_PASS = 0
EXIT_FAIL = 2
EXIT_ERROR = 3


class GuardError(Exception):
    """Base class for deterministic guard failures."""

    code = "E_INTERNAL"

    def __init__(self, message: str, *, path: str | None = None):
        super().__init__(message)
        self.message = message
        self.path = path


class ContractError(GuardError):
    code = "E_CONTRACT"


class GitInputError(GuardError):
    code = "E_GIT_INPUT"


class RepositoryStateError(GuardError):
    code = "E_REPOSITORY_STATE"


@dataclasses.dataclass(frozen=True)
class Diagnostic:
    code: str
    message: str
    severity: str
    path: str | None = None

    def as_dict(self) -> dict[str, object]:
        result: dict[str, object] = {
            "code": self.code,
            "message": self.message,
            "severity": self.severity,
        }
        if self.path is not None:
            result["path"] = self.path
        return result


@dataclasses.dataclass(frozen=True)
class Contract:
    version: str
    allowed_patterns: tuple[str, ...]
    forbidden_patterns: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class TreeObject:
    mode: str
    object_type: str
    object_sha: str
    path: str


@dataclasses.dataclass(frozen=True)
class ChangedEntry:
    status: str
    score: int | None
    old_path: str | None
    new_path: str | None

    def checked_paths(self) -> tuple[str, ...]:
        if self.status in {"R", "C"}:
            assert self.old_path is not None and self.new_path is not None
            return (self.old_path, self.new_path)
        path = self.new_path if self.status == "A" else self.old_path
        assert path is not None
        return (path,)


@dataclasses.dataclass(frozen=True)
class PathEvaluation:
    path: str
    allowed_matches: tuple[str, ...]
    forbidden_matches: tuple[str, ...]
    violations: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "allowed_matches": list(self.allowed_matches),
            "forbidden_matches": list(self.forbidden_matches),
            "violations": list(self.violations),
        }
