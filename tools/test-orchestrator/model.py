"""Shared data model for the Styx automatic test orchestrator."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Mapping

PLAN_SCHEMA_ID = "styx.test-plan/v1"
REPORT_SCHEMA_ID = "styx.test-report/v1"
FAILURE_SCHEMA_ID = "styx.test-failure/v1"
SCOPE_REPORT_SCHEMA_ID = "styx.task-scope-report/v1"
TOOL_VERSION = "0.1.0"

EXIT_PASS = 0
EXIT_FAIL = 2
EXIT_ERROR = 3

EXECUTION_CLASSES = (
    "MANDATORY",
    "REGRESSION",
    "GENERATED",
    "ADVERSARIAL",
    "STATIC",
    "ROLLBACK",
)
ORIGINS = (
    "issue-contract",
    "regression-discovery",
    "planner-builtin",
    "generated-proposal",
)
ISOLATION_MODES = ("worktree", "archive")

MAX_TIMEOUT_SECONDS = 1800
MAX_OUTPUT_BYTES = 10_485_760
DEFAULT_TIMEOUT_SECONDS = 900
DEFAULT_MAX_OUTPUT_BYTES = 1_048_576

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

SECRET_KEY_RE = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|AUTHORIZATION|CREDENTIAL)", re.IGNORECASE)
SECRET_VALUE_RE = re.compile(
    r"(?i)(authorization:\s*(?:bearer|token)\s+)[^\s]+"
    r"|\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"
)


class OrchestratorError(Exception):
    """Base class for deterministic orchestrator failures."""

    code = "E_INTERNAL"

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class ContractInputError(OrchestratorError):
    code = "E_CONTRACT"


class ScopeReportError(OrchestratorError):
    code = "E_SCOPE_REPORT"


class PlanError(OrchestratorError):
    code = "E_PLAN"


class CommandPolicyError(OrchestratorError):
    code = "E_COMMAND_POLICY"


class RepositoryStateError(OrchestratorError):
    code = "E_REPOSITORY_STATE"


@dataclasses.dataclass(frozen=True)
class PlannedCheck:
    origin: str
    purpose: str
    execution_class: str
    head_sha: str
    command: tuple[str, ...]
    timeout_seconds: int
    max_output_bytes: int
    isolation: str
    discard_stdout: bool = False

    def identifier(self) -> str:
        material = canonical_json_bytes(
            {
                "command": list(self.command),
                "discard_stdout": self.discard_stdout,
                "execution_class": self.execution_class,
                "head_sha": self.head_sha,
                "isolation": self.isolation,
                "origin": self.origin,
                "purpose": self.purpose,
            }
        )
        return hashlib.sha256(material).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.identifier(),
            "origin": self.origin,
            "purpose": self.purpose,
            "execution_class": self.execution_class,
            "head_sha": self.head_sha,
            "command": list(self.command),
            "cwd": ".",
            "timeout_seconds": self.timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
            "network": "denied",
            "isolation": self.isolation,
            "discard_stdout": self.discard_stdout,
        }


def canonical_json_bytes(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def generation_stanza() -> dict[str, Any]:
    return {"canonical_json": "RFC8259-sort-keys-utf8-lf", "timestamp_omitted": True}


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_strict_json(raw: bytes, *, source: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=reject_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise PlanError(f"{source} is not strict canonical JSON: {exc}") from exc


def redact_text(value: str, env: Mapping[str, str] | None = None) -> str:
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


def atomic_write(path: Path, data: bytes) -> None:
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
