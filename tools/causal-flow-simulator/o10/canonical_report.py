"""Closed canonical JSON reports for the O-10 evidence package."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


class ReportError(ValueError):
    """A report is non-canonical or contains forbidden provenance."""


_FORBIDDEN_KEYS = frozenset(
    {
    "timestamp",
    "duration",
    "elapsed",
    "rss",
    "hostname",
    "username",
    "pid",
    "process",
    "environment",
    "repository",
    "candidate",
    "commit",
    "absolute_path",
    "repository_identity",
    "candidate_identity",
    "commit_identity",
    }
)
_ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:/|\\|[A-Za-z]:[\\/]|\\\\[^\\\s]+[\\/][^\\\s]+)"
)
_TIMESTAMP = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")
_MEASUREMENT = re.compile(r"\b(?:elapsed|duration|runtime|rss)\s*[:=]", re.I)


def _walk(value: Any, path: tuple[str, ...] = ()) -> None:
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        raise ReportError("floating-point measurements are forbidden")
    if isinstance(value, str):
        if _ABSOLUTE_PATH.search(value):
            raise ReportError("absolute path is forbidden")
        if _TIMESTAMP.search(value) or _MEASUREMENT.search(value):
            raise ReportError("runtime measurement is forbidden")
        return
    if isinstance(value, list):
        for item in value:
            _walk(item, path)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ReportError("report keys must be strings")
            lowered = key.lower()
            if lowered in _FORBIDDEN_KEYS:
                raise ReportError(f"forbidden report key: {key}")
            _walk(item, path + (key,))
        return
    raise ReportError(f"unsupported report value at {'.'.join(path)}")


def canonical_bytes(report: dict[str, Any], *, allowed_fields: frozenset[str]) -> bytes:
    if set(report) != set(allowed_fields):
        raise ReportError("report fields do not match the closed schema")
    _walk(report)
    return (
        json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def store_report(
    path: Path, report: dict[str, Any], *, allowed_fields: frozenset[str]
) -> None:
    payload = canonical_bytes(report, allowed_fields=allowed_fields)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def load_report(path: Path, *, allowed_fields: frozenset[str]) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        decoded = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReportError("report is unreadable") from exc
    if not isinstance(decoded, dict):
        raise ReportError("report root must be an object")
    if raw != canonical_bytes(decoded, allowed_fields=allowed_fields):
        raise ReportError("report bytes are not canonical")
    return decoded
