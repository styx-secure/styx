"""Closed canonical reports and provenance hygiene for APP-CORE-IFACE-0."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from canonical_json import CanonicalJsonError, dumps, loads


class ReportError(ValueError):
    """A report is malformed, non-canonical, or leaks forbidden provenance."""


_FORBIDDEN_KEYS = frozenset(
    {
        "absolute_path",
        "base",
        "bundle",
        "candidate",
        "commit",
        "diff",
        "duration",
        "elapsed",
        "environment",
        "exception",
        "head",
        "hostname",
        "pid",
        "process",
        "repository",
        "rss",
        "stack",
        "timestamp",
        "tree",
        "username",
    }
)
_ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:/|\\|[A-Za-z]:[\\/]|\\\\[^\\\s]+[\\/][^\\\s]+)"
)
_TIMESTAMP = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")
_MEASUREMENT = re.compile(r"\b(?:elapsed|duration|runtime|rss)\s*[:=]", re.I)
_EXCEPTION = re.compile(r"\b(?:traceback|exception|stack\s*trace)\b", re.I)


def _walk(value: Any, forbidden_values: frozenset[str]) -> None:
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        raise ReportError("floating-point report values are forbidden")
    if isinstance(value, str):
        if _ABSOLUTE_PATH.search(value):
            raise ReportError("absolute path is forbidden")
        if _TIMESTAMP.search(value) or _MEASUREMENT.search(value):
            raise ReportError("runtime measurement is forbidden")
        if _EXCEPTION.search(value):
            raise ReportError("exception material is forbidden")
        for forbidden in forbidden_values:
            if forbidden and (value == forbidden or len(forbidden) >= 7 and forbidden in value):
                raise ReportError("forbidden identity is present")
        return
    if isinstance(value, list):
        for item in value:
            _walk(item, forbidden_values)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ReportError("report keys must be strings")
            if key.lower() in _FORBIDDEN_KEYS:
                raise ReportError(f"forbidden report key: {key}")
            _walk(key, forbidden_values)
            _walk(item, forbidden_values)
        return
    raise ReportError("unsupported report value")


def canonical_bytes(
    report: dict[str, Any],
    *,
    allowed_fields: frozenset[str],
    forbidden_values: frozenset[str] = frozenset(),
) -> bytes:
    if not isinstance(report, dict) or set(report) != set(allowed_fields):
        raise ReportError("report fields do not match the closed schema")
    _walk(report, forbidden_values)
    try:
        return dumps(report)
    except CanonicalJsonError as error:
        raise ReportError("report is not canonical JSON") from error


def store_report(
    path: Path,
    report: dict[str, Any],
    *,
    allowed_fields: frozenset[str],
    forbidden_values: frozenset[str] = frozenset(),
) -> None:
    payload = canonical_bytes(
        report, allowed_fields=allowed_fields, forbidden_values=forbidden_values
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)


def load_report(
    path: Path,
    *,
    allowed_fields: frozenset[str],
    forbidden_values: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
        value = loads(raw)
    except (OSError, CanonicalJsonError) as error:
        raise ReportError("report is unreadable or non-canonical") from error
    if not isinstance(value, dict):
        raise ReportError("report root must be an object")
    if raw != canonical_bytes(
        value, allowed_fields=allowed_fields, forbidden_values=forbidden_values
    ):
        raise ReportError("report bytes are not canonical")
    return value

