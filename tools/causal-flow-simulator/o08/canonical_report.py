"""Canonical host-independent O-08 report encoding and hygiene checks."""

from __future__ import annotations

import json
from pathlib import Path
import re

from semantic_registry import canonical_bytes


_ABSOLUTE_PATH = re.compile(r"(?<![A-Za-z0-9_.-])(?:/|\\|[A-Za-z]:[\\/])")
_TIMESTAMP = re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2})?")
_RUNTIME_VALUE = re.compile(
    r"\b(?:elapsed|duration|runtime|wall|cpu|rss|pid|hostname|username)\s*[:=]",
    re.IGNORECASE,
)


class ReportError(ValueError):
    """A canonical report contains non-canonical or host-derived data."""


def _walk(value: object) -> None:
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise ReportError("report keys must be strings")
        for key, item in value.items():
            _walk(key)
            _walk(item)
    elif isinstance(value, list):
        for item in value:
            _walk(item)
    elif isinstance(value, str):
        if _ABSOLUTE_PATH.search(value):
            raise ReportError("canonical report contains an absolute path")
        if _TIMESTAMP.search(value) or _RUNTIME_VALUE.search(value):
            raise ReportError("canonical report contains runtime provenance")
    elif not isinstance(value, (int, bool)) and value is not None:
        raise ReportError("canonical report contains an unsupported scalar")


def validate_report(value: dict[str, object], expected_schema: str) -> None:
    if value.get("schema") != expected_schema:
        raise ReportError("report schema mismatch")
    _walk(value)


def store_report(path: Path, value: dict[str, object], expected_schema: str) -> None:
    validate_report(value, expected_schema)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))


def load_report(path: Path, expected_schema: str) -> dict[str, object]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ReportError("report object required")
    validate_report(value, expected_schema)
    if raw != canonical_bytes(value):
        raise ReportError("report is not canonical JSON with trailing LF")
    return value
