#!/usr/bin/env python3
"""Canonical, provenance-free report boundary for SS-0 evidence."""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any


_FORBIDDEN_KEY = re.compile(
    r"(?:absolute|bundle|commit|diff|duration|elapsed|hostname|path|pid|runtime_details|timestamp|tree|username|worktree)",
    re.IGNORECASE,
)
_ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:/|\\|[A-Za-z]:[\\/]|\\\\[^\\\s]+[\\/][^\\\s]+)"
)
_TIME_VALUE = re.compile(
    r"(?:\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}|\b(?:elapsed|duration|runtime)\s*[=:])",
    re.IGNORECASE,
)


def _walk(value: Any, path: str = "$report") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or _FORBIDDEN_KEY.search(key):
                raise ValueError(f"forbidden canonical key at {path}")
            _walk(child, f"{path}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _walk(child, f"{path}[{index}]")
        return
    if isinstance(value, str):
        if _ABSOLUTE_PATH.search(value) or _TIME_VALUE.search(value):
            raise ValueError(f"runtime provenance in canonical value at {path}")
        if "-----BEGIN" in value or "secret=" in value.lower():
            raise ValueError(f"sensitive value in canonical report at {path}")
        return
    if value is None or isinstance(value, (bool, int)):
        return
    raise ValueError(f"unsupported canonical value at {path}")


def canonical_bytes(report: dict[str, Any]) -> bytes:
    _walk(report)
    return (json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def store(report: dict[str, Any], output: Path) -> None:
    payload = canonical_bytes(report)
    output.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output.parent, prefix=f".{output.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
