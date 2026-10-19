#!/usr/bin/env python3
"""Canonical JSON helpers for the synthetic SS-0 corpus."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


class CanonicalJsonError(ValueError):
    """Raised when JSON cannot satisfy the corpus encoding contract."""


def _reject_float(value: str) -> None:
    raise CanonicalJsonError(f"floating-point value is forbidden: {value}")


def _reject_constant(value: str) -> None:
    raise CanonicalJsonError(f"non-finite value is forbidden: {value}")


def _unique_object(values: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in values:
        if key in result:
            raise CanonicalJsonError(f"duplicate object key: {key}")
        result[key] = value
    return result


def _validate_value(value: Any, path: str = "$json") -> None:
    if isinstance(value, float):
        raise CanonicalJsonError(f"floating-point value at {path}")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJsonError(f"non-string object key at {path}")
            _validate_value(item, f"{path}.{key}")
        return
    raise CanonicalJsonError(f"unsupported value at {path}: {type(value).__name__}")


def loads_unique(data: bytes) -> Any:
    if data.startswith(b"\xef\xbb\xbf"):
        raise CanonicalJsonError("UTF-8 BOM is forbidden")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise CanonicalJsonError("invalid UTF-8") from error
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as error:
        raise CanonicalJsonError("malformed JSON") from error
    _validate_value(value)
    return value


def canonical_bytes(value: Any) -> bytes:
    _validate_value(value)
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def load_canonical(path: Path) -> Any:
    data = path.read_bytes()
    value = loads_unique(data)
    if canonical_bytes(value) != data:
        raise CanonicalJsonError(f"non-canonical JSON: {path}")
    return value


def store_atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()
