"""Canonical JSON primitives for the transcript-only C0.3 corpus.

This package is conformance evidence, not product or wire-format code.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class CanonicalJsonError(ValueError):
    """Input is outside the closed corpus JSON grammar."""


def _reject_float(value: str) -> None:
    raise CanonicalJsonError(f"floating-point values are forbidden: {value}")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJsonError(f"duplicate object key: {key}")
        result[key] = value
    return result


def loads(data: bytes) -> Any:
    """Parse exactly one UTF-8 JSON value with no BOM, duplicates or floats."""

    if data.startswith(b"\xef\xbb\xbf"):
        raise CanonicalJsonError("UTF-8 BOM is forbidden")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CanonicalJsonError("input is not UTF-8") from error
    decoder = json.JSONDecoder(
        object_pairs_hook=_object_pairs,
        parse_float=_reject_float,
        parse_constant=_reject_float,
    )
    try:
        value, end = decoder.raw_decode(text)
    except json.JSONDecodeError as error:
        raise CanonicalJsonError("invalid JSON") from error
    if text[end:] != "\n":
        raise CanonicalJsonError("canonical JSON requires exactly one final LF")
    if dumps(value) != data:
        raise CanonicalJsonError("JSON is not in canonical corpus form")
    return value


def dumps(value: Any) -> bytes:
    """Encode one canonical JSON value with exactly one final LF."""

    _validate_value(value)
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        + "\n"
    ).encode("utf-8")


def load(path: Path) -> Any:
    return loads(path.read_bytes())


def store(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(dumps(value))


def _validate_value(value: Any, location: str = "$") -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        raise CanonicalJsonError(f"float at {location}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_value(item, f"{location}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJsonError(f"non-string key at {location}")
            _validate_value(item, f"{location}.{key}")
        return
    raise CanonicalJsonError(f"unsupported value at {location}: {type(value).__name__}")
