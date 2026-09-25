"""Strict canonical JSON for APP-CORE-IFACE-0 evidence.

This serialization is conformance evidence, not a protocol wire or storage
encoding and not an authority or mutation identity.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class CanonicalJsonError(ValueError):
    """Input is outside STYX_CANONICAL_EVIDENCE_JSON_V0."""


def _reject_non_integer_number(value: str) -> None:
    raise CanonicalJsonError(f"non-integer JSON number is forbidden: {value}")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJsonError("duplicate JSON member")
        result[key] = value
    return result


def _validate(value: Any, location: str = "$") -> None:
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        raise CanonicalJsonError(f"floating-point value at {location}")
    if isinstance(value, str):
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError as error:
            raise CanonicalJsonError(f"non-Unicode scalar at {location}") from error
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate(item, f"{location}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJsonError(f"non-string object key at {location}")
            _validate(key, f"{location}.<key>")
            _validate(item, f"{location}.{key}")
        return
    raise CanonicalJsonError(
        f"unsupported value at {location}: {type(value).__name__}"
    )


def dumps(value: Any) -> bytes:
    """Serialize one value with sorted keys and exactly one final LF."""

    _validate(value)
    try:
        text = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise CanonicalJsonError("value is not canonical JSON") from error
    return (text + "\n").encode("utf-8", "strict")


def loads(data: bytes) -> Any:
    """Parse exactly one canonical UTF-8 JSON value."""

    if data.startswith(b"\xef\xbb\xbf"):
        raise CanonicalJsonError("UTF-8 BOM is forbidden")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise CanonicalJsonError("input is not strict UTF-8") from error
    decoder = json.JSONDecoder(
        object_pairs_hook=_object_pairs,
        parse_float=_reject_non_integer_number,
        parse_constant=_reject_non_integer_number,
    )
    try:
        value, end = decoder.raw_decode(text)
    except (json.JSONDecodeError, CanonicalJsonError) as error:
        if isinstance(error, CanonicalJsonError):
            raise
        raise CanonicalJsonError("invalid JSON") from error
    if text[end:] != "\n":
        raise CanonicalJsonError("canonical JSON requires exactly one final LF")
    if dumps(value) != data:
        raise CanonicalJsonError("JSON is not in canonical form")
    return value


def load(path: Path) -> Any:
    return loads(path.read_bytes())


def store(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(dumps(value))

