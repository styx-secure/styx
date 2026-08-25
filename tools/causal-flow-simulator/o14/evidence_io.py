"""Canonical report encoding for the isolated O-14 evidence package."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class CanonicalJsonReport:
    """Encode and persist deterministic JSON evidence without runtime metadata."""

    @classmethod
    def _reject_floats(cls, value: object) -> None:
        if isinstance(value, float):
            raise ValueError("floating-point values are forbidden in canonical evidence")
        if isinstance(value, dict):
            for key, item in value.items():
                cls._reject_floats(key)
                cls._reject_floats(item)
        elif isinstance(value, (list, tuple)):
            for item in value:
                cls._reject_floats(item)

    @classmethod
    def encode(cls, value: object) -> bytes:
        cls._reject_floats(value)
        document = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return f"{document}\n".encode("utf-8")

    @classmethod
    def store(cls, destination: Path, value: object) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(cls.encode(value))

    @staticmethod
    def load(source: Path) -> Any:
        with source.open("r", encoding="utf-8") as stream:
            return json.load(stream)


def content_sha256(data: bytes) -> str:
    """Return the lowercase SHA-256 identity of exact evidence bytes."""

    return hashlib.sha256(data).hexdigest()
