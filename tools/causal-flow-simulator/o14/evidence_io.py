"""Canonical report encoding for the isolated O-14 evidence package."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class CanonicalJsonReport:
    """Encode and persist deterministic JSON evidence without runtime metadata."""

    @staticmethod
    def encode(value: object) -> bytes:
        document = json.dumps(
            value,
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
