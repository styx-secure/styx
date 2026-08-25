"""Deterministic helpers for the isolated O-14 evidence package."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def write_report(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))


def read_json(path: Path) -> object:
    return json.loads(path.read_text(encoding="utf-8"))
