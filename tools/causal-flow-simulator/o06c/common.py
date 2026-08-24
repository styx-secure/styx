"""Deterministic helpers shared only by the isolated O-06c evidence package."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def sha256_hex(data: bytes) -> str:
    """Return the full-width lowercase SHA-256 digest of *data*."""

    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: object) -> bytes:
    """Encode a report as RFC 8259 JSON with sorted keys and one final LF."""

    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def write_report(path: Path, value: object) -> None:
    """Write one canonical report to a caller-selected external path."""

    path.write_bytes(canonical_bytes(value))
