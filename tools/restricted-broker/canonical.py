"""Canonical JSON serialization and hashing. No policy, no interpretation."""
from __future__ import annotations

import hashlib
import json


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_sha256(value: object) -> str:
    return sha256_hex(canonical_bytes(value))
