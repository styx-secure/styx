"""Load untrusted JSON as an object, rejecting duplicate keys and non-objects."""
from __future__ import annotations

import json

from model import EvidenceError


def _reject_duplicates(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise EvidenceError(f"duplicate JSON key: {key!r}")
        seen[key] = value
    return seen


def load_object(raw: bytes) -> dict:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise EvidenceError(f"malformed JSON: {exc}") from None
    if not isinstance(value, dict):
        raise EvidenceError("request root must be a JSON object")
    return value
