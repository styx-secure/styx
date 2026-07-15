"""Atomic idempotency reference implementation (in-memory).

The atomic ``begin`` removes the check-then-act window; ``complete`` finalizes a
reserved key. Only the logical semantics are frozen here — no on-disk format,
directory, locking discipline, retention or recovery is decided by v1.
"""
from __future__ import annotations

import abc
import copy
import threading

MISS_RESERVED = "MISS_RESERVED"
REPLAY = "REPLAY"
CONFLICT = "CONFLICT"


class IdempotencyStore(abc.ABC):
    @abc.abstractmethod
    def begin(self, key: str, fingerprint: str) -> str:
        ...

    @abc.abstractmethod
    def complete(self, key: str, outcome: dict) -> None:
        ...

    @abc.abstractmethod
    def recorded_outcome(self, key: str) -> dict:
        ...


class InMemoryIdempotencyStore(IdempotencyStore):
    def __init__(self):
        self._lock = threading.Lock()
        self._entries = {}  # key -> {"fingerprint": str, "outcome": dict | None}

    def begin(self, key: str, fingerprint: str) -> str:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self._entries[key] = {"fingerprint": fingerprint, "outcome": None}
                return MISS_RESERVED
            if entry["fingerprint"] != fingerprint:
                return CONFLICT
            return REPLAY

    def complete(self, key: str, outcome: dict) -> None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                raise KeyError(key)
            entry["outcome"] = copy.deepcopy(outcome)

    def recorded_outcome(self, key: str) -> dict:
        with self._lock:
            entry = self._entries[key]
            if entry["outcome"] is None:
                raise KeyError(key)
            return copy.deepcopy(entry["outcome"])
