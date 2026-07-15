"""Atomic idempotency reference implementation (in-memory).

Explicit deterministic state machine — no on-disk format, directory, locking
discipline, retention or recovery is decided by v1.

States per key:
- absent     : no reservation.
- RESERVED   : begin() reserved the key; no terminal outcome yet.
- TERMINAL   : a client invocation produced a recorded, replayable outcome.

Transitions:
- begin(absent)               -> RESERVED,  returns MISS_RESERVED
- begin(RESERVED, same fp)    -> unchanged, returns PENDING   (concurrent/incomplete)
- begin(TERMINAL, same fp)    -> unchanged, returns REPLAY
- begin(*,        other fp)   -> unchanged, returns CONFLICT
- abort(RESERVED)             -> absent     (pre-call failure: nothing executed)
- complete(RESERVED, outcome) -> TERMINAL   (client invoked: outcome is terminal)

``abort`` is used ONLY for failures before the client call begins, so the key
stays retryable. Once the client is invoked, the broker always ``complete``s the
key with a terminal recorded outcome (success OR client-produced failure), so a
replay never re-invokes the client.
"""
from __future__ import annotations

import abc
import copy
import threading

MISS_RESERVED = "MISS_RESERVED"
REPLAY = "REPLAY"
CONFLICT = "CONFLICT"
PENDING = "PENDING"

_RESERVED = "RESERVED"
_TERMINAL = "TERMINAL"


class IdempotencyStore(abc.ABC):
    @abc.abstractmethod
    def begin(self, key: str, fingerprint: str) -> str:
        ...

    @abc.abstractmethod
    def abort(self, key: str) -> None:
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
        self._entries = {}  # key -> {"fingerprint", "state", "outcome"}

    def begin(self, key: str, fingerprint: str) -> str:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                self._entries[key] = {"fingerprint": fingerprint, "state": _RESERVED, "outcome": None}
                return MISS_RESERVED
            if entry["fingerprint"] != fingerprint:
                return CONFLICT
            if entry["state"] == _TERMINAL:
                return REPLAY
            return PENDING

    def abort(self, key: str) -> None:
        """Release a reservation that never reached a client call. No-op unless
        the key is currently RESERVED; a TERMINAL key is never aborted."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is not None and entry["state"] == _RESERVED:
                del self._entries[key]

    def complete(self, key: str, outcome: dict) -> None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None or entry["state"] != _RESERVED:
                raise KeyError(key)
            entry["state"] = _TERMINAL
            entry["outcome"] = copy.deepcopy(outcome)

    def recorded_outcome(self, key: str) -> dict:
        with self._lock:
            entry = self._entries[key]
            if entry["state"] != _TERMINAL or entry["outcome"] is None:
                raise KeyError(key)
            return copy.deepcopy(entry["outcome"])
