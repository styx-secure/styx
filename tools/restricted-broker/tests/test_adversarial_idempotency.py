"""Adversarial tests for the atomic idempotency store of the restricted broker.

GAP JUSTIFICATION (GAPS.md of the parent re-run t_3e22486c, §2): the row

    tools/restricted-broker/idempotency.py | test che lo citano: 1 | categories
    assenti: boundary/size limits, resource exhaustion / amplification,
    rollback / atomicity, timeout / liveness

is the gap this module closes. The store is the only thing standing between a
retried broker invocation and a duplicated side effect, so the suite pins the
absent categories: the reservation/terminal boundary, the abort rollback, the
snapshot discipline, and non-blocking progress under contention.

Deterministic and offline: fixed keys, no wall clock, no unseeded randomness.
"""

import inspect
import os
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import idempotency  # noqa: E402
from idempotency import (  # noqa: E402
    CONFLICT,
    MISS_RESERVED,
    PENDING,
    REPLAY,
    InMemoryIdempotencyStore,
)


class TestBoundary(unittest.TestCase):
    def test_empty_key_and_empty_fingerprint_are_a_legal_boundary(self):
        store = InMemoryIdempotencyStore()
        self.assertEqual(store.begin("", ""), MISS_RESERVED)
        self.assertEqual(store.begin("", ""), PENDING)
        store.complete("", {})
        self.assertEqual(store.begin("", ""), REPLAY)
        self.assertEqual(store.recorded_outcome(""), {})

    def test_whitespace_and_empty_fingerprints_never_collide(self):
        store = InMemoryIdempotencyStore()
        self.assertEqual(store.begin("k", ""), MISS_RESERVED)
        for other in (" ", "\n", "\t", "  "):
            self.assertEqual(store.begin("k", other), CONFLICT)

    def test_oversized_key_and_fingerprint_round_trip(self):
        store = InMemoryIdempotencyStore()
        key = "k" * 100000
        fingerprint = "f" * 100000
        self.assertEqual(store.begin(key, fingerprint), MISS_RESERVED)
        store.complete(key, {"result": "OK"})
        self.assertEqual(store.begin(key, fingerprint), REPLAY)
        self.assertEqual(store.begin(key, "f" * 99999 + "g"), CONFLICT)


class TestCollisionAndAmbiguity(unittest.TestCase):
    def test_single_byte_fingerprint_differences_are_conflicts(self):
        store = InMemoryIdempotencyStore()
        base = '{"operation":"push_task_branch","issue_number":53}'
        self.assertEqual(store.begin("k", base), MISS_RESERVED)
        variants = [
            base.upper(),
            base + " ",
            " " + base,
            base.replace("53", "54"),
            base.replace('"', "'"),
            '{"operation":"push_task_branch","issue_number":53}\n',
            '{"issue_number":53,"operation":"push_task_branch"}',
        ]
        for variant in variants:
            self.assertNotEqual(variant, base)
            self.assertEqual(store.begin("k", variant), CONFLICT)
        self.assertEqual(store.begin("k", base), PENDING)

    def test_unicode_normalization_is_not_applied_to_fingerprints(self):
        store = InMemoryIdempotencyStore()
        nfc = "evidence-\u00f1"
        nfd = "evidence-n\u0303"
        self.assertNotEqual(nfc, nfd)
        self.assertEqual(store.begin("k", nfc), MISS_RESERVED)
        self.assertEqual(store.begin("k", nfd), CONFLICT)

    def test_terminal_replay_is_not_confused_with_pending(self):
        store = InMemoryIdempotencyStore()
        store.begin("k", "fp")
        self.assertEqual(store.begin("k", "fp"), PENDING)
        store.complete("k", {"result": "OK"})
        self.assertEqual(store.begin("k", "fp"), REPLAY)
        self.assertEqual(store.begin("k", "fp"), REPLAY)


class TestRollbackAndAtomicity(unittest.TestCase):
    def test_abort_releases_only_a_live_reservation(self):
        store = InMemoryIdempotencyStore()
        store.begin("k", "fp-a")
        store.abort("k")
        # Nothing was executed, so the key is retryable even with a *different*
        # fingerprint: a released reservation leaves no memory of the conflict.
        self.assertEqual(store.begin("k", "fp-b"), MISS_RESERVED)
        store.complete("k", {"result": "OK"})
        # A terminal key is never aborted: the recorded outcome stays replayable.
        store.abort("k")
        self.assertEqual(store.begin("k", "fp-b"), REPLAY)
        self.assertEqual(store.recorded_outcome("k"), {"result": "OK"})

    def test_abort_on_absent_key_is_a_noop(self):
        store = InMemoryIdempotencyStore()
        store.abort("never-seen")
        self.assertEqual(store.begin("never-seen", "fp"), MISS_RESERVED)

    def test_complete_after_abort_is_refused(self):
        store = InMemoryIdempotencyStore()
        store.begin("k", "fp")
        store.abort("k")
        with self.assertRaises(KeyError):
            store.complete("k", {"result": "OK"})

    def test_double_complete_is_refused_and_the_first_outcome_wins(self):
        store = InMemoryIdempotencyStore()
        store.begin("k", "fp")
        store.complete("k", {"result": "OK", "pr": 1})
        with self.assertRaises(KeyError):
            store.complete("k", {"result": "FORGED", "pr": 999})
        self.assertEqual(store.recorded_outcome("k"), {"result": "OK", "pr": 1})

    def test_recorded_outcome_cannot_be_poisoned_through_aliasing(self):
        store = InMemoryIdempotencyStore()
        outcome = {"result": "OK", "nested": {"list": [1, 2, 3]}}
        store.begin("k", "fp")
        store.complete("k", outcome)
        outcome["nested"]["list"].append(4)
        outcome["result"] = "FORGED"
        first = store.recorded_outcome("k")
        self.assertEqual(first, {"result": "OK", "nested": {"list": [1, 2, 3]}})
        first["nested"]["list"].append(5)
        self.assertEqual(store.recorded_outcome("k")["nested"]["list"], [1, 2, 3])

    def test_failed_begin_leaves_the_state_machine_untouched(self):
        store = InMemoryIdempotencyStore()
        store.begin("k", "fp")
        store.begin("k", "other")  # CONFLICT, must not reserve or mutate
        store.complete("k", {"result": "OK"})
        self.assertEqual(store.recorded_outcome("k"), {"result": "OK"})


class TestResourceAndLiveness(unittest.TestCase):
    def test_many_keys_never_cross_contaminate(self):
        store = InMemoryIdempotencyStore()
        count = 20000
        for index in range(count):
            self.assertEqual(store.begin(f"k{index}", f"fp{index}"), MISS_RESERVED)
            store.complete(f"k{index}", {"result": "OK", "index": index})
        self.assertEqual(store.begin("k0", "fp0"), REPLAY)
        self.assertEqual(store.recorded_outcome(f"k{count - 1}")["index"], count - 1)
        self.assertEqual(store.begin("k0", "fp1"), CONFLICT)

    def test_contention_admits_exactly_one_reservation(self):
        store = InMemoryIdempotencyStore()
        workers = 8
        barrier = threading.Barrier(workers)
        results = []
        lock = threading.Lock()

        def worker():
            barrier.wait()
            outcome = store.begin("contended", "fp")
            with lock:
                results.append(outcome)

        threads = [threading.Thread(target=worker) for _ in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(sorted(results), sorted([MISS_RESERVED] + [PENDING] * (workers - 1)))
        store.complete("contended", {"result": "OK"})
        self.assertEqual(store.begin("contended", "fp"), REPLAY)

    def test_source_has_no_clock_randomness_or_io(self):
        source = inspect.getsource(idempotency)
        for token in ("import time", "time.", "random", "socket", "sleep", "datetime", "open("):
            self.assertNotIn(token, source, token)


class TestTypingObservation(unittest.TestCase):
    def test_runtime_accepts_a_non_dict_outcome(self):
        """Observed (see FINDINGS.md): the ``dict`` type hint is not enforced.

        ``complete`` stores any deep-copyable object, so a non-dict outcome is
        recorded and later replayed verbatim instead of raising. The broker only
        ever stores dicts, so this is an observation on the store's own
        contract, not a reachable broker path.
        """
        store = InMemoryIdempotencyStore()
        store.begin("k", "fp")
        store.complete("k", ["not", "a", "dict"])  # type: ignore[arg-type]
        self.assertEqual(store.recorded_outcome("k"), ["not", "a", "dict"])


if __name__ == "__main__":
    unittest.main()
