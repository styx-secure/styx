import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import idempotency  # noqa: E402
from idempotency import CONFLICT, MISS_RESERVED, PENDING, REPLAY  # noqa: E402


class TestIdempotency(unittest.TestCase):
    def setUp(self):
        self.store = idempotency.InMemoryIdempotencyStore()

    def test_first_begin_reserves(self):
        self.assertEqual(self.store.begin("k", "fp1"), MISS_RESERVED)

    def test_same_key_same_fp_after_complete_replays(self):
        self.store.begin("k", "fp1")
        self.store.complete("k", {"result": "SUCCESS", "outcome": {"r": 1}})
        self.assertEqual(self.store.begin("k", "fp1"), REPLAY)
        self.assertEqual(self.store.recorded_outcome("k"), {"result": "SUCCESS", "outcome": {"r": 1}})

    def test_same_key_different_fp_conflicts(self):
        self.store.begin("k", "fp1")
        self.store.complete("k", {"result": "SUCCESS", "outcome": {}})
        self.assertEqual(self.store.begin("k", "fp2"), CONFLICT)

    def test_reserved_but_not_completed_same_fp_is_pending(self):
        self.store.begin("k", "fp1")
        self.assertEqual(self.store.begin("k", "fp1"), PENDING)

    def test_reserved_different_fp_conflicts(self):
        self.store.begin("k", "fp1")
        self.assertEqual(self.store.begin("k", "fp2"), CONFLICT)

    def test_abort_releases_reserved_key_for_retry(self):
        self.store.begin("k", "fp1")
        self.store.abort("k")
        self.assertEqual(self.store.begin("k", "fp1"), MISS_RESERVED)  # retryable

    def test_abort_does_not_touch_terminal_key(self):
        self.store.begin("k", "fp1")
        self.store.complete("k", {"result": "SUCCESS", "outcome": {"r": 1}})
        self.store.abort("k")  # no-op on terminal
        self.assertEqual(self.store.begin("k", "fp1"), REPLAY)

    def test_abort_absent_key_is_noop(self):
        self.store.abort("absent")  # must not raise

    def test_complete_requires_reservation(self):
        with self.assertRaises(KeyError):
            self.store.complete("absent", {"result": "SUCCESS", "outcome": {}})

    def test_recorded_outcome_missing_raises(self):
        with self.assertRaises(KeyError):
            self.store.recorded_outcome("absent")

    def test_recorded_outcome_on_reserved_raises(self):
        self.store.begin("k", "fp1")  # reserved, not terminal
        with self.assertRaises(KeyError):
            self.store.recorded_outcome("k")

    def test_outcome_is_deep_copied(self):
        self.store.begin("k", "fp1")
        payload = {"result": "SUCCESS", "outcome": {"nested": {"v": 1}}}
        self.store.complete("k", payload)
        payload["outcome"]["nested"]["v"] = 999
        self.assertEqual(self.store.recorded_outcome("k")["outcome"], {"nested": {"v": 1}})


if __name__ == "__main__":
    unittest.main()
