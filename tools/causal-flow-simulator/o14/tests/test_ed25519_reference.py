from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ed25519_reference as ed


class Ed25519ReferenceTest(unittest.TestCase):
    def test_independent_positive_round_trip(self) -> None:
        message = b"independently generated O-14 witness"
        key, signature = ed.sign_from_seed(bytes(range(32)), message)
        self.assertTrue(ed.verify(signature, message, key, zip215=False, cofactored=True))
        self.assertTrue(ed.verify(signature, message, key, zip215=False, cofactored=False))
        self.assertTrue(ed.selected_verify(signature, message, key))

    def test_mixed_order_separates_equations(self) -> None:
        message = b"cofactored-only"
        key, signature = ed.mixed_order_forgery(bytes(range(32)), message)
        self.assertTrue(ed.verify(signature, message, key, zip215=False, cofactored=True))
        self.assertFalse(ed.verify(signature, message, key, zip215=False, cofactored=False))
        self.assertFalse(ed.selected_verify(signature, message, key))

    def test_cofactorless_can_accept_mixed_order(self) -> None:
        message = b"cofactorless-mixed-order"
        key, signature = ed.mixed_order_cofactorless_valid(bytes(range(32)), message)
        self.assertTrue(ed.verify(signature, message, key, zip215=False, cofactored=False))
        self.assertTrue(ed.verify(signature, message, key, zip215=False, cofactored=True))
        self.assertFalse(ed.selected_verify(signature, message, key))

    def test_zip215_noncanonical_witness(self) -> None:
        message = b"zip215-only"
        key, signature = ed.zip215_noncanonical_key_forgery(message)
        self.assertTrue(ed.verify(signature, message, key, zip215=True, cofactored=True))
        self.assertFalse(ed.verify(signature, message, key, zip215=False, cofactored=True))
        self.assertFalse(ed.selected_verify(signature, message, key))


if __name__ == "__main__":
    unittest.main()
