from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from generate_seed_registry import prove_reachability  # noqa: E402


class SeedReachabilityTests(unittest.TestCase):
    def test_every_ratified_object_and_union_arm_has_a_valid_carrier(self) -> None:
        self.assertEqual(
            prove_reachability(ROOT / "contract"),
            {"object_schema_count": 78, "one_of_arm_count": 54},
        )


if __name__ == "__main__":
    unittest.main()
