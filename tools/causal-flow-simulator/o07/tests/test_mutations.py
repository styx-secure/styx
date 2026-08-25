from __future__ import annotations

from pathlib import Path
import sys
import unittest


O07_ROOT = Path(__file__).resolve().parents[1]
if str(O07_ROOT) not in sys.path:
    sys.path.insert(0, str(O07_ROOT))

from run_mutations import MUTATIONS, build_report


class MutationTest(unittest.TestCase):
    def test_every_registered_source_mutant_is_killed(self) -> None:
        repo = Path(__file__).resolve().parents[4]
        report, passed = build_report(repo)
        self.assertTrue(passed)
        self.assertEqual(report["required_mutant_count"], len(MUTATIONS))
        self.assertEqual(report["survived"], [])


if __name__ == "__main__":
    unittest.main()
