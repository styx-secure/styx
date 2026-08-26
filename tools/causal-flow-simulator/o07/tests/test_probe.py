from __future__ import annotations

from pathlib import Path
import sys
import unittest


O07_ROOT = Path(__file__).resolve().parents[1]
if str(O07_ROOT) not in sys.path:
    sys.path.insert(0, str(O07_ROOT))

from run_genesis_checkpoint_probe import build_report


class ProbeTest(unittest.TestCase):
    def test_required_hostile_inventory_passes(self) -> None:
        report, passed = build_report()
        self.assertTrue(passed)
        self.assertEqual(report["inventory_relation_count"], 287)
        self.assertEqual(report["semantic_atom_count"], 229)
        self.assertEqual(report["external_gate_count"], 58)
        self.assertEqual(report["failed_semantic_atoms"], [])
        self.assertEqual(report["semantic_verdict"], "PASS")
        self.assertEqual(report["final_o07_gate"], "NOT_EVALUATED_BY_THIS_PROBE")


if __name__ == "__main__":
    unittest.main()
