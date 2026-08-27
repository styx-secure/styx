from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tools/causal-flow-simulator/o10"))

from fixtures import primary_scenario  # noqa: E402
from taxonomy import PRIMARY_ROWS, evaluate  # noqa: E402


class RemoteCollapseTests(unittest.TestCase):
    def test_only_applied_is_distinguishable_remotely(self) -> None:
        for primary in PRIMARY_ROWS:
            observed = evaluate(primary_scenario(primary)).as_dict()["remote"]
            expected = "APPLIED" if primary == "APPLIED" else "OPAQUE_REMOTE_FAILURE"
            self.assertEqual(observed, {"result": expected})


if __name__ == "__main__":
    unittest.main()
