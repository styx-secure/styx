from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "tools/causal-flow-simulator/o10"))

from taxonomy import ALIAS, PRIMARY_ROWS, TaxonomyError, resolve_recovery  # noqa: E402


class RecoveryTests(unittest.TestCase):
    def test_recovery_matches_every_primary_and_alias(self) -> None:
        for identifier, row in PRIMARY_ROWS.items():
            self.assertEqual(resolve_recovery(identifier), row[3])
        self.assertEqual(resolve_recovery(ALIAS), "QUARANTINE_LINEAGE_AND_REPLAY")

    def test_unknown_recovery_identifier_fails_closed(self) -> None:
        with self.assertRaises(TaxonomyError):
            resolve_recovery("INVENTED_OUTCOME")


if __name__ == "__main__":
    unittest.main()
