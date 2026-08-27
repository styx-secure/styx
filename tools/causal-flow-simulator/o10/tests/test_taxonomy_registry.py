from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
O10 = ROOT / "tools/causal-flow-simulator/o10"
sys.path.insert(0, str(O10))

from build_taxonomy_registry import canonical_bytes, registry  # noqa: E402


class TaxonomyRegistryTests(unittest.TestCase):
    def test_literal_registry_is_exact_and_canonical(self) -> None:
        raw = (O10 / "outcome-taxonomy.json").read_bytes()
        self.assertEqual(raw, canonical_bytes(registry()))
        self.assertEqual(len(json.loads(raw)["primaries"]), 25)


if __name__ == "__main__":
    unittest.main()
