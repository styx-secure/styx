from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[5]
CORPUS_TOOL = ROOT / "tools/causal-flow-simulator/ss0/corpus"
sys.path.insert(0, str(CORPUS_TOOL))

from scope_guard import (  # noqa: E402
    CONTRACT_SHA256,
    K11_INVENTORY_SHA256,
    K11_RATIFICATION_BODY,
    _load_contract_module,
    _normalize_body,
)


class ScopeGuardTests(unittest.TestCase):
    def test_contract_parser_and_path_matcher_are_the_official_ones(self) -> None:
        module = _load_contract_module(ROOT)
        self.assertEqual("contract", module.__name__)
        self.assertTrue(callable(module.parse_contract))
        self.assertTrue(callable(module.evaluate_path))

    def test_provider_body_normalization_is_closed(self) -> None:
        normalized = _normalize_body("alpha  \r\nbeta\t\r\n\r\n")
        self.assertEqual(b"alpha\nbeta\n", normalized)
        self.assertEqual(64, len(CONTRACT_SHA256))
        self.assertIn(K11_INVENTORY_SHA256, K11_RATIFICATION_BODY)
        self.assertFalse(K11_RATIFICATION_BODY.endswith("\n"))


if __name__ == "__main__":
    unittest.main()
