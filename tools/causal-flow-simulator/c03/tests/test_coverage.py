from __future__ import annotations

import sys
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
sys.path.insert(0, str(ROOT))

from corpus_model import (  # noqa: E402
    BASE_REVIEW_MODEL_DIGEST_RECONCILIATIONS,
    BASE_SHA,
    validate_base_inputs,
)


class ClosedInputTests(unittest.TestCase):
    def test_r7_brand_only_digest_reconciliation_is_exact(self) -> None:
        self.assertEqual(
            BASE_REVIEW_MODEL_DIGEST_RECONCILIATIONS,
            {
                "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md": (
                    "fc8cbef3f492fc0004f13c98128b9569f913348ec1e1fd42608cf316fd83e03e",
                    "1f40fde4b8912766eb586d56f4e72f8c040448e74bc3e6503ed25787abbb7e8f",
                ),
                "docs/security/STYX-THREAT-MODEL.md": (
                    "e4a003e55022ff2c0c31a5ac0dafb93482fb76585f379c8af18842f8407c03f8",
                    "53ff40c30155b3c7607493c0fb100430904ccf9bfe0c68c95557b94d5dd2674d",
                ),
            },
        )

    def test_source_map_and_inventory_match_exact_base(self) -> None:
        source_map, inventory = validate_base_inputs(REPO)
        self.assertEqual(source_map["base"], BASE_SHA)
        self.assertEqual(inventory["o07_relation_count"], 287)
        self.assertEqual(len(inventory["o10_primaries"]), 25)
        self.assertEqual(
            sum(
                len(inventory["o08_roles"][role])
                for role in (
                    "C03_SEMANTIC_LIMIT",
                    "C03_ACTIVATION_CAPABILITY_INPUT",
                    "C03_EXPLICIT_ZERO_OR_UNSUPPORTED",
                )
            ),
            53,
        )


if __name__ == "__main__":
    unittest.main()
