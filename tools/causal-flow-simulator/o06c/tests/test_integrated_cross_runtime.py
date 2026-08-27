"""Contract tests for the bounded integrated runtime report."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import unittest


INTEGRATION_DIRECTORY = Path(__file__).resolve().parents[1]
PROJECT_DIRECTORY = INTEGRATION_DIRECTORY.parents[2]
sys.path.insert(0, str(INTEGRATION_DIRECTORY))

from integrated_cross_runtime import (
    EXPECTED_NODE,
    EXPECTED_PYTHON,
    REPORT_FIELDS,
    build_report,
)
from o10.canonical_report import canonical_bytes


class IntegratedRuntimeContract(unittest.TestCase):
    """Prove the limited cross-runtime claim and its explicit non-claims."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.javascript = shutil.which("node")
        if cls.javascript is None:
            raise RuntimeError("the ratified Node runtime is unavailable")
        cls.evidence = build_report(PROJECT_DIRECTORY, cls.javascript)
        cls.encoded = canonical_bytes(cls.evidence, allowed_fields=REPORT_FIELDS)

    def test_report_has_the_closed_shape_and_success_state(self) -> None:
        self.assertEqual(set(self.evidence), REPORT_FIELDS)
        self.assertEqual(self.evidence["verdict"], "PASS")
        self.assertGreater(self.evidence["derived_event_count"], 0)
        self.assertEqual(len(self.evidence["integrated_probe_digest"]), 64)
        self.assertEqual(len(self.evidence["legacy_cross_language_digest"]), 64)

    def test_interchange_is_never_presented_as_o11(self) -> None:
        self.assertEqual(self.evidence["interchange"], "TEST_ONLY_NOT_O11")
        self.assertEqual(
            self.evidence["javascript_surface"],
            "DEPENDENCY_FREE_FORWARD_O06C_ENCODER",
        )
        self.assertEqual(
            self.evidence["python_surface"],
            "AUTHORITATIVE_O06C_TRANSCRIPT_AND_REFERENCE",
        )

    def test_shared_primitives_are_disclosed(self) -> None:
        self.assertEqual(
            self.evidence["shared_primitives"],
            [
                "SHA256",
                "FROZEN_O06B1_FIELD_ASSIGNMENT",
                "FROZEN_O06B2_COMMITMENT_ASSIGNMENT",
            ],
        )

    def test_toolchain_contract_is_exact(self) -> None:
        self.assertEqual(
            self.evidence["toolchain_contract"],
            [EXPECTED_PYTHON, f"Node {EXPECTED_NODE}"],
        )

    def test_canonical_bytes_are_stable_and_identity_free(self) -> None:
        self.assertTrue(self.encoded.endswith(b"\n"))
        self.assertEqual(json.loads(self.encoded), self.evidence)
        self.assertNotIn(str(PROJECT_DIRECTORY).encode("utf-8"), self.encoded)
        self.assertNotIn(str(Path.home()).encode("utf-8"), self.encoded)


if __name__ == "__main__":
    unittest.main()
