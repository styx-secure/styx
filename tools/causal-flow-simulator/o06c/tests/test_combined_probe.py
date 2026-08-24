from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


O06C_ROOT = Path(__file__).resolve().parents[1]
PROBE = O06C_ROOT / "combined_falsification_probe.py"
REVIEW_MODEL = (
    O06C_ROOT.parents[2]
    / "docs/protocol/review/styx-app-kernel-v0-review-model.json"
)
sys.path.insert(0, str(O06C_ROOT))

from combined_falsification_probe import ProbeError, reject_digest_alias  # noqa: E402


class CombinedProbeTests(unittest.TestCase):
    def test_required_probe_is_canonical_and_exercises_all_stages(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            frozen = root / "frozen.json"
            frozen.write_text(
                '{"schema":"styx-o06c-frozen-section-report/v1","verdict":"PASS"}\n',
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment["O06C_MODEL_SEED"] = "o06c-v1-deterministic-test-seed"
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            outputs = (root / "first.json", root / "second.json")
            for output in outputs:
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(PROBE),
                        "--suite",
                        "required",
                        "--frozen-report",
                        str(frozen),
                        "--review-model",
                        str(REVIEW_MODEL),
                        "--output",
                        str(output),
                    ],
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())
            report = json.loads(outputs[0].read_bytes())
            self.assertEqual(report["verdict"], "NO_COUNTEREXAMPLE_WITHIN_BOUNDS")
            self.assertGreaterEqual(report["witness_count"], 23)
            self.assertFalse(report["failed_witnesses"])
            self.assertEqual(
                report["evidence"]["pinned_c02j"]["execution_status"],
                "PINNED_NOT_REDERIVED",
            )
            removal = report["evidence"]["removal_tail_variance"]
            self.assertTrue(removal["full_ap_projection_equal"])
            statuses = removal["vacuous_target_statuses"]
            self.assertEqual(
                {
                    label: {
                        key: value[key]
                        for key in (
                            "classification",
                            "target_presentation",
                            "target_retention",
                            "target_validity",
                        )
                    }
                    for label, value in statuses.items()
                },
                {
                    "ABSENT": {
                        "classification": "REMOVAL_INAPPLICABLE",
                        "target_presentation": "ABSENT",
                        "target_retention": "NOT_RETAINED",
                        "target_validity": "ABSENT",
                    },
                    "NONE": {
                        "classification": "REMOVAL_INAPPLICABLE",
                        "target_presentation": "VISIBLE",
                        "target_retention": "RETAINED",
                        "target_validity": "VALIDATED",
                    },
                    "NOT_RETAINED": {
                        "classification": "REMOVAL_DEFERRED",
                        "target_presentation": "WITHHELD",
                        "target_retention": "NOT_RETAINED",
                        "target_validity": "VALIDATED",
                    },
                    "REQUIRED": {
                        "classification": "REMOVAL_INAPPLICABLE",
                        "target_presentation": "VISIBLE",
                        "target_retention": "RETAINED",
                        "target_validity": "VALIDATED",
                    },
                },
            )
            self.assertEqual(
                {
                    label: value["target_binding_status"]
                    for label, value in statuses.items()
                },
                {
                    "ABSENT": "UNOBSERVED",
                    "NONE": "BOUND",
                    "NOT_RETAINED": "BOUND",
                    "REQUIRED": "BOUND",
                },
            )
            self.assertEqual(statuses["ABSENT"]["target_descriptor"], None)
            self.assertEqual(statuses["NONE"]["target_descriptor"], ["NONE", 0])
            self.assertEqual(
                statuses["REQUIRED"]["target_descriptor"][:4],
                ["REQUIRED", 15, 7, 1],
            )
            self.assertEqual(
                statuses["NOT_RETAINED"]["target_descriptor"][:4],
                ["DETACHABLE", 4, 9, 0],
            )
            self.assertTrue(
                all(
                    len(value["target_reference"]) == 64
                    for value in statuses.values()
                )
            )
            expected_graph_references = {
                "4fd47b59542a39f2fd77d09f25b57030480b3c654286e50a79514313b8feb0e7",
                "5395d84d94565ced79b015e206eb9a0449e4959fb8af9ac3c17308c89236470a",
                "bd51a9583df6998963570886fe6354695c916989dd5e757dc3f2ccff0f9f2f27",
                "c6c86e3f6c98f62b32b40ef0d77aee48bb396b092753d505abd4659e54b76516",
            }
            for value in statuses.values():
                self.assertEqual(
                    {row["reference"] for row in value["graph_causality"]},
                    expected_graph_references,
                )
                self.assertTrue(
                    all(not row["parents"] for row in value["graph_causality"])
                )
            self.assertTrue(removal["retained_detachable_applied"])
            self.assertTrue(removal["retained_detachable_projection_equal"])
            self.assertTrue(removal["retained_detachable_differs_from_vacuous"])
            self.assertTrue(removal["retained_detachable_only_target_changed"])
            self.assertTrue(removal["k06_order_spanned"])
            self.assertTrue(removal["collapsed_identity_positive_detected"])
            self.assertTrue(removal["collapsed_identity_false_positive_rejected"])
            self.assertTrue(removal["pending_subtree_equal"])
            negative_controls = report["evidence"]["exhaustive_mutations"][
                "classifier_negative_controls"
            ]
            self.assertEqual(negative_controls["status"], "PASS")
            self.assertEqual(
                negative_controls["forbidden_dispositions_exercised"],
                ["IDENTITY_COLLISION", "NONCANONICAL_ACCEPTANCE"],
            )
            self.assertEqual(
                set(report["evidence"]["c03_model_record"]["blocks"]),
                {
                    "corpus",
                    "implementation_alignment",
                    "demo",
                    "product",
                    "sensitive_use",
                },
            )
            counters = report["evidence"]["aggregate_stage_counters"]
            self.assertTrue(all(value > 0 for value in counters.values()))

    def test_injected_digest_alias_is_a_blocking_finding(self) -> None:
        with self.assertRaisesRegex(ProbeError, "HASH_COLLISION_FINDING"):
            reject_digest_alias(b"distinct-a", b"distinct-b", bytes(32), bytes(32))


if __name__ == "__main__":
    unittest.main()
