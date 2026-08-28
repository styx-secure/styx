from __future__ import annotations

from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
CORPUS = REPO / "conformance/application-protocol/c03"
sys.path.insert(0, str(ROOT))

from canonical_json import load  # noqa: E402
from run_mutations import run  # noqa: E402


class MutationTests(unittest.TestCase):
    def test_both_runtimes_kill_closed_registry(self) -> None:
        report = run(REPO, CORPUS)
        self.assertEqual(report["result"], "PASS")
        self.assertEqual(report["killed"], 513)
        self.assertEqual(report["runtimes"], ["javascript", "python"])
        self.assertRegex(report["killDigest"], r"^[0-9a-f]{64}$")

    def test_registry_has_every_required_detector_family(self) -> None:
        records = load(CORPUS / "adversarial-mutations.json")["records"]
        counts: dict[str, int] = {}
        for record in records:
            counts[record["detector"]] = counts.get(record["detector"], 0) + 1
        self.assertEqual(counts["O07_EXACT_RELATION_SET"], 287)
        self.assertEqual(counts["O08_EXACT_DIMENSION_SET"], 53)
        self.assertEqual(counts["O10_EXACT_SOURCE_ROW_SET"], 102)
        self.assertEqual(counts["MANIFEST_DIGEST_MISMATCH"], 5)
        self.assertEqual(counts["INDEPENDENT_REPLAY_EXPECTATION_MISMATCH"], 27)
        self.assertEqual(counts["INDEPENDENT_EXPECTED_STAGE_MISMATCH"], 1)
        self.assertEqual(counts["INDEPENDENT_EXPECTED_OUTCOME_MISMATCH"], 1)
        self.assertEqual(counts["INDEPENDENT_EXPECTED_TRACE_MISMATCH"], 1)
        self.assertEqual(counts["INDEPENDENT_EXPECTED_DEPENDENCY_STATUS_MISMATCH"], 1)
        self.assertEqual(counts["INVARIANT_WITNESS_TRACE_MISMATCH"], 21)
        self.assertEqual(counts["SOURCE_O10_CLASS_MEMBERSHIP"], 1)
        self.assertEqual(counts["SOURCE_O10_APPLICABILITY"], 1)
        self.assertEqual(counts["SOURCE_O10_PRECEDENCE"], 1)
        self.assertEqual(counts["SOURCE_CHECKPOINT_BEFORE_PROTECTED_WORK"], 1)
        self.assertEqual(counts["SOURCE_GEOMETRY_PREDICATE"], 7)
        self.assertEqual(counts["SOURCE_R6_CLASSIFICATION"], 1)
        self.assertEqual(counts["SOURCE_R5_LAYERING"], 1)
        self.assertEqual(counts["SOURCE_FORK_DESCENDANT_GRAPH_RETENTION"], 1)
        identifiers = [record["id"] for record in records]
        self.assertEqual(identifiers, sorted(set(identifiers)))
        semantic = [record for record in records if record.get("mutationClass") == "SEMANTIC_INVARIANT"]
        self.assertEqual(len(semantic), 21)
        self.assertEqual(len({record["violatedInvariant"] for record in semantic}), 21)
        self.assertEqual(len({record["sourceRecordId"] for record in semantic}), 21)
        anchored = [
            record
            for record in records
            if record.get("mutationClass") == "SOURCE_ANCHORED_SECURITY"
        ]
        self.assertEqual(len(anchored), 14)
        self.assertTrue(
            all(
                record.get("sourcePath")
                and record.get("sourceAnchor")
                and record.get("sourceRowIds")
                for record in anchored
            )
        )


if __name__ == "__main__":
    unittest.main()
