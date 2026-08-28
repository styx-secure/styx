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
        self.assertEqual(report["killed"], 466)
        self.assertEqual(report["runtimes"], ["javascript", "python"])
        self.assertRegex(report["killDigest"], r"^[0-9a-f]{64}$")

    def test_registry_has_every_required_detector_family(self) -> None:
        records = load(CORPUS / "adversarial-mutations.json")["records"]
        counts: dict[str, int] = {}
        for record in records:
            counts[record["detector"]] = counts.get(record["detector"], 0) + 1
        self.assertEqual(counts["O07_EXACT_RELATION_SET"], 287)
        self.assertEqual(counts["O08_SELECTED_BOUND_CHECK"], 53)
        self.assertEqual(counts["O10_EXACT_SOURCE_ROW_SET"], 102)
        self.assertEqual(counts["MANIFEST_DIGEST_MISMATCH"], 5)
        self.assertEqual(counts["INDEPENDENT_REPLAY_EXPECTATION_MISMATCH"], 16)
        self.assertEqual(counts["INDEPENDENT_EXPECTED_STAGE_MISMATCH"], 1)
        self.assertEqual(counts["INDEPENDENT_EXPECTED_OUTCOME_MISMATCH"], 1)
        self.assertEqual(counts["INDEPENDENT_EXPECTED_TRACE_MISMATCH"], 1)
        identifiers = [record["id"] for record in records]
        self.assertEqual(identifiers, sorted(set(identifiers)))


if __name__ == "__main__":
    unittest.main()
