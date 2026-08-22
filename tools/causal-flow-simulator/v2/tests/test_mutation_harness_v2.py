from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

V2_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(V2_ROOT))

from mutation_harness_v2 import (  # noqa: E402
    MUTANTS,
    REQUIRED_MUTANT_IDS,
    Mutant,
    assertion_registry_violations,
    build_report,
    canonical_bytes,
    main,
    validate_registry,
)


class MutationHarnessTests(unittest.TestCase):
    def test_required_registry_is_exact(self) -> None:
        self.assertEqual({mutant.identifier for mutant in MUTANTS}, REQUIRED_MUTANT_IDS)
        self.assertEqual(validate_registry(), ())

    def test_registry_rejects_missing_and_unknown_mutants(self) -> None:
        self.assertTrue(any(item.startswith("MISSING_REQUIRED:") for item in validate_registry(MUTANTS[:-1])))
        unknown = Mutant("UNKNOWN", "x", "before", "after", "required-suite")
        failures = validate_registry(MUTANTS + (unknown,))
        self.assertTrue(any(item.startswith("UNKNOWN_MUTANT:") for item in failures))

    def test_assertion_registry_matches_clean_source(self) -> None:
        self.assertEqual(assertion_registry_violations(V2_ROOT / "scenarios_v2.py"), ())

    def test_every_required_mutant_is_killed_deterministically(self) -> None:
        report, passed = build_report()
        self.assertTrue(passed)
        self.assertTrue(report["deterministic"])
        self.assertEqual(report["verdict"], "ALL_REQUIRED_MUTANTS_KILLED")
        self.assertEqual(
            {item["id"] for item in report["results"] if item["killed"]},
            REQUIRED_MUTANT_IDS,
        )
        self.assertTrue(all(item["deterministic"] for item in report["results"]))

    def test_canonical_output_is_stable_and_cli_repeats_it(self) -> None:
        report, _ = build_report()
        self.assertEqual(json.loads(canonical_bytes(report)), report)
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.json"
            second = Path(directory) / "second.json"
            self.assertEqual(main(["--suite", "required", "--output", str(first)]), 0)
            self.assertEqual(main(["--suite", "required", "--output", str(second)]), 0)
            self.assertEqual(first.read_bytes(), second.read_bytes())


if __name__ == "__main__":
    unittest.main()
