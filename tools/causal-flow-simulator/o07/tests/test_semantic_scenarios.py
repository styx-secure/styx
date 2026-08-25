from __future__ import annotations

from pathlib import Path
import sys
import unittest
from unittest.mock import patch


O07_ROOT = Path(__file__).resolve().parents[1]
if str(O07_ROOT) not in sys.path:
    sys.path.insert(0, str(O07_ROOT))

from inventory import validate_inventory  # noqa: E402
from test_helpers import scenario_engine  # noqa: E402
from test_helpers.scenario_engine import evaluate_semantic_scenario  # noqa: E402


class SemanticScenarioTest(unittest.TestCase):
    def test_every_semantic_atom_executes_without_skip_or_alias(self) -> None:
        inventory = validate_inventory()
        outputs = []
        for entry in inventory.semantic_entries:
            result = evaluate_semantic_scenario(entry["atom_instance_id"])
            self.assertEqual(
                result["disposition"],
                entry["expected_disposition"],
                entry["atom_instance_id"],
            )
            self.assertTrue(result["observation"], entry["atom_instance_id"])
            outputs.append(
                (
                    entry["atom_instance_id"],
                    entry["scenario_instance_id"],
                    entry["assertion_id"],
                    entry["observation_id"],
                )
            )
        self.assertEqual(len(outputs), 229)
        self.assertEqual(len(outputs), len(set(outputs)))

    def test_grant_collision_atoms_execute_distinct_real_setups(self) -> None:
        fixture = scenario_engine.fixture()
        transcripts = []
        original = scenario_engine.derive_event_reference

        def recording_derivation(transcript: bytes) -> bytes:
            transcripts.append(transcript)
            return original(transcript)

        with patch.object(
            scenario_engine,
            "derive_event_reference",
            side_effect=recording_derivation,
        ):
            for atom in ("A-LIN-007", "A-LIN-008", "A-LIN-009"):
                result = evaluate_semantic_scenario(atom)
                self.assertEqual(result["disposition"], "REJECT")
                self.assertEqual(
                    result["observation"],
                    "GRANT_REFERENCE_EQUALS_GENESIS_CREDENTIAL",
                )

        self.assertEqual(len(transcripts), 3)
        self.assertEqual(len(set(transcripts)), 3)
        self.assertNotIn(fixture.candidate.transcript, transcripts)
        self.assertNotIn(fixture.reference, (original(item) for item in transcripts))

        distinct_transcripts = set(transcripts)
        transcripts.clear()
        with patch.object(
            scenario_engine,
            "derive_event_reference",
            side_effect=recording_derivation,
        ):
            result = evaluate_semantic_scenario("A-LIN-023")
        self.assertEqual(result["disposition"], "REJECT")
        self.assertEqual(len(transcripts), 3)
        self.assertEqual(set(transcripts), distinct_transcripts)


if __name__ == "__main__":
    unittest.main()
