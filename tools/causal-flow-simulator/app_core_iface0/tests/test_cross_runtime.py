from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from generate_seed_registry import prove_reachability  # noqa: E402
from authority_witness import isolated_authority_states_witness  # noqa: E402


class SeedReachabilityTests(unittest.TestCase):
    def test_every_ratified_object_and_union_arm_has_a_valid_carrier(self) -> None:
        self.assertEqual(
            prove_reachability(ROOT / "contract"),
            {"object_schema_count": 78, "one_of_arm_count": 54},
        )

    def test_independent_javascript_fork_join_label_matches_v9_vector(self) -> None:
        witness = {
            "credentialIdentifierHex": "11" * 32,
            "authorSequence": "7",
            "siblingReferences": ["22" * 32, "33" * 32],
        }
        command = [
            "node",
            str(ROOT / "node_adapter.mjs"),
            "--derive-fork-join",
            "--contract",
            str(ROOT / "contract"),
        ]
        completed = subprocess.run(
            command,
            input=json.dumps(witness),
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(
            json.loads(completed.stdout),
            {
                "joinLabelHex": "6c0e9469f72779ab48f96a90a76f088c23ec88674a3290a19baef8418c49c073"
            },
        )

        noncanonical = dict(witness)
        noncanonical["siblingReferences"] = list(
            reversed(witness["siblingReferences"])
        )
        rejected = subprocess.run(
            command,
            input=json.dumps(noncanonical),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("not bytewise canonical", rejected.stderr)

    def test_independent_javascript_authority_witness_matches_v9_metrics(self) -> None:
        command = [
            "node",
            str(ROOT / "node_adapter.mjs"),
            "--authority-metrics",
            "--contract",
            str(ROOT / "contract"),
        ]
        unbounded = subprocess.run(
            command,
            input=json.dumps(
                isolated_authority_states_witness(
                    state_limit=1000, transition_limit=1000
                )
            ),
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(
            json.loads(unbounded.stdout),
            {
                "kind": "AVAILABLE",
                "maxConcurrentControls": 3,
                "ordinaryPrefixQueryMax": 9,
                "reachableStateCount": 273,
                "replayedEventWork": 1199,
                "transitionCount": 500,
            },
        )
        protected = subprocess.run(
            command,
            input=json.dumps(
                isolated_authority_states_witness(
                    state_limit=256, transition_limit=512
                )
            ),
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(
            json.loads(protected.stdout),
            {"kind": "UNAVAILABLE", "reason": "AUTHORITY_STATES"},
        )


if __name__ == "__main__":
    unittest.main()
