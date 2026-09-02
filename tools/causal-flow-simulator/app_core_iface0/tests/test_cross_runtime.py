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

    def test_independent_javascript_graph_projection_is_greedy_and_pending_exact(self) -> None:
        parent = "22" * 32
        newly_ready = "11" * 32
        concurrent = "33" * 32
        fork_left = "44" * 32
        fork_right = "55" * 32
        root = "66" * 32
        fork_actor = "77" * 32
        value = {
            "events": [
                {"reference": parent, "credential": root, "sequence": 0, "dependencies": []},
                {"reference": newly_ready, "credential": root, "sequence": 1, "dependencies": [parent]},
                {"reference": concurrent, "credential": "88" * 32, "sequence": 0, "dependencies": []},
                {"reference": fork_left, "credential": fork_actor, "sequence": 7, "dependencies": []},
                {"reference": fork_right, "credential": fork_actor, "sequence": 7, "dependencies": []},
            ],
            "unverifiedRequiredReferences": [parent],
        }
        completed = subprocess.run(
            [
                "node",
                str(ROOT / "node_adapter.mjs"),
                "--graph-projection",
                "--contract",
                str(ROOT / "contract"),
            ],
            input=json.dumps(value),
            text=True,
            capture_output=True,
            check=True,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(
            result["protocolKOrder"],
            [parent, newly_ready, concurrent, fork_left, fork_right],
        )
        self.assertEqual(result["pendingRootReferences"], [parent])
        self.assertEqual(result["pendingReferences"], [newly_ready])
        self.assertEqual(
            result["forks"],
            [
                {
                    "credential": fork_actor,
                    "sequence": 7,
                    "siblings": [fork_left, fork_right],
                }
            ],
        )
        ancestors = {
            row["reference"]: row["ancestors"] for row in result["ancestors"]
        }
        self.assertEqual(ancestors[newly_ready], [parent])
        self.assertEqual(ancestors[concurrent], [])

    def test_independent_javascript_credential_projection_is_grant_rooted(self) -> None:
        root = "11" * 32
        first = "22" * 32
        child = "33" * 32
        shared_key = "aa" * 32
        child_key = "bb" * 32
        command = [
            "node",
            str(ROOT / "node_adapter.mjs"),
            "--credential-projection",
            "--contract",
            str(ROOT / "contract"),
        ]
        value = {
            "root": {
                "credentialIdentifierHex": root,
                "signatureSuiteId": "1",
                "verificationKeyHex": shared_key,
            },
            # The dependent grant appears first: input order is not authority.
            "grants": [
                {
                    "reference": child,
                    "issuerCredentialIdentifierHex": first,
                    "verificationKeyHex": child_key,
                },
                {
                    "reference": first,
                    "issuerCredentialIdentifierHex": root,
                    "verificationKeyHex": shared_key,
                },
            ],
        }
        completed = subprocess.run(
            command,
            input=json.dumps(value),
            text=True,
            capture_output=True,
            check=True,
        )
        result = json.loads(completed.stdout)
        self.assertEqual(result["aliasGroups"], [[root, first]])
        self.assertEqual(
            [row["credentialIdentifierHex"] for row in result["credentialBindings"]],
            [root, first, child],
        )
        self.assertEqual(
            result["credentialBindings"][2]["issuerCredentialIdentifierHex"],
            first,
        )

        unbound = json.loads(json.dumps(value))
        unbound["grants"][1]["issuerCredentialIdentifierHex"] = "ff" * 32
        rejected = subprocess.run(
            command,
            input=json.dumps(unbound),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("no issuer binding", rejected.stderr)

    def test_independent_javascript_rejects_reserved_f13_before_release(self) -> None:
        command = [
            "node",
            str(ROOT / "node_adapter.mjs"),
            "--validate-response",
            "--contract",
            str(ROOT / "contract"),
        ]
        profile = {
            "applicationProfileId": "1",
            "applicationProfileVersion": "1",
            "styxProtocolVersion": "1",
        }

        reachable = {
            "interfaceVersion": "0",
            "operation": "EVALUATE_CANDIDATE",
            "profile": profile,
            "result": {
                "evaluation": {
                    "kind": "TERMINAL_NO_SUCCESSOR",
                    "primary": "DUPLICATE",
                    "stage": "S3_KERNEL_STRUCTURAL",
                }
            },
        }
        accepted = subprocess.run(
            command,
            input=json.dumps(reachable),
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(json.loads(accepted.stdout), {"verdict": "PASS"})

        reserved = json.loads(json.dumps(reachable))
        reserved["result"]["evaluation"]["primary"] = "LENGTH_MISMATCH"
        rejected = subprocess.run(
            command,
            input=json.dumps(reserved),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("reserved F13", rejected.stderr)


if __name__ == "__main__":
    unittest.main()
