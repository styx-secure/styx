from __future__ import annotations

from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[2]
O14 = ROOT.parent / "o14"
CORPUS = REPO / "conformance/application-protocol/c03"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(O14))

from canonical_json import dumps, load, loads  # noqa: E402
from corpus_model import (  # noqa: E402
    DOMAINS,
    ed25519_sign,
    ed25519_verify_detailed,
    evaluate_k_admission_graph,
    framed_hash,
    synthetic_octets,
)
from generate_corpus import _application_vector, _event_fields  # noqa: E402
from scenarios import required_witnesses  # noqa: E402


def _boundary_expected(code: str) -> tuple[bool, str, int]:
    if code == "ACCEPTED":
        return True, "GUARD_ACCEPTED", 1
    if code == "SIGNATURE_INVALID":
        return False, "GUARD_ACCEPTED", 1
    return False, code, 0


def _runtime_witnesses():
    return tuple(witness for witness in required_witnesses() if witness.runtime)


class H1BoundaryTests(unittest.TestCase):
    def test_python_matches_all_frozen_o14_boundary_vectors(self) -> None:
        witnesses = _runtime_witnesses()
        self.assertEqual(len(witnesses), 29)
        for witness in witnesses:
            with self.subTest(witness=witness.identifier):
                event = witness.event
                key = event.binding.verification_key if event.binding else b""
                observed = ed25519_verify_detailed(
                    key, event.signature, event.transcript
                )
                accepted, guard, equations = _boundary_expected(
                    witness.expected_code
                )
                self.assertEqual(
                    observed,
                    {
                        "accepted": accepted,
                        "equationInvocations": equations,
                        "guardCode": guard,
                    },
                )

    def test_javascript_independently_matches_python_boundary(self) -> None:
        records = []
        expected = []
        for witness in _runtime_witnesses():
            event = witness.event
            key = event.binding.verification_key if event.binding else b""
            records.append(
                {
                    "id": witness.identifier,
                    "messageHex": event.transcript.hex(),
                    "publicKeyHex": key.hex(),
                    "signatureHex": event.signature.hex(),
                }
            )
            expected.append(
                {
                    "id": witness.identifier,
                    **ed25519_verify_detailed(
                        key, event.signature, event.transcript
                    ),
                }
            )
        with tempfile.TemporaryDirectory(prefix="styx-c03-h1-") as tmp:
            input_path = Path(tmp) / "input.json"
            output_path = Path(tmp) / "output.json"
            input_path.write_bytes(
                dumps(
                    {
                        "records": records,
                        "schema": "styx-c03-h1-boundary-input/v1",
                    }
                )
            )
            completed = subprocess.run(
                [
                    "node",
                    str(ROOT / "node_adapter.mjs"),
                    "--h1-input",
                    str(input_path),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            observed = loads(output_path.read_bytes())
            self.assertEqual(observed["observations"], expected)


class H2AdmissionOrderTests(unittest.TestCase):
    def setUp(self) -> None:
        hostiles = load(CORPUS / "adversarial-mutations.json")[
            "kAdmissionScenarios"
        ]
        self.pending = deepcopy(
            next(
                row
                for row in hostiles
                if row["id"]
                == "k-hostile-required-opening-and-pending-ancestor"
            )
        )

    @staticmethod
    def _resign(record: dict, seed_label: str) -> dict:
        value = deepcopy(record)
        transcript = bytes.fromhex(value["transcriptHex"])
        public, signature = ed25519_sign(
            synthetic_octets(seed_label, 32), transcript
        )
        value["binding"]["verificationKeyHex"] = public.hex()
        value["signatureHex"] = signature.hex()
        return value

    def _root_event(self, identifier: str, *, parents=()) -> dict:
        genesis = self.pending["acceptedGenesisRecord"]
        predecessor = self.pending["records"][0]["eventReferenceHex"]
        return _application_vector(
            identifier,
            _event_fields(
                identifier,
                sequence=1 if parents else 0,
                predecessor=predecessor if parents else None,
                parents=list(parents),
                credential=bytes.fromhex(genesis["genesisReferenceHex"]),
                context=bytes.fromhex(
                    genesis["fields"]["contextIdentifierHex"]
                ),
                genesis_reference=bytes.fromhex(
                    genesis["genesisReferenceHex"]
                ),
            ),
            "k-linear/root",
        )

    def test_pending_dependency_does_not_hide_invalid_signature(self) -> None:
        genesis = self.pending["acceptedGenesisRecord"]
        pending, descendant = deepcopy(self.pending["records"])
        signature = bytearray.fromhex(descendant["signatureHex"])
        signature[-1] ^= 1
        descendant["signatureHex"] = bytes(signature).hex()
        observed = {
            row["id"]: row
            for row in evaluate_k_admission_graph(
                genesis, [pending, descendant]
            )
        }
        self.assertEqual(
            observed[pending["id"]]["protocolErrorCode"], "PENDING_OPENING"
        )
        self.assertEqual(
            (
                observed[descendant["id"]]["protocolErrorCode"],
                observed[descendant["id"]]["stage"],
            ),
            ("INVALID", "S3_KERNEL_STRUCTURAL"),
        )

    def test_pending_and_ready_siblings_form_one_complete_fork(self) -> None:
        genesis = self.pending["acceptedGenesisRecord"]
        pending = deepcopy(self.pending["records"][0])
        sibling = self._root_event("package-a-ready-sibling")
        observations = evaluate_k_admission_graph(genesis, [pending, sibling])
        self.assertEqual(
            {
                (row["kBindingAdmission"], row["protocolErrorCode"], row["stage"])
                for row in observations
            },
            {("ADMITTED", "FORK_EVIDENCE", "EVENT_LOCAL")},
        )

    def test_pending_plus_absent_dependency_fails_at_s4(self) -> None:
        genesis = self.pending["acceptedGenesisRecord"]
        pending = deepcopy(self.pending["records"][0])
        descendant = self._root_event(
            "package-a-pending-plus-absent",
            parents=("ab" * 32,),
        )
        observed = {
            row["id"]: row
            for row in evaluate_k_admission_graph(
                genesis, [pending, descendant]
            )
        }
        self.assertEqual(
            (
                observed[descendant["id"]]["kBindingAdmission"],
                observed[descendant["id"]]["protocolErrorCode"],
                observed[descendant["id"]]["stage"],
            ),
            ("REJECTED", "DEPENDENCY_DEFERRED", "S4_GRAPH_ADMISSION"),
        )

    def test_graph_results_match_javascript_for_hostile_rows(self) -> None:
        genesis = self.pending["acceptedGenesisRecord"]
        pending, descendant = deepcopy(self.pending["records"])
        signature = bytearray.fromhex(descendant["signatureHex"])
        signature[-1] ^= 1
        descendant["signatureHex"] = bytes(signature).hex()
        sibling = self._root_event("package-a-ready-sibling-js")
        scenarios = [
            {
                "acceptedGenesisRecord": genesis,
                "graphEvaluation": True,
                "id": "pending-invalid",
                "records": [pending, descendant],
            },
            {
                "acceptedGenesisRecord": genesis,
                "graphEvaluation": True,
                "id": "pending-fork",
                "records": [pending, sibling],
            },
        ]
        expected = [
            {
                "id": scenario["id"],
                "observations": evaluate_k_admission_graph(
                    genesis, scenario["records"]
                ),
            }
            for scenario in scenarios
        ]
        with tempfile.TemporaryDirectory(prefix="styx-c03-h2-") as tmp:
            input_path = Path(tmp) / "input.json"
            output_path = Path(tmp) / "output.json"
            input_path.write_bytes(dumps({"scenarios": scenarios}))
            completed = subprocess.run(
                [
                    "node",
                    str(ROOT / "node_adapter.mjs"),
                    "--k-scenario-input",
                    str(input_path),
                    "--output",
                    str(output_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                loads(output_path.read_bytes()),
                {"observations": expected, "result": "PASS"},
            )


if __name__ == "__main__":
    unittest.main()
