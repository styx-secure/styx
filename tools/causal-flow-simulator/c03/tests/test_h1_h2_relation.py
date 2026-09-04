from __future__ import annotations

from copy import deepcopy
import os
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
    ProtocolError,
    ed25519_sign,
    ed25519_verify_detailed,
    evaluate_k_admission_graph,
    framed_hash,
    synthetic_octets,
)
from generate_corpus import _application_vector, _event_fields  # noqa: E402
from h1_h2_relation import (  # noqa: E402
    MUTANTS,
    RelationError,
    TEP_FILENAMES,
    _clean_checkout,
    _closed_environment,
    _manifest_bytes,
    _resolve_toolchain,
    _validate_candidate_set_wrapper_identities,
    _validate_jsonl,
    _verify_tep_structure,
    run_runtime,
    slot_cases,
    validate_relation,
)
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
    def test_literal_relation_is_closed(self) -> None:
        validate_relation()

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

    def test_literal_slot_relation_exercises_both_lexical_schedules(self) -> None:
        schedules = {
            case["lexicalSchedule"]
            for case in slot_cases()
            if case["lexicalSchedule"] != "NOT_APPLICABLE"
        }
        self.assertEqual(schedules, {"LEFT_LT_RIGHT", "LEFT_GT_RIGHT"})

    def test_complete_relation_is_byte_equivalent_across_runtimes(self) -> None:
        self.assertEqual(run_runtime("python"), run_runtime("javascript"))

    def test_valid_aliases_authenticate_independently_and_commit_once(self) -> None:
        case = slot_cases()[62]
        rows = evaluate_k_admission_graph(
            case["genesis"], case["records"], presentation_evidence=True
        )
        targets = [row for row in rows if row["id"] in case["targets"]]
        aliases = [row for row in targets if row["id"].endswith(("-V", "-A"))]
        self.assertEqual(len(aliases), 2)
        self.assertEqual(
            {
                (
                    row["kBindingAdmission"],
                    row["coalescedPresentationCount"],
                    row["logicalEventEffectCount"],
                )
                for row in aliases
            },
            {("ADMITTED", 2, 1)},
        )
        self.assertEqual(
            {row["eventReferenceHex"] for row in aliases},
            {aliases[0]["logicalEventReferenceHex"]},
        )

    def test_invalid_alias_and_opening_cannot_poison_or_supply(self) -> None:
        for index, rejected_code, surviving_code in (
            (68, "INVALID", None),
            (80, "COMMITMENT_MISMATCH", None),
            (88, "INVALID", "PENDING_OPENING"),
            (94, "COMMITMENT_MISMATCH", "PENDING_OPENING"),
        ):
            with self.subTest(row=index + 1):
                case = slot_cases()[index]
                rows = evaluate_k_admission_graph(
                    case["genesis"],
                    case["records"],
                    presentation_evidence=True,
                )
                targets = [row for row in rows if row["id"] in case["targets"]]
                rejected = next(
                    row for row in targets if row["protocolErrorCode"] == rejected_code
                )
                self.assertEqual(
                    (
                        rejected["kBindingAdmission"],
                        rejected["coalescedPresentationCount"],
                        rejected["logicalEventEffectCount"],
                    ),
                    ("REJECTED", 0, 0),
                )
                survivor = next(
                    row
                    for row in targets
                    if row["eventReferenceHex"] == rejected["eventReferenceHex"]
                    and row["id"] != rejected["id"]
                )
                self.assertEqual(survivor["protocolErrorCode"], surviving_code)
                self.assertEqual(survivor["logicalEventEffectCount"], 1)

    def test_conflicting_stable_identifier_fails_before_graph_processing(self) -> None:
        case = slot_cases()[62]
        first = deepcopy(case["records"][-3])
        conflicting = deepcopy(case["records"][-2])
        conflicting["id"] = first["id"]
        with self.assertRaisesRegex(ProtocolError, "STRUCTURAL_REJECTION"):
            evaluate_k_admission_graph(case["genesis"], [first, conflicting])

    def test_relation_wrapper_identity_guard_is_bidirectional_and_local(self) -> None:
        case = slot_cases()[62]
        first = deepcopy(case["records"][-3])
        second = deepcopy(case["records"][-2])

        _validate_candidate_set_wrapper_identities(
            case["genesis"], case["records"]
        )
        _validate_candidate_set_wrapper_identities(
            case["genesis"], [first, deepcopy(first)]
        )

        different_wrapper_same_id = deepcopy(second)
        different_wrapper_same_id["id"] = first["id"]
        with self.assertRaisesRegex(
            RelationError, "stable ID names different wrapper bytes"
        ):
            _validate_candidate_set_wrapper_identities(
                case["genesis"], [first, different_wrapper_same_id]
            )

        identical_wrapper_different_id = deepcopy(first)
        identical_wrapper_different_id["id"] = f"{first['id']}-clone"
        with self.assertRaisesRegex(
            RelationError, "byte-identical wrappers use different stable IDs"
        ):
            _validate_candidate_set_wrapper_identities(
                case["genesis"], [first, identical_wrapper_different_id]
            )

    def test_private_collision_rows_do_not_claim_admission_or_effect(self) -> None:
        for case in slot_cases()[86:88]:
            with self.subTest(row=case["row"].row_id):
                from h1_h2_relation import _project_slot_case

                projected = _project_slot_case(case)
                self.assertEqual(
                    {row["classification"] for row in projected["observations"]},
                    {"REFERENCE_COLLISION_UNSUPPORTED", "UNIQUE"},
                )
                self.assertTrue(
                    all(
                        "logicalEventEffectCount" not in row
                        and "kBindingAdmission" not in row
                        for row in projected["observations"]
                    )
                )


class FinalGateGitIdentityTests(unittest.TestCase):
    def test_replace_ref_cannot_make_an_old_tree_look_clean(self) -> None:
        with tempfile.TemporaryDirectory(prefix="styx-c03-replace-ref-") as tmp:
            repo = Path(tmp) / "repo"
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "config", "user.name", "Styx test"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(repo), "config", "user.email", "test@invalid"],
                check=True,
            )
            tracked = repo / "tracked.txt"
            tracked.write_text("base\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "add", "tracked.txt"], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-qm", "base"], check=True
            )
            base = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
            ).strip()
            tracked.write_text("candidate\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(repo), "commit", "-qam", "candidate"], check=True)
            candidate = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
            ).strip()
            attacker_environment = dict(os.environ)
            attacker_environment.pop("GIT_NO_REPLACE_OBJECTS", None)
            subprocess.run(
                ["git", "-C", str(repo), "replace", candidate, base],
                check=True,
                env=attacker_environment,
            )
            subprocess.run(
                ["git", "-C", str(repo), "reset", "--hard", "-q", candidate],
                check=True,
                env=attacker_environment,
            )
            self.assertEqual(
                subprocess.check_output(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "status",
                        "--porcelain=v1",
                        "--untracked-files=all",
                        "--ignored=matching",
                    ],
                    env=attacker_environment,
                    text=True,
                ),
                "",
            )
            with self.assertRaisesRegex(
                RelationError, "tracked checkout bytes mismatch"
            ):
                _clean_checkout(repo, candidate)

    def test_assume_unchanged_cannot_hide_modified_source_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="styx-c03-assume-unchanged-") as tmp:
            repo = Path(tmp) / "repo"
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            for key, value in (
                ("user.name", "Styx test"),
                ("user.email", "test@invalid"),
            ):
                subprocess.run(
                    ["git", "-C", str(repo), "config", key, value], check=True
                )
            tracked = repo / "tracked.txt"
            tracked.write_text("expected\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(repo), "add", "tracked.txt"], check=True
            )
            subprocess.run(
                ["git", "-C", str(repo), "commit", "-qm", "candidate"],
                check=True,
            )
            candidate = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
            ).strip()
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(repo),
                    "update-index",
                    "--assume-unchanged",
                    "tracked.txt",
                ],
                check=True,
            )
            tracked.write_text("malicious\n", encoding="utf-8")
            self.assertEqual(
                subprocess.check_output(
                    ["git", "-C", str(repo), "status", "--porcelain=v1"],
                    text=True,
                ),
                "",
            )
            with self.assertRaisesRegex(
                RelationError, "tracked checkout bytes mismatch"
            ):
                _clean_checkout(repo, candidate)

    def test_git_dir_environment_cannot_redirect_checkout_identity(self) -> None:
        with tempfile.TemporaryDirectory(prefix="styx-c03-git-env-") as tmp:
            repo = Path(tmp) / "repo"
            other = Path(tmp) / "other"
            for path, content in ((repo, "expected\n"), (other, "other\n")):
                subprocess.run(["git", "init", "-q", str(path)], check=True)
                subprocess.run(
                    ["git", "-C", str(path), "config", "user.name", "Styx test"],
                    check=True,
                )
                subprocess.run(
                    ["git", "-C", str(path), "config", "user.email", "test@invalid"],
                    check=True,
                )
                (path / "tracked.txt").write_text(content, encoding="utf-8")
                subprocess.run(["git", "-C", str(path), "add", "tracked.txt"], check=True)
                subprocess.run(
                    ["git", "-C", str(path), "commit", "-qm", "initial"], check=True
                )
            candidate = subprocess.check_output(
                ["git", "-C", str(repo), "rev-parse", "HEAD"], text=True
            ).strip()
            previous = os.environ.get("GIT_DIR")
            os.environ["GIT_DIR"] = str(other / ".git")
            try:
                _clean_checkout(repo, candidate)
            finally:
                if previous is None:
                    os.environ.pop("GIT_DIR", None)
                else:
                    os.environ["GIT_DIR"] = previous


class TechnicalEvidencePackageTests(unittest.TestCase):
    def test_closed_environment_contains_only_ratified_keys(self) -> None:
        tools, versions = _resolve_toolchain()
        self.assertEqual(len(versions.splitlines()), 5)
        with tempfile.TemporaryDirectory(prefix="styx-c03-env-test-") as tmp:
            environment = _closed_environment(tools, Path(tmp) / "environment")
            self.assertEqual(
                set(environment),
                {
                    "GIT_CONFIG_GLOBAL",
                    "GIT_CONFIG_NOSYSTEM",
                    "GIT_NO_REPLACE_OBJECTS",
                    "HOME",
                    "LANG",
                    "LC_ALL",
                    "PATH",
                    "PYTHONDONTWRITEBYTECODE",
                    "TMPDIR",
                    "TZ",
                },
            )
            self.assertNotIn("PYTHONPATH", environment)
            self.assertNotIn("PYTHONOPTIMIZE", environment)
            self.assertNotIn("NODE_OPTIONS", environment)

    def test_mutation_ledger_requires_exact_order_and_zero_exit(self) -> None:
        rows = [
            {
                "argv": ["python3", "detector.py", mutant],
                "checkoutRole": "CHECKOUT_1",
                "commandId": mutant,
                "exitStatus": 0,
                "stderrUtf8": "",
                "stdoutUtf8": "PASS\n",
            }
            for mutant in MUTANTS
        ]
        payload = b"".join(dumps(row) for row in rows)
        self.assertEqual(
            len(
                _validate_jsonl(
                    payload,
                    expected_ids=MUTANTS,
                    checkout_role="CHECKOUT_1",
                )
            ),
            24,
        )
        rows[-1]["exitStatus"] = 2
        with self.assertRaisesRegex(RelationError, "command-ledger row"):
            _validate_jsonl(
                b"".join(dumps(row) for row in rows),
                expected_ids=MUTANTS,
                checkout_role="CHECKOUT_1",
            )

    def test_flat_package_schema_and_manifest_are_exact(self) -> None:
        with tempfile.TemporaryDirectory(prefix="styx-c03-tep-test-") as tmp:
            package = Path(tmp) / "package"
            package.mkdir()
            for name in TEP_FILENAMES:
                if name not in {"PACKAGE_SCHEMA.txt", "SHA256SUMS.txt"}:
                    (package / name).write_bytes(f"fixture:{name}\n".encode())
            (package / "PACKAGE_SCHEMA.txt").write_bytes(
                "".join(f"{name}\n" for name in TEP_FILENAMES).encode("ascii")
            )
            (package / "SHA256SUMS.txt").write_bytes(_manifest_bytes(package))
            self.assertEqual(len(_verify_tep_structure(package)), 34)
            (package / "UNLISTED").write_text("no\n", encoding="utf-8")
            with self.assertRaisesRegex(RelationError, "artifact set"):
                _verify_tep_structure(package)

    def test_flat_package_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="styx-c03-tep-link-") as tmp:
            package = Path(tmp) / "package"
            package.mkdir()
            target = package / "target"
            target.write_text("target\n", encoding="utf-8")
            (package / "alias").symlink_to(target)
            with self.assertRaisesRegex(RelationError, "invalid package artifact"):
                _verify_tep_structure(package)


if __name__ == "__main__":
    unittest.main()
