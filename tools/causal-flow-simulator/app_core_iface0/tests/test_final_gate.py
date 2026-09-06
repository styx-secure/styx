from __future__ import annotations

import json
import hashlib
import base64
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from email.message import Message
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from final_gate import (  # noqa: E402
    ACV049_MUTANT_CHANNEL,
    ACV049_PYTHON_RUNTIME_MONITOR,
    COMBINED_BRANCH_REF,
    COMBINED_BRANCH_URL,
    FinalGateError,
    RATIFIED_CARRIER_AUTHORITY_V3_SHA256,
    _aggregate_acv049_runtime_rows,
    _carrier_subtree,
    _controlled_acv049_environment,
    _decode_acv049_runtime_log,
    _fetch_json,
    _generate_phase_a_from_checkout,
    _historical_carrier_bytes,
    _verify_exact_carrier_bytes,
    _next_link,
    _local_source_blobs,
    _frozen_semantic_fixture_slice,
    _scan_acv049_javascript_source,
    _scan_acv049_python_source,
    _scan_provider_authority,
    _run_acv049_runtime_negative_controls,
    _successful_exec_count,
    _tree,
    _validate_acv049_e_report,
    _validate_provider_authority,
    _verify_provider_source_slice,
    _verify_runtime_semantic_fixture,
    _verify_clean_checkout,
    run_acv049_static_provenance_scan,
    run_acv049_e_baseline_gate,
    run_phase_a_gate,
)
from canonical_json import dumps  # noqa: E402
from inventory import BASE_SHA  # noqa: E402


class _Response:
    def __init__(self, url: str, value: object) -> None:
        self.status = 200
        self._url = url
        self._raw = json.dumps(value).encode("utf-8")
        self.headers = Message()

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def geturl(self) -> str:
        return self._url

    def read(self) -> bytes:
        return self._raw


class _Opener:
    def __init__(self, response: _Response) -> None:
        self.response = response

    def open(self, _request: object, timeout: int) -> _Response:
        if timeout != 30:
            raise AssertionError("provider timeout drift")
        return self.response


def _acv049_semantic_report() -> dict[str, object]:
    counts = {
        "ACV-049-E": 77,
        "ACV-049-L": 401,
        "ACV-049-N": 5,
        "ACV-049-P": 300,
        "ACV-049-S": 101,
    }
    rows: list[dict[str, object]] = []
    for relation_id, count in counts.items():
        for index in range(count):
            source = (
                f"PCR-REQUEST-X-{index:04d}"
                if relation_id == "ACV-049-E"
                else f"{relation_id}-SOURCE-{index:04d}"
            )
            row: dict[str, object] = {
                "relationId": relation_id,
                "sourceIdentity": source,
            }
            if relation_id == "ACV-049-E":
                row.update(
                    {
                        "assertionId": f"ASSERT-{index:04d}",
                        "detectorId": f"DETECT-{index:04d}",
                        "evidenceDisposition": (
                            "LOCAL_BLIND_EXECUTION_PASS_TWO_ENVIRONMENT_PENDING"
                        ),
                        "executionPhase": "BLIND_INPUT_EXECUTION",
                        "faultContext": "NONE",
                        "instanceId": f"INSTANCE-{index:04d}",
                        "observationId": f"OBSERVE-{index:04d}",
                        "requestOctets": 1,
                        "requestSha256": "a" * 64,
                        "responseCarrierCaseIds": ["PCR-RESPONSE-X-0000"],
                        "responseOctets": 1,
                        "responseSha256": "b" * 64,
                    }
                )
            rows.append(row)
    return {
        "instance_count": 884,
        "pending_relation_counts": {"ACV-049-E": 77, "ACV-049-P": 300},
        "relation_counts": counts,
        "rows": rows,
        "schema": "styx.app-core-iface0.semantic-acv049-partial-execution.v3",
        "semantic_rule_id": "ACV-049",
        "status": "REMEDIATION_PARTIAL_EXECUTION",
        "verdict": "PARTIAL_EXECUTION_PASS",
    }


def _runtime_permit_row() -> dict[str, object]:
    return {
        "detail": {"api": "test"},
        "disposition": "PERMIT",
        "justification": "test permit",
        "kind": "monitor",
    }


class FinalGateTests(unittest.TestCase):
    def test_ratified_semantic_fixture_source_is_exact_at_head(self) -> None:
        source_repo = ROOT.parents[2]
        selection_head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=source_repo,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        selected = (ROOT / "generate_seed_registry.py").read_bytes()
        frozen = _frozen_semantic_fixture_slice(selected)
        self.assertEqual(len(frozen), 18424)
        self.assertEqual(
            hashlib.sha256(frozen).hexdigest(),
            "323c5227972b79a33bc8238390e8e6000cd6a339a65375155ebea21010b4c8d4",
        )
        self.assertEqual(selected.count(frozen), 1)
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw) / "clean-checkout"
            subprocess.run(
                ["git", "clone", "--quiet", "--shared", str(source_repo), str(repo)],
                check=True,
            )
            subprocess.run(
                ["git", "checkout", "--quiet", "--detach", selection_head],
                cwd=repo,
                check=True,
            )
            historical_blob, selected_blob = _local_source_blobs(
                repo,
                selection_head,
            )
        self.assertEqual(
            _frozen_semantic_fixture_slice(historical_blob),
            _frozen_semantic_fixture_slice(selected_blob),
        )

    def test_provider_source_slice_must_equal_local_selection_blob(self) -> None:
        selected = (ROOT / "generate_seed_registry.py").read_bytes()

        def provider(url: str) -> tuple[object, bytes, dict[str, str]]:
            value = {
                "content": base64.b64encode(selected).decode("ascii"),
                "encoding": "base64",
                "path": (
                    "tools/causal-flow-simulator/app_core_iface0/"
                    "generate_seed_registry.py"
                ),
                "type": "file",
            }
            return value, b"provider", {}

        with patch("final_gate._fetch_json", side_effect=provider):
            _verify_provider_source_slice("a" * 40, (selected, selected))
            with self.assertRaisesRegex(FinalGateError, "local source blobs differ"):
                _verify_provider_source_slice(
                    "a" * 40, (selected, selected + b"drift")
                )

    def test_semantic_fixture_source_rejects_definition_shadowing_and_rebinding(self) -> None:
        selected = (ROOT / "generate_seed_registry.py").read_bytes()
        with self.assertRaisesRegex(FinalGateError, "definition count drift"):
            _frozen_semantic_fixture_slice(
                selected + b"\ndef _semantic_request_carriers(authority):\n    return []\n"
            )
        with self.assertRaisesRegex(FinalGateError, "call-site drift"):
            _frozen_semantic_fixture_slice(
                selected + b"\nsemantic = _semantic_request_carriers\n"
            )
        with self.assertRaisesRegex(FinalGateError, "definition count drift"):
            _frozen_semantic_fixture_slice(
                selected
                + b"\nif True:\n"
                + b"    def _semantic_request_carriers(authority):\n"
                + b"        return []\n"
            )
        with self.assertRaisesRegex(FinalGateError, "identifier is rebound"):
            _frozen_semantic_fixture_slice(
                selected
                + b"\nclass _semantic_request_carriers(tuple):\n"
                + b"    pass\n"
            )
        with self.assertRaisesRegex(FinalGateError, "identifier is rebound"):
            _frozen_semantic_fixture_slice(
                selected
                + b'\nglobals()["_semantic_request_" "carriers"] = object()\n'
            )
        decorated = selected.replace(
            b"def _semantic_request_carriers(authority: Any)",
            b"@staticmethod\ndef _semantic_request_carriers(authority: Any)",
            1,
        )
        with self.assertRaisesRegex(FinalGateError, "definition count drift"):
            _frozen_semantic_fixture_slice(decorated)
        with self.assertRaisesRegex(FinalGateError, "identifier is rebound"):
            _frozen_semantic_fixture_slice(selected + b"\nfrom inventory import *\n")
        with self.assertRaisesRegex(FinalGateError, "identifier is rebound"):
            _frozen_semantic_fixture_slice(
                selected
                + b'\nsys.modules[__name__].__dict__["fixture"] = object()\n'
            )
        indirect_call = selected.replace(
            b"_semantic_request_carriers(authority)",
            b"(_semantic_request_carriers)(authority)",
            1,
        )
        with self.assertRaisesRegex(FinalGateError, "identifier is rebound"):
            _frozen_semantic_fixture_slice(indirect_call)

    def test_runtime_semantic_fixture_is_exact_imported_callable(self) -> None:
        selected = (ROOT / "generate_seed_registry.py").read_bytes()
        attestation = _verify_runtime_semantic_fixture(ROOT.parents[2], selected)
        self.assertEqual(len(attestation), 3)
        for digest in attestation:
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
        with self.assertRaisesRegex(FinalGateError, "differs from Git object"):
            _verify_runtime_semantic_fixture(ROOT.parents[2], selected + b"\n")

    def test_historical_execution_rejects_context_and_oracle_application_mutations(self) -> None:
        source_repo = ROOT.parents[2]
        selected = (ROOT / "generate_seed_registry.py").read_bytes()
        baseline = _verify_runtime_semantic_fixture(source_repo, selected)
        conditional_injection = b'''\nif __name__ != "styx_app_core_frozen_generator":\n    _g = globals\n    _original_oracle = _g()["_TestCollision" "Oracle"]\n    def _patched_oracle(family, alternate_input, forced_digest):\n        return _original_oracle(family, alternate_input, b"\\x00" * 32)\n    _g()["_TestCollision" "Oracle"] = _patched_oracle\n'''
        path_discriminating_injection = b'''\nif __name__ != "styx_app_core_frozen_generator" and not any("historical-fixture" in item for item in sys.argv):\n    _g = globals\n    _original_oracle = _g()["_TestCollision" "Oracle"]\n    def _patched_oracle(family, alternate_input, forced_digest):\n        return _original_oracle(family, alternate_input, b"\\x00" * 32)\n    _g()["_TestCollision" "Oracle"] = _patched_oracle\n'''
        mutations = {
            "distinguishable-runtime": selected.replace(
                b'\n\nif __name__ == "__main__":\n',
                conditional_injection + b'\nif __name__ == "__main__":\n',
                1,
            ),
            "oracle-application": selected.replace(
                b"return oracle.forced_digest",
                b"return bytes(32)",
                1,
            ),
            "path-discriminating-runtime": selected.replace(
                b'\n\nif __name__ == "__main__":\n',
                path_discriminating_injection + b'\nif __name__ == "__main__":\n',
                1,
            ),
        }
        historical = subprocess.run(
            [
                "git",
                "show",
                "fb42037934618dacbb8d4aac65f68b01bc9e7bbb:"
                "tools/causal-flow-simulator/app_core_iface0/"
                "generate_seed_registry.py",
            ],
            cwd=source_repo,
            check=True,
            capture_output=True,
        ).stdout
        for name, mutated in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                self.assertEqual(
                    _frozen_semantic_fixture_slice(mutated),
                    _frozen_semantic_fixture_slice(selected),
                )
                repo = Path(raw) / "checkout"
                subprocess.run(
                    [
                        "git",
                        "clone",
                        "--quiet",
                        "--shared",
                        str(source_repo),
                        str(repo),
                    ],
                    check=True,
                )
                generated = repo / (
                    "tools/causal-flow-simulator/app_core_iface0/"
                    "generate_seed_registry.py"
                )
                generated.write_bytes(mutated)
                subprocess.run(
                    [
                        "git",
                        "-c",
                        "user.name=Styx Test",
                        "-c",
                        "user.email=styx-test.invalid",
                        "add",
                        str(generated.relative_to(repo)),
                    ],
                    cwd=repo,
                    check=True,
                )
                subprocess.run(
                    [
                        "git",
                        "-c",
                        "user.name=Styx Test",
                        "-c",
                        "user.email=styx-test.invalid",
                        "commit",
                        "--quiet",
                        "-m",
                        "test hostile fixture mutation",
                    ],
                    cwd=repo,
                    check=True,
                )
                selection_head = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=repo,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()
                mutated_attestation = _verify_runtime_semantic_fixture(repo, mutated)
                self.assertEqual(mutated_attestation, baseline)
                with self.assertRaisesRegex(
                    FinalGateError,
                    "checkout-owned evidence tool failed|carrier bytes differ",
                ):
                    actual_evidence = Path(raw) / "actual-phase-a-evidence"
                    _generate_phase_a_from_checkout(repo, actual_evidence)
                    historical_carriers = _historical_carrier_bytes(
                        repo,
                        historical,
                        mutated_attestation,
                        selection_head,
                    )
                    _verify_exact_carrier_bytes(
                        historical_carriers,
                        _carrier_subtree(_tree(actual_evidence)),
                    )

    def test_exact_carrier_comparison_requires_77_requests_and_19_responses(self) -> None:
        names = [
            *(f"PCR-REQUEST-X-{index:04d}.json" for index in range(77)),
            *(f"PCR-RESPONSE-X-{index:04d}.json" for index in range(19)),
        ]
        historical = {name: b"{}\n" for name in names}
        selected = dict(historical)
        _verify_exact_carrier_bytes(historical, selected)

        selected[names[-1]] = b'{"changed":true}\n'
        with self.assertRaisesRegex(FinalGateError, "carrier bytes differ"):
            _verify_exact_carrier_bytes(historical, selected)

        for changed in (
            {**historical, "PCR-REQUEST-X-extra.json": b"{}\n"},
            {
                **{
                    name: payload
                    for name, payload in historical.items()
                    if name != names[0]
                },
                "PCR-RESPONSE-X-extra.json": b"{}\n",
            },
        ):
            with self.assertRaisesRegex(FinalGateError, "carrier bytes differ"):
                _verify_exact_carrier_bytes(historical, changed)

    def test_provider_fetch_preserves_object_or_array_shape(self) -> None:
        url = "https://api.github.com/repos/styx-secure/styx/issues/295/comments"
        for value in ({"id": 1}, [{"id": 1}]):
            with self.subTest(value=value), patch.dict("os.environ", {}, clear=True):
                with patch(
                    "final_gate.urllib.request.build_opener",
                    return_value=_Opener(_Response(url, value)),
                ) as build_opener:
                    observed, raw, _headers = _fetch_json(url)
                handlers = build_opener.call_args.args
                proxy = next(
                    handler
                    for handler in handlers
                    if isinstance(handler, urllib.request.ProxyHandler)
                )
                self.assertEqual(proxy.proxies, {})
            self.assertEqual(observed, value)
            self.assertEqual(json.loads(raw), value)

    def test_provider_environment_override_fails_before_network(self) -> None:
        for name in (
            "GITHUB_TOKEN",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        ):
            with self.subTest(name=name), patch.dict(
                "os.environ", {name: "forbidden"}, clear=True
            ):
                with self.assertRaisesRegex(FinalGateError, "override environment"):
                    _fetch_json(COMBINED_BRANCH_URL)

    def test_next_link_accepts_only_the_exact_next_relation(self) -> None:
        self.assertEqual(
            _next_link(
                {
                    "link": (
                        '<https://api.github.com/items?page=2>; rel="next", '
                        '<https://api.github.com/items?page=9>; rel="last"'
                    )
                }
            ),
            "https://api.github.com/items?page=2",
        )
        self.assertIsNone(_next_link({"link": "<x>; rel=next"}))

    def test_checkout_verification_requires_head_ancestry_and_full_cleanliness(self) -> None:
        selection_head = "a" * 40
        calls: list[tuple[str, ...]] = []

        def clean_git(_repo: Path, *arguments: str) -> str:
            calls.append(arguments)
            if arguments == ("rev-parse", "HEAD"):
                return selection_head + "\n"
            if arguments == (
                "merge-base",
                "--is-ancestor",
                BASE_SHA,
                selection_head,
            ):
                return ""
            if arguments[0] == "status":
                return ""
            raise AssertionError(arguments)

        with tempfile.TemporaryDirectory() as raw:
            with patch("final_gate._git", side_effect=clean_git):
                _verify_clean_checkout(Path(raw), selection_head)
        self.assertIn(
            ("status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"),
            calls,
        )

        def dirty_git(_repo: Path, *arguments: str) -> str:
            if arguments == ("rev-parse", "HEAD"):
                return selection_head + "\n"
            if arguments[0] == "merge-base":
                return ""
            return "?? generated.json\n"

        with tempfile.TemporaryDirectory() as raw:
            with patch("final_gate._git", side_effect=dirty_git):
                with self.assertRaisesRegex(FinalGateError, "not clean"):
                    _verify_clean_checkout(Path(raw), selection_head)

    def test_evidence_tree_rejects_symlinks_and_preserves_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "nested").mkdir()
            (root / "nested/evidence.json").write_bytes(b"{}\n")
            self.assertEqual(_tree(root), {"nested/evidence.json": b"{}\n"})
            (root / "alias").symlink_to("nested/evidence.json")
            with self.assertRaisesRegex(FinalGateError, "non-regular"):
                _tree(root)

    def test_phase_a_rejects_bad_identity_and_same_checkout_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with self.assertRaisesRegex(FinalGateError, "full lowercase"):
                run_phase_a_gate(root, root, root / "a", root / "b", "HEAD")
            with self.assertRaisesRegex(FinalGateError, "not distinct"):
                run_phase_a_gate(root, root, root / "a", root / "b", "a" * 40)

    def test_phase_a_compares_historical_bytes_with_actual_gate_input(self) -> None:
        names = [
            *(f"PCR-REQUEST-X-{index:04d}.json" for index in range(77)),
            *(f"PCR-RESPONSE-X-{index:04d}.json" for index in range(19)),
        ]
        historical = {name: b"{}\n" for name in names}
        selected = dict(historical)
        selected[names[-1]] = b'{"path-discriminated":true}\n'
        validation = {
            "inventory_sha256": "a" * 64,
            "package_report_sha256": "b" * 64,
            "request_set_manifest_sha256": (
                "43a75ca967bf95991692ad07c3944b5792456b4c958df2ff663b2b9ec6b8145d"
            ),
        }
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo_one = root / "repo-one"
            repo_two = root / "repo-two"
            evidence_one = root / "evidence-one"
            evidence_two = root / "evidence-two"
            repo_one.mkdir()
            repo_two.mkdir()
            for evidence in (evidence_one, evidence_two):
                carriers = evidence / "carriers"
                carriers.mkdir(parents=True)
                for name, payload in selected.items():
                    (carriers / name).write_bytes(payload)
            with (
                patch("final_gate._verify_clean_checkout"),
                patch("final_gate._local_source_blobs", return_value=(b"h", b"s")),
                patch("final_gate._verify_provider_source_slice"),
                patch("final_gate._validate_external_root", return_value=validation),
                patch(
                    "final_gate._verify_runtime_semantic_fixture",
                    return_value=("a" * 64, "b" * 64, "c" * 64),
                ),
                patch(
                    "final_gate._historical_carrier_bytes",
                    return_value=historical,
                ),
                patch("final_gate._generate_phase_a_from_checkout") as regenerate,
            ):
                with self.assertRaisesRegex(FinalGateError, "carrier bytes differ"):
                    run_phase_a_gate(
                        repo_one,
                        repo_two,
                        evidence_one,
                        evidence_two,
                        "d" * 40,
                    )
            regenerate.assert_not_called()

    def test_phase_a_uses_two_clean_checkout_tools_and_regenerates_exact_bytes(self) -> None:
        source = ROOT.parents[2]
        selection_head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=source,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            checkout_one = temporary / "checkout-one"
            checkout_two = temporary / "checkout-two"
            for checkout in (checkout_one, checkout_two):
                subprocess.run(
                    ["git", "clone", "--quiet", "--shared", str(source), str(checkout)],
                    check=True,
                )
                subprocess.run(
                    ["git", "checkout", "--quiet", "--detach", selection_head],
                    cwd=checkout,
                    check=True,
                )
            evidence_one = temporary / "evidence-one"
            evidence_two = temporary / "evidence-two"
            _generate_phase_a_from_checkout(checkout_one, evidence_one)
            _generate_phase_a_from_checkout(checkout_two, evidence_two)
            with patch("final_gate._verify_provider_source_slice"):
                result = run_phase_a_gate(
                    checkout_one,
                    checkout_two,
                    evidence_one,
                    evidence_two,
                    selection_head,
                )
        self.assertEqual(result["verdict"], "PASS")
        self.assertEqual(result["caseCount"], 96)
        self.assertRegex(result["positiveCarrierInventorySha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(
            result["requestSetManifestSha256"],
            "43a75ca967bf95991692ad07c3944b5792456b4c958df2ff663b2b9ec6b8145d",
        )
        self.assertRegex(result["phaseAPackageReportSha256"], r"^[0-9a-f]{64}$")

    def test_acv049_controlled_environment_is_closed_and_channel_only(self) -> None:
        first = _controlled_acv049_environment("ACV049-ONE")
        second = _controlled_acv049_environment("ACV049-TWO")
        self.assertEqual(
            set(first),
            {
                "LC_CTYPE",
                "PATH",
                "PYTHONDONTWRITEBYTECODE",
                ACV049_MUTANT_CHANNEL,
            },
        )
        self.assertEqual(set(first), set(second))
        self.assertEqual(first["PATH"], second["PATH"])
        self.assertEqual(
            first["PYTHONDONTWRITEBYTECODE"],
            second["PYTHONDONTWRITEBYTECODE"],
        )
        self.assertNotEqual(
            first[ACV049_MUTANT_CHANNEL], second[ACV049_MUTANT_CHANNEL]
        )
        for invalid in ("", " leading", "trailing ", "non-ascii-è"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(FinalGateError, "canonical ASCII"):
                    _controlled_acv049_environment(invalid)

    def test_acv049_runtime_log_is_closed_and_aggregation_is_lossless(self) -> None:
        row = _runtime_permit_row()
        raw = dumps(row) + dumps(row)
        decoded = _decode_acv049_runtime_log(raw)
        self.assertEqual(decoded, [row, row])
        self.assertEqual(
            _aggregate_acv049_runtime_rows(decoded),
            [{"access": row, "count": 2}],
        )
        denied = dict(row, disposition="DENY")
        with self.assertRaisesRegex(FinalGateError, "access was denied"):
            _decode_acv049_runtime_log(dumps(denied))
        self.assertEqual(
            _successful_exec_count(
                b'1 execve("/usr/bin/python3", [], []) = 0\n'
                b'2 execve("/missing", [], []) = -1 ENOENT\n'
            ),
            1,
        )

    def test_acv049_python_runtime_monitor_detects_every_provenance_class(
        self,
    ) -> None:
        environment = _controlled_acv049_environment("ACV049-NEGATIVE")
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw).resolve()
            policy = {
                "allowed_metadata": [str(temporary), str(temporary.parent)],
                "allowed_reads": [],
                "allowed_writes": [],
                "bootstrap": ACV049_PYTHON_RUNTIME_MONITOR,
                "enumerable_directories": [str(temporary)],
                "git_executable": "/usr/bin/git",
                "monitored_roots": [str(ROOT)],
                "negative_ambient_path": str(temporary / "ambient"),
                "node_adapter": str(ROOT / "node_adapter.mjs"),
            }
            controls = _run_acv049_runtime_negative_controls(
                ROOT.parents[2], policy, environment
            )
        self.assertEqual(len(controls), 12)
        self.assertEqual(
            {row["control"] for row in controls if row["control"].startswith("environment:")},
            {f"environment:{name}" for name in environment},
        )
        self.assertTrue(all(row["verdict"] == "DETECTED" for row in controls))

    def test_acv049_static_provenance_scan_closes_loaded_sources(self) -> None:
        report = run_acv049_static_provenance_scan(ROOT.parents[2])
        self.assertEqual(
            report,
            {
                "basePinnedModuleCount": 1,
                "dormantBaseSpawnCount": 2,
                "evaluatorModuleCount": 9,
                "javascriptReaderCount": 1,
                "permittedSpawnSiteCount": 10,
                "validatorDescendantModuleCount": 4,
                "verdict": "STATIC_PROVENANCE_PASS",
            },
        )

    def test_acv049_static_python_scan_rejects_provenance_and_spawn_injection(
        self,
    ) -> None:
        hostile = {
            "denied import": b"import os\ndef value():\n    return 1\n",
            "dynamic import": b"def value():\n    return __import__('os')\n",
            "unclassified spawn": (
                b"import subprocess\ndef value():\n"
                b"    return subprocess.run(['git', 'status'])\n"
            ),
            "private subprocess escape": (
                b"import subprocess\ndef value():\n"
                b"    return subprocess._fork_exec([], [], True)\n"
            ),
        }
        for name, source in hostile.items():
            with self.subTest(name=name):
                with self.assertRaises(FinalGateError):
                    _scan_acv049_python_source("canonical_json.py", source)

    def test_acv049_static_javascript_scan_rejects_each_provenance_family(
        self,
    ) -> None:
        hostile = (
            "process.env.VALUE",
            "process['pid']",
            "new Date()",
            "performance.now()",
            "crypto.randomBytes(8)",
            "Math.random()",
            'import os from "node:os"',
            'require("os")',
            'import("node:os")',
        )
        for source in hostile:
            with self.subTest(source=source):
                with self.assertRaisesRegex(FinalGateError, "JavaScript provenance"):
                    _scan_acv049_javascript_source(source)
        _scan_acv049_javascript_source("process.argv; process.stdout.write('ok')")

    def test_acv049_e_report_validation_is_exact_and_fail_closed(self) -> None:
        report = _acv049_semantic_report()
        sources = {
            f"PCR-REQUEST-X-{index:04d}" for index in range(77)
        }
        self.assertEqual(len(_validate_acv049_e_report(report, sources)), 77)
        report["rows"][0]["responseSha256"] = "not-a-digest"
        with self.assertRaisesRegex(FinalGateError, "execution row drift"):
            _validate_acv049_e_report(report, sources)

    def test_acv049_e_baseline_runs_two_closed_environments_and_compares_bytes(
        self,
    ) -> None:
        report = _acv049_semantic_report()
        sources = [f"PCR-REQUEST-X-{index:04d}" for index in range(77)]
        environments: list[dict[str, str]] = []
        javascript_environments: list[dict[str, str]] = []

        def execute(
            _repo: Path,
            _tool: str,
            arguments: list[str],
            *,
            policy: dict[str, object],
            environment: dict[str, str] | None = None,
            input_bytes: bytes | None = None,
            timeout: int = 180,
        ) -> tuple[
            subprocess.CompletedProcess[bytes], list[dict[str, object]], bytes
        ]:
            self.assertEqual(timeout, 600)
            self.assertEqual(policy, {"runtime": "policy"})
            self.assertIsNotNone(environment)
            environments.append(dict(environment or {}))
            if "--emit-terminal-jobs" in arguments:
                self.assertIsNone(input_bytes)
                jobs = [{"job": index} for index in range(507)]
                completed = subprocess.CompletedProcess(
                    [], 0, dumps({"jobs": jobs}), b""
                )
                return completed, [_runtime_permit_row()], b"emitter-trace"
            self.assertIsNotNone(input_bytes)
            output = Path(arguments[arguments.index("--output") + 1])
            output.write_bytes(dumps(report))
            completed = subprocess.CompletedProcess([], 0, b"", b"")
            return completed, [_runtime_permit_row()], b"builder-trace"

        def javascript_reader(
            _repo: Path,
            _node: Path,
            _contract: Path,
            _jobs_bytes: bytes,
            environment: dict[str, str],
            policy: dict[str, object],
        ) -> tuple[bytes, list[dict[str, object]], list[bytes]]:
            self.assertEqual(policy, {"runtime": "policy"})
            javascript_environments.append(dict(environment))
            return (
                dumps({"results": []}),
                [_runtime_permit_row()],
                [b"javascript-trace"],
            )

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo_one = root / "repo-one"
            repo_two = root / "repo-two"
            evidence_one = root / "evidence-one"
            evidence_two = root / "evidence-two"
            for path in (repo_one, repo_two, evidence_one, evidence_two):
                path.mkdir()
            with (
                patch(
                    "final_gate._verify_acv049_checkout_pair",
                    return_value=(repo_one, repo_two),
                ),
                patch(
                    "final_gate.run_acv049_static_provenance_scan",
                    return_value={"verdict": "STATIC_PROVENANCE_PASS"},
                ),
                patch(
                    "final_gate._git",
                    side_effect=[str(root / "git-one"), str(root / "git-two")],
                ),
                patch("final_gate._verify_clean_checkout"),
                patch("final_gate._validate_external_root", return_value={"ok": True}),
                patch("final_gate._tree", return_value={"carrier": b"bytes"}),
                patch(
                    "final_gate.derive_acv049_relation_members",
                    return_value={"ACV-049-E": sources},
                ),
                patch(
                    "final_gate._acv049_runtime_policy",
                    return_value={"runtime": "policy"},
                ),
                patch(
                    "final_gate._run_acv049_runtime_negative_controls",
                    return_value=[{"control": "python", "verdict": "DETECTED"}],
                ),
                patch(
                    "final_gate._run_acv049_node_runtime_negative_controls",
                    return_value=[{"control": "javascript", "verdict": "DETECTED"}],
                ),
                patch(
                    "final_gate._run_acv049_monitored_python", side_effect=execute
                ),
                patch(
                    "final_gate._run_acv049_monitored_javascript_reader",
                    side_effect=javascript_reader,
                ),
            ):
                result = run_acv049_e_baseline_gate(
                    repo_one,
                    repo_two,
                    evidence_one,
                    evidence_two,
                    "c" * 40,
                    node=Path(sys.executable),
                )
        self.assertEqual(result["eRelationCount"], 77)
        self.assertEqual(
            result["provenanceControls"], "STATIC_AND_RUNTIME_PASS"
        )
        self.assertEqual(len(result["runtimeProvenance"]), 2)
        self.assertEqual(
            result["staticProvenance"], {"verdict": "STATIC_PROVENANCE_PASS"}
        )
        self.assertEqual(result["verdict"], "TWO_ENVIRONMENT_BASELINE_IDENTITY_PASS")
        self.assertEqual(len(environments), 4)
        self.assertEqual(len(javascript_environments), 2)
        self.assertEqual(environments[0], environments[1])
        self.assertEqual(environments[2], environments[3])
        self.assertEqual(environments[0], javascript_environments[0])
        self.assertEqual(environments[2], javascript_environments[1])
        self.assertEqual(set(environments[0]), set(environments[2]))
        for name in environments[0]:
            if name != ACV049_MUTANT_CHANNEL:
                self.assertEqual(environments[0][name], environments[2][name])
        self.assertNotEqual(
            environments[0][ACV049_MUTANT_CHANNEL],
            environments[2][ACV049_MUTANT_CHANNEL],
        )

    def test_authority_scan_rejects_withdrawal_and_supersession(self) -> None:
        selection_head = "a" * 40
        manifest_sha = "b" * 64
        selected_decision = {
            "baseSha": BASE_SHA,
            "candidateManifestSha256": manifest_sha,
            "caseCount": 96,
            "closureAmendmentSha256": RATIFIED_CARRIER_AUTHORITY_V3_SHA256,
            "decision": "RATIFY",
            "issue": 295,
            "kind": "APP_CORE_POSITIVE_CARRIER_INVENTORY_RATIFICATION_V1",
            "phaseAPackageReportSha256": "c" * 64,
            "positiveCarrierInventorySha256": "d" * 64,
            "repository": "styx-secure/styx",
            "requestCaseCount": 77,
            "responseCaseCount": 19,
            "selectionHead": selection_head,
        }
        selected_body = dumps(selected_decision).decode("utf-8")
        selected = {
            "body": selected_body,
            "created_at": "2026-09-02T00:00:00Z",
            "id": 100,
            "issue_url": "https://api.github.com/repos/styx-secure/styx/issues/295",
            "performed_via_github_app": None,
            "updated_at": "2026-09-02T00:00:00Z",
            "url": "https://api.github.com/repos/styx-secure/styx/issues/comments/100",
            "user": {"id": 141346846, "login": "maverde73"},
        }
        for action, replacement in (("WITHDRAW", None), ("SUPERSEDE", "300")):
            with self.subTest(action=action):
                change_body = dumps(
                    {
                        "decision": action,
                        "issue": 295,
                        "kind": "APP_CORE_POSITIVE_CARRIER_INVENTORY_AUTHORITY_CHANGE_V1",
                        "replacementCommentId": replacement,
                        "repository": "styx-secure/styx",
                        "selectionHead": selection_head,
                        "targetCommentBodySha256": hashlib.sha256(
                            selected_body.encode("utf-8")
                        ).hexdigest(),
                        "targetCommentId": "100",
                    }
                ).decode("utf-8")
                change = {
                    "body": change_body,
                    "created_at": "2026-09-02T00:00:01Z",
                    "id": 200,
                    "issue_url": "https://api.github.com/repos/styx-secure/styx/issues/295",
                    "performed_via_github_app": None,
                    "updated_at": "2026-09-02T00:00:01Z",
                    "url": "https://api.github.com/repos/styx-secure/styx/issues/comments/200",
                    "user": {"id": 141346846, "login": "maverde73"},
                }

                def fetch(url: str) -> tuple[object, bytes, dict[str, str]]:
                    if "/issues/295/comments?" in url:
                        return [selected, change], b"collection", {}
                    if url.endswith("/200"):
                        return change, json.dumps(change).encode("utf-8"), {}
                    if url.endswith("/100"):
                        return selected, json.dumps(selected).encode("utf-8"), {}
                    raise AssertionError(url)

                with patch("final_gate._fetch_json", side_effect=fetch):
                    with self.assertRaisesRegex(FinalGateError, "withdrawn or superseded"):
                        _scan_provider_authority(
                            selected_decision,
                            selected,
                            manifest_sha,
                        )

    def test_authority_scan_fails_closed_on_operator_candidate_but_ignores_others(self) -> None:
        decision = {
            "candidateManifestSha256": "b" * 64,
            "kind": "APP_CORE_POSITIVE_CARRIER_INVENTORY_RATIFICATION_V1",
            "selectionHead": "a" * 40,
        }
        selected = {
            "body": dumps(decision).decode("utf-8"),
            "created_at": "2026-09-02T00:00:00Z",
            "id": 100,
            "user": {"id": 141346846, "login": "maverde73"},
        }
        suspicious = {
            "body": "invalid APP_CORE_POSITIVE_CARRIER_INVENTORY_AUTHORITY_CHANGE_V1",
            "created_at": "2026-09-02T00:00:01Z",
            "id": 200,
            "user": {"id": 141346846, "login": "maverde73"},
        }
        with (
            patch(
                "final_gate._fetch_issue_comments",
                return_value=[selected, suspicious],
            ),
            patch(
                "final_gate._fetch_json",
                return_value=(suspicious, json.dumps(suspicious).encode("utf-8"), {}),
            ),
        ):
            with self.assertRaises(FinalGateError):
                _scan_provider_authority(decision, selected, "b" * 64)

        suspicious["user"] = {"id": 999, "login": "other"}
        with patch(
            "final_gate._fetch_issue_comments",
            return_value=[selected, suspicious],
        ):
            self.assertEqual(
                _scan_provider_authority(decision, selected, "b" * 64),
                (),
            )

        unrelated = {
            "body": "ordinary operator note",
            "created_at": "2026-09-02T00:00:02Z",
            "id": 201,
            "user": {"id": 141346846, "login": "maverde73"},
        }
        with patch(
            "final_gate._fetch_issue_comments",
            return_value=[selected, unrelated],
        ):
            self.assertEqual(
                _scan_provider_authority(decision, selected, "b" * 64),
                (),
            )

        duplicate = dict(selected, id=101)
        with patch(
            "final_gate._fetch_issue_comments",
            return_value=[selected, duplicate],
        ):
            with self.assertRaisesRegex(FinalGateError, "duplicate matching"):
                _scan_provider_authority(decision, selected, "b" * 64)

    def test_phase_b_authenticates_before_fresh_regeneration_and_refreshes(self) -> None:
        selection_head = "a" * 40
        inventory_sha = "b" * 64
        package_sha = "c" * 64
        comment_id = "12345"
        comment_url = (
            "https://api.github.com/repos/styx-secure/styx/issues/comments/"
            + comment_id
        )
        events: list[str] = []

        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw) / "repo"
            contract = repo / "tools/causal-flow-simulator/app_core_iface0/contract"
            contract.mkdir(parents=True)
            manifest = contract / "APP-CORE-IFACE-0-CANDIDATE-MANIFEST.json"
            manifest.write_bytes(b"manifest\n")
            manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
            decision = {
                "baseSha": BASE_SHA,
                "candidateManifestSha256": manifest_sha,
                "caseCount": 96,
                "closureAmendmentSha256": RATIFIED_CARRIER_AUTHORITY_V3_SHA256,
                "decision": "RATIFY",
                "issue": 295,
                "kind": "APP_CORE_POSITIVE_CARRIER_INVENTORY_RATIFICATION_V1",
                "phaseAPackageReportSha256": package_sha,
                "positiveCarrierInventorySha256": inventory_sha,
                "repository": "styx-secure/styx",
                "requestCaseCount": 77,
                "responseCaseCount": 19,
                "selectionHead": selection_head,
            }
            comment = {
                "body": dumps(decision).decode("utf-8"),
                "created_at": "2026-09-02T00:00:00Z",
                "id": int(comment_id),
                "issue_url": "https://api.github.com/repos/styx-secure/styx/issues/295",
                "performed_via_github_app": None,
                "updated_at": "2026-09-02T00:00:00Z",
                "url": comment_url,
                "user": {"id": 141346846, "login": "maverde73"},
            }
            provider_raw = json.dumps(comment, sort_keys=True).encode("utf-8")

            def fetch(url: str) -> tuple[object, bytes, dict[str, str]]:
                if url == comment_url:
                    events.append("comment")
                    return comment, provider_raw, {}
                if url.endswith("/commits/" + selection_head):
                    events.append("commit")
                    return {"sha": selection_head}, b"commit", {}
                if url == COMBINED_BRANCH_URL:
                    events.append("branch")
                    return {
                        "ref": COMBINED_BRANCH_REF,
                        "object": {"sha": selection_head, "type": "commit"},
                    }, b"branch", {}
                if "/issues/295/comments?" in url:
                    events.append("comments")
                    return [comment], b"comments", {}
                raise AssertionError(url)

            def generate(_repo: Path, output: Path) -> None:
                self.assertFalse(output.exists())
                self.assertEqual(
                    events,
                    ["comment", "commit", "branch", "comments", "source"],
                )
                events.append("generate")
                output.mkdir()
                (output / "generated").write_bytes(b"phase-a")

            def validate(_repo: Path, output: Path) -> dict[str, object]:
                self.assertEqual((output / "generated").read_bytes(), b"phase-a")
                events.append("validate")
                return {
                    "inventory_sha256": inventory_sha,
                    "package_report_sha256": package_sha,
                    "request_set_manifest_sha256": (
                        "43a75ca967bf95991692ad07c3944b5792456b4c958df2ff663b2b9ec6b8145d"
                    ),
                }

            def verify_actual_carriers(
                _repo: Path,
                _sources: tuple[bytes, bytes],
                _selection_head: str,
                actual_tree: dict[str, bytes],
            ) -> None:
                self.assertEqual(actual_tree, {"generated": b"phase-a"})
                self.assertEqual(
                    events,
                    ["comment", "commit", "branch", "comments", "source", "generate"],
                )
                events.append("historical")

            def verify_source(
                _selection_head: str,
                _selected: tuple[bytes, bytes],
            ) -> None:
                self.assertEqual(events, ["comment", "commit", "branch", "comments"])
                events.append("source")

            with (
                patch("final_gate._fetch_json", side_effect=fetch),
                patch("final_gate._verify_clean_checkout"),
                patch("final_gate._local_source_blobs", return_value=(b"s", b"s")),
                patch("final_gate._verify_provider_source_slice", side_effect=verify_source),
                patch("final_gate._generate_phase_a_from_checkout", side_effect=generate),
                patch(
                    "final_gate._verify_actual_carriers_against_historical",
                    side_effect=verify_actual_carriers,
                ),
                patch("final_gate._validate_external_root", side_effect=validate),
            ):
                observed = _validate_provider_authority(comment_id, repo)

            malformed_comment = dict(comment)
            malformed_comment["user"] = None
            with patch(
                "final_gate._fetch_json",
                return_value=(malformed_comment, b"malformed", {}),
            ):
                with self.assertRaisesRegex(FinalGateError, "provenance drift"):
                    _validate_provider_authority(comment_id, repo)

            stale_decision = dict(decision)
            stale_decision["closureAmendmentSha256"] = (
                "fd17ed39c7288620cd62f132db3fd5a877f6ba1ef0ff3580c9ad745146d85165"
            )
            stale_comment = dict(comment)
            stale_comment["body"] = dumps(stale_decision).decode("utf-8")
            with patch(
                "final_gate._fetch_json",
                return_value=(stale_comment, b"stale", {}),
            ):
                with self.assertRaisesRegex(FinalGateError, "value drift"):
                    _validate_provider_authority(comment_id, repo)

            def malformed_branch_fetch(
                url: str,
            ) -> tuple[object, bytes, dict[str, str]]:
                if url == comment_url:
                    return comment, provider_raw, {}
                if url.endswith("/commits/" + selection_head):
                    return {"sha": selection_head}, b"commit", {}
                if url == COMBINED_BRANCH_URL:
                    return {
                        "ref": COMBINED_BRANCH_REF,
                        "object": {"sha": selection_head, "type": "tag"},
                    }, b"branch", {}
                raise AssertionError(url)

            with (
                patch("final_gate._fetch_json", side_effect=malformed_branch_fetch),
                patch("final_gate._verify_clean_checkout"),
            ):
                with self.assertRaisesRegex(FinalGateError, "branch identity drift"):
                    _validate_provider_authority(comment_id, repo)

        self.assertEqual(observed, decision)
        self.assertEqual(
            events,
            [
                "comment", "commit", "branch", "comments", "source",
                "generate", "historical", "validate", "comment", "comments",
            ],
        )

    def test_phase_b_rejects_provider_change_during_regeneration(self) -> None:
        selection_head = "a" * 40
        comment_id = "12345"
        comment_url = (
            "https://api.github.com/repos/styx-secure/styx/issues/comments/"
            + comment_id
        )
        with tempfile.TemporaryDirectory() as raw:
            repo = Path(raw) / "repo"
            contract = repo / "tools/causal-flow-simulator/app_core_iface0/contract"
            contract.mkdir(parents=True)
            manifest = contract / "APP-CORE-IFACE-0-CANDIDATE-MANIFEST.json"
            manifest.write_bytes(b"manifest\n")
            decision = {
                "baseSha": BASE_SHA,
                "candidateManifestSha256": hashlib.sha256(
                    manifest.read_bytes()
                ).hexdigest(),
                "caseCount": 96,
                "closureAmendmentSha256": RATIFIED_CARRIER_AUTHORITY_V3_SHA256,
                "decision": "RATIFY",
                "issue": 295,
                "kind": "APP_CORE_POSITIVE_CARRIER_INVENTORY_RATIFICATION_V1",
                "phaseAPackageReportSha256": "c" * 64,
                "positiveCarrierInventorySha256": "b" * 64,
                "repository": "styx-secure/styx",
                "requestCaseCount": 77,
                "responseCaseCount": 19,
                "selectionHead": selection_head,
            }
            comment = {
                "body": dumps(decision).decode("utf-8"),
                "created_at": "2026-09-02T00:00:00Z",
                "id": int(comment_id),
                "issue_url": "https://api.github.com/repos/styx-secure/styx/issues/295",
                "performed_via_github_app": None,
                "updated_at": "2026-09-02T00:00:00Z",
                "url": comment_url,
                "user": {"id": 141346846, "login": "maverde73"},
            }
            first_raw = json.dumps(comment, sort_keys=True).encode("utf-8")
            calls = 0

            def fetch(url: str) -> tuple[object, bytes, dict[str, str]]:
                nonlocal calls
                if url == comment_url:
                    calls += 1
                    raw_comment = first_raw if calls == 1 else first_raw + b" "
                    return comment, raw_comment, {}
                if url.endswith("/commits/" + selection_head):
                    return {"sha": selection_head}, b"commit", {}
                if url == COMBINED_BRANCH_URL:
                    return {
                        "ref": COMBINED_BRANCH_REF,
                        "object": {"sha": selection_head, "type": "commit"},
                    }, b"branch", {}
                return [comment], b"comments", {}

            def generate(_repo: Path, output: Path) -> None:
                output.mkdir()

            with (
                patch("final_gate._fetch_json", side_effect=fetch),
                patch("final_gate._verify_clean_checkout"),
                patch("final_gate._local_source_blobs", return_value=(b"h", b"s")),
                patch("final_gate._verify_provider_source_slice"),
                patch("final_gate._generate_phase_a_from_checkout", side_effect=generate),
                patch("final_gate._verify_actual_carriers_against_historical"),
                patch(
                    "final_gate._validate_external_root",
                    return_value={
                        "inventory_sha256": "b" * 64,
                        "package_report_sha256": "c" * 64,
                        "request_set_manifest_sha256": (
                            "43a75ca967bf95991692ad07c3944b5792456b4c958df2ff663b2b9ec6b8145d"
                        ),
                    },
                ),
            ):
                with self.assertRaisesRegex(FinalGateError, "changed during"):
                    _validate_provider_authority(comment_id, repo)


if __name__ == "__main__":
    unittest.main()
