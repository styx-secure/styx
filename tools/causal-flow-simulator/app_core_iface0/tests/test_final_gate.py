from __future__ import annotations

import json
import hashlib
import base64
import subprocess
import sys
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from final_gate import (  # noqa: E402
    FinalGateError,
    _fetch_json,
    _generate_phase_a_from_checkout,
    _next_link,
    _local_source_blobs,
    _frozen_semantic_fixture_slice,
    _scan_provider_authority,
    _tree,
    _validate_provider_authority,
    _verify_provider_source_slice,
    _verify_clean_checkout,
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


class FinalGateTests(unittest.TestCase):
    def test_ratified_semantic_fixture_slice_is_exact_in_git_history_and_head(self) -> None:
        repo = ROOT.parents[2]
        selection_head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        historical, selected = _local_source_blobs(repo, selection_head)
        frozen = _frozen_semantic_fixture_slice(historical)
        self.assertEqual(len(frozen), 7121)
        self.assertEqual(
            hashlib.sha256(frozen).hexdigest(),
            "686208b6d1285d42f8ec165fbb511905004eee124a0708207b103b60c561e1ad",
        )
        self.assertEqual(selected.count(frozen), 1)

    def test_provider_source_slice_must_equal_both_local_git_blobs(self) -> None:
        historical = b"".join(
            subprocess.run(
                [
                    "git",
                    "show",
                    (
                        "284b9230126cfa70337723c2a9d001800a64804c:"
                        "tools/causal-flow-simulator/app_core_iface0/"
                        "generate_seed_registry.py"
                    ),
                ],
                cwd=ROOT.parents[2],
                check=True,
                capture_output=True,
            ).stdout.splitlines(keepends=True)
        )
        selected = historical + b"# selected-only\n"

        def provider(url: str) -> tuple[object, bytes, dict[str, str]]:
            payload = historical if "284b923" in url else selected
            value = {
                "content": base64.b64encode(payload).decode("ascii"),
                "encoding": "base64",
                "path": (
                    "tools/causal-flow-simulator/app_core_iface0/"
                    "generate_seed_registry.py"
                ),
                "type": "file",
            }
            return value, b"provider", {}

        with patch("final_gate._fetch_json", side_effect=provider):
            _verify_provider_source_slice("a" * 40, historical, selected)
            with self.assertRaisesRegex(FinalGateError, "local source blobs differ"):
                _verify_provider_source_slice("a" * 40, historical, selected + b"drift")

    def test_provider_fetch_preserves_object_or_array_shape(self) -> None:
        url = "https://api.github.com/repos/styx-secure/styx/issues/295/comments"
        for value in ({"id": 1}, [{"id": 1}]):
            with self.subTest(value=value), patch.dict("os.environ", {}, clear=True):
                with patch(
                    "final_gate.urllib.request.build_opener",
                    return_value=_Opener(_Response(url, value)),
                ):
                    observed, raw, _headers = _fetch_json(url)
            self.assertEqual(observed, value)
            self.assertEqual(json.loads(raw), value)

    def test_provider_environment_override_fails_before_network(self) -> None:
        with patch.dict("os.environ", {"GITHUB_TOKEN": "forbidden"}, clear=True):
            with self.assertRaisesRegex(FinalGateError, "override environment"):
                _fetch_json("https://api.github.com/repos/styx-secure/styx/pulls/296")

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
        self.assertEqual(result["caseCount"], 80)
        self.assertRegex(result["positiveCarrierInventorySha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(result["phaseAPackageReportSha256"], r"^[0-9a-f]{64}$")

    def test_authority_scan_rejects_withdrawal_and_supersession(self) -> None:
        selection_head = "a" * 40
        manifest_sha = "b" * 64
        selected_decision = {
            "baseSha": BASE_SHA,
            "candidateManifestSha256": manifest_sha,
            "caseCount": 80,
            "closureAmendmentSha256": (
                "fd17ed39c7288620cd62f132db3fd5a877f6ba1ef0ff3580c9ad745146d85165"
            ),
            "decision": "RATIFY",
            "issue": 295,
            "kind": "APP_CORE_POSITIVE_CARRIER_INVENTORY_RATIFICATION_V1",
            "phaseAPackageReportSha256": "c" * 64,
            "positiveCarrierInventorySha256": "d" * 64,
            "repository": "styx-secure/styx",
            "requestCaseCount": 65,
            "responseCaseCount": 15,
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
                "caseCount": 80,
                "closureAmendmentSha256": (
                    "fd17ed39c7288620cd62f132db3fd5a877f6ba1ef0ff3580c9ad745146d85165"
                ),
                "decision": "RATIFY",
                "issue": 295,
                "kind": "APP_CORE_POSITIVE_CARRIER_INVENTORY_RATIFICATION_V1",
                "phaseAPackageReportSha256": package_sha,
                "positiveCarrierInventorySha256": inventory_sha,
                "repository": "styx-secure/styx",
                "requestCaseCount": 65,
                "responseCaseCount": 15,
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
                if url.endswith("/pulls/296"):
                    events.append("pull")
                    return {
                        "base": {"sha": BASE_SHA},
                        "draft": True,
                        "head": {"sha": selection_head},
                        "state": "open",
                    }, b"pull", {}
                if "/issues/295/comments?" in url:
                    events.append("comments")
                    return [comment], b"comments", {}
                raise AssertionError(url)

            def generate(_repo: Path, output: Path) -> None:
                self.assertFalse(output.exists())
                self.assertEqual(
                    events,
                    ["comment", "commit", "pull", "comments", "source"],
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
                }

            def verify_source(
                _selection_head: str,
                _historical: bytes,
                _selected: bytes,
            ) -> None:
                self.assertEqual(events, ["comment", "commit", "pull", "comments"])
                events.append("source")

            with (
                patch("final_gate._fetch_json", side_effect=fetch),
                patch("final_gate._verify_clean_checkout"),
                patch("final_gate._local_source_blobs", return_value=(b"h", b"s")),
                patch("final_gate._verify_provider_source_slice", side_effect=verify_source),
                patch("final_gate._generate_phase_a_from_checkout", side_effect=generate),
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

            def malformed_pull_fetch(
                url: str,
            ) -> tuple[object, bytes, dict[str, str]]:
                if url == comment_url:
                    return comment, provider_raw, {}
                if url.endswith("/commits/" + selection_head):
                    return {"sha": selection_head}, b"commit", {}
                if url.endswith("/pulls/296"):
                    return {
                        "base": None,
                        "draft": True,
                        "head": {"sha": selection_head},
                        "state": "open",
                    }, b"pull", {}
                raise AssertionError(url)

            with (
                patch("final_gate._fetch_json", side_effect=malformed_pull_fetch),
                patch("final_gate._verify_clean_checkout"),
            ):
                with self.assertRaisesRegex(FinalGateError, "PR freeze identity drift"):
                    _validate_provider_authority(comment_id, repo)

        self.assertEqual(observed, decision)
        self.assertEqual(
            events,
            [
                "comment", "commit", "pull", "comments", "source",
                "generate", "validate", "comment", "comments",
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
                "caseCount": 80,
                "closureAmendmentSha256": (
                    "fd17ed39c7288620cd62f132db3fd5a877f6ba1ef0ff3580c9ad745146d85165"
                ),
                "decision": "RATIFY",
                "issue": 295,
                "kind": "APP_CORE_POSITIVE_CARRIER_INVENTORY_RATIFICATION_V1",
                "phaseAPackageReportSha256": "c" * 64,
                "positiveCarrierInventorySha256": "b" * 64,
                "repository": "styx-secure/styx",
                "requestCaseCount": 65,
                "responseCaseCount": 15,
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
                if url.endswith("/pulls/296"):
                    return {
                        "base": {"sha": BASE_SHA},
                        "draft": True,
                        "head": {"sha": selection_head},
                        "state": "open",
                    }, b"pull", {}
                return [comment], b"comments", {}

            def generate(_repo: Path, output: Path) -> None:
                output.mkdir()

            with (
                patch("final_gate._fetch_json", side_effect=fetch),
                patch("final_gate._verify_clean_checkout"),
                patch("final_gate._local_source_blobs", return_value=(b"h", b"s")),
                patch("final_gate._verify_provider_source_slice"),
                patch("final_gate._generate_phase_a_from_checkout", side_effect=generate),
                patch(
                    "final_gate._validate_external_root",
                    return_value={
                        "inventory_sha256": "b" * 64,
                        "package_report_sha256": "c" * 64,
                    },
                ),
            ):
                with self.assertRaisesRegex(FinalGateError, "changed during"):
                    _validate_provider_authority(comment_id, repo)


if __name__ == "__main__":
    unittest.main()
