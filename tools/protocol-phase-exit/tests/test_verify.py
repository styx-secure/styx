from __future__ import annotations

import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = ROOT / "tools/protocol-phase-exit/verify.py"
SPEC = importlib.util.spec_from_file_location("phase_exit_verify", MODULE_PATH)
verify = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = verify
SPEC.loader.exec_module(verify)

# Every tree-reading test runs against a clean, throw-away checkout of the
# recorded candidate (verify.CANDIDATE_SHA, the squash merge of PR #288 that
# carries the BOUNDED_GO phase exit), never against the caller's working tree.
# The verifier code under test is still the one loaded from ROOT above.
#
# PR #288 was squash-merged, so on `main` the candidate's first parent is
# BASE_SHA itself, which predates the canonical report. The provider-bound heads
# are therefore the ones the live gates recorded on the PR branch: the Phase-A
# HEAD named by verdict comment 5482518791 and the final HEAD approved by review
# 5070295549. The final HEAD has exactly the candidate's tree, which the tests
# assert. Those commits live on refs/heads/task/287-protocol-phase-exit (and
# refs/pull/288/head); a clone without them fails closed with a fetch hint.
PHASE_A_HEAD = "033cb89947ec9e1ac4c6565bcfe825d4de861049"
FINAL_HEAD = "2fcd1e0ed41ea23765c1f1a3b911a35875711997"
PR_BRANCH_COMMIT = "12e22220f9521f303d655e190d1e7b070628b997"
FETCH_HINT = (
    "commit missing from this clone; fetch the PR #288 history with "
    "`git fetch origin refs/heads/task/287-protocol-phase-exit` "
    "or `git fetch origin refs/pull/288/head`"
)

_CHECKOUTS = contextlib.ExitStack()
CANDIDATE: Path = ROOT


def setUpModule():
    global CANDIDATE
    CANDIDATE = _CHECKOUTS.enter_context(verify.candidate_checkout(ROOT, verify.CANDIDATE_SHA))


def tearDownModule():
    _CHECKOUTS.close()


def require_commit(revision: str) -> str:
    try:
        return verify.resolve_commit(ROOT, revision)
    except verify.ExitError as error:
        raise AssertionError(f"{revision}: {FETCH_HINT}") from error


def git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ("git", "-C", str(repo), "-c", "user.name=phase-exit-test",
         "-c", "user.email=phase-exit-test@invalid", "-c", "commit.gpgsign=false", *args),
        check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    ).stdout


class VerifyTests(unittest.TestCase):
    def test_first_parent_identity_is_exact(self):
        commits = verify.first_parent_commits(CANDIDATE)
        self.assertEqual(24, len(commits))
        self.assertEqual(verify.FREEZE_SHA, commits[0])
        self.assertEqual(verify.BASE_SHA, commits[-1])

    def test_base_pins_and_frozen_manifest(self):
        verify.verify_base_pins(CANDIDATE)
        digest, mapping = verify.frozen_manifest(CANDIDATE)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertGreater(len(mapping), 100)

    def test_registry_is_closed(self):
        registry = verify.load_registry(CANDIDATE)
        self.assertEqual([f"EXIT-{index:02d}" for index in range(1, 12)], [item["id"] for item in registry["conditions"]])
        registered = {
            evidence_id
            for item in registry["conditions"]
            for evidence_id in item["required_evidence_ids"]
        }
        self.assertEqual(set(verify.EVIDENCE_PATHS) | {"frozen_manifest", "first_parent_audit"}, registered)
        self.assertEqual(
            verify.EXPECTED_APPLICABILITY,
            {item["id"]: item["applicability"] for item in registry["conditions"]},
        )

    def test_conditional_exclusion_citations_fail_closed(self):
        record = copy.deepcopy(verify.load_registry(CANDIDATE)["conditions"][0])
        hostile_values = (
            ("file", "docs/protocol/styx-secure-session-v0-decisions.md"),
            ("heading", "## 5. Selected v0 contract"),
            ("quoted_condition", record["excluded_claims"][2]["quoted_condition"]),
            ("base_sha256", "0" * 64),
        )
        for key, value in hostile_values:
            hostile = copy.deepcopy(record)
            hostile["excluded_claims"][0][key] = value
            with self.subTest(key=key), self.assertRaises(verify.ExitError):
                verify.validate_excluded_claims(CANDIDATE, hostile)

    def test_report_is_bounded_and_deterministic(self):
        first = verify.canonical_bytes(verify.build_report(CANDIDATE))
        second = verify.canonical_bytes(verify.build_report(CANDIDATE))
        self.assertEqual(first, second)
        report = json.loads(first)
        self.assertEqual("ELIGIBLE_FOR_BOUNDED_GO", report["eligibility"])
        self.assertEqual("HUMAN_GATE_PENDING", report["conditions"][7]["disposition"])
        self.assertEqual("HUMAN_GATE_PENDING", report["conditions"][8]["disposition"])
        self.assertIn("adapter", report["non_authorizations"])
        self.assertEqual(verify.MINIMUM_CONDITIONAL_STATEMENTS, report["conditional_exclusions"])
        self.assertEqual(3, len(report["conditions"][0]["excluded_claims"]))

    def test_fail_dominates_eligibility(self):
        self.assertEqual("REQUIRES_NO_GO", verify.mechanical_eligibility(["PASS", "FAIL"]))
        self.assertEqual("ELIGIBLE_FOR_BOUNDED_GO", verify.mechanical_eligibility(["PASS", "CONDITIONAL_EXCLUSION"]))
        self.assertEqual("ELIGIBLE_FOR_GO", verify.mechanical_eligibility(["PASS"]))

    def test_digest_substitution_and_duplicate_evidence_fail_closed(self):
        registry = verify.load_registry(CANDIDATE)
        record = copy.deepcopy(registry["conditions"][2])
        observed = dict(record["expected_evidence_sha256"])
        observed["protocol_plan"] = "0" * 64
        with self.assertRaises(verify.ExitError):
            verify.disposition_for(record, observed)
        record["required_evidence_ids"].append(record["required_evidence_ids"][0])
        with self.assertRaises(verify.ExitError):
            verify.validate_evidence_declaration(record)

    def test_missing_registered_input_fails_closed(self):
        with mock.patch.dict(verify.EVIDENCE_PATHS, {"missing_fixture": ("not/present",)}):
            with self.assertRaises(verify.ExitError):
                verify.evidence_digest(CANDIDATE, "missing_fixture", "0" * 64, "1" * 64)

    def test_committed_report_substitution_fails_closed(self):
        report = {"schema": "test", "eligibility": "ELIGIBLE_FOR_BOUNDED_GO"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / verify.CANONICAL_REPORT_PATH
            path.parent.mkdir(parents=True)
            path.write_bytes(verify.canonical_bytes(report))
            verify.verify_committed_report(root, report)
            path.write_text('{"eligibility":"ELIGIBLE_FOR_GO"}\n', encoding="utf-8")
            with self.assertRaises(verify.ExitError):
                verify.verify_committed_report(root, report)

    def test_report_hygiene_and_scope_are_fail_closed(self):
        verify.validate_report_strings({"value": "docs/protocol/root-authority.md"}, {"deadbeef"})
        for value in ("/tmp/leak", "path=C:\\review", "2026-08-31T12:00", "candidate-deadbeef"):
            with self.subTest(value=value), self.assertRaises(verify.ExitError):
                verify.validate_report_strings({"value": value}, {"deadbeef"})
        self.assertTrue(verify.is_allowed_changed_path("tools/protocol-phase-exit/verify.py"))
        self.assertFalse(verify.is_allowed_changed_path("tools/causal-flow-simulator/ss0/model.py"))

    def test_candidate_scope_hostile_operations_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "tools/protocol-phase-exit/fixture.txt"
            allowed.parent.mkdir(parents=True)
            allowed.write_text("fixture", encoding="utf-8")
            verify.validate_candidate_scope(root, b"", b"A\ttools/protocol-phase-exit/fixture.txt\n")
            hostile = (
                (b"?? untracked\n", b"A\ttools/protocol-phase-exit/fixture.txt\n"),
                (b"", b"D\ttools/protocol-phase-exit/fixture.txt\n"),
                (b"", b"A\toutside.txt\n"),
                (b"", b"A\ttools/protocol-phase-exit/fixture.txt\nM\ttools/protocol-phase-exit/fixture.txt\n"),
            )
            for status, changed in hostile:
                with self.subTest(changed=changed), self.assertRaises(verify.ExitError):
                    verify.validate_candidate_scope(root, status, changed)
            link = root / "tools/protocol-phase-exit/link.txt"
            link.symlink_to(allowed)
            with self.assertRaises(verify.ExitError):
                verify.validate_candidate_scope(root, b"", b"A\ttools/protocol-phase-exit/link.txt\n")

    def test_base_frozen_and_audit_drift_fail_closed(self):
        pins = dict(verify.PINNED_BASE_BLOBS)
        first = next(iter(pins))
        pins[first] = "0" * 64
        with mock.patch.object(verify, "PINNED_BASE_BLOBS", pins), self.assertRaises(verify.ExitError):
            verify.verify_base_pins(CANDIDATE)
        with mock.patch.object(verify, "FIRST_PARENT_SHA256", "0" * 64), self.assertRaises(verify.ExitError):
            verify.first_parent_commits(CANDIDATE)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "x").write_bytes(b"observed")

            def fake_git(_repo, *args):
                if args[0] == "ls-files":
                    return b"x\n"
                if args[0] == "show":
                    return b"expected"
                raise AssertionError(args)

            with mock.patch.object(verify, "frozen_paths", return_value=["x"]), \
                    mock.patch.object(verify, "run_git", side_effect=fake_git), \
                    self.assertRaises(verify.ExitError):
                verify.frozen_manifest(root)
            plan = root / "docs/protocol/protocol-hardening-plan.md"
            plan.parent.mkdir(parents=True)
            plan.write_bytes((CANDIDATE / "docs/protocol/protocol-hardening-plan.md").read_bytes())
            commits = verify.first_parent_commits(CANDIDATE)
            verify.audit_identity(root, commits)
            plan.write_bytes(plan.read_bytes().replace(commits[0].encode(), b"0" * 40, 1))
            with self.assertRaises(verify.ExitError):
                verify.audit_identity(root, commits)

    def test_unknown_evidence_fails_closed(self):
        with self.assertRaises(verify.ExitError):
            verify.evidence_digest(CANDIDATE, "unknown", "0" * 64, "1" * 64)

    def test_verdict_monotonicity(self):
        self.assertTrue(verify.monotone_verdict("ELIGIBLE_FOR_GO", "GO"))
        self.assertTrue(verify.monotone_verdict("ELIGIBLE_FOR_GO", "BOUNDED_GO"))
        self.assertTrue(verify.monotone_verdict("ELIGIBLE_FOR_BOUNDED_GO", "BOUNDED_GO"))
        self.assertFalse(verify.monotone_verdict("ELIGIBLE_FOR_BOUNDED_GO", "GO"))
        self.assertFalse(verify.monotone_verdict("REQUIRES_NO_GO", "BOUNDED_GO"))
        self.assertTrue(verify.monotone_verdict("REQUIRES_NO_GO", "NO_GO"))

    def test_verdict_provider_identity_and_payload(self):
        comment_id = "5476501347"
        url = verify.verdict_url(comment_id)
        payload = {
            "schema": "styx-protocol-phase-exit-verdict/v1",
            "issue_number": 287,
            "issue_body_sha256": verify.ISSUE_BODY_SHA256,
            "operator": "maverde73",
            "base_sha": verify.BASE_SHA,
            "phase_a_head": "a" * 40,
            "phase_exit_report_sha256": "b" * 64,
            "frozen_manifest_sha256": "c" * 64,
            "first_parent_audit_sha256": "d" * 64,
            "mechanical_eligibility": "ELIGIBLE_FOR_BOUNDED_GO",
            "verdict": "BOUNDED_GO",
        }
        comment = {
            "id": int(comment_id), "url": url, "issue_url": verify.ISSUE_API_URL,
            "user": {"id": verify.MAVERDE_ID, "login": "maverde73"},
            "created_at": "2026-08-31T12:00:00Z", "updated_at": "2026-08-31T12:00:00Z",
            "body": json.dumps(payload, sort_keys=True, separators=(",", ":")),
        }
        result = verify.validate_verdict_comment(
            comment, comment_id=comment_id, phase_a_head="a" * 40,
            report_sha="b" * 64, frozen_sha="c" * 64, audit_sha="d" * 64,
            eligibility="ELIGIBLE_FOR_BOUNDED_GO",
        )
        self.assertEqual("BOUNDED_GO", result["verdict"])
        hostile = copy.deepcopy(comment)
        hostile["updated_at"] = "2026-08-31T12:00:01Z"
        with self.assertRaises(verify.ExitError):
            verify.validate_verdict_comment(
                hostile, comment_id=comment_id, phase_a_head="a" * 40,
                report_sha="b" * 64, frozen_sha="c" * 64, audit_sha="d" * 64,
                eligibility="ELIGIBLE_FOR_BOUNDED_GO",
            )
        for key, value in (
            ("id", 1),
            ("url", "https://example.invalid/comment"),
            ("issue_url", "https://api.github.com/repos/styx-secure/styx/issues/1"),
            ("user", {"id": 1, "login": "maverde73"}),
        ):
            hostile = copy.deepcopy(comment)
            hostile[key] = value
            with self.subTest(key=key), self.assertRaises(verify.ExitError):
                verify.validate_verdict_comment(
                    hostile, comment_id=comment_id, phase_a_head="a" * 40,
                    report_sha="b" * 64, frozen_sha="c" * 64, audit_sha="d" * 64,
                    eligibility="ELIGIBLE_FOR_BOUNDED_GO",
                )

    def test_approval_provider_identity_and_head(self):
        review_id = "5065807842"
        review = {
            "id": int(review_id),
            "pull_request_url": f"https://api.github.com/repos/styx-secure/styx/pulls/{verify.PR_NUMBER}",
            "user": {"id": verify.MANEXADA_ID, "login": "manexada"},
            "state": "APPROVED",
            "commit_id": "a" * 40,
            "submitted_at": "2026-08-31T12:00:00Z",
        }
        result = verify.validate_approval_review(review, review_id=review_id, final_head="a" * 40)
        self.assertEqual("a" * 40, result["approved_head"])
        hostile = copy.deepcopy(review)
        hostile["commit_id"] = "b" * 40
        with self.assertRaises(verify.ExitError):
            verify.validate_approval_review(hostile, review_id=review_id, final_head="a" * 40)
        for key, value in (
            ("id", 1),
            ("pull_request_url", "https://api.github.com/repos/styx-secure/styx/pulls/1"),
            ("user", {"id": 1, "login": "manexada"}),
        ):
            hostile = copy.deepcopy(review)
            hostile[key] = value
            with self.subTest(key=key), self.assertRaises(verify.ExitError):
                verify.validate_approval_review(hostile, review_id=review_id, final_head="a" * 40)

    def test_provider_heads_are_derived_from_git(self):
        # Historical note, kept on purpose: at the candidate this test derived
        # the Phase-A HEAD as `HEAD^`. On the PR branch that was the real Phase-A
        # commit, but PR #288 was squash-merged, so on `main` `fc7d153^` is
        # BASE_SHA, where the canonical report does not exist yet, and the test
        # already failed at the candidate itself (`git show BASE:report` fails).
        # It now uses the provider-bound heads recorded by the live gates instead
        # of guessing them from the topology, and proves the approved final HEAD
        # carries exactly the candidate tree.
        phase = require_commit(PHASE_A_HEAD)
        final = require_commit(FINAL_HEAD)
        self.assertEqual(
            git(ROOT, "rev-parse", f"{verify.CANDIDATE_SHA}^{{tree}}"),
            git(ROOT, "rev-parse", f"{final}^{{tree}}"),
        )
        with verify.candidate_checkout(ROOT, final) as tree:
            status_document = verify.run_git(tree, "show", f"{final}:AGENTS.md")
            observed = [
                value for value in ("GO", "BOUNDED_GO", "NO_GO")
                if verify.status_block("AGENTS.md", value) in status_document
            ]
            self.assertEqual(["BOUNDED_GO"], observed)
            verdict = observed[0]
            committed = verify.run_git(tree, "show", f"{phase}:{verify.CANONICAL_REPORT_PATH.as_posix()}")
            digest = verify.sha256(committed)
            report = json.loads(verify.run_git(tree, "show", f"{final}:{verify.CANONICAL_REPORT_PATH.as_posix()}"))
            self.assertEqual((phase, final), verify.validate_provider_heads(
                tree, phase_a_head=phase, phase_a_report_sha256=digest, final_head=final,
                final_report=report, verdict=verdict,
            ))
            for hostile_phase, report_digest, hostile_final in (
                (phase, "0" * 64, final),
                (verify.FREEZE_SHA, digest, final),
                (phase, digest, verify.BASE_SHA),
            ):
                with self.subTest(phase=hostile_phase, final=hostile_final), self.assertRaises(verify.ExitError):
                    verify.validate_provider_heads(
                        tree, phase_a_head=hostile_phase, phase_a_report_sha256=report_digest,
                        final_head=hostile_final, final_report=report, verdict=verdict,
                    )

    def test_status_document_transition_is_an_exact_replacement(self):
        path = "AGENTS.md"
        phase = b"prefix\n" + verify.status_block(path, "PENDING") + b"\nsuffix\n"
        final = b"prefix\n" + verify.status_block(path, "BOUNDED_GO") + b"\nsuffix\n"
        verify.validate_status_document_transition(path, phase, final, "BOUNDED_GO")
        for hostile in (
            final + b"extra\n",
            phase,
            phase + b"\n" + verify.status_block(path, "PENDING"),
            b"prefix\n" + verify.status_block(path, "GO") + b"\nsuffix\n",
        ):
            with self.subTest(hostile=hostile[-32:]), self.assertRaises(verify.ExitError):
                verify.validate_status_document_transition(path, phase, hostile, "BOUNDED_GO")

    def test_phase_exit_readme_keeps_operational_status_only_in_versioned_block(self):
        path = "docs/protocol/review/phase-exit/README.md"
        document = (CANDIDATE / path).read_bytes()
        verify.validate_phase_neutral_status_prose(path, document)
        for stale in (
            b"This directory contains the deterministic Phase-A report for Issue #287.",
            b"Current state:",
            b"protocol-hardening freeze: **still active**",
        ):
            with self.subTest(stale=stale), self.assertRaises(verify.ExitError):
                verify.validate_phase_neutral_status_prose(path, document.replace(
                    b"Canonical mechanical record:",
                    b"Canonical mechanical record:\n" + stale,
                ))

    def test_phase_b_transition_rejects_code_and_semantic_changes(self):
        head = verify.CANDIDATE_SHA
        report = json.loads(verify.run_git(CANDIDATE, "show", f"{head}:{verify.CANONICAL_REPORT_PATH.as_posix()}"))
        with self.assertRaises(verify.ExitError):
            verify.phase_b_changed_paths(CANDIDATE, require_commit(PR_BRANCH_COMMIT), head)
        hostile = copy.deepcopy(report)
        hostile["non_authorizations"].remove("sdk")
        with self.assertRaises(verify.ExitError):
            verify.validate_phase_b_report_transition(report, hostile)
        registry = json.loads((CANDIDATE / verify.REGISTRY_PATH).read_text(encoding="utf-8"))
        hostile_registry = copy.deepcopy(registry)
        hostile_registry["conditions"][0]["residual_risks"] = []
        with self.assertRaises(verify.ExitError):
            verify.validate_phase_b_registry_transition(registry, hostile_registry)
        allowed_registry = copy.deepcopy(registry)
        allowed_registry["conditions"][1]["expected_evidence_sha256"]["phase_exit_status"] = "1" * 64
        allowed_registry["conditions"][1]["expected_evidence_sha256"]["review_records"] = "2" * 64
        allowed_registry["conditions"][2]["expected_evidence_sha256"]["protocol_plan"] = "3" * 64
        verify.validate_phase_b_registry_transition(registry, allowed_registry)
        allowed_report = copy.deepcopy(report)
        allowed_report["conditions"][1]["observed_evidence_sha256"]["phase_exit_status"] = "1" * 64
        allowed_report["conditions"][1]["observed_evidence_sha256"]["review_records"] = "2" * 64
        allowed_report["conditions"][2]["observed_evidence_sha256"]["protocol_plan"] = "3" * 64
        verify.validate_phase_b_report_transition(report, allowed_report)

    def test_live_issue_identity_and_body_are_bound(self):
        issue = {
            "url": verify.ISSUE_API_URL,
            "repository_url": "https://api.github.com/repos/styx-secure/styx",
            "number": verify.ISSUE_NUMBER,
            "user": {"id": verify.MAVERDE_ID, "login": "maverde73"},
            "state": "open",
            "body": "ratified body",
        }
        digest = verify.sha256(issue["body"].encode())
        with mock.patch.object(verify, "ISSUE_BODY_SHA256", digest):
            verify.validate_issue_provider(issue)
            for key, value in (
                ("url", "https://example.invalid/issue"),
                ("repository_url", "https://api.github.com/repos/other/repo"),
                ("number", 1),
                ("user", {"id": 1, "login": "maverde73"}),
                ("body", "substituted"),
            ):
                hostile = copy.deepcopy(issue)
                hostile[key] = value
                with self.subTest(key=key), self.assertRaises(verify.ExitError):
                    verify.validate_issue_provider(hostile)

    def test_provider_bootstrap_and_tls_surface_fail_closed(self):
        self.assertTrue(verify._trusted_import_path(str(Path(sys.base_prefix) / "lib")))
        self.assertFalse(verify._trusted_import_path(str(ROOT)))
        opener = verify.provider_opener()
        proxies = [item for item in opener.handlers if isinstance(item, verify.urllib.request.ProxyHandler)]
        self.assertFalse(proxies)
        tls_handlers = [item for item in opener.handlers if isinstance(item, verify.urllib.request.HTTPSHandler)]
        self.assertEqual(1, len(tls_handlers))
        self.assertEqual(verify.ssl.CERT_REQUIRED, tls_handlers[0]._context.verify_mode)
        self.assertTrue(tls_handlers[0]._context.check_hostname)
        with self.assertRaises(verify.ExitError):
            verify.fetch_provider_json(verify.ISSUE_API_URL)
        self.assertEqual(2, verify.main([
            "--repo-root", str(ROOT), "--base", verify.BASE_SHA,
            "--output", str(ROOT / "forbidden-output.json"),
            "--verdict-comment-id", "1",
        ]))
        probe = (
            "import os,runpy,sys;"
            f"sys.argv=[{str(MODULE_PATH)!r},'--repo-root',{str(ROOT)!r},'--base','invalid','--output','/dev/null'];"
            f"p={str(MODULE_PATH)!r};"
            "\ntry: runpy.run_path(p,run_name='__main__')\n"
            "except SystemExit: pass\n"
            "blocked={'SSL_CERT_FILE','HTTPS_PROXY','PYTHONPATH'};"
            "assert not blocked.intersection(os.environ);"
            "assert all(x.startswith(sys.base_prefix) for x in sys.path)"
        )
        environment = dict(os.environ)
        environment.update({
            "SSL_CERT_FILE": "/tmp/hostile-ca.pem",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "PYTHONPATH": str(ROOT),
        })
        result = subprocess.run(
            [verify.SYSTEM_PYTHON, "-I", "-S", "-B", "-c", probe],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment,
        )
        self.assertEqual(0, result.returncode, result.stderr.decode())

    def test_external_evidence_is_outside_and_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            outside = Path(directory) / "raw.json"
            verify.store_external_bytes(ROOT, outside, b"{}")
            self.assertEqual(b"{}", outside.read_bytes())
            with self.assertRaises(verify.ExitError):
                verify.store_external_bytes(ROOT, outside, b"replacement")
        with self.assertRaises(verify.ExitError):
            verify.external_target(ROOT, ROOT / "evidence.json")

    def test_canonical_json_has_no_insignificant_whitespace(self):
        self.assertEqual(b'{"a":2,"z":1}\n', verify.canonical_bytes({"z": 1, "a": 2}))

    def test_candidate_checkout_is_the_exact_clean_commit(self):
        self.assertEqual(verify.CANDIDATE_SHA, verify.resolve_commit(CANDIDATE, "HEAD"))
        self.assertEqual(b"", verify.run_git(CANDIDATE, "status", "--porcelain=v1", "--untracked-files=all"))
        self.assertNotEqual(ROOT.resolve(), CANDIDATE.resolve())
        for hostile in ("HEAD", "fc7d153", "0" * 40):
            with self.subTest(revision=hostile), self.assertRaises(verify.ExitError):
                with verify.candidate_checkout(ROOT, hostile):
                    pass

    def test_injected_frozen_change_at_candidate_is_detected(self):
        # Inject a change into the candidate's frozen set and require the
        # verifier to refuse it: byte drift in a frozen file, a new untracked
        # file under a frozen prefix, and the same drift committed on top.
        frozen = verify.frozen_paths(CANDIDATE)
        target = next(path for path in frozen if path.startswith("tools/causal-flow-simulator/"))
        with verify.candidate_checkout(ROOT, verify.CANDIDATE_SHA) as tree:
            verify.frozen_manifest(tree)
            original = (tree / target).read_bytes()
            (tree / target).write_bytes(original + b"\n")
            with self.assertRaisesRegex(verify.ExitError, "frozen byte drift"):
                verify.frozen_manifest(tree)
            (tree / target).write_bytes(original)
            verify.frozen_manifest(tree)
            extra = tree / "conformance/injected.txt"
            extra.write_bytes(b"injected\n")
            with self.assertRaisesRegex(verify.ExitError, "frozen path set drift"):
                verify.frozen_manifest(tree)
            extra.unlink()
            (tree / target).write_bytes(original + b"\n")
            git(tree, "commit", "--quiet", "--no-verify", "-am", "inject frozen drift")
            with self.assertRaisesRegex(verify.ExitError, "frozen byte drift"):
                verify.frozen_manifest(tree)

    def test_bytecode_residue_is_not_frozen_drift(self):
        python_file = next(
            path for path in verify.frozen_paths(CANDIDATE)
            if path.startswith("tools/causal-flow-simulator/") and path.endswith(".py")
        )
        with verify.candidate_checkout(ROOT, verify.CANDIDATE_SHA) as tree:
            cache = tree / Path(python_file).parent / "__pycache__"
            cache.mkdir(exist_ok=True)
            (cache / (Path(python_file).stem + ".cpython-314.pyc")).write_bytes(b"\x00bytecode")
            nested = tree / "conformance/__pycache__"
            nested.mkdir(exist_ok=True)
            (nested / "x.cpython-312.pyc").write_bytes(b"\x00")
            self.assertEqual(verify.frozen_manifest(CANDIDATE), verify.frozen_manifest(tree))
            # Only bytecode inside __pycache__ is residue; anything else there
            # is still drift.
            (cache / "notes.txt").write_bytes(b"not bytecode\n")
            with self.assertRaisesRegex(verify.ExitError, "frozen path set drift"):
                verify.frozen_manifest(tree)
        self.assertTrue(verify.is_bytecode_residue("conformance/__pycache__/a.cpython-314.pyc"))
        for path in ("conformance/a.pyc", "conformance/__pycache__/a.py", "__pycache__", "conformance/__pycache__"):
            with self.subTest(path=path):
                self.assertFalse(verify.is_bytecode_residue(path))

    def test_cli_verifies_the_candidate_not_the_working_tree(self):
        # The documented ordinary verification, run from whatever is checked
        # out at ROOT, reproduces the committed canonical report of the
        # candidate byte for byte and leaves ROOT untouched.
        before = verify.run_git(ROOT, "status", "--porcelain=v1", "--untracked-files=all")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "phase-exit-report.json"
            self.assertEqual(0, verify.main([
                "--repo-root", str(ROOT), "--base", verify.BASE_SHA, "--output", str(output),
            ]))
            committed = verify.run_git(ROOT, "show", f"{verify.CANDIDATE_SHA}:{verify.CANONICAL_REPORT_PATH.as_posix()}")
            self.assertEqual(committed, output.read_bytes())
            self.assertEqual(2, verify.main([
                "--repo-root", str(ROOT), "--base", verify.BASE_SHA,
                "--output", str(Path(directory) / "base.json"), "--candidate", verify.BASE_SHA,
            ]))
        self.assertEqual(before, verify.run_git(ROOT, "status", "--porcelain=v1", "--untracked-files=all"))


if __name__ == "__main__":
    unittest.main()
