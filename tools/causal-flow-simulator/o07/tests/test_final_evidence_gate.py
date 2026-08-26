from __future__ import annotations

import copy
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch


O07_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = O07_ROOT.parents[2]
if str(O07_ROOT) not in sys.path:
    sys.path.insert(0, str(O07_ROOT))

from inventory import validate_inventory  # noqa: E402
from run_cross_runtime import build_report as build_runtime  # noqa: E402
from run_genesis_checkpoint_probe import build_report as build_probe  # noqa: E402
from run_mutations import build_report as build_mutations  # noqa: E402
from verify_final_evidence_hygiene import (  # noqa: E402
    BASE_SHA,
    FAMILIES,
    RunDescriptor,
    _contained_regular_file,
    _validate_mutation_content,
    _validate_probe_content,
    _validate_run_roots,
    _validate_runtime_content,
)


CANDIDATE_SHA = "1" * 40


def _descriptor(repo: Path, evidence: Path) -> RunDescriptor:
    evidence.mkdir(parents=True, exist_ok=True)
    reports: dict[str, Path] = {}
    for family in FAMILIES:
        report = evidence / f"{family}.json"
        report.write_text("{}\n")
        reports[family] = report
    return RunDescriptor(repo=repo, evidence=evidence, **reports)


def _git_result(repo: Path, *arguments: str, **_: object) -> bytes:
    if arguments == ("rev-parse", f"{BASE_SHA}^{{commit}}"):
        return f"{BASE_SHA}\n".encode()
    if arguments in {
        ("rev-parse", f"{CANDIDATE_SHA}^{{commit}}"),
        ("rev-parse", "HEAD^{commit}"),
    }:
        return f"{CANDIDATE_SHA}\n".encode()
    if arguments == ("rev-parse", "--absolute-git-dir"):
        return f"{repo}/.git\n".encode()
    if arguments == ("rev-parse", "--git-common-dir"):
        return b".git\n"
    raise AssertionError(f"unexpected Git query: {arguments}")


class FinalEvidenceGateTests(unittest.TestCase):
    def test_probe_rejects_zero_count_and_falsified_disposition(self) -> None:
        inventory = validate_inventory()
        report, passed = build_probe()
        self.assertTrue(passed)
        _validate_probe_content(report, inventory)

        zero = copy.deepcopy(report)
        zero["inventory_relation_count"] = 0
        zero["semantic_atom_count"] = 0
        zero["external_gate_count"] = 0
        zero["semantic_cases"] = []
        zero["external_gates"] = []
        with self.assertRaisesRegex(ValueError, "relation is not exact"):
            _validate_probe_content(zero, inventory)

        falsified = copy.deepcopy(report)
        expected = falsified["semantic_cases"][0]["expected_disposition"]
        falsified["semantic_cases"][0]["observed_disposition"] = (
            "REJECT" if expected != "REJECT" else "ACCEPT"
        )
        with self.assertRaisesRegex(ValueError, "falsified"):
            _validate_probe_content(falsified, inventory)

    def test_runtime_and_mutation_results_are_substantive(self) -> None:
        inventory = validate_inventory()
        with tempfile.TemporaryDirectory() as temporary:
            runtime, passed = build_runtime(
                REPO_ROOT, Path(temporary) / "runtime", "node"
            )
        self.assertTrue(passed)
        _validate_runtime_content(runtime, inventory)
        runtime["comparisons"][0]["exact"] = False
        with self.assertRaisesRegex(ValueError, "not exact"):
            _validate_runtime_content(runtime, inventory)

        mutations, passed = build_mutations(REPO_ROOT)
        self.assertTrue(passed)
        _validate_mutation_content(mutations, inventory)
        mutations["mutants"][0]["killed"] = False
        with self.assertRaisesRegex(ValueError, "falsified"):
            _validate_mutation_content(mutations, inventory)

    def test_report_must_be_regular_contained_and_not_symlinked(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "evidence"
            evidence.mkdir()
            report = evidence / "report.json"
            report.write_text("{}\n")
            self.assertEqual(_contained_regular_file(report, evidence), report.resolve())

            outside = root / "outside.json"
            outside.write_text("{}\n")
            with self.assertRaisesRegex(ValueError, "outside"):
                _contained_regular_file(outside, evidence)

            link = evidence / "link.json"
            link.symlink_to(report)
            with self.assertRaisesRegex(ValueError, "symlink"):
                _contained_regular_file(link, evidence)

    def test_run_roots_reject_aliases_overlap_and_reused_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo_two = root / "repo-two"
            repo_two.mkdir()
            run_one = _descriptor(REPO_ROOT, root / "evidence-one")
            run_two = _descriptor(repo_two, root / "evidence-two")
            merge_base_ok = SimpleNamespace(returncode=0)
            clean = lambda path: path.resolve()  # noqa: E731
            with (
                patch(
                    "verify_final_evidence_hygiene.verify_clean_checkout",
                    side_effect=clean,
                ),
                patch("verify_final_evidence_hygiene._git", side_effect=_git_result),
                patch(
                    "verify_final_evidence_hygiene.subprocess.run",
                    return_value=merge_base_ok,
                ),
            ):
                normalized = _validate_run_roots(
                    run_one,
                    run_two,
                    base=BASE_SHA,
                    candidate=CANDIDATE_SHA,
                )
                self.assertEqual(normalized[1].repo, repo_two.resolve())

                with self.assertRaisesRegex(ValueError, "distinct checkout"):
                    _validate_run_roots(
                        run_one,
                        replace(run_two, repo=REPO_ROOT),
                        base=BASE_SHA,
                        candidate=CANDIDATE_SHA,
                    )

                same_evidence = replace(run_two, evidence=run_one.evidence)
                with self.assertRaisesRegex(ValueError, "distinct evidence"):
                    _validate_run_roots(
                        run_one,
                        same_evidence,
                        base=BASE_SHA,
                        candidate=CANDIDATE_SHA,
                    )

                reused = RunDescriptor(
                    repo=repo_two,
                    evidence=run_two.evidence,
                    probe=run_two.probe,
                    runtime=run_two.probe,
                    mutations=run_two.mutations,
                    scope=run_two.scope,
                )
                with self.assertRaisesRegex(ValueError, "reused"):
                    _validate_run_roots(
                        run_one,
                        reused,
                        base=BASE_SHA,
                        candidate=CANDIDATE_SHA,
                    )

    def test_run_roots_reject_wrong_head_and_evidence_inside_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo_two = root / "repo-two"
            repo_two.mkdir()
            run_one = _descriptor(REPO_ROOT, root / "evidence-one")
            run_two = _descriptor(repo_two, root / "evidence-two")
            merge_base_ok = SimpleNamespace(returncode=0)
            clean = lambda path: path.resolve()  # noqa: E731

            def wrong_head(repo: Path, *arguments: str, **kwargs: object) -> bytes:
                if repo.resolve() == repo_two.resolve() and arguments == (
                    "rev-parse",
                    "HEAD^{commit}",
                ):
                    return f"{'2' * 40}\n".encode()
                return _git_result(repo, *arguments, **kwargs)

            with (
                patch(
                    "verify_final_evidence_hygiene.verify_clean_checkout",
                    side_effect=clean,
                ),
                patch("verify_final_evidence_hygiene._git", side_effect=wrong_head),
                patch(
                    "verify_final_evidence_hygiene.subprocess.run",
                    return_value=merge_base_ok,
                ),
                self.assertRaisesRegex(ValueError, "Base/HEAD mismatch"),
            ):
                _validate_run_roots(
                    run_one,
                    run_two,
                    base=BASE_SHA,
                    candidate=CANDIDATE_SHA,
                )

            overlap = _descriptor(repo_two, repo_two / "evidence")
            with (
                patch(
                    "verify_final_evidence_hygiene.verify_clean_checkout",
                    side_effect=clean,
                ),
                patch("verify_final_evidence_hygiene._git", side_effect=_git_result),
                patch(
                    "verify_final_evidence_hygiene.subprocess.run",
                    return_value=merge_base_ok,
                ),
                self.assertRaisesRegex(ValueError, "overlaps"),
            ):
                _validate_run_roots(
                    run_one,
                    overlap,
                    base=BASE_SHA,
                    candidate=CANDIDATE_SHA,
                )


if __name__ == "__main__":
    unittest.main()
