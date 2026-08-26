from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


O07_ROOT = Path(__file__).resolve().parents[1]
if str(O07_ROOT) not in sys.path:
    sys.path.insert(0, str(O07_ROOT))

from report_schema import (  # noqa: E402
    CROSS_RUNTIME_SCHEMA,
    MUTATION_SCHEMA,
    PROBE_SCHEMA,
    SCOPE_SCHEMA,
    FinalEvidenceIdentityContext,
    final_evidence_hygiene_context,
    validate_canonical_report,
)


IDENTITY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
RUNTIME_VALUES = ("/tmp/styx-o07-runtime", "review-host.invalid", "review-user")


def _context(*identities: str) -> FinalEvidenceIdentityContext:
    return FinalEvidenceIdentityContext(identities or (IDENTITY,), RUNTIME_VALUES)


def _reports() -> list[dict[str, object]]:
    return [
        {
            "schema": PROBE_SCHEMA,
            "inventory_relation_count": 1,
            "semantic_atom_count": 0,
            "external_gate_count": 1,
            "semantic_cases": [],
            "external_gates": [
                {
                    "atom_instance_id": "A-EVD-001",
                    "gate_instance_id": "G-EVD-001",
                    "state": "REQUIRED_SEPARATE_GATE",
                }
            ],
            "failed_semantic_atoms": [],
            "semantic_verdict": "PASS",
            "final_o07_gate": "NOT_EVALUATED_BY_THIS_PROBE",
        },
        {
            "schema": CROSS_RUNTIME_SCHEMA,
            "adapter_count": 2,
            "semantic_atom_count": 0,
            "comparisons": [],
            "failed": [],
            "verdict": "PASS",
        },
        {
            "schema": MUTATION_SCHEMA,
            "registered_mutant_count": 0,
            "semantic_relation_count": 0,
            "mutants": [],
            "relations": [],
            "survived": [],
            "uncovered_atoms": [],
            "verdict": "ALL_REGISTERED_MUTANTS_KILLED",
        },
        {
            "schema": SCOPE_SCHEMA,
            "copy_threshold_percent": 25,
            "changed_relation": [{"status": "M", "paths": ["docs/protocol/a.md"]}],
            "changed_endpoint_count": 1,
            "validator_assignments_changed": ["EXPECTED_SOURCE_RECORDS"],
            "approved_artifact_count": 1,
            "predecessor_review_test_count": 9,
            "byte_identical_o07_base_blob_count": 0,
            "predecessor_import_count": 0,
            "verdict": "PASS",
        },
    ]


def _string_paths(value: object, prefix: tuple[object, ...] = ()) -> list[tuple[object, ...]]:
    result: list[tuple[object, ...]] = []
    if isinstance(value, str):
        result.append(prefix)
    elif isinstance(value, dict):
        for key, item in value.items():
            result.extend(_string_paths(item, prefix + (key,)))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            result.extend(_string_paths(item, prefix + (index,)))
    return result


def _replace(value: object, path: tuple[object, ...], replacement: str) -> object:
    changed = copy.deepcopy(value)
    cursor = changed
    for part in path[:-1]:
        cursor = cursor[part]  # type: ignore[index]
    cursor[path[-1]] = replacement  # type: ignore[index]
    return changed


def _git(repo: Path, *arguments: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *arguments]).decode().strip()


class ReportHygieneTests(unittest.TestCase):
    def test_context_is_mandatory_and_non_empty(self) -> None:
        with self.assertRaises(TypeError):
            validate_canonical_report(_reports()[0])  # type: ignore[call-arg]
        with self.assertRaises(ValueError):
            FinalEvidenceIdentityContext((), RUNTIME_VALUES)
        with self.assertRaises(ValueError):
            FinalEvidenceIdentityContext((IDENTITY,), ())

    def test_full_and_abbreviated_identity_rejected_in_every_string_field(self) -> None:
        for report in _reports():
            for path in _string_paths(report):
                for needle in (IDENTITY, IDENTITY[:7], IDENTITY.upper()[:7]):
                    with self.subTest(schema=report["schema"], path=path, needle=needle):
                        with self.assertRaises(ValueError):
                            validate_canonical_report(
                                _replace(report, path, needle),
                                hygiene_context=_context(),
                            )

    def test_runtime_provenance_and_measurement_are_rejected(self) -> None:
        report = _reports()[-1]
        for value in (
            "/tmp/styx-o07-runtime",
            "username=review-user",
            "hostname=review-host.invalid",
            "pid=731",
            "2026-08-25T20:37",
            "elapsed=1.234s",
            "duration=25ms",
        ):
            changed = copy.deepcopy(report)
            changed["changed_relation"] = [{"status": "M", "paths": [value]}]
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_canonical_report(changed, hygiene_context=_context())

    def test_short_username_does_not_match_protocol_substrings(self) -> None:
        context = FinalEvidenceIdentityContext((IDENTITY,), ("/tmp/repo", "host", "root"))
        report = copy.deepcopy(_reports()[-1])
        report["changed_relation"] = [
            {"status": "M", "paths": ["docs/protocol/root-authority.md"]}
        ]
        validate_canonical_report(report, hygiene_context=context)

        report["changed_relation"] = [{"status": "M", "paths": ["root"]}]
        with self.assertRaisesRegex(ValueError, "runtime identity"):
            validate_canonical_report(report, hygiene_context=context)

    def test_bundle_digest_is_bound_before_report_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            _git(repo, "init", "-q")
            _git(repo, "config", "user.name", "O07 test")
            _git(repo, "config", "user.email", "o07@example.invalid")
            (repo / "value.txt").write_text("base\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-qm", "base")
            base = _git(repo, "rev-parse", "HEAD")
            (repo / "value.txt").write_text("candidate\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-qm", "candidate")
            bundle = root / "candidate.bundle"
            _git(repo, "bundle", "create", str(bundle), "HEAD")
            digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
            context = final_evidence_hygiene_context(
                repo,
                base,
                "HEAD",
                bundle=bundle,
                bundle_sha256=digest,
            )
            self.assertEqual(len(context.repository_identities), 6)
            bundle.write_bytes(bundle.read_bytes() + b"substitution")
            with self.assertRaisesRegex(ValueError, "bundle SHA-256 mismatch"):
                final_evidence_hygiene_context(
                    repo,
                    base,
                    "HEAD",
                    bundle=bundle,
                    bundle_sha256=digest,
                )

    def test_free_form_external_gate_member_is_rejected(self) -> None:
        report = copy.deepcopy(_reports()[0])
        report["external_gates"][0]["requirement"] = "free prose"  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "schema mismatch"):
            validate_canonical_report(report, hygiene_context=_context())


if __name__ == "__main__":
    unittest.main()
