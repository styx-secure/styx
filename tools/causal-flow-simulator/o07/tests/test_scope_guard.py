from __future__ import annotations

import ast
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


O07_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = O07_ROOT.parents[2]
HISTORICAL_CANDIDATE_SHA = "ba0525da1dd78c76c5cc60bc2041e2d3bed44bb3"
sys.path.insert(0, str(O07_ROOT))

from scope_guard_o07 import (  # noqa: E402
    ALLOWED_FILES,
    BASE_SHA,
    COPY_THRESHOLD,
    EXPECTED_ARTIFACT_SHA256,
    MODEL_PATH,
    ScopeViolation,
    VALIDATOR_PATH,
    _assignments,
    _expected_validator_values,
    _literal,
    _path_is_allowed,
    _path_is_forbidden,
    changed_relation,
    enforce_declared_validator_ast_delta,
    enforce_endpoint_types_and_identity,
    enforce_predecessor_test_integrity,
    enforce_test_authenticator_isolation,
    validate_scope_report,
)
from report_schema import FinalEvidenceIdentityContext, SCOPE_SCHEMA  # noqa: E402


def _git(repo: Path, *arguments: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *arguments])


class ScopeGuardTests(unittest.TestCase):
    def test_contract_uses_ratified_copy_threshold(self) -> None:
        self.assertEqual(COPY_THRESHOLD, 25)

    def test_forbidden_paths_win_over_broad_allowed_trees(self) -> None:
        self.assertTrue(_path_is_allowed("tools/causal-flow-simulator/o07/model.py"))
        self.assertTrue(_path_is_forbidden("tools/causal-flow-simulator/o07/state.wasm"))
        self.assertTrue(_path_is_forbidden("tools/causal-flow-simulator/o07/package-lock.json"))
        self.assertTrue(_path_is_forbidden("styx-js/src/product.js"))
        self.assertFalse(_path_is_allowed("docs/unrelated.md"))

    def test_normative_artifact_pins_match_historical_candidate(self) -> None:
        self.assertEqual(set(EXPECTED_ARTIFACT_SHA256), ALLOWED_FILES - {VALIDATOR_PATH})
        for relative, expected in sorted(EXPECTED_ARTIFACT_SHA256.items()):
            observed = hashlib.sha256(
                _git(REPO_ROOT, "show", f"{HISTORICAL_CANDIDATE_SHA}:{relative}")
            ).hexdigest()
            self.assertEqual(observed, expected, relative)

    def test_validator_historical_delta_and_reusable_ast_guard_are_exact(self) -> None:
        before = _git(REPO_ROOT, "show", f"{BASE_SHA}:{VALIDATOR_PATH}").decode("utf-8")
        after = _git(
            REPO_ROOT, "show", f"{HISTORICAL_CANDIDATE_SHA}:{VALIDATOR_PATH}"
        ).decode("utf-8")
        before_assign, before_fixed = _assignments(before)
        after_assign, after_fixed = _assignments(after)
        self.assertEqual(before_fixed, after_fixed)
        names = set(before_assign) | set(after_assign)
        changed = {
            name
            for name in names
            if name not in before_assign
            or name not in after_assign
            or ast.dump(before_assign[name], include_attributes=False)
            != ast.dump(after_assign[name], include_attributes=False)
        }
        required = {
            "CONTRACT_BASE_COMMIT",
            "EXPECTED_COUNTEREXAMPLE_BLOCKS",
            "EXPECTED_FIELD_SECURITY_DIGEST",
            "EXPECTED_FIELD_STATUS",
            "EXPECTED_SOURCE_RECORDS",
            "EXPECTED_STATUS_BY_COLLECTION",
            "PROTECTED_UNRESOLVED_FIELDS",
        }
        self.assertEqual(changed, required)
        base_values = {name: _literal(before_assign, name) for name in required}
        expected = _expected_validator_values(base_values)
        for name in sorted(required):
            self.assertEqual(_literal(after_assign, name), expected[name], name)

        fixture_before = """\
CONTRACT_BASE_COMMIT = "base-sha"
EXPECTED_BLOCKER_EDGES_DIGEST = "edges-sha"
EXPECTED_MODULE_ASSIGNMENTS = {"validator": "existing"}
EXPECTED_STATUS_BY_COLLECTION = {"blockers": {"O-10": "OPEN", "O-14": "DECIDED"}}
def validate_existing():
    return True
def main():
    validate_existing()
"""
        fixture_expected = """\
CONTRACT_BASE_COMMIT = "base-sha"
EXPECTED_BLOCKER_EDGES_DIGEST = "edges-sha"
EXPECTED_MODULE_ASSIGNMENTS = {"validator": "existing"}
EXPECTED_STATUS_BY_COLLECTION = {"blockers": {"O-10": "DECIDED", "O-14": "DECIDED"}}
def validate_existing():
    return True
def validate_o10_outcome_taxonomy():
    return True
def main():
    validate_existing()
    validate_o10_outcome_taxonomy()
"""
        allowed_arguments = {
            "allowed_assignments": {"EXPECTED_STATUS_BY_COLLECTION"},
            "allowed_functions": {"main", "validate_o10_outcome_taxonomy"},
            "allowed_literal_changes": {
                ("EXPECTED_STATUS_BY_COLLECTION", "blockers", "O-10")
            },
            "allowed_function_call_additions": {
                "main": {"validate_o10_outcome_taxonomy"}
            },
            "protected_literal_paths": {
                ("EXPECTED_STATUS_BY_COLLECTION", "blockers", "O-14")
            },
        }
        enforce_declared_validator_ast_delta(
            fixture_before,
            fixture_expected,
            fixture_expected,
            **allowed_arguments,
        )

        def assert_rejected(
            expected: str,
            pattern: str,
            *,
            actual: str | None = None,
        ) -> None:
            with self.assertRaisesRegex(ScopeViolation, pattern):
                enforce_declared_validator_ast_delta(
                    fixture_before,
                    expected if actual is None else actual,
                    expected,
                    **allowed_arguments,
                )

        assert_rejected("import os\n" + fixture_expected, "undeclared top-level AST")
        assert_rejected(fixture_expected + "EXTRA = 1\n", "assignment AST drift")
        assert_rejected(
            fixture_expected.replace('CONTRACT_BASE_COMMIT = "base-sha"\n', ""),
            "assignment AST drift",
        )
        for old, new in (
            ('CONTRACT_BASE_COMMIT = "base-sha"', 'CONTRACT_BASE_COMMIT = "other"'),
            (
                'EXPECTED_BLOCKER_EDGES_DIGEST = "edges-sha"',
                'EXPECTED_BLOCKER_EDGES_DIGEST = "other"',
            ),
            ('{"validator": "existing"}', '{"validator": "other"}'),
        ):
            assert_rejected(
                fixture_expected.replace(old, new),
                "assignment AST drift",
            )
        assert_rejected(
            fixture_expected + "validate_existing()\n",
            "undeclared top-level AST",
        )
        assert_rejected(
            fixture_expected + "def extra():\n    return True\n",
            "function AST drift",
        )
        assert_rejected(
            fixture_expected.replace("def validate_existing():\n    return True\n", ""),
            "function AST drift",
        )
        assert_rejected(
            fixture_expected + "class Extra:\n    pass\n",
            "class AST drift",
        )
        assert_rejected(
            fixture_expected.replace(
                "    validate_o10_outcome_taxonomy()\n",
                "    validate_other()\n",
            ),
            "registry call drift",
        )
        for o14_drift in (
            fixture_expected.replace(', "O-14": "DECIDED"', ""),
            fixture_expected.replace('"O-14": "DECIDED"', '"O-14": "OPEN"'),
        ):
            assert_rejected(o14_drift, "literal AST drift|protected literal path drift")

        body_drift = fixture_expected.replace(
            "def validate_o10_outcome_taxonomy():\n    return True",
            "def validate_o10_outcome_taxonomy():\n    return False",
        )
        assert_rejected(
            fixture_expected,
            "declared expected AST",
            actual=body_drift,
        )

    def test_copy_relation_is_rejected_at_ratified_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            _git(repo, "init", "-q")
            _git(repo, "config", "user.name", "O07 test")
            _git(repo, "config", "user.email", "o07@example.invalid")
            source = repo / "tools/causal-flow-simulator/o07/source.py"
            source.parent.mkdir(parents=True)
            source.write_text("\n".join(f"row_{index} = {index}" for index in range(80)) + "\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-qm", "base")
            base = _git(repo, "rev-parse", "HEAD").decode().strip()
            target = repo / "tools/causal-flow-simulator/o07/target.py"
            target.write_bytes(source.read_bytes())
            _git(repo, "add", ".")
            _git(repo, "commit", "-qm", "copy")
            candidate = _git(repo, "rev-parse", "HEAD").decode().strip()
            with self.assertRaisesRegex(ScopeViolation, "copy/rename relation forbidden at 25%"):
                changed_relation(repo, base, candidate)

    def test_added_o07_blob_cannot_duplicate_any_base_blob(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            _git(repo, "init", "-q")
            _git(repo, "config", "user.name", "O07 test")
            _git(repo, "config", "user.email", "o07@example.invalid")
            source = repo / "existing.txt"
            source.write_text("independent provenance\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-qm", "base")
            base = _git(repo, "rev-parse", "HEAD").decode().strip()
            target = repo / "tools/causal-flow-simulator/o07/reused.txt"
            target.parent.mkdir(parents=True)
            target.write_bytes(source.read_bytes())
            _git(repo, "add", ".")
            _git(repo, "commit", "-qm", "candidate")
            candidate = _git(repo, "rev-parse", "HEAD").decode().strip()
            relation = [{"status": "A", "paths": [str(target.relative_to(repo))]}]
            with self.assertRaisesRegex(ScopeViolation, "byte-identical O-07 Base blob"):
                enforce_endpoint_types_and_identity(repo, base, candidate, relation)

    def test_predecessor_review_test_deletion_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            _git(repo, "init", "-q")
            _git(repo, "config", "user.name", "O07 test")
            _git(repo, "config", "user.email", "o07@example.invalid")
            test_root = repo / "tools/protocol-review-model/tests"
            test_root.mkdir(parents=True)
            for index in range(3):
                (test_root / f"test_{index}.py").write_text(
                    f"def test_{index}():\n    assert True\n"
                )
            test_path = test_root / "support.py"
            test_path.write_text("VALUE = True\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-qm", "base")
            base = _git(repo, "rev-parse", "HEAD").decode().strip()
            test_path.unlink()
            _git(repo, "add", "-u")
            _git(repo, "commit", "-qm", "delete predecessor test")
            candidate = _git(repo, "rev-parse", "HEAD").decode().strip()
            with self.assertRaisesRegex(
                ScopeViolation, "predecessor review test deleted"
            ):
                enforce_predecessor_test_integrity(repo, base, candidate)

    def test_predecessor_review_test_change_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            _git(repo, "init", "-q")
            _git(repo, "config", "user.name", "O07 test")
            _git(repo, "config", "user.email", "o07@example.invalid")
            test_root = repo / "tools/protocol-review-model/tests"
            test_root.mkdir(parents=True)
            for index in range(3):
                (test_root / f"test_{index}.py").write_text(
                    f"def test_{index}():\n    assert True\n"
                )
            test_path = test_root / "support.py"
            test_path.write_text("VALUE = True\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-qm", "base")
            base = _git(repo, "rev-parse", "HEAD").decode().strip()
            test_path.write_text("def test_existing():\n    return None\n")
            _git(repo, "add", ".")
            _git(repo, "commit", "-qm", "weaken predecessor test")
            candidate = _git(repo, "rev-parse", "HEAD").decode().strip()
            with self.assertRaisesRegex(
                ScopeViolation, "predecessor review test changed"
            ):
                enforce_predecessor_test_integrity(repo, base, candidate)

    def test_test_authenticator_cannot_escape_test_harness(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            _git(repo, "init", "-q")
            _git(repo, "config", "user.name", "O07 test")
            _git(repo, "config", "user.email", "o07@example.invalid")
            source = repo / "tools/causal-flow-simulator/o07/runner.py"
            source.parent.mkdir(parents=True)
            source.write_text(
                "from test_helpers.ceremony import new_test_ceremony_harness\n"
            )
            _git(repo, "add", ".")
            _git(repo, "commit", "-qm", "candidate")
            candidate = _git(repo, "rev-parse", "HEAD").decode().strip()
            with self.assertRaisesRegex(
                ScopeViolation, "test-only ceremony authenticator escaped"
            ):
                enforce_test_authenticator_isolation(repo, candidate)

    def test_scope_report_schema_and_identity_hygiene_fail_closed(self) -> None:
        report = {
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
        }
        context = FinalEvidenceIdentityContext(
            ("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",),
            ("/tmp/o07-scope-test", "scope-host.invalid", "scope-user"),
        )
        validate_scope_report(report, hygiene_context=context)

        unknown = dict(report, unexpected="value")
        with self.assertRaises(ValueError):
            validate_scope_report(unknown, hygiene_context=context)

        identity = "0123456789abcdef0123456789abcdef01234567"
        leaked = dict(report)
        leaked["changed_relation"] = [
            {"status": "M", "paths": [f"docs/protocol/{identity[:7]}.md"]}
        ]
        with self.assertRaisesRegex(ValueError, "repository identity"):
            validate_scope_report(
                leaked,
                hygiene_context=FinalEvidenceIdentityContext(
                    (identity,), context.runtime_values
                ),
            )

        absolute = dict(report)
        absolute["changed_relation"] = [{"status": "M", "paths": ["/tmp/leak"]}]
        with self.assertRaises(ValueError):
            validate_scope_report(absolute, hygiene_context=context)

    def test_model_is_an_explicit_normative_artifact(self) -> None:
        self.assertIn(MODEL_PATH, EXPECTED_ARTIFACT_SHA256)


if __name__ == "__main__":
    unittest.main()
