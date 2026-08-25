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
    enforce_endpoint_types_and_identity,
    enforce_predecessor_test_integrity,
)


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

    def test_normative_artifact_pins_match_worktree(self) -> None:
        self.assertEqual(set(EXPECTED_ARTIFACT_SHA256), ALLOWED_FILES - {VALIDATOR_PATH})
        for relative, expected in sorted(EXPECTED_ARTIFACT_SHA256.items()):
            observed = hashlib.sha256((REPO_ROOT / relative).read_bytes()).hexdigest()
            self.assertEqual(observed, expected, relative)

    def test_validator_worktree_delta_is_exact(self) -> None:
        before = _git(REPO_ROOT, "show", f"{BASE_SHA}:{VALIDATOR_PATH}").decode("utf-8")
        after = (REPO_ROOT / VALIDATOR_PATH).read_text(encoding="utf-8")
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
            test_path = repo / "tools/protocol-review-model/tests/test_existing.py"
            test_path.parent.mkdir(parents=True)
            test_path.write_text("def test_existing():\n    assert True\n")
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
            test_path = repo / "tools/protocol-review-model/tests/test_existing.py"
            test_path.parent.mkdir(parents=True)
            test_path.write_text("def test_existing():\n    assert True\n")
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

    def test_model_is_an_explicit_normative_artifact(self) -> None:
        self.assertIn(MODEL_PATH, EXPECTED_ARTIFACT_SHA256)


if __name__ == "__main__":
    unittest.main()
