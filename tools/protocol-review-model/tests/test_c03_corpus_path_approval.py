"""Fail-closed evidence for the Issue #253 C0.3 corpus path approval."""

from __future__ import annotations

import copy
import hashlib
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path

from support import MODEL_PATH, REPO_ROOT, SCHEMA_PATH, load_validator


validator = load_validator()
BASE_SHA = "4a4ebc4b8fc91e500ecd8002801896dc73d5073f"
INVENTORY_SHA256 = "060212f77405f02c186b27b5925d74b9fbf75f0347807b34dbdb93e6d06a01aa"
O10_ROOT = REPO_ROOT / "tools/causal-flow-simulator/o10"
sys.path.insert(0, str(O10_ROOT))

from scope_guard import ScopeError, validate_validator_delta  # noqa: E402


EXISTING_APACHE_PATHS = (
    "styx-js/test/fixtures/vault-crypto-v1/hkdf-v1.json",
    "styx-js/test/fixtures/vault-crypto-v1/manifest-hmac-v1.json",
    "styx-js/test/fixtures/vault-crypto-v1/record-v1-bytes.json",
    "styx-js/test/fixtures/vault-crypto-v1/record-v1-json.json",
    "styx-js/test/fixtures/vault-crypto-v1/wrapper-v1.json",
    "styx-js/test/fixtures/kdf-kat-vectors.js",
)
C03_APACHE_PATHS = (
    "conformance/application-protocol/c03/manifest.json",
    "conformance/application-protocol/c03/valid-transcript-vectors.json",
    "conformance/application-protocol/c03/invalid-transcript-vectors.json",
    "conformance/application-protocol/c03/state-machine-scenarios.json",
    "conformance/application-protocol/c03/adversarial-mutations.json",
    "conformance/application-protocol/c03/expected-traces.json",
)
APACHE_METADATA = {
    "precedence": "override",
    "SPDX-FileCopyrightText": "2026 Maurizio Verde",
    "SPDX-License-Identifier": "Apache-2.0",
}
HISTORICAL_O10_TEST = (
    REPO_ROOT
    / "tools/protocol-review-model/tests/test_o10_outcome_taxonomy.py"
)
HISTORICAL_O10_TEST_SHA256 = (
    "64a89053e22c7e46d2e8e414250519f09db5a135cbe215c0637b46eb2a053ad2"
)


def _git_show(revision: str, path: str) -> bytes:
    return subprocess.check_output(
        ["git", "-C", str(REPO_ROOT), "show", f"{revision}:{path}"]
    )


def _apache_annotations(document: dict) -> list[dict]:
    return [
        annotation
        for annotation in document["annotations"]
        if annotation.get("SPDX-License-Identifier") == "Apache-2.0"
    ]


def _blocker(model: dict, blocker_id: str) -> dict:
    matches = [item for item in model["blockers"] if item["id"] == blocker_id]
    if len(matches) != 1:
        raise AssertionError(f"expected one blocker {blocker_id!r}")
    return matches[0]


class C03CorpusPathApprovalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reuse_path = REPO_ROOT / "REUSE.toml"
        cls.reuse_text = cls.reuse_path.read_text(encoding="utf-8")
        cls.current_reuse = tomllib.loads(cls.reuse_text)
        cls.base_reuse = tomllib.loads(
            _git_show(BASE_SHA, "REUSE.toml").decode("utf-8")
        )
        cls.model = validator.load_json_unique(MODEL_PATH)
        cls.schema = validator.load_json_unique(SCHEMA_PATH)
        cls.base_validator = _git_show(
            "d35052dfbf0631c726f250933bc401f424602f31",
            "tools/protocol-review-model/validate.py",
        ).decode("utf-8")
        cls.actual_validator = (
            REPO_ROOT / "tools/protocol-review-model/validate.py"
        ).read_text(encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        print(f"existing_apache_paths={len(EXISTING_APACHE_PATHS)}")
        print(f"c03_apache_paths={len(C03_APACHE_PATHS)}")
        print(f"total_apache_paths={len(EXISTING_APACHE_PATHS + C03_APACHE_PATHS)}")
        print("wildcards=0")
        print("duplicates=0")
        print("future_files_present=0")
        print("third_party_annotations_changed=0")
        print("c03_gate=DECIDED")
        print("c03=NO_GO")

    def test_inventory_digest_and_exact_order(self) -> None:
        inventory = "".join(f"{path}\n" for path in C03_APACHE_PATHS).encode()
        self.assertEqual(INVENTORY_SHA256, hashlib.sha256(inventory).hexdigest())
        apache = _apache_annotations(self.current_reuse)
        self.assertEqual(2, len(apache))
        self.assertEqual(list(EXISTING_APACHE_PATHS), apache[0]["path"])
        self.assertEqual(list(C03_APACHE_PATHS), apache[1]["path"])

    def test_annotations_have_exact_metadata_and_no_globs(self) -> None:
        apache = _apache_annotations(self.current_reuse)
        paths = [path for annotation in apache for path in annotation["path"]]
        self.assertEqual(12, len(paths))
        self.assertEqual(12, len(set(paths)))
        self.assertFalse(any("*" in path or "?" in path or "[" in path for path in paths))
        for annotation in apache:
            with self.subTest(paths=annotation["path"]):
                self.assertEqual(
                    APACHE_METADATA,
                    {key: annotation[key] for key in APACHE_METADATA},
                )

    def test_default_existing_and_third_party_annotations_are_frozen(self) -> None:
        current = self.current_reuse["annotations"]
        base = self.base_reuse["annotations"]
        self.assertEqual(len(base) + 1, len(current))
        self.assertEqual(base[0], current[0])
        self.assertEqual(base[1], current[1])
        self.assertEqual(base[2:], current[3:])

    def test_future_paths_are_absent_and_no_six_only_header_remains(self) -> None:
        self.assertFalse(any((REPO_ROOT / path).exists() for path in C03_APACHE_PATHS))
        self.assertNotIn("The six vector files below are the only", self.reuse_text)
        self.assertIn("The twelve paths below are the only approved", self.reuse_text)

    def test_licensing_documents_record_the_bounded_approval(self) -> None:
        required = {
            "LICENSING.md": ("twelve paths", "Issue #253", "creates no corpus bytes"),
            "README.md": ("Twelve exact synthetic data paths", "Issue #253"),
            "CONTRIBUTING.md": ("twelve exact", "Issues #41 and #253"),
            "docs/architecture/decisions/ADR-0004-licensing-strategy.md": (
                "esattamente dodici path",
                "Issue #253",
            ),
        }
        for path, fragments in required.items():
            text = (REPO_ROOT / path).read_text(encoding="utf-8")
            for fragment in fragments:
                with self.subTest(path=path, fragment=fragment):
                    self.assertIn(fragment, text)

    def test_gate_is_decided_while_c03_remains_no_go(self) -> None:
        gate = _blocker(self.model, "C0.3_CORPUS_PATH_APPROVAL")
        c03 = _blocker(self.model, "C0.3")
        self.assertEqual("DECIDED", gate["status"])
        self.assertEqual([], gate["depends_on"])
        self.assertEqual(["C0.3"], gate["blocks"])
        self.assertEqual("NO_GO", c03["status"])
        self.assertEqual(
            ["C0.3_CORPUS_PATH_APPROVAL", "O-06c", "O-07", "O-08", "O-10", "O-14"],
            c03["depends_on"],
        )
        self.assertEqual([], validator.validate(self.model, self.schema, REPO_ROOT))

    def test_rebased_o10_guard_accepts_the_exact_validator(self) -> None:
        hashes = validate_validator_delta(self.base_validator, self.actual_validator)
        self.assertEqual(
            "a77067d559270c1779353d870c4663705951cea8ce19150c325014726d59629d",
            hashes["complete_source_sha256"],
        )

    def test_rebased_o10_guard_rejects_open_gate(self) -> None:
        drift = self.actual_validator.replace(
            '        "C0.3_CORPUS_PATH_APPROVAL": "DECIDED",',
            '        "C0.3_CORPUS_PATH_APPROVAL": "OPEN",',
            1,
        )
        with self.assertRaises(ScopeError):
            validate_validator_delta(self.base_validator, drift)

    def test_rebased_o10_guard_rejects_other_gate_status(self) -> None:
        drift = self.actual_validator.replace(
            '        "C0.3_CORPUS_PATH_APPROVAL": "DECIDED",',
            '        "C0.3_CORPUS_PATH_APPROVAL": "NO_GO",',
            1,
        )
        with self.assertRaises(ScopeError):
            validate_validator_delta(self.base_validator, drift)

    def test_blocker_edge_drift_fails_core_validation(self) -> None:
        model = copy.deepcopy(self.model)
        _blocker(model, "C0.3_CORPUS_PATH_APPROVAL")["depends_on"] = ["O-16"]
        codes = {finding.code for finding in validator.validate(model, self.schema, REPO_ROOT)}
        self.assertIn("BLOCKER_EDGE_MISMATCH", codes)

    def test_historical_o10_test_is_byte_identical(self) -> None:
        self.assertEqual(
            HISTORICAL_O10_TEST_SHA256,
            hashlib.sha256(HISTORICAL_O10_TEST.read_bytes()).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
