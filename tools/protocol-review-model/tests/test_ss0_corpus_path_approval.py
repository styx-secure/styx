"""Fail-closed evidence for the Issues #291/#293 SS-0 corpus boundary."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

from support import MODEL_PATH, REPO_ROOT, SCHEMA_PATH, load_validator


validator = load_validator()
BASE_SHA = "fc7d15356f2299e9acd8a106f46d6631d0c66b74"
INVENTORY_SHA256 = "61bea8adc1e36af3bc011df2553f634f0eeeae2c2dba01611a426628341b1861"

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
SS0_APACHE_PATHS = (
    "conformance/secure-session/ss0/manifest.json",
    "conformance/secure-session/ss0/valid-session-vectors.json",
    "conformance/secure-session/ss0/invalid-session-vectors.json",
    "conformance/secure-session/ss0/state-machine-scenarios.json",
    "conformance/secure-session/ss0/adversarial-mutations.json",
    "conformance/secure-session/ss0/expected-traces.json",
)
APACHE_METADATA = {
    "precedence": "override",
    "SPDX-FileCopyrightText": "2026 Maurizio Verde",
    "SPDX-License-Identifier": "Apache-2.0",
}
FROZEN_BASE_SHA256 = {
    "docs/protocol/styx-secure-session-v0-decisions.md":
        "235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07",
    "docs/protocol/review/styx-app-kernel-v0-review-model.schema.json":
        "9975d7ad63bb00ff3351bcf7e740f315a5cbac3acf9b13ac36901e421b46f846",
    "tools/protocol-review-model/validate.py":
        "e79caecde38c457ed79036d339c67b7aa7a394e37708ba76f0aa715ce0092f3b",
    "tools/agent-enforcement/contract.py":
        "524e1cf700e9e47fec3fe2b839e6f277e5ca219bafba1dc5ed35281561833e29",
    "docs/security/STYX-THREAT-MODEL.md":
        "8863ce4b2ef697055e95da22e0a2fbb630172cdf3f5fd0c91b27ec02f9d2ba54",
}


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


def _inventory_errors(document: dict, *, root: Path = REPO_ROOT) -> list[str]:
    annotations = _apache_annotations(document)
    errors: list[str] = []
    expected = [
        list(EXISTING_APACHE_PATHS),
        list(C03_APACHE_PATHS),
        list(SS0_APACHE_PATHS),
    ]
    if len(annotations) != 3:
        errors.append("APACHE_ANNOTATION_COUNT")
    elif [item.get("path") for item in annotations] != expected:
        errors.append("APACHE_PATH_ORDER")
    paths = [path for item in annotations for path in item.get("path", [])]
    if len(paths) != 18:
        errors.append("APACHE_PATH_COUNT")
    if len(paths) != len(set(paths)):
        errors.append("DUPLICATE_PATH")
    if any("*" in path or "?" in path or "[" in path for path in paths):
        errors.append("WILDCARD_PATH")
    if any(
        {key: item.get(key) for key in APACHE_METADATA} != APACHE_METADATA
        for item in annotations
    ):
        errors.append("APACHE_METADATA")
    if any(
        not (root / path).is_file() or (root / path).is_symlink()
        for path in SS0_APACHE_PATHS
    ):
        errors.append("SS0_FILE_INVALID")
    return errors


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    following = re.search(r"\n##(?:#)? ", text[start + len(heading):])
    if following is None:
        raise AssertionError(f"missing following heading after {heading}")
    return text[start:start + len(heading) + following.start()]


def _annotation_blocks(text: str) -> list[str]:
    """Return each TOML annotation table as its exact byte-equivalent text."""

    lines = text.splitlines(keepends=True)
    blocks: list[str] = []
    for start, line in enumerate(lines):
        if line.rstrip("\r\n") != "[[annotations]]":
            continue
        end = start + 1
        while end < len(lines) and lines[end].strip():
            end += 1
        blocks.append("".join(lines[start:end]))
    return blocks


def _k11_frozen_projection(section: str) -> str:
    """Mask only the three K-11 bullets authorized to change."""

    allowed = {"Rule", "Residual/reopen condition", "Human ratification"}
    matches = list(re.finditer(r"(?m)^- \*\*(.+?):\*\*", section))
    if not matches:
        raise AssertionError("K-11 has no bullet registry")
    projection = [section[:matches[0].start()]]
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(section)
        label = match.group(1)
        projection.append(
            f"- **{label}:** <RATIFIED_CHANGE>\n"
            if label in allowed
            else section[match.start():end]
        )
    return "".join(projection)


class Ss0CorpusPathApprovalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reuse_text = (REPO_ROOT / "REUSE.toml").read_text(encoding="utf-8")
        cls.base_reuse_text = _git_show(BASE_SHA, "REUSE.toml").decode("utf-8")
        cls.current_reuse = tomllib.loads(cls.reuse_text)
        cls.base_reuse = tomllib.loads(cls.base_reuse_text)
        cls.current_annotation_blocks = _annotation_blocks(cls.reuse_text)
        cls.base_annotation_blocks = _annotation_blocks(cls.base_reuse_text)
        cls.apache_annotations = _apache_annotations(cls.current_reuse)
        cls.apache_paths = [
            path for annotation in cls.apache_annotations for path in annotation["path"]
        ]
        cls.wildcard_count = sum(
            "*" in path or "?" in path or "[" in path for path in cls.apache_paths
        )
        cls.duplicate_count = len(cls.apache_paths) - len(set(cls.apache_paths))
        cls.ss0_regular_files = sum(
            (REPO_ROOT / path).is_file() and not (REPO_ROOT / path).is_symlink()
            for path in SS0_APACHE_PATHS
        )
        cls.preexisting_annotations_changed = sum(
            left != right
            for left, right in zip(
                cls.base_annotation_blocks,
                cls.current_annotation_blocks[:3] + cls.current_annotation_blocks[4:],
                strict=True,
            )
        )

    @classmethod
    def tearDownClass(cls) -> None:
        print(f"existing_vector_apache_paths={len(EXISTING_APACHE_PATHS)}")
        print(f"c03_apache_paths={len(C03_APACHE_PATHS)}")
        print(f"ss0_apache_paths={len(SS0_APACHE_PATHS)}")
        print(f"total_apache_paths={len(cls.apache_paths)}")
        print(f"wildcards={cls.wildcard_count}")
        print(f"duplicates={cls.duplicate_count}")
        print(f"ss0_regular_files={cls.ss0_regular_files}")
        print(f"preexisting_annotations_changed={cls.preexisting_annotations_changed}")

    def test_inventory_digest_and_exact_order(self) -> None:
        inventory = "".join(f"{path}\n" for path in SS0_APACHE_PATHS).encode()
        self.assertEqual(INVENTORY_SHA256, hashlib.sha256(inventory).hexdigest())
        self.assertEqual([], _inventory_errors(self.current_reuse))

    def test_existing_annotations_are_byte_equivalent_and_ordered(self) -> None:
        base = self.base_annotation_blocks
        current = self.current_annotation_blocks
        self.assertEqual(len(base) + 1, len(current))
        self.assertEqual(base[:3], current[:3])
        self.assertEqual(base[3:], current[4:])

    def test_ss0_paths_are_populated_regular_synthetic_files(self) -> None:
        self.assertEqual(6, self.ss0_regular_files)
        for path in SS0_APACHE_PATHS:
            self.assertTrue((REPO_ROOT / path).is_file(), path)
            self.assertFalse((REPO_ROOT / path).is_symlink(), path)

    def test_manifest_is_canonical_and_binds_all_six_files(self) -> None:
        manifest_path = REPO_ROOT / SS0_APACHE_PATHS[0]
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        canonical = json.dumps(
            manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8") + b"\n"
        self.assertEqual(canonical, manifest_path.read_bytes())
        self.assertTrue(manifest["synthetic"])
        self.assertEqual("none", manifest["upstreamBytes"])
        self.assertEqual(list(SS0_APACHE_PATHS[1:]), [
            row["path"] for row in manifest["generatedFiles"]
        ])
        for row in manifest["generatedFiles"]:
            self.assertEqual(
                row["sha256"],
                hashlib.sha256((REPO_ROOT / row["path"]).read_bytes()).hexdigest(),
            )

    def test_changed_seventh_wildcard_and_duplicate_paths_fail(self) -> None:
        mutations = []
        changed = copy.deepcopy(self.current_reuse)
        changed["annotations"][3]["path"][0] += ".changed"
        mutations.append(changed)
        seventh = copy.deepcopy(self.current_reuse)
        seventh["annotations"][3]["path"].append("conformance/secure-session/ss0/extra.json")
        mutations.append(seventh)
        wildcard = copy.deepcopy(self.current_reuse)
        wildcard["annotations"][3]["path"][0] = "conformance/secure-session/ss0/*.json"
        mutations.append(wildcard)
        duplicate = copy.deepcopy(self.current_reuse)
        duplicate["annotations"][3]["path"][1] = duplicate["annotations"][3]["path"][0]
        mutations.append(duplicate)
        for document in mutations:
            with self.subTest(errors=_inventory_errors(document)):
                self.assertTrue(_inventory_errors(document))

    def test_missing_symlink_and_metadata_mutations_fail(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for path in SS0_APACHE_PATHS:
                candidate = root / path
                candidate.parent.mkdir(parents=True, exist_ok=True)
                candidate.write_text("{}\n", encoding="utf-8")
            (root / SS0_APACHE_PATHS[0]).unlink()
            self.assertIn(
                "SS0_FILE_INVALID",
                _inventory_errors(self.current_reuse, root=root),
            )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for path in SS0_APACHE_PATHS:
                candidate = root / path
                candidate.parent.mkdir(parents=True, exist_ok=True)
                candidate.write_text("{}\n", encoding="utf-8")
            dangling = root / SS0_APACHE_PATHS[1]
            dangling.unlink()
            os.symlink("missing-target", dangling)
            self.assertFalse(dangling.exists())
            self.assertIn(
                "SS0_FILE_INVALID",
                _inventory_errors(self.current_reuse, root=root),
            )
        for key, value in (
            ("precedence", "closest"),
            ("SPDX-FileCopyrightText", "someone else"),
            ("SPDX-License-Identifier", "MIT"),
        ):
            document = copy.deepcopy(self.current_reuse)
            document["annotations"][3][key] = value
            with self.subTest(key=key):
                self.assertTrue(_inventory_errors(document))

    def test_reordered_and_preexisting_annotation_mutations_fail(self) -> None:
        reordered = copy.deepcopy(self.current_reuse)
        reordered["annotations"][2], reordered["annotations"][3] = (
            reordered["annotations"][3],
            reordered["annotations"][2],
        )
        self.assertTrue(_inventory_errors(reordered))
        altered = copy.deepcopy(self.current_reuse)
        altered["annotations"][1]["path"][0] += ".changed"
        self.assertTrue(_inventory_errors(altered))

    def test_frozen_inputs_are_byte_identical(self) -> None:
        for path, expected in FROZEN_BASE_SHA256.items():
            with self.subTest(path=path):
                actual = hashlib.sha256((REPO_ROOT / path).read_bytes()).hexdigest()
                self.assertEqual(expected, actual)

    def test_k11_only_changes_ratified_bullets(self) -> None:
        path = "docs/protocol/styx-app-kernel-v0-decisions.md"
        base_text = _git_show(BASE_SHA, path).decode()
        current_text = (REPO_ROOT / path).read_text(encoding="utf-8")
        base = _section(base_text, "### K-11")
        current = _section(current_text, "### K-11")
        self.assertNotIn("\n## 3.", base)
        self.assertNotIn("\n## 3.", current)
        self.assertEqual(
            base_text.replace(base, "", 1),
            current_text.replace(current, "", 1),
        )
        self.assertEqual(_k11_frozen_projection(base), _k11_frozen_projection(current))
        self.assertIn(INVENTORY_SHA256, current)
        self.assertIn("Issue #291 comment `5484188019`", current)
        self.assertIn("Issue #293 comment `5485961310`", current)

    def test_review_model_changes_only_decisions_source_digest(self) -> None:
        current = validator.load_json_unique(MODEL_PATH)
        base = json.loads(
            _git_show(
                BASE_SHA,
                "docs/protocol/review/styx-app-kernel-v0-review-model.json",
            )
        )
        current_projection = copy.deepcopy(current)
        current_source = next(item for item in current_projection["sources"] if item["id"] == "decisions")
        base_source = next(item for item in base["sources"] if item["id"] == "decisions")
        current_source["sha256"] = base_source["sha256"]
        self.assertEqual(base, current_projection)
        schema = validator.load_json_unique(SCHEMA_PATH)
        self.assertEqual([], validator.validate(current, schema, REPO_ROOT))

    def test_licensing_documents_record_bounded_approval(self) -> None:
        required = {
            "LICENSING.md": ("eighteen paths", "Issue #291", "populated by Issue #293"),
            "README.md": ("Eighteen exact synthetic data paths", "Issue #293"),
            "CONTRIBUTING.md": ("eighteen exact", "Issue #293"),
            "docs/architecture/decisions/ADR-0004-licensing-strategy.md": (
                "esattamente diciotto path",
                "Issue #291",
            ),
            "docs/protocol/protocol-hardening-plan.md": ("Issue #291", "K11-SS"),
            "docs/protocol/review/README.md": ("Issue #291", "K11-SS"),
        }
        for path, fragments in required.items():
            text = (REPO_ROOT / path).read_text(encoding="utf-8")
            for fragment in fragments:
                with self.subTest(path=path, fragment=fragment):
                    self.assertIn(fragment, text)


if __name__ == "__main__":
    unittest.main()
