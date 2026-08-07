#!/usr/bin/env python3
"""Validate canonical/mirror documentation pairs without network access.

The checker proves file pairing, canonical hash freshness, structural parity,
and preservation of selected machine-checkable tokens. It intentionally does
not claim that a translation is correct or semantically equivalent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

EXIT_PASS = 0
EXIT_FAIL = 2
EXIT_ERROR = 3

SCHEMA = "styx.docs.translation-pairs"
SCHEMA_VERSION = 1
TOP_LEVEL_KEYS = {"schema", "version", "hash", "pairs"}
PAIR_KEYS = {"canonical", "mirror"}
STATUS_LABELS = (
    "implemented",
    "partial",
    "missing",
    "separate design decision",
)

TRANSLATION_METADATA = re.compile(
    r'\A<!-- styx-translation:v1 canonical="(?P<canonical>[^"]+)" '
    r'sha256="(?P<digest>[0-9a-f]{64})" -->$',
    re.MULTILINE,
)
CANONICAL_METADATA = re.compile(
    r'\A<!-- styx-canonical:v1 mirror="(?P<mirror>[^"]+)" -->$',
    re.MULTILINE,
)
TRANSLATION_MARKER = re.compile(r"<!--\s*styx-translation:v1\b")
CANONICAL_MARKER = re.compile(r"<!--\s*styx-canonical:v1\b")
HEADING = re.compile(r"^(#{1,6})\s+(.+?)\s*$", re.MULTILINE)
SECTION_NUMBER = re.compile(r"^(?P<number>\d+(?:\.\d+)*)\.?(?:\s+|$)")
INLINE_CODE = re.compile(r"`([^`\n]+)`")
FENCE = re.compile(r"^[ \t]{0,3}(?P<marker>`{3,}|~{3,})")
REPOSITORY_PATH = re.compile(
    r"^(?:\.github/|docs/|specs/|styx-js/|packages/|push_bridge(?:_server)?/|"
    r"tools/|AGENTS\.md$|CLAUDE\.md$|CODEOWNERS$)"
)
MARKDOWN_LINK = re.compile(r"\[[^\]]+\]\(([^)]+)\)")


class DuplicateKeyError(ValueError):
    """Raised when a JSON object repeats a key."""


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateKeyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_manifest(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as source:
        value = json.load(source, object_pairs_hook=reject_duplicate_keys)
    if not isinstance(value, dict):
        raise ValueError("manifest root must be an object")
    return value


def repository_root(manifest: Path) -> Path:
    platform_dir = manifest.parent
    if platform_dir.name != "platform" or platform_dir.parent.name != "docs":
        raise ValueError("manifest must be located at docs/platform/translation-pairs.json")
    return platform_dir.parent.parent.resolve()


def resolve_markdown_path(root: Path, raw: Any, field: str) -> tuple[Path | None, str | None]:
    if not isinstance(raw, str) or not raw:
        return None, f"{field} must be a non-empty string"
    pure = PurePosixPath(raw)
    if pure.is_absolute() or ".." in pure.parts:
        return None, f"{field} escapes docs/platform: {raw}"
    if pure.suffix != ".md":
        return None, f"{field} is not Markdown: {raw}"
    if len(pure.parts) < 3 or pure.parts[:2] != ("docs", "platform"):
        return None, f"{field} is outside docs/platform: {raw}"
    candidate = root.joinpath(*pure.parts)
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError:
        return None, f"{field} does not exist: {raw}"
    platform_root = (root / "docs" / "platform").resolve()
    if resolved != platform_root and platform_root not in resolved.parents:
        return None, f"{field} resolves outside docs/platform: {raw}"
    if candidate.is_symlink() or not resolved.is_file():
        return None, f"{field} must be a regular non-symlink file: {raw}"
    return resolved, None


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def without_fenced_blocks(text: str) -> str:
    """Blank fenced blocks while preserving line boundaries."""
    visible: list[str] = []
    fence_char: str | None = None
    fence_length = 0
    for line in text.splitlines(keepends=True):
        match = FENCE.match(line)
        if fence_char is None and match:
            marker = match.group("marker")
            fence_char = marker[0]
            fence_length = len(marker)
            visible.append("\n" if line.endswith("\n") else "")
            continue
        if fence_char is not None:
            stripped = line.lstrip(" \t")
            if stripped.startswith(fence_char * fence_length):
                trailing = stripped[fence_length:].strip()
                if not trailing or set(trailing) == {fence_char}:
                    fence_char = None
                    fence_length = 0
            visible.append("\n" if line.endswith("\n") else "")
            continue
        visible.append(line)
    return "".join(visible)


def heading_signature(text: str) -> list[tuple[int, str | None]]:
    signature: list[tuple[int, str | None]] = []
    for match in HEADING.finditer(without_fenced_blocks(text)):
        title = match.group(2).strip()
        number = SECTION_NUMBER.match(title)
        signature.append((len(match.group(1)), number.group("number") if number else None))
    return signature


def status_signature(text: str) -> list[str]:
    pattern = re.compile(
        rf"\*\*(?P<label>{'|'.join(re.escape(label) for label in STATUS_LABELS)})\*\*"
    )
    return [match.group("label") for match in pattern.finditer(without_fenced_blocks(text))]


def repository_path_signature(text: str) -> list[str]:
    return [
        token
        for token in INLINE_CODE.findall(without_fenced_blocks(text))
        if REPOSITORY_PATH.match(token)
    ]


def has_peer_link(text: str, peer: str) -> bool:
    peer_name = PurePosixPath(peer).name
    return any(target.split("#", 1)[0] == peer_name for target in MARKDOWN_LINK.findall(text))


def validate_pair(
    root: Path,
    index: int,
    pair: Any,
    seen: set[str],
) -> list[str]:
    prefix = f"pairs[{index}]"
    findings: list[str] = []
    if not isinstance(pair, dict):
        return [f"{prefix} must be an object"]
    if set(pair) != PAIR_KEYS:
        findings.append(
            f"{prefix} must contain exactly {sorted(PAIR_KEYS)}; got {sorted(pair)}"
        )
        return findings

    canonical_raw = pair["canonical"]
    mirror_raw = pair["mirror"]
    for field, raw in (("canonical", canonical_raw), ("mirror", mirror_raw)):
        if isinstance(raw, str) and raw in seen:
            findings.append(f"{prefix}.{field} duplicates path: {raw}")
        elif isinstance(raw, str):
            seen.add(raw)

    canonical, error = resolve_markdown_path(root, canonical_raw, f"{prefix}.canonical")
    if error:
        findings.append(error)
    mirror, error = resolve_markdown_path(root, mirror_raw, f"{prefix}.mirror")
    if error:
        findings.append(error)
    if canonical is None or mirror is None:
        return findings

    if PurePosixPath(str(canonical_raw)).stem.endswith("_IT"):
        findings.append(f"{prefix}.canonical must not use the _IT suffix")
    expected_mirror = f"{PurePosixPath(str(canonical_raw)).stem}_IT.md"
    if PurePosixPath(str(mirror_raw)).name != expected_mirror:
        findings.append(f"{prefix}.mirror must be named {expected_mirror}")

    canonical_text = canonical.read_text(encoding="utf-8")
    mirror_text = mirror.read_text(encoding="utf-8")

    canonical_meta = CANONICAL_METADATA.match(canonical_text)
    if (
        len(CANONICAL_MARKER.findall(canonical_text)) != 1
        or not canonical_meta
        or canonical_meta.group("mirror") != mirror_raw
    ):
        findings.append(f"{prefix}.canonical has missing or incorrect mirror metadata")

    mirror_meta = TRANSLATION_METADATA.match(mirror_text)
    if (
        len(TRANSLATION_MARKER.findall(mirror_text)) != 1
        or not mirror_meta
        or mirror_meta.group("canonical") != canonical_raw
    ):
        findings.append(f"{prefix}.mirror has missing or incorrect canonical metadata")
    elif mirror_meta.group("digest") != sha256(canonical):
        findings.append(f"{prefix}.mirror has a stale canonical SHA-256")

    if not has_peer_link(canonical_text, str(mirror_raw)):
        findings.append(f"{prefix}.canonical does not link directly to its mirror")
    if not has_peer_link(mirror_text, str(canonical_raw)):
        findings.append(f"{prefix}.mirror does not link directly to its canonical document")

    if heading_signature(canonical_text) != heading_signature(mirror_text):
        findings.append(f"{prefix} has incompatible heading structure")
    if status_signature(canonical_text) != status_signature(mirror_text):
        findings.append(f"{prefix} has divergent status labels")
    if repository_path_signature(canonical_text) != repository_path_signature(mirror_text):
        findings.append(f"{prefix} has divergent repository paths")

    return findings


def validate_manifest(path: Path) -> list[str]:
    manifest = read_manifest(path)
    findings: list[str] = []
    if set(manifest) != TOP_LEVEL_KEYS:
        findings.append(
            f"manifest must contain exactly {sorted(TOP_LEVEL_KEYS)}; got {sorted(manifest)}"
        )
        return findings
    if manifest["schema"] != SCHEMA:
        findings.append(f"unsupported schema: {manifest['schema']!r}")
    if manifest["version"] != SCHEMA_VERSION:
        findings.append(f"unsupported schema version: {manifest['version']!r}")
    if manifest["hash"] != "sha256":
        findings.append(f"unsupported hash algorithm: {manifest['hash']!r}")
    pairs = manifest["pairs"]
    if not isinstance(pairs, list) or not pairs:
        findings.append("pairs must be a non-empty array")
        return findings

    root = repository_root(path)
    seen: set[str] = set()
    for index, pair in enumerate(pairs):
        findings.extend(validate_pair(root, index, pair, seen))

    platform_root = root / "docs" / "platform"
    markdown_paths: set[str] = set()
    for current, directories, files in os.walk(platform_root, followlinks=False):
        current_path = Path(current)
        for directory in sorted(tuple(directories)):
            candidate = current_path / directory
            if candidate.is_symlink():
                findings.append(
                    "symlinked path under docs/platform: "
                    f"{candidate.relative_to(root).as_posix()}"
                )
                directories.remove(directory)
        for filename in sorted(files):
            if not filename.endswith(".md"):
                continue
            document = current_path / filename
            relative = document.relative_to(root).as_posix()
            if document.is_symlink():
                findings.append(f"symlinked Markdown file under docs/platform: {relative}")
            elif document.is_file():
                markdown_paths.add(relative)
    for unpaired in sorted(markdown_paths - seen):
        findings.append(f"Markdown file is missing from the manifest: {unpaired}")
    for undeclared in sorted(seen - markdown_paths):
        findings.append(f"manifest path is not a regular platform Markdown file: {undeclared}")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args(argv)

    try:
        findings = validate_manifest(args.manifest.resolve(strict=True))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"translation-sync: error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    for finding in findings:
        print(f"translation-sync: {finding}")
    print(f"translation-sync: {len(findings)} finding(s)")
    return EXIT_FAIL if findings else EXIT_PASS


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    raise SystemExit(main())
