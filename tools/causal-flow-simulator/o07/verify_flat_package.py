#!/usr/bin/env python3
"""Fail closed on incomplete, extra or non-flat O-07 review packages."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import stat
import subprocess
import sys


MANIFEST_NAME = "SHA256SUMS.txt"
MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})  ([^/\\\r\n]+)$")


def verify_flat_package(package_root: Path, manifest: Path | None = None) -> int:
    """Validate exact names and hashes, then run plain sha256sum verification."""

    if package_root.is_symlink() or not package_root.is_dir():
        raise ValueError("package root must be a real directory")
    root = package_root.resolve(strict=True)
    manifest_path = manifest or (root / MANIFEST_NAME)
    if manifest_path.is_symlink():
        raise ValueError("manifest must not be a symlink")
    manifest_path = manifest_path.resolve(strict=True)
    if manifest_path.parent != root or manifest_path.name != MANIFEST_NAME:
        raise ValueError("manifest must be the canonical flat package manifest")
    if not stat.S_ISREG(manifest_path.stat().st_mode):
        raise ValueError("manifest must be a regular file")

    expected: dict[str, str] = {}
    lines = manifest_path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise ValueError("manifest must not be empty")
    for line in lines:
        match = MANIFEST_LINE.fullmatch(line)
        if match is None:
            raise ValueError("manifest line is not canonical")
        digest, name = match.groups()
        if name == MANIFEST_NAME or name in expected:
            raise ValueError("duplicate or self-referential manifest name")
        expected[name] = digest

    actual: set[str] = set()
    for entry in root.iterdir():
        if entry.name == MANIFEST_NAME:
            continue
        metadata = entry.lstat()
        if entry.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise ValueError("package contains a non-regular artifact")
        actual.add(entry.name)
    if actual != set(expected):
        raise ValueError("package artifact set does not equal the manifest")
    for name, digest in expected.items():
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
            raise ValueError("package artifact digest mismatch")

    subprocess.run(
        ["sha256sum", "-c", MANIFEST_NAME],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return len(expected)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-root", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        count = verify_flat_package(args.package_root)
    except (OSError, UnicodeError, ValueError, subprocess.CalledProcessError) as error:
        print(f"O-07 package preflight failed: {error}", file=sys.stderr)
        return 2
    print(f"O-07 PACKAGE PREFLIGHT verdict=PASS artifacts={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
