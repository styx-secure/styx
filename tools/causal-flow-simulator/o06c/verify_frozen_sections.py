#!/usr/bin/env python3
"""Verify the six raw normative sections frozen by the O-06c handoff."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True

from common import sha256_hex, write_report


BASE_SHA = "3f439189e0cbe4071f642c693dbb196b477a48ea"
REPORT_SCHEMA = "styx-o06c-frozen-section-report/v1"


@dataclass(frozen=True)
class FrozenSection:
    identifier: str
    path: str
    heading_prefix: bytes
    expected_sha256: str


FROZEN_SECTIONS = (
    FrozenSection(
        "O06B1_SECTION_4",
        "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md",
        b"## 4.",
        "5b6bc4041b028ead4821cd7d33bb102255d7df728309e2e8bef232f16c9e3fb3",
    ),
    FrozenSection(
        "O06B2_SECTION_6",
        "docs/protocol/styx-app-kernel-v0-commitment-encoding-profile.md",
        b"## 6.",
        "14bcde53d5534584e3cd1ba2503a3bb755df112ed0d42485cf9f1bef61b1f7f8",
    ),
    FrozenSection(
        "O06B2_SECTION_2",
        "docs/protocol/styx-app-kernel-v0-commitment-encoding-profile.md",
        b"## 2.",
        "9efff974cbc69ae58a2c2c883347c90129587cf9a7355f046c5b0f437e1234b1",
    ),
    FrozenSection(
        "O06B1_SECTION_5",
        "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md",
        b"## 5.",
        "f3f074befc0d258345b2e067f97a0eabbb08069591fb30b7c508f2ff56d5d8c1",
    ),
    FrozenSection(
        "O06B2_SECTION_3",
        "docs/protocol/styx-app-kernel-v0-commitment-encoding-profile.md",
        b"## 3.",
        "4ec776a1bbb8bb044de235ec0a8e34a61158d7d30e33bf1146d1787b6765abf0",
    ),
    FrozenSection(
        "O06B2_SECTION_4",
        "docs/protocol/styx-app-kernel-v0-commitment-encoding-profile.md",
        b"## 4.",
        "ce6172a9843a43628fff2f36c70336b5df49e8713b5ea3822f9b6e8e5f57037e",
    ),
)


class FrozenSectionError(ValueError):
    """The raw-section extraction rule was not satisfied."""


def digest_status(actual: str, expected: str) -> str:
    """Return the only success state for an exact full-width digest match."""

    return "PASS" if actual == expected else "DIGEST_MISMATCH"


def _fence_marker(line: bytes) -> tuple[int, int] | None:
    stripped = line.rstrip(b"\r\n")
    spaces = len(stripped) - len(stripped.lstrip(b" "))
    if spaces > 3:
        return None
    candidate = stripped[spaces:]
    if not candidate or candidate[:1] not in (b"`", b"~"):
        return None
    marker = candidate[:1]
    width = len(candidate) - len(candidate.lstrip(marker))
    return (marker[0], width) if width >= 3 else None


def extract_raw_section(document: bytes, heading_prefix: bytes) -> bytes:
    """Apply the frozen byte rule without Markdown normalization."""

    lines = document.splitlines(keepends=True)
    starts = [
        index
        for index, line in enumerate(lines)
        if line.startswith(heading_prefix)
    ]
    if len(starts) != 1:
        raise FrozenSectionError(
            f"heading count for {heading_prefix.decode('ascii')} is {len(starts)}"
        )
    start = starts[0]
    fence: tuple[int, int] | None = None
    end: int | None = None
    for index in range(start + 1, len(lines)):
        line = lines[index]
        marker = _fence_marker(line)
        if marker is not None:
            if fence is None:
                fence = marker
            elif marker[0] == fence[0] and marker[1] >= fence[1]:
                fence = None
            continue
        if line.startswith(b"## "):
            if fence is not None:
                raise FrozenSectionError("column-zero section heading inside fence")
            end = index
            break
    if end is None:
        raise FrozenSectionError("selected section has no following level-two heading")
    return b"".join(lines[start:end])


def _git(repo: Path, *arguments: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *arguments])


def build_report(
    repo: Path, candidate: str, expected_base: str
) -> tuple[dict[str, object], bool]:
    resolved_base = _git(repo, "rev-parse", f"{expected_base}^{{commit}}").decode().strip()
    resolved_candidate = _git(repo, "rev-parse", f"{candidate}^{{commit}}").decode().strip()
    if resolved_base != BASE_SHA or expected_base != BASE_SHA:
        raise FrozenSectionError("unexpected contract base")
    records = []
    passed = True
    for section in FROZEN_SECTIONS:
        document = _git(repo, "cat-file", "blob", f"{resolved_candidate}:{section.path}")
        try:
            raw = extract_raw_section(document, section.heading_prefix)
            actual = sha256_hex(raw)
            status = digest_status(actual, section.expected_sha256)
        except FrozenSectionError as error:
            raw = b""
            actual = None
            status = f"EXTRACTION_ERROR:{error}"
        if status != "PASS":
            passed = False
        records.append(
            {
                "id": section.identifier,
                "path": section.path,
                "heading": section.heading_prefix.decode("ascii"),
                "octets": len(raw),
                "expected_sha256": section.expected_sha256,
                "actual_sha256": actual,
                "status": status,
            }
        )
    report: dict[str, object] = {
        "schema": REPORT_SCHEMA,
        "mode": "strict",
        "expected_base": BASE_SHA,
        # Candidate identity belongs in immutable PR evidence.  Keeping it out of
        # a report whose digest is recorded in a tracked normative document is
        # what makes that digest non-self-referential.
        "candidate_identity_location": "immutable_pr_evidence",
        "sections": records,
        "verdict": "PASS" if passed else "FAIL",
    }
    return report, passed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--expected-base", required=True)
    parser.add_argument("--mode", required=True, choices=("strict",))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report, passed = build_report(
            args.repo_root.resolve(), args.candidate, args.expected_base
        )
        write_report(args.output, report)
    except (FrozenSectionError, OSError, subprocess.CalledProcessError) as error:
        print(f"frozen-section verification failure: {error}", file=sys.stderr)
        return 2
    print(f"O-06c frozen sections verdict={report['verdict']} count={len(report['sections'])}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
