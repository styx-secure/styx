#!/usr/bin/env python3
"""Deterministic path and named-region scope guard for Issue #246."""

from __future__ import annotations

import argparse
import ast
import copy
import json
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True

from evidence_io import CanonicalJsonReport, content_sha256


BASE_SHA = "94f0a9b2781d45324199e6588629d23babedf746"
SCHEMA = "styx-o14-scope-report/v1"
VALIDATOR = "tools/protocol-review-model/validate.py"
MODEL = "docs/protocol/review/styx-app-kernel-v0-review-model.json"
REVIEW_TESTS = "tools/protocol-review-model/tests/"

ALLOWED_EXACT = {
    "docs/protocol/protocol-hardening-plan.md",
    "docs/protocol/styx-app-kernel-v0-decisions.md",
    "docs/protocol/styx-app-kernel-v0-commitment-encoding-profile.md",
    "docs/protocol/styx-app-kernel-v0-identifier-derivation-analysis.md",
    "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md",
    "docs/protocol/styx-app-kernel-v0-credential-succession-analysis.md",
    "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md",
    "docs/protocol/styx-app-kernel-v0-signature-suite-analysis.md",
    "docs/protocol/styx-app-kernel-v0-signature-suite-falsification-report.md",
    "docs/protocol/review/README.md",
    MODEL,
    "docs/security/STYX-THREAT-MODEL.md",
    "tools/causal-flow-simulator/README.md",
    VALIDATOR,
}
ALLOWED_PREFIXES = ("tools/causal-flow-simulator/o14/", REVIEW_TESTS)
FORBIDDEN_EXACT = {
    "CODEOWNERS", "AGENTS.md", "CLAUDE.md", "LICENSE", "REUSE.toml",
    "pubspec.yaml", "package.json", "package-lock.json",
    "docs/protocol/review/styx-app-kernel-v0-review-model.schema.json",
    "tools/causal-flow-simulator/model.py",
    "tools/causal-flow-simulator/payload_model.py",
    "tools/causal-flow-simulator/scenarios.py",
    "tools/causal-flow-simulator/payload_scenarios.py",
    "tools/causal-flow-simulator/causal_flow_simulator.py",
}
FORBIDDEN_PREFIXES = (
    ".github/", "LICENSES/", "conformance/", "specs/", "styx-js/",
    "packages/", "push_bridge_server/", "tools/causal-flow-simulator/tests/",
    "tools/causal-flow-simulator/v2/", "tools/causal-flow-simulator/v3/",
    "tools/causal-flow-simulator/c02k/", "tools/causal-flow-simulator/o06c/",
)


class ScopeError(ValueError):
    pass


def git(repo: Path, *arguments: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *arguments])


def forbidden(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if path in FORBIDDEN_EXACT or path.startswith(FORBIDDEN_PREFIXES):
        return True
    if name in {"package.json", "package-lock.json", "pubspec.yaml", "pubspec.lock"}:
        return True
    if path.endswith(".wasm"):
        return True
    if path.startswith("tools/causal-flow-simulator/o14/") and path.endswith((".json", ".bin")):
        return True
    return False


def allowed(path: str) -> bool:
    return path in ALLOWED_EXACT or path.startswith(ALLOWED_PREFIXES)


def changed_records(repo: Path, base: str, candidate: str) -> list[dict[str, object]]:
    raw = git(
        repo, "diff-tree", "-r", "-M", "-C50%", "--find-copies-harder", "-l0",
        "--name-status", "-z", "--no-commit-id", base, candidate,
    )
    parts = raw.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    records: list[dict[str, object]] = []
    index = 0
    while index < len(parts):
        status = parts[index].decode("ascii")
        index += 1
        count = 2 if status[:1] in {"R", "C"} else 1
        if index + count > len(parts):
            raise ScopeError("truncated diff-tree relation")
        paths = [parts[index + offset].decode("utf-8") for offset in range(count)]
        index += count
        for path in paths:
            if forbidden(path):
                raise ScopeError(f"forbidden {status} endpoint: {path}")
            if not allowed(path):
                raise ScopeError(f"out-of-scope {status} endpoint: {path}")
        records.append({"status": status, "paths": paths})
    return records


def blob(repo: Path, revision: str, path: str) -> bytes:
    return git(repo, "cat-file", "blob", f"{revision}:{path}")


def tree_mode(repo: Path, revision: str, path: str) -> str:
    raw = git(repo, "ls-tree", revision, "--", path).decode("utf-8")
    if not raw:
        raise ScopeError(f"missing tree endpoint: {revision}:{path}")
    return raw.split(None, 1)[0]


def enforce_text_artifacts(
    repo: Path, base: str, candidate: str, records: list[dict[str, object]]
) -> None:
    for record in records:
        status = str(record["status"])
        paths = list(record["paths"])
        if status.startswith(("R", "C")):
            endpoints = [(base, paths[0]), (candidate, paths[1])]
        elif status.startswith("D"):
            endpoints = [(base, paths[0])]
        else:
            endpoints = [(candidate, paths[0])]
        for revision, path in endpoints:
            mode = tree_mode(repo, revision, path)
            if mode in {"120000", "160000"}:
                raise ScopeError(f"symlink/submodule endpoint: {revision}:{path}")
            if b"\0" in blob(repo, revision, path):
                raise ScopeError(f"binary endpoint: {revision}:{path}")


def enforce_oracle_isolation(repo: Path, candidate: str) -> list[str]:
    """Fail if the verification-only reference oracle escapes o14 evidence code."""

    completed = subprocess.run(
        [
            "git", "-C", str(repo), "grep", "-l", "-F",
            "ed25519_reference", candidate, "--", "*.py", "*.js", "*.mjs", "*.dart",
        ],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode not in {0, 1}:
        raise ScopeError("unable to inspect verification-only oracle references")
    references = sorted(
        line.split(":", 1)[1]
        for line in completed.stdout.splitlines()
        if not line.split(":", 1)[1].startswith(
            "tools/causal-flow-simulator/o14/"
        )
    )
    if references:
        raise ScopeError(
            "verification-only oracle referenced outside o14: " + ",".join(references)
        )
    return references


def assignments(tree: ast.Module) -> tuple[dict[str, ast.expr | None], list[str]]:
    values: dict[str, ast.expr | None] = {}
    other: list[str] = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            values[node.targets[0].id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            values[node.target.id] = node.value
        else:
            other.append(ast.dump(node, include_attributes=False))
    return values, other


def _mask_assignment_values(source: str, names: set[str]) -> str:
    tree = ast.parse(source)
    values, _ = assignments(tree)
    spans: list[tuple[int, int, str]] = []
    encoded_lines = source.splitlines(keepends=True)
    offsets = [0]
    for line in encoded_lines:
        offsets.append(offsets[-1] + len(line))
    for name in names:
        node = values.get(name)
        if node is None or node.end_lineno is None or node.end_col_offset is None:
            raise ScopeError(f"missing assignment span: {name}")
        start = offsets[node.lineno - 1] + node.col_offset
        end = offsets[node.end_lineno - 1] + node.end_col_offset
        spans.append((start, end, f"@@STYX_O14_{name}@@"))
    normalized = source
    for start, end, marker in sorted(spans, reverse=True):
        normalized = normalized[:start] + marker + normalized[end:]
    return normalized


def enforce_validator_ast(repo: Path, base: str, candidate: str) -> list[str]:
    base_source = blob(repo, base, VALIDATOR).decode("utf-8")
    head_source = blob(repo, candidate, VALIDATOR).decode("utf-8")
    base_assign, base_other = assignments(ast.parse(base_source))
    head_assign, head_other = assignments(ast.parse(head_source))
    if base_other != head_other:
        raise ScopeError("validator control-flow/import/function/class AST drift")
    names = set(base_assign) | set(head_assign)
    changed = sorted(
        name for name in names
        if name not in base_assign or name not in head_assign
        or ast.dump(base_assign[name], include_attributes=False)
        != ast.dump(head_assign[name], include_attributes=False)
    )
    expected = {"EXPECTED_SOURCE_RECORDS", "EXPECTED_STATUS_BY_COLLECTION"}
    if set(changed) != expected:
        raise ScopeError("validator assignment delta is not exact: " + ",".join(changed))
    literal_values: dict[str, object] = {}
    base_values: dict[str, object] = {}
    for name in changed:
        try:
            literal_values[name] = ast.literal_eval(head_assign[name])
            base_values[name] = ast.literal_eval(base_assign[name])
        except Exception as error:
            raise ScopeError(f"non-literal validator assignment {name}: {error}") from error
    expected_sources = dict(base_values["EXPECTED_SOURCE_RECORDS"])
    expected_sources.update(
        {
            "signature_suite_analysis": (
                "docs/protocol/styx-app-kernel-v0-signature-suite-analysis.md",
                "evidence",
            ),
            "signature_suite_report": (
                "docs/protocol/styx-app-kernel-v0-signature-suite-falsification-report.md",
                "evidence",
            ),
        }
    )
    if literal_values["EXPECTED_SOURCE_RECORDS"] != expected_sources:
        raise ScopeError("validator source-record delta is not the exact two additions")
    expected_status = copy.deepcopy(base_values["EXPECTED_STATUS_BY_COLLECTION"])
    expected_status["blockers"]["O-14"] = "DECIDED"
    if literal_values["EXPECTED_STATUS_BY_COLLECTION"] != expected_status:
        raise ScopeError("validator status delta is not exactly O-14 OPEN to DECIDED")
    if _mask_assignment_values(base_source, expected) != _mask_assignment_values(
        head_source, expected
    ):
        raise ScopeError("validator byte drift outside exact assignment values")
    return changed


def enforce_review_tests(
    repo: Path, base: str, candidate: str, records: list[dict[str, object]]
) -> list[str]:
    existing = set(git(repo, "ls-tree", "-r", "--name-only", base, REVIEW_TESTS).decode().splitlines())
    for path in existing:
        if blob(repo, candidate, path) != blob(repo, base, path):
            raise ScopeError(f"pre-existing validator test/fixture drift: {path}")
    added: list[str] = []
    for record in records:
        status = str(record["status"])
        for path in record["paths"]:
            if not path.startswith(REVIEW_TESTS) or path in existing:
                continue
            relative = path[len(REVIEW_TESTS):]
            if status[:1] != "A" or "/" in relative or not relative.startswith("test_o14_") or not relative.endswith(".py"):
                raise ScopeError(f"invalid new validator test artifact: {status} {path}")
            added.append(path)
    return sorted(set(added))


def _mask_section(lines: list[str], heading: str, marker: str) -> None:
    matches = [i for i, line in enumerate(lines) if line.rstrip("\n") == heading]
    if len(matches) != 1:
        raise ScopeError(f"section selector count drift: {heading}")
    start = matches[0]
    level = len(heading) - len(heading.lstrip("#"))
    end = len(lines)
    for index in range(start + 1, len(lines)):
        stripped = lines[index].lstrip()
        if stripped.startswith("#"):
            next_level = len(stripped) - len(stripped.lstrip("#"))
            if next_level <= level:
                end = index
                break
    lines[start:end] = [marker + "\n"]


def _mask_block(
    lines: list[str], prefix: str | tuple[str, ...], marker: str, continuation: str = "  "
) -> None:
    choices = (prefix,) if isinstance(prefix, str) else prefix
    matches = [i for i, line in enumerate(lines) if any(line.startswith(value) for value in choices)]
    if len(matches) != 1:
        raise ScopeError(f"block selector count drift: {choices}")
    start = matches[0]
    end = start + 1
    while end < len(lines) and (lines[end].startswith(continuation) or not lines[end].strip()):
        if not lines[end].strip():
            break
        end += 1
    lines[start:end] = [marker + "\n"]


def _mask_line(lines: list[str], prefix: str | tuple[str, ...], marker: str) -> None:
    choices = (prefix,) if isinstance(prefix, str) else prefix
    matches = [i for i, line in enumerate(lines) if any(line.startswith(value) for value in choices)]
    if len(matches) != 1:
        raise ScopeError(f"line selector count drift: {choices}")
    lines[matches[0]] = marker + "\n"


def _mask_exact_variant(
    lines: list[str], variants: tuple[tuple[str, ...], ...], marker: str
) -> None:
    """Mask exactly one approved base/candidate text variant and nothing wider."""

    matches: list[tuple[int, int]] = []
    for variant in variants:
        expected = [line + "\n" for line in variant]
        width = len(expected)
        for start in range(0, len(lines) - width + 1):
            if lines[start : start + width] == expected:
                matches.append((start, start + width))
    if len(matches) != 1:
        raise ScopeError(f"exact variant selector count drift: {len(matches)}")
    start, end = matches[0]
    lines[start:end] = [marker + "\n"]


def _mask_paragraph_containing(
    lines: list[str], needle: str | tuple[str, ...], marker: str
) -> None:
    choices = (needle,) if isinstance(needle, str) else needle
    matches = [i for i, line in enumerate(lines) if any(value in line for value in choices)]
    if len(matches) != 1:
        raise ScopeError(f"paragraph selector count drift: {choices}")
    hit = matches[0]
    start = hit
    while start and lines[start - 1].strip() and not lines[start - 1].startswith("#"):
        start -= 1
    end = hit + 1
    while end < len(lines) and lines[end].strip() and not lines[end].startswith("#"):
        end += 1
    lines[start:end] = [marker + "\n"]


def normalize_normative(data: bytes, path: str) -> bytes:
    lines = data.decode("utf-8").splitlines(keepends=True)
    marker_index = 0

    def marker() -> str:
        nonlocal marker_index
        value = f"@@STYX_O14_ALLOWED_{marker_index}@@"
        marker_index += 1
        return value

    if path == "docs/protocol/protocol-hardening-plan.md":
        _mask_exact_variant(
            lines,
            (
                (
                    "4. **Resolve remaining C0.3 blockers.** Close or precisely scope O-07 genesis",
                    "   and checkpoint evidence, O-08 resource bounds, O-10 stable errors and O-14",
                    "   signature-suite binding. Resolve O-12 wherever a selected profile carries",
                    "   time.",
                ),
                (
                    "4. **Resolve remaining C0.3 blockers.** Close or precisely scope O-07 genesis",
                    "   and checkpoint evidence, O-08 resource bounds and O-10 stable errors. O-14",
                    "   is condition-bearing `DECIDED`; before any corpus authorization, replace its",
                    "   O-06c placeholder with the selected signature semantics and rerun the",
                    "   complete combined evidence. Resolve O-12 wherever a selected profile carries",
                    "   time.",
                ),
            ),
            marker(),
        )
        _mask_line(lines, "| O-07, O-08, O-10", marker())
        # The split adds a second adjacent row in the candidate.
        candidates = [i for i, line in enumerate(lines) if line.startswith("| O-14 |")]
        if len(candidates) > 1:
            raise ScopeError("duplicate O-14 objective row")
        if candidates:
            del lines[candidates[0]]
        _mask_exact_variant(
            lines,
            (
                (
                    "- O-07, O-08, O-10 and O-14 remain open; O-12 remains conditional as described",
                    "  in section 4; O-11, O-13, O-15 and O-16 retain their explicitly bounded",
                    "  non-blocking or downstream-blocking roles;",
                ),
                (
                    "- O-07, O-08 and O-10 remain open. O-14 is condition-bearing `DECIDED`, with",
                    "  Dart/browser support claims and the separately ratified O-06c",
                    "  placeholder-substitution rerun still gated. O-12 remains conditional as",
                    "  described in section 4; O-11, O-13, O-15 and O-16 retain their explicitly",
                    "  bounded non-blocking or downstream-blocking roles;",
                ),
            ),
            marker(),
        )
    elif path == "docs/protocol/styx-app-kernel-v0-decisions.md":
        _mask_section(lines, "### O-14 — Signature-suite registry and credential algorithm binding", marker())
        _mask_line(lines, ("O-06 through O-08, O-10", "O-06 through O-08 and O-10"), marker())
        _mask_exact_variant(
            lines,
            (
                (
                    "5. preserve and rerun the completed v1, v2, v3 and C0.2k baseline and mutation evidence after those changes, then",
                    "   close genesis/checkpoint evidence, cardinality, error and signature-suite",
                    "   questions O-07, O-08, O-10 and O-14, plus O-12 for any time-bearing profile,",
                    "   without product implementation authority; retain O-11 for the later",
                    "   wire/storage decision;",
                ),
                (
                    "5. preserve and rerun the completed v1, v2, v3 and C0.2k baseline and mutation evidence after those changes, then",
                    "   close genesis/checkpoint evidence, cardinality and error questions O-07,",
                    "   O-08 and O-10, preserve O-14's condition-bearing decision",
                    "   and discharge its separately ratified combined-evidence rerun, plus O-12 for any time-bearing profile,",
                    "   without product implementation authority; retain O-11 for the later",
                    "   wire/storage decision;",
                ),
            ),
            marker(),
        )
    elif path == "docs/protocol/styx-app-kernel-v0-commitment-encoding-profile.md":
        _mask_section(lines, "## 12. Remaining ownership and reopen predicates", marker())
    elif path == "docs/protocol/styx-app-kernel-v0-identifier-derivation-analysis.md":
        _mask_line(lines, "| Signature algorithm identifier |", marker())
        _mask_line(lines, "| O-02 / O-06 |", marker())
        _mask_section(lines, "## 11. C0.3 gate", marker())
    elif path == "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md":
        _mask_section(lines, "## 8. O-14 compatibility and reopen predicate", marker())
        _mask_section(lines, "## 12. Required next increments and gate", marker())
    elif path == "docs/protocol/styx-app-kernel-v0-credential-succession-analysis.md":
        _mask_section(lines, "## 9. Reopen and downstream gates", marker())
    elif path == "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md":
        for prefix in ("- **Status:**", "- **Authority:**", "- **Decision effect:**"):
            _mask_block(lines, prefix, marker())
        evidence = [i for i, line in enumerate(lines) if line.startswith("- **O-14 evidence baseline:**")]
        if len(evidence) > 1:
            raise ScopeError("duplicate O-14 evidence baseline")
        if evidence:
            start = evidence[0]
            end = start + 1
            while end < len(lines) and lines[end].startswith("  "):
                end += 1
            del lines[start:end]
        _mask_line(lines, "| `OB-K18` |", marker())
        _mask_line(lines, "| O-14 signature-suite registry |", marker())
        _mask_paragraph_containing(
            lines,
            ("O-14 likewise leaves verification mechanics", "O-14 selects verification mechanics"),
            marker(),
        )
        _mask_paragraph_containing(
            lines,
            ("signature suites and AP semantic injectivity", "O-14 supplies bounded guarded-signature evidence"),
            marker(),
        )
    elif path == "docs/security/STYX-THREAT-MODEL.md":
        _mask_exact_variant(
            lines,
            (
                (
                    "  evidence. O-06c now supplies bounded combined evidence; C0.3 remains",
                    "  `NO-GO` because O-07/O-08/O-10/O-14 and the corpus-path gate remain open.",
                ),
                (
                    "  evidence. O-06c now supplies bounded combined evidence; C0.3 remains",
                    "  `NO-GO` because O-07/O-08/O-10, O-14's retained combined-rerun condition and",
                    "  the corpus-path gate remain unresolved.",
                ),
            ),
            marker(),
        )
        amendment = [i for i, line in enumerate(lines) if line.startswith("- **O-14 amendment:**")]
        if len(amendment) > 1:
            raise ScopeError("duplicate O-14 threat-model amendment")
        if amendment:
            start = amendment[0]
            end = start + 1
            while end < len(lines) and lines[end].startswith("  "):
                end += 1
            del lines[start:end]
        _mask_exact_variant(
            lines,
            (
                (
                    "rotation model; concrete profile grants/bounds and the O-14 signature-suite",
                    "registry remain open. C0.2j's M20 rule deliberately keeps every K-admitted",
                ),
                (
                    "rotation model; concrete profile grants/bounds remain open, while O-14 fixes",
                    "only the guarded signature language. C0.2j's M20 rule deliberately keeps every K-admitted",
                ),
            ),
            marker(),
        )
        _mask_line(lines, "| A2 valid but unauthorized actor |", marker())
    elif path == "docs/protocol/review/README.md":
        snapshot = [i for i, line in enumerate(lines) if line.startswith("The O-14 snapshot adds")]
        if len(snapshot) > 1:
            raise ScopeError("duplicate O-14 review snapshot")
        if snapshot:
            start = snapshot[0]
            previous = start - 1
            while previous >= 0 and not lines[previous].strip():
                previous -= 1
            paragraph_start = previous
            while paragraph_start > 0 and lines[paragraph_start - 1].strip():
                paragraph_start -= 1
            if not any("O-06c snapshot adds" in line for line in lines[paragraph_start : previous + 1]):
                raise ScopeError("O-14 review snapshot is not adjacent to O-06c snapshot")
            end = start + 1
            while end < len(lines) and lines[end].strip():
                end += 1
            if end < len(lines) and not lines[end].strip():
                end += 1
            del lines[start:end]
        _mask_exact_variant(
            lines,
            (
                (
                    "bounded combined-construction evidence. O-07, O-08, O-10 and O-14 remain open",
                    "blockers for C0.3. While C0.3 is `NO_GO`, C0.3 itself blocks corpus,",
                    "implementation alignment, demo, product and sensitive-use claims.",
                ),
                (
                    "bounded combined-construction evidence. O-14 selects only its bounded guarded",
                    "signature language and remains a condition-bearing C0.3 dependency until its",
                    "separately ratified combined rerun passes. O-07, O-08 and O-10 remain open",
                    "blockers for C0.3. While C0.3 is `NO_GO`, C0.3 itself blocks corpus,",
                    "implementation alignment, demo, product and sensitive-use claims.",
                ),
            ),
            marker(),
        )
    elif path == "tools/causal-flow-simulator/README.md":
        heading = "## O-14 signature-suite evidence package"
        if any(line.rstrip("\n") == heading for line in lines):
            index = next(i for i, line in enumerate(lines) if line.rstrip("\n") == heading)
            if index and not lines[index - 1].strip():
                index -= 1
            del lines[index:]
    else:
        raise ScopeError(f"no normative boundary rule: {path}")
    return "".join(lines).encode("utf-8")


NORMATIVE_BOUNDED = {
    "docs/protocol/protocol-hardening-plan.md",
    "docs/protocol/styx-app-kernel-v0-decisions.md",
    "docs/protocol/styx-app-kernel-v0-commitment-encoding-profile.md",
    "docs/protocol/styx-app-kernel-v0-identifier-derivation-analysis.md",
    "docs/protocol/styx-app-kernel-v0-transcript-encoding-profile.md",
    "docs/protocol/styx-app-kernel-v0-credential-succession-analysis.md",
    "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md",
    "docs/security/STYX-THREAT-MODEL.md",
    "docs/protocol/review/README.md",
    "tools/causal-flow-simulator/README.md",
}


def enforce_named_regions(repo: Path, base: str, candidate: str) -> dict[str, str]:
    digests: dict[str, str] = {}
    for path in sorted(NORMATIVE_BOUNDED):
        before = normalize_normative(blob(repo, base, path), path)
        after = normalize_normative(blob(repo, candidate, path), path)
        if before != after:
            raise ScopeError(f"unnamed normative-document drift: {path}")
        digests[path] = content_sha256(after)
    return digests


def enforce_review_model(repo: Path, base: str, candidate: str) -> None:
    before = json.loads(blob(repo, base, MODEL))
    after = json.loads(blob(repo, candidate, MODEL))
    before_ids = {item["id"] for item in before["sources"]}
    new_sources = [item for item in after["sources"] if item["id"] not in before_ids]
    expected_new = [
        {
            "authority": "evidence",
            "id": "signature_suite_analysis",
            "path": "docs/protocol/styx-app-kernel-v0-signature-suite-analysis.md",
        },
        {
            "authority": "evidence",
            "id": "signature_suite_report",
            "path": "docs/protocol/styx-app-kernel-v0-signature-suite-falsification-report.md",
        },
    ]
    if len(new_sources) != 2:
        raise ScopeError("review model must append exactly two sources")
    for actual, expected in zip(new_sources, expected_new, strict=True):
        if {key: actual.get(key) for key in expected} != expected or set(actual) != set(expected) | {"sha256"}:
            raise ScopeError("unexpected appended O-14 source record")
    normalized_before = copy.deepcopy(before)
    normalized_after = copy.deepcopy(after)
    normalized_after["sources"] = [
        item for item in normalized_after["sources"] if item["id"] in before_ids
    ]
    after_by_id = {item["id"]: item for item in normalized_after["sources"]}
    for item in normalized_before["sources"]:
        peer = after_by_id[item["id"]]
        if peer["sha256"] != item["sha256"]:
            peer["sha256"] = item["sha256"]
    before_o14 = next(item for item in normalized_before["blockers"] if item["id"] == "O-14")
    after_o14 = next(item for item in normalized_after["blockers"] if item["id"] == "O-14")
    if after_o14["status"] != "DECIDED" or not after_o14["reason"].startswith("CONDITION-BEARING:"):
        raise ScopeError("O-14 model status/reason is not condition-bearing DECIDED")
    expected_citations = [
        {
            "anchor": "# Styx O-14 signature-suite analysis",
            "source_id": "signature_suite_analysis",
        },
        {
            "anchor": "# Styx O-14 signature-suite falsification report",
            "source_id": "signature_suite_report",
        },
    ]
    if after_o14["citations"] != before_o14["citations"] + expected_citations:
        raise ScopeError("O-14 evidence citations are not exact append-only additions")
    after_o14["status"] = before_o14["status"]
    after_o14["reason"] = before_o14["reason"]
    after_o14["citations"] = before_o14["citations"]
    if normalized_after != normalized_before:
        raise ScopeError("review model drift outside authorized O-14 fields")


def build_report(repo: Path, base_argument: str, candidate_argument: str) -> dict[str, object]:
    base = git(repo, "rev-parse", f"{base_argument}^{{commit}}").decode().strip()
    candidate = git(repo, "rev-parse", f"{candidate_argument}^{{commit}}").decode().strip()
    if base_argument != BASE_SHA or base != BASE_SHA:
        raise ScopeError("contract base mismatch")
    records = changed_records(repo, base, candidate)
    enforce_text_artifacts(repo, base, candidate, records)
    oracle_references = enforce_oracle_isolation(repo, candidate)
    validator_assignments = enforce_validator_ast(repo, base, candidate)
    new_review_tests = enforce_review_tests(repo, base, candidate, records)
    region_digests = enforce_named_regions(repo, base, candidate)
    enforce_review_model(repo, base, candidate)
    return {
        "schema": SCHEMA,
        "base_commit": base,
        "candidate_identity_location": "immutable_pr_evidence",
        "changed_relation": records,
        "changed_endpoint_count": sum(len(record["paths"]) for record in records),
        "validator_assignments_changed": validator_assignments,
        "new_review_tests": new_review_tests,
        "oracle_references_outside_o14": oracle_references,
        "normalized_region_sha256": region_digests,
        "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--base", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--mode", choices=("strict",), default="strict")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = build_report(args.repo_root.resolve(), args.base, args.candidate)
        CanonicalJsonReport.store(args.output, report)
    except (ScopeError, OSError, UnicodeError, subprocess.CalledProcessError, ValueError) as error:
        print(f"O-14 scope failure: {error}", file=sys.stderr)
        return 2
    print(f"O-14 scope verdict=PASS records={len(report['changed_relation'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
