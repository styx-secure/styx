#!/usr/bin/env python3
"""Deterministically evaluate the bounded protocol-hardening exit evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.request


BASE_SHA = "636c12c7da68fde309767732c42284f92b83ade3"
FREEZE_SHA = "8f30f1940e4417fcb47b156b08c2242f405dc09b"
FIRST_PARENT_SHA256 = "1b433bf9bf65339a044c42dd1956472df5b3061d67736cc7c095917bd19f1f6a"
ISSUE_NUMBER = 287
ISSUE_BODY_SHA256 = "6e48e020820cbb7427d9e7334a9f12a336e2684397a04dda6c7c41b7f8991239"
MAVERDE_ID = 141346846
MANEXADA_ID = 314148709
MAX_PROVIDER_BYTES = 256 * 1024
ISSUE_API_URL = "https://api.github.com/repos/styx-secure/styx/issues/287"
PR_NUMBER = 288

PINNED_BASE_BLOBS = {
    "AGENTS.md": "50588a0cf2309af8fdf1551cd09facb6338e2eba8362d4e13ab22390a2f5bc93",
    "CLAUDE.md": "385deb4ea78ee8ee9237c9ab3173f57ff61ee28f892e00d96cebc8b0ed53620f",
    "docs/PROJECT_BRIEF.md": "f3eb56d4c502e7da90702022fb88724d6d69c6240955a52052b1ba8f211d1cff",
    "docs/platform/integration-roadmap.md": "2a1d99287cdfff6e8dc98368a8f257c32a52c6be1e4717487c443ebe8bfa698f",
    "docs/platform/integration-roadmap_IT.md": "e0405265315f0029c261f265ff49e4af87ac8213aa47fc5bf5912d06aadc9dac",
    "docs/protocol/protocol-hardening-plan.md": "008719aa3ec1510572c0a1eddba42dca52566482384a0ff1353a6e705d46ed6f",
    "docs/protocol/review/README.md": "218d4fce6aa7211e6cf5bea8ae83e7ddd6242ba108541a1c25767d01a2784ffb",
    "docs/protocol/review/styx-app-kernel-v0-review-model.json": "5b5208993973f4543688777026130cd3207e637aac5986b3b7fe757d0979e77e",
    "docs/protocol/styx-app-kernel-v0-decisions.md": "3e1c31db9a1c14057578aac216ee63ab3f40dfe3557fb8f051338697e2440edc",
    "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md": "3ea43a5b6c9b93a19b2b17ab6a54815583275ea7a544de7e5102b294b13f53db",
    "docs/protocol/styx-secure-session-v0-decisions.md": "235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07",
    "docs/security/STYX-THREAT-MODEL.md": "8863ce4b2ef697055e95da22e0a2fbb630172cdf3f5fd0c91b27ec02f9d2ba54",
    "docs/protocol/review/styx-app-kernel-v0-review-model.schema.json": "9975d7ad63bb00ff3351bcf7e740f315a5cbac3acf9b13ac36901e421b46f846",
    "tools/protocol-review-model/validate.py": "e79caecde38c457ed79036d339c67b7aa7a394e37708ba76f0aa715ce0092f3b",
    "tools/docs-claims-lint/claims_lint.py": "8922c9f76a2cba57ed908fe7fdf9cdd29ae1606bf14c5d0690fb57cad8dde1b5",
    "tools/docs-translation-sync/check.py": "dce868a3c6f42eedd67423698659bf2d1ddfbce2913f001f37d62895b1b25603",
    "docs/platform/translation-pairs.json": "402872e69808e035aac7112a518268d5ea7db7cfc95126d5e12e30da07452560",
}

FROZEN_LITERAL_FILES = {
    "docs/protocol/styx-app-kernel-v0-decisions.md",
    "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md",
    "docs/protocol/styx-secure-session-v0-decisions.md",
    "docs/security/STYX-THREAT-MODEL.md",
}
FROZEN_PREFIXES = (
    "conformance/",
    "tools/causal-flow-simulator/",
    "tools/protocol-review-model/",
)

EVIDENCE_PATHS = {
    "decision_registries": (
        "docs/protocol/styx-app-kernel-v0-decisions.md",
        "docs/protocol/styx-secure-session-v0-decisions.md",
    ),
    "review_model": ("docs/protocol/review/styx-app-kernel-v0-review-model.json",),
    "review_records": ("docs/protocol/review/README.md",),
    "protocol_plan": ("docs/protocol/protocol-hardening-plan.md",),
    "c03_evidence": (
        "conformance/application-protocol/c03/manifest.json",
        "tools/causal-flow-simulator/c03/corpus-inventory.json",
        "tools/causal-flow-simulator/c03/corpus-source-map.json",
        "conformance/application-protocol/c03/adversarial-mutations.json",
    ),
    "ss0_evidence": (
        "tools/causal-flow-simulator/ss0/source-inventory.json",
        "tools/causal-flow-simulator/ss0/source-mutants.json",
    ),
    "c03_cross_runtime": (
        "tools/causal-flow-simulator/c03/corpus_model.py",
        "tools/causal-flow-simulator/c03/node_adapter.mjs",
    ),
    "ss0_cross_runtime": (
        "tools/causal-flow-simulator/ss0/model.py",
        "tools/causal-flow-simulator/ss0/node_adapter.mjs",
    ),
    "resource_evidence": (
        "tools/causal-flow-simulator/o08/resource-envelope.candidate.json",
        "tools/causal-flow-simulator/ss0/phase-b-anchor.json",
    ),
    "threat_and_responsibility": (
        "docs/security/STYX-THREAT-MODEL.md",
        "docs/protocol/styx-app-kernel-v0-responsibility-matrix.md",
    ),
    "c03_license_boundary": (
        "conformance/application-protocol/c03/manifest.json",
        "LICENSES/Apache-2.0.txt",
    ),
}


class ExitError(RuntimeError):
    """The phase-exit evidence failed closed."""


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ExitError(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def monotone_verdict(eligibility: str, verdict: str) -> bool:
    return verdict == "NO_GO" or (
        verdict == "GO" and eligibility == "ELIGIBLE_FOR_GO"
    ) or (
        verdict == "BOUNDED_GO"
        and eligibility in {"ELIGIBLE_FOR_GO", "ELIGIBLE_FOR_BOUNDED_GO"}
    )


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def provider_opener() -> urllib.request.OpenerDirector:
    context = ssl.create_default_context()
    require(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname, "provider TLS is not strict")
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
        NoRedirect(),
    )


def fetch_provider_json(url: str) -> tuple[dict[str, object], bytes]:
    require(sys.flags.isolated == 1, "provider fetch requires Python isolated mode")
    require(sys.flags.no_site == 1, "provider fetch requires site isolation")
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with provider_opener().open(request, timeout=30) as response:
            require(response.geturl() == url, "provider response URL mismatch")
            length = response.headers.get("Content-Length")
            if length is not None:
                require(int(length) <= MAX_PROVIDER_BYTES, "provider response oversized")
            raw = response.read(MAX_PROVIDER_BYTES + 1)
    except (urllib.error.URLError, TimeoutError, ValueError) as error:
        raise ExitError("provider fetch failed") from error
    require(len(raw) <= MAX_PROVIDER_BYTES, "provider response oversized")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ExitError("provider response is not JSON") from error
    require(isinstance(value, dict), "provider response must be an object")
    return value, raw


def verdict_url(comment_id: str) -> str:
    require(re.fullmatch(r"[1-9][0-9]*", comment_id) is not None, "invalid verdict comment id")
    return f"https://api.github.com/repos/styx-secure/styx/issues/comments/{comment_id}"


def provider_projection(comment: dict[str, object]) -> dict[str, object]:
    user = comment.get("user")
    require(isinstance(user, dict), "provider user missing")
    keys = {"id", "url", "issue_url", "created_at", "updated_at", "body"}
    require(all(key in comment for key in keys), "provider projection field missing")
    return {
        "id": comment["id"],
        "url": comment["url"],
        "issue_url": comment["issue_url"],
        "user": {"id": user.get("id"), "login": user.get("login")},
        "created_at": comment["created_at"],
        "updated_at": comment["updated_at"],
        "body": comment["body"],
    }


def validate_verdict_comment(
    comment: dict[str, object], *, comment_id: str, phase_a_head: str,
    report_sha: str, frozen_sha: str, audit_sha: str, eligibility: str,
) -> dict[str, object]:
    url = verdict_url(comment_id)
    projection = provider_projection(comment)
    require(projection["id"] == int(comment_id), "verdict comment id mismatch")
    require(projection["url"] == url, "verdict comment URL mismatch")
    require(projection["issue_url"] == ISSUE_API_URL, "verdict Issue mismatch")
    require(projection["user"] == {"id": MAVERDE_ID, "login": "maverde73"}, "verdict operator mismatch")
    require(projection["created_at"] == projection["updated_at"], "verdict comment was edited")
    body = projection["body"]
    require(isinstance(body, str), "verdict body missing")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as error:
        raise ExitError("verdict body must be one JSON object") from error
    require(isinstance(payload, dict), "verdict body must be one JSON object")
    expected = {
        "schema", "issue_number", "issue_body_sha256", "operator", "base_sha",
        "phase_a_head", "phase_exit_report_sha256", "frozen_manifest_sha256",
        "first_parent_audit_sha256", "mechanical_eligibility", "verdict",
    }
    require(set(payload) == expected, "verdict body shape mismatch")
    require(payload["schema"] == "styx-protocol-phase-exit-verdict/v1", "verdict schema mismatch")
    require(payload["issue_number"] == ISSUE_NUMBER, "verdict Issue number mismatch")
    require(payload["issue_body_sha256"] == ISSUE_BODY_SHA256, "verdict Issue digest mismatch")
    require(payload["operator"] == "maverde73", "verdict operator body mismatch")
    require(payload["base_sha"] == BASE_SHA, "verdict Base mismatch")
    require(payload["phase_a_head"] == phase_a_head, "verdict Phase-A HEAD mismatch")
    require(payload["phase_exit_report_sha256"] == report_sha, "verdict report mismatch")
    require(payload["frozen_manifest_sha256"] == frozen_sha, "verdict frozen manifest mismatch")
    require(payload["first_parent_audit_sha256"] == audit_sha, "verdict audit mismatch")
    require(payload["mechanical_eligibility"] == eligibility, "verdict eligibility mismatch")
    require(payload["verdict"] in {"GO", "BOUNDED_GO", "NO_GO"}, "unknown verdict")
    require(monotone_verdict(eligibility, payload["verdict"]), "verdict is not monotone")
    return {
        "provider_projection_sha256": sha256(canonical_bytes(projection)),
        "verdict": payload["verdict"],
        "mechanical_eligibility": eligibility,
        "comment_id": int(comment_id),
    }


def run_git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(
        ("/usr/bin/git", "-C", str(repo), *args),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"LANG": "C", "LC_ALL": "C", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"},
    )
    require(result.returncode == 0, f"git failed: {' '.join(args)}")
    return result.stdout


def verify_base_pins(repo: Path) -> None:
    for path, expected in sorted(PINNED_BASE_BLOBS.items()):
        observed = sha256(run_git(repo, "show", f"{BASE_SHA}:{path}"))
        require(observed == expected, f"Base digest mismatch: {path}")


def first_parent_commits(repo: Path) -> list[str]:
    raw = run_git(repo, "rev-list", "--first-parent", "--reverse", f"{FREEZE_SHA}^..{BASE_SHA}")
    require(sha256(raw) == FIRST_PARENT_SHA256, "first-parent identity mismatch")
    lines = raw.decode("ascii").splitlines()
    require(len(lines) == 23, "first-parent count mismatch")
    require(all(re.fullmatch(r"[0-9a-f]{40}", line) for line in lines), "invalid first-parent identity")
    return lines


def frozen_paths(repo: Path) -> list[str]:
    raw = run_git(repo, "ls-tree", "-r", "--name-only", BASE_SHA, "--", *FROZEN_PREFIXES, *sorted(FROZEN_LITERAL_FILES))
    paths = raw.decode().splitlines()
    require(paths == sorted(set(paths)), "frozen Base path set is not canonical")
    return paths


def frozen_manifest(repo: Path) -> tuple[str, dict[str, str]]:
    paths = frozen_paths(repo)
    tracked = set(run_git(repo, "ls-files", "--cached", "--others", "--exclude-standard", "--", *FROZEN_PREFIXES, *sorted(FROZEN_LITERAL_FILES)).decode().splitlines())
    require(tracked == set(paths), "frozen path set drift")
    mapping: dict[str, str] = {}
    lines: list[str] = []
    for path in paths:
        current = repo / path
        require(current.is_file() and not current.is_symlink(), f"invalid frozen path: {path}")
        expected = sha256(run_git(repo, "show", f"{BASE_SHA}:{path}"))
        observed = sha256(current.read_bytes())
        require(observed == expected, f"frozen byte drift: {path}")
        mapping[path] = observed
        lines.append(f"{path} {observed}\n")
    return sha256("".join(lines).encode()), mapping


def audit_identity(repo: Path, commits: list[str]) -> str:
    data = (repo / "docs/protocol/protocol-hardening-plan.md").read_bytes()
    start_marker = b"<!-- styx-section8-exception-audit:v1:start -->"
    end_marker = b"<!-- styx-section8-exception-audit:v1:end -->"
    require(data.count(start_marker) == 1 and data.count(end_marker) == 1, "audit markers invalid")
    body = data.split(start_marker, 1)[1].split(end_marker, 1)[0]
    rows = re.findall(rb"^\| `([0-9a-f]{40})` \|", body, flags=re.MULTILINE)
    observed = [row.decode() for row in rows]
    require(observed == commits, "first-parent audit rows mismatch")
    return sha256(body)


def evidence_digest(repo: Path, evidence_id: str, frozen_sha: str, audit_sha: str) -> str:
    if evidence_id == "frozen_manifest":
        return frozen_sha
    if evidence_id == "first_parent_audit":
        return audit_sha
    require(evidence_id in EVIDENCE_PATHS, f"unknown evidence id: {evidence_id}")
    manifest: list[dict[str, str]] = []
    for path in EVIDENCE_PATHS[evidence_id]:
        candidate = repo / path
        require(candidate.is_file() and not candidate.is_symlink(), f"missing evidence: {path}")
        manifest.append({"path": path, "sha256": sha256(candidate.read_bytes())})
    return sha256(canonical_bytes(manifest))


def load_registry(repo: Path) -> dict[str, object]:
    path = repo / "tools/protocol-phase-exit/exit-registry.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    require(value.get("schema") == "styx-protocol-phase-exit-registry/v1", "registry schema mismatch")
    conditions = value.get("conditions")
    require(isinstance(conditions, list), "registry conditions missing")
    expected = [f"EXIT-{index:02d}" for index in range(1, 12)]
    require([item.get("id") for item in conditions if isinstance(item, dict)] == expected, "condition set mismatch")
    for item in conditions:
        require(set(item) == {"id", "applicability", "disposition", "required_evidence_ids", "residual_risks", "reopen_triggers"}, f"condition shape mismatch: {item.get('id')}")
        disposition = item["disposition"]
        if item["id"] in {"EXIT-08", "EXIT-09"}:
            require(disposition == "HUMAN_GATE_PENDING", "external gate must be pending")
        else:
            require(disposition in {"PASS", "CONDITIONAL_EXCLUSION", "FAIL"}, "invalid mechanical disposition")
    return value


def build_report(repo: Path) -> dict[str, object]:
    verify_base_pins(repo)
    commits = first_parent_commits(repo)
    frozen_sha, _ = frozen_manifest(repo)
    audit_sha = audit_identity(repo, commits)
    registry = load_registry(repo)
    records: list[dict[str, object]] = []
    mechanical: list[str] = []
    for item in registry["conditions"]:
        evidence_ids = item["required_evidence_ids"]
        observed = {evidence_id: evidence_digest(repo, evidence_id, frozen_sha, audit_sha) for evidence_id in evidence_ids}
        record = dict(item)
        record["observed_evidence_sha256"] = observed
        records.append(record)
        if item["id"] not in {"EXIT-08", "EXIT-09"}:
            mechanical.append(item["disposition"])
    if "FAIL" in mechanical:
        eligibility = "REQUIRES_NO_GO"
    elif "CONDITIONAL_EXCLUSION" in mechanical:
        eligibility = "ELIGIBLE_FOR_BOUNDED_GO"
    else:
        eligibility = "ELIGIBLE_FOR_GO"
    return {
        "schema": "styx-protocol-phase-exit-report/v1",
        "issue_body_sha256": ISSUE_BODY_SHA256,
        "eligibility": eligibility,
        "frozen_manifest_sha256": frozen_sha,
        "first_parent_audit_sha256": audit_sha,
        "conditions": records,
        "non_authorizations": [
            "adapter", "authenticated_persistence", "sdk", "transport_delivery",
            "ss_corpus_until_k11_ss", "product", "demo", "deployment", "sensitive_use",
        ],
    }


def write_report(report: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(canonical_bytes(report))


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verdict-comment-id")
    parser.add_argument("--phase-a-head")
    parser.add_argument("--phase-a-report-sha256")
    parser.add_argument("--provider-output", type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        require(args.base == BASE_SHA, "Base argument mismatch")
        repo = args.repo_root.resolve(strict=True)
        report = build_report(repo)
        write_report(report, args.output)
        if args.verdict_comment_id is not None:
            require(args.phase_a_head is not None, "Phase-A HEAD required")
            require(args.phase_a_report_sha256 is not None, "Phase-A report digest required")
            require(args.provider_output is not None, "provider output required")
            url = verdict_url(args.verdict_comment_id)
            comment, raw = fetch_provider_json(url)
            result = validate_verdict_comment(
                comment,
                comment_id=args.verdict_comment_id,
                phase_a_head=args.phase_a_head,
                report_sha=args.phase_a_report_sha256,
                frozen_sha=report["frozen_manifest_sha256"],
                audit_sha=report["first_parent_audit_sha256"],
                eligibility=report["eligibility"],
            )
            result["provider_response_sha256"] = sha256(raw)
            write_report(result, args.provider_output)
    except (ExitError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"phase_exit_failure={error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
