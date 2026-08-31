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


BASE_SHA = "fd6f652af1666c6c9dca8356c2aed615773f5208"
FREEZE_SHA = "8f30f1940e4417fcb47b156b08c2242f405dc09b"
FIRST_PARENT_SHA256 = "837ffcaf884059cf121414a44a88e5fa06ed4351b175c13e67dd43be4d7ad92d"
ISSUE_NUMBER = 287
ISSUE_BODY_SHA256 = "a43d7e53df4656e6a6cd1b73b90b0fb8a4f4e4329bd4e6144ea4d0ab5fbdb778"
MAVERDE_ID = 141346846
MANEXADA_ID = 314148709
MAX_PROVIDER_BYTES = 256 * 1024
ISSUE_API_URL = "https://api.github.com/repos/styx-secure/styx/issues/287"
PR_NUMBER = 288
CANONICAL_REPORT_PATH = Path("docs/protocol/review/phase-exit/phase-exit-report.json")
ALLOWED_CHANGED_PATHS = {
    "AGENTS.md",
    "CLAUDE.md",
    "docs/PROJECT_BRIEF.md",
    "docs/platform/integration-roadmap.md",
    "docs/platform/integration-roadmap_IT.md",
    "docs/protocol/protocol-hardening-plan.md",
    "docs/protocol/review/README.md",
    "docs/protocol/review/styx-app-kernel-v0-review-model.json",
}
ALLOWED_CHANGED_PREFIXES = (
    "docs/protocol/review/phase-exit/",
    "tools/protocol-phase-exit/",
)
HISTORICAL_NON_PR_COMMIT = "578b3241d6e7d0231da0d2e00b9d04c69530d24e"
MINIMUM_CONDITIONAL_STATEMENTS = [
    "O-12 is excluded only because the bounded v0 K and SS profiles make no physical-time claim.",
    "O-13 is excluded only from non-destructive interface/corpus work and remains blocking for irreversible effects and deletion or erasure claims.",
    "O-15 remains blocking for profile succession, migration and upgrade claims.",
    "O-16 remains blocking for semantic finality, recovery or finality UI and irreversible-effect claims.",
    "O-11 and RS custody obligations remain blocking for durable product or storage claims.",
    "No exclusion authorizes an adapter, authenticated persistence or product.",
]

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
    "phase_exit_status": ("docs/protocol/review/phase-exit/README.md",),
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


def normalized_prose(data: bytes) -> str:
    return " ".join(data.decode("utf-8").replace("-\n", "-").split())


def report_strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from report_strings(key)
            yield from report_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from report_strings(item)


def validate_report_strings(report: dict[str, object], forbidden: set[str]) -> None:
    timestamp = re.compile(r"(?:19|20)[0-9]{2}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}")
    absolute_path = re.compile(r"(?<![A-Za-z0-9_.-])(?:/|\\|[A-Za-z]:[\\/])")
    for value in report_strings(report):
        require(not any(identity in value for identity in forbidden), "canonical report contains execution identity")
        require(timestamp.search(value) is None, "canonical report contains timestamp")
        require(absolute_path.search(value) is None, "canonical report contains absolute path")
        for identity in re.findall(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])", value):
            require(identity == HISTORICAL_NON_PR_COMMIT, "canonical report contains unapproved commit identity")


def validate_report_hygiene(repo: Path, report: dict[str, object]) -> None:
    head = run_git(repo, "rev-parse", "HEAD").decode().strip()
    tree = run_git(repo, "rev-parse", "HEAD^{tree}").decode().strip()
    base_tree = run_git(repo, "rev-parse", f"{BASE_SHA}^{{tree}}").decode().strip()
    diff = sha256(run_git(repo, "diff", "--binary", "--full-index", f"{BASE_SHA}...HEAD"))
    validate_report_strings(report, {head, tree, base_tree, diff})


def verify_committed_report(repo: Path, report: dict[str, object]) -> None:
    path = repo / CANONICAL_REPORT_PATH
    require(path.is_file() and not path.is_symlink(), "canonical report missing")
    require(path.read_bytes() == canonical_bytes(report), "canonical report byte mismatch")


def is_allowed_changed_path(path: str) -> bool:
    return path in ALLOWED_CHANGED_PATHS or path.startswith(ALLOWED_CHANGED_PREFIXES)


def verify_candidate_scope(repo: Path) -> None:
    require(not run_git(repo, "status", "--porcelain=v1", "--untracked-files=all"), "candidate checkout is not clean")
    raw = run_git(repo, "diff", "--name-status", "--no-renames", f"{BASE_SHA}...HEAD")
    seen: set[str] = set()
    for line in raw.decode("utf-8").splitlines():
        fields = line.split("\t")
        require(len(fields) == 2 and fields[0] in {"A", "M"}, "candidate contains forbidden path operation")
        path = fields[1]
        require(path not in seen, "candidate changed-path duplicate")
        seen.add(path)
        require(is_allowed_changed_path(path), f"candidate path outside scope: {path}")
        candidate = repo / path
        require(candidate.is_file() and not candidate.is_symlink(), f"invalid candidate path: {path}")
    require(bool(seen), "candidate changed-path set is empty")


def mechanical_eligibility(dispositions: list[str]) -> str:
    if "FAIL" in dispositions:
        return "REQUIRES_NO_GO"
    if "CONDITIONAL_EXCLUSION" in dispositions:
        return "ELIGIBLE_FOR_BOUNDED_GO"
    return "ELIGIBLE_FOR_GO"


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


def approval_url(review_id: str) -> str:
    require(re.fullmatch(r"[1-9][0-9]*", review_id) is not None, "invalid approval review id")
    return f"https://api.github.com/repos/styx-secure/styx/pulls/{PR_NUMBER}/reviews/{review_id}"


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


def validate_approval_review(
    review: dict[str, object], *, review_id: str, final_head: str,
) -> dict[str, object]:
    url = approval_url(review_id)
    user = review.get("user")
    require(isinstance(user, dict), "approval user missing")
    require(review.get("id") == int(review_id), "approval review id mismatch")
    require(review.get("url") == url, "approval review URL mismatch")
    require(review.get("pull_request_url") == f"https://api.github.com/repos/styx-secure/styx/pulls/{PR_NUMBER}", "approval PR mismatch")
    require(user.get("id") == MANEXADA_ID and user.get("login") == "manexada", "approval operator mismatch")
    require(review.get("state") == "APPROVED", "approval state mismatch")
    require(review.get("commit_id") == final_head, "approval HEAD mismatch")
    require(isinstance(review.get("submitted_at"), str) and bool(review["submitted_at"]), "approval submission missing")
    projection = {
        "id": review["id"],
        "url": review["url"],
        "pull_request_url": review["pull_request_url"],
        "user": {"id": user["id"], "login": user["login"]},
        "state": review["state"],
        "commit_id": review["commit_id"],
        "submitted_at": review["submitted_at"],
    }
    return {
        "approval_provider_projection_sha256": sha256(canonical_bytes(projection)),
        "approval_review_id": int(review_id),
        "approved_head": final_head,
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
    require(len(lines) == 24, "first-parent count mismatch")
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
    registered_ids: list[str] = []
    for item in conditions:
        required_shape = {
            "id", "applicability", "required_evidence_ids",
            "expected_evidence_sha256", "residual_risks", "reopen_triggers",
        }
        if item["id"] == "EXIT-01":
            required_shape.add("excluded_claims")
        require(set(item) == required_shape, f"condition shape mismatch: {item.get('id')}")
        evidence_ids = validate_evidence_declaration(item)
        registered_ids.extend(evidence_ids)
    require(set(registered_ids) == set(EVIDENCE_PATHS) | {"frozen_manifest", "first_parent_audit"}, "registered evidence universe mismatch")
    validate_excluded_claims(repo, conditions[0])
    return value


def validate_evidence_declaration(item: dict[str, object]) -> list[str]:
    evidence_ids = item["required_evidence_ids"]
    expected_digests = item["expected_evidence_sha256"]
    require(isinstance(evidence_ids, list), "required evidence ids missing")
    require(all(isinstance(value, str) for value in evidence_ids), "invalid required evidence id")
    require(len(evidence_ids) == len(set(evidence_ids)), "duplicate required evidence id")
    known = set(EVIDENCE_PATHS) | {"frozen_manifest", "first_parent_audit"}
    require(all(value in known for value in evidence_ids), "unknown required evidence id")
    require(isinstance(expected_digests, dict) and set(expected_digests) == set(evidence_ids), "expected evidence set mismatch")
    require(all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) for value in expected_digests.values()), "invalid expected evidence digest")
    return evidence_ids


def validate_excluded_claims(repo: Path, record: dict[str, object]) -> None:
    claims = record.get("excluded_claims")
    require(isinstance(claims, list) and len(claims) == 3, "conditional exclusion claim set mismatch")
    seen: set[tuple[str, str, str]] = set()
    for claim in claims:
        require(isinstance(claim, dict), "conditional exclusion claim invalid")
        require(set(claim) == {"file", "heading", "quoted_condition", "base_sha256"}, "conditional exclusion shape mismatch")
        path = claim["file"]
        require(path in {
            "docs/protocol/styx-app-kernel-v0-decisions.md",
            "docs/protocol/styx-secure-session-v0-decisions.md",
        }, "conditional exclusion source outside decision registry")
        require(claim["base_sha256"] == PINNED_BASE_BLOBS[path], "conditional exclusion Base digest mismatch")
        source = normalized_prose(run_git(repo, "show", f"{BASE_SHA}:{path}"))
        heading = " ".join(str(claim["heading"]).split())
        quoted = " ".join(str(claim["quoted_condition"]).split())
        require(heading in source, "conditional exclusion heading missing")
        require(quoted in source, "conditional exclusion quote missing")
        identity = (path, heading, quoted)
        require(identity not in seen, "conditional exclusion duplicate")
        seen.add(identity)


def disposition_for(record: dict[str, object], observed: dict[str, str]) -> str:
    expected = record["expected_evidence_sha256"]
    require(observed == expected, f"evidence digest mismatch: {record['id']}")
    if record["id"] == "EXIT-01":
        return "CONDITIONAL_EXCLUSION"
    if record["id"] in {"EXIT-08", "EXIT-09"}:
        return "HUMAN_GATE_PENDING"
    return "PASS"


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
        disposition = disposition_for(item, observed)
        record = {
            "id": item["id"],
            "applicability": item["applicability"],
            "required_evidence_ids": evidence_ids,
            "observed_evidence_sha256": observed,
            "disposition": disposition,
            "residual_risks": item["residual_risks"],
            "reopen_triggers": item["reopen_triggers"],
        }
        if item["id"] == "EXIT-01":
            record["excluded_claims"] = item["excluded_claims"]
        records.append(record)
        if item["id"] not in {"EXIT-08", "EXIT-09"}:
            mechanical.append(disposition)
    report = {
        "schema": "styx-protocol-phase-exit-report/v1",
        "issue_body_sha256": ISSUE_BODY_SHA256,
        "eligibility": mechanical_eligibility(mechanical),
        "frozen_manifest_sha256": frozen_sha,
        "first_parent_audit_sha256": audit_sha,
        "conditions": records,
        "conditional_exclusions": MINIMUM_CONDITIONAL_STATEMENTS,
        "non_authorizations": [
            "adapter", "authenticated_persistence", "sdk", "transport_delivery",
            "ss_corpus_until_k11_ss", "product", "demo", "deployment", "sensitive_use",
        ],
    }
    validate_report_hygiene(repo, report)
    return report


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
    parser.add_argument("--approval-review-id")
    parser.add_argument("--final-head")
    parser.add_argument("--approval-provider-output", type=Path)
    parser.add_argument("--refresh-canonical-report", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        require(args.base == BASE_SHA, "Base argument mismatch")
        require((args.verdict_comment_id is None) == (args.phase_a_head is None), "verdict identity arguments incomplete")
        require((args.verdict_comment_id is None) == (args.phase_a_report_sha256 is None), "verdict report arguments incomplete")
        require((args.verdict_comment_id is None) == (args.provider_output is None), "verdict output arguments incomplete")
        require((args.approval_review_id is None) == (args.final_head is None), "approval identity arguments incomplete")
        require((args.approval_review_id is None) == (args.approval_provider_output is None), "approval output arguments incomplete")
        repo = args.repo_root.resolve(strict=True)
        report = build_report(repo)
        if args.refresh_canonical_report:
            require(args.output.resolve() == (repo / CANONICAL_REPORT_PATH).resolve(), "refresh output must be canonical report")
            require(args.verdict_comment_id is None and args.approval_review_id is None, "refresh cannot resolve provider gates")
            write_report(report, args.output)
        else:
            verify_candidate_scope(repo)
            verify_committed_report(repo, report)
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
        if args.approval_review_id is not None:
            require(args.final_head is not None, "final HEAD required")
            require(args.approval_provider_output is not None, "approval provider output required")
            require(re.fullmatch(r"[0-9a-f]{40}", args.final_head) is not None, "invalid final HEAD")
            url = approval_url(args.approval_review_id)
            review, raw = fetch_provider_json(url)
            result = validate_approval_review(
                review, review_id=args.approval_review_id, final_head=args.final_head,
            )
            result["approval_provider_response_sha256"] = sha256(raw)
            write_report(result, args.approval_provider_output)
    except (ExitError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"phase_exit_failure={error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
