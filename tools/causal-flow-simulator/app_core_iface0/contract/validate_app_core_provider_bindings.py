#!/usr/bin/env python3
"""Validate APP-core historical GitHub authority and live scope separation."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
BINDINGS = ROOT / "APP-CORE-IFACE-0-PROVIDER-BINDINGS-CANDIDATE.json"
ALLOWED_BLOCK = re.compile(
    r"^## Allowed paths\s*$.*?^```(?:text)?\s*$\n(?P<paths>.*?)^```\s*$",
    re.MULTILINE | re.DOTALL,
)


def require(ok: bool, message: str) -> None:
    if not ok:
        raise SystemExit(message)


def command(*args: str) -> bytes:
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    require(result.returncode == 0, result.stderr.decode(errors="replace").strip())
    return result.stdout


def api(path: str) -> Any:
    return json.loads(command("gh", "api", path))


def issue_paths(body: str, number: int) -> list[str]:
    match = ALLOWED_BLOCK.search(body)
    require(match is not None, f"Issue #{number} has no parseable Allowed paths block")
    rows = []
    for raw in match.group("paths").splitlines():
        value = raw.strip().strip("`")
        if value and not value.startswith("#"):
            rows.append(value)
    require(rows, f"Issue #{number} has empty Allowed paths block")
    return rows


def intersects(external: str, literals: set[str], prefix: str) -> bool:
    if external in literals or external.startswith(prefix):
        return True
    if any(fnmatch.fnmatchcase(path, external) for path in literals):
        return True
    prefix_probe = prefix + "__scope_probe__"
    return fnmatch.fnmatchcase(prefix_probe, external)


def main() -> int:
    data = json.loads(BINDINGS.read_text(encoding="utf-8"))
    owner = data["providerIdentities"]["integrationOwner"]
    reviewer = data["providerIdentities"]["humanTechnicalReviewer"]
    repository = data["repository"]
    base = data["baseSha"]

    resolved = command("git", "-C", str(Path.cwd()), "rev-parse", f"{base}^{{commit}}").decode().strip()
    require(resolved == base, "exact Base unavailable")

    for row in data["historicalIncrements"]:
        issue_expected = row["issue"]
        issue = api(f"repos/{repository}/issues/{issue_expected['number']}")
        require(issue["id"] == issue_expected["id"], f"Issue ID drift: {row['id']}")
        require(issue["node_id"] == issue_expected["nodeId"], f"Issue node drift: {row['id']}")
        require(issue["state"] == "closed" and issue.get("state_reason") == "completed", f"Issue state drift: {row['id']}")
        require(issue["user"]["id"] == owner["id"] and issue["user"]["login"] == owner["login"], f"Issue owner drift: {row['id']}")
        body_digest = hashlib.sha256((issue.get("body") or "").encode()).hexdigest()
        require(body_digest == issue_expected["bodySha256"], f"Issue body drift: {row['id']}")

        pr_expected = row["pullRequest"]
        pr = api(f"repos/{repository}/pulls/{pr_expected['number']}")
        require(pr["id"] == pr_expected["id"] and pr["node_id"] == pr_expected["nodeId"], f"PR identity drift: {row['id']}")
        require(pr["merged"] is True and pr["state"] == "closed", f"PR state drift: {row['id']}")
        require(pr["user"]["id"] == owner["id"] and pr["user"]["login"] == owner["login"], f"PR owner drift: {row['id']}")
        require(pr["base"]["sha"] == pr_expected["baseSha"], f"PR Base drift: {row['id']}")
        require(pr["head"]["sha"] == pr_expected["headSha"], f"PR HEAD drift: {row['id']}")
        require(pr["merge_commit_sha"] == pr_expected["mergeSha"], f"PR merge drift: {row['id']}")
        ancestor = subprocess.run(
            ["git", "-C", str(Path.cwd()), "merge-base", "--is-ancestor", pr_expected["mergeSha"], base],
            check=False,
        )
        require(ancestor.returncode == 0, f"historical merge not in Base: {row['id']}")

        approval_expected = row["exactHeadApproval"]
        reviews = api(f"repos/{repository}/pulls/{pr_expected['number']}/reviews")
        matches = [review for review in reviews if review["id"] == approval_expected["id"]]
        require(len(matches) == 1, f"approval missing or duplicated: {row['id']}")
        review = matches[0]
        require(review["node_id"] == approval_expected["nodeId"], f"approval node drift: {row['id']}")
        require(review["state"] == "APPROVED", f"approval state drift: {row['id']}")
        require(review["commit_id"] == approval_expected["commitSha"] == pr_expected["headSha"], f"approval HEAD drift: {row['id']}")
        require(review["user"]["id"] == reviewer["id"] and review["user"]["login"] == reviewer["login"], f"reviewer drift: {row['id']}")

    scope = data["candidateMutableScope"]
    literals = set(scope["literalPaths"])
    prefix = scope["directoryPrefix"]
    open_items = api(f"repos/{repository}/issues?state=open&per_page=100")
    checked_contracts = 0
    for issue in open_items:
        if "pull_request" in issue:
            continue
        body = issue.get("body") or ""
        if not body.lstrip().startswith("<!-- styx-task-contract:v1 -->"):
            continue
        checked_contracts += 1
        overlap = sorted(path for path in issue_paths(body, issue["number"]) if intersects(path, literals, prefix))
        require(not overlap, f"mutable scope overlap with Issue #{issue['number']}: {overlap}")

    print(
        "PASS "
        f"historical_increments={len(data['historicalIncrements'])} "
        f"open_task_contracts={checked_contracts} mutable_overlap=0 base={base}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
