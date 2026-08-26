#!/usr/bin/env python3
"""Validate the selected O-08 envelope and its external selection evidence."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

sys.dont_write_bytecode = True

from canonical_report import store_report
from envelope_model import candidate_identity, load_selected_envelope, validate_candidate_set, validate_selected
from semantic_registry import BASE_SHA, CANDIDATES_PATH, SELECTED_PATH, load_json


REPORT_SCHEMA = "styx-o08-envelope-report/v1"
ISSUE_URL = "https://api.github.com/repos/styx-secure/styx/issues/250"
COMMENT_URL_PREFIX = "https://api.github.com/repos/styx-secure/styx/issues/comments/"
OPERATOR_ID = 141346846
OPERATOR_LOGIN = "maverde73"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise HTTPError(req.full_url, code, "redirect forbidden", headers, fp)


def _provider_url(object_id: str) -> str:
    if not object_id or not object_id.isdecimal():
        raise ValueError("provider object ID must be non-empty decimal")
    return COMMENT_URL_PREFIX + object_id


def fetch_provider_object(url: str, object_id: str) -> dict[str, object]:
    expected_url = _provider_url(object_id)
    if url != expected_url:
        raise ValueError("provider URL is not derived from object ID")
    request = Request(url, headers={"Accept": "application/vnd.github+json"})
    try:
        with build_opener(_NoRedirect).open(request, timeout=30) as response:
            raw = response.read()
    except (HTTPError, URLError, TimeoutError) as error:
        raise ValueError(f"provider fetch failed: {error}") from error
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("provider response object required")
    validate_provider_identity(value, url, object_id)
    return value


def validate_provider_identity(value: dict[str, object], url: str, object_id: str) -> None:
    expected_url = _provider_url(object_id)
    user = value.get("user")
    if value.get("id") != int(object_id) or value.get("url") != expected_url or url != expected_url:
        raise ValueError("provider comment identity mismatch")
    if value.get("issue_url") != ISSUE_URL:
        raise ValueError("provider issue mismatch")
    if not isinstance(user, dict) or user.get("id") != OPERATOR_ID or user.get("login") != OPERATOR_LOGIN:
        raise ValueError("provider operator mismatch")
    if value.get("created_at") != value.get("updated_at"):
        raise ValueError("provider selection was edited")


def _selection_body(value: dict[str, object]) -> dict[str, object]:
    body = value.get("body")
    if not isinstance(body, str):
        raise ValueError("provider selection body missing")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as error:
        raise ValueError("provider body must be one JSON object") from error
    if not isinstance(payload, dict):
        raise ValueError("selection object required")
    required = {
        "schema", "status", "operator", "base_sha", "selection_head",
        "candidate_set_sha256", "measurement_reports", "comparison_report_sha256",
        "selected_candidate_id", "selected_envelope_sha256",
    }
    if set(payload) != required or payload["schema"] != "styx-o08-selection/v1":
        raise ValueError("selection body schema mismatch")
    if payload["status"] != "accepted" or payload["operator"] != OPERATOR_LOGIN:
        raise ValueError("selection was not accepted by required operator")
    reports = payload["measurement_reports"]
    if not isinstance(reports, list) or len(reports) != 6:
        raise ValueError("exactly six measurement identities required")
    expected_pairs = {
        (candidate, profile)
        for candidate in ("conservative", "balanced", "expansive")
        for profile in ("conservative", "balanced")
    }
    observed_pairs: set[tuple[object, object]] = set()
    for report in reports:
        if not isinstance(report, dict) or set(report) != {
            "candidate_id", "capability_profile", "report_sha256"
        }:
            raise ValueError("measurement identity schema mismatch")
        if not isinstance(report["report_sha256"], str) or len(report["report_sha256"]) != 64:
            raise ValueError("measurement digest invalid")
        observed_pairs.add((report["candidate_id"], report["capability_profile"]))
    if observed_pairs != expected_pairs:
        raise ValueError("measurement identity set mismatch")
    return payload


def validate_selection(
    provider: dict[str, object], *, url: str, object_id: str, base: str, selection_head: str
) -> dict[str, object]:
    validate_provider_identity(provider, url, object_id)
    payload = _selection_body(provider)
    candidate_set_raw = CANDIDATES_PATH.read_bytes()
    if payload["base_sha"] != base or base != BASE_SHA:
        raise ValueError("selection Base mismatch")
    if payload["selection_head"] != selection_head or len(selection_head) != 40:
        raise ValueError("selection HEAD mismatch")
    if payload["candidate_set_sha256"] != sha256(candidate_set_raw).hexdigest():
        raise ValueError("candidate-set digest mismatch")
    candidates_payload = json.loads(candidate_set_raw)
    candidates = validate_candidate_set(candidates_payload)
    candidate = next((item for item in candidates if item["id"] == payload["selected_candidate_id"]), None)
    if candidate is None or candidate_identity(candidate) != payload["selected_envelope_sha256"]:
        raise ValueError("selected envelope digest mismatch")
    return payload


def build_report(approved_digest: str) -> dict[str, object]:
    if len(approved_digest) != 64:
        raise ValueError("approved envelope digest must be 64 hexadecimal characters")
    int(approved_digest, 16)
    envelope = validate_selected(load_selected_envelope(), load_json(CANDIDATES_PATH))
    if envelope["candidate_digest"] != approved_digest:
        raise ValueError("selected envelope is not provider-approved")
    entries = envelope["entries"]
    counts: dict[str, int] = {}
    for entry in entries.values():
        role = entry["role"]
        counts[role] = counts.get(role, 0) + 1
    return {
        "schema": REPORT_SCHEMA,
        "candidate_id": envelope["candidate_id"],
        "candidate_digest": envelope["candidate_digest"],
        "role_counts": {key: counts[key] for key in sorted(counts)},
        "verdict": "PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--approved-envelope-digest")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fetch-selection-evidence", action="store_true")
    parser.add_argument("--selection-evidence", type=Path)
    parser.add_argument("--selection-evidence-cache", type=Path)
    parser.add_argument("--selection-provider-url")
    parser.add_argument("--selection-provider-object-id")
    parser.add_argument("--base")
    parser.add_argument("--selection-head")
    parser.add_argument("--print-approved-digest", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.fetch_selection_evidence:
            value = fetch_provider_object(args.selection_provider_url, args.selection_provider_object_id)
            args.selection_evidence_cache.parent.mkdir(parents=True, exist_ok=True)
            args.selection_evidence_cache.write_text(
                json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
            )
            return 0
        if args.print_approved_digest:
            provider = json.loads(args.selection_evidence.read_text(encoding="utf-8"))
            payload = validate_selection(
                provider, url=args.selection_provider_url,
                object_id=args.selection_provider_object_id, base=args.base,
                selection_head=args.selection_head,
            )
            print(payload["selected_envelope_sha256"])
            return 0
        report = build_report(args.approved_envelope_digest)
        store_report(args.output, report, REPORT_SCHEMA)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
        print(f"O-08 envelope validation failed: {error}", file=sys.stderr)
        return 2
    print("O-08 ENVELOPE verdict=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
