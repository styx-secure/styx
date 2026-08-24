#!/usr/bin/env python3
"""Generate deterministic semantic-only O-06c cross-language inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


EXPECTED_SEED = "o06c-v1-deterministic-test-seed"


def derived(label: str, length: int = 32) -> str:
    seed = os.environ.get("O06C_MODEL_SEED")
    if seed != EXPECTED_SEED:
        raise SystemExit("O06C_MODEL_SEED mismatch")
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hashlib.sha256(f"{seed}|{label}|{counter}".encode("utf-8")).digest()
        )
        counter += 1
    return bytes(output[:length]).hex()


def event_common(name: str, sequence: int = 0) -> dict[str, object]:
    return {
        "id": name,
        "application_profile_id": 1,
        "application_profile_version": 1,
        "context_identifier": derived("context"),
        "event_type_id": 1,
        "schema_id": 1,
        "schema_version": 1,
        "transition_block": derived(f"transition:{name}", 13),
        "author_sequence": sequence,
        "direct_predecessor": None if sequence == 0 else derived(f"predecessor:{name}"),
        "causal_parents": [] if sequence == 0 else [derived(f"parent:{name}")],
        "genesis_reference": derived("genesis"),
    }


def build_registry() -> dict[str, object]:
    root = event_common("grant-root")
    root.update(
        {
            "event_role": "credential",
            "credential_identifier": {"literal": derived("genesis-issuer")},
            "content": {"class": "none"},
            "tail": {
                "control_kind": "grant",
                "grantee_suite_id": 1,
                "grantee_verification_key": derived("grantee-key", 48),
            },
        }
    )

    cases: list[dict[str, object]] = []
    ordinary_single = event_common("ordinary-single")
    ordinary_single.update(
        {
            "event_role": "ordinary",
            "credential_identifier": {"grant_reference": "grant-root"},
            "content": {
                "class": "required",
                "content_type_id": 7,
                "content": derived("single-content", 17),
                "randomizer": derived("single-randomizer"),
                "shape": "single",
            },
            "tail": None,
        }
    )
    cases.append(ordinary_single)

    ordinary_tree = event_common("ordinary-tree", 1)
    ordinary_tree.update(
        {
            "event_role": "ordinary",
            "credential_identifier": {"grant_reference": "grant-root"},
            "content": {
                "class": "detachable",
                "content_type_id": 8,
                "content": derived("tree-content", 37),
                "randomizer": derived("tree-randomizer"),
                "shape": "tree",
                "chunk_size": 7,
            },
            "tail": None,
        }
    )
    cases.append(ordinary_tree)

    removal = event_common("removal", 1)
    removal.update(
        {
            "event_role": "removal",
            "credential_identifier": {"grant_reference": "grant-root"},
            "content": {"class": "none"},
            "tail": {
                "target_event_reference": derived("removal-target"),
                "target_commitment": derived("removal-commitment"),
            },
        }
    )
    cases.append(removal)

    arms = {
        "revoke": {"target_credential_id": derived("revoked-credential")},
        "rotate": {
            "retiring_credential_id": derived("retiring-credential"),
            "replacement_grant_reference": derived("replacement-grant"),
        },
        "recover": {
            "retired_credential_id": derived("retired-credential"),
            "recovery_grant_reference": derived("recovery-grant"),
        },
        "policy": {},
        "closure": {},
    }
    for index, (kind, fields) in enumerate(arms.items(), start=2):
        control = event_common(f"control-{kind}", index)
        control.update(
            {
                "event_role": "credential",
                "credential_identifier": {"grant_reference": "grant-root"},
                "content": {"class": "none"},
                "tail": {"control_kind": kind, **fields},
            }
        )
        cases.append(control)

    return {
        "format": "styx-o06c-semantic-input-v1",
        "seed_label": EXPECTED_SEED,
        "grants": [root],
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(build_registry(), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
