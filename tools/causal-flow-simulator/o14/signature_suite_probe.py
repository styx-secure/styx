#!/usr/bin/env python3
"""Emit deterministic O-14 semantic-registry and oracle evidence."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.dont_write_bytecode = True

from common import write_report
from ed25519_reference import verify as oracle_verify
from scenarios import execute_suite, required_witnesses
from semantic_registry import SELECTED_SUITE


SCHEMA = "styx-o14-signature-suite-probe/v1"


def build_report() -> tuple[dict[str, object], bool]:
    semantic_results = execute_suite()
    runtime_vectors = []
    for witness in required_witnesses():
        if not witness.runtime:
            continue
        event = witness.event
        key = event.binding.verification_key if event.binding else bytes()
        runtime_vectors.append(
            {
                "id": witness.identifier,
                "message_hex": event.transcript.hex(),
                "public_key_hex": key.hex(),
                "signature_hex": event.signature.hex(),
                "expected_selected": witness.expected,
                "oracle_rfc8032_cofactored": oracle_verify(
                    event.signature,
                    event.transcript,
                    key,
                    zip215=False,
                    cofactored=True,
                ),
                "oracle_rfc8032_cofactorless": oracle_verify(
                    event.signature,
                    event.transcript,
                    key,
                    zip215=False,
                    cofactored=False,
                ),
                "oracle_zip215": oracle_verify(
                    event.signature,
                    event.transcript,
                    key,
                    zip215=True,
                    cofactored=True,
                ),
            }
        )
    failed = [item["id"] for item in semantic_results if not item["passed"]]
    report = {
        "schema": SCHEMA,
        "selected_suite": {
            "id": SELECTED_SUITE.identifier,
            "name": "STYX-ED25519-PRIMEORDER-RFC8032-V1",
            "signing_mode": SELECTED_SUITE.signing_mode,
            "verification_equation": SELECTED_SUITE.verification_equation,
            "public_key_encoding": SELECTED_SUITE.public_key_encoding,
            "public_key_octets": SELECTED_SUITE.public_key_octets,
            "signature_encoding": SELECTED_SUITE.signature_encoding,
            "signature_octets": SELECTED_SUITE.signature_octets,
            "transcript_input": SELECTED_SUITE.transcript_input,
            "malformed_behavior": SELECTED_SUITE.malformed_behavior,
            "registry": {"assigned": [1], "reserved": [0, 65535], "fallback": False},
        },
        "semantic_results": list(semantic_results),
        "runtime_vectors": runtime_vectors,
        "failed": failed,
        "verdict": "PASS" if not failed else "FAIL",
    }
    return report, not failed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--suite", required=True, choices=("required",))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    report, passed = build_report()
    write_report(args.output, report)
    print(f"O-14 PROBE verdict={report['verdict']} vectors={len(report['runtime_vectors'])}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
