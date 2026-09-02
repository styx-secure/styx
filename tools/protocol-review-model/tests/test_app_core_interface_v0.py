from __future__ import annotations

import hashlib
import json
import re
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
APP_CORE_ROOT = REPO_ROOT / "tools/causal-flow-simulator/app_core_iface0"
sys.path.insert(0, str(APP_CORE_ROOT))

from interface_model import verify_native_authority  # noqa: E402


LITERAL = """NO_OPERATIONAL_AUTHORITY is an APP-core v0 context state. It is below
AUTHORITY_UNAVAILABLE and above every partial fork or pending state in context
precedence. It is entered only by an accepted revoke/rotate reduction that
removes the last operational authority or by a newly completed fork join with
the same effect. It is authority-restoration-terminal in v0. Its only outgoing
state change is escalation to AUTHORITY_UNAVAILABLE when a later K-valid record
crosses a selected S5 authority envelope. It does not authorize recovery,
replacement authority, transport/session substitution or product activation.
The dated C0.3 corpus and public kernel review model do not yet contain this
APP-core state token."""

PRECEDENCE = [
    "STALE_EVIDENCE",
    "AUTHORITY_PROJECTION_UNAVAILABLE",
    "FORK_EVIDENCE",
    "PENDING_OPENING",
    "PENDING_ANCESTOR",
    "REMOVAL_INAPPLICABLE",
    "POST_REVOCATION",
    "LINEAGE_QUARANTINED",
    "AUTHENTIC_BUT_UNAUTHORIZED",
    "APPLIED",
]


def normalized(value: str) -> str:
    return re.sub(r"\s+", " ", value, flags=re.UNICODE).strip()


class AppCoreInterfaceV0Tests(unittest.TestCase):
    def test_public_boundary_and_historical_bytes_are_exact(self) -> None:
        interface = (
            REPO_ROOT / "docs/protocol/styx-app-core-interface-v0.md"
        ).read_text(encoding="utf-8")
        self.assertIn(normalized(LITERAL), normalized(interface))

        readme = (REPO_ROOT / "docs/protocol/review/README.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            normalized(
                "The historical C0.3 corpus and public kernel review model do "
                "not yet carry the APP-core `NO_OPERATIONAL_AUTHORITY` state token."
            ),
            normalized(readme),
        )

        model = json.loads(
            (
                REPO_ROOT
                / "docs/protocol/review/styx-app-kernel-v0-review-model.json"
            ).read_bytes()
        )
        ap_projection = next(
            row for row in model["state_models"] if row["id"] == "ap_projection"
        )
        self.assertEqual(ap_projection["precedence"], PRECEDENCE)
        self.assertNotIn("NO_OPERATIONAL_AUTHORITY", json.dumps(model))

        contract = APP_CORE_ROOT / "contract"
        verify_native_authority(REPO_ROOT, contract)
        inventory = json.loads(
            (
                contract / "APP-CORE-IFACE-0-NATIVE-DEPENDENCIES-CANDIDATE.json"
            ).read_bytes()
        )
        rows = [
            row
            for row in inventory["dependencies"]
            if row["path"].startswith("conformance/application-protocol/c03/")
            or row["path"].startswith("tools/causal-flow-simulator/c03/")
        ]
        self.assertEqual(len(rows), 30)
        for row in rows:
            self.assertEqual(row["mutationPolicy"], "READ_ONLY_BYTE_IDENTICAL")
            self.assertEqual(
                hashlib.sha256((REPO_ROOT / row["path"]).read_bytes()).hexdigest(),
                row["sha256"],
            )


if __name__ == "__main__":
    unittest.main()
