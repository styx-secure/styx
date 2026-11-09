"""Documentation lint for the M3 SDK and reference PWA threat model.

The threat model lives at docs/architecture/m3/threat-model-m3-pwa.md. These
tests require the document to exist and to keep its key invariants: the
separation of SDK obligations, integration contracts and downstream duties in
every threat, the invariant index, the declared limits, the known
documentation limits, no affirmative forbidden claim, no wording that declares
a risk resolved, and an unchanged protocol threat model.
"""

import hashlib
import re
import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from claims_lint import lint_text  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
DOC_PATH = REPO_ROOT / "docs" / "architecture" / "m3" / "threat-model-m3-pwa.md"
PROTOCOL_THREAT_MODEL = REPO_ROOT / "docs" / "security" / "STYX-THREAT-MODEL.md"
PROTOCOL_THREAT_MODEL_SHA256 = (
    "8863ce4b2ef697055e95da22e0a2fbb630172cdf3f5fd0c91b27ec02f9d2ba54"
)

REQUIRED_HEADINGS = (
    "# M3 early-lane SDK and reference PWA threat model (runtime profile)",
    "## 1. Scope and relation to the protocol threat model",
    "### 1.1 How each threat is written",
    "## 2. Assets, boundaries and adversaries",
    "## 3. M3 SDK",
    "### 3.1 Invitations: KeyPackage, Welcome and delegated gift wrap",
    "### 3.2 Inbound frames, validation and flooding",
    "### 3.3 Catch-up cursors and EOSE",
    "### 3.4 Durable receive: stage, openCandidate, commit and resolve",
    "### 3.5 Quotas and injected ports",
    "### 3.6 Outbound queue in memory",
    "### 3.7 Duplicates and transient open failures without the durable port",
    "### 3.8 Routing metadata",
    "## 4. Reference chat PWA",
    "### 4.1 Service worker and update path",
    "### 4.2 Notifications and push",
    "### 4.3 URL parameters as hostile input",
    "### 4.4 Inbound chat payloads and local state",
    "## 5. Cross-cutting",
    "## 6. Declared limits",
    "## 7. Known documentation limits",
    "## 8. Invariant index",
    "## 9. Non-claims",
)

THREAT_SECTIONS = tuple(
    heading for heading in REQUIRED_HEADINGS
    if re.match(r"### [34]\.\d ", heading)
)

OBLIGATION_LABELS = (
    "- SDK obligation",
    "- Integration contract:",
    "- Downstream duty:",
    "- Residual behaviour:",
)

KEY_STATEMENTS = (
    # Status: informative, never authority.
    "It is not a contract, not protocol authority and not an audit.",
    "The reference PWA does not use the M3 SDK.",
    # Invitations.
    "a failed join may consume the KeyPackage while the inviter retains a group,"
    " with no rollback of caller state",
    "The SDK implements none of these constructions and verifies none of their"
    " meaning.",
    # Inbound bounds and the unbounded transport decoding.
    "at most 1 048 576 cost units per frame and 16 777 216 in total",
    "the transport decodes each frame's JSON before any SDK bound applies",
    # Cursors and EOSE.
    "EOSE is never proof of completeness.",
    "are not recovered by the durable barrier: they depend on a later delivery or"
    " replay by a relay",
    # Durable receive.
    "an admitted event is staged durably before `openCandidate`",
    "freezes the receive state for the rest of the client's lifetime (fail-stop)",
    "nothing falls back to the path without the port",
    "The SDK cannot verify any of this.",
    # Quotas and ports.
    "there is no per-sender fairness",
    "A shape-valid port return proves nothing about encryption, signing meaning"
    " or durability",
    # Outbound queue.
    "every non-terminal item becomes `LOST_ON_SHUTDOWN`",
    "never resumes, replays or re-sends a stored item",
    "after a crash or abrupt termination nothing is reported and nothing is"
    " recovered",
    # Reference PWA.
    "`registerType: 'autoUpdate'`",
    "calls `self.skipWaiting()` on install and `self.clients.claim()` on activate",
    "The service worker's `push` handler ignores `event.data`",
    "with no content and no sender",
    "treat `local`, `relay`, `bridge` and `ns` from the URL as hostile input",
    "The app uses `local`, `relay` and `bridge` from the URL only after the user"
    " confirms them in a dialog that lists them",
    "`?ns=` is accepted without a confirmation step.",
    # Chat payload validation since #562, with its legacy exception.
    "validates the typed fields of every inbound payload that decodes to a JSON"
    " object before that payload is stored",
    "A payload that decodes to a JSON array is discarded and counted as"
    " malformed.",
    "A payload that decodes to neither a JSON object nor a JSON array is still"
    " accepted as bare legacy text",
    "`?ns=` still switches namespace without asking.",
    # Legacy chat robustness since the C7 correction.
    "marks a message sent only when its event was written to at least one open"
    " relay connection, and failed otherwise; that is not a relay acknowledgement.",
    "the user can turn read receipts off; delivery receipts stay automatic.",
    # Honest state.
    "The review was model-assisted, not a human audit.",
    "is not resolved by this document or by those corrections",
)

DECLARED_LIMITS = {
    "H7": "C-DLV §5.5",
    "H9": "C-DLV §7.1",
    "H15": "C-DLV §11",
    "H17": "C-DLV §8",
    "H18": "C-DLV §5.2",
}

KNOWN_DOCUMENTATION_LIMITS = (
    "`docs/architecture/m3/scenarios/README.md`",
    "`docs/architecture/m3/flegias-preview.md`",
    "`docs/PROJECT_BRIEF.md`",
    "`docs/architecture/m3/delivery-layer.md` §11",
)

INVARIANT_COUNT = 14

VERBATIM_NON_CLAIMS = (
    '"Styx is under active development and has **not** completed an independent'
    " security audit. Do not use current builds for sensitive, high-risk, or"
    ' life-critical use."',
    '"C0.3 remains `NO-GO` for implementation alignment, demo, product, and'
    ' sensitive use."',
)

RESOLUTION_CLAIM = re.compile(
    r"\b(is|are|was|were|has been|have been)\s+(now\s+)?"
    r"((fully|partially|largely|mostly)\s+)?"
    r"(resolved|fixed|mitigated|remediated|eliminated|closed)\b",
    re.IGNORECASE,
)


def normalize(text):
    return " ".join(text.split())


def read_document():
    return DOC_PATH.read_text(encoding="utf-8")


def section_body(text, heading):
    lines = text.splitlines()
    start = lines.index(heading)
    level = len(heading) - len(heading.lstrip("#"))
    body = []
    for line in lines[start + 1:]:
        match = re.match(r"(#+) ", line)
        if match and len(match.group(1)) <= level:
            break
        body.append(line)
    return "\n".join(body)


class ThreatModelDocumentTests(unittest.TestCase):
    def test_document_exists(self):
        self.assertTrue(DOC_PATH.is_file(), f"missing {DOC_PATH}")

    def test_required_headings_in_order(self):
        lines = read_document().splitlines()
        positions = []
        for heading in REQUIRED_HEADINGS:
            with self.subTest(heading=heading):
                self.assertEqual(lines.count(heading), 1)
                positions.append(lines.index(heading))
        self.assertEqual(positions, sorted(positions))

    def test_every_threat_separates_the_three_obligations(self):
        text = read_document()
        for heading in THREAT_SECTIONS:
            body = section_body(text, heading)
            bullets = [line for line in body.splitlines() if line.startswith("- ")]
            for label in OBLIGATION_LABELS:
                with self.subTest(section=heading, label=label):
                    matches = [line for line in bullets if line.startswith(label)]
                    self.assertEqual(len(matches), 1)
            with self.subTest(section=heading, check="order"):
                order = [
                    next(i for i, line in enumerate(bullets) if line.startswith(label))
                    for label in OBLIGATION_LABELS
                ]
                self.assertEqual(order, sorted(order))
            with self.subTest(section=heading, check="threat"):
                threats = [line for line in body.splitlines() if line.startswith("Threat:")]
                self.assertEqual(len(threats), 1)

    def test_key_statements_are_present(self):
        text = normalize(read_document())
        for statement in KEY_STATEMENTS:
            with self.subTest(statement=statement):
                self.assertIn(normalize(statement), text)

    def test_declared_limits_table(self):
        body = section_body(read_document(), "## 6. Declared limits")
        rows = [line for line in body.splitlines() if re.match(r"\| H\d+ \|", line)]
        self.assertEqual(
            [row.split("|")[1].strip() for row in rows], list(DECLARED_LIMITS)
        )
        for row in rows:
            label = row.split("|")[1].strip()
            with self.subTest(label=label):
                self.assertEqual(row.split("|")[3].strip(), DECLARED_LIMITS[label])
                self.assertTrue(row.split("|")[2].strip())

    def test_known_documentation_limits_are_listed_not_changed(self):
        body = section_body(read_document(), "## 7. Known documentation limits")
        self.assertIn("are not changed by this document", normalize(body))
        for reference in KNOWN_DOCUMENTATION_LIMITS:
            with self.subTest(reference=reference):
                self.assertIn(reference, body)

    def test_invariant_index_is_complete_and_ordered(self):
        text = read_document()
        body = section_body(text, "## 8. Invariant index")
        found = re.findall(r"^- \*\*(TM3-INV-\d{2})\*\*: \S", body, re.MULTILINE)
        expected = [f"TM3-INV-{n:02d}" for n in range(1, INVARIANT_COUNT + 1)]
        self.assertEqual(found, expected)
        for identifier in expected:
            with self.subTest(identifier=identifier):
                self.assertEqual(text.count(identifier), 1)

    def test_no_affirmative_forbidden_claim(self):
        self.assertEqual(lint_text(read_document(), str(DOC_PATH)), [])

    def test_no_risk_is_declared_resolved(self):
        for number, line in enumerate(read_document().splitlines(), start=1):
            match = RESOLUTION_CLAIM.search(line)
            with self.subTest(line=number):
                self.assertIsNone(match, line.strip()[:160])

    def test_verbatim_non_claims(self):
        body = normalize(section_body(read_document(), "## 9. Non-claims"))
        for statement in VERBATIM_NON_CLAIMS:
            with self.subTest(statement=statement[:40]):
                self.assertIn(normalize(statement), body)

    def test_protocol_threat_model_is_referenced_and_unchanged(self):
        self.assertIn(PROTOCOL_THREAT_MODEL_SHA256, read_document())
        digest = hashlib.sha256(PROTOCOL_THREAT_MODEL.read_bytes()).hexdigest()
        self.assertEqual(digest, PROTOCOL_THREAT_MODEL_SHA256)


class SectionBodyTests(unittest.TestCase):
    def test_section_body_stops_at_same_or_higher_level(self):
        text = "## A\none\n### A.1\ntwo\n## B\nthree"
        self.assertEqual(section_body(text, "## A"), "one\n### A.1\ntwo")
        self.assertEqual(section_body(text, "### A.1"), "two")

    def test_resolution_pattern(self):
        self.assertIsNotNone(RESOLUTION_CLAIM.search("This risk is resolved."))
        self.assertIsNotNone(RESOLUTION_CLAIM.search("both were fully mitigated"))
        self.assertIsNotNone(RESOLUTION_CLAIM.search("it is partially resolved"))
        self.assertIsNotNone(RESOLUTION_CLAIM.search("it was largely mitigated"))
        self.assertIsNotNone(RESOLUTION_CLAIM.search("the gap has been remediated"))
        self.assertIsNone(RESOLUTION_CLAIM.search("is not resolved by this document"))


if __name__ == "__main__":
    unittest.main()
