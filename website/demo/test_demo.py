"""Structural, provenance and claim-boundary tests for the C0.3 explorer."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse


DEMO = Path(__file__).resolve().parent
REPO = DEMO.parents[1]
HTML_PATH = DEMO / "index.html"
CSS_PATH = DEMO / "styles.css"
APP_PATH = DEMO / "app.mjs"
DATA_PATH = DEMO / "data" / "c03-evidence.json"
CORPUS = REPO / "conformance" / "application-protocol" / "c03"


class DemoParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags: list[tuple[str, dict[str, str]]] = []
        self.ids: list[str] = []
        self.text: list[str] = []
        self.h1_count = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        self.tags.append((tag, values))
        if values.get("id"):
            self.ids.append(values["id"])
        if tag == "h1":
            self.h1_count += 1

    def handle_data(self, data: str) -> None:
        self.text.append(data)


def _load_builder():
    spec = importlib.util.spec_from_file_location("styx_demo_build_data", DEMO / "build_data.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load build_data.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EvidenceExplorerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = HTML_PATH.read_text(encoding="utf-8")
        cls.css = CSS_PATH.read_text(encoding="utf-8")
        cls.app = APP_PATH.read_text(encoding="utf-8")
        cls.data_raw = DATA_PATH.read_bytes()
        cls.data = json.loads(cls.data_raw)
        cls.parser = DemoParser()
        cls.parser.feed(cls.html)
        cls.text = " ".join(" ".join(cls.parser.text).split())

    def tags_named(self, name: str) -> list[dict[str, str]]:
        return [attrs for tag, attrs in self.parser.tags if tag == name]

    def test_projection_regenerates_byte_for_byte(self) -> None:
        builder = _load_builder()
        expected = builder.canonical_bytes(builder.build_projection(REPO))
        self.assertEqual(self.data_raw, expected)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "c03-evidence.json"
            output.write_bytes(expected)
            self.assertEqual(output.read_bytes(), self.data_raw)

    def test_projection_identity_counts_and_claim_boundaries(self) -> None:
        self.assertEqual(self.data["schema"], "styx-c03-evidence-explorer/v1")
        self.assertIs(self.data["source"]["synthetic"], True)
        self.assertEqual(self.data["authority"]["c03Verdict"], "NO_GO")
        self.assertEqual(
            self.data["authority"]["blocks"],
            ["demo", "implementation_alignment", "product", "sensitive_use"],
        )
        self.assertEqual(
            self.data["counts"],
            {"invalidVectors": 29, "mutations": 501, "scenarios": 118, "traces": 118, "validVectors": 17},
        )
        self.assertEqual(len(self.data["vectors"]), 46)
        self.assertEqual(len(self.data["scenarios"]), 118)
        self.assertEqual(len(self.data["mutations"]), 501)
        self.assertEqual(
            set(self.data["nonClaims"]),
            {
                "NO_IMPLEMENTATION_ALIGNMENT",
                "NO_PRODUCT_OR_DEMO_READINESS",
                "NO_PRODUCTION_CEREMONY_OR_RECOVERY",
                "NO_RUNTIME_STORAGE_TRANSPORT_OR_WIRE_CLAIM",
                "NO_SECURITY_PROOF_OR_AUDIT",
                "NO_SENSITIVE_USE",
            },
        )

    def test_projection_preserves_exact_scenario_trace_relation(self) -> None:
        scenarios = json.loads((CORPUS / "state-machine-scenarios.json").read_text())["records"]
        traces = json.loads((CORPUS / "expected-traces.json").read_text())["records"]
        source_steps = {record["id"]: len(record["steps"]) for record in scenarios}
        trace_steps = {record["scenarioId"]: len(record["steps"]) for record in traces}
        projected_steps = {record["id"]: len(record["steps"]) for record in self.data["scenarios"]}
        self.assertEqual(projected_steps, source_steps)
        self.assertEqual(projected_steps, trace_steps)
        for record in self.data["scenarios"]:
            for index, step in enumerate(record["steps"]):
                self.assertEqual(step["observed"]["step"], index)

    def test_projection_omits_secret_like_and_full_byte_material(self) -> None:
        forbidden = {
            "transcriptHex",
            "signatureHex",
            "verificationKeyHex",
            "credentialIdentifierHex",
            "contextIdentifierHex",
            "opening",
        }

        def visit(value) -> None:
            if isinstance(value, dict):
                self.assertFalse(forbidden & set(value))
                for child in value.values():
                    visit(child)
            elif isinstance(value, list):
                for child in value:
                    visit(child)

        visit(self.data)

    def test_document_is_semantic_and_scope_warning_is_unavoidable(self) -> None:
        self.assertEqual(self.parser.h1_count, 1)
        self.assertEqual(len(self.parser.ids), len(set(self.parser.ids)))
        for landmark in ("header", "main", "footer"):
            self.assertTrue(self.tags_named(landmark), landmark)
        for phrase in (
            "Synthetic · transcript-only · read-only",
            "Current phase verdict NO-GO",
            "not a product, security, encryption or implementation demo",
            "No implementation alignment",
            "No sensitive use",
            "The interactive replay is unavailable",
            "Input transcript summary",
            "does not describe transport encryption, recipients, routing metadata or plaintext visibility",
        ):
            self.assertIn(phrase, self.text)

    def test_csp_and_runtime_resources_are_local(self) -> None:
        policies = [
            attrs.get("content", "")
            for attrs in self.tags_named("meta")
            if attrs.get("http-equiv", "").lower() == "content-security-policy"
        ]
        self.assertEqual(len(policies), 1)
        for directive in (
            "default-src 'self'",
            "script-src 'self'",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'none'",
            "form-action 'none'",
        ):
            self.assertIn(directive, policies[0])

        resources = []
        for tag, attribute in (("script", "src"), ("link", "href"), ("img", "src")):
            resources.extend(attrs[attribute] for attrs in self.tags_named(tag) if attrs.get(attribute))
        for resource in resources:
            parsed = urlparse(resource)
            self.assertFalse(parsed.scheme or parsed.netloc, resource)
            resolved = (DEMO / parsed.path).resolve()
            self.assertTrue(resolved.is_relative_to(DEMO.parent), resource)
            self.assertTrue(resolved.is_file(), resource)

    def test_external_links_are_safe_and_no_unsafe_dom_sink_exists(self) -> None:
        external = [
            attrs
            for attrs in self.tags_named("a")
            if urlparse(attrs.get("href", "")).scheme in {"http", "https"}
        ]
        self.assertTrue(external)
        for attrs in external:
            self.assertEqual(attrs.get("target"), "_blank")
            self.assertTrue({"noopener", "noreferrer"}.issubset(set(attrs.get("rel", "").split())))
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            self.assertNotIn(sink, self.app)
        self.assertEqual(self.app.count("fetch("), 1)
        self.assertIn('fetch("./data/c03-evidence.json"', self.app)

    def test_progressive_enhancement_and_accessible_controls(self) -> None:
        for control_id in ("scenario-search", "model-filter", "previous-step", "reset-step", "next-step", "mutation-search"):
            matches = [attrs for attrs in self.parser.tags if attrs[1].get("id") == control_id]
            self.assertEqual(len(matches), 1, control_id)
            self.assertIn("disabled", matches[0][1], control_id)
        self.assertIn('aria-live="polite"', self.html)
        self.assertIn(".skip-link", self.css)
        self.assertIn(":focus-visible", self.css)
        self.assertIn("@media (max-width: 360px)", self.css)
        self.assertIn("@media (prefers-reduced-motion: reduce)", self.css)


if __name__ == "__main__":
    unittest.main()
