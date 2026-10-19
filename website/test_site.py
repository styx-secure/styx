"""Structural safety checks for the dependency-free Styx landing page."""

from __future__ import annotations

import unittest
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse


SITE = Path(__file__).resolve().parent
HTML_PATH = SITE / "index.html"
CSS_PATH = SITE / "styles.css"
SVG_PATH = SITE / "assets" / "styx-mark.svg"
DEMO_HTML_PATH = SITE / "demo" / "index.html"

REQUIRED_IDS = {
    "main",
    "mission",
    "problem",
    "audiences",
    "architecture",
    "flegias",
    "evidence",
    "roadmap",
    "boundaries",
    "open-source",
    "contribute",
}

PROHIBITED_ELEMENTS = {"script", "form", "iframe", "object", "embed"}
RUNTIME_ATTRIBUTES = {
    "img": "src",
    "source": "src",
    "video": "src",
    "audio": "src",
}


class DocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.start_tags: list[tuple[str, dict[str, str]]] = []
        self.ids: list[str] = []
        self.h1_count = 0
        self.title_depth = 0
        self.title_text: list[str] = []
        self.anchor_depth = 0
        self.current_anchor_text: list[str] = []
        self.anchor_texts: list[str] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name: value or "" for name, value in attrs}
        self.start_tags.append((tag, values))
        if "id" in values:
            self.ids.append(values["id"])
        if tag == "h1":
            self.h1_count += 1
        if tag == "title":
            self.title_depth += 1
        if tag == "a":
            self.anchor_depth += 1
            self.current_anchor_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self.title_depth -= 1
        if tag == "a":
            self.anchor_texts.append(
                " ".join(" ".join(self.current_anchor_text).split())
            )
            self.anchor_depth -= 1

    def handle_data(self, data: str) -> None:
        self.text.append(data)
        if self.title_depth:
            self.title_text.append(data)
        if self.anchor_depth:
            self.current_anchor_text.append(data)


class LandingPageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.html = HTML_PATH.read_text(encoding="utf-8")
        cls.css = CSS_PATH.read_text(encoding="utf-8")
        cls.parser = DocumentParser()
        cls.parser.feed(cls.html)
        cls.tags = cls.parser.start_tags
        cls.text = " ".join(" ".join(cls.parser.text).split())

    def tags_named(self, name: str) -> list[dict[str, str]]:
        return [attrs for tag, attrs in self.tags if tag == name]

    def test_document_metadata_is_complete_and_english(self) -> None:
        html_tags = self.tags_named("html")
        self.assertEqual(len(html_tags), 1)
        self.assertEqual(html_tags[0].get("lang"), "en")

        title = "".join(self.parser.title_text).strip()
        self.assertIn("Styx", title)
        self.assertIn("Secure infrastructure", title)

        descriptions = [
            tag.get("content", "")
            for tag in self.tags_named("meta")
            if tag.get("name") == "description"
        ]
        self.assertEqual(len(descriptions), 1)
        self.assertGreaterEqual(len(descriptions[0]), 80)
        self.assertIn("Flegias", descriptions[0])

        color_schemes = [
            tag.get("content", "")
            for tag in self.tags_named("meta")
            if tag.get("name") == "color-scheme"
        ]
        self.assertEqual(color_schemes, ["light"])

    def test_semantic_outline_and_required_sections(self) -> None:
        self.assertEqual(self.parser.h1_count, 1)
        self.assertEqual(len(self.parser.ids), len(set(self.parser.ids)))
        self.assertTrue(REQUIRED_IDS.issubset(set(self.parser.ids)))
        for landmark in ("header", "nav", "main", "footer"):
            self.assertTrue(self.tags_named(landmark), f"missing {landmark} landmark")

    def test_prohibited_runtime_elements_are_absent(self) -> None:
        present = {tag for tag, _ in self.tags}
        self.assertFalse(PROHIBITED_ELEMENTS & present)
        self.assertNotIn("javascript:", self.html.lower())
        self.assertNotRegex(self.html.lower(), r"\son[a-z]+\s*=")

    def test_all_runtime_resources_are_local_and_exist(self) -> None:
        resources: list[str] = []
        for tag, attribute in RUNTIME_ATTRIBUTES.items():
            resources.extend(
                attrs[attribute]
                for attrs in self.tags_named(tag)
                if attrs.get(attribute)
            )
        resources.extend(
            attrs["href"]
            for attrs in self.tags_named("link")
            if attrs.get("rel") in {"stylesheet", "icon"} and attrs.get("href")
        )

        self.assertTrue(resources)
        for resource in resources:
            parsed = urlparse(resource)
            self.assertFalse(parsed.scheme or parsed.netloc, resource)
            resolved = (SITE / parsed.path).resolve()
            self.assertTrue(resolved.is_relative_to(SITE), resource)
            self.assertTrue(resolved.is_file(), resource)

        self.assertNotRegex(self.css, r"(?i)@import\b")
        self.assertNotRegex(self.css, r"(?i)url\s*\(")
        self.assertNotRegex(self.css, r"(?i)https?://|//[a-z0-9]")

    def test_external_links_are_explicit_and_safe(self) -> None:
        external_links = []
        for attrs in self.tags_named("a"):
            href = attrs.get("href", "")
            if urlparse(href).scheme in {"http", "https"}:
                external_links.append(attrs)

        self.assertTrue(external_links)
        for attrs in external_links:
            self.assertEqual(attrs.get("target"), "_blank", attrs.get("href"))
            rel = set(attrs.get("rel", "").split())
            self.assertTrue({"noopener", "noreferrer"}.issubset(rel), attrs.get("href"))

    def test_local_navigation_targets_exist(self) -> None:
        known_ids = set(self.parser.ids)
        for attrs in self.tags_named("a"):
            href = attrs.get("href", "")
            if href.startswith("#"):
                self.assertIn(href[1:], known_ids, href)
            elif href and not urlparse(href).scheme:
                parsed = urlparse(href)
                target = (SITE / parsed.path).resolve()
                self.assertTrue(target.is_relative_to(SITE), href)
                self.assertTrue(target.is_file(), href)

    def test_first_viewport_content_and_warning_are_present(self) -> None:
        for phrase in (
            "Secure infrastructure for sensitive work",
            "human-rights and civil-society teams",
            "Flegias by Styx",
            "Not ready for live reporting",
            "has not completed an independent security audit",
            "must not be used for sensitive, high-risk, or life-critical work",
        ):
            self.assertIn(phrase, self.text)

    def test_flegias_name_is_current_and_stale_legacy_surface_is_absent(self) -> None:
        self.assertIn("Flegias by Styx", self.text)
        self.assertIn('id="flegias"', self.html)
        self.assertIn(".flegias", self.css)
        flegias_nav = [
            text
            for (tag, attrs), text in zip(
                (item for item in self.tags if item[0] == "a"),
                self.parser.anchor_texts,
                strict=True,
            )
            if attrs.get("href") == "#flegias"
        ]
        self.assertIn("Flegias", flegias_nav)

        demo_html = DEMO_HTML_PATH.read_text(encoding="utf-8")
        self.assertIn("No Flegias workflow", demo_html)

        # Build the former token so this guard does not become a live stale
        # reference rejected by the repository-wide migration check itself.
        legacy = "the" + "mis"
        for surface in (self.html, self.css, demo_html):
            self.assertNotIn(legacy, surface.lower())

    def test_current_evidence_links_are_marked(self) -> None:
        evidence_links = [
            attrs
            for attrs in self.tags_named("a")
            if attrs.get("data-status") == "implemented"
        ]
        self.assertGreaterEqual(len(evidence_links), 5)
        for attrs in evidence_links:
            self.assertIn("github.com/styx-secure/styx", attrs.get("href", ""))

    def test_c03_evidence_is_current_bounded_and_links_one_explorer(self) -> None:
        for phrase in (
            "Conformance evidence on main",
            "Synthetic C0.3 conformance corpus",
            "independent Python and JavaScript replay",
            "not implementation conformance, a security audit, or product readiness",
            "C0.3 remains NO-GO",
        ):
            self.assertIn(phrase, self.text)

        hrefs = {attrs.get("href", "") for attrs in self.tags_named("a")}
        self.assertIn(
            "https://github.com/styx-secure/styx/blob/main/"
            "conformance/application-protocol/c03/manifest.json",
            hrefs,
        )
        self.assertIn(
            "https://github.com/styx-secure/styx/blob/main/"
            "tools/causal-flow-simulator/c03/README.md",
            hrefs,
        )
        explorer_links = [
            attrs
            for attrs in self.tags_named("a")
            if attrs.get("data-status") == "explorer"
        ]
        self.assertEqual(
            explorer_links,
            [{"data-status": "explorer", "href": "demo/index.html"}],
        )
        explorer_text = [
            text
            for attrs, text in zip(
                self.tags_named("a"), self.parser.anchor_texts, strict=True
            )
            if attrs.get("data-status") == "explorer"
        ]
        self.assertEqual(explorer_text, ["Explore the evidence visually →"])

    def test_svg_is_restricted_human_readable_source(self) -> None:
        source = SVG_PATH.read_text(encoding="utf-8")
        self.assertLess(len(source), 4096)
        self.assertNotRegex(source, r"(?i)<(?:script|image|foreignObject)\b")
        self.assertNotRegex(source, r"(?i)(?:href|src)\s*=")
        content_without_namespace = source.replace("http://www.w3.org/2000/svg", "")
        self.assertNotRegex(content_without_namespace, r"(?i)data:|https?://")

        root = ET.fromstring(source)
        self.assertEqual(root.tag, "{http://www.w3.org/2000/svg}svg")
        self.assertEqual(root.get("viewBox"), "0 0 96 96")
        self.assertEqual(len(root.findall("{http://www.w3.org/2000/svg}title")), 1)
        self.assertEqual(len(root.findall("{http://www.w3.org/2000/svg}desc")), 1)

    def test_responsive_and_accessibility_rules_exist(self) -> None:
        self.assertRegex(self.css, r"@media\s*\(max-width:\s*560px\)")
        self.assertRegex(self.css, r"@media\s*\(prefers-reduced-motion:\s*reduce\)")
        self.assertRegex(self.css, r":focus-visible")
        self.assertIn(".skip-link", self.css)
        self.assertIn("overflow: hidden", self.css)
        self.assertIn("outline: 3px solid var(--foam)", self.css)
        self.assertIn("box-shadow: 0 0 0 7px var(--obsidian)", self.css)


if __name__ == "__main__":
    unittest.main()
