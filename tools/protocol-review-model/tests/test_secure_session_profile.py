"""Closed derived-model checks for the Gate-A-frozen SS-0 profile."""

from __future__ import annotations

import copy
import unittest

from support import MODEL_PATH, REPO_ROOT, SCHEMA_PATH, load_validator


validator = load_validator()


class SecureSessionProfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.model = validator.load_json_unique(MODEL_PATH)
        cls.schema = validator.load_json_unique(SCHEMA_PATH)

    def codes(self, model: dict) -> set[str]:
        return {
            finding.code
            for finding in validator.validate(model, self.schema, REPO_ROOT)
        }

    def test_gate_a_source_and_scope_are_exact(self) -> None:
        sources = {source["id"]: source for source in self.model["sources"]}
        self.assertEqual(
            {
                "authority": "normative",
                "id": "secure_session_decisions",
                "path": "docs/protocol/styx-secure-session-v0-decisions.md",
                "sha256": "235bcb86f9dd25e3c3cb56ed3a0b4820214821cf78ea881547c824db831eba07",
            },
            sources["secure_session_decisions"],
        )
        self.assertEqual(validator.EXPECTED_MODELED_SCOPE, self.model["modeled_scope"])
        self.assertFalse(self.model["artifact"]["implementation_claim"])
        self.assertEqual("NO_GO", self.model["artifact"]["c03_verdict"])

    def test_every_decision_has_one_normative_source(self) -> None:
        actual = {
            record["decision_id"]: record["source_id"]
            for record in self.model["decision_sources"]
        }
        self.assertEqual(validator.EXPECTED_DECISION_SOURCES, actual)
        self.assertEqual(len(actual), len(self.model["decision_sources"]))

    def test_ss_boundary_is_closed(self) -> None:
        actors = {record["id"]: record for record in self.model["actors"]}
        layers = {record["id"]: record for record in self.model["layers"]}
        for record in (actors["secure_session_adapter"], layers["SS"]):
            self.assertEqual(
                validator.EXPECTED_SS_DECISION_REFS, record["decision_refs"]
            )
            self.assertEqual(
                validator.EXPECTED_SS_OBLIGATION_REFS, record["obligation_refs"]
            )
        self.assertEqual(
            validator.EXPECTED_SS_FORBIDDEN_INFERENCES,
            layers["SS"]["forbidden_inferences"],
        )

    def test_missing_duplicate_unknown_and_misattributed_decisions_fail_closed(self) -> None:
        mutations = []

        missing = copy.deepcopy(self.model)
        missing["decision_sources"] = missing["decision_sources"][1:]
        mutations.append((missing, "REQUIRED_RECORD_MISSING"))

        duplicate = copy.deepcopy(self.model)
        duplicate["decision_sources"].append(
            copy.deepcopy(duplicate["decision_sources"][0])
        )
        mutations.append((duplicate, "DUPLICATE_ID"))

        unknown = copy.deepcopy(self.model)
        unknown["decision_sources"][0]["decision_id"] = "SSD-99"
        mutations.append((unknown, "UNKNOWN_REGISTRY_VALUE"))

        misattributed = copy.deepcopy(self.model)
        index = next(
            index
            for index, record in enumerate(misattributed["decision_sources"])
            if record["decision_id"] == "SSD-01"
        )
        misattributed["decision_sources"][index]["source_id"] = "decisions"
        mutations.append((misattributed, "PINNED_VALUE_DRIFT"))

        inconsistent = copy.deepcopy(self.model)
        inconsistent["modeled_scope"]["supported_adapter"] = True
        mutations.append((inconsistent, "PINNED_VALUE_DRIFT"))

        for model, expected in mutations:
            with self.subTest(expected=expected):
                self.assertIn(expected, self.codes(model))

    def test_ss_registry_drift_fails_closed(self) -> None:
        model = copy.deepcopy(self.model)
        model["registries"]["decisions"].remove("SSD-11")
        self.assertIn("UNKNOWN_REGISTRY_VALUE", self.codes(model))


if __name__ == "__main__":
    unittest.main()
