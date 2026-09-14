from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jsonschema.validators import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from generate_structural_witnesses import (  # noqa: E402
    _PARENT_RESOLVED_ARRAY_INSERTION_FAMILIES,
    _load_phase_a,
    _resolve_data_pointer,
    derive_phase_b_registries,
    derive_seed_registry,
    derive_structural_isolation_preflight,
    derive_structural_plan,
    derive_structural_target_preflight,
    main as structural_main,
    validate_structural_witness_identifiers,
    WitnessGenerationError,
)
from generate_seed_registry import (  # noqa: E402
    _evaluate_fixture_request,
    _semantic_request_carriers,
    generate_phase_a,
)
from canonical_json import dumps as canonical_dumps  # noqa: E402
from canonical_report import canonical_bytes  # noqa: E402
from inventory import (  # noqa: E402
    LogicalTerminal,
    derive_acv049_path_partition,
    resolve_logical_terminal,
)
from interface_model import ContractAuthority  # noqa: E402
from run_mutations import build_report as build_phase_a_mutation_report  # noqa: E402
from run_semantic_preflight import (  # noqa: E402
    SemanticPreflightError,
    build_report_from_seed_registry as build_semantic_preflight,
)
from run_semantic_acv048 import derive_python_report as derive_acv048_report  # noqa: E402
from run_semantic_acv049 import (  # noqa: E402
    REPORT_FIELDS as ACV049_REPORT_FIELDS,
    SemanticACV049Error,
    _SourceSiteInstrumenter,
    _SourceTaggedString,
    _changed_json_pointers,
    _derive_schema_candidate_pair,
    _mutated_source_tree,
    _pattern_values,
    _raw_report_logical_path,
    _store_external_artifact,
    _tag_source_value,
    _terminal_execution_plan,
    _value_at_report_pointer,
    build_report as build_acv049_preflight,
    build_phase_a_enum_tuple_source_mutant_manifest,
    build_phase_a_scalar_source_mutant_manifest,
    build_scalar_source_mutant_spec,
    build_terminal_jobs as build_acv049_terminal_jobs,
    derive_phase_a_materialized_paths,
    derive_phase_a_source_site_map,
)


class StructuralPlanTests(unittest.TestCase):
    _MINIMAL_SCHEMA = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": {},
    }

    @staticmethod
    def _terminal(*nodes: dict[str, object]) -> LogicalTerminal:
        return LogicalTerminal((), nodes, tuple(f"/node/{i}" for i in range(len(nodes))), ())

    def test_acv049_source_tagging_is_value_preserving_and_nearest_site_wins(
        self,
    ) -> None:
        tagged = _tag_source_value(
            "PURITY-SITE-FIRST",
            {"outer": ["alpha", {"inner": "bravo"}], "number": 7},
        )
        self.assertEqual(
            tagged,
            {"outer": ["alpha", {"inner": "bravo"}], "number": 7},
        )
        self.assertIsInstance(tagged["outer"][0], _SourceTaggedString)
        self.assertEqual(tagged["outer"][0].site_id, "PURITY-SITE-FIRST")
        self.assertEqual(tagged["outer"][0].source_tokens, ("outer", 0))
        self.assertEqual(
            tagged["outer"][1]["inner"].source_tokens,
            ("outer", 1, "inner"),
        )
        retagged = _tag_source_value("PURITY-SITE-SECOND", tagged)
        self.assertEqual(retagged["outer"][0].site_id, "PURITY-SITE-FIRST")
        self.assertIs(copy.deepcopy(retagged["outer"][0]), retagged["outer"][0])

    def test_acv049_pattern_expansion_retains_every_concrete_pointer(self) -> None:
        value = {"items": [{"state": "one"}, {"state": "two"}]}
        self.assertEqual(
            _pattern_values(value, ("items", None, "state")),
            [
                (("items", 0, "state"), "one"),
                (("items", 1, "state"), "two"),
            ],
        )
        self.assertEqual(_pattern_values(value, ("missing",)), [])

    def test_acv049_external_diagnostics_report_exact_changed_leaves(self) -> None:
        baseline = {"result": {"items": [{"state": "READY"}], "count": 1}}
        candidate = {"result": {"items": [{"state": "REJECTED"}], "count": 2}}
        self.assertEqual(
            _changed_json_pointers(baseline, candidate),
            [
                "JSON_POINTER:result%2Fcount",
                "JSON_POINTER:result%2Fitems%2F0%2Fstate",
            ],
        )
        self.assertEqual(
            _changed_json_pointers({"result": {}}, {"result": {"new": True}}),
            ["JSON_POINTER:result"],
        )

    def test_acv049_duplicate_explicit_removal_site_fails_closed(self) -> None:
        tree = ast.parse(
            "def _assemble_context_projection():\n"
            "    result = {}\n"
            "    result['retentionState'] = 'FIRST'\n"
            "    result['retentionState'] = 'SECOND'\n"
            "    return result\n"
        )
        with self.assertRaisesRegex(
            SemanticACV049Error, "duplicate ACV-049 construction site"
        ):
            _SourceSiteInstrumenter().visit(tree)

    def test_acv049_schema_candidate_recipes_are_finite_and_ordered(self) -> None:
        channels = ("CHANNEL-ZULU", "CHANNEL-ALPHA")
        ordered = sorted(channel.encode("ascii") for channel in channels)
        hex_pair = _derive_schema_candidate_pair(
            self._MINIMAL_SCHEMA,
            self._terminal({"type": "string", "pattern": "^[0-9a-f]{64}$"}),
            "0" * 64,
            channels,
        )
        self.assertEqual(
            hex_pair["candidateValues"],
            [hashlib.sha256(channel).hexdigest() for channel in ordered],
        )
        self.assertEqual(hex_pair["domainClass"], "HEX64")

        decimal_terminal = self._terminal(
            {"type": "string", "pattern": "^(0|[1-9][0-9]*)$"},
            {"maxLength": 5},
        )
        initial = _derive_schema_candidate_pair(
            self._MINIMAL_SCHEMA, decimal_terminal, "99999", channels
        )
        collided = _derive_schema_candidate_pair(
            self._MINIMAL_SCHEMA,
            decimal_terminal,
            initial["candidateValues"][0],
            channels,
        )
        self.assertEqual(collided["advanceCounts"], [1, 0])
        self.assertNotIn(
            initial["candidateValues"][0], collided["candidateValues"]
        )
        self.assertTrue(
            all(len(value) <= 5 for value in collided["candidateValues"])
        )

    def test_acv049_enum_candidate_recipe_respects_reserved_and_singleton(
        self,
    ) -> None:
        terminal = self._terminal({"enum": ["B", "A", "C"]})
        two_state = _derive_schema_candidate_pair(
            self._MINIMAL_SCHEMA,
            terminal,
            "B",
            ("CHANNEL-ALPHA", "CHANNEL-BRAVO"),
            reserved_values=frozenset({"C"}),
        )
        self.assertEqual(two_state["candidateValues"], ["A", "B"])
        self.assertTrue(two_state["twoStateRule"])
        singleton = _derive_schema_candidate_pair(
            self._MINIMAL_SCHEMA,
            terminal,
            "B",
            ("CHANNEL-ALPHA", "CHANNEL-BRAVO"),
            reserved_values=frozenset({"A", "C"}),
        )
        self.assertEqual(singleton["candidateValues"], [])
        self.assertEqual(singleton["evidenceDisposition"], "RELATION_SINGLETON")

    def test_acv049_candidate_recipe_rejects_unratified_channels_and_patterns(
        self,
    ) -> None:
        terminal = self._terminal({"type": "string", "pattern": "^open$"})
        for channels, message in (
            (("SAME", "SAME"), "not distinct"),
            (("CHANNEL-ALPHA", "line\nfeed"), "canonical ASCII"),
        ):
            with self.subTest(channels=channels):
                with self.assertRaisesRegex(SemanticACV049Error, message):
                    _derive_schema_candidate_pair(
                        self._MINIMAL_SCHEMA, terminal, "open", channels
                    )
        with self.assertRaisesRegex(SemanticACV049Error, "no ratified recipe"):
            _derive_schema_candidate_pair(
                self._MINIMAL_SCHEMA,
                terminal,
                "open",
                ("CHANNEL-ALPHA", "CHANNEL-BRAVO"),
            )

    def test_acv049_source_mutant_changes_only_the_exact_ast_site(self) -> None:
        source = (
            '"""fixture"""\n'
            "from __future__ import annotations\n"
            "def build():\n"
            "    return {'value': 'baseline', 'control': 'unchanged'}\n"
        )
        mapper = _SourceSiteInstrumenter()
        mapper.visit(ast.parse(source))
        target = next(
            site_id
            for site_id, row in mapper.sites.items()
            if row["label"] == "value"
        )
        channels = ("CHANNEL-BRAVO", "CHANNEL-ALPHA")
        transformed, sites, canonical_source = _mutated_source_tree(
            source,
            "fixture.py",
            {target: (((), ("candidate-alpha", "candidate-bravo")),)},
            channels,
        )
        self.assertEqual(set(sites), set(mapper.sites))
        namespace: dict[str, object] = {}
        exec(compile(transformed, "fixture.py", "exec"), namespace)
        build = namespace["build"]
        self.assertTrue(callable(build))
        for channel, expected in (
            ("CHANNEL-ALPHA", "candidate-alpha"),
            ("CHANNEL-BRAVO", "candidate-bravo"),
        ):
            with mock.patch.dict(
                "os.environ", {"STYX_ACV049_MUTANT_CHANNEL": channel}, clear=False
            ):
                self.assertEqual(
                    build(),  # type: ignore[operator]
                    {"value": expected, "control": "unchanged"},
                )
        self.assertIn(
            b"from os import environ as _acv049_mutant_environ", canonical_source
        )
        self.assertEqual(canonical_source.count(b"STYX_ACV049_MUTANT_CHANNEL"), 1)

    def test_acv049_source_mutant_rejects_an_absent_site(self) -> None:
        with self.assertRaisesRegex(
            SemanticACV049Error, "source mutation site is absent or dead"
        ):
            _mutated_source_tree(
                "def build():\n    return {'value': 'baseline'}\n",
                "fixture.py",
                {"PURITY-SITE-ABSENT": (((), ("one", "two")),)},
                ("CHANNEL-ALPHA", "CHANNEL-BRAVO"),
            )

    def test_acv049_pn1_rejects_two_ast_sites_disguised_as_one_tuple(self) -> None:
        source = "def build():\n    return {'primary': 'BASE', 'stage': 'START'}\n"
        mapper = _SourceSiteInstrumenter()
        mapper.visit(ast.parse(source))
        mutations = {
            site_id: (((), ("FIRST", "SECOND")),)
            for site_id in mapper.sites
        }
        self.assertEqual(len(mutations), 2)
        with self.assertRaisesRegex(SemanticACV049Error, "exactly one AST construction site"):
            _mutated_source_tree(
                source, "fixture.py", mutations, ("CHANNEL-ALPHA", "CHANNEL-BRAVO")
            )

    def test_v33_record_tuple_owns_one_actual_dictionary_expression(self) -> None:
        import run_semantic_acv049 as semantic

        source = (
            "def _assemble_context_projection():\n"
            "    return {'disposition': 'APPLIED', 'eventReferenceHex': 'AB', "
            "'stage': 'FINAL_AFTER_S6'}\n"
        )
        mapper = _SourceSiteInstrumenter()
        mapper.tuple_constructions = True
        tagged = mapper.visit(ast.parse(source))
        sites = [s for s in mapper.sites.values() if s['kind'] == 'TUPLE-DICT']
        self.assertEqual(len(sites), 1, 'one actual dictionary, not merged leaf sites')
        namespace = {
            '_acv049_tag_source_value': _tag_source_value,
            '_acv049_tuple_source_value': semantic._tuple_source_value,
        }
        exec(compile(ast.fix_missing_locations(tagged), 'fixture.py', 'exec'), namespace)
        row = namespace['_assemble_context_projection']()
        site_id = sites[0]['siteId']
        self.assertEqual(row['disposition'].site_id, site_id)
        self.assertEqual(row['stage'].site_id, site_id)
        self.assertNotEqual(row['eventReferenceHex'].site_id, site_id)
        self.assertEqual(row['disposition'].source_tokens, ('disposition',))
        mutations = {site_id: (
            (('disposition',), ('RETAIN_NEW', 'AUTHORITY_PROJECTION_UNAVAILABLE')),
            (('stage',), ('EVENT_LOCAL', 'S5_AUTHORITY_PROJECTION')),
        )}
        tree, _, _ = _mutated_source_tree(
            source, 'fixture.py', mutations, ('CHANNEL-ALPHA', 'CHANNEL-BRAVO'),
            tuple_constructions=True,
        )
        target = {}
        exec(compile(tree, 'fixture.py', 'exec'), target)
        for channel, disposition, stage in [
            ('CHANNEL-ALPHA', 'RETAIN_NEW', 'EVENT_LOCAL'),
            ('CHANNEL-BRAVO', 'AUTHORITY_PROJECTION_UNAVAILABLE', 'S5_AUTHORITY_PROJECTION'),
        ]:
            with mock.patch.dict(os.environ, {'STYX_ACV049_MUTANT_CHANNEL': channel}):
                self.assertEqual(target['_assemble_context_projection'](), {
                    'disposition': disposition, 'eventReferenceHex': 'AB', 'stage': stage,
                })
        self.assertEqual(target['_acv049_mutated_sites_executed'], {site_id})

    def test_v33_additional_couplings_cannot_fall_back_to_scalar_labels(self) -> None:
        import run_semantic_acv049 as semantic

        prefixes = [
            'InterfaceResponseV0/<OperationResponseEvaluateCandidateV0>/result/evaluation/<CandidateEvaluationReadyV0>/proposal/successor',
            'InterfaceResponseV0/<OperationResponseEvaluateEvidenceUpdateV0>/result/evaluation/<EvidenceUpdateReadyV0>/proposal/successor',
            'InterfaceResponseV0/<OperationResponseReplayContextV0>/result/<ReplayContextResultReadyV0>/proposedContext',
        ]
        paths = [p + '/projection/recordOutcomes/*/' + f
                 for p in prefixes for f in ('disposition', 'stage')]
        paths.append(prefixes[0].split('/proposal/successor')[0] + '/primaryOnCommit')
        paths += ['InterfaceResponseV0/<OperationResponseReplayContextV0>/result/<ReplayContextResultCandidateRejectedV0>/' + f
                  for f in ('primary', 'stage')]
        self.assertEqual(len(set(paths)), 9)
        for path in paths:
            label = semantic._semantic_construction_site(path, 'PURITY-SITE-AST-FIXTURE-001')
            self.assertIn(label, {'PURITY-SITE-RECORD-OUTCOME', 'PURITY-SITE-REPLAY-CANDIDATE-TERMINAL'})

    def test_v33_primary_on_commit_preserves_actual_tuple_propagation(self) -> None:
        import run_semantic_acv049 as semantic

        source = (
            "def _assemble_context_projection():\n"
            "    return {'disposition': 'APPLIED', 'eventReferenceHex': 'AB', 'stage': 'FINAL_AFTER_S6'}\n"
            "def evaluate():\n"
            "    outcome = _assemble_context_projection()\n"
            "    return {'record': outcome, 'primaryOnCommit': str(outcome['disposition'])}\n"
        )
        mapper = _SourceSiteInstrumenter()
        mapper.tuple_constructions = True
        tree = mapper.visit(ast.parse(source))
        namespace = dict(vars(semantic))
        namespace.update({'_acv049_tag_source_value': _tag_source_value,
                          '_acv049_tuple_source_value': semantic._tuple_source_value})
        exec(compile(ast.fix_missing_locations(tree), 'fixture.py', 'exec'), namespace)
        response = namespace['evaluate']()
        disposition = response['record']['disposition']
        self.assertEqual(response['primaryOnCommit'].site_id, disposition.site_id)
        self.assertEqual(response['primaryOnCommit'].source_tokens, disposition.source_tokens)
        self.assertEqual(response['record']['stage'].site_id, disposition.site_id)
        self.assertNotEqual(response['record']['eventReferenceHex'].site_id, disposition.site_id)

    def test_v33_relation_constructors_bind_actual_complete_expressions(self) -> None:
        mapper = _SourceSiteInstrumenter()
        mapper.tuple_constructions = True
        mapper.visit(ast.parse((ROOT / 'interface_model.py').read_text()))
        expected = {
            '_assemble_context_projection': ('disposition', 'stage'),
            '_candidate_result_from_primary': ('primary', 'stage'),
            '_candidate_terminal': ('primary', 'stage'),
            '_rejected_transcript_result': ('reason', 'stage'),
            'evaluate_genesis': ('reason', 'stage'),
            '_project_content_states': ('contentClass', 'localAvailability',
                                        'bindingObservation', 'retentionState', 'replayReadiness'),
        }
        for function, fields in expected.items():
            with self.subTest(function=function):
                sites = [s for s in mapper.sites.values()
                         if s['function'] == function and s['kind'] == 'TUPLE-DICT']
                self.assertTrue(sites, 'missing actual tuple constructor')
                for site in sites:
                    self.assertEqual(tuple(site['tupleFields']), fields)
                    self.assertEqual(len(site['sourceExpressionSha256']), 64)
                    self.assertGreater(site['line'], 0)

    def test_acv049_source_mutant_replaces_one_relation_tuple_atomically(self) -> None:
        source = (
            "def build():\n"
            "    return {'tuple': {'reason': 'BASE', 'stage': 'START'}}\n"
        )
        mapper = _SourceSiteInstrumenter()
        mapper.visit(ast.parse(source))
        target = next(
            site_id
            for site_id, row in mapper.sites.items()
            if row["label"] == "tuple"
        )
        transformed, _sites, _canonical_source = _mutated_source_tree(
            source,
            "fixture.py",
            {
                target: (
                    (("reason",), ("FIRST", "SECOND")),
                    (("stage",), ("S1", "S2")),
                )
            },
            ("CHANNEL-ALPHA", "CHANNEL-BRAVO"),
        )
        namespace: dict[str, object] = {}
        exec(compile(transformed, "fixture.py", "exec"), namespace)
        build = namespace["build"]
        self.assertTrue(callable(build))
        for channel, expected in (
            ("CHANNEL-ALPHA", {"reason": "FIRST", "stage": "S1"}),
            ("CHANNEL-BRAVO", {"reason": "SECOND", "stage": "S2"}),
        ):
            with mock.patch.dict(
                "os.environ", {"STYX_ACV049_MUTANT_CHANNEL": channel}, clear=False
            ):
                self.assertEqual(build(), {"tuple": expected})  # type: ignore[operator]

    def test_acv049_dict_comprehension_mutant_targets_one_runtime_key(self) -> None:
        source = (
            "def sample():\n"
            "    return {f'item-{index}': 'BASE' for index in range(2)}\n"
        )
        site_id = "PURITY-SITE-AST-SAMPLE-DICT-COMPREHENSION-VALUE-001"
        tree, _sites, _canonical = _mutated_source_tree(
            source,
            "synthetic.py",
            {site_id: ((("item-1",), ("ALPHA", "BRAVO")),)},
            (
                "ACV049-CONTROL-CHANNEL-ALPHA",
                "ACV049-CONTROL-CHANNEL-BRAVO",
            ),
        )
        namespace: dict[str, object] = {}
        exec(compile(tree, "synthetic.py", "exec"), namespace)
        sample = namespace["sample"]
        self.assertTrue(callable(sample))
        for channel, expected in (
            ("ACV049-CONTROL-CHANNEL-ALPHA", "ALPHA"),
            ("ACV049-CONTROL-CHANNEL-BRAVO", "BRAVO"),
        ):
            with mock.patch.dict(
                "os.environ", {"STYX_ACV049_MUTANT_CHANNEL": channel}
            ):
                self.assertEqual(
                    sample(),  # type: ignore[operator]
                    {"item-0": "BASE", "item-1": expected},
                )

    def test_acv049_external_artifacts_are_exclusive_and_outside_repository(
        self,
    ) -> None:
        repository = ROOT.parents[2]
        inside = ROOT / "forbidden-acv049-artifact.json"
        with self.assertRaisesRegex(SemanticACV049Error, "path is invalid"):
            _store_external_artifact(repository, inside, {"verdict": "PASS"})
        self.assertFalse(inside.exists())
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "acv049-artifact.json"
            _store_external_artifact(repository, output, {"verdict": "PASS"})
            self.assertEqual(
                output.read_bytes(), canonical_dumps({"verdict": "PASS"})
            )
            with self.assertRaisesRegex(SemanticACV049Error, "path is invalid"):
                _store_external_artifact(repository, output, {"verdict": "PASS"})

    def test_contract_derives_exact_closed_structural_plan(self) -> None:
        report = derive_structural_plan(ROOT / "contract")
        self.assertEqual(report["instance_count"], 1553)
        rows = report["rows"]
        self.assertEqual(len(rows), 1553)
        self.assertEqual(len({row["instanceId"] for row in rows}), 1553)
        self.assertEqual(len({row["assertionId"] for row in rows}), 1553)
        self.assertEqual(len({row["mutationId"] for row in rows}), 1553)
        self.assertEqual(len({row["detectorId"] for row in rows}), 1553)
        self.assertEqual(
            rows[0]["instanceId"], "STR-REQUIRED-PROPERTY-OMISSION--0001"
        )
        self.assertEqual(
            rows[-1]["instanceId"], "STR-MAX-PROPERTIES-OVERFLOW--0001"
        )
        self.assertEqual(
            {row["isolationMode"] for row in rows},
            {
                "TARGET_ONLY_COUNTERFACTUAL",
                "RATIFIED_REDUNDANT_OCCURRENCE_SELF_TEST",
            },
        )

        schema = json.loads(
            (ROOT / "contract/APP-CORE-IFACE-0-STRUCTURAL-WITNESS-SCHEMA-CANDIDATE.json").read_text(
                encoding="utf-8"
            )
        )
        validators = {
            field: Draft202012Validator(
                {"$schema": schema["$schema"], **schema["$defs"][definition]}
            )
            for field, definition in {
                "assertionId": "AssertionId",
                "mutationId": "MutationId",
                "detectorId": "DetectorId",
            }.items()
        }
        for row in rows:
            for field, validator in validators.items():
                self.assertTrue(validator.is_valid(row[field]), (field, row[field]))

        first = rows[0]
        invalid = {
            "wrong namespace": ("assertionId", first["assertionId"].replace("AST-", "DET-", 1)),
            "missing double hyphen": ("assertionId", first["assertionId"].replace("--", "-", 1)),
            "extra hyphen": ("mutationId", first["mutationId"].replace("--", "---", 1)),
        }
        for name, (field, value) in invalid.items():
            with self.subTest(name=name):
                self.assertFalse(validators[field].is_valid(value))

    def test_full_synthesis_cannot_run_without_provider_bound_mode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "witnesses.json"
            result = structural_main(
                ["--contract", str(ROOT / "contract"), "--output", str(output)]
            )
            self.assertEqual(result, 2)
            self.assertFalse(output.exists())


    def test_v33_tuple_observer_rejects_undeclared_propagation_and_off_target_changes(self) -> None:
        import run_semantic_acv049 as semantic

        self.assertTrue(callable(getattr(semantic, "_observe_declared_tuple_change", None)))
        baseline = {
            "outcome": {"disposition": "APPLIED", "stage": "FINAL_AFTER_S6"},
            "primaryOnCommit": "APPLIED", "unchanged": "retained",
        }
        spec = {
            "twoStateRule": False,
            "patches": [
                {"concretePointer": semantic._report_pointer(pointer),
                 "candidateValues": candidates}
                for pointer, candidates in (
                    ("/outcome/disposition", ["AUTHENTIC_BUT_UNAUTHORIZED", "AUTHORITY_PROJECTION_UNAVAILABLE"]),
                    ("/outcome/stage", ["EVENT_LOCAL", "S5_AUTHORITY_PROJECTION"]),
                    ("/primaryOnCommit", ["AUTHENTIC_BUT_UNAUTHORIZED", "AUTHORITY_PROJECTION_UNAVAILABLE"]),
                )
            ],
        }
        observed = copy.deepcopy(baseline)
        for patch in spec["patches"]:
            semantic._set_value_at_report_pointer(
                observed, patch["concretePointer"], patch["candidateValues"][0],
            )
        self.assertEqual(semantic._observe_declared_tuple_change(baseline, observed, spec), 0)
        undeclared = copy.deepcopy(spec)
        undeclared["patches"].pop()
        with self.assertRaisesRegex(SemanticACV049Error, "multiple targets"):
            semantic._observe_declared_tuple_change(baseline, observed, undeclared)
        off_target = copy.deepcopy(observed)
        off_target["unchanged"] = "corrupted"
        with self.assertRaisesRegex(SemanticACV049Error, "multiple targets"):
            semantic._observe_declared_tuple_change(baseline, off_target, spec)
        partial = copy.deepcopy(observed)
        partial["outcome"]["stage"] = "FINAL_AFTER_S6"
        with self.assertRaisesRegex(SemanticACV049Error, "candidate tuple"):
            semantic._observe_declared_tuple_change(baseline, partial, spec)


class PhaseAMutationIntegrationTests(unittest.TestCase):
    def test_v33_recurrence_pair_and_sibling_are_frozen_from_exact_historical_bindings(self) -> None:
        import run_semantic_acv049 as semantic

        self.assertTrue(callable(getattr(semantic, "freeze_v33_recurrence_bindings", None)))
        authority = ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
        legacy = semantic.build_phase_a_scalar_source_mutant_manifest(ROOT.parents[2], ROOT / "contract", self.evidence)
        fields = ("requestCaseId", "concretePointer", "sourceSiteMapRouteSha256")
        identities = [{key: row[key] for key in fields} for row in legacy["pendingGuardedCandidates"]]
        order = lambda row: (row["requestCaseId"], row["concretePointer"])
        a = sorted([row for row in identities if "%2Fsuccessor%2Fprojection%2F" in row["concretePointer"]], key=order)
        b = sorted([row for row in identities if row not in a], key=order)
        c = []
        for target in a:
            old = next(row for row in legacy["pendingGuardedCandidates"] if all(row[key] == target[key] for key in fields))
            sibling_pointer = target["concretePointer"].replace("result%2Fevaluation%2Fproposal%2Fsuccessor", "result%2FproposedContext", 1)
            sibling = next(row for row in legacy["mutants"] if row["requestCaseId"] == "PCR-REQUEST-REPLAY-CONTEXT-0011" and row["concretePointer"] == sibling_pointer)
            c.append({"target": target, "sibling": {key: sibling[key] for key in fields},
                      "historicalTargetAstTag": old["astSiteId"], "historicalSiblingAstSiteId": sibling["astSiteId"],
                      "ownershipStatus": "REQUIRES_REDERIVATION_NOT_PROVEN_BY_HISTORICAL_TAG",
                      "relativeTokens": sibling["relativeTokens"], "historicalMutantId": sibling["mutantId"],
                      "historicalCandidatePairSha256": semantic.sha256_bytes(semantic.dumps(sibling["candidateValues"]))})
        current = derive_phase_a_source_site_map(ROOT.parents[2], ROOT / "contract", self.evidence, tuple_constructions=True)
        bound = semantic.bind_v33_closed_routes(a, b, current)
        baselines = {}
        for case_id in {row["target"]["requestCaseId"] for row in c} | {row["sibling"]["requestCaseId"] for row in c}:
            request = json.loads((self.evidence / "carriers" / (case_id + ".json")).read_bytes())
            baselines[case_id] = semantic._evaluate_fixture_request(authority, request, None)
        frozen = semantic.freeze_v33_recurrence_bindings(c, bound, current, authority.schema, baselines)
        plans = json.loads(frozen)
        self.assertEqual(len(plans), 12)
        self.assertTrue(all(not plan["twoStateRule"] and len(set(plan["candidateValues"])) == 2 for plan in plans))
        self.assertEqual(frozen, semantic.freeze_v33_recurrence_bindings(c, bound, current, authority.schema, baselines))
        swapped = copy.deepcopy(c)
        swapped[0]["sibling"]["requestCaseId"] = "PCR-REQUEST-REPLAY-CONTEXT-0010"
        with self.assertRaises(SemanticACV049Error):
            semantic.freeze_v33_recurrence_bindings(swapped, bound, current, authority.schema, baselines)
        incomplete = dict(baselines)
        incomplete.pop(c[0]["target"]["requestCaseId"])
        with self.assertRaises(SemanticACV049Error):
            semantic.freeze_v33_recurrence_bindings(c, bound, current, authority.schema, incomplete)

    def test_v33_guarded_source_rejection_has_exact_origin_and_no_successor(self) -> None:
        import io
        import run_semantic_acv049 as semantic

        case_id = "PCR-REQUEST-EVALUATE-CANDIDATE-0023"
        request = json.loads((self.evidence / "carriers" / (case_id + ".json")).read_bytes())
        authority = ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
        baseline = semantic._evaluate_fixture_request(authority, request, None)
        pointer = semantic._report_pointer("/result/evaluation/proposal/successor/projection/authority/necessaryCredentialIdentifiers/0")
        source_map = derive_phase_a_source_site_map(ROOT.parents[2], ROOT / "contract", self.evidence, tuple_constructions=True)
        routes = [r for r in source_map["routes"] if r["requestCaseId"] == case_id and pointer in r["concretePointers"]]
        self.assertEqual(len(routes), 1)
        route = routes[0]
        terminal = semantic.resolve_logical_terminal(authority.schema, semantic._raw_report_logical_path(route["logicalPath"]))
        spec = semantic.build_scalar_source_mutant_spec(authority.schema, route, terminal, semantic._value_at_report_pointer(baseline, pointer))
        mutations = {spec["astSiteId"]: ((tuple(spec["relativeTokens"]), tuple(spec["candidateValues"])),)}
        mutated, sites, _ = semantic._mutated_interface_model(ROOT.parents[2], mutations, semantic.ACV049_MUTANT_CHANNELS, tuple_constructions=True)
        for index, channel in enumerate(semantic.ACV049_MUTANT_CHANNELS):
            mutated._acv049_trace_events.clear()
            with mock.patch.dict(os.environ, {semantic.ACV049_MUTANT_CHANNEL_NAME: channel}), mock.patch.dict(sys.modules, {"interface_model": mutated}):
                local = mutated.ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
                with self.assertRaises(mutated.RequestRejected):
                    semantic._evaluate_fixture_request(local, request, None)
            events = mutated._acv049_trace_events
            guards = [event for event in events if event["kind"] == "PRIOR_GUARD"]
            self.assertEqual(len(guards), 1)
            self.assertFalse(guards[0]["value"]["equal"])
            self.assertEqual(events[-1]["kind"], "REQUEST_REJECTED_ORIGIN")
            self.assertEqual(sites[events[-1]["siteId"]]["function"], "evaluate_candidate")
            self.assertFalse(any(sites[e["siteId"]]["function"] == "replay_context" for e in events if e["kind"] == "CONSTRUCTION"))
            actual = guards[0]["value"]["regenerated"]["projection"]["authority"]["necessaryCredentialIdentifiers"][0]
            self.assertEqual(actual, spec["candidateValues"][index])
        mutated._acv049_trace_events.clear()
        with self.assertRaises(mutated.RequestRejected):
            mutated.read_bounded_request(io.BytesIO(b"xx"), maximum_octets=1)
        self.assertEqual(mutated._acv049_trace_events, [], "same-class rejection from another origin has no guard credit")

    def test_v33_closed_route_mapping_requires_exact_bijection_not_counts(self) -> None:
        import run_semantic_acv049 as semantic

        self.assertTrue(callable(getattr(semantic, "bind_v33_closed_routes", None)))
        legacy = semantic.build_phase_a_scalar_source_mutant_manifest(ROOT.parents[2], ROOT / "contract", self.evidence)
        fields = ("requestCaseId", "concretePointer", "sourceSiteMapRouteSha256")
        identities = [{key: row[key] for key in fields} for row in legacy["pendingGuardedCandidates"]]
        order = lambda row: (row["requestCaseId"], row["concretePointer"])
        a = sorted([row for row in identities if "%2Fsuccessor%2Fprojection%2F" in row["concretePointer"]], key=order)
        b = sorted([row for row in identities if row not in a], key=order)
        current = derive_phase_a_source_site_map(ROOT.parents[2], ROOT / "contract", self.evidence, tuple_constructions=True)
        bound = semantic.bind_v33_closed_routes(a, b, current)
        self.assertEqual(len(bound), 48)
        self.assertEqual(sum(row["residualEligible"] for row in bound), 12)
        self.assertEqual({semantic.dumps(row["historical"]) for row in bound}, {semantic.dumps(row) for row in identities})
        for changed_a, changed_b in ((a[:-1], b), (a, b + [b[0]]), (a, [*b[:-1], b[0]])):
            with self.assertRaises(SemanticACV049Error):
                semantic.bind_v33_closed_routes(changed_a, changed_b, current)
        with self.assertRaises(SemanticACV049Error):
            semantic.bind_v33_closed_routes(a, b, current, p_path_count=299)
        changed = copy.deepcopy(current)
        selected = [row for row in changed["routes"] if row["requestCaseId"] == b[0]["requestCaseId"] and b[0]["concretePointer"] in row["concretePointers"]]
        self.assertEqual(len(selected), 1)
        replacement = next(index for index, row in enumerate(changed["routes"]) if row["requestCaseId"] == b[1]["requestCaseId"] and b[1]["concretePointer"] in row["concretePointers"])
        changed["routes"][replacement] = copy.deepcopy(selected[0])
        changed["routeSetSha256"] = semantic.sha256_bytes(semantic.dumps(changed["routes"]))
        with self.assertRaises(SemanticACV049Error):
            semantic.bind_v33_closed_routes(a, b, changed)

    def test_v33_prior_guard_trace_binds_the_unchanged_comparison_and_successor(self) -> None:
        import run_semantic_acv049 as semantic

        traced, sites = semantic._instrumented_interface_model(ROOT.parents[2], tuple_constructions=True)
        request = json.loads((self.evidence / "carriers" / "PCR-REQUEST-EVALUATE-CANDIDATE-0023.json").read_bytes())
        with mock.patch.dict(sys.modules, {"interface_model": traced}):
            local = traced.ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
            response = semantic._evaluate_fixture_request(local, request, None)
        events = getattr(traced, "_acv049_trace_events", [])
        guards = [(index, event) for index, event in enumerate(events) if event["kind"] == "PRIOR_GUARD"]
        self.assertEqual(len(guards), 1, "the exact existing prior comparison must execute")
        index, guard = guards[0]
        self.assertTrue(guard["value"]["equal"])
        self.assertEqual(semantic.dumps(guard["value"]["prior"]), semantic.dumps(request["input"]["prior"]))
        self.assertEqual(semantic.dumps(guard["value"]["regenerated"]), semantic.dumps(request["input"]["prior"]))
        before = {event["siteId"] for event in events[:index] if event["kind"] == "CONSTRUCTION"}
        after = {event["siteId"] for event in events[index + 1:] if event["kind"] == "CONSTRUCTION"}
        self.assertTrue(before & after)
        leaf = response["result"]["evaluation"]["proposal"]["successor"]["projection"]["authority"]["necessaryCredentialIdentifiers"][0]
        self.assertEqual(sites[leaf.site_id]["function"], "_assemble_context_projection")
        self.assertIn(leaf.site_id, before & after)

    def test_v33_successor_copy_owner_is_not_internal_reconstruction(self) -> None:
        import run_semantic_acv049 as semantic

        traced, sites = semantic._instrumented_interface_model(ROOT.parents[2], tuple_constructions=True)
        authority = ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
        for case_id in ("PCR-REQUEST-EVALUATE-CANDIDATE-0023", "PCR-REQUEST-EVALUATE-EVIDENCE-UPDATE-0028"):
            request = json.loads((self.evidence / "carriers" / (case_id + ".json")).read_bytes())
            baseline = semantic._evaluate_fixture_request(authority, request, None)
            with mock.patch.dict(sys.modules, {"interface_model": traced}):
                local = traced.ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
                response = semantic._evaluate_fixture_request(local, request, None)
            self.assertEqual(semantic.dumps(response), semantic.dumps(baseline))
            successor = response["result"]["evaluation"]["proposal"]["successor"]
            copied = [successor["genesis"]["logicalGenesis"]["transcriptHex"]]
            copied.extend(row["transcriptHex"] for row in successor["logicalEvents"])
            self.assertTrue(copied)
            for leaf in copied:
                self.assertEqual(sites[leaf.site_id]["function"], "replay_context",
                                 "internal replay-input reconstruction cannot own an emitted successor")
                self.assertIn(sites[leaf.site_id]["label"], ("genesis", "logicalEvents"))

    def test_v33_e_source_control_rejects_extra_copy_corruption_without_reader_changes(self) -> None:
        import run_semantic_acv049 as semantic

        case_id = "PCR-REQUEST-EVALUATE-CANDIDATE-0023"
        request = json.loads((self.evidence / "carriers" / (case_id + ".json")).read_bytes())
        authority = ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
        baseline = semantic._evaluate_fixture_request(authority, request, None)
        source_map = derive_phase_a_source_site_map(ROOT.parents[2], ROOT / "contract", self.evidence, tuple_constructions=True)
        manifest = build_phase_a_enum_tuple_source_mutant_manifest(ROOT.parents[2], ROOT / "contract", self.evidence, source_site_map=source_map)
        selected = [m for m in manifest["mutants"] if m["requestCaseId"] == case_id and m["siteId"] == "PURITY-SITE-RECORD-OUTCOME"]
        self.assertEqual(len(selected), 1)
        spec = selected[0]
        frozen = semantic.freeze_retained_input_plan(authority, request, target_pointers=tuple(p["concretePointer"] for p in spec["patches"]))
        mutations = {}
        for patch in spec["patches"]:
            mutations.setdefault(patch["astSiteId"], set()).add((tuple(patch["relativeTokens"]), tuple(patch["candidateValues"])))
        mutations = {site: tuple(sorted(patches)) for site, patches in mutations.items()}
        self.assertEqual(len(mutations), 1)
        mutated, _, _ = semantic._mutated_interface_model(ROOT.parents[2], mutations, semantic.ACV049_MUTANT_CHANNELS, tuple_constructions=True)
        for channel in semantic.ACV049_MUTANT_CHANNELS:
            with mock.patch.dict(os.environ, {semantic.ACV049_MUTANT_CHANNEL_NAME: channel}), mock.patch.dict(sys.modules, {"interface_model": mutated}):
                live_authority = mutated.ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
                response = semantic._evaluate_fixture_request(live_authority, request, None)
            self.assertEqual(mutated._acv049_mutated_sites_executed, set(mutations))
            semantic._observe_declared_tuple_change(baseline, response, spec)
            self.assertEqual(semantic.observe_retained_input(frozen, response)["verdict"], "RETAINED_INPUT_PASS")
            # Extra post-output corruption is a checker sentinel, never a kill.
            damaged = copy.deepcopy(response)
            pointer = semantic._report_pointer("/result/evaluation/proposal/successor/genesis/logicalGenesis/transcriptHex")
            value = semantic._value_at_report_pointer(damaged, pointer)
            semantic._set_value_at_report_pointer(damaged, pointer, value[:-2] + ("00" if value[-2:] != "00" else "ff"))
            self.assertEqual(semantic.observe_retained_input(frozen, damaged)["verdict"], "RETAINED_INPUT_FAIL")
            for document in (response, damaged):
                raw = semantic.dumps(document)
                semantic.validate_response_before_release(authority, document)
                for mode in ("--validate-response", "--validate-response-batch"):
                    payload = semantic.dumps({"responses": [document]}) if mode.endswith("-batch") else raw
                    result = subprocess.run(["node", str(ROOT / "node_adapter.mjs"), mode, "--contract", str(ROOT / "contract")], input=payload, capture_output=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, b"")
                self.assertEqual(semantic.dumps(document), raw)

    def test_v33_retained_target_diagnostic_is_not_a_copy_correctness_claim(self) -> None:
        import run_semantic_acv049 as semantic

        request = json.loads((self.evidence / "carriers" / "PCR-REQUEST-EVALUATE-EVIDENCE-UPDATE-0028.json").read_bytes())
        authority = ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
        pointer = semantic._report_pointer("/result/evaluation/proposal/successor/genesis/logicalGenesis/transcriptHex")
        try:
            frozen = semantic.freeze_retained_input_plan(authority, request, target_pointers=(pointer,))
        except TypeError as error:
            self.fail("pre-frozen retained target observation is unavailable: " + str(error))
        response = semantic._evaluate_fixture_request(authority, request, None)
        # Observer diagnostics, not executed source-mutant evidence.
        damaged = copy.deepcopy(response)
        value = semantic._value_at_report_pointer(damaged, pointer)
        semantic._set_value_at_report_pointer(damaged, pointer, value[:-2] + ("00" if value[-2:] != "00" else "ff"))
        report = semantic.observe_retained_input(frozen, damaged)
        self.assertEqual(report["targetDifferences"], [pointer])
        self.assertEqual(report["offTargetDifferences"], [])
        self.assertEqual(report["verdict"], "RETAINED_OFF_TARGET_PASS_TARGET_EXPERIMENT")
        extra = semantic._report_pointer("/result/evaluation/proposal/successor/logicalEvents/0/transcriptHex")
        old = semantic._value_at_report_pointer(damaged, extra)
        semantic._set_value_at_report_pointer(damaged, extra, old[:-2] + ("00" if old[-2:] != "00" else "ff"))
        self.assertEqual(semantic.observe_retained_input(frozen, damaged)["verdict"], "RETAINED_INPUT_FAIL")

    def test_v34_identity_target_plan_allows_only_frozen_position_without_candidates(self) -> None:
        import run_semantic_acv049 as semantic

        request = json.loads((self.evidence / "carriers" / "PCR-REQUEST-EVALUATE-EVIDENCE-UPDATE-0028.json").read_bytes())
        authority = ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
        pointer = semantic._report_pointer(
            "/result/evaluation/proposal/successor/logicalEvents/0/eventReferenceHex"
        )
        frozen = semantic.freeze_retained_input_plan(
            authority, request, target_pointers=(pointer,)
        )
        plan = json.loads(frozen)
        prior_identity = request["input"]["prior"]["logicalEvents"][0]["eventReferenceHex"]
        self.assertEqual(
            plan["positionalIdentityBindings"],
            [{
                "canonicalPosition": 0,
                "collectionPath": ["logicalEvents"],
                "priorIdentity": prior_identity,
                "targetPointer": pointer,
            }],
        )
        self.assertNotIn("candidateValues", frozen.decode())
        self.assertNotIn(semantic.ACV049_MUTANT_CHANNEL_NAME, frozen.decode())

        response = semantic._evaluate_fixture_request(authority, request, None)
        changed = copy.deepcopy(response)
        replacement = "00" * 32 if prior_identity != "00" * 32 else "11" * 32
        semantic._set_value_at_report_pointer(changed, pointer, replacement)
        report = semantic.observe_retained_input(frozen, changed)
        self.assertEqual(report["verdict"], "RETAINED_OFF_TARGET_PASS_TARGET_EXPERIMENT")
        self.assertEqual(report["targetDifferences"], [pointer])
        self.assertEqual(report["offTargetDifferences"], [])
        self.assertEqual(report["structuralDifferences"], [])

        original = semantic.freeze_retained_input_plan(authority, request)
        self.assertEqual(
            semantic.observe_retained_input(original, changed)["verdict"],
            "RETAINED_INPUT_FAIL",
        )

    def test_v34_identity_target_source_run_conjoins_observer_and_manifest_detector(self) -> None:
        import run_semantic_acv049 as semantic

        case_id = "PCR-REQUEST-EVALUATE-EVIDENCE-UPDATE-0028"
        pointer = semantic._report_pointer(
            "/result/evaluation/proposal/successor/logicalEvents/0/eventReferenceHex"
        )
        request = json.loads((self.evidence / "carriers" / (case_id + ".json")).read_bytes())
        authority = ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
        baseline = semantic._evaluate_fixture_request(authority, request, None)
        source_map = derive_phase_a_source_site_map(
            ROOT.parents[2], ROOT / "contract", self.evidence,
            tuple_constructions=True,
        )
        routes = [
            route for route in source_map["routes"]
            if route["requestCaseId"] == case_id and route["concretePointers"] == [pointer]
        ]
        self.assertEqual(len(routes), 1)
        route = routes[0]
        terminal = semantic.resolve_logical_terminal(
            authority.schema, semantic._raw_report_logical_path(route["logicalPath"]),
        )
        spec = semantic.build_scalar_source_mutant_spec(
            authority.schema, route, terminal,
            semantic._value_at_report_pointer(baseline, pointer),
        )

        runs = []
        for channel in semantic.ACV049_MUTANT_CHANNELS:
            with mock.patch.dict(os.environ, {semantic.ACV049_MUTANT_CHANNEL_NAME: channel}):
                run = semantic.execute_scalar_source_mutant(
                    ROOT.parents[2], ROOT / "contract", self.evidence, spec,
                )
            self.assertEqual(
                run["retainedInputObservation"]["verdict"],
                "RETAINED_OFF_TARGET_PASS_TARGET_EXPERIMENT",
            )
            self.assertEqual(
                run["retainedInputObservation"]["runBindingRecordSha256"],
                run["runBindingRecordSha256"],
            )
            self.assertEqual(
                run["runBindingRecord"]["mutantManifestSha256"],
                semantic.sha256_bytes(semantic.dumps(spec)),
            )
            binding_bytes = semantic.dumps(run["runBindingRecord"])
            self.assertNotIn(b"candidateValues", binding_bytes)
            self.assertNotIn(b"response", binding_bytes)
            self.assertEqual(
                run["runBindingRecord"]["sourceEvidence"]["function"],
                "replay_context",
            )
            self.assertEqual(
                run["runBindingRecord"]["sourceEvidence"]["relativeTokens"],
                [0, "eventReferenceHex"],
            )
            self.assertEqual(
                run["sourceQualification"]["verdict"],
                "V34_IDENTITY_TARGET_SOURCE_RUN_PASS",
            )
            runs.append(run)
        self.assertEqual(runs[0]["runBindingRecordSha256"], runs[1]["runBindingRecordSha256"])

    def test_v34_identity_target_qualification_rejects_binding_and_post_output_tampering(self) -> None:
        import run_semantic_acv049 as semantic

        case_id = "PCR-REQUEST-EVALUATE-EVIDENCE-UPDATE-0028"
        pointer = semantic._report_pointer(
            "/result/evaluation/proposal/successor/logicalEvents/0/eventReferenceHex"
        )
        authority = ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
        request = json.loads((self.evidence / "carriers" / (case_id + ".json")).read_bytes())
        baseline = semantic._evaluate_fixture_request(authority, request, None)
        source_map = derive_phase_a_source_site_map(
            ROOT.parents[2], ROOT / "contract", self.evidence,
            tuple_constructions=True,
        )
        route = next(
            row for row in source_map["routes"]
            if row["requestCaseId"] == case_id and row["concretePointers"] == [pointer]
        )
        terminal = semantic.resolve_logical_terminal(
            authority.schema, semantic._raw_report_logical_path(route["logicalPath"]),
        )
        spec = semantic.build_scalar_source_mutant_spec(
            authority.schema, route, terminal,
            semantic._value_at_report_pointer(baseline, pointer),
        )
        with mock.patch.dict(
            os.environ,
            {semantic.ACV049_MUTANT_CHANNEL_NAME: semantic.ACV049_MUTANT_CHANNELS[0]},
        ):
            run = semantic.execute_scalar_source_mutant(
                ROOT.parents[2], ROOT / "contract", self.evidence, spec,
            )

        tampered_binding = copy.deepcopy(run)
        tampered_binding["runBindingRecord"]["requestSha256"] = "00" * 32
        with self.assertRaisesRegex(semantic.SemanticACV049Error, "run binding"):
            semantic._validate_v34_identity_target_source_qualification(
                ROOT.parents[2], ROOT / "contract", self.evidence, spec,
                tampered_binding,
            )

        post_output = copy.deepcopy(run)
        post_output["sourceSiteExecuted"] = False
        with self.assertRaisesRegex(semantic.SemanticACV049Error, "source execution trace"):
            semantic._validate_v34_identity_target_source_qualification(
                ROOT.parents[2], ROOT / "contract", self.evidence, spec,
                post_output,
            )

        wrong_value = copy.deepcopy(run)
        wrong_value["response"] = copy.deepcopy(baseline)
        semantic._set_value_at_report_pointer(
            wrong_value["response"], pointer, spec["candidateValues"][1],
        )
        wrong_value["responseSha256"] = semantic.sha256_bytes(
            semantic.dumps(wrong_value["response"])
        )
        with self.assertRaisesRegex(semantic.SemanticACV049Error, "candidate index"):
            semantic._validate_v34_identity_target_source_qualification(
                ROOT.parents[2], ROOT / "contract", self.evidence, spec,
                wrong_value,
            )

    def test_v33_retained_observer_allows_only_contract_candidate_additions(self) -> None:
        import run_semantic_acv049 as semantic

        request = json.loads((self.evidence / "carriers" / "PCR-REQUEST-EVALUATE-CANDIDATE-0023.json").read_bytes())
        authority = ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
        response = semantic._evaluate_fixture_request(authority, request, None)
        try:
            frozen = semantic.freeze_retained_input_plan(authority, request)
        except SemanticACV049Error as error:
            self.fail("candidate retained-input contract is unavailable: " + str(error))
        self.assertEqual(semantic.observe_retained_input(frozen, response)["verdict"], "RETAINED_INPUT_PASS")
        successor = response["result"]["evaluation"]["proposal"]["successor"]
        self.assertGreater(len(successor["logicalEvents"]), len(request["input"]["prior"]["logicalEvents"]))
        for collection in ("logicalEvents", "retainedProofs"):
            damaged = copy.deepcopy(response)
            target = damaged["result"]["evaluation"]["proposal"]["successor"]
            rows = target[collection] if collection == "logicalEvents" else target["localRevalidation"][collection]
            rows.append(copy.deepcopy(rows[0]))
            report = semantic.observe_retained_input(frozen, damaged)
            self.assertEqual(report["verdict"], "RETAINED_INPUT_FAIL")
            self.assertTrue(report["structuralDifferences"])

    def test_v33_retained_observer_rejects_corrupted_prior_leaves(self) -> None:
        import run_semantic_acv049 as semantic

        self.assertTrue(callable(getattr(semantic, "freeze_retained_input_plan", None)))
        request = json.loads((self.evidence / "carriers" / "PCR-REQUEST-EVALUATE-EVIDENCE-UPDATE-0028.json").read_bytes())
        authority = ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
        response = semantic._evaluate_fixture_request(authority, request, None)
        frozen = semantic.freeze_retained_input_plan(authority, request)
        original = semantic.dumps(response)
        self.assertTrue(request["input"]["prior"]["logicalEvents"])
        clean = semantic.observe_retained_input(frozen, response)
        self.assertEqual(clean["verdict"], "RETAINED_INPUT_PASS")
        self.assertGreater(clean["retainedLeafCount"], 0)
        self.assertEqual(semantic.dumps(response), original)
        # Checker self-tests only: these substitutions claim zero source kills.
        for suffix in ("/genesis/logicalGenesis/transcriptHex", "/logicalEvents/0/transcriptHex"):
            pointer = semantic._report_pointer("/result/evaluation/proposal/successor" + suffix)
            damaged = copy.deepcopy(response)
            value = semantic._value_at_report_pointer(damaged, pointer)
            semantic._set_value_at_report_pointer(damaged, pointer, value[:-2] + ("00" if value[-2:] != "00" else "ff"))
            report = semantic.observe_retained_input(frozen, damaged)
            self.assertEqual(report["verdict"], "RETAINED_INPUT_FAIL")
            self.assertIn(pointer, report["offTargetDifferences"])
        self.assertEqual(frozen, semantic.freeze_retained_input_plan(authority, request))

    @classmethod
    def setUpClass(cls) -> None:
        cls._temporary = tempfile.TemporaryDirectory()
        cls.evidence = Path(cls._temporary.name) / "evidence"
        generate_phase_a(ROOT.parents[2], ROOT / "contract", cls.evidence)
        cls.phase_b_seeds, cls.phase_b_registry = derive_phase_b_registries(
            ROOT.parents[2], ROOT / "contract", cls.evidence
        )

    @classmethod
    def tearDownClass(cls) -> None:
        cls._temporary.cleanup()

    def test_v33_enum_tuple_cli_emits_single_construction_ownership(self) -> None:
        import contextlib
        import io
        import run_semantic_acv049 as semantic

        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / 'enum-tuple-manifest.json'
            with contextlib.redirect_stdout(io.StringIO()):
                code = semantic.main([
                    '--repo-root', str(ROOT.parents[2]),
                    '--contract', str(ROOT / 'contract'),
                    '--evidence-root', str(self.evidence),
                    '--emit-enum-tuple-source-mutant-manifest',
                    '--output', str(output),
                ])
            self.assertEqual(code, 0)
            manifest = json.loads(output.read_bytes())
        self.assertEqual(manifest.get('ownershipRevision'), 'V33_TUPLE_CONSTRUCTIONS')
        self.assertTrue(manifest['mutants'])
        for mutant in manifest['mutants']:
            self.assertEqual(len({patch['astSiteId'] for patch in mutant['patches']}), 1)
        source_map = derive_phase_a_source_site_map(
            ROOT.parents[2], ROOT / 'contract', self.evidence, tuple_constructions=True,
        )
        expected = build_phase_a_enum_tuple_source_mutant_manifest(
            ROOT.parents[2], ROOT / 'contract', self.evidence, source_site_map=source_map,
        )
        self.assertEqual(canonical_dumps(manifest), canonical_dumps(expected))

    def test_v33_manifest_declares_complete_atomic_and_propagated_tuples(self) -> None:
        report = derive_phase_a_source_site_map(
            ROOT.parents[2], ROOT / 'contract', self.evidence, tuple_constructions=True,
        )
        manifest = build_phase_a_enum_tuple_source_mutant_manifest(
            ROOT.parents[2], ROOT / 'contract', self.evidence, source_site_map=report,
        )
        coupled = [m for m in manifest['mutants'] if m['siteId'] in {
            'PURITY-SITE-RECORD-OUTCOME', 'PURITY-SITE-REPLAY-CANDIDATE-TERMINAL',
        }]
        self.assertTrue(coupled)
        self.assertTrue(all(m['kind'] == 'RELATION_TUPLE' for m in coupled),
                        'a coupled obligation must not become an ordinary enum')
        for mutant in manifest['mutants']:
            self.assertEqual(len({p['astSiteId'] for p in mutant['patches']}), 1)
        candidate = [m for m in coupled if any('/primaryOnCommit' in _raw_report_logical_path(p)
                                               for p in m['logicalPaths'])]
        self.assertTrue(candidate)
        for mutant in candidate:
            self.assertEqual({p['field'] for p in mutant['patches']},
                             {'primaryOnCommit', 'disposition', 'stage'})
            propagated = next(p for p in mutant['patches'] if p['field'] == 'primaryOnCommit')
            source = next(p for p in mutant['patches'] if p['field'] == 'disposition')
            self.assertEqual(propagated['relativeTokens'], source['relativeTokens'])
            self.assertEqual(propagated['candidateValues'], source['candidateValues'])

    def test_v33_atomic_source_execution_retains_declared_candidate_propagation(self) -> None:
        import run_semantic_acv049 as semantic

        source_map = derive_phase_a_source_site_map(
            ROOT.parents[2], ROOT / 'contract', self.evidence, tuple_constructions=True,
        )
        manifest = build_phase_a_enum_tuple_source_mutant_manifest(
            ROOT.parents[2], ROOT / 'contract', self.evidence, source_site_map=source_map,
        )
        observations = []
        for channel in semantic.ACV049_MUTANT_CHANNELS:
            with mock.patch.dict(os.environ, {'STYX_ACV049_MUTANT_CHANNEL': channel}):
                try:
                    report = semantic.execute_enum_tuple_source_mutant_batch(
                        ROOT.parents[2], ROOT / 'contract', self.evidence, manifest,
                    )
                except SemanticACV049Error as error:
                    self.fail('V33 ownership execution is unavailable: ' + str(error))
            candidate_ids = {m['mutantId'] for m in manifest['mutants']
                             if m['siteId'] == 'PURITY-SITE-RECORD-OUTCOME'
                             and any(p['field'] == 'primaryOnCommit' for p in m['patches'])}
            selected = [row for row in report['rows'] if row['mutantId'] in candidate_ids]
            self.assertEqual({row['mutantId'] for row in selected}, candidate_ids)
            self.assertTrue(selected)
            observations.append({row['mutantId']: row['responseSha256'] for row in selected})
        self.assertEqual(set(observations[0]), set(observations[1]))
        self.assertTrue(all(observations[0][key] != observations[1][key] for key in observations[0]))

    def test_every_phase_a_package_mutant_is_killed(self) -> None:
        report = build_phase_a_mutation_report(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(
            report,
            {
                "family_counts": {
                    "authority-header": 2,
                    "carrier-identity": 1,
                    "coverage-binding": 1,
                    "direction-binding": 1,
                    "inventory-closure": 2,
                    "oracle-binding": 2,
                    "package-closure": 3,
                    "toolchain-identity": 1,
                },
                "killed_count": 13,
                "schema": "styx.app-core-iface0.phase-a-mutation-report.v1",
                "survivor_count": 0,
                "verdict": "PASS",
            },
        )

    def test_real_seed_partition_closes_all_semantic_execution_rows(self) -> None:
        materialized = derive_phase_a_materialized_paths(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        report = build_semantic_preflight(
            self.phase_b_seeds,
            ROOT / "contract",
            acv049_materialized_paths=materialized,
        )
        self.assertEqual(report["semantic_instance_count"], 2359)
        self.assertEqual(
            report["seed_direction_counts"], {"REQUEST": 56, "RESPONSE": 31}
        )
        self.assertEqual(
            report["acv048_phase_counts"],
            {
                "BLIND_INPUT_EXECUTION": 504,
                "POST_OUTPUT_MUTATION": 279,
                "VALIDATOR_SELF_TEST": 0,
                "TWO_ENVIRONMENT_SOURCE_MUTATION": 0,
            },
        )
        self.assertEqual(
            report["execution_phase_counts"],
            {
                "BLIND_INPUT_EXECUTION": 1156,
                "POST_OUTPUT_MUTATION": 691,
                "VALIDATOR_SELF_TEST": 212,
                "TWO_ENVIRONMENT_SOURCE_MUTATION": 300,
            },
        )
        self.assertEqual(report["status"], "PRESELECTION_EVIDENCE")

    def test_semantic_preflight_rejects_incomplete_seed_relation(self) -> None:
        mutant = copy.deepcopy(self.phase_b_seeds)
        mutant["rows"].pop()
        with self.assertRaisesRegex(
            SemanticPreflightError, "requires 87 seed rows"
        ):
            build_semantic_preflight(
                mutant,
                ROOT / "contract",
                acv049_materialized_paths=set(),
            )

    def test_acv048_executes_all_cross_plane_field_smuggling_instances(self) -> None:
        report = derive_acv048_report(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(report["instance_count"], 783)
        self.assertEqual(report["exact_rejected_count"], 783)
        self.assertEqual(report["mutant_admitted_count"], 783)
        self.assertEqual(
            report["phase_counts"],
            {"BLIND_INPUT_EXECUTION": 504, "POST_OUTPUT_MUTATION": 279},
        )
        self.assertEqual(len({row["instanceId"] for row in report["rows"]}), 783)
        self.assertTrue(all(not row["exactAccepted"] for row in report["rows"]))
        self.assertTrue(all(row["mutantAccepted"] for row in report["rows"]))

    def test_acv049_replacement_registry_is_branch_faithful_and_non_authoritative(self) -> None:
        jobs = build_acv049_terminal_jobs(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )["jobs"]
        javascript_rows: list[object] = []
        for offset in range(0, len(jobs), 64):
            batch = jobs[offset:offset + 64]
            with tempfile.TemporaryFile() as input_file:
                input_file.write(canonical_dumps({"jobs": batch}))
                input_file.seek(0)
                completed = subprocess.run(
                    [
                        "node",
                        str(ROOT / "node_adapter.mjs"),
                        "--self-test-terminal-schema",
                        "--contract",
                        str(ROOT / "contract"),
                    ],
                    stdin=input_file,
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
            result = json.loads(completed.stdout)
            self.assertEqual(set(result), {"results"})
            javascript_rows.extend(result["results"])
        report = build_acv049_preflight(
            ROOT.parents[2], ROOT / "contract", self.evidence,
            javascript_result={"results": javascript_rows},
        )
        self.assertEqual(report["instance_count"], 884)
        self.assertEqual(report["path_count"], 406)
        self.assertEqual(report["materialized_path_count"], 321)
        self.assertEqual(report["materialized_mutable_path_count"], 228)
        self.assertEqual(report["materialized_singleton_path_count"], 93)
        self.assertEqual(report["unmaterialized_path_count"], 80)
        self.assertEqual(report["claimed_mutant_kills"], 0)
        self.assertEqual(report["historical_reconciliation_count"], 4060)
        self.assertEqual(report["status"], "REMEDIATION_PARTIAL_EXECUTION")
        self.assertEqual(report["verdict"], "PARTIAL_EXECUTION_PASS")
        self.assertTrue(canonical_bytes(report, allowed_fields=ACV049_REPORT_FIELDS))
        self.assertEqual(
            report["executed_relation_counts"],
            {"ACV-049-L": 401, "ACV-049-N": 5, "ACV-049-S": 101},
        )
        self.assertEqual(
            report["pending_relation_counts"],
            {"ACV-049-E": 77, "ACV-049-P": 300},
        )
        self.assertEqual(
            report["relation_counts"],
            {
                "ACV-049-L": 401,
                "ACV-049-P": 300,
                "ACV-049-S": 101,
                "ACV-049-N": 5,
                "ACV-049-E": 77,
            },
        )
        self.assertEqual(len({row["instanceId"] for row in report["rows"]}), 884)
        self.assertTrue(
            all(
                row.get("evidenceDisposition")
                in {
                    "DOMAIN_CLOSURE_PASS",
                    "LITERAL_PROVENANCE_CLOSURE_PASS",
                    "LOCAL_BLIND_EXECUTION_PASS_TWO_ENVIRONMENT_PENDING",
                    "NON_STRING_RECONCILIATION_PASS",
                    "SOURCE_SITE_EVIDENCE_PENDING",
                }
                for row in report["rows"]
            )
        )
        literal_rows = [
            row for row in report["rows"] if row["relationId"] == "ACV-049-L"
        ]
        self.assertTrue(
            all(
                [member["familyId"] for member in row["literalFamilyVector"]]
                == [f"LITERAL-FAMILY-{index:02d}" for index in range(10)]
                and all(
                    len(member["encodedRepresentatives"]) == 3
                    for member in row["literalFamilyVector"]
                )
                for row in literal_rows
            )
        )
        self.assertTrue(
            all(
                row["dataPointer"].startswith("JSON_POINTER:")
                and all(
                    occurrence.startswith("JSON_POINTER:")
                    for occurrence in row["terminalSchemaOccurrences"]
                )
                for row in literal_rows
            )
        )
        singleton_rows = [
            row for row in report["rows"] if row["relationId"] == "ACV-049-S"
        ]
        non_string_rows = [
            row for row in report["rows"] if row["relationId"] == "ACV-049-N"
        ]
        self.assertTrue(
            all(
                row["pythonSchemaAccepted"]
                == row["javascriptSchemaAccepted"]
                == [True, False]
                for row in singleton_rows
            )
        )
        self.assertTrue(
            all(
                row["pythonSchemaAccepted"]
                == row["javascriptSchemaAccepted"]
                == [True, False, False]
                and len(row["historicalStringProvenanceIdsRetired"]) == 10
                for row in non_string_rows
            )
        )
        evaluator_rows = [
            row for row in report["rows"] if row["relationId"] == "ACV-049-E"
        ]
        self.assertEqual(len(evaluator_rows), 77)
        self.assertTrue(
            all(
                len(row["requestSha256"]) == 64
                and len(row["responseSha256"]) == 64
                and row["responseCarrierCaseIds"]
                and row["evidenceDisposition"]
                == "LOCAL_BLIND_EXECUTION_PASS_TWO_ENVIRONMENT_PENDING"
                for row in evaluator_rows
            )
        )

    def test_acv049_phase_a_source_sites_are_ast_derived_and_closed(self) -> None:
        report = derive_phase_a_source_site_map(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(report["schema"], "styx.app-core-iface0.acv049-source-site-map.v1")
        self.assertEqual(report["verdict"], "PHASE_A_SOURCE_SITE_MAP_PASS")
        self.assertEqual(report["instrumentationPointCount"], 507)
        self.assertEqual(report["materializedMutablePathCount"], 228)
        self.assertEqual(report["pendingSupplementaryMutablePathCount"], 72)
        self.assertEqual(
            len(set(report["pendingSupplementaryLogicalPaths"])), 72
        )
        self.assertEqual(report["routeCount"], 596)
        self.assertEqual(
            report["routeClassCounts"],
            {"FAULT_INJECTED_ROUTE": 15, "ORDINARY_ROUTE": 581},
        )
        self.assertEqual(report["usedSiteCount"], 76)
        self.assertEqual(len(report["routeSetSha256"]), 64)
        self.assertEqual(len(report["usedSiteSetSha256"]), 64)
        self.assertEqual(
            len({row["siteId"] for row in report["usedSites"]}),
            report["usedSiteCount"],
        )
        self.assertTrue(
            {
                "PURITY-SITE-CANDIDATE-TERMINAL",
                "PURITY-SITE-CONTENT-STATE-AXIS",
                "PURITY-SITE-GENESIS-TERMINAL",
                "PURITY-SITE-TRANSCRIPT-REJECTED",
                "PURITY-SITE-TRANSCRIPT-VALIDATED",
            }
            <= {row["siteId"] for row in report["usedSites"]}
        )
        self.assertTrue(all(row["astMembers"] for row in report["usedSites"]))
        self.assertTrue(
            all(
                row["logicalPath"].startswith("LOGICAL_PATH:")
                and row["concretePointers"]
                and all(
                    pointer.startswith("JSON_POINTER:")
                    for pointer in row["concretePointers"]
                )
                and row["astSiteIds"]
                and row["sourceSelectors"]
                and all(
                    set(selector)
                    == {
                        "astSiteId",
                        "concretePointer",
                        "relativePointer",
                        "relativeTokens",
                    }
                    for selector in row["sourceSelectors"]
                )
                and row["siteId"].startswith("PURITY-SITE-")
                and row["routeClass"]
                in {"ORDINARY_ROUTE", "FAULT_INJECTED_ROUTE"}
                for row in report["routes"]
            )
        )

        scalar_manifest = build_phase_a_scalar_source_mutant_manifest(
            ROOT.parents[2],
            ROOT / "contract",
            self.evidence,
            source_site_map=report,
        )
        self.assertEqual(
            scalar_manifest["verdict"],
            "PHASE_A_SCALAR_MUTANT_MANIFEST_PASS",
        )
        self.assertEqual(
            scalar_manifest["mutantCount"]
            + scalar_manifest["o08BoundCandidateCount"]
            + scalar_manifest["pendingGuardedCandidateCount"]
            + scalar_manifest["skippedEnumRouteCount"],
            596,
        )
        self.assertEqual(scalar_manifest["o08BoundCandidateCount"], 5)
        self.assertEqual(scalar_manifest["pendingGuardedCandidateCount"], 48)
        self.assertEqual(scalar_manifest["mutantCount"], 331)
        self.assertEqual(scalar_manifest["skippedEnumRouteCount"], 212)
        self.assertEqual(
            {row["dimension"] for row in scalar_manifest["o08BoundCandidates"]},
            {
                "ACTIVATION_CAPABILITY_SET",
                "CUSTODY_REDUNDANCY",
                "DURABLE_RECORDS",
                "DURABLE_REQUIRED_OCTETS",
                "TRANSIENT_MEMORY_CAPABILITY",
            },
        )
        self.assertEqual(
            len({row["mutantId"] for row in scalar_manifest["mutants"]}),
            scalar_manifest["mutantCount"],
        )

        enum_tuple_manifest = build_phase_a_enum_tuple_source_mutant_manifest(
            ROOT.parents[2],
            ROOT / "contract",
            self.evidence,
            source_site_map=report,
        )
        self.assertEqual(
            enum_tuple_manifest["verdict"],
            "PHASE_A_ENUM_TUPLE_MUTANT_MANIFEST_PASS",
        )
        self.assertEqual(enum_tuple_manifest["enumRouteCount"], 212)
        self.assertEqual(enum_tuple_manifest["coveredEnumRouteCount"], 212)
        self.assertEqual(enum_tuple_manifest["ordinaryEnumMutantCount"], 124)
        self.assertEqual(enum_tuple_manifest["relationTupleMutantCount"], 34)
        self.assertEqual(enum_tuple_manifest["relationTupleResidualCount"], 1)
        self.assertEqual(enum_tuple_manifest["o08BoundCandidateCount"], 10)
        self.assertEqual(enum_tuple_manifest["mutantCount"], 158)
        self.assertEqual(
            len({row["mutantId"] for row in enum_tuple_manifest["mutants"]}),
            158,
        )
        self.assertEqual(
            {
                (row["dimension"], row["field"])
                for row in enum_tuple_manifest["o08BoundCandidates"]
            },
            {
                (dimension, field)
                for dimension in {
                    "ACTIVATION_CAPABILITY_SET",
                    "CUSTODY_REDUNDANCY",
                    "DURABLE_RECORDS",
                    "DURABLE_REQUIRED_OCTETS",
                    "TRANSIENT_MEMORY_CAPABILITY",
                }
                for field in {"comparison", "unit"}
            },
        )
        self.assertTrue(
            all(
                row["evidenceStatus"] == "PENDING_NEGATIVE_CONTROL"
                and row["schemaAdmissibleAlternativeValues"]
                for row in enum_tuple_manifest["o08BoundCandidates"]
            )
        )
        self.assertEqual(
            {
                (row["siteId"], row["baselineRelationRowId"])
                for row in enum_tuple_manifest["residuals"]
            },
            {("PURITY-SITE-TRANSCRIPT-VALIDATED", "TRS-001")},
        )
        self.assertEqual(
            sum(
                row["twoStateRule"]
                for row in enum_tuple_manifest["mutants"]
                if row["kind"] == "ORDINARY_ENUM"
            ),
            13,
        )
        self.assertEqual(
            sum(
                bool(row["reservedValues"])
                for row in enum_tuple_manifest["mutants"]
                if row["kind"] == "ORDINARY_ENUM"
            ),
            10,
        )

        target_route = next(
            row
            for row in report["routes"]
            if _raw_report_logical_path(row["logicalPath"]).endswith(
                "/profile/applicationProfileId"
            )
            and row["faultContext"] == "NONE"
        )
        self.assertEqual(len(target_route["astSiteIds"]), 1)
        authority = ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
        _inventory, _inventory_bytes, carriers = _load_phase_a(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        request, request_bytes = carriers[target_route["requestCaseId"]]
        oracle_by_request = {
            canonical_dumps(case.request): case.collision_oracle
            for case in _semantic_request_carriers(authority)
            if case.collision_oracle is not None
        }
        oracle = oracle_by_request.get(request_bytes)
        baseline_response = _evaluate_fixture_request(authority, request, oracle)
        logical_path = _raw_report_logical_path(target_route["logicalPath"])
        terminal = resolve_logical_terminal(authority.schema, logical_path)
        pointer = target_route["concretePointers"][0]
        baseline_value = _value_at_report_pointer(baseline_response, pointer)
        self.assertIsInstance(baseline_value, str)
        spec = build_scalar_source_mutant_spec(
            authority.schema, target_route, terminal, baseline_value
        )
        runs = []
        with tempfile.TemporaryDirectory() as raw:
            spec_path = Path(raw) / "scalar-mutant-spec.json"
            spec_path.write_bytes(canonical_dumps(spec))
            for expected_index, channel in enumerate(
                (
                    "ACV049-CONTROL-CHANNEL-ALPHA",
                    "ACV049-CONTROL-CHANNEL-BRAVO",
                )
            ):
                completed = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "run_semantic_acv049.py"),
                        "--repo-root",
                        str(ROOT.parents[2]),
                        "--contract",
                        str(ROOT / "contract"),
                        "--evidence-root",
                        str(self.evidence),
                        "--execute-scalar-source-mutant",
                        str(spec_path),
                    ],
                    check=False,
                    capture_output=True,
                    env={
                        "LC_CTYPE": "C.UTF-8",
                        "PATH": "/usr/bin:/bin",
                        "PYTHONDONTWRITEBYTECODE": "1",
                        "STYX_ACV049_MUTANT_CHANNEL": channel,
                    },
                )
                self.assertEqual(completed.returncode, 0, completed.stderr.decode())
                run = json.loads(completed.stdout)
                self.assertEqual(canonical_dumps(run), completed.stdout)
                self.assertEqual(run["verdict"], "PYTHON_RELEASE_MUTANT_PASS")
                self.assertEqual(run["observedCandidateIndex"], expected_index)
                self.assertTrue(run["sourceSiteExecuted"])
                runs.append(run)
        self.assertEqual(runs[0]["mutantSourceSha256"], runs[1]["mutantSourceSha256"])
        self.assertNotEqual(runs[0]["responseSha256"], runs[1]["responseSha256"])
        node = shutil.which("node")
        self.assertIsNotNone(node)
        for run in runs:
            javascript = subprocess.run(
                [
                    node,
                    str(ROOT / "node_adapter.mjs"),
                    "--validate-response",
                    "--contract",
                    str(ROOT / "contract"),
                ],
                cwd=ROOT.parents[2],
                check=False,
                capture_output=True,
                input=canonical_dumps(run["response"]),
                env={
                    "LC_CTYPE": "C.UTF-8",
                    "PATH": "/usr/bin:/bin",
                },
            )
            self.assertEqual(javascript.returncode, 0, javascript.stderr.decode())
            self.assertEqual(json.loads(javascript.stdout), {"verdict": "PASS"})
        javascript_batch_input = canonical_dumps(
            {"responses": [run["response"] for run in runs]}
        )
        javascript_batch = subprocess.run(
            [
                node,
                str(ROOT / "node_adapter.mjs"),
                "--validate-response-batch",
                "--contract",
                str(ROOT / "contract"),
            ],
            cwd=ROOT.parents[2],
            check=False,
            capture_output=True,
            input=javascript_batch_input,
            env={"LC_CTYPE": "C.UTF-8", "PATH": "/usr/bin:/bin"},
        )
        self.assertEqual(
            javascript_batch.returncode, 0, javascript_batch.stderr.decode()
        )
        self.assertEqual(
            json.loads(javascript_batch.stdout),
            {
                "responseCount": 2,
                "responseSha256s": [
                    hashlib.sha256(canonical_dumps(run["response"])).hexdigest()
                    for run in runs
                ],
                "verdict": "PASS",
            },
        )

    def test_acv049_all_materialized_scalar_domains_have_finite_candidates(
        self,
    ) -> None:
        authority = ContractAuthority.load(ROOT.parents[2], ROOT / "contract")
        _inventory, _inventory_bytes, carriers = _load_phase_a(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        responses = sorted(
            (
                (case_id, value)
                for case_id, (value, _raw) in carriers.items()
                if case_id.startswith("PCR-RESPONSE-")
            ),
            key=lambda row: row[0].encode("utf-8"),
        )
        partition = derive_acv049_path_partition(ROOT / "contract")
        terminals, carriers_by_path, _jobs = _terminal_execution_plan(
            authority, responses, partition
        )
        class_counts: dict[str, int] = {}
        candidate_pair_count = 0
        for path in partition["mutable"]:
            if not carriers_by_path[path]:
                continue
            terminal = terminals[path]
            if any("enum" in node for node in terminal.nodes):
                continue
            for baseline in sorted(
                {value for _case_id, _response, value in carriers_by_path[path]}
            ):
                plan = _derive_schema_candidate_pair(
                    authority.schema,
                    terminal,
                    baseline,
                    (
                        "ACV049-CONTROL-CHANNEL-ALPHA",
                        "ACV049-CONTROL-CHANNEL-BRAVO",
                    ),
                )
                self.assertEqual(plan["evidenceDisposition"], "KILLED")
                self.assertEqual(len(set(plan["candidateValues"])), 2)
                self.assertNotIn(baseline, plan["candidateValues"])
                candidate_pair_count += 1
                domain_class = plan["domainClass"]
                class_counts[domain_class] = class_counts.get(domain_class, 0) + 1
        self.assertEqual(candidate_pair_count, 166)
        self.assertEqual(
            class_counts,
            {"CANONICAL_DECIMAL": 76, "EVEN_LOWER_HEX": 19, "HEX64": 71},
        )

    def test_phase_b_seed_registry_selects_all_87_objects_deterministically(self) -> None:
        registry, cases = derive_seed_registry(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(registry["rowCount"], 87)
        self.assertEqual(len(registry["rows"]), 87)
        self.assertEqual(len(cases), 96)
        self.assertEqual(
            len({row["objectSchemaId"] for row in registry["rows"]}), 87
        )
        self.assertEqual(
            len({row["objectSchemaPointer"] for row in registry["rows"]}), 87
        )
        self.assertEqual(
            registry["rows"][0]["objectSchemaId"], "OBJ-0001"
        )
        self.assertEqual(
            registry["rows"][-1]["objectSchemaId"], "OBJ-0087"
        )
        repeated, _cases = derive_seed_registry(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(registry, repeated)

    def test_stored_witness_ids_are_recomputed_before_consumption(self) -> None:
        registry = self.phase_b_registry
        validate_structural_witness_identifiers(registry)
        mutations = {
            "wrong namespace": ("assertionId", "DET-REQUIRED-PROPERTY-OMISSION--0001"),
            "wrong suffix": ("mutationId", "MUT-WRONG-SUFFIX--0001"),
            "wrong index": ("detectorId", "DET-REQUIRED-PROPERTY-OMISSION--0002"),
            "missing double hyphen": ("assertionId", "AST-REQUIRED-PROPERTY-OMISSION-0001"),
        }
        for name, (field, value) in mutations.items():
            with self.subTest(name=name):
                candidate = copy.deepcopy(registry)
                candidate["rows"][0][field] = value
                with self.assertRaisesRegex(WitnessGenerationError, field):
                    validate_structural_witness_identifiers(candidate)

    def test_every_witness_target_has_a_real_carrier_parent(self) -> None:
        inventory = json.loads(
            (self.evidence / "positive-carrier-inventory.json").read_text(
                encoding="utf-8"
            )
        )
        carrier_files = {
            row["caseId"]: row["carrierFile"] for row in inventory["cases"]
        }
        inserted_arrays = {
            "STR-REF-TARGET-CONSTRAINT--0001",
            "STR-REF-TARGET-CONSTRAINT--0015",
            "STR-REF-TARGET-CONSTRAINT--0031",
            "STR-REF-TARGET-CONSTRAINT--0044",
            "STR-REF-TARGET-CONSTRAINT--0072",
            "STR-REF-TARGET-CONSTRAINT--0075",
            "STR-REF-TARGET-CONSTRAINT--0076",
            "STR-REF-TARGET-CONSTRAINT--0077",
            "STR-REF-TARGET-CONSTRAINT--0078",
            "STR-REF-TARGET-CONSTRAINT--0082",
            "STR-REF-TARGET-CONSTRAINT--0083",
            "STR-REF-TARGET-CONSTRAINT--0084",
            "STR-REF-TARGET-CONSTRAINT--0096",
            "STR-REF-TARGET-CONSTRAINT--0097",
            "STR-REF-TARGET-CONSTRAINT--0115",
            "STR-REF-TARGET-CONSTRAINT--0116",
            "STR-REF-TARGET-CONSTRAINT--0161",
            "STR-REF-TARGET-CONSTRAINT--0215",
            "STR-MIN-ITEMS-UNDERFLOW--0001",
            "STR-ALL-OF-BRANCH-CONSTRAINT--0001",
            "STR-ALL-OF-BRANCH-CONSTRAINT--0002",
        }
        observed_array_insertions: set[str] = set()
        for row in self.phase_b_registry["rows"]:
            carrier = json.loads(
                (self.evidence / carrier_files[row["carrierCaseId"]]).read_text(
                    encoding="utf-8"
                )
            )
            target = row["targetJsonPointer"]
            try:
                _resolve_data_pointer(carrier, target)
                continue
            except (KeyError, IndexError, TypeError, ValueError):
                pass
            parent_pointer, token = target.rsplit("/", 1)
            parent = _resolve_data_pointer(carrier, parent_pointer)
            if isinstance(parent, dict):
                self.assertNotIn(token, parent, row["instanceId"])
            else:
                self.assertIsInstance(parent, list, row["instanceId"])
                self.assertTrue(token.isdecimal(), row["instanceId"])
                self.assertEqual(int(token), len(parent), row["instanceId"])
                self.assertIn(
                    row["structuralRuleId"],
                    _PARENT_RESOLVED_ARRAY_INSERTION_FAMILIES,
                )
                observed_array_insertions.add(row["instanceId"])
        self.assertEqual(observed_array_insertions, inserted_arrays)

    def test_structural_target_preflight_covers_every_instance(self) -> None:
        report = derive_structural_target_preflight(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["instance_count"], 1553)
        self.assertEqual(report["unresolved_instance_ids"], [])
        self.assertEqual(
            report["resolution_counts"],
            {
                "PARENT_RESOLVED_MEMBER_ABSENT": 25,
                "RESOLVED": 1528,
                "UNRESOLVED_TARGET": 0,
            },
        )

    def test_carrier_search_isolation_preflight_is_complete_and_fail_closed(self) -> None:
        report = derive_structural_isolation_preflight(
            ROOT.parents[2], ROOT / "contract", self.evidence
        )
        self.assertEqual(report["verdict"], "PASS")
        self.assertEqual(report["instance_count"], 1553)
        self.assertEqual(
            report["classification_counts"],
            {
                "ANTI_DOWNGRADE_OVERLAP_SELF_TEST": 1,
                "CO_CONSTRAINED_OCCURRENCE_SELF_TEST": 82,
                "RATIFIED_REDUNDANT_OCCURRENCE_SELF_TEST": 1,
                "TARGET_ONLY_COUNTERFACTUAL": 1469,
            },
        )
        self.assertEqual(
            report["selected_classification_counts"],
            {
                "ANTI_DOWNGRADE_OVERLAP_SELF_TEST": 1,
                "EQUIVALENT_MUTANT": 28,
                "PALETTE_EXHAUSTED": 1,
                "RATIFIED_REDUNDANT_OCCURRENCE_SELF_TEST": 1,
                "SATISFIABLE": 1522,
            },
        )
        self.assertEqual(report["non_satisfiable_rows"], [])
        relation = json.loads(
            (
                ROOT
                / "contract/APP-CORE-IFACE-0-STRUCTURAL-ISOLATION-RELATION-CANDIDATE.json"
            ).read_text(encoding="utf-8")
        )
        expected_reselections = [
            {
                "candidate_ordinal": row["candidateOrdinal"],
                "carrier_case_id": row["carrierCaseId"],
                "instance_id": row["instanceId"],
            }
            for row in relation["carrierReselections"]
        ]
        self.assertEqual(report["reselected_count"], 29)
        self.assertEqual(report["reselected_rows"], expected_reselections)
        self.assertTrue(
            all(row["candidate_ordinal"] >= 2 for row in report["reselected_rows"])
        )
        self.assertNotIn(
            "RECIPE_NOT_IMPLEMENTED", report["classification_counts"]
        )


if __name__ == "__main__":
    unittest.main()
