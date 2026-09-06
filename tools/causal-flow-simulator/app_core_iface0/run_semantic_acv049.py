#!/usr/bin/env python3
"""Derive ACV-049 relations and execute the L/S/N reader evidence."""

from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
import sys
import types
from pathlib import Path
from typing import Any

from jsonschema.validators import Draft202012Validator

sys.dont_write_bytecode = True

from canonical_json import dumps
from canonical_report import ReportError, store_report
from generate_structural_witnesses import (
    WitnessGenerationError,
    _load_phase_a,
    derive_structural_plan,
)
from generate_seed_registry import (  # noqa: E402
    _evaluate_fixture_request,
    _semantic_request_carriers,
)
from interface_model import (
    ContractAuthority,
    HarnessFailure,
    validate_response_before_release,
)
from inventory import (
    ACV049_LITERAL_FAMILIES,
    InventoryError,
    LogicalTerminal,
    derive_acv049_path_partition,
    derive_acv049_old_to_new_reconciliation,
    derive_acv049_relation_members,
    digest_lines,
    expand_acv049_replacement_instances,
    resolve_logical_terminal,
    sha256_bytes,
)


REPORT_FIELDS = frozenset(
    {
        "claimed_mutant_kills", "historical_reconciliation_count",
        "historical_reconciliation_sha256", "instance_count",
        "executed_relation_counts",
        "materialized_mutable_path_count", "materialized_path_count",
        "materialized_singleton_path_count", "path_count",
        "pending_relation_counts", "relation_counts",
        "relation_member_set_sha256", "rows", "schema", "semantic_rule_id",
        "status", "unmaterialized_path_count", "verdict",
    }
)


LITERAL_REPRESENTATIVES = {
    "DURATION": "duration=1.25s",
    "ELAPSED": "elapsed=1.25s",
    "ENVIRONMENT": "environment=production",
    "EXCEPTION": "exception=ValueError",
    "HOST": "hostname=review-host",
    "PATH": "provenance=/tmp/styx-runtime",
    "PID": "pid=4242",
    "STACK": "stack trace: frame",
    "TIMESTAMP": "timestamp=2026-09-03T12:34:56Z",
    "USER": "username=operator",
}


class SemanticACV049Error(ValueError):
    """The ACV-049 preflight relation is malformed or overclaims evidence."""


class _SourceTaggedString(str):
    """One immutable string carrying its nearest evaluator construction site."""

    def __new__(cls, value: str, site_id: str) -> _SourceTaggedString:
        instance = super().__new__(cls, value)
        instance.site_id = site_id
        return instance

    def __deepcopy__(self, memo: dict[int, Any]) -> _SourceTaggedString:
        del memo
        return self


def _tag_source_value(site_id: str, value: Any) -> Any:
    """Tag unowned strings without changing their JSON-visible value or shape."""

    if isinstance(value, _SourceTaggedString):
        return value
    if isinstance(value, str):
        return _SourceTaggedString(value, site_id)
    if isinstance(value, list):
        return [_tag_source_value(site_id, item) for item in value]
    if isinstance(value, tuple):
        return tuple(_tag_source_value(site_id, item) for item in value)
    if isinstance(value, dict):
        return {
            key: _tag_source_value(site_id, item) for key, item in value.items()
        }
    if isinstance(value, set):
        return {_tag_source_value(site_id, item) for item in value}
    if isinstance(value, frozenset):
        return frozenset(_tag_source_value(site_id, item) for item in value)
    return value


def _site_token(value: str) -> str:
    token = "".join(character if character.isalnum() else "-" for character in value)
    token = "-".join(part for part in token.upper().split("-") if part)
    return token or "VALUE"


class _SourceSiteInstrumenter(ast.NodeTransformer):
    """Instrument evaluator value-producing AST nodes with stable site IDs."""

    def __init__(self) -> None:
        self.function_names: list[str] = []
        self.occurrences: dict[tuple[str, str, str], int] = {}
        self.sites: dict[str, dict[str, Any]] = {}

    @property
    def function_name(self) -> str | None:
        return self.function_names[-1] if self.function_names else None

    def _site(
        self, node: ast.AST, kind: str, label: str, *, explicit: str | None = None
    ) -> str:
        function = self.function_name
        if function is None:
            raise SemanticACV049Error("module-level ACV-049 site is forbidden")
        if explicit is None:
            key = (function, kind, label)
            occurrence = self.occurrences.get(key, 0) + 1
            self.occurrences[key] = occurrence
            site_id = (
                "PURITY-SITE-AST-"
                + _site_token(function)
                + "-"
                + _site_token(kind)
                + "-"
                + _site_token(label)
                + f"-{occurrence:03d}"
            )
        else:
            site_id = explicit
        if site_id in self.sites:
            raise SemanticACV049Error(f"duplicate ACV-049 construction site: {site_id}")
        self.sites[site_id] = {
            "column": int(getattr(node, "col_offset", -1)),
            "function": function,
            "kind": kind,
            "label": label,
            "line": int(getattr(node, "lineno", -1)),
            "siteId": site_id,
        }
        return site_id

    @staticmethod
    def _tag(site_id: str, value: ast.expr) -> ast.Call:
        return ast.Call(
            func=ast.Name(id="_acv049_tag_source_value", ctx=ast.Load()),
            args=[ast.Constant(site_id), value],
            keywords=[],
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
        self.function_names.append(node.name)
        try:
            return self.generic_visit(node)
        finally:
            self.function_names.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
        self.function_names.append(node.name)
        try:
            return self.generic_visit(node)
        finally:
            self.function_names.pop()

    def visit_Dict(self, node: ast.Dict) -> ast.AST:
        node = self.generic_visit(node)
        if self.function_name is None:
            return node
        wrapped: list[ast.expr] = []
        for index, (key, value) in enumerate(zip(node.keys, node.values, strict=True)):
            label = (
                str(key.value)
                if isinstance(key, ast.Constant) and isinstance(key.value, str)
                else f"SPREAD-{index:03d}"
            )
            site_id = self._site(value, "DICT-VALUE", label)
            wrapped.append(ast.copy_location(self._tag(site_id, value), value))
        node.values = wrapped
        return node

    def visit_DictComp(self, node: ast.DictComp) -> ast.AST:
        node = self.generic_visit(node)
        if self.function_name is None:
            return node
        site_id = self._site(node.value, "DICT-COMPREHENSION", "VALUE")
        node.value = ast.copy_location(self._tag(site_id, node.value), node.value)
        return node

    def visit_Assign(self, node: ast.Assign) -> ast.AST:
        node = self.generic_visit(node)
        if self.function_name is None:
            return node
        subscript_targets = [target for target in node.targets if isinstance(target, ast.Subscript)]
        if not subscript_targets:
            return node
        labels = []
        for target in subscript_targets:
            labels.append(
                str(target.slice.value)
                if isinstance(target.slice, ast.Constant)
                else "DYNAMIC-SUBSCRIPT"
            )
        explicit = None
        if (
            self.function_name == "_assemble_context_projection"
            and labels == ["retentionState"]
        ):
            explicit = "PURITY-SITE-CONTENT-STATE-AXIS-REMOVAL"
        site_id = self._site(
            node.value,
            "SUBSCRIPT-ASSIGNMENT",
            "+".join(labels),
            explicit=explicit,
        )
        node.value = ast.copy_location(self._tag(site_id, node.value), node.value)
        return node

    def visit_Call(self, node: ast.Call) -> ast.AST:
        node = self.generic_visit(node)
        if (
            self.function_name is None
            or not isinstance(node.func, ast.Attribute)
            or node.func.attr not in {"append", "extend", "setdefault", "update"}
            or not node.args
        ):
            return node
        wrapped: list[ast.expr] = []
        for index, argument in enumerate(node.args):
            site_id = self._site(
                argument, "MUTATING-CALL", f"{node.func.attr}-{index:03d}"
            )
            wrapped.append(ast.copy_location(self._tag(site_id, argument), argument))
        node.args = wrapped
        return node


def _instrumented_interface_model(
    repo_root: Path,
) -> tuple[types.ModuleType, dict[str, dict[str, Any]]]:
    """Compile an in-memory, value-preserving source-provenance evaluator."""

    source_path = (
        repo_root
        / "tools/causal-flow-simulator/app_core_iface0/interface_model.py"
    )
    try:
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(source_path))
    except (OSError, UnicodeDecodeError, SyntaxError, ValueError) as error:
        raise SemanticACV049Error("ACV-049 evaluator AST is unavailable") from error
    instrumenter = _SourceSiteInstrumenter()
    instrumented = instrumenter.visit(tree)
    ast.fix_missing_locations(instrumented)
    module = types.ModuleType("interface_model")
    module.__file__ = str(source_path)
    module.__dict__["_acv049_tag_source_value"] = _tag_source_value
    previous = sys.modules.get("interface_model")
    sys.modules["interface_model"] = module
    try:
        exec(compile(instrumented, str(source_path), "exec"), module.__dict__)
    except Exception:
        if previous is None:
            sys.modules.pop("interface_model", None)
        else:
            sys.modules["interface_model"] = previous
        raise
    if previous is None:
        sys.modules.pop("interface_model", None)
    else:
        sys.modules["interface_model"] = previous
    return module, instrumenter.sites


def _logical_data_pattern(path: str) -> tuple[str | None, ...]:
    parts = path.split("/")
    if not parts or parts[0] != "InterfaceResponseV0":
        raise SemanticACV049Error("ACV-049 logical response path drift")
    return tuple(
        None if part == "*" else part.replace("~1", "/").replace("~0", "~")
        for part in parts[1:]
        if not (part.startswith("<") and part.endswith(">"))
    )


def _pattern_values(
    value: Any,
    pattern: tuple[str | None, ...],
    prefix: tuple[str | int, ...] = (),
) -> list[tuple[tuple[str | int, ...], Any]]:
    if not pattern:
        return [(prefix, value)]
    token, remaining = pattern[0], pattern[1:]
    if token is None:
        if not isinstance(value, list):
            return []
        return [
            result
            for index, item in enumerate(value)
            for result in _pattern_values(item, remaining, (*prefix, index))
        ]
    if not isinstance(value, dict) or token not in value:
        return []
    return _pattern_values(value[token], remaining, (*prefix, token))


def _controlled_channel_order(channels: tuple[str, str]) -> tuple[bytes, bytes]:
    encoded: list[bytes] = []
    for channel in channels:
        try:
            raw = channel.encode("ascii")
        except UnicodeEncodeError as error:
            raise SemanticACV049Error("ACV-049 mutant channel is not ASCII") from error
        if not raw or any(octet < 0x21 or octet > 0x7E for octet in raw):
            raise SemanticACV049Error("ACV-049 mutant channel is not canonical ASCII")
        encoded.append(raw)
    if encoded[0] == encoded[1]:
        raise SemanticACV049Error("ACV-049 mutant channels are not distinct")
    ordered = sorted(encoded)
    return ordered[0], ordered[1]


def _terminal_constraints(terminal: LogicalTerminal) -> dict[str, Any]:
    constraints: dict[str, Any] = {}
    for node in terminal.nodes:
        for keyword in (
            "enum", "maxLength", "minLength", "pattern",
            "x-styx-unsigned-maximum", "x-styx-unsigned-minimum",
        ):
            if keyword not in node:
                continue
            value = node[keyword]
            if keyword in constraints and constraints[keyword] != value:
                raise SemanticACV049Error(
                    f"ACV-049 terminal constraint is ambiguous: {keyword}"
                )
            constraints[keyword] = copy.deepcopy(value)
    return constraints


def _derive_schema_candidate_pair(
    schema: dict[str, Any],
    terminal: LogicalTerminal,
    baseline: str,
    channels: tuple[str, str],
    *,
    reserved_values: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Derive the closed V26--V28 candidate pair without evaluator output."""

    ordered_channels = _controlled_channel_order(channels)
    constraints = _terminal_constraints(terminal)
    enum = constraints.get("enum")
    if enum is not None:
        if (
            not isinstance(enum, list)
            or not enum
            or any(not isinstance(value, str) for value in enum)
            or len(set(enum)) != len(enum)
            or baseline not in enum
            or not reserved_values <= set(enum)
        ):
            raise SemanticACV049Error("ACV-049 enum domain is malformed")
        eligible = sorted(
            set(enum) - {baseline} - set(reserved_values),
            key=lambda value: value.encode("utf-8"),
        )
        if not eligible:
            return {
                "advanceCounts": [0, 0],
                "candidateValues": [],
                "domainClass": "ENUM",
                "evidenceDisposition": "RELATION_SINGLETON",
                "twoStateRule": False,
            }
        if len(eligible) == 1:
            candidates = [eligible[0], baseline]
            two_state = True
        else:
            candidates = eligible[:2]
            two_state = False
        validator = _subschema_validator(schema, terminal.nodes)
        if any(not validator.is_valid(value) for value in candidates):
            raise SemanticACV049Error("ACV-049 enum candidate is not admitted")
        return {
            "advanceCounts": [0, 0],
            "candidateValues": candidates,
            "domainClass": "ENUM",
            "evidenceDisposition": "KILLED",
            "twoStateRule": two_state,
        }

    pattern = constraints.get("pattern")
    advance_counts = [0, 0]
    if pattern in {"^[0-9a-f]{64}$", "^(?:[0-9a-f]{2})*$"}:
        candidates = [
            hashlib.sha256(channel).hexdigest() for channel in ordered_channels
        ]
        domain_class = (
            "HEX64" if pattern == "^[0-9a-f]{64}$" else "EVEN_LOWER_HEX"
        )
        cardinality = 1 << 256

        def advance(value: str) -> str:
            return f"{(int(value, 16) + 1) % cardinality:064x}"

    elif pattern in {"^(0|[1-9][0-9]*)$", "^(0|[1-9][0-9]{0,19})$"}:
        maximum_length = constraints.get("maxLength", 20)
        if not isinstance(maximum_length, int) or maximum_length < 1:
            raise SemanticACV049Error("ACV-049 decimal length is malformed")
        minimum = int(constraints.get("x-styx-unsigned-minimum", "0"))
        if "x-styx-unsigned-maximum" in constraints:
            maximum = int(constraints["x-styx-unsigned-maximum"])
        else:
            maximum = minimum + (10 ** min(maximum_length, 4)) - 1
        if minimum < 0 or maximum < minimum:
            raise SemanticACV049Error("ACV-049 decimal bounds are malformed")
        cardinality = maximum - minimum + 1
        candidates = [
            str(
                minimum
                + (
                    int.from_bytes(hashlib.sha256(channel).digest(), "big")
                    % cardinality
                )
            )
            for channel in ordered_channels
        ]
        domain_class = "CANONICAL_DECIMAL"

        def advance(value: str) -> str:
            return str(minimum + ((int(value) - minimum + 1) % cardinality))

    else:
        raise SemanticACV049Error("ACV-049 string pattern has no ratified recipe")

    for _iteration in range(cardinality + 1):
        changed = False
        if candidates[0] == baseline:
            candidates[0] = advance(candidates[0])
            advance_counts[0] += 1
            changed = True
        if candidates[1] == baseline or candidates[1] == candidates[0]:
            candidates[1] = advance(candidates[1])
            advance_counts[1] += 1
            changed = True
        if not changed:
            break
    else:
        raise SemanticACV049Error("ACV-049 candidate domain is exhausted")
    validator = _subschema_validator(schema, terminal.nodes)
    if (
        candidates[0] == candidates[1]
        or baseline in candidates
        or any(not validator.is_valid(value) for value in candidates)
    ):
        raise SemanticACV049Error("ACV-049 derived candidate pair is invalid")
    return {
        "advanceCounts": advance_counts,
        "candidateValues": candidates,
        "domainClass": domain_class,
        "evidenceDisposition": "KILLED",
        "twoStateRule": False,
    }


def _semantic_construction_site(path: str, ast_site_id: str) -> str:
    """Collapse only the five tuple sites named by the ratified amendment."""

    if "/<CandidateEvaluationTerminalV0>/" in path:
        return "PURITY-SITE-CANDIDATE-TERMINAL"
    if "/<EvaluateGenesisResultTerminalV0>/" in path:
        return "PURITY-SITE-GENESIS-TERMINAL"
    if "/<ValidateTranscriptResultRejectedV0>/" in path and path.endswith(
        ("/reason", "/stage")
    ):
        return "PURITY-SITE-TRANSCRIPT-REJECTED"
    if path.endswith("/<ValidateTranscriptResultValidatedV0>/stage"):
        return "PURITY-SITE-TRANSCRIPT-VALIDATED"
    if "/projection/contentStates/*/" in path and path.rsplit("/", 1)[1] in {
        "bindingObservation",
        "contentClass",
        "localAvailability",
        "replayReadiness",
        "retentionState",
    }:
        if ast_site_id == "PURITY-SITE-CONTENT-STATE-AXIS-REMOVAL":
            return ast_site_id
        return "PURITY-SITE-CONTENT-STATE-AXIS"
    return ast_site_id


def derive_phase_a_source_site_map(
    repo_root: Path, contract: Path, evidence_root: Path
) -> dict[str, Any]:
    """Map Phase-A mutable response leaves to exact evaluator AST sites."""

    authority = ContractAuthority.load(repo_root, contract)
    _inventory, _inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    requests = sorted(
        (
            (case_id, value, raw)
            for case_id, (value, raw) in carriers.items()
            if case_id.startswith("PCR-REQUEST-")
        ),
        key=lambda row: row[0].encode("utf-8"),
    )
    if len(requests) != 77:
        raise SemanticACV049Error("ACV-049 requires 77 frozen requests")
    collision_oracle_by_request = {
        dumps(case.request): case.collision_oracle
        for case in _semantic_request_carriers(authority)
        if case.collision_oracle is not None
    }
    instrumented, ast_sites = _instrumented_interface_model(repo_root)
    previous = sys.modules.get("interface_model")
    sys.modules["interface_model"] = instrumented
    tagged_responses: list[tuple[str, dict[str, Any], bool]] = []
    try:
        instrumented_authority = instrumented.ContractAuthority.load(repo_root, contract)
        for case_id, request, raw in requests:
            oracle = collision_oracle_by_request.get(raw)
            response = _evaluate_fixture_request(
                instrumented_authority, request, oracle
            )
            instrumented.validate_response_before_release(
                instrumented_authority, response
            )
            tagged_responses.append((case_id, response, oracle is not None))
    finally:
        if previous is None:
            sys.modules.pop("interface_model", None)
        else:
            sys.modules["interface_model"] = previous

    partition = derive_acv049_path_partition(contract)
    terminals = {
        path: resolve_logical_terminal(authority.schema, path)
        for path in partition["mutable"]
    }
    route_groups: dict[
        tuple[str, str, str, str], dict[str, set[str]]
    ] = {}
    materialized: set[str] = set()
    used_sites: set[str] = set()
    for path in partition["mutable"]:
        terminal = terminals[path]
        pattern = _logical_data_pattern(path)
        for case_id, response, fault_injected in tagged_responses:
            try:
                selected = all(
                    _validator(authority.schema, arm).is_valid(
                        _data_value(response, prefix)
                    )
                    for prefix, arm in terminal.branches
                )
            except (KeyError, TypeError):
                continue
            if not selected:
                continue
            values = _pattern_values(response, pattern)
            if not values:
                continue
            materialized.add(path)
            for pointer, value in values:
                if not isinstance(value, _SourceTaggedString):
                    raise SemanticACV049Error(
                        f"ACV-049 materialized leaf has no AST site: {path}"
                    )
                if value.site_id not in ast_sites:
                    raise SemanticACV049Error("ACV-049 reported an unknown AST site")
                semantic_site = _semantic_construction_site(path, value.site_id)
                used_sites.add(semantic_site)
                fault_context = (
                    "FIXED_INTERNAL_COLLISION_ORACLE" if fault_injected else "NONE"
                )
                key = (path, semantic_site, case_id, fault_context)
                group = route_groups.setdefault(
                    key, {"astSiteIds": set(), "concretePointers": set()}
                )
                group["astSiteIds"].add(value.site_id)
                group["concretePointers"].add(
                    _report_pointer(_json_pointer(pointer))
                )
    expected_materialized = derive_phase_a_materialized_paths(
        repo_root, contract, evidence_root
    ) & set(partition["mutable"])
    if materialized != expected_materialized or len(materialized) != 228:
        raise SemanticACV049Error("ACV-049 source-site materialization drift")
    if len(set(partition["mutable"]) - materialized) != 72:
        raise SemanticACV049Error("ACV-049 supplementary mutable-path count drift")
    route_rows = [
        {
            "astSiteIds": sorted(group["astSiteIds"]),
            "concretePointers": sorted(group["concretePointers"]),
            "faultContext": fault_context,
            "logicalPath": _report_logical_path(path),
            "requestCaseId": case_id,
            "routeClass": (
                "FAULT_INJECTED_ROUTE"
                if fault_context == "FIXED_INTERNAL_COLLISION_ORACLE"
                else "ORDINARY_ROUTE"
            ),
            "siteId": site_id,
        }
        for (path, site_id, case_id, fault_context), group in route_groups.items()
    ]
    route_rows.sort(
        key=lambda row: dumps(
            [
                row["logicalPath"], row["siteId"], row["requestCaseId"],
                row["faultContext"],
            ]
        )
    )
    ast_claims: dict[str, set[str]] = {}
    for row in route_rows:
        for ast_site_id in row["astSiteIds"]:
            ast_claims.setdefault(ast_site_id, set()).add(row["siteId"])
    multiply_claimed = {
        ast_site_id: claims
        for ast_site_id, claims in ast_claims.items()
        if len(claims) != 1
    }
    if multiply_claimed:
        raise SemanticACV049Error("ACV-049 AST site is multiply claimed")
    grouped_sites = []
    for site_id in sorted(used_sites):
        member_ids = sorted(
            {
                ast_site_id
                for row in route_rows
                if row["siteId"] == site_id
                for ast_site_id in row["astSiteIds"]
            }
        )
        if not member_ids or any(member not in ast_sites for member in member_ids):
            raise SemanticACV049Error("ACV-049 used-site closure drift")
        grouped_sites.append(
            {
                "astMembers": [ast_sites[member] for member in member_ids],
                "siteId": site_id,
            }
        )
    pending_paths = sorted(set(partition["mutable"]) - materialized)
    route_class_counts = {
        route_class: sum(row["routeClass"] == route_class for row in route_rows)
        for route_class in ("ORDINARY_ROUTE", "FAULT_INJECTED_ROUTE")
    }
    if (
        len(route_rows) != 596
        or len(grouped_sites) != 76
        or route_class_counts
        != {"ORDINARY_ROUTE": 581, "FAULT_INJECTED_ROUTE": 15}
    ):
        raise SemanticACV049Error("ACV-049 Phase-A source-site relation drift")
    return {
        "instrumentationPointCount": len(ast_sites),
        "materializedMutablePathCount": len(materialized),
        "pendingSupplementaryMutablePathCount": 72,
        "pendingSupplementaryLogicalPaths": [
            _report_logical_path(path) for path in pending_paths
        ],
        "routeCount": len(route_rows),
        "routeClassCounts": route_class_counts,
        "routeSetSha256": sha256_bytes(dumps(route_rows)),
        "routes": route_rows,
        "schema": "styx.app-core-iface0.acv049-source-site-map.v1",
        "usedSiteCount": len(used_sites),
        "usedSiteSetSha256": sha256_bytes(dumps(grouped_sites)),
        "usedSites": grouped_sites,
        "verdict": "PHASE_A_SOURCE_SITE_MAP_PASS",
    }


def _data_value(value: Any, tokens: tuple[str | int, ...]) -> Any:
    current = value
    for token in tokens:
        if isinstance(token, int):
            if not isinstance(current, list) or token >= len(current):
                raise KeyError(token)
            current = current[token]
        else:
            if not isinstance(current, dict) or token not in current:
                raise KeyError(token)
            current = current[token]
    return current


def _subschema_validator(
    schema: dict[str, Any], nodes: tuple[dict[str, Any], ...]
) -> Draft202012Validator:
    body: dict[str, Any] = (
        copy.deepcopy(nodes[0])
        if len(nodes) == 1
        else {"allOf": [copy.deepcopy(node) for node in nodes]}
    )
    return Draft202012Validator(
        {"$schema": schema["$schema"], **body, "$defs": schema["$defs"]}
    )


def _encoded_representatives(family: str) -> tuple[str, ...]:
    literal = LITERAL_REPRESENTATIVES[family]
    digest = hashlib.sha256(literal.encode("utf-8")).hexdigest()
    decimal = {
        "DURATION": "1250", "ELAPSED": "1250", "ENVIRONMENT": "1",
        "EXCEPTION": "1", "HOST": "1", "PATH": "1", "PID": "4242",
        "STACK": "1", "TIMESTAMP": "1788438896", "USER": "1",
    }[family]
    return (decimal, literal.encode("utf-8").hex(), digest)


def _terminal_test_values() -> list[str]:
    return [
        value
        for family in ACV049_LITERAL_FAMILIES
        for value in (LITERAL_REPRESENTATIVES[family], *_encoded_representatives(family))
    ]


def _set_data_value(
    value: Any, tokens: tuple[str | int, ...], replacement: Any
) -> None:
    if not tokens:
        raise SemanticACV049Error("ACV-049 cannot replace the response root")
    parent = _data_value(value, tokens[:-1])
    final = tokens[-1]
    if isinstance(final, int):
        if not isinstance(parent, list) or final >= len(parent):
            raise SemanticACV049Error("ACV-049 array target disappeared")
        parent[final] = replacement
    else:
        if not isinstance(parent, dict) or final not in parent:
            raise SemanticACV049Error("ACV-049 object target disappeared")
        parent[final] = replacement


def _json_pointer(tokens: tuple[str | int, ...]) -> str:
    return "".join(
        "/" + str(token).replace("~", "~0").replace("/", "~1")
        for token in tokens
    )


def _report_pointer(pointer: str) -> str:
    if not pointer.startswith("/") or pointer == "/":
        raise SemanticACV049Error("ACV-049 report pointer is not rooted")
    return "JSON_POINTER:" + pointer[1:].replace("%", "%25").replace("/", "%2F")


def _raw_report_pointer(pointer: str) -> str:
    prefix = "JSON_POINTER:"
    if not pointer.startswith(prefix):
        raise SemanticACV049Error("ACV-049 report pointer encoding drift")
    return "/" + pointer[len(prefix):].replace("%2F", "/").replace("%25", "%")


def _report_logical_path(path: str) -> str:
    if not path or path.startswith("/"):
        raise SemanticACV049Error("ACV-049 logical path identity drift")
    return "LOGICAL_PATH:" + path.replace("%", "%25").replace("/", "%2F")


def _constraint_occurrences(terminal: LogicalTerminal) -> list[dict[str, Any]]:
    constraint_keywords = {
        "$ref", "allOf", "anyOf", "const", "enum", "items", "maxItems",
        "maxLength", "minItems", "minLength", "not", "oneOf", "pattern",
        "type", "uniqueItems",
    }
    rows = [
        {
            "keyword": keyword,
            "occurrence": _report_pointer(
                f"{pointer}/{keyword.replace('~', '~0').replace('/', '~1')}"
            ),
            "valueSha256": sha256_bytes(dumps(node[keyword])),
        }
        for pointer, node in zip(
            terminal.node_pointers, terminal.nodes, strict=True
        )
        for keyword in sorted(set(node) & constraint_keywords)
    ]
    if not rows:
        raise SemanticACV049Error("ACV-049 terminal has no constraint occurrence")
    return rows


def _const_value(terminal: LogicalTerminal) -> Any:
    values = [node["const"] for node in terminal.nodes if "const" in node]
    if not values or any(value != values[0] for value in values[1:]):
        raise SemanticACV049Error("ACV-049 const binding is absent or ambiguous")
    return copy.deepcopy(values[0])


def _non_const_value(value: Any) -> Any:
    if isinstance(value, str):
        candidate = value + "-ACV049-DISTINCT"
        return candidate if candidate != value else "ACV049-DISTINCT"
    if isinstance(value, list):
        return [*copy.deepcopy(value), "ACV049-DISTINCT"]
    raise SemanticACV049Error("ACV-049 const has an unsupported terminal type")


def _validator(schema: dict[str, Any], node: dict[str, Any]) -> Draft202012Validator:
    return Draft202012Validator(
        {"$schema": schema["$schema"], **node, "$defs": schema["$defs"]}
    )


def _materialized_carrier(
    schema: dict[str, Any], terminal: LogicalTerminal,
    responses: list[tuple[str, dict[str, Any]]],
) -> tuple[str, dict[str, Any]] | None:
    for case_id, response in responses:
        try:
            target = _data_value(response, terminal.data_tokens)
            selected = all(
                _validator(schema, arm).is_valid(_data_value(response, prefix))
                for prefix, arm in terminal.branches
            )
        except (KeyError, TypeError):
            continue
        if isinstance(target, str) and selected:
            return case_id, response
    return None


def derive_phase_a_materialized_paths(
    repo_root: Path, contract: Path, evidence_root: Path
) -> set[str]:
    """Re-derive the exact ACV-049 Phase-A response-path materialization set."""

    authority = ContractAuthority.load(repo_root, contract)
    _inventory, _inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    responses = sorted(
        (
            (case_id, value)
            for case_id, (value, _raw) in carriers.items()
            if case_id.startswith("PCR-RESPONSE-")
        ),
        key=lambda row: row[0].encode("utf-8"),
    )
    if len(responses) != 19:
        raise SemanticACV049Error("ACV-049 requires 19 frozen responses")
    partition = derive_acv049_path_partition(contract)
    terminals = {
        path: resolve_logical_terminal(authority.schema, path)
        for path in partition["logical"]
    }
    materialized = {
        path
        for path, terminal in terminals.items()
        if _materialized_carrier(authority.schema, terminal, responses) is not None
    }
    mutable = sorted(materialized & set(partition["mutable"]))
    singleton = sorted(materialized & set(partition["singleton"]))
    non_string = materialized & set(partition["non_string"])
    if (
        len(materialized) != 321
        or len(mutable) != 228
        or len(singleton) != 93
        or non_string
        or sha256_bytes("".join(path + "\n" for path in mutable).encode("utf-8"))
        != "47756a4adf5eaa79589f21c4b443e8f273e94efc4c798bace194cb9e1fe611de"
        or sha256_bytes("".join(path + "\n" for path in singleton).encode("utf-8"))
        != "6f06ee47fe0950fec29462ab849d46d7928ee7ff85de4829829731b82839c77a"
    ):
        raise SemanticACV049Error("ACV-049 Phase-A materialization relation drift")
    return materialized


def _python_rejects(authority: ContractAuthority, response: dict[str, Any]) -> bool:
    try:
        validate_response_before_release(authority, response)
    except HarnessFailure:
        return True
    return False


def _terminal_execution_plan(
    authority: ContractAuthority,
    responses: list[tuple[str, dict[str, Any]]],
    partition: dict[str, list[str]],
) -> tuple[
    dict[str, LogicalTerminal],
    dict[str, list[tuple[str, dict[str, Any], str]]],
    list[tuple[str, str, list[Any], list[dict[str, Any]]]],
]:
    terminals = {
        path: resolve_logical_terminal(authority.schema, path)
        for path in partition["logical"]
    }

    def selected_carriers(path: str) -> list[tuple[str, dict[str, Any], str]]:
        terminal = terminals[path]
        found: list[tuple[str, dict[str, Any], str]] = []
        for case_id, response in responses:
            try:
                target = _data_value(response, terminal.data_tokens)
                selected = all(
                    _validator(authority.schema, arm).is_valid(
                        _data_value(response, prefix)
                    )
                    for prefix, arm in terminal.branches
                )
            except (KeyError, TypeError):
                continue
            if isinstance(target, str) and selected:
                found.append((case_id, response, target))
        return found

    carriers_by_path = {
        path: selected_carriers(path) for path in partition["literal"]
    }
    literal_values = _terminal_test_values()
    job_specs: list[tuple[str, str, list[Any], list[dict[str, Any]]]] = []
    for path in partition["literal"]:
        job_specs.append(
            (
                "ACV-049-L",
                path,
                literal_values,
                [response for _case_id, response, _value in carriers_by_path[path]],
            )
        )
    for path in partition["singleton"]:
        const_value = _const_value(terminals[path])
        job_specs.append(
            ("ACV-049-S", path, [const_value, _non_const_value(const_value)], [])
        )
    for path in partition["non_string"]:
        const_value = _const_value(terminals[path])
        job_specs.append(
            (
                "ACV-049-N",
                path,
                [const_value, "ACV049-STRING-HOSTILE", _non_const_value(const_value)],
                [],
            )
        )
    return terminals, carriers_by_path, job_specs


def _terminal_jobs(
    job_specs: list[tuple[str, str, list[Any], list[dict[str, Any]]]],
) -> dict[str, list[dict[str, Any]]]:
    return {
        "jobs": [
            {"baselines": baselines, "logicalPath": path, "values": values}
            for _relation_id, path, values, baselines in job_specs
        ]
    }


def build_terminal_jobs(
    repo_root: Path, contract: Path, evidence_root: Path
) -> dict[str, list[dict[str, Any]]]:
    """Build the blind JavaScript-reader input without executing a child."""

    authority = ContractAuthority.load(repo_root, contract)
    _inventory, _inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    responses = sorted(
        (
            (case_id, value)
            for case_id, (value, _raw) in carriers.items()
            if case_id.startswith("PCR-RESPONSE-")
        ),
        key=lambda row: row[0].encode("utf-8"),
    )
    if len(responses) != 19:
        raise SemanticACV049Error("ACV-049 requires 19 frozen responses")
    if any(_python_rejects(authority, response) for _case_id, response in responses):
        raise SemanticACV049Error("ACV-049 negative control is rejected")
    partition = derive_acv049_path_partition(contract)
    _terminals, _carriers_by_path, job_specs = _terminal_execution_plan(
        authority, responses, partition
    )
    jobs = _terminal_jobs(job_specs)
    if len(jobs["jobs"]) != 507:
        raise SemanticACV049Error("ACV-049 terminal job count drift")
    return jobs


def _validate_javascript_terminal_results(
    jobs: list[dict[str, Any]], result: object
) -> list[dict[str, Any]]:
    if (
        not isinstance(result, dict)
        or set(result) != {"results"}
        or not isinstance(result["results"], list)
        or len(result["results"]) != len(jobs)
    ):
        raise SemanticACV049Error("JavaScript terminal-schema result drift")
    for job, row in zip(jobs, result["results"], strict=True):
        expected_release_rows = len(job["baselines"])
        if (
            not isinstance(row, dict)
            or set(row) != {"logicalPath", "releaseAccepted", "schemaAccepted"}
            or row["logicalPath"] != job["logicalPath"]
            or not isinstance(row["schemaAccepted"], list)
            or len(row["schemaAccepted"]) != len(job["values"])
            or any(not isinstance(value, bool) for value in row["schemaAccepted"])
            or not isinstance(row["releaseAccepted"], list)
            or len(row["releaseAccepted"]) != expected_release_rows
            or any(
                not isinstance(releases, list)
                or len(releases) != len(job["values"])
                or any(not isinstance(value, bool) for value in releases)
                for releases in row["releaseAccepted"]
            )
        ):
            raise SemanticACV049Error("JavaScript terminal-schema row drift")
    return result["results"]


def build_report(
    repo_root: Path,
    contract: Path,
    evidence_root: Path,
    *,
    javascript_result: object,
) -> dict[str, Any]:
    """Build the exact registry and execute its L/S/N evidence.

    The runner deliberately records zero mutant kills. P source-purity and E
    two-environment execution remain separate gates and stay explicitly pending.
    """

    authority = ContractAuthority.load(repo_root, contract)
    _inventory, _inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    responses = sorted(
        (
            (case_id, value)
            for case_id, (value, _raw) in carriers.items()
            if case_id.startswith("PCR-RESPONSE-")
        ),
        key=lambda row: row[0].encode("utf-8"),
    )
    if len(responses) != 19:
        raise SemanticACV049Error("ACV-049 requires 19 frozen responses")
    if any(_python_rejects(authority, response) for _case_id, response in responses):
        raise SemanticACV049Error("ACV-049 negative control is rejected")

    requests = sorted(
        (
            (case_id, value, raw)
            for case_id, (value, raw) in carriers.items()
            if case_id.startswith("PCR-REQUEST-")
        ),
        key=lambda row: row[0].encode("utf-8"),
    )
    if len(requests) != 77:
        raise SemanticACV049Error("ACV-049 requires 77 frozen requests")
    collision_oracle_by_request = {
        dumps(case.request): case.collision_oracle
        for case in _semantic_request_carriers(authority)
        if case.collision_oracle is not None
    }
    if (
        len(collision_oracle_by_request) != 3
        or not set(collision_oracle_by_request).issubset({raw for _id, _value, raw in requests})
    ):
        raise SemanticACV049Error("ACV-049 collision-oracle identity drift")
    response_carriers_by_bytes: dict[bytes, list[str]] = {}
    for case_id, response in responses:
        response_carriers_by_bytes.setdefault(dumps(response), []).append(case_id)
    e_execution: dict[str, dict[str, Any]] = {}
    for case_id, request, raw in requests:
        collision_oracle = collision_oracle_by_request.get(raw)
        response = _evaluate_fixture_request(
            authority, request, collision_oracle
        )
        validate_response_before_release(authority, response)
        response_bytes = dumps(response)
        response_carrier_ids = response_carriers_by_bytes.get(response_bytes, [])
        if not response_carrier_ids:
            raise SemanticACV049Error(
                f"ACV-049 blind response left the frozen carrier set: {case_id}"
            )
        e_execution[case_id] = {
            "faultContext": (
                "FIXED_INTERNAL_COLLISION_ORACLE"
                if collision_oracle is not None
                else "NONE"
            ),
            "requestOctets": len(raw),
            "requestSha256": sha256_bytes(raw),
            "responseCarrierCaseIds": response_carrier_ids,
            "responseOctets": len(response_bytes),
            "responseSha256": sha256_bytes(response_bytes),
        }

    partition = derive_acv049_path_partition(contract)
    relation_members = derive_acv049_relation_members(contract)
    instances = expand_acv049_replacement_instances(contract)
    instance_by_relation_and_source = {
        (row.family_id, row.source): row for row in instances
    }
    if len(instance_by_relation_and_source) != 884:
        raise SemanticACV049Error("ACV-049 replacement instance identity drift")

    terminals, carriers_by_path, job_specs = _terminal_execution_plan(
        authority, responses, partition
    )
    materialized = {
        path for path, carriers in carriers_by_path.items() if carriers
    }
    derived_materialized = derive_phase_a_materialized_paths(
        repo_root, contract, evidence_root
    )
    if materialized != derived_materialized:
        raise SemanticACV049Error("ACV-049 materialization derivations disagree")

    jobs = _terminal_jobs(job_specs)["jobs"]
    javascript_rows = _validate_javascript_terminal_results(
        jobs, javascript_result
    )
    execution_results: dict[tuple[str, str], dict[str, Any]] = {}
    for spec, javascript_row in zip(job_specs, javascript_rows, strict=True):
        relation_id, path, values, baselines = spec
        terminal = terminals[path]
        validator = _subschema_validator(authority.schema, terminal.nodes)
        python_schema = [validator.is_valid(value) for value in values]
        python_release: list[list[bool]] = []
        for baseline in baselines:
            carrier_results: list[bool] = []
            for value in values:
                candidate = copy.deepcopy(baseline)
                _set_data_value(candidate, terminal.data_tokens, value)
                carrier_results.append(not _python_rejects(authority, candidate))
            python_release.append(carrier_results)
        if (
            javascript_row["schemaAccepted"] != python_schema
            or javascript_row["releaseAccepted"] != python_release
        ):
            raise SemanticACV049Error(
                f"ACV-049 Python/JavaScript terminal result drift: {relation_id} {path}"
            )
        if relation_id == "ACV-049-S" and python_schema != [True, False]:
            raise SemanticACV049Error(f"ACV-049 singleton closure drift: {path}")
        if relation_id == "ACV-049-N" and python_schema != [True, False, False]:
            raise SemanticACV049Error(f"ACV-049 non-string closure drift: {path}")
        execution_results[(relation_id, path)] = {
            "javascriptReleaseAccepted": javascript_row["releaseAccepted"],
            "javascriptSchemaAccepted": javascript_row["schemaAccepted"],
            "pythonReleaseAccepted": python_release,
            "pythonSchemaAccepted": python_schema,
            "testValues": values,
        }

    structural_rows = derive_structural_plan(contract)["rows"]
    structural_by_occurrence: dict[str, list[str]] = {}
    for structural_row in structural_rows:
        structural_by_occurrence.setdefault(
            structural_row["sourcePointerOrRowId"], []
        ).append(structural_row["instanceId"])

    def terminal_binding(path: str) -> dict[str, Any]:
        terminal = terminals[path]
        occurrences = _constraint_occurrences(terminal)
        witness_ids = sorted(
            {
                witness_id
                for occurrence in occurrences
                for witness_id in structural_by_occurrence.get(
                    _raw_report_pointer(occurrence["occurrence"]),
                    [],
                )
            },
            key=lambda value: value.encode("utf-8"),
        )
        if not witness_ids:
            raise SemanticACV049Error(
                f"ACV-049 terminal has no structural witness binding: {path}"
            )
        return {
            "branchLabels": [
                part[1:-1]
                for part in path.split("/")
                if part.startswith("<") and part.endswith(">")
            ],
            "coConstrainingKeywordOccurrences": occurrences,
            "dataPointer": _report_pointer(_json_pointer(terminal.data_tokens)),
            "structuralWitnessIds": witness_ids,
            "terminalSchemaOccurrences": [
                _report_pointer(pointer) for pointer in terminal.node_pointers
            ],
            "terminalSchemaSha256": sha256_bytes(dumps(list(terminal.nodes))),
        }

    mutable = set(partition["mutable"])
    singleton = set(partition["singleton"])
    reconciliation = derive_acv049_old_to_new_reconciliation(contract)

    def equality_status(path: str, value: Any) -> tuple[str, list[str]]:
        equal_carriers = [
            case_id
            for case_id, _response, baseline_value in carriers_by_path.get(path, [])
            if baseline_value == value
        ]
        if not carriers_by_path.get(path):
            return "NO_PHASE_A_BASELINE", []
        return (
            "EQUIVALENT_REPRESENTATIVE" if equal_carriers
            else "DISTINCT_REPRESENTATIVE",
            equal_carriers,
        )

    def literal_family_vector(path: str) -> list[dict[str, Any]]:
        evidence = execution_results[("ACV-049-L", path)]
        detector_ids = terminal_binding(path)["structuralWitnessIds"]
        carrier_ids = [
            case_id for case_id, _response, _value in carriers_by_path[path]
        ]
        vector: list[dict[str, Any]] = []
        for family_index, family in enumerate(ACV049_LITERAL_FAMILIES):
            start = family_index * 4
            family_values = evidence["testValues"][start:start + 4]
            representations: list[dict[str, Any]] = []
            for value_index, value in enumerate(family_values):
                global_index = start + value_index
                equality, equal_carriers = equality_status(path, value)
                representations.append(
                    {
                        "encoding": (
                            "LITERAL" if value_index == 0
                            else ("DECIMAL", "LOWERCASE_HEX", "SHA256_HEX")[value_index - 1]
                        ),
                        "equalCarrierCaseIds": equal_carriers,
                        "equalityToBaseline": equality,
                        "javascriptReleaseAccepted": [
                            {
                                "accepted": row[global_index],
                                "carrierCaseId": case_id,
                            }
                            for case_id, row in zip(
                                carrier_ids,
                                evidence["javascriptReleaseAccepted"],
                                strict=True,
                            )
                        ],
                        "javascriptSchemaAccepted": evidence[
                            "javascriptSchemaAccepted"
                        ][global_index],
                        "pythonReleaseAccepted": [
                            {
                                "accepted": row[global_index],
                                "carrierCaseId": case_id,
                            }
                            for case_id, row in zip(
                                carrier_ids,
                                evidence["pythonReleaseAccepted"],
                                strict=True,
                            )
                        ],
                        "pythonSchemaAccepted": evidence["pythonSchemaAccepted"][
                            global_index
                        ],
                        "representativeSha256": sha256_bytes(dumps(value)),
                    }
                )
            vector.append(
                {
                    "detector": detector_ids,
                    "encodedRepresentatives": representations[1:],
                    "familyId": f"LITERAL-FAMILY-{family_index:02d}",
                    "literalRepresentative": representations[0],
                }
            )
        return vector

    rows: list[dict[str, Any]] = []
    for relation_id in (
        "ACV-049-L",
        "ACV-049-P",
        "ACV-049-S",
        "ACV-049-N",
        "ACV-049-E",
    ):
        for source in relation_members[relation_id]:
            instance = instance_by_relation_and_source[(relation_id, source)]
            row: dict[str, Any] = {
                "assertionId": instance.assertion_id,
                "detectorId": instance.detector_id,
                "instanceId": instance.instance_id,
                "observationId": instance.observation_id,
                "relationId": relation_id,
                "sourceIdentity": (
                    source if relation_id == "ACV-049-E"
                    else _report_logical_path(source)
                ),
            }
            if relation_id == "ACV-049-L":
                binding = terminal_binding(source)
                row.update(
                    {
                        **binding,
                        "carrierCaseIds": [
                            case_id
                            for case_id, _response, _value in carriers_by_path[source]
                        ],
                        "domainClass": (
                            "MUTABLE_DOMAIN" if source in mutable else "SINGLETON_CONST"
                        ),
                        "evidenceDisposition": "LITERAL_PROVENANCE_CLOSURE_PASS",
                        "executionPhase": (
                            "POST_OUTPUT_MUTATION"
                            if source in materialized
                            else "VALIDATOR_SELF_TEST"
                        ),
                        "literalFamilyVector": literal_family_vector(source),
                        "materialized": source in materialized,
                    }
                )
            elif relation_id == "ACV-049-P":
                row.update(
                    {
                        "executionPhase": "TWO_ENVIRONMENT_SOURCE_MUTATION",
                        "evidenceDisposition": "SOURCE_SITE_EVIDENCE_PENDING",
                    }
                )
            elif relation_id in {"ACV-049-S", "ACV-049-N"}:
                binding = terminal_binding(source)
                evidence = execution_results[(relation_id, source)]
                const_value = _const_value(terminals[source])
                const_occurrences = [
                    item
                    for item in binding["coConstrainingKeywordOccurrences"]
                    if item["keyword"] == "const"
                ]
                if not const_occurrences:
                    raise SemanticACV049Error(
                        f"ACV-049 const occurrence is absent: {source}"
                    )
                row.update(
                    {
                        **binding,
                        "constOccurrences": const_occurrences,
                        "constValue": const_value,
                        "executionPhase": "VALIDATOR_SELF_TEST",
                        "evidenceDisposition": (
                            "DOMAIN_CLOSURE_PASS"
                            if relation_id == "ACV-049-S"
                            else "NON_STRING_RECONCILIATION_PASS"
                        ),
                        "javascriptSchemaAccepted": evidence[
                            "javascriptSchemaAccepted"
                        ],
                        "materialized": source in materialized,
                        "pythonSchemaAccepted": evidence["pythonSchemaAccepted"],
                        "selfTestValues": evidence["testValues"],
                    }
                )
                if relation_id == "ACV-049-S":
                    row.update(
                        {
                            "carrierCaseIds": [
                                case_id
                                for case_id, _response, _value
                                in carriers_by_path[source]
                            ],
                            "supplementaryReachability": (
                                "NOT_REQUIRED_PHASE_A_MATERIALIZED"
                                if source in materialized
                                else "REQUIRED_PENDING_SEPARATE_RATIFICATION"
                            ),
                        }
                    )
                else:
                    retired = [
                        item["historicalInstanceId"]
                        for item in reconciliation
                        if item["logicalPath"] == source
                    ]
                    if len(retired) != 10:
                        raise SemanticACV049Error(
                            f"ACV-049 non-string reconciliation drift: {source}"
                        )
                    row.update(
                        {
                            "historicalStringProvenanceIdsRetired": retired,
                            "terminalType": "array",
                        }
                    )
            else:
                row.update(
                    {
                        **e_execution[source],
                        "executionPhase": "BLIND_INPUT_EXECUTION",
                        "evidenceDisposition": (
                            "LOCAL_BLIND_EXECUTION_PASS_TWO_ENVIRONMENT_PENDING"
                        ),
                    }
                )
            rows.append(row)

    relation_counts = {
        relation_id: len(members)
        for relation_id, members in relation_members.items()
    }
    relation_digests = {
        relation_id: digest_lines(members)
        for relation_id, members in relation_members.items()
    }
    if len(rows) != 884 or relation_counts != {
        "ACV-049-L": 401,
        "ACV-049-P": 300,
        "ACV-049-S": 101,
        "ACV-049-N": 5,
        "ACV-049-E": 77,
    }:
        raise SemanticACV049Error("ACV-049 replacement report count drift")
    return {
        "claimed_mutant_kills": 0,
        "executed_relation_counts": {
            "ACV-049-L": 401,
            "ACV-049-N": 5,
            "ACV-049-S": 101,
        },
        "historical_reconciliation_count": len(reconciliation),
        "historical_reconciliation_sha256": sha256_bytes(dumps(reconciliation)),
        "instance_count": len(rows),
        "materialized_mutable_path_count": len(materialized & mutable),
        "materialized_path_count": len(materialized),
        "materialized_singleton_path_count": len(materialized & singleton),
        "path_count": len(partition["logical"]),
        "pending_relation_counts": {"ACV-049-E": 77, "ACV-049-P": 300},
        "relation_counts": relation_counts,
        "relation_member_set_sha256": relation_digests,
        "rows": rows,
        "schema": "styx.app-core-iface0.semantic-acv049-partial-execution.v3",
        "semantic_rule_id": "ACV-049",
        "status": "REMEDIATION_PARTIAL_EXECUTION",
        "unmaterialized_path_count": len(set(partition["literal"]) - materialized),
        "verdict": "PARTIAL_EXECUTION_PASS",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--emit-terminal-jobs", action="store_true")
    modes.add_argument("--emit-source-site-map", action="store_true")
    parser.add_argument("--javascript-results-stdin", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.emit_terminal_jobs:
            if args.javascript_results_stdin or args.output is not None:
                raise SemanticACV049Error("terminal-job mode argument drift")
            sys.stdout.buffer.write(
                dumps(
                    build_terminal_jobs(
                        args.repo_root.resolve(),
                        args.contract.resolve(),
                        args.evidence_root.resolve(),
                    )
                )
            )
            return 0
        if args.emit_source_site_map:
            if args.javascript_results_stdin or args.output is not None:
                raise SemanticACV049Error("source-site mode argument drift")
            sys.stdout.buffer.write(
                dumps(
                    derive_phase_a_source_site_map(
                        args.repo_root.resolve(),
                        args.contract.resolve(),
                        args.evidence_root.resolve(),
                    )
                )
            )
            return 0
        if not args.javascript_results_stdin or args.output is None:
            raise SemanticACV049Error("report mode requires JavaScript stdin and output")
        try:
            javascript_result = json.loads(sys.stdin.buffer.read())
        except (UnicodeDecodeError, ValueError) as error:
            raise SemanticACV049Error(
                "JavaScript terminal-schema self-test emitted invalid JSON"
            ) from error
        report = build_report(
            args.repo_root.resolve(), args.contract.resolve(),
            args.evidence_root.resolve(), javascript_result=javascript_result,
        )
        store_report(args.output, report, allowed_fields=REPORT_FIELDS)
    except (
        InventoryError, OSError, ReportError, SemanticACV049Error,
        WitnessGenerationError,
    ) as error:
        print(f"APP-core semantic ACV-049 preflight: FAIL: {error}", file=sys.stderr)
        return 2
    print(
        "APP-core semantic ACV-049 L/S/N partial execution: PASS "
        f"instances={report['instance_count']} sha256={sha256_bytes(dumps(report))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
