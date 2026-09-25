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
import interface_model as _retained_contract
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

ACV049_MUTANT_CHANNEL_NAME = "STYX_ACV049_MUTANT_CHANNEL"
ACV049_MUTANT_CHANNELS = (
    "ACV049-CONTROL-CHANNEL-ALPHA",
    "ACV049-CONTROL-CHANNEL-BRAVO",
)


class SemanticACV049Error(ValueError):
    """The ACV-049 preflight relation is malformed or overclaims evidence."""


class _SourceTaggedString(str):
    """One immutable string carrying its nearest evaluator construction site."""

    def __new__(
        cls,
        value: str,
        site_id: str,
        source_tokens: tuple[str | int, ...] = (),
    ) -> _SourceTaggedString:
        instance = super().__new__(cls, value)
        instance.site_id = site_id
        instance.source_tokens = source_tokens
        return instance

    def __deepcopy__(self, memo: dict[int, Any]) -> _SourceTaggedString:
        del memo
        return self


class _SourceTaggedDict(dict[Any, Any]):
    def __init__(self, value: dict[Any, Any], site_id: str) -> None:
        super().__init__(value)
        self.site_id = site_id

    def __deepcopy__(self, memo: dict[int, Any]) -> _SourceTaggedDict:
        return _SourceTaggedDict(copy.deepcopy(dict(self), memo), self.site_id)


class _SourceTaggedList(list[Any]):
    def __init__(self, value: list[Any], site_id: str) -> None:
        super().__init__(value)
        self.site_id = site_id

    def __deepcopy__(self, memo: dict[int, Any]) -> _SourceTaggedList:
        return _SourceTaggedList(copy.deepcopy(list(self), memo), self.site_id)


class _SourceTaggedTuple(tuple[Any, ...]):
    def __new__(cls, value: tuple[Any, ...], site_id: str) -> _SourceTaggedTuple:
        instance = super().__new__(cls, value)
        instance.site_id = site_id
        return instance

    def __deepcopy__(self, memo: dict[int, Any]) -> _SourceTaggedTuple:
        return _SourceTaggedTuple(
            tuple(copy.deepcopy(item, memo) for item in self), self.site_id
        )


def _tag_source_value(
    site_id: str,
    value: Any,
    *,
    _source_tokens: tuple[str | int, ...] = (),
) -> Any:
    """Tag unowned strings without changing their JSON-visible value or shape."""

    if isinstance(
        value,
        (_SourceTaggedString, _SourceTaggedDict, _SourceTaggedList, _SourceTaggedTuple),
    ):
        return value
    if isinstance(value, str):
        return _SourceTaggedString(value, site_id, _source_tokens)
    if isinstance(value, list):
        return _SourceTaggedList(
            [
                _tag_source_value(
                    site_id, item, _source_tokens=(*_source_tokens, index)
                )
                for index, item in enumerate(value)
            ],
            site_id,
        )
    if isinstance(value, tuple):
        return _SourceTaggedTuple(
            tuple(
                _tag_source_value(
                    site_id, item, _source_tokens=(*_source_tokens, index)
                )
                for index, item in enumerate(value)
            ),
            site_id,
        )
    if isinstance(value, dict):
        return _SourceTaggedDict(
            {
                key: _tag_source_value(
                    site_id, item, _source_tokens=(*_source_tokens, key)
                )
                for key, item in value.items()
            },
            site_id,
        )
    if isinstance(value, set):
        return {
            _tag_source_value(site_id, item, _source_tokens=_source_tokens)
            for item in value
        }
    if isinstance(value, frozenset):
        return frozenset(
            _tag_source_value(site_id, item, _source_tokens=_source_tokens)
            for item in value
        )
    return value


def _acv049_source_str(value: Any) -> str:
    """Preserve provenance through a value-preserving string cast, not a new owner."""

    return value if isinstance(value, _SourceTaggedString) else str(value)


def _response_copy_source_value(value: Any) -> Any:
    """A new output-copy expression owns its copied leaves, not prior trace tags."""
    if isinstance(value, dict):
        return {key: _response_copy_source_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_response_copy_source_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_response_copy_source_value(item) for item in value)
    return str(value) if isinstance(value, str) else value


def _install_source_trace(module: types.ModuleType) -> None:
    events: list[dict[str, Any]] = []

    def trace(kind: str, site_id: str, value: Any) -> Any:
        events.append({"kind": kind, "siteId": site_id, "value": _response_copy_source_value(value)})
        return value

    def guard(site_id: str, equal: bool, regenerated: Any, prior: Any) -> bool:
        trace("PRIOR_GUARD", site_id, {"equal": equal, "regenerated": regenerated, "prior": prior})
        return equal

    module.__dict__.update(_acv049_trace_events=events, _acv049_trace=trace, _acv049_guard_comparison=guard)


def _tuple_source_value(value: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    """Retag only fields constructed together by one observed dict expression."""

    if not isinstance(value, dict) or any(
        field not in value or not isinstance(value[field], str) for field in fields
    ):
        raise SemanticACV049Error("ACV-049 tuple construction shape drift")
    return {key: str(item) if key in fields else item for key, item in value.items()}


def _acv049_single_dict_value(value: dict[Any, Any]) -> Any:
    """Return the value of an instrumented one-entry comprehension fragment."""

    if not isinstance(value, dict) or len(value) != 1:
        raise SemanticACV049Error("ACV-049 comprehension fragment is not singular")
    return next(iter(value.values()))


def _site_token(value: str) -> str:
    token = "".join(character if character.isalnum() else "-" for character in value)
    token = "-".join(part for part in token.upper().split("-") if part)
    return token or "VALUE"


class _SourceSiteInstrumenter(ast.NodeTransformer):
    """Instrument evaluator value-producing AST nodes with stable site IDs."""

    def __init__(self) -> None:
        self.tuple_constructions = False
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

    def _tag_dict_comprehension(
        self, site_id: str, fragment: ast.Dict
    ) -> ast.expr:
        return self._tag(site_id, fragment)

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
        value_digests = [sha256_bytes(ast.dump(value, include_attributes=False).encode()) for value in node.values]
        keys = {key.value for key in node.keys if isinstance(key, ast.Constant)}
        constructors = {
            "_assemble_context_projection": ("RECORD-OUTCOME", ("disposition", "stage")),
            "_candidate_result_from_primary": ("CANDIDATE-TERMINAL", ("primary", "stage")),
            "_candidate_terminal": ("REPLAY-CANDIDATE-TERMINAL", ("primary", "stage")),
            "_rejected_transcript_result": ("TRANSCRIPT-REJECTED", ("reason", "stage")),
            "evaluate_genesis": ("GENESIS-TERMINAL", ("reason", "stage")),
            "_project_content_states": ("CONTENT-STATE-AXIS", (
                "contentClass", "localAvailability", "bindingObservation",
                "retentionState", "replayReadiness",
            )),
        }
        tuple_label, fields = constructors.get(self.function_name, ("", ()))
        tuple_fields = fields if self.tuple_constructions and fields and set(fields) <= keys else ()
        expression_digest = sha256_bytes(ast.dump(node, include_attributes=False).encode())
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
            trace_construction = False
            if self.tuple_constructions:
                self.sites[site_id]["sourceExpressionSha256"] = value_digests[index]
                trace_construction = (
                    (self.function_name == "replay_context" and label in {"genesis", "logicalEvents"})
                    or (self.function_name == "_assemble_context_projection" and label in {
                        "necessaryCredentialIdentifiers", "possibleCredentialIdentifiers", "terminalCredentialIdentifiers"})
                    or (self.function_name == "_credential_projection" and label in {
                        "credentialIdentifierHex", "signatureSuiteId", "verificationKeyHex"})
                )
                if trace_construction:
                    value = self._response_copy(value)
            tagged = self._tag(site_id, value)
            if trace_construction:
                tagged = ast.Call(func=ast.Name(id="_acv049_trace", ctx=ast.Load()), args=[ast.Constant("CONSTRUCTION"), ast.Constant(site_id), tagged], keywords=[])
            wrapped.append(ast.copy_location(tagged, value))
        node.values = wrapped
        if tuple_fields:
            site_id = self._site(node, "TUPLE-DICT", tuple_label)
            self.sites[site_id].update({
                "tupleFields": list(tuple_fields),
                "sourceExpressionSha256": expression_digest,
            })
            reset = ast.Call(
                func=ast.Name(id="_acv049_tuple_source_value", ctx=ast.Load()),
                args=[node, ast.Tuple(elts=[ast.Constant(field) for field in tuple_fields], ctx=ast.Load())],
                keywords=[],
            )
            return ast.copy_location(self._tag(site_id, reset), node)
        return node

    def visit_Compare(self, node: ast.Compare) -> ast.AST:
        if (self.tuple_constructions and self.function_name == "_revalidate_prior_snapshot"
                and isinstance(node.left, ast.Name) and node.left.id == "regenerated"
                and len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq)
                and len(node.comparators) == 1 and isinstance(node.comparators[0], ast.Name)
                and node.comparators[0].id == "prior"):
            site_id = self._site(node, "PRIOR-GUARD", "REGENERATED-EQUAL-PRIOR")
            self.sites[site_id]["sourceExpressionSha256"] = sha256_bytes(ast.dump(node, include_attributes=False).encode())
            return ast.copy_location(ast.Call(func=ast.Name(id="_acv049_guard_comparison", ctx=ast.Load()),
                args=[ast.Constant(site_id), node, ast.Name(id="regenerated", ctx=ast.Load()), ast.Name(id="prior", ctx=ast.Load())], keywords=[]), node)
        return self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> ast.AST | list[ast.stmt]:
        if (self.tuple_constructions and self.function_name == "evaluate_candidate"
                and isinstance(node.exc, ast.Call) and isinstance(node.exc.func, ast.Name)
                and node.exc.func.id == "RequestRejected" and not node.exc.args and not node.exc.keywords):
            site_id = self._site(node, "REJECTION-ORIGIN", "REQUEST-REJECTED")
            self.sites[site_id]["sourceExpressionSha256"] = sha256_bytes(ast.dump(node, include_attributes=False).encode())
            observation = ast.Expr(value=ast.Call(func=ast.Name(id="_acv049_trace", ctx=ast.Load()),
                args=[ast.Constant("REQUEST_REJECTED_ORIGIN"), ast.Constant(site_id), ast.Constant(None)], keywords=[]))
            return [ast.copy_location(observation, node), node]
        return self.generic_visit(node)

    def visit_DictComp(self, node: ast.DictComp) -> ast.AST:
        node = self.generic_visit(node)
        if self.function_name is None:
            return node
        site_id = self._site(node.value, "DICT-COMPREHENSION", "VALUE")
        fragment = ast.Dict(
            keys=[copy.deepcopy(node.key)],
            values=[node.value],
        )
        tagged = self._tag_dict_comprehension(site_id, fragment)
        node.value = ast.copy_location(
            ast.Call(
                func=ast.Name(id="_acv049_single_dict_value", ctx=ast.Load()),
                args=[tagged],
                keywords=[],
            ),
            node.value,
        )
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

    def _response_copy(self, value: ast.expr) -> ast.expr:
        return ast.copy_location(ast.Call(func=ast.Name(id="_acv049_response_copy", ctx=ast.Load()), args=[value], keywords=[]), value)

    def _source_str_call(self, node: ast.Call) -> ast.AST:
        node.func = ast.copy_location(ast.Name(id="_acv049_source_str", ctx=ast.Load()), node.func)
        return node

    def visit_Call(self, node: ast.Call) -> ast.AST:
        node = self.generic_visit(node)
        if (self.tuple_constructions and isinstance(node.func, ast.Name)
                and node.func.id == "str" and len(node.args) == 1 and not node.keywords):
            return self._source_str_call(node)
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


class _SourceMutationInstrumenter(_SourceSiteInstrumenter):
    """Replace only named string construction sites with a frozen pair."""

    def __init__(
        self,
        mutations: dict[
            str,
            tuple[tuple[tuple[str | int, ...], tuple[str, str]], ...],
        ],
        channels: tuple[str, str],
    ) -> None:
        super().__init__()
        if len(mutations) != 1:
            raise SemanticACV049Error(
                "ACV-049 source mutant requires exactly one AST construction site"
            )
        if not mutations or any(
            not site_id.startswith("PURITY-SITE-")
            or not patches
            or len({selector for selector, _candidates in patches}) != len(patches)
            or any(
                any(not isinstance(token, (str, int)) for token in selector)
                or len(candidates) != 2
                or any(not isinstance(value, str) for value in candidates)
                for selector, candidates in patches
            )
            for site_id, patches in mutations.items()
        ):
            raise SemanticACV049Error("ACV-049 source mutation map is malformed")
        ordered_channels = _controlled_channel_order(channels)
        self.channels = tuple(channel.decode("ascii") for channel in ordered_channels)
        self.mutations = dict(mutations)
        self.mutated_sites: set[str] = set()

    def _response_copy(self, value: ast.expr) -> ast.expr:
        return value

    def _source_str_call(self, node: ast.Call) -> ast.AST:
        # Mutant evaluation uses ordinary strings; no provenance helper is needed.
        return node

    def _tag(self, site_id: str, value: ast.expr) -> ast.expr:
        patches = self.mutations.get(site_id)
        if patches is None:
            return value
        self.mutated_sites.add(site_id)
        mutated = value
        for selector, candidates in patches:
            channel_read = ast.Subscript(
                value=ast.Name(id="_acv049_mutant_environ", ctx=ast.Load()),
                slice=ast.Constant(ACV049_MUTANT_CHANNEL_NAME),
                ctx=ast.Load(),
            )
            replacement = ast.Subscript(
                value=ast.Dict(
                    keys=[ast.Constant(channel) for channel in self.channels],
                    values=[ast.Constant(candidate) for candidate in candidates],
                ),
                slice=channel_read,
                ctx=ast.Load(),
            )
            mutated = ast.Call(
                func=ast.Name(id="_acv049_replace_source_value", ctx=ast.Load()),
                args=[
                    mutated,
                    ast.Tuple(
                        elts=[ast.Constant(token) for token in selector],
                        ctx=ast.Load(),
                    ),
                    replacement,
                ],
                keywords=[],
            )
        return ast.Call(
            func=ast.Name(id="_acv049_record_mutated_site", ctx=ast.Load()),
            args=[ast.Constant(site_id), mutated],
            keywords=[],
        )

    def _tag_dict_comprehension(
        self, site_id: str, fragment: ast.Dict
    ) -> ast.expr:
        patches = self.mutations.get(site_id)
        if patches is None:
            return fragment
        self.mutated_sites.add(site_id)
        mutated: ast.expr = fragment
        for selector, candidates in patches:
            channel_read = ast.Subscript(
                value=ast.Name(id="_acv049_mutant_environ", ctx=ast.Load()),
                slice=ast.Constant(ACV049_MUTANT_CHANNEL_NAME),
                ctx=ast.Load(),
            )
            replacement = ast.Subscript(
                value=ast.Dict(
                    keys=[ast.Constant(channel) for channel in self.channels],
                    values=[ast.Constant(candidate) for candidate in candidates],
                ),
                slice=channel_read,
                ctx=ast.Load(),
            )
            mutated = ast.Call(
                func=ast.Name(
                    id="_acv049_replace_comprehension_source_value",
                    ctx=ast.Load(),
                ),
                args=[
                    mutated,
                    ast.Tuple(
                        elts=[ast.Constant(token) for token in selector],
                        ctx=ast.Load(),
                    ),
                    replacement,
                ],
                keywords=[],
            )
        return ast.Call(
            func=ast.Name(id="_acv049_record_mutated_site", ctx=ast.Load()),
            args=[ast.Constant(site_id), mutated],
            keywords=[],
        )

    def visit_Module(self, node: ast.Module) -> ast.AST:
        node = self.generic_visit(node)
        insertion = 0
        if (
            node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        ):
            insertion = 1
        while (
            insertion < len(node.body)
            and isinstance(node.body[insertion], ast.ImportFrom)
            and node.body[insertion].module == "__future__"
        ):
            insertion += 1
        node.body.insert(
            insertion,
            ast.ImportFrom(
                module="os",
                names=[
                    ast.alias(name="environ", asname="_acv049_mutant_environ")
                ],
                level=0,
            ),
        )
        helpers = ast.parse(
            "def _acv049_replace_source_value(value, path, replacement):\n"
            "    if not path:\n"
            "        return replacement\n"
            "    head, *tail = path\n"
            "    if isinstance(value, dict) and isinstance(head, str) and head in value:\n"
            "        result = dict(value)\n"
            "        result[head] = _acv049_replace_source_value(value[head], tuple(tail), replacement)\n"
            "        return result\n"
            "    if isinstance(value, list) and isinstance(head, int) and 0 <= head < len(value):\n"
            "        result = list(value)\n"
            "        result[head] = _acv049_replace_source_value(value[head], tuple(tail), replacement)\n"
            "        return result\n"
            "    raise RuntimeError('ACV-049 source selector drift')\n"
            "\n"
            "def _acv049_replace_comprehension_source_value(value, path, replacement):\n"
            "    if not isinstance(value, dict) or len(value) != 1 or not path:\n"
            "        raise RuntimeError('ACV-049 comprehension selector drift')\n"
            "    if path[0] not in value:\n"
            "        return value\n"
            "    return _acv049_replace_source_value(value, path, replacement)\n"
            "\n"
            "def _acv049_single_dict_value(value):\n"
            "    if not isinstance(value, dict) or len(value) != 1:\n"
            "        raise RuntimeError('ACV-049 comprehension fragment is not singular')\n"
            "    return next(iter(value.values()))\n"
            "\n"
            "_acv049_mutated_sites_executed = set()\n"
            "def _acv049_record_mutated_site(site_id, value):\n"
            "    _acv049_mutated_sites_executed.add(site_id)\n"
            "    return value\n"
        ).body
        for offset, helper in enumerate(helpers, start=1):
            node.body.insert(insertion + offset, helper)
        if self.tuple_constructions:
            node.body.insert(insertion + len(helpers) + 1, ast.parse(
                "def _acv049_tuple_source_value(value, fields):\n"
                "    if not isinstance(value, dict) or any(field not in value or not isinstance(value[field], str) for field in fields):\n"
                "        raise RuntimeError('ACV-049 tuple construction shape drift')\n"
                "    return {key: str(item) if key in fields else item for key, item in value.items()}\n"
            ).body[0])
        return node


def _mutated_source_tree(
    source: str,
    filename: str,
    mutations: dict[
        str,
        tuple[tuple[tuple[str | int, ...], tuple[str, str]], ...],
    ],
    channels: tuple[str, str],
    *,
    tuple_constructions: bool = False,
) -> tuple[ast.Module, dict[str, dict[str, Any]], bytes]:
    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, ValueError) as error:
        raise SemanticACV049Error("ACV-049 evaluator AST is unavailable") from error
    instrumenter = _SourceMutationInstrumenter(mutations, channels)
    instrumenter.tuple_constructions = tuple_constructions
    transformed = instrumenter.visit(tree)
    if not isinstance(transformed, ast.Module):
        raise SemanticACV049Error("ACV-049 mutated evaluator root drift")
    ast.fix_missing_locations(transformed)
    if instrumenter.mutated_sites != set(mutations):
        raise SemanticACV049Error("ACV-049 source mutation site is absent or dead")
    canonical_source = (ast.unparse(transformed) + "\n").encode("utf-8")
    reparsed = ast.parse(canonical_source, filename=filename)
    if ast.dump(reparsed, include_attributes=False) != ast.dump(
        transformed, include_attributes=False
    ):
        raise SemanticACV049Error("ACV-049 mutant source round-trip drift")
    return transformed, instrumenter.sites, canonical_source


def _mutated_interface_model(
    repo_root: Path,
    mutations: dict[
        str,
        tuple[tuple[tuple[str | int, ...], tuple[str, str]], ...],
    ],
    channels: tuple[str, str],
    *,
    tuple_constructions: bool = False,
) -> tuple[types.ModuleType, dict[str, dict[str, Any]], bytes]:
    source_path = (
        repo_root
        / "tools/causal-flow-simulator/app_core_iface0/interface_model.py"
    )
    try:
        source = source_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise SemanticACV049Error("ACV-049 evaluator source is unavailable") from error
    tree, sites, canonical_source = _mutated_source_tree(
        source, str(source_path), mutations, channels,
        tuple_constructions=tuple_constructions,
    )
    module = types.ModuleType("interface_model")
    module.__file__ = str(source_path)
    previous = sys.modules.get("interface_model")
    sys.modules["interface_model"] = module
    try:
        exec(compile(tree, str(source_path), "exec"), module.__dict__)
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
    if tuple_constructions:
        _install_source_trace(module)
    return module, sites, canonical_source


def _instrumented_interface_model(
    repo_root: Path,
    *,
    tuple_constructions: bool = False,
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
    instrumenter.tuple_constructions = tuple_constructions
    instrumented = instrumenter.visit(tree)
    ast.fix_missing_locations(instrumented)
    module = types.ModuleType("interface_model")
    module.__file__ = str(source_path)
    module.__dict__["_acv049_tag_source_value"] = _tag_source_value
    module.__dict__["_acv049_single_dict_value"] = _acv049_single_dict_value
    module.__dict__["_acv049_tuple_source_value"] = _tuple_source_value
    module.__dict__["_acv049_response_copy"] = _response_copy_source_value
    module.__dict__["_acv049_source_str"] = _acv049_source_str
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
    if tuple_constructions:
        _install_source_trace(module)
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


def _pattern_source_values(
    value: Any,
    pattern: tuple[str | None, ...],
    prefix: tuple[str | int, ...] = (),
) -> list[tuple[tuple[str | int, ...], _SourceTaggedString, tuple[str | int, ...]]]:
    if not pattern:
        if not isinstance(value, _SourceTaggedString):
            return []
        return [(prefix, value, value.source_tokens)]
    token, remaining = pattern[0], pattern[1:]
    if token is None:
        if not isinstance(value, list):
            return []
        return [
            result
            for index, item in enumerate(value)
            for result in _pattern_source_values(
                item, remaining, (*prefix, index)
            )
        ]
    if not isinstance(value, dict) or token not in value:
        return []
    return _pattern_source_values(value[token], remaining, (*prefix, token))


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


def _semantic_construction_site(
    path: str, ast_site_id: str, *, tuple_constructions: bool = True,
) -> str:
    """Name semantic ownership; this label never establishes AST identity."""

    if tuple_constructions:
        if ("/projection/recordOutcomes/*/" in path and path.endswith(("/disposition", "/stage"))) or path.endswith(
            "/<CandidateEvaluationReadyV0>/primaryOnCommit"
        ):
            return "PURITY-SITE-RECORD-OUTCOME"
        if "/<ReplayContextResultCandidateRejectedV0>/" in path and path.endswith(("/primary", "/stage")):
            return "PURITY-SITE-REPLAY-CANDIDATE-TERMINAL"

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
    repo_root: Path, contract: Path, evidence_root: Path,
    *, tuple_constructions: bool = False,
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
    instrumented, ast_sites = _instrumented_interface_model(
        repo_root, tuple_constructions=tuple_constructions,
    )
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
        tuple[str, str, str, str], dict[str, set[Any]]
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
            values = _pattern_source_values(response, pattern)
            if not values:
                continue
            materialized.add(path)
            for pointer, value, relative_pointer in values:
                if value.site_id not in ast_sites:
                    raise SemanticACV049Error("ACV-049 reported an unknown AST site")
                semantic_site = _semantic_construction_site(
                    path, value.site_id, tuple_constructions=tuple_constructions,
                )
                used_sites.add(semantic_site)
                fault_context = (
                    "FIXED_INTERNAL_COLLISION_ORACLE" if fault_injected else "NONE"
                )
                key = (path, semantic_site, case_id, fault_context)
                group = route_groups.setdefault(
                    key,
                    {
                        "astSiteIds": set(),
                        "concretePointers": set(),
                        "sourceSelectors": set(),
                    },
                )
                group["astSiteIds"].add(value.site_id)
                concrete_pointer = _report_pointer(_json_pointer(pointer))
                relative = _json_pointer(relative_pointer)
                relative_report_pointer = (
                    "SELF" if not relative else _report_pointer(relative)
                )
                group["concretePointers"].add(concrete_pointer)
                group["sourceSelectors"].add(
                    (
                        value.site_id,
                        concrete_pointer,
                        relative_report_pointer,
                        relative_pointer,
                    )
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
            "sourceSelectors": [
                {
                    "astSiteId": ast_site_id,
                    "concretePointer": concrete_pointer,
                    "relativePointer": relative_pointer,
                    "relativeTokens": list(relative_tokens),
                }
                for (
                    ast_site_id,
                    concrete_pointer,
                    relative_pointer,
                    relative_tokens,
                ) in sorted(
                    group["sourceSelectors"],
                    key=lambda item: dumps(list(item[:3]) + [list(item[3])]),
                )
            ],
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
        or (not tuple_constructions and len(grouped_sites) != 76)
        or route_class_counts
        != {"ORDINARY_ROUTE": 581, "FAULT_INJECTED_ROUTE": 15}
    ):
        raise SemanticACV049Error("ACV-049 Phase-A source-site relation drift")
    return {
        **({"ownershipRevision": "V33_TUPLE_CONSTRUCTIONS"} if tuple_constructions else {}),
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


def build_scalar_source_mutant_spec(
    schema: dict[str, Any],
    route: dict[str, Any],
    terminal: LogicalTerminal,
    baseline: str,
) -> dict[str, Any]:
    if any("enum" in node for node in terminal.nodes):
        raise SemanticACV049Error("ACV-049 scalar mutant cannot own an enum")
    selectors = route.get("sourceSelectors")
    if (
        not isinstance(selectors, list)
        or len(selectors) != 1
        or not isinstance(selectors[0], dict)
        or set(selectors[0])
        != {
            "astSiteId",
            "concretePointer",
            "relativePointer",
            "relativeTokens",
        }
        or route.get("astSiteIds") != [selectors[0]["astSiteId"]]
        or route.get("concretePointers") != [selectors[0]["concretePointer"]]
    ):
        raise SemanticACV049Error("ACV-049 scalar source selector is not exact")
    candidate_plan = _derive_schema_candidate_pair(
        schema, terminal, baseline, ACV049_MUTANT_CHANNELS
    )
    core = {
        "advanceCounts": candidate_plan["advanceCounts"],
        "astSiteId": selectors[0]["astSiteId"],
        "candidateValues": candidate_plan["candidateValues"],
        "concretePointer": selectors[0]["concretePointer"],
        "domainClass": candidate_plan["domainClass"],
        "faultContext": route["faultContext"],
        "logicalPath": route["logicalPath"],
        "relativePointer": selectors[0]["relativePointer"],
        "relativeTokens": selectors[0]["relativeTokens"],
        "requestCaseId": route["requestCaseId"],
        "routeClass": route["routeClass"],
        "siteId": route["siteId"],
        "sourceSiteMapRouteSha256": sha256_bytes(dumps(route)),
        "twoStateRule": candidate_plan["twoStateRule"],
    }
    return {
        **core,
        "mutantId": "ACV049-P-MUTANT-" + sha256_bytes(dumps(core))[:24].upper(),
        "schema": "styx.app-core-iface0.acv049-scalar-source-mutant-spec.v1",
    }


def build_phase_a_scalar_source_mutant_manifest(
    repo_root: Path,
    contract: Path,
    evidence_root: Path,
    *,
    source_site_map: dict[str, Any] | None = None,
) -> dict[str, Any]:
    authority = ContractAuthority.load(repo_root, contract)
    _inventory, _inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    site_map = (
        derive_phase_a_source_site_map(repo_root, contract, evidence_root)
        if source_site_map is None
        else copy.deepcopy(source_site_map)
    )
    if (
        site_map.get("schema")
        != "styx.app-core-iface0.acv049-source-site-map.v1"
        or site_map.get("verdict") != "PHASE_A_SOURCE_SITE_MAP_PASS"
        or site_map.get("routeCount") != 596
        or not isinstance(site_map.get("routes"), list)
    ):
        raise SemanticACV049Error("ACV-049 source-site map is not final")
    request_rows = {
        case_id: (value, raw)
        for case_id, (value, raw) in carriers.items()
        if case_id.startswith("PCR-REQUEST-")
    }
    oracle_by_request = {
        dumps(case.request): case.collision_oracle
        for case in _semantic_request_carriers(authority)
        if case.collision_oracle is not None
    }
    responses: dict[str, dict[str, Any]] = {}
    for case_id, (request, raw) in request_rows.items():
        response = _evaluate_fixture_request(
            authority, request, oracle_by_request.get(raw)
        )
        validate_response_before_release(authority, response)
        responses[case_id] = response

    terminals: dict[str, LogicalTerminal] = {}
    specs = []
    o08_bound_candidates = []
    pending_guarded_candidates = []
    skipped_enum_routes = 0
    capability_dimensions = frozenset(authority.capability_requirements())
    guarded_site_ids = {
        row["siteId"]
        for row in site_map.get("usedSites", [])
        if any(
            member.get("function") == "_revalidate_prior_snapshot"
            and member.get("kind") == "DICT-VALUE"
            and member.get("label") in {"logicalEvent", "proposedGenesis"}
            for member in row.get("astMembers", [])
        )
    }
    if len(guarded_site_ids) != 2:
        raise SemanticACV049Error("ACV-049 prior revalidation site drift")
    for route in site_map["routes"]:
        if not isinstance(route, dict):
            raise SemanticACV049Error("ACV-049 source-site route is malformed")
        logical_path = _raw_report_logical_path(route.get("logicalPath", ""))
        terminal = terminals.setdefault(
            logical_path, resolve_logical_terminal(authority.schema, logical_path)
        )
        if (
            len(terminal.data_tokens) == 5
            and terminal.data_tokens[:3]
            == ("result", "descriptor", "capabilityRequirements")
            and terminal.data_tokens[3] in capability_dimensions
            and terminal.data_tokens[4] == "selectedValue"
        ):
            selectors = route.get("sourceSelectors")
            if not isinstance(selectors, list) or len(selectors) != 1:
                raise SemanticACV049Error(
                    "ACV-049 O-08-bound route selector is not exact"
                )
            selector = selectors[0]
            o08_bound_candidates.append(
                {
                    "astSiteId": selector["astSiteId"],
                    "candidateDisposition": "O08_BOUND",
                    "concretePointer": selector["concretePointer"],
                    "dimension": terminal.data_tokens[3],
                    "evidenceStatus": "PENDING_NEGATIVE_CONTROL",
                    "logicalPath": route["logicalPath"],
                    "requestCaseId": route["requestCaseId"],
                    "sourceSiteMapRouteSha256": sha256_bytes(dumps(route)),
                }
            )
            continue
        route_site_ids = set(route.get("astSiteIds", []))
        if route_site_ids and route_site_ids <= guarded_site_ids:
            selectors = route.get("sourceSelectors")
            if not isinstance(selectors, list) or len(selectors) != 1:
                raise SemanticACV049Error(
                    "ACV-049 guarded pass-through selector is not exact"
                )
            selector = selectors[0]
            pending_guarded_candidates.append(
                {
                    "astSiteId": selector["astSiteId"],
                    "candidateDisposition": "PENDING_CONTRACT_CLASSIFICATION",
                    "concretePointer": selector["concretePointer"],
                    "guard": "PRIOR_SNAPSHOT_BYTE_EQUALITY",
                    "logicalPath": route["logicalPath"],
                    "requestCaseId": route["requestCaseId"],
                    "sourceSiteMapRouteSha256": sha256_bytes(dumps(route)),
                }
            )
            continue
        if any("enum" in node for node in terminal.nodes):
            skipped_enum_routes += 1
            continue
        response = responses.get(route.get("requestCaseId"))
        if response is None:
            raise SemanticACV049Error("ACV-049 scalar route request is absent")
        pointers = route.get("concretePointers")
        if not isinstance(pointers, list) or len(pointers) != 1:
            raise SemanticACV049Error("ACV-049 scalar route pointer is not exact")
        baseline = _value_at_report_pointer(response, pointers[0])
        if not isinstance(baseline, str):
            raise SemanticACV049Error("ACV-049 scalar route is not a string")
        specs.append(
            build_scalar_source_mutant_spec(
                authority.schema, route, terminal, baseline
            )
        )
    if (
        not specs
        or len(specs)
        + len(o08_bound_candidates)
        + len(pending_guarded_candidates)
        + skipped_enum_routes
        != site_map["routeCount"]
        or len({spec["mutantId"] for spec in specs}) != len(specs)
        or len(o08_bound_candidates) != len(capability_dimensions)
        or {row["dimension"] for row in o08_bound_candidates}
        != capability_dimensions
        or len(pending_guarded_candidates) != 48
    ):
        raise SemanticACV049Error("ACV-049 scalar mutant manifest is incomplete")
    return {
        "mutantCount": len(specs),
        "mutantSetSha256": sha256_bytes(
            dumps([spec["mutantId"] for spec in specs])
        ),
        "mutants": specs,
        "o08BoundCandidateCount": len(o08_bound_candidates),
        "o08BoundCandidates": o08_bound_candidates,
        "pendingGuardedCandidateCount": len(pending_guarded_candidates),
        "pendingGuardedCandidates": pending_guarded_candidates,
        "schema": "styx.app-core-iface0.acv049-scalar-source-mutant-manifest.v1",
        "skippedEnumRouteCount": skipped_enum_routes,
        "sourceSiteRouteCount": site_map["routeCount"],
        "sourceSiteRouteSetSha256": site_map["routeSetSha256"],
        "verdict": "PHASE_A_SCALAR_MUTANT_MANIFEST_PASS",
    }


_ACV049_RELATION_SITE_SPECS = {
    "PURITY-SITE-RECORD-OUTCOME": {
        "fields": ("disposition", "stage"),
        "relation": "candidateEvaluationPrimaryRelationV0",
    },
    "PURITY-SITE-REPLAY-CANDIDATE-TERMINAL": {
        "fields": ("primary", "stage"),
        "relation": "candidateEvaluationPrimaryRelationV0",
    },
    "PURITY-SITE-CANDIDATE-TERMINAL": {
        "fields": ("primary", "stage"),
        "relation": "candidateEvaluationPrimaryRelationV0",
    },
    "PURITY-SITE-CONTENT-STATE-AXIS": {
        "fields": (
            "contentClass", "localAvailability", "bindingObservation",
            "retentionState", "replayReadiness",
        ),
        "relation": "contentAxisLegalRelationV0",
    },
    "PURITY-SITE-GENESIS-TERMINAL": {
        "fields": ("reason", "stage"),
        "relation": "genesisReasonStageRelationV0",
    },
    "PURITY-SITE-TRANSCRIPT-REJECTED": {
        "fields": ("reason", "stage"),
        "relation": "transcriptReasonStageRelationV0",
    },
    "PURITY-SITE-TRANSCRIPT-VALIDATED": {
        "fields": ("stage",),
        "relation": "transcriptReasonStageRelationV0",
    },
}


def _enum_domain(terminal: LogicalTerminal) -> tuple[str, ...]:
    domains = {
        tuple(node["enum"])
        for node in terminal.nodes
        if isinstance(node.get("enum"), list)
        and all(isinstance(value, str) for value in node["enum"])
    }
    if len(domains) != 1:
        raise SemanticACV049Error("ACV-049 enum domain is ambiguous")
    domain = next(iter(domains))
    if not domain or len(set(domain)) != len(domain):
        raise SemanticACV049Error("ACV-049 enum domain is malformed")
    return domain


def _acv049_reserved_enum_values(
    terminal: LogicalTerminal,
    logical_path: str,
    relations: dict[str, Any],
    semantics: dict[str, Any],
) -> tuple[frozenset[str], tuple[str, ...]]:
    """Derive the exact V27 rule-4 exclusions used by current Phase A."""

    domain = set(_enum_domain(terminal))
    reserved: set[str] = set()
    evidence: set[str] = set()
    for row in relations.get("candidateEvaluationPrimaryRelationV0", []):
        if (
            isinstance(row, dict)
            and row.get("reachability") == "RESERVED_UNREACHABLE_V0"
            and row.get("primary") in domain
        ):
            reserved.add(row["primary"])
            evidence.add(str(row.get("id")))
    if logical_path.endswith("/referenceVerification") and "REJECTED" in domain:
        reserved.add("REJECTED")
        evidence.add("ACV-066:referenceVerification=REJECTED")
    for rule in semantics.get("rules", []):
        if not isinstance(rule, dict):
            continue
        parameters = rule.get("parameters")
        if not isinstance(parameters, dict):
            continue
        values: list[Any] = []
        if "reservedValue" in parameters:
            values.append(parameters["reservedValue"])
        if isinstance(parameters.get("reservedValues"), list):
            values.extend(parameters["reservedValues"])
        if "RESERVED" in str(rule.get("rule", "")) and "primary" in parameters:
            values.append(parameters["primary"])
        selected = {value for value in values if isinstance(value, str)} & domain
        if selected:
            reserved.update(selected)
            evidence.add(str(rule.get("id")))
    return frozenset(reserved), tuple(sorted(evidence))


def _relation_row_value(site_id: str, row: dict[str, Any], field: str) -> str:
    if site_id in {"PURITY-SITE-CANDIDATE-TERMINAL", "PURITY-SITE-RECORD-OUTCOME",
                   "PURITY-SITE-REPLAY-CANDIDATE-TERMINAL"} and field == "stage":
        value = row.get("existingO10Stage")
    elif site_id == "PURITY-SITE-RECORD-OUTCOME" and field in {"disposition", "primaryOnCommit"}:
        value = row.get("primary")
    else:
        value = row.get(field)
    if not isinstance(value, str):
        raise SemanticACV049Error("ACV-049 relation tuple field is not a string")
    return value


def _relation_rows_for_response(
    site_id: str,
    response: dict[str, Any],
    relations: dict[str, Any],
) -> tuple[str, tuple[str, ...], list[dict[str, Any]], dict[str, Any]]:
    spec = _ACV049_RELATION_SITE_SPECS.get(site_id)
    if spec is None:
        raise SemanticACV049Error("ACV-049 relation site is not ratified")
    relation_name = str(spec["relation"])
    fields = tuple(spec["fields"])
    source_rows = relations.get(relation_name)
    if not isinstance(source_rows, list) or not source_rows:
        raise SemanticACV049Error("ACV-049 owning relation is malformed")
    operation = response.get("operation")
    result = response.get("result")
    if not isinstance(result, dict):
        raise SemanticACV049Error("ACV-049 relation response result is malformed")
    if site_id == "PURITY-SITE-RECORD-OUTCOME":
        rows = [row for row in source_rows if row.get("reachability") == "REACHABLE"
                and row.get("kRetentionEffect") == "RETAIN_NEW"
                and row.get("coreResultKind") == "PROPOSAL_READY"]
        observed = {}
    elif site_id == "PURITY-SITE-REPLAY-CANDIDATE-TERMINAL":
        rows = [row for row in source_rows if row.get("reachability") == "REACHABLE"
                and row.get("coreResultKind") == "TERMINAL_NO_SUCCESSOR"]
        observed = {"primary": result.get("primary"), "stage": result.get("stage")}
    elif site_id == "PURITY-SITE-CANDIDATE-TERMINAL":
        branch = result.get("evaluation")
        if not isinstance(branch, dict):
            raise SemanticACV049Error("ACV-049 candidate relation branch is absent")
        branch_kind = branch.get("kind")
        rows = [
            row for row in source_rows
            if row.get("reachability") == "REACHABLE"
            and row.get("coreResultKind") == branch_kind
        ]
        observed = {
            "primary": branch.get("primary"),
            "stage": branch.get("stage"),
        }
    elif site_id == "PURITY-SITE-CONTENT-STATE-AXIS":
        rows = [
            row for row in source_rows
            if row.get("reachability") == "REACHABLE"
            and operation in row.get("reachableOperations", [])
        ]
        observed = {}
    else:
        branch_kind = result.get("kind")
        rows = [
            row for row in source_rows
            if row.get("reachability") == "REACHABLE"
            and row.get("kind") == branch_kind
        ]
        observed = {"reason": result.get("reason"), "stage": result.get("stage")}
    if (
        not rows
        or any(not isinstance(row, dict) or not isinstance(row.get("id"), str) for row in rows)
        or [row["id"] for row in rows] != sorted(row["id"] for row in rows)
    ):
        raise SemanticACV049Error("ACV-049 reachable relation rows are malformed")
    baseline_rows = [
        row for row in rows
        if all(_relation_row_value(site_id, row, field) == observed.get(field) for field in fields)
    ] if observed else []
    return relation_name, fields, rows, (
        baseline_rows[0] if len(baseline_rows) == 1 else {}
    )


def _relation_projection_row_id(
    relation_row: dict[str, Any], relations: dict[str, Any]
) -> str:
    relation_id = relation_row["id"]
    if not relation_id.startswith(("GRS-", "TRS-")):
        return "NOT_APPLICABLE"
    projections = [
        row for row in relations.get("terminalPredicateRelationV0", [])
        if isinstance(row, dict) and row.get("relationRowId") == relation_id
    ]
    if len(projections) != 1 or projections[0].get("result") != {
        key: relation_row.get(key)
        for key in ("kind", "reason", "stage", "reachability")
    }:
        raise SemanticACV049Error("ACV-049 terminal-predicate projection drift")
    projection_id = projections[0].get("id")
    if not isinstance(projection_id, str):
        raise SemanticACV049Error("ACV-049 terminal-predicate identity drift")
    return projection_id


def build_phase_a_enum_tuple_source_mutant_manifest(
    repo_root: Path,
    contract: Path,
    evidence_root: Path,
    *,
    source_site_map: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Freeze all Phase-A enum and relation-tuple source mutations."""

    authority = ContractAuthority.load(repo_root, contract)
    _inventory, _inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    site_map = (
        derive_phase_a_source_site_map(repo_root, contract, evidence_root)
        if source_site_map is None
        else copy.deepcopy(source_site_map)
    )
    if (
        site_map.get("schema")
        != "styx.app-core-iface0.acv049-source-site-map.v1"
        or site_map.get("verdict") != "PHASE_A_SOURCE_SITE_MAP_PASS"
        or site_map.get("routeCount") != 596
        or not isinstance(site_map.get("routes"), list)
    ):
        raise SemanticACV049Error("ACV-049 source-site map is not final")
    request_rows = {
        case_id: (value, raw)
        for case_id, (value, raw) in carriers.items()
        if case_id.startswith("PCR-REQUEST-")
    }
    oracle_by_request = {
        dumps(case.request): case.collision_oracle
        for case in _semantic_request_carriers(authority)
        if case.collision_oracle is not None
    }
    responses: dict[str, dict[str, Any]] = {}
    for case_id, (request, raw) in request_rows.items():
        response = _evaluate_fixture_request(authority, request, oracle_by_request.get(raw))
        validate_response_before_release(authority, response)
        responses[case_id] = response
    relations = json.loads(
        (contract / "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json").read_text(
            encoding="utf-8"
        )
    )
    semantics = json.loads(
        (contract / "APP-CORE-IFACE-0-SEMANTIC-CONSTRAINTS-CANDIDATE.json").read_text(
            encoding="utf-8"
        )
    )
    tuple_constructions = site_map.get("ownershipRevision") == "V33_TUPLE_CONSTRUCTIONS"
    enum_routes: list[tuple[dict[str, Any], str, LogicalTerminal]] = []
    for route in site_map["routes"]:
        logical_path = _raw_report_logical_path(route["logicalPath"])
        terminal = resolve_logical_terminal(authority.schema, logical_path)
        if any("enum" in node for node in terminal.nodes):
            enum_routes.append((route, logical_path, terminal))
    if len(enum_routes) != 212:
        raise SemanticACV049Error("ACV-049 Phase-A enum route count drift")

    relation_groups: dict[tuple[str, str, str], list[tuple[dict[str, Any], str, LogicalTerminal]]] = {}
    ordinary = []
    o08_bound_candidates: list[dict[str, Any]] = []
    capability_dimensions = frozenset(authority.capability_requirements())
    for route, logical_path, terminal in enum_routes:
        tokens = terminal.data_tokens
        if (
            len(tokens) == 5
            and tokens[:3] == ("result", "descriptor", "capabilityRequirements")
            and tokens[3] in capability_dimensions
            and tokens[4] in {"comparison", "unit"}
        ):
            selectors = route.get("sourceSelectors")
            pointers = route.get("concretePointers")
            if (
                not isinstance(selectors, list) or len(selectors) != 1
                or not isinstance(pointers, list) or len(pointers) != 1
                or route.get("astSiteIds") != [selectors[0].get("astSiteId")]
            ):
                raise SemanticACV049Error(
                    "ACV-049 enum O-08-bound selector is not exact"
                )
            dimension = str(tokens[3])
            field = str(tokens[4])
            baseline = _value_at_report_pointer(
                responses[route["requestCaseId"]], pointers[0]
            )
            envelope_row = authority.resource_envelope.get("entries", {}).get(
                dimension
            )
            alternatives = sorted(
                set(_enum_domain(terminal)) - {baseline},
                key=lambda value: value.encode("utf-8"),
            )
            if (
                not isinstance(baseline, str)
                or not isinstance(envelope_row, dict)
                or envelope_row.get(field) != baseline
                or not alternatives
            ):
                raise SemanticACV049Error(
                    "ACV-049 enum O-08 envelope binding drift"
                )
            o08_bound_candidates.append(
                {
                    "astSiteId": selectors[0]["astSiteId"],
                    "baselineValue": baseline,
                    "candidateDisposition": "O08_BOUND",
                    "concretePointer": selectors[0]["concretePointer"],
                    "dimension": dimension,
                    "evidenceStatus": "PENDING_NEGATIVE_CONTROL",
                    "field": field,
                    "logicalPath": route["logicalPath"],
                    "requestCaseId": route["requestCaseId"],
                    "schemaAdmissibleAlternativeValues": alternatives,
                    "sourceSiteMapRouteSha256": sha256_bytes(dumps(route)),
                }
            )
            continue
        if route["siteId"] in _ACV049_RELATION_SITE_SPECS:
            relation_groups.setdefault(
                (route["siteId"], route["requestCaseId"], route["faultContext"]), []
            ).append((route, logical_path, terminal))
        else:
            ordinary.append((route, logical_path, terminal))

    mutants: list[dict[str, Any]] = []
    residuals: list[dict[str, Any]] = []
    covered_routes = len(o08_bound_candidates)
    for route, logical_path, terminal in ordinary:
        selectors = route.get("sourceSelectors")
        pointers = route.get("concretePointers")
        if (
            not isinstance(selectors, list) or len(selectors) != 1
            or not isinstance(pointers, list) or len(pointers) != 1
            or route.get("astSiteIds") != [selectors[0].get("astSiteId")]
        ):
            raise SemanticACV049Error("ACV-049 enum source selector is not exact")
        baseline = _value_at_report_pointer(
            responses[route["requestCaseId"]], pointers[0]
        )
        if not isinstance(baseline, str):
            raise SemanticACV049Error("ACV-049 enum baseline is not a string")
        reserved, reserved_evidence = _acv049_reserved_enum_values(
            terminal, logical_path, relations, semantics
        )
        plan = _derive_schema_candidate_pair(
            authority.schema, terminal, baseline, ACV049_MUTANT_CHANNELS,
            reserved_values=reserved,
        )
        core = {
            "candidateValues": plan["candidateValues"],
            "domainClass": "ENUM",
            "faultContext": route["faultContext"],
            "kind": "ORDINARY_ENUM",
            "logicalPaths": [route["logicalPath"]],
            "patches": [{
                "astSiteId": selectors[0]["astSiteId"],
                "candidateValues": plan["candidateValues"],
                "concretePointer": selectors[0]["concretePointer"],
                "field": _logical_data_pattern(logical_path)[-1],
                "relativeTokens": selectors[0]["relativeTokens"],
            }],
            "requestCaseId": route["requestCaseId"],
            "reservedEvidence": list(reserved_evidence),
            "reservedValues": sorted(reserved),
            "routeClass": route["routeClass"],
            "siteId": route["siteId"],
            "sourceSiteMapRouteSha256s": [sha256_bytes(dumps(route))],
            "twoStateRule": plan["twoStateRule"],
        }
        if plan["evidenceDisposition"] == "RELATION_SINGLETON":
            residuals.append({
                **core,
                "evidenceDisposition": "RELATION_SINGLETON",
                "schema": "styx.app-core-iface0.acv049-enum-tuple-residual.v1",
            })
        else:
            mutants.append({
                **core,
                "mutantId": "ACV049-P-ENUM-" + sha256_bytes(dumps(core))[:24].upper(),
                "schema": "styx.app-core-iface0.acv049-enum-tuple-mutant-spec.v1",
            })
        covered_routes += 1

    for (site_id, request_case_id, fault_context), group in sorted(
        relation_groups.items(), key=lambda item: dumps(list(item[0]))
    ):
        response = responses[request_case_id]
        relation_name, fields, rows, baseline_row = _relation_rows_for_response(
            site_id, response, relations
        )
        if tuple_constructions:
            owners = {owner for route, _path, _terminal in group for owner in route["astSiteIds"]}
            if len(owners) != 1:
                raise SemanticACV049Error("ACV-049 coupled tuple has no unique actual construction")
            if site_id == "PURITY-SITE-RECORD-OUTCOME" and any(
                _logical_data_pattern(path)[-1] == "primaryOnCommit" for _route, path, _terminal in group
            ):
                fields = (*fields, "primaryOnCommit")
        observed = {}
        route_by_field = {}
        for route, logical_path, _terminal in group:
            field = _logical_data_pattern(logical_path)[-1]
            if field not in fields or field in route_by_field:
                raise SemanticACV049Error("ACV-049 coupled relation field drift")
            route_by_field[field] = (route, logical_path)
            observed[field] = _value_at_report_pointer(
                response, route["concretePointers"][0]
            )
        if site_id in {"PURITY-SITE-CONTENT-STATE-AXIS", "PURITY-SITE-RECORD-OUTCOME"}:
            matches = [
                row for row in rows
                if all(_relation_row_value(site_id, row, field) == observed[field] for field in fields)
            ]
            baseline_row = matches[0] if len(matches) == 1 else {}
        if not baseline_row or set(route_by_field) != set(fields):
            raise SemanticACV049Error("ACV-049 coupled baseline row is not unique")
        alternatives = [row for row in rows if row["id"] != baseline_row["id"]]
        if not alternatives:
            residuals.append({
                "baselineRelationRowId": baseline_row["id"],
                "evidenceDisposition": "RELATION_SINGLETON",
                "faultContext": fault_context,
                "kind": "RELATION_TUPLE",
                "logicalPaths": sorted(route["logicalPath"] for route, _p, _t in group),
                "owningRelation": relation_name,
                "releaseDetector": "validate_response_before_release",
                "requestCaseId": request_case_id,
                "schema": "styx.app-core-iface0.acv049-enum-tuple-residual.v1",
                "siteId": site_id,
                "sourceSiteMapRouteSha256s": sorted(
                    sha256_bytes(dumps(route)) for route, _p, _t in group
                ),
            })
            covered_routes += len(group)
            continue
        selected_rows = alternatives[:2]
        two_state = len(selected_rows) == 1
        if two_state:
            selected_rows.append(baseline_row)
        patches = []
        for field in fields:
            route, _logical_path = route_by_field[field]
            selectors = route.get("sourceSelectors")
            if not isinstance(selectors, list) or len(selectors) != 1:
                raise SemanticACV049Error("ACV-049 coupled source selector is not exact")
            patches.append({
                "astSiteId": selectors[0]["astSiteId"],
                "candidateValues": [
                    _relation_row_value(site_id, row, field) for row in selected_rows
                ],
                "concretePointer": selectors[0]["concretePointer"],
                "field": field,
                "relativeTokens": selectors[0]["relativeTokens"],
            })
        core = {
            "baselineRelationRowId": baseline_row["id"],
            "baselineTerminalPredicateRowId": _relation_projection_row_id(
                baseline_row, relations
            ),
            "candidateRelationRowIds": [row["id"] for row in selected_rows],
            "candidateTerminalPredicateRowIds": [
                _relation_projection_row_id(row, relations) for row in selected_rows
            ],
            "coupledFields": list(fields),
            "faultContext": fault_context,
            "kind": "RELATION_TUPLE",
            "logicalPaths": sorted(route["logicalPath"] for route, _p, _t in group),
            "owningRelation": relation_name,
            "patches": patches,
            "requestCaseId": request_case_id,
            "routeClass": group[0][0]["routeClass"],
            "siteId": site_id,
            "sourceSiteMapRouteSha256s": sorted(
                sha256_bytes(dumps(route)) for route, _p, _t in group
            ),
            "twoStateRule": two_state,
        }
        mutants.append({
            **core,
            "mutantId": "ACV049-P-TUPLE-" + sha256_bytes(dumps(core))[:24].upper(),
            "schema": "styx.app-core-iface0.acv049-enum-tuple-mutant-spec.v1",
        })
        covered_routes += len(group)

    mutants.sort(key=lambda row: row["mutantId"])
    residuals.sort(key=lambda row: dumps(row))
    ordinary_count = sum(row["kind"] == "ORDINARY_ENUM" for row in mutants)
    relation_count = sum(row["kind"] == "RELATION_TUPLE" for row in mutants)
    if (
        (not tuple_constructions and (
            len(relation_groups) != 35 or len(ordinary) != 124
            or ordinary_count != 124 or relation_count != 34
        ))
        or len(residuals) != 1
        or len(o08_bound_candidates) != 10
        or {
            (row["dimension"], row["field"])
            for row in o08_bound_candidates
        }
        != {
            (dimension, field)
            for dimension in capability_dimensions
            for field in ("comparison", "unit")
        }
        or residuals[0].get("siteId") != "PURITY-SITE-TRANSCRIPT-VALIDATED"
        or covered_routes != 212
    ):
        raise SemanticACV049Error("ACV-049 enum/tuple manifest closure drift")
    mutant_ids = [row["mutantId"] for row in mutants]
    return {
        **({"ownershipRevision": "V33_TUPLE_CONSTRUCTIONS"} if tuple_constructions else {}),
        "coveredEnumRouteCount": covered_routes,
        "enumRouteCount": len(enum_routes),
        "mutantCount": len(mutants),
        "mutantSetSha256": sha256_bytes(dumps(mutant_ids)),
        "mutants": mutants,
        "o08BoundCandidateCount": len(o08_bound_candidates),
        "o08BoundCandidates": sorted(
            o08_bound_candidates,
            key=lambda row: (row["dimension"], row["field"]),
        ),
        "ordinaryEnumMutantCount": ordinary_count,
        "relationTupleMutantCount": relation_count,
        "relationTupleResidualCount": len(residuals),
        "residuals": residuals,
        "schema": "styx.app-core-iface0.acv049-enum-tuple-source-mutant-manifest.v1",
        "sourceSiteRouteSetSha256": site_map["routeSetSha256"],
        "verdict": "PHASE_A_ENUM_TUPLE_MUTANT_MANIFEST_PASS",
    }


def _validate_scalar_source_mutant_spec(spec: dict[str, Any]) -> None:
    fields = {
        "advanceCounts", "astSiteId", "candidateValues", "concretePointer",
        "domainClass", "faultContext", "logicalPath", "mutantId",
        "relativePointer", "relativeTokens", "requestCaseId", "routeClass",
        "schema", "siteId", "sourceSiteMapRouteSha256", "twoStateRule",
    }
    if (
        not isinstance(spec, dict)
        or set(spec) != fields
        or spec.get("schema")
        != "styx.app-core-iface0.acv049-scalar-source-mutant-spec.v1"
        or not isinstance(spec.get("candidateValues"), list)
        or len(spec["candidateValues"]) != 2
        or any(not isinstance(value, str) for value in spec["candidateValues"])
        or len(set(spec["candidateValues"])) != 2
        or not isinstance(spec.get("relativeTokens"), list)
        or any(not isinstance(token, (str, int)) for token in spec["relativeTokens"])
        or not isinstance(spec.get("advanceCounts"), list)
        or len(spec["advanceCounts"]) != 2
        or any(not isinstance(value, int) or value < 0 for value in spec["advanceCounts"])
        or spec.get("routeClass")
        not in {"ORDINARY_ROUTE", "FAULT_INJECTED_ROUTE"}
        or spec.get("faultContext")
        not in {"NONE", "FIXED_INTERNAL_COLLISION_ORACLE"}
    ):
        raise SemanticACV049Error("ACV-049 scalar mutant spec is malformed")
    core = {key: value for key, value in spec.items() if key not in {"mutantId", "schema"}}
    expected = "ACV049-P-MUTANT-" + sha256_bytes(dumps(core))[:24].upper()
    if spec["mutantId"] != expected:
        raise SemanticACV049Error("ACV-049 scalar mutant identity drift")


def _validate_scalar_source_mutant_manifest(manifest: dict[str, Any]) -> None:
    fields = {
        "mutantCount", "mutantSetSha256", "mutants", "schema",
        "o08BoundCandidateCount", "o08BoundCandidates",
        "pendingGuardedCandidateCount", "pendingGuardedCandidates",
        "skippedEnumRouteCount", "sourceSiteRouteCount",
        "sourceSiteRouteSetSha256", "verdict",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != fields
        or manifest.get("schema")
        != "styx.app-core-iface0.acv049-scalar-source-mutant-manifest.v1"
        or manifest.get("verdict") != "PHASE_A_SCALAR_MUTANT_MANIFEST_PASS"
        or not isinstance(manifest.get("mutants"), list)
        or not isinstance(manifest.get("o08BoundCandidates"), list)
        or not isinstance(manifest.get("pendingGuardedCandidates"), list)
        or manifest.get("mutantCount") != len(manifest["mutants"])
        or manifest.get("o08BoundCandidateCount")
        != len(manifest["o08BoundCandidates"])
        or manifest["o08BoundCandidateCount"] != 5
        or manifest.get("pendingGuardedCandidateCount")
        != len(manifest["pendingGuardedCandidates"])
        or manifest["pendingGuardedCandidateCount"] != 48
        or not isinstance(manifest.get("skippedEnumRouteCount"), int)
        or manifest["skippedEnumRouteCount"] < 0
        or manifest.get("sourceSiteRouteCount")
        != manifest["mutantCount"]
        + manifest["o08BoundCandidateCount"]
        + manifest["pendingGuardedCandidateCount"]
        + manifest["skippedEnumRouteCount"]
        or manifest["sourceSiteRouteCount"] != 596
        or any(
            not isinstance(manifest.get(field), str)
            or len(manifest[field]) != 64
            or any(character not in "0123456789abcdef" for character in manifest[field])
            for field in ("mutantSetSha256", "sourceSiteRouteSetSha256")
        )
    ):
        raise SemanticACV049Error("ACV-049 scalar mutant manifest is malformed")
    for spec in manifest["mutants"]:
        _validate_scalar_source_mutant_spec(spec)
    o08_fields = {
        "astSiteId", "candidateDisposition", "concretePointer", "dimension",
        "evidenceStatus", "logicalPath", "requestCaseId",
        "sourceSiteMapRouteSha256",
    }
    for row in manifest["o08BoundCandidates"]:
        if (
            not isinstance(row, dict)
            or set(row) != o08_fields
            or row.get("candidateDisposition") != "O08_BOUND"
            or row.get("evidenceStatus") != "PENDING_NEGATIVE_CONTROL"
            or any(
                not isinstance(row.get(field), str) or not row[field]
                for field in o08_fields
            )
        ):
            raise SemanticACV049Error(
                "ACV-049 O-08-bound candidate manifest is malformed"
            )
    if len({row["dimension"] for row in manifest["o08BoundCandidates"]}) != 5:
        raise SemanticACV049Error("ACV-049 O-08-bound candidate set drift")
    guarded_fields = {
        "astSiteId", "candidateDisposition", "concretePointer", "guard",
        "logicalPath", "requestCaseId", "sourceSiteMapRouteSha256",
    }
    for row in manifest["pendingGuardedCandidates"]:
        if (
            not isinstance(row, dict)
            or set(row) != guarded_fields
            or row.get("candidateDisposition")
            != "PENDING_CONTRACT_CLASSIFICATION"
            or row.get("guard") != "PRIOR_SNAPSHOT_BYTE_EQUALITY"
            or any(
                not isinstance(row.get(field), str) or not row[field]
                for field in guarded_fields
            )
        ):
            raise SemanticACV049Error(
                "ACV-049 guarded candidate manifest is malformed"
            )
    if (
        len(
            {
                (row["logicalPath"], row["requestCaseId"])
                for row in manifest["pendingGuardedCandidates"]
            }
        )
        != 48
    ):
        raise SemanticACV049Error("ACV-049 guarded candidate set drift")
    mutant_ids = [spec["mutantId"] for spec in manifest["mutants"]]
    if (
        len(set(mutant_ids)) != len(mutant_ids)
        or manifest.get("mutantSetSha256") != sha256_bytes(dumps(mutant_ids))
    ):
        raise SemanticACV049Error("ACV-049 scalar mutant set identity drift")


def _scalar_batch_failure(
    spec: dict[str, Any], stage: str, error: Exception,
) -> dict[str, str]:
    """Preserve the exact scalar failure stage and detector."""

    return {
        "astSiteId": spec["astSiteId"],
        "failureClass": type(error).__name__,
        "failureMessage": str(error),
        "mutantId": spec["mutantId"],
        "requestCaseId": spec["requestCaseId"],
        "stage": stage,
    }


def _execute_scalar_mutant_stages(
    mutated: types.ModuleType,
    mutated_authority: Any,
    request: dict[str, Any],
    oracle: Any,
    spec: dict[str, Any],
) -> tuple[tuple[Any, Any, frozenset[str], frozenset[str]] | None, dict[str, str] | None]:
    """Evaluate twice, then run Python release admission as a distinct stage."""

    try:
        mutated._acv049_mutated_sites_executed.clear()
        first = _evaluate_fixture_request(mutated_authority, request, oracle)
        first_executed_sites = frozenset(mutated._acv049_mutated_sites_executed)
        mutated._acv049_mutated_sites_executed.clear()
        second = _evaluate_fixture_request(mutated_authority, request, oracle)
        second_executed_sites = frozenset(mutated._acv049_mutated_sites_executed)
    except Exception as error:
        return None, _scalar_batch_failure(spec, "evaluation", error)
    try:
        mutated.validate_response_before_release(mutated_authority, first)
        mutated.validate_response_before_release(mutated_authority, second)
    except Exception as error:
        return None, _scalar_batch_failure(spec, "python_release_admission", error)
    return (first, second, first_executed_sites, second_executed_sites), None


def execute_scalar_source_mutant_batch(
    repo_root: Path,
    contract: Path,
    evidence_root: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Execute every scalar route in one channel-bound evidence process."""

    _validate_scalar_source_mutant_manifest(manifest)
    expected_manifest = build_phase_a_scalar_source_mutant_manifest(
        repo_root, contract, evidence_root
    )
    if dumps(expected_manifest) != dumps(manifest):
        raise SemanticACV049Error("ACV-049 scalar mutant manifest is stale")
    authority = ContractAuthority.load(repo_root, contract)
    _inventory, _inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    request_rows = {
        case_id: (value, raw)
        for case_id, (value, raw) in carriers.items()
        if case_id.startswith("PCR-REQUEST-")
    }
    if len(request_rows) != 77:
        raise SemanticACV049Error("ACV-049 scalar batch request set drift")
    oracle_by_request = {
        dumps(case.request): case.collision_oracle
        for case in _semantic_request_carriers(authority)
        if case.collision_oracle is not None
    }
    instrumented, ast_sites = _instrumented_interface_model(repo_root)
    previous = sys.modules.get("interface_model")
    sys.modules["interface_model"] = instrumented
    tagged_responses: dict[str, dict[str, Any]] = {}
    try:
        instrumented_authority = instrumented.ContractAuthority.load(
            repo_root, contract
        )
        for case_id, (request, raw) in request_rows.items():
            response = _evaluate_fixture_request(
                instrumented_authority, request, oracle_by_request.get(raw)
            )
            instrumented.validate_response_before_release(
                instrumented_authority, response
            )
            tagged_responses[case_id] = response
    finally:
        if previous is None:
            sys.modules.pop("interface_model", None)
        else:
            sys.modules["interface_model"] = previous

    module_cache: dict[
        bytes, tuple[types.ModuleType, Any, str]
    ] = {}
    terminal_cache: dict[str, LogicalTerminal] = {}
    admission_failures: list[dict[str, str]] = []
    execution_failures: list[dict[str, str]] = []
    rows: list[dict[str, Any]] = []
    for spec in manifest["mutants"]:
        request, request_bytes = request_rows[spec["requestCaseId"]]
        oracle = oracle_by_request.get(request_bytes)
        expected_fault = (
            "FIXED_INTERNAL_COLLISION_ORACLE" if oracle is not None else "NONE"
        )
        if spec["faultContext"] != expected_fault:
            raise SemanticACV049Error("ACV-049 scalar batch fault-context drift")
        logical_path = _raw_report_logical_path(spec["logicalPath"])
        terminal = terminal_cache.setdefault(
            logical_path,
            resolve_logical_terminal(authority.schema, logical_path),
        )
        baseline_response = tagged_responses[spec["requestCaseId"]]
        source_values = _pattern_source_values(
            baseline_response, _logical_data_pattern(logical_path)
        )
        selected = [
            value
            for pointer, value, relative in source_values
            if _report_pointer(_json_pointer(pointer)) == spec["concretePointer"]
            and value.site_id == spec["astSiteId"]
            and list(relative) == spec["relativeTokens"]
        ]
        if len(selected) != 1 or spec["astSiteId"] not in ast_sites:
            raise SemanticACV049Error("ACV-049 scalar batch selector did not execute")
        baseline = str(selected[0])
        plan = _derive_schema_candidate_pair(
            authority.schema, terminal, baseline, ACV049_MUTANT_CHANNELS
        )
        for key in (
            "advanceCounts", "candidateValues", "domainClass", "twoStateRule"
        ):
            if spec[key] != plan[key]:
                raise SemanticACV049Error("ACV-049 scalar batch candidate drift")
        module_key = dumps(
            {
                "astSiteId": spec["astSiteId"],
                "candidateValues": spec["candidateValues"],
                "relativeTokens": spec["relativeTokens"],
            }
        )
        cached = module_cache.get(module_key)
        if cached is None:
            mutated, _mutant_sites, mutant_source = _mutated_interface_model(
                repo_root,
                {
                    spec["astSiteId"]: (
                        (
                            tuple(spec["relativeTokens"]),
                            tuple(spec["candidateValues"]),
                        ),
                    )
                },
                ACV049_MUTANT_CHANNELS,
            )
            previous = sys.modules.get("interface_model")
            sys.modules["interface_model"] = mutated
            try:
                mutated_authority = mutated.ContractAuthority.load(
                    repo_root, contract
                )
            finally:
                if previous is None:
                    sys.modules.pop("interface_model", None)
                else:
                    sys.modules["interface_model"] = previous
            cached = (
                mutated,
                mutated_authority,
                sha256_bytes(mutant_source),
            )
            module_cache[module_key] = cached
        mutated, mutated_authority, mutant_source_sha256 = cached
        previous = sys.modules.get("interface_model")
        sys.modules["interface_model"] = mutated
        try:
            staged_result, staged_failure = _execute_scalar_mutant_stages(
                mutated, mutated_authority, request, oracle, spec
            )
            if staged_failure is not None:
                admission_failures.append(staged_failure)
                continue
            if staged_result is None:
                raise SemanticACV049Error(
                    "ACV-049 scalar batch stage result drift"
                )
            first, second, first_executed_sites, second_executed_sites = staged_result
        finally:
            if previous is None:
                sys.modules.pop("interface_model", None)
            else:
                sys.modules["interface_model"] = previous
        try:
            if first_executed_sites != {spec["astSiteId"]} or (
                second_executed_sites != {spec["astSiteId"]}
            ):
                raise SemanticACV049Error(
                    "ACV-049 scalar batch mutant site did not execute exactly"
                )
            if dumps(first) != dumps(second):
                raise SemanticACV049Error(
                    "ACV-049 scalar batch mutant is nondeterministic"
                )
            observed = _value_at_report_pointer(first, spec["concretePointer"])
            if observed not in spec["candidateValues"] or observed == baseline:
                raise SemanticACV049Error(
                    "ACV-049 scalar batch target did not change"
                )
            normalized = copy.deepcopy(first)
            _set_value_at_report_pointer(
                normalized, spec["concretePointer"], baseline
            )
            if dumps(normalized) != dumps(baseline_response):
                raise SemanticACV049Error(
                    "ACV-049 scalar batch changed multiple targets"
                )
        except (KeyError, SemanticACV049Error) as error:
            execution_failures.append(
                _scalar_batch_failure(spec, "execution", error)
            )
            continue
        rows.append(
            {
                "baselineResponseSha256": sha256_bytes(dumps(baseline_response)),
                "mutantId": spec["mutantId"],
                "mutantSourceSha256": mutant_source_sha256,
                "observedCandidateIndex": spec["candidateValues"].index(observed),
                "requestCaseId": spec["requestCaseId"],
                "requestSha256": sha256_bytes(request_bytes),
                "response": first,
                "responseSha256": sha256_bytes(dumps(first)),
                "sourceSiteExecuted": True,
            }
        )
    if (
        len(rows) + len(admission_failures) + len(execution_failures)
        != manifest["mutantCount"]
    ):
        raise SemanticACV049Error("ACV-049 scalar batch result count drift")
    return {
        "admissionFailureCount": len(admission_failures),
        "admissionFailures": admission_failures,
        "executionFailureCount": len(execution_failures),
        "executionFailures": execution_failures,
        "moduleCount": len(module_cache),
        "mutantSetSha256": manifest["mutantSetSha256"],
        "passedMutantCount": len(rows),
        "rows": rows,
        "scheduledMutantCount": manifest["mutantCount"],
        "schema": "styx.app-core-iface0.acv049-scalar-source-mutant-batch.v1",
        "verdict": (
            "PYTHON_RELEASE_SCALAR_MUTANT_BATCH_PASS"
            if not admission_failures and not execution_failures
            else "PYTHON_RELEASE_SCALAR_MUTANT_BATCH_FAIL"
        ),
    }


def bind_v33_closed_routes(
    appendix_a: list[dict[str, Any]], appendix_b: list[dict[str, Any]],
    source_map: dict[str, Any], *, p_path_count: int = 300,
) -> list[dict[str, Any]]:
    """Bind immutable obligations, without converting a binding into a kill."""
    for rows, count, digest in (
        (appendix_a, 12, "2f624c5dbdc02a1bbad59e8049066b1f83bc5802bd321a511a746d52604c3694"),
        (appendix_b, 36, "43bf4e9119db75b3a0fc537c2f22aa3411acb7d0114ad77f407332bb194210e9"),
    ):
        if len(rows) != count or sha256_bytes(dumps(rows)) != digest:
            raise SemanticACV049Error("V33 historical closed route identities changed")
    if (p_path_count != 300 or source_map.get("ownershipRevision") != "V33_TUPLE_CONSTRUCTIONS"
            or source_map.get("routeCount") != 596 or len(source_map.get("routes", [])) != 596
            or sha256_bytes(dumps(source_map["routes"])) != source_map.get("routeSetSha256")
            or source_map["materializedMutablePathCount"] + source_map["pendingSupplementaryMutablePathCount"] != p_path_count):
        raise SemanticACV049Error("V33 closed source-map invariants changed")
    members = {member["siteId"]: member for site in source_map["usedSites"] for member in site["astMembers"]}
    result = []
    seen = set()
    for eligible, rows in ((True, appendix_a), (False, appendix_b)):
        for historical in rows:
            identity = (historical["requestCaseId"], historical["concretePointer"])
            matches = [route for route in source_map["routes"]
                       if route["requestCaseId"] == identity[0] and identity[1] in route["concretePointers"]]
            if identity in seen or len(matches) != 1:
                raise SemanticACV049Error("V33 historical-to-current mapping is not bijective")
            seen.add(identity)
            route = matches[0]
            selectors = [item for item in route["sourceSelectors"] if item["concretePointer"] == identity[1]]
            if len(selectors) != 1 or selectors[0]["astSiteId"] not in members:
                raise SemanticACV049Error("V33 source ownership is missing or ambiguous")
            selector = selectors[0]
            owner = members[selector["astSiteId"]]
            if (owner["function"] == "_revalidate_prior_snapshot"
                    or len(owner.get("sourceExpressionSha256", "")) != 64
                    or any(type(token) not in (str, int) for token in selector["relativeTokens"])):
                raise SemanticACV049Error("V33 output ownership is unproved or reconstruction-only")
            result.append({
                "historical": copy.deepcopy(historical), "residualEligible": eligible,
                "currentRouteSha256": sha256_bytes(dumps(route)),
                "logicalPath": route["logicalPath"], "selector": copy.deepcopy(selector),
                "source": copy.deepcopy(owner), "disposition": "PENDING_CONTRACT_CLASSIFICATION",
            })
    return result


def freeze_v33_recurrence_bindings(
    appendix_c: list[dict[str, Any]], bound: list[dict[str, Any]], source_map: dict[str, Any],
    schema: dict[str, Any], baselines: dict[str, dict[str, Any]],
) -> bytes:
    """Freeze the exact replay sibling and recipe, not a residual disposition."""
    if (len(appendix_c) != 12 or sha256_bytes(dumps(appendix_c)) !=
            "0c95af1749c2adc1d850f281450ab4f4548e9c7169a00c05b23ea34a91f3811e"):
        raise SemanticACV049Error("V33 exact Appendix C binding changed")
    rebuilt = bind_v33_closed_routes(
        [row["historical"] for row in bound if row["residualEligible"]],
        [row["historical"] for row in bound if not row["residualEligible"]], source_map,
    )
    if dumps(rebuilt) != dumps(bound):
        raise SemanticACV049Error("V33 closed binding changed after derivation")
    plans = []
    members = {member["siteId"]: member for site in source_map["usedSites"] for member in site["astMembers"]}
    for obligation in appendix_c:
        targets = [row for row in bound if row["historical"] == obligation["target"] and row["residualEligible"]]
        sibling = obligation["sibling"]
        siblings = [row for row in source_map["routes"] if row["requestCaseId"] == sibling["requestCaseId"]
                    and sibling["concretePointer"] in row["concretePointers"]]
        if len(targets) != 1 or len(siblings) != 1:
            raise SemanticACV049Error("V33 target or exact replay sibling is missing")
        target, replay_route = targets[0], siblings[0]
        selectors = [row for row in replay_route["sourceSelectors"] if row["concretePointer"] == sibling["concretePointer"]]
        if len(selectors) != 1:
            raise SemanticACV049Error("V33 replay sibling selector is ambiguous")
        selector = selectors[0]
        source = target["source"]
        if (selector["astSiteId"] != obligation["historicalSiblingAstSiteId"]
                or target["selector"]["astSiteId"] != selector["astSiteId"]
                or target["selector"]["relativeTokens"] != obligation["relativeTokens"]
                or selector["relativeTokens"] != obligation["relativeTokens"]
                or members[selector["astSiteId"]]["sourceExpressionSha256"] != source["sourceExpressionSha256"]
                or source["function"] not in {"_assemble_context_projection", "_credential_projection"}):
            raise SemanticACV049Error("V33 actual source/selector mapping requires structural proof")
        target_case = target["historical"]["requestCaseId"]
        if target_case not in baselines or sibling["requestCaseId"] not in baselines:
            raise SemanticACV049Error("V33 successful baseline successor coverage is absent")
        target_baseline = _value_at_report_pointer(baselines[target_case], target["historical"]["concretePointer"])
        sibling_baseline = _value_at_report_pointer(baselines[sibling["requestCaseId"]], sibling["concretePointer"])
        terminal = resolve_logical_terminal(schema, _raw_report_logical_path(target["logicalPath"]))
        pair = _derive_schema_candidate_pair(schema, terminal, target_baseline, ACV049_MUTANT_CHANNELS)
        candidates = pair["candidateValues"]
        if pair["twoStateRule"] or len(set(candidates)) != 2 or any(value in candidates for value in (target_baseline, sibling_baseline)):
            raise SemanticACV049Error("V33 recurrence cannot use baseline-equivalent candidates")
        plans.append({
            "target": copy.deepcopy(target), "sibling": copy.deepcopy(sibling),
            "siblingCurrentRouteSha256": sha256_bytes(dumps(replay_route)),
            "astSiteId": selector["astSiteId"], "relativeTokens": copy.deepcopy(selector["relativeTokens"]),
            "candidateValues": candidates, "twoStateRule": False,
            "channels": list(ACV049_MUTANT_CHANNELS),
            "targetBaselineSha256": sha256_bytes(dumps(baselines[target_case])),
            "siblingBaselineSha256": sha256_bytes(dumps(baselines[sibling["requestCaseId"]])),
        })
    return dumps(plans)


def _retained_leaf_bytes(value: Any, tokens: tuple[str | int, ...]) -> dict[str, bytes]:
    if isinstance(value, dict) and value:
        return {pointer: raw for key in sorted(value)
                for pointer, raw in _retained_leaf_bytes(value[key], (*tokens, key)).items()}
    if isinstance(value, list) and value:
        return {pointer: raw for index, item in enumerate(value)
                for pointer, raw in _retained_leaf_bytes(item, (*tokens, index)).items()}
    return {_report_pointer(_json_pointer(tokens)): dumps(value)}


_V34_IDENTITY_TARGET_REQUEST_SHA256 = (
    "ef56560cff4b25b1dd66450ad0f3a4db0d90e62dd2b143e931d9955d39bff91a"
)
_V34_IDENTITY_TARGET_REQUEST_CASE_ID = "PCR-REQUEST-EVALUATE-EVIDENCE-UPDATE-0028"
_V34_IDENTITY_TARGET_HISTORICAL_ROUTE_SHA256 = (
    "ad8bdf499daa48a5fd341445357653f6859d5a8955204127e8162c7f9e69a6e8"
)
_V34_IDENTITY_TARGET_POINTER = (
    "JSON_POINTER:result%2Fevaluation%2Fproposal%2Fsuccessor%2FlogicalEvents%2F0%2FeventReferenceHex"
)


def _v34_positional_identity_bindings(
    request: dict[str, Any], expected: dict[str, Any], target_pointers: tuple[str, ...],
) -> list[dict[str, Any]]:
    if _V34_IDENTITY_TARGET_POINTER not in target_pointers:
        return []
    if (
        target_pointers != (_V34_IDENTITY_TARGET_POINTER,)
        or request["operation"] != "EVALUATE_EVIDENCE_UPDATE"
        or sha256_bytes(dumps(request)) != _V34_IDENTITY_TARGET_REQUEST_SHA256
    ):
        raise SemanticACV049Error("V34 identity-target binding is outside Appendix S")
    prior_rows = request["input"]["prior"]["logicalEvents"]
    expected_rows = expected["logicalEvents"]
    if len(prior_rows) != 1 or len(expected_rows) != 1:
        raise SemanticACV049Error("V34 identity-target binding requires one logical event")
    prior_identity = prior_rows[0].get("eventReferenceHex")
    if (
        not isinstance(prior_identity, str)
        or expected_rows[0].get("eventReferenceHex") != prior_identity
    ):
        raise SemanticACV049Error("V34 identity-target prior binding drift")
    return [{
        "canonicalPosition": 0,
        "collectionPath": ["logicalEvents"],
        "priorIdentity": prior_identity,
        "targetPointer": _V34_IDENTITY_TARGET_POINTER,
    }]


def freeze_retained_input_plan(
    authority: ContractAuthority, request: dict[str, Any], *, target_pointers: tuple[str, ...] = (),
) -> bytes:
    """Freeze request-derived E expectations before executing any source mutant."""
    if request["operation"] not in {"EVALUATE_CANDIDATE", "EVALUATE_EVIDENCE_UPDATE"}:
        raise SemanticACV049Error("E retained-input operation is not supported")
    value = request["input"]
    prior = value["prior"]
    projected = _retained_contract._revalidate_prior_snapshot(authority, request["profile"], prior)
    if projected is None:
        raise SemanticACV049Error("E requires successful byte-exact prior revalidation")
    expected = copy.deepcopy({key: prior[key] for key in ("genesis", "logicalEvents", "localRevalidation")})
    if request["operation"] == "EVALUATE_CANDIDATE":
        combined = _retained_contract.project_replay_state(authority, request["profile"], {
            "proposedGenesis": prior["genesis"],
            "presentations": [*_retained_contract._retained_presentations(projected.closure.candidates), value["candidate"]],
            "evidenceAttempts": _retained_contract._internal_evidence_as_attempts(projected.closure.evidence),
        })
        if isinstance(combined, dict):
            raise SemanticACV049Error("E candidate has no admitted closure")
        expected["logicalEvents"] = [candidate.candidate for candidate in combined.closure.candidates]
        expected["localRevalidation"]["retainedProofs"] = [
            {"eventReferenceHex": candidate.reference_hex, "signatureHex": candidate.retained_proof_signature_hex}
            for candidate in combined.closure.candidates
        ]
        expected["localRevalidation"]["evidence"] = _retained_contract._internal_evidence_to_authoritative(combined.closure.evidence)
        # New membership is contract-derived; retained bytes still come from prior.
        for old_rows, new_rows in (
            (prior["logicalEvents"], expected["logicalEvents"]),
            (prior["localRevalidation"]["retainedProofs"], expected["localRevalidation"]["retainedProofs"]),
            (prior["localRevalidation"]["evidence"]["verifiedComplete"], expected["localRevalidation"]["evidence"]["verifiedComplete"]),
        ):
            for retained in old_rows:
                matches = [row for row in new_rows if row["eventReferenceHex"] == retained["eventReferenceHex"]]
                if len(matches) != 1 or dumps(matches[0]) != dumps(retained):
                    raise SemanticACV049Error("E candidate closure does not preserve prior identity and bytes")
    else:
        additions: dict[str, Any] = {"contentMaterial": [], "openingMaterial": []}
        for attempt in sorted(value["additions"], key=dumps):
            raw = _retained_contract._attempt_to_internal_evidence(attempt)
            if raw is None:
                continue
            try:
                verified = _retained_contract._reduce_complete_evidence_attempts(authority, projected.closure.candidates, raw)
            except _retained_contract.EvidenceError:
                continue
            if verified["contentMaterial"]:
                additions, _ = _retained_contract.merge_verified_complete_evidence(additions, verified)
        if not additions["contentMaterial"]:
            raise SemanticACV049Error("E has no contract-permitted evidence addition")
        merged, _ = _retained_contract.merge_verified_complete_evidence(projected.closure.evidence, additions)
        expected["localRevalidation"]["evidence"] = _retained_contract._internal_evidence_to_authoritative(merged)
    prefix = ("result", "evaluation", "proposal", "successor")
    leaves = _retained_leaf_bytes(expected, prefix)
    if len(target_pointers) != len(set(target_pointers)):
        raise SemanticACV049Error("E duplicate frozen target pointer")
    for pointer in target_pointers:
        if _report_pointer(_raw_report_pointer(pointer)) != pointer:
            raise SemanticACV049Error("E noncanonical frozen target pointer")
        if pointer in leaves and leaves[pointer].startswith((b"{", b"[")):
            raise SemanticACV049Error("E a retained container cannot be a leaf target")
    return dumps({
        "schema": "styx.app-core-iface0.retained-input-plan.v1",
        "experimentalTargetPointers": sorted(target_pointers),
        "positionalIdentityBindings": _v34_positional_identity_bindings(
            request, expected, target_pointers,
        ),
        "operation": request["operation"], "requestSha256": sha256_bytes(dumps(request)),
        "proposalPath": ["result", "evaluation", "proposal", "successor"], "expected": expected,
        "retainedLeafCount": len(_retained_leaf_bytes(
            {key: prior[key] for key in expected}, ("prior",),
        )),
    })


def observe_retained_input(frozen: bytes, response: dict[str, Any]) -> dict[str, Any]:
    """Evidence-only comparison; neither reader receives this plan or result."""
    plan = json.loads(frozen)
    if plan.get("schema") != "styx.app-core-iface0.retained-input-plan.v1":
        raise SemanticACV049Error("E retained-input plan schema drift")
    prefix = tuple(plan["proposalPath"])
    expected = plan["expected"]
    positional_bindings = plan.get("positionalIdentityBindings")
    if not isinstance(positional_bindings, list):
        raise SemanticACV049Error("E retained-input positional binding drift")
    structural: list[str] = []
    differences: list[str] = []
    try:
        proposal = response
        for token in prefix:
            proposal = proposal[token]
        actual = {key: proposal[key] for key in expected}
        collections = [
            ("logicalEvents",), ("localRevalidation", "retainedProofs"),
            ("localRevalidation", "evidence", "verifiedComplete"),
        ]
        for path in collections:
            left, right = expected, actual
            for token in path:
                left, right = left[token], right[token]
            expected_ids = [row["eventReferenceHex"] for row in left]
            actual_ids = [row["eventReferenceHex"] for row in right]
            bindings = [
                binding for binding in positional_bindings
                if binding.get("collectionPath") == list(path)
            ]
            qualified = False
            if len(bindings) == 1:
                binding = bindings[0]
                position = binding.get("canonicalPosition")
                qualified = (
                    path == ("logicalEvents",)
                    and position == 0
                    and binding.get("targetPointer") == _V34_IDENTITY_TARGET_POINTER
                    and len(expected_ids) == len(actual_ids) == 1
                    and expected_ids[0] == binding.get("priorIdentity")
                    and actual_ids == sorted(set(actual_ids))
                )
            if (
                expected_ids != sorted(set(expected_ids))
                or (not qualified and actual_ids != expected_ids)
                or len(bindings) > 1
                or (bindings and not qualified)
            ):
                structural.append(_report_pointer(_json_pointer((*prefix, *path))))
        before = _retained_leaf_bytes(expected, prefix)
        after = _retained_leaf_bytes(actual, prefix)
        differences = sorted(pointer for pointer in before.keys() | after.keys()
                             if before.get(pointer) != after.get(pointer))
        if before.keys() != after.keys():
            structural.append(_report_pointer(_json_pointer(prefix)))
    except (KeyError, TypeError, ValueError):
        structural.append(_report_pointer(_json_pointer(prefix)))
    targets = sorted(set(differences) & set(plan["experimentalTargetPointers"]))
    off_target = sorted(set(differences) - set(targets))
    return {
        "offTargetDifferences": off_target, "targetDifferences": targets,
        "structuralDifferences": sorted(set(structural)),
        "retainedLeafCount": plan["retainedLeafCount"],
        "verdict": (
            "RETAINED_INPUT_FAIL" if off_target or structural else
            "RETAINED_OFF_TARGET_PASS_TARGET_EXPERIMENT" if targets else "RETAINED_INPUT_PASS"
        ),
    }


def _observe_declared_tuple_change(
    baseline: dict[str, Any], response: dict[str, Any], spec: dict[str, Any],
) -> int:
    """Observe a frozen experiment; never repair the response sent to a reader."""
    matching_indexes = [
        index for index in (0, 1)
        if all(
            _value_at_report_pointer(response, patch["concretePointer"])
            == patch["candidateValues"][index]
            for patch in spec["patches"]
        )
    ]
    if len(matching_indexes) != 1:
        raise SemanticACV049Error("ACV-049 enum/tuple candidate tuple is ambiguous")
    index = matching_indexes[0]
    if (dumps(response) == dumps(baseline)) != (bool(spec["twoStateRule"]) and index == 1):
        raise SemanticACV049Error("ACV-049 enum/tuple baseline equivalence is invalid")
    normalized = copy.deepcopy(response)
    for patch in spec["patches"]:
        pointer = patch["concretePointer"]
        _set_value_at_report_pointer(normalized, pointer, _value_at_report_pointer(baseline, pointer))
    if dumps(normalized) != dumps(baseline):
        raise SemanticACV049Error("ACV-049 enum/tuple mutant changed multiple targets")
    return index


def execute_enum_tuple_source_mutant_batch(
    repo_root: Path,
    contract: Path,
    evidence_root: Path,
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Execute every frozen Phase-A enum/tuple mutant in one channel."""

    if (
        not isinstance(manifest, dict)
        or manifest.get("schema")
        != "styx.app-core-iface0.acv049-enum-tuple-source-mutant-manifest.v1"
        or manifest.get("verdict") != "PHASE_A_ENUM_TUPLE_MUTANT_MANIFEST_PASS"
    ):
        raise SemanticACV049Error("ACV-049 enum/tuple manifest is malformed")
    tuple_constructions = manifest.get("ownershipRevision") == "V33_TUPLE_CONSTRUCTIONS"
    current_sites = derive_phase_a_source_site_map(
        repo_root, contract, evidence_root, tuple_constructions=tuple_constructions,
    )
    expected_manifest = build_phase_a_enum_tuple_source_mutant_manifest(
        repo_root, contract, evidence_root, source_site_map=current_sites,
    )
    if dumps(expected_manifest) != dumps(manifest):
        raise SemanticACV049Error("ACV-049 enum/tuple manifest is stale")
    authority = ContractAuthority.load(repo_root, contract)
    _inventory, _inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    request_rows = {
        case_id: (value, raw)
        for case_id, (value, raw) in carriers.items()
        if case_id.startswith("PCR-REQUEST-")
    }
    oracle_by_request = {
        dumps(case.request): case.collision_oracle
        for case in _semantic_request_carriers(authority)
        if case.collision_oracle is not None
    }
    instrumented, ast_sites = _instrumented_interface_model(
        repo_root, tuple_constructions=tuple_constructions,
    )
    previous = sys.modules.get("interface_model")
    sys.modules["interface_model"] = instrumented
    tagged_responses: dict[str, dict[str, Any]] = {}
    try:
        instrumented_authority = instrumented.ContractAuthority.load(
            repo_root, contract
        )
        for case_id, (request, raw) in request_rows.items():
            response = _evaluate_fixture_request(
                instrumented_authority, request, oracle_by_request.get(raw)
            )
            instrumented.validate_response_before_release(
                instrumented_authority, response
            )
            tagged_responses[case_id] = response
    finally:
        if previous is None:
            sys.modules.pop("interface_model", None)
        else:
            sys.modules["interface_model"] = previous

    module_cache: dict[bytes, tuple[types.ModuleType, Any, str]] = {}
    admission_failures: list[dict[str, str]] = []
    execution_failures: list[dict[str, str]] = []
    rows: list[dict[str, Any]] = []
    for spec in manifest["mutants"]:
        request, request_bytes = request_rows[spec["requestCaseId"]]
        oracle = oracle_by_request.get(request_bytes)
        expected_fault = (
            "FIXED_INTERNAL_COLLISION_ORACLE" if oracle is not None else "NONE"
        )
        if spec["faultContext"] != expected_fault:
            raise SemanticACV049Error("ACV-049 enum/tuple fault-context drift")
        baseline_response = tagged_responses[spec["requestCaseId"]]
        mutation_map: dict[
            str, list[tuple[tuple[str | int, ...], tuple[str, str]]]
        ] = {}
        baseline_by_pointer: dict[str, Any] = {}
        for patch in spec["patches"]:
            ast_site_id = patch["astSiteId"]
            if ast_site_id not in ast_sites:
                raise SemanticACV049Error("ACV-049 enum/tuple AST site is absent")
            logical_path = next(
                _raw_report_logical_path(path)
                for path in spec["logicalPaths"]
                if _logical_data_pattern(_raw_report_logical_path(path))[-1]
                == patch["field"]
            )
            selected = [
                value
                for pointer, value, relative in _pattern_source_values(
                    baseline_response, _logical_data_pattern(logical_path)
                )
                if _report_pointer(_json_pointer(pointer))
                == patch["concretePointer"]
                and value.site_id == ast_site_id
                and list(relative) == patch["relativeTokens"]
            ]
            if len(selected) != 1:
                raise SemanticACV049Error(
                    "ACV-049 enum/tuple source selector did not execute"
                )
            baseline_by_pointer[patch["concretePointer"]] = str(selected[0])
            mutation_map.setdefault(ast_site_id, []).append(
                (
                    tuple(patch["relativeTokens"]),
                    tuple(patch["candidateValues"]),
                )
            )
        frozen_mutation_map = {
            site_id: tuple(sorted(set(patches) if tuple_constructions else patches,
                                  key=lambda row: dumps([list(row[0]), list(row[1])])))
            for site_id, patches in mutation_map.items()
        }
        module_key = dumps(
            {
                site_id: [[list(selector), list(candidates)] for selector, candidates in patches]
                for site_id, patches in sorted(frozen_mutation_map.items())
            }
        )
        cached = module_cache.get(module_key)
        if cached is None:
            mutated, _mutant_sites, mutant_source = _mutated_interface_model(
                repo_root, frozen_mutation_map, ACV049_MUTANT_CHANNELS,
                tuple_constructions=tuple_constructions,
            )
            previous = sys.modules.get("interface_model")
            sys.modules["interface_model"] = mutated
            try:
                mutated_authority = mutated.ContractAuthority.load(repo_root, contract)
            finally:
                if previous is None:
                    sys.modules.pop("interface_model", None)
                else:
                    sys.modules["interface_model"] = previous
            cached = (mutated, mutated_authority, sha256_bytes(mutant_source))
            module_cache[module_key] = cached
        mutated, mutated_authority, mutant_source_sha256 = cached
        previous = sys.modules.get("interface_model")
        sys.modules["interface_model"] = mutated
        try:
            try:
                mutated._acv049_mutated_sites_executed.clear()
                first = _evaluate_fixture_request(mutated_authority, request, oracle)
                first_executed_sites = frozenset(
                    mutated._acv049_mutated_sites_executed
                )
                mutated._acv049_mutated_sites_executed.clear()
                second = _evaluate_fixture_request(mutated_authority, request, oracle)
                second_executed_sites = frozenset(
                    mutated._acv049_mutated_sites_executed
                )
                mutated.validate_response_before_release(mutated_authority, first)
                mutated.validate_response_before_release(mutated_authority, second)
            except Exception as error:
                admission_failures.append({
                    "failureClass": type(error).__name__,
                    "failureMessage": str(error),
                    "mutantId": spec["mutantId"],
                    "requestCaseId": spec["requestCaseId"],
                    "siteId": spec["siteId"],
                })
                continue
        finally:
            if previous is None:
                sys.modules.pop("interface_model", None)
            else:
                sys.modules["interface_model"] = previous
        try:
            expected_executed_sites = frozenset(frozen_mutation_map)
            if (
                first_executed_sites != expected_executed_sites
                or second_executed_sites != expected_executed_sites
            ):
                raise SemanticACV049Error(
                    "ACV-049 enum/tuple mutant sites did not execute exactly"
                )
            if dumps(first) != dumps(second):
                raise SemanticACV049Error(
                    "ACV-049 enum/tuple mutant is nondeterministic"
                )
            observed_index = _observe_declared_tuple_change(baseline_response, first, spec)
        except (KeyError, SemanticACV049Error) as error:
            execution_failures.append({
                "changedPointers": _changed_json_pointers(
                    baseline_response, first
                ),
                "failureClass": type(error).__name__,
                "failureMessage": str(error),
                "mutantId": spec["mutantId"],
                "requestCaseId": spec["requestCaseId"],
                "siteId": spec["siteId"],
            })
            continue
        rows.append({
            "baselineResponseSha256": sha256_bytes(dumps(baseline_response)),
            "mutantId": spec["mutantId"],
            "mutantSourceSha256": mutant_source_sha256,
            "observedCandidateIndex": observed_index,
            "requestCaseId": spec["requestCaseId"],
            "requestSha256": sha256_bytes(request_bytes),
            "response": first,
            "responseSha256": sha256_bytes(dumps(first)),
            "sourceSiteExecuted": True,
        })
    if (
        len(rows) + len(admission_failures) + len(execution_failures)
        != manifest["mutantCount"]
    ):
        raise SemanticACV049Error("ACV-049 enum/tuple result count drift")
    return {
        "admissionFailureCount": len(admission_failures),
        "admissionFailures": admission_failures,
        "executionFailureCount": len(execution_failures),
        "executionFailures": execution_failures,
        "moduleCount": len(module_cache),
        "mutantSetSha256": manifest["mutantSetSha256"],
        "passedMutantCount": len(rows),
        "relationTupleResidualCount": manifest["relationTupleResidualCount"],
        "rows": rows,
        "scheduledMutantCount": manifest["mutantCount"],
        "schema": "styx.app-core-iface0.acv049-enum-tuple-source-mutant-batch.v1",
        "verdict": (
            "PYTHON_RELEASE_ENUM_TUPLE_MUTANT_BATCH_PASS"
            if not admission_failures and not execution_failures
            else "PYTHON_RELEASE_ENUM_TUPLE_MUTANT_BATCH_FAIL"
        ),
    }


def _v34_identity_target_run_binding(
    repo_root: Path,
    contract: Path,
    request_bytes: bytes,
    inventory_bytes: bytes,
    retained_input_plan: bytes,
    spec: dict[str, Any],
    ast_sites: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], str]:
    """Bind the independent V34 E plan and scalar manifest before execution."""

    if sha256_bytes(request_bytes) != _V34_IDENTITY_TARGET_REQUEST_SHA256:
        raise SemanticACV049Error("V34 identity-target run request drift")
    if spec["concretePointer"] != _V34_IDENTITY_TARGET_POINTER:
        raise SemanticACV049Error("V34 identity-target run pointer drift")
    if spec["relativeTokens"] != [0, "eventReferenceHex"]:
        raise SemanticACV049Error("V34 identity-target source selector drift")
    site = ast_sites.get(spec["astSiteId"])
    if site is None or site.get("function") != "replay_context":
        raise SemanticACV049Error("V34 identity-target response-copy owner drift")
    if site.get("label") != "logicalEvents":
        raise SemanticACV049Error("V34 identity-target response-copy label drift")

    implementation = repo_root / "tools/causal-flow-simulator/app_core_iface0"
    interface_model = implementation / "interface_model.py"
    artifacts = {
        "evaluatorSource": sha256_bytes(interface_model.read_bytes()),
        "instrumenterSource": sha256_bytes(Path(__file__).read_bytes()),
        "nodeReaderSource": sha256_bytes(
            (implementation / "node_adapter.mjs").read_bytes()
        ),
        "positiveCarrierInventory": sha256_bytes(inventory_bytes),
        "pythonReaderSource": sha256_bytes(interface_model.read_bytes()),
        "relations": sha256_bytes(
            (
                contract
                / "APP-CORE-IFACE-0-SEMANTIC-RELATIONS-CANDIDATE.json"
            ).read_bytes()
        ),
        "schema": sha256_bytes(
            (contract / "APP-CORE-IFACE-0-SCHEMA-CANDIDATE.json").read_bytes()
        ),
    }
    record = {
        "artifactSha256": artifacts,
        "controlledChannels": list(ACV049_MUTANT_CHANNELS),
        "historicalSourceSiteMapRouteSha256": (
            _V34_IDENTITY_TARGET_HISTORICAL_ROUTE_SHA256
        ),
        "mutantManifestSha256": sha256_bytes(dumps(spec)),
        "requestCaseId": spec["requestCaseId"],
        "requestSha256": sha256_bytes(request_bytes),
        "retainedInputPlanSha256": sha256_bytes(retained_input_plan),
        "schema": "styx.app-core-iface0.acv049-v34-identity-target-run-binding.v1",
        "sourceEvidence": {
            "astSiteId": spec["astSiteId"],
            "function": site["function"],
            "label": site["label"],
            "relativeTokens": list(spec["relativeTokens"]),
            "sourceExpressionSha256": site["sourceExpressionSha256"],
            "sourceSiteMapRouteSha256": spec["sourceSiteMapRouteSha256"],
        },
    }
    raw = dumps(record)
    if any(value.encode("utf-8") in raw for value in spec["candidateValues"]):
        raise SemanticACV049Error("V34 run binding copied a candidate value")
    return record, sha256_bytes(raw)


def _validate_v34_identity_target_source_qualification(
    repo_root: Path,
    contract: Path,
    evidence_root: Path,
    spec: dict[str, Any],
    run: dict[str, Any],
) -> dict[str, Any]:
    """Conjoin Appendix-S binding, source trace, E, and value detection."""

    if (
        spec.get("requestCaseId") != _V34_IDENTITY_TARGET_REQUEST_CASE_ID
        or spec.get("concretePointer") != _V34_IDENTITY_TARGET_POINTER
    ):
        raise SemanticACV049Error("V34 source qualification is outside Appendix S")
    _validate_scalar_source_mutant_spec(spec)
    authority = ContractAuthority.load(repo_root, contract)
    _inventory, inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    request, request_bytes = carriers[spec["requestCaseId"]]
    instrumented, ast_sites = _instrumented_interface_model(
        repo_root, tuple_constructions=True
    )
    retained_input_plan = freeze_retained_input_plan(
        authority, request, target_pointers=(spec["concretePointer"],)
    )
    expected_binding, expected_binding_sha256 = _v34_identity_target_run_binding(
        repo_root,
        contract,
        request_bytes,
        inventory_bytes,
        retained_input_plan,
        spec,
        ast_sites,
    )
    if run.get("runBindingRecord") != expected_binding or (
        run.get("runBindingRecordSha256") != expected_binding_sha256
    ):
        raise SemanticACV049Error("V34 run binding record drift")
    if run.get("sourceSiteExecuted") is not True:
        raise SemanticACV049Error("V34 source execution trace is absent")
    _mutated, _mutant_sites, mutant_source = _mutated_interface_model(
        repo_root,
        {
            spec["astSiteId"]: (
                (tuple(spec["relativeTokens"]), tuple(spec["candidateValues"])),
            )
        },
        ACV049_MUTANT_CHANNELS,
        tuple_constructions=True,
    )
    if run.get("mutantSourceSha256") != sha256_bytes(mutant_source):
        raise SemanticACV049Error("V34 source execution trace digest drift")
    response = run.get("response")
    if not isinstance(response, dict) or run.get("responseSha256") != sha256_bytes(
        dumps(response)
    ):
        raise SemanticACV049Error("V34 source response digest drift")
    retained = observe_retained_input(retained_input_plan, response)
    if retained.get("verdict") != "RETAINED_OFF_TARGET_PASS_TARGET_EXPERIMENT":
        raise SemanticACV049Error("V34 retained-input qualification failed")
    oracle_by_request = {
        dumps(case.request): case.collision_oracle
        for case in _semantic_request_carriers(authority)
        if case.collision_oracle is not None
    }
    baseline = _evaluate_fixture_request(
        authority, request, oracle_by_request.get(request_bytes)
    )
    observed_index = _observe_declared_tuple_change(
        baseline,
        response,
        {
            "patches": [
                {
                    "candidateValues": list(spec["candidateValues"]),
                    "concretePointer": spec["concretePointer"],
                }
            ],
            "twoStateRule": spec["twoStateRule"],
        },
    )
    if run.get("observedCandidateIndex") != observed_index:
        raise SemanticACV049Error("V34 source candidate index drift")
    return {
        "mutantManifestSha256": sha256_bytes(dumps(spec)),
        "retainedInputPlanSha256": sha256_bytes(retained_input_plan),
        "runBindingRecordSha256": expected_binding_sha256,
        "sourceSiteExecuted": True,
        "verdict": "V34_IDENTITY_TARGET_SOURCE_RUN_PASS",
    }


def execute_scalar_source_mutant(
    repo_root: Path,
    contract: Path,
    evidence_root: Path,
    spec: dict[str, Any],
    *,
    tuple_constructions: bool = False,
) -> dict[str, Any]:
    """Execute one frozen scalar source mutant without reading its channel."""

    _validate_scalar_source_mutant_spec(spec)
    tuple_constructions = tuple_constructions or (
        spec["requestCaseId"] == _V34_IDENTITY_TARGET_REQUEST_CASE_ID
        and spec["concretePointer"] == _V34_IDENTITY_TARGET_POINTER
    )
    authority = ContractAuthority.load(repo_root, contract)
    _inventory, inventory_bytes, carriers = _load_phase_a(
        repo_root, contract, evidence_root
    )
    carrier = carriers.get(spec["requestCaseId"])
    if carrier is None or not spec["requestCaseId"].startswith("PCR-REQUEST-"):
        raise SemanticACV049Error("ACV-049 source-mutant request is absent")
    request, request_bytes = carrier
    oracle_by_request = {
        dumps(case.request): case.collision_oracle
        for case in _semantic_request_carriers(authority)
        if case.collision_oracle is not None
    }
    oracle = oracle_by_request.get(request_bytes)
    expected_fault = (
        "FIXED_INTERNAL_COLLISION_ORACLE" if oracle is not None else "NONE"
    )
    if spec["faultContext"] != expected_fault:
        raise SemanticACV049Error("ACV-049 source-mutant fault context drift")

    logical_path = _raw_report_logical_path(spec["logicalPath"])
    terminal = resolve_logical_terminal(authority.schema, logical_path)
    instrumented, ast_sites = _instrumented_interface_model(
        repo_root, tuple_constructions=tuple_constructions
    )
    previous = sys.modules.get("interface_model")
    sys.modules["interface_model"] = instrumented
    try:
        instrumented_authority = instrumented.ContractAuthority.load(
            repo_root, contract
        )
        baseline_response = _evaluate_fixture_request(
            instrumented_authority, request, oracle
        )
        instrumented.validate_response_before_release(
            instrumented_authority, baseline_response
        )
    finally:
        if previous is None:
            sys.modules.pop("interface_model", None)
        else:
            sys.modules["interface_model"] = previous
    if spec["astSiteId"] not in ast_sites:
        raise SemanticACV049Error("ACV-049 scalar mutant AST site is absent")
    source_values = _pattern_source_values(
        baseline_response, _logical_data_pattern(logical_path)
    )
    selected = [
        value
        for pointer, value, relative in source_values
        if _report_pointer(_json_pointer(pointer)) == spec["concretePointer"]
        and value.site_id == spec["astSiteId"]
        and list(relative) == spec["relativeTokens"]
    ]
    if len(selected) != 1:
        raise SemanticACV049Error("ACV-049 scalar source selector did not execute")
    baseline = str(selected[0])
    candidate_plan = _derive_schema_candidate_pair(
        authority.schema, terminal, baseline, ACV049_MUTANT_CHANNELS
    )
    for key in ("advanceCounts", "candidateValues", "domainClass", "twoStateRule"):
        if spec[key] != candidate_plan[key]:
            raise SemanticACV049Error("ACV-049 scalar candidate-plan drift")

    retained_input_plan: bytes | None = None
    run_binding: dict[str, Any] | None = None
    run_binding_sha256: str | None = None
    if spec["requestCaseId"] == _V34_IDENTITY_TARGET_REQUEST_CASE_ID and (
        spec["concretePointer"] == _V34_IDENTITY_TARGET_POINTER
    ):
        retained_input_plan = freeze_retained_input_plan(
            authority, request, target_pointers=(spec["concretePointer"],)
        )
        run_binding, run_binding_sha256 = _v34_identity_target_run_binding(
            repo_root,
            contract,
            request_bytes,
            inventory_bytes,
            retained_input_plan,
            spec,
            ast_sites,
        )

    mutated, _mutant_sites, mutant_source = _mutated_interface_model(
        repo_root,
        {
            spec["astSiteId"]: (
                (
                    tuple(spec["relativeTokens"]),
                    tuple(spec["candidateValues"]),
                ),
            )
        },
        ACV049_MUTANT_CHANNELS,
        tuple_constructions=tuple_constructions,
    )
    previous = sys.modules.get("interface_model")
    sys.modules["interface_model"] = mutated
    try:
        mutated_authority = mutated.ContractAuthority.load(repo_root, contract)
        mutated._acv049_mutated_sites_executed.clear()
        first = _evaluate_fixture_request(mutated_authority, request, oracle)
        first_executed_sites = frozenset(mutated._acv049_mutated_sites_executed)
        mutated._acv049_mutated_sites_executed.clear()
        second = _evaluate_fixture_request(mutated_authority, request, oracle)
        second_executed_sites = frozenset(mutated._acv049_mutated_sites_executed)
        mutated.validate_response_before_release(mutated_authority, first)
        mutated.validate_response_before_release(mutated_authority, second)
    finally:
        if previous is None:
            sys.modules.pop("interface_model", None)
        else:
            sys.modules["interface_model"] = previous
    if first_executed_sites != {spec["astSiteId"]} or (
        second_executed_sites != {spec["astSiteId"]}
    ):
        raise SemanticACV049Error("ACV-049 scalar mutant site did not execute exactly")
    if dumps(first) != dumps(second):
        raise SemanticACV049Error("ACV-049 scalar mutant is nondeterministic")
    observed = _value_at_report_pointer(first, spec["concretePointer"])
    if observed not in spec["candidateValues"] or observed == baseline:
        raise SemanticACV049Error("ACV-049 scalar mutant target did not change")
    normalized = copy.deepcopy(first)
    _set_value_at_report_pointer(normalized, spec["concretePointer"], baseline)
    if dumps(normalized) != dumps(baseline_response):
        raise SemanticACV049Error("ACV-049 scalar mutant changed multiple targets")
    result = {
        "baselineResponseSha256": sha256_bytes(dumps(baseline_response)),
        "mutantId": spec["mutantId"],
        "mutantSourceSha256": sha256_bytes(mutant_source),
        "observedCandidateIndex": spec["candidateValues"].index(observed),
        "requestCaseId": spec["requestCaseId"],
        "requestSha256": sha256_bytes(request_bytes),
        "response": first,
        "responseSha256": sha256_bytes(dumps(first)),
        "schema": "styx.app-core-iface0.acv049-scalar-source-mutant-run.v1",
        "sourceSiteExecuted": True,
        "verdict": "PYTHON_RELEASE_MUTANT_PASS",
    }
    if retained_input_plan is not None:
        retained_observation = observe_retained_input(retained_input_plan, first)
        if retained_observation["verdict"] != (
            "RETAINED_OFF_TARGET_PASS_TARGET_EXPERIMENT"
        ):
            raise SemanticACV049Error("V34 retained-input observer failed")
        retained_observation = {
            **retained_observation,
            "runBindingRecordSha256": run_binding_sha256,
        }
        result.update(
            {
                "retainedInputObservation": retained_observation,
                "runBindingRecord": run_binding,
                "runBindingRecordSha256": run_binding_sha256,
            }
        )
        result["sourceQualification"] = (
            _validate_v34_identity_target_source_qualification(
                repo_root, contract, evidence_root, spec, result
            )
        )
    return result


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


def _changed_json_pointers(
    baseline: Any,
    candidate: Any,
    prefix: tuple[str | int, ...] = (),
) -> list[str]:
    """Return a closed leaf-level diff for external mutant diagnostics."""

    if isinstance(baseline, dict) and isinstance(candidate, dict):
        if set(baseline) != set(candidate):
            return [_report_pointer(_json_pointer(prefix))]
        return [
            pointer
            for key in sorted(baseline)
            for pointer in _changed_json_pointers(
                baseline[key], candidate[key], (*prefix, key)
            )
        ]
    if isinstance(baseline, list) and isinstance(candidate, list):
        if len(baseline) != len(candidate):
            return [_report_pointer(_json_pointer(prefix))]
        return [
            pointer
            for index, (left, right) in enumerate(zip(baseline, candidate, strict=True))
            for pointer in _changed_json_pointers(left, right, (*prefix, index))
        ]
    return [] if baseline == candidate else [_report_pointer(_json_pointer(prefix))]


def _report_pointer(pointer: str) -> str:
    if not pointer.startswith("/") or pointer == "/":
        raise SemanticACV049Error("ACV-049 report pointer is not rooted")
    return "JSON_POINTER:" + pointer[1:].replace("%", "%25").replace("/", "%2F")


def _raw_report_pointer(pointer: str) -> str:
    prefix = "JSON_POINTER:"
    if not pointer.startswith(prefix):
        raise SemanticACV049Error("ACV-049 report pointer encoding drift")
    return "/" + pointer[len(prefix):].replace("%2F", "/").replace("%25", "%")


def _value_at_report_pointer(value: Any, pointer: str) -> Any:
    raw = _raw_report_pointer(pointer)
    current = value
    for encoded in raw.removeprefix("/").split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if not token.isdecimal() or int(token) >= len(current):
                raise SemanticACV049Error("ACV-049 report array pointer drift")
            current = current[int(token)]
        elif isinstance(current, dict) and token in current:
            current = current[token]
        else:
            raise SemanticACV049Error("ACV-049 report object pointer drift")
    return current


def _set_value_at_report_pointer(value: Any, pointer: str, replacement: Any) -> None:
    raw = _raw_report_pointer(pointer)
    encoded_tokens = raw.removeprefix("/").split("/")
    if not encoded_tokens:
        raise SemanticACV049Error("ACV-049 report pointer targets the root")
    current = value
    for encoded in encoded_tokens[:-1]:
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if not token.isdecimal() or int(token) >= len(current):
                raise SemanticACV049Error("ACV-049 report array pointer drift")
            current = current[int(token)]
        elif isinstance(current, dict) and token in current:
            current = current[token]
        else:
            raise SemanticACV049Error("ACV-049 report object pointer drift")
    final = encoded_tokens[-1].replace("~1", "/").replace("~0", "~")
    if isinstance(current, list):
        if not final.isdecimal() or int(final) >= len(current):
            raise SemanticACV049Error("ACV-049 report array pointer drift")
        current[int(final)] = replacement
    elif isinstance(current, dict) and final in current:
        current[final] = replacement
    else:
        raise SemanticACV049Error("ACV-049 report object pointer drift")


def _report_logical_path(path: str) -> str:
    if not path or path.startswith("/"):
        raise SemanticACV049Error("ACV-049 logical path identity drift")
    return "LOGICAL_PATH:" + path.replace("%", "%25").replace("/", "%2F")


def _raw_report_logical_path(path: str) -> str:
    prefix = "LOGICAL_PATH:"
    if not path.startswith(prefix):
        raise SemanticACV049Error("ACV-049 report logical path encoding drift")
    decoded = path[len(prefix):].replace("%2F", "/").replace("%25", "%")
    if not decoded or decoded.startswith("/"):
        raise SemanticACV049Error("ACV-049 report logical path identity drift")
    return decoded


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


def _store_external_artifact(repo_root: Path, output: Path, value: Any) -> None:
    repository = repo_root.resolve()
    parent = output.parent.resolve(strict=True)
    target = parent / output.name
    if (
        not output.name
        or output.name in {".", ".."}
        or target.exists()
        or target.is_symlink()
        or target == repository
        or repository in target.parents
    ):
        raise SemanticACV049Error("ACV-049 external artifact path is invalid")
    raw = dumps(value)
    try:
        with target.open("xb") as stream:
            stream.write(raw)
    except OSError as error:
        raise SemanticACV049Error("ACV-049 external artifact write failed") from error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--evidence-root", required=True, type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--emit-terminal-jobs", action="store_true")
    modes.add_argument("--emit-source-site-map", action="store_true")
    modes.add_argument("--emit-scalar-source-mutant-manifest", action="store_true")
    modes.add_argument("--emit-enum-tuple-source-mutant-manifest", action="store_true")
    modes.add_argument("--execute-scalar-source-mutant", type=Path)
    modes.add_argument("--execute-scalar-source-mutant-batch", type=Path)
    modes.add_argument("--execute-enum-tuple-source-mutant-batch", type=Path)
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
        if args.emit_scalar_source_mutant_manifest:
            if args.javascript_results_stdin or args.output is None:
                raise SemanticACV049Error("source-mutant manifest mode argument drift")
            manifest = build_phase_a_scalar_source_mutant_manifest(
                args.repo_root.resolve(),
                args.contract.resolve(),
                args.evidence_root.resolve(),
            )
            _store_external_artifact(
                args.repo_root.resolve(), args.output, manifest
            )
            print(
                "APP-core ACV-049 scalar mutant manifest: PASS "
                f"mutants={manifest['mutantCount']} "
                f"sha256={sha256_bytes(dumps(manifest))}"
            )
            return 0
        if args.emit_enum_tuple_source_mutant_manifest:
            if args.javascript_results_stdin or args.output is None:
                raise SemanticACV049Error("enum/tuple manifest mode argument drift")
            source_site_map = derive_phase_a_source_site_map(
                args.repo_root.resolve(),
                args.contract.resolve(),
                args.evidence_root.resolve(),
                tuple_constructions=True,
            )
            manifest = build_phase_a_enum_tuple_source_mutant_manifest(
                args.repo_root.resolve(),
                args.contract.resolve(),
                args.evidence_root.resolve(),
                source_site_map=source_site_map,
            )
            _store_external_artifact(args.repo_root.resolve(), args.output, manifest)
            print(
                "APP-core ACV-049 enum/tuple mutant manifest: PASS "
                f"mutants={manifest['mutantCount']} "
                f"residuals={manifest['relationTupleResidualCount']} "
                f"sha256={sha256_bytes(dumps(manifest))}"
            )
            return 0
        if args.execute_enum_tuple_source_mutant_batch is not None:
            if args.javascript_results_stdin or args.output is None:
                raise SemanticACV049Error("enum/tuple batch mode argument drift")
            raw_manifest = args.execute_enum_tuple_source_mutant_batch.read_bytes()
            try:
                manifest = json.loads(raw_manifest)
            except (UnicodeDecodeError, ValueError) as error:
                raise SemanticACV049Error(
                    "ACV-049 enum/tuple manifest is not JSON"
                ) from error
            if not isinstance(manifest, dict) or dumps(manifest) != raw_manifest:
                raise SemanticACV049Error(
                    "ACV-049 enum/tuple manifest is not canonical"
                )
            result = execute_enum_tuple_source_mutant_batch(
                args.repo_root.resolve(),
                args.contract.resolve(),
                args.evidence_root.resolve(),
                manifest,
            )
            _store_external_artifact(args.repo_root.resolve(), args.output, result)
            print(
                "APP-core ACV-049 enum/tuple mutant batch: "
                f"{'PASS' if result['verdict'].endswith('_PASS') else 'FAIL'} "
                f"scheduled={result['scheduledMutantCount']} "
                f"passed={result['passedMutantCount']} "
                f"modules={result['moduleCount']} "
                f"admission_failures={result['admissionFailureCount']} "
                f"execution_failures={result['executionFailureCount']} "
                f"sha256={sha256_bytes(dumps(result))}"
            )
            return (
                0
                if result["admissionFailureCount"] == 0
                and result["executionFailureCount"] == 0
                else 2
            )
        if args.execute_scalar_source_mutant_batch is not None:
            if args.javascript_results_stdin or args.output is None:
                raise SemanticACV049Error("source-mutant batch mode argument drift")
            raw_manifest = args.execute_scalar_source_mutant_batch.read_bytes()
            try:
                manifest = json.loads(raw_manifest)
            except (UnicodeDecodeError, ValueError) as error:
                raise SemanticACV049Error(
                    "ACV-049 scalar mutant manifest is not JSON"
                ) from error
            if not isinstance(manifest, dict) or dumps(manifest) != raw_manifest:
                raise SemanticACV049Error(
                    "ACV-049 scalar mutant manifest is not canonical"
                )
            result = execute_scalar_source_mutant_batch(
                args.repo_root.resolve(),
                args.contract.resolve(),
                args.evidence_root.resolve(),
                manifest,
            )
            _store_external_artifact(
                args.repo_root.resolve(), args.output, result
            )
            print(
                "APP-core ACV-049 scalar mutant batch: "
                f"{'PASS' if result['verdict'].endswith('_PASS') else 'FAIL'} "
                f"scheduled={result['scheduledMutantCount']} "
                f"passed={result['passedMutantCount']} "
                f"modules={result['moduleCount']} "
                f"admission_failures={result['admissionFailureCount']} "
                f"execution_failures={result['executionFailureCount']} "
                f"sha256={sha256_bytes(dumps(result))}"
            )
            return (
                0
                if result["admissionFailureCount"] == 0
                and result["executionFailureCount"] == 0
                else 2
            )
        if args.execute_scalar_source_mutant is not None:
            if args.javascript_results_stdin or args.output is not None:
                raise SemanticACV049Error("source-mutant mode argument drift")
            raw_spec = args.execute_scalar_source_mutant.read_bytes()
            try:
                spec = json.loads(raw_spec)
            except (UnicodeDecodeError, ValueError) as error:
                raise SemanticACV049Error(
                    "ACV-049 source-mutant spec is not JSON"
                ) from error
            if not isinstance(spec, dict) or dumps(spec) != raw_spec:
                raise SemanticACV049Error(
                    "ACV-049 source-mutant spec is not canonical"
                )
            sys.stdout.buffer.write(
                dumps(
                    execute_scalar_source_mutant(
                        args.repo_root.resolve(),
                        args.contract.resolve(),
                        args.evidence_root.resolve(),
                        spec,
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
