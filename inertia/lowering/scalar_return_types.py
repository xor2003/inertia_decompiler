"""Materialize scalar function return types from typed return expressions.

Layer: Types/lowering.
Responsibility: join complete C-AST return-expression type evidence into the
inferred function prototype without changing return values or control flow.

This pass consumes typed expressions produced from binary semantics. It refuses
partial, mixed-width, unsigned, explicit-source, or non-scalar evidence and
never consults rendered C text, function names, or sidecars.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import contextlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CExpression, CReturn
from angr.sim_type import SimTypeFunction, SimTypeInt, SimTypeShort
from archinfo import Arch

from inertia.lowering.annotations import ANNOTATION_KEY
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616

__all__ = [
    "ScalarReturnTypeEvidenceStatus8616",
    "ScalarReturnTypeResult8616",
    "ScalarReturnTypeStats8616",
    "materialize_scalar_return_type_8616",
    "record_scalar_return_type_evidence_8616",
]


class _ProjectSurface8616(Protocol):
    """Third-party project fields used by return type materialization."""

    _inertia_scalar_return_type_evidence_8616: dict[int, ScalarReturnTypeEvidence8616]
    arch: Arch
    kb: object


class _CodegenSurface8616(Protocol):
    """Dynamic codegen fields consumed and produced by this Lowering owner."""

    cfunc: object
    _inertia_scalar_return_type_result_8616: ScalarReturnTypeResult8616


class _CFunctionSurface8616(Protocol):
    """angr CFunction fields synchronized with typed return evidence."""

    addr: int
    body: object
    statements: object
    functy: object


class _KnowledgeBaseSurface8616(Protocol):
    """Third-party knowledge-base function manager boundary."""

    functions: _FunctionManagerSurface8616


class _FunctionManagerSurface8616(Protocol):
    """Third-party function lookup used to synchronize prototypes."""

    def function(self, *, addr: int, create: bool) -> _FunctionSurface8616 | None:
        """Return one existing function without creating it."""


class _FunctionSurface8616(Protocol):
    """Third-party function metadata used to protect explicit prototypes."""

    info: object
    prototype: object


@dataclass(frozen=True, slots=True)
class ScalarReturnTypeStats8616:
    """Evidence accounting for scalar return type materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class ScalarReturnTypeResult8616:
    """Result of joining typed return expressions into one prototype."""

    changed: bool
    stats: ScalarReturnTypeStats8616


class ScalarReturnTypeEvidenceStatus8616(Enum):
    """Outcome of publishing one complete scalar return-type fact set."""

    RECORDED = "recorded"
    UNCHANGED = "unchanged"
    REFUSED = "refused"


@dataclass(frozen=True, slots=True)
class ScalarReturnTypeEvidence8616:
    """Durable signed-return evidence keyed by one exact function address."""

    function_addr: int
    expressions: tuple[CExpression, ...]
    stats: ScalarReturnTypeStats8616

    @property
    def complete(self) -> bool:
        """Return whether every collected fact was classified and materialized."""
        count = len(self.expressions)
        return (
            count > 0
            and self.stats.raw_fact_count == count
            and self.stats.normalized_fact_count == count
            and self.stats.classified_fact_count == count
            and self.stats.materialized_count == count
            and self.stats.failure_count == 0
        )


def _return_expressions_8616(cfunc: _CFunctionSurface8616) -> tuple[object, ...]:
    """Return each unique emitted return expression, including missing values."""
    expressions: list[object] = []
    seen: set[int] = set()
    roots: list[object] = []
    with contextlib.suppress(AttributeError):
        roots.append(cfunc.statements)
    with contextlib.suppress(AttributeError):
        roots.append(cfunc.body)
    for root in roots:
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, CReturn) or id(node) in seen:
                continue
            seen.add(id(node))
            expressions.append(node.retval)
    return tuple(expressions)


def _is_signed_word_expression_8616(expression: object) -> bool:
    """Return whether one expression has explicit signed 16-bit scalar type."""
    if not isinstance(expression, CExpression):
        return False
    type_ = expression.type
    return (
        isinstance(type_, (SimTypeInt, SimTypeShort))
        and type_.size == 16
        and type_.signed is True
    )


def record_scalar_return_type_evidence_8616(
    project: object,
    function_addr: int,
    expressions: Sequence[object],
) -> ScalarReturnTypeEvidenceStatus8616:
    """Publish complete signed return facts across Structuring codegen rebuilds."""
    normalized = tuple(expression for expression in expressions if isinstance(expression, CExpression))
    count = len(expressions)
    if count == 0 or len(normalized) != count or not all(
        _is_signed_word_expression_8616(expression) for expression in normalized
    ):
        return ScalarReturnTypeEvidenceStatus8616.REFUSED
    stats = ScalarReturnTypeStats8616(count, count, count, count, 0)
    evidence = ScalarReturnTypeEvidence8616(function_addr, normalized, stats)
    project_surface = cast(_ProjectSurface8616, project)
    try:
        evidence_by_addr = project_surface._inertia_scalar_return_type_evidence_8616
    except AttributeError:
        evidence_by_addr = {}
    existing = evidence_by_addr.get(function_addr)
    if existing is not None:
        merged = list(existing.expressions)
        for expression in evidence.expressions:
            if not any(
                _same_c_expression_8616(expression, prior)
                for prior in merged
            ):
                merged.append(expression)
        if len(merged) == len(existing.expressions):
            return ScalarReturnTypeEvidenceStatus8616.UNCHANGED
        count = len(merged)
        evidence = ScalarReturnTypeEvidence8616(
            function_addr,
            tuple(merged),
            ScalarReturnTypeStats8616(count, count, count, count, 0),
        )
    project_surface._inertia_scalar_return_type_evidence_8616 = {
        **evidence_by_addr,
        function_addr: evidence,
    }
    return ScalarReturnTypeEvidenceStatus8616.RECORDED


def _matching_recorded_return_evidence_8616(
    project: _ProjectSurface8616,
    function_addr: int,
    expressions: Sequence[CExpression],
) -> ScalarReturnTypeEvidence8616 | None:
    """Select complete durable evidence matching every current return value."""
    try:
        evidence = project._inertia_scalar_return_type_evidence_8616.get(function_addr)
    except AttributeError:
        return None
    if evidence is None or not evidence.complete:
        return None
    if not expressions:
        return None
    covered = all(
        any(
            _same_c_expression_8616(expression, proven)
            for proven in evidence.expressions
        )
        for expression in expressions
    )
    return evidence if covered else None


def _has_explicit_prototype_8616(function: _FunctionSurface8616 | None) -> bool:
    """Return whether source/debug annotations own the function prototype."""
    if function is None or not isinstance(function.info, Mapping):
        return False
    annotations = function.info.get(ANNOTATION_KEY)
    return isinstance(annotations, Mapping) and isinstance(annotations.get("prototype"), SimTypeFunction)


def materialize_scalar_return_type_8616(
    project: object,
    codegen: object,
) -> ScalarReturnTypeResult8616:
    """Promote a guessed unsigned word result from complete signed evidence."""
    project_surface = cast(_ProjectSurface8616, project)
    codegen_surface = cast(_CodegenSurface8616, codegen)
    try:
        cfunc = cast(_CFunctionSurface8616, codegen_surface.cfunc)
        arch = project_surface.arch
        expressions = _return_expressions_8616(cfunc)
    except AttributeError:
        result = ScalarReturnTypeResult8616(False, ScalarReturnTypeStats8616(failure_count=1))
        codegen_surface._inertia_scalar_return_type_result_8616 = result
        return result
    raw_count = len(expressions)
    normalized_count = sum(isinstance(expression, CExpression) for expression in expressions)
    direct_classified_count = sum(_is_signed_word_expression_8616(expression) for expression in expressions)
    try:
        knowledge_base = cast(_KnowledgeBaseSurface8616, project_surface.kb)
        function = knowledge_base.functions.function(addr=cfunc.addr, create=False)
    except AttributeError:
        function = None
    normalized_expressions = tuple(
        expression for expression in expressions if isinstance(expression, CExpression)
    )
    recorded_evidence = _matching_recorded_return_evidence_8616(
        project_surface,
        cfunc.addr,
        normalized_expressions,
    )
    classified_count = raw_count if recorded_evidence is not None else direct_classified_count
    prototype = cfunc.functy
    complete = raw_count > 0 and normalized_count == raw_count and classified_count == raw_count
    if (
        not complete
        or not isinstance(prototype, SimTypeFunction)
        or _has_explicit_prototype_8616(function)
    ):
        failures = int(raw_count > 0 and not complete)
        result = ScalarReturnTypeResult8616(
            False,
            ScalarReturnTypeStats8616(
                raw_count,
                normalized_count,
                classified_count,
                0,
                failures,
            ),
        )
        codegen_surface._inertia_scalar_return_type_result_8616 = result
        return result
    return_type = prototype.returnty
    if isinstance(return_type, SimTypeInt) and return_type.signed is True and return_type.size == 16:
        materialized = classified_count
        result = ScalarReturnTypeResult8616(
            False,
            ScalarReturnTypeStats8616(raw_count, normalized_count, classified_count, materialized, 0),
        )
        codegen_surface._inertia_scalar_return_type_result_8616 = result
        return result
    if not isinstance(return_type, SimTypeShort) or return_type.size != 16 or return_type.signed is not False:
        result = ScalarReturnTypeResult8616(
            False,
            ScalarReturnTypeStats8616(raw_count, normalized_count, classified_count, 0, 1),
        )
        codegen_surface._inertia_scalar_return_type_result_8616 = result
        return result
    rebuilt = SimTypeFunction(
        list(prototype.args),
        SimTypeInt(signed=True).with_arch(arch),
        arg_names=prototype.arg_names,
        variadic=prototype.variadic,
    ).with_arch(arch)
    cfunc.functy = rebuilt
    if function is not None:
        function.prototype = rebuilt
    result = ScalarReturnTypeResult8616(
        True,
        ScalarReturnTypeStats8616(
            raw_count,
            normalized_count,
            classified_count,
            classified_count,
            0,
        ),
    )
    codegen_surface._inertia_scalar_return_type_result_8616 = result
    return result
