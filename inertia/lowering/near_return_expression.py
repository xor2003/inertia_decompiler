"""Build a candidate structured-C near-pointer return expression.

Layer: Types/Lowering.
Responsibility: pure, nonpublishing construction of a structured C AST
candidate for an already proven near scaled-return operand congruence:
``(T_near)NEAR_BYTE_ADD(src_seg, dst_seg, base_cvar, (uint16_t)((uint32_t)
(uint16_t)index_cvar * scaleUL))``. Both cvar leaves retain exact canonical
registry identity and ``scale`` is the proven modular index coefficient; the
widened unsigned multiply never relies on undefined signed-16 shift or
overflow, and no base pointee width is inferred from scale or result type.
Selector safety is owned by ``near_return_selector`` and replayed before use.
This detached AST grants no pointer, segment or native-representation authority
and mutates no body or prototype. Every refusal keeps classified and materialized
counts zero; retained congruence, operand identity and mutable nodes are replayed.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TypeGuard, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import (
    SimTypeLong,
    SimTypePointer,
    SimTypeShort,
)

from inertia.lowering.c_runtime_header import is_lowered_runtime_macro_8616
from inertia.lowering.near_pointer_type import SimTypeNearPointer16_8616
from inertia.lowering.near_return_c_ast_congruence import (
    NearReturnBoundOperand8616,
    NearReturnOperandCongruenceFailure8616,
    NearReturnOperandCongruenceResult8616,
    NearReturnOperandRole8616,
)
from inertia.lowering.stack_variable_coordinates import (
    stack_variable_coordinate_registry_8616,
)

from .near_return_selector import (
    _WORD_MODULUS_8616,
    _unsigned_int_bits_8616,
    classify_near_return_selector_8616,
)
from .near_return_selector import (
    NearReturnSelectorEvidence8616 as _SelectorEvidence8616,
)

__all__ = [
    "NearReturnPointerExpressionFailure8616",
    "NearReturnPointerExpressionResult8616",
    "NearReturnPointerExpressionStats8616",
    "NearReturnPointerExpressionVerdict8616",
    "build_near_return_pointer_expression_8616",
]

_NEAR_BYTE_ADD_HELPER_8616 = "NEAR_BYTE_ADD"


class NearReturnPointerExpressionVerdict8616(StrEnum):
    """Whether the candidate near-return expression was constructed."""

    BOUND = "bound"
    UNKNOWN_REFUSE = "unknown_refuse"


class NearReturnPointerExpressionFailure8616(StrEnum):
    """Stable reasons the candidate expression cannot be constructed."""

    CONGRUENCE_INCOMPLETE = "congruence_incomplete"
    CODEGEN_SURFACE_UNPROVEN = "codegen_surface_unproven"
    FUNCTION_MISMATCH = "function_mismatch"
    COEFFICIENT_FORM_UNSUPPORTED = "coefficient_form_unsupported"
    SELECTOR_NOT_SIDE_EFFECT_FREE = "selector_not_side_effect_free"
    SELECTOR_DOMAIN_UNPROVEN = "selector_domain_unproven"
    RESULT_TYPE_MALFORMED = "result_type_malformed"
    HELPER_SURFACE_MISSING = "helper_surface_missing"


_F8616 = NearReturnPointerExpressionFailure8616


@dataclass(frozen=True, slots=True)
class NearReturnPointerExpressionStats8616:
    """Closed five-stage evidence loop for one requested construction."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


def _fixed16_pointer_bits_8616(pointer_type: object) -> int | None:
    """Return the owned fixed16 near-pointer width, or ``None`` when absent.

    Only the owned ``SimTypeNearPointer16_8616`` counts: a generic
    ``SimTypePointer`` reports the bound architecture's address width, so a
    numeric ``size`` match cannot stand in for the planned contract.
    """
    if not isinstance(pointer_type, SimTypeNearPointer16_8616):
        return None
    try:
        size = pointer_type.size
    except (AttributeError, TypeError, ValueError):
        return None
    return size if type(size) is int and size == 16 else None


def _unsigned_cast_bits_8616(node: object, bits: int) -> TypeGuard[structured_c.CTypeCast]:
    """Return whether ``node`` is a ``(uintN_t)`` cast of exact width."""
    return isinstance(node, structured_c.CTypeCast) and _unsigned_int_bits_8616(node.dst_type, bits)


def _stats_bound_8616(stats: object) -> bool:
    """Return whether stats are the exact-int bound receipt ``(1,1,1,1,0)``."""
    if not isinstance(stats, NearReturnPointerExpressionStats8616):
        return False
    fields = (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    )
    return all(type(value) is int for value in fields) and fields == (1, 1, 1, 1, 0)


@dataclass(frozen=True, slots=True)
class NearReturnPointerExpressionResult8616:
    """One constructed candidate expression or a typed atomic refusal.

    ``expression`` is detached: it is never attached to the codegen body, and
    the caller still owes representation and body-census preflight before any
    publication. ``complete`` re-evaluates the live congruence, re-walks both
    retained selector subtrees for purity and word domain, and re-verifies
    the retained AST's types, scale constant, and operand coefficients, so a
    mutated node or detached field cannot keep a bound verdict.
    """

    verdict: NearReturnPointerExpressionVerdict8616
    failure: NearReturnPointerExpressionFailure8616 | None
    stats: NearReturnPointerExpressionStats8616
    callee_addr: int = -1
    expression: structured_c.CExpression | None = None
    congruence: NearReturnOperandCongruenceResult8616 | None = None
    bound_operands: tuple[NearReturnBoundOperand8616, ...] = ()
    source_selector: structured_c.CExpression | None = None
    result_selector: structured_c.CExpression | None = None
    byte_scale: int = -1
    result_pointer_type: SimTypePointer | None = None
    upstream_failure: NearReturnOperandCongruenceFailure8616 | None = None

    @property
    def complete(self) -> bool:
        """Recheck the retained candidate AST against the live congruence."""
        if (
            self.verdict is not NearReturnPointerExpressionVerdict8616.BOUND
            or self.failure is not None
            or self.upstream_failure is not None
            or not _stats_bound_8616(self.stats)
        ):
            return False
        congruence = self.congruence
        if (
            congruence is None
            or not congruence.complete
            or type(self.callee_addr) is not int
            or self.callee_addr != congruence.callee_addr
            or self.bound_operands != congruence.bound_operands
        ):
            return False
        operands = {operand.role: operand for operand in self.bound_operands}
        base = operands.get(NearReturnOperandRole8616.OFFSET_BASE)
        index = operands.get(NearReturnOperandRole8616.OFFSET_INDEX)
        if base is None or index is None:
            return False
        if (
            not _word_coefficient_8616(base.coefficient, 1)
            or not _word_coefficient_8616(index.coefficient, self.byte_scale)
        ):
            return False
        return (
            _fixed16_pointer_bits_8616(self.result_pointer_type) == 16
            and _selector_failure_8616(self.source_selector) is None
            and _selector_failure_8616(self.result_selector) is None
            and self._expression_matches(base, index)
        )

    def _expression_matches(
        self,
        base: NearReturnBoundOperand8616,
        index: NearReturnBoundOperand8616,
    ) -> bool:
        """Rewalk the retained AST against the bound operands and selectors."""
        expression = self.expression
        if not isinstance(expression, structured_c.CTypeCast):
            return False
        call = expression.expr
        if not isinstance(call, structured_c.CFunctionCall) or len(call.args) != 4:
            return False
        args = call.args
        product = args[3].expr if _unsigned_cast_bits_8616(args[3], 16) else None
        widened = (
            product.lhs
            if isinstance(product, structured_c.CBinaryOp) and product.op == "Mul"
            else None
        )
        narrowed = widened.expr if _unsigned_cast_bits_8616(widened, 32) else None
        scale_node = product.rhs if isinstance(product, structured_c.CBinaryOp) else None
        return bool(
            expression.dst_type == self.result_pointer_type
            and _fixed16_pointer_bits_8616(expression.dst_type) == 16
            and call.callee_func is None
            and call.callee_target == _NEAR_BYTE_ADD_HELPER_8616
            and args[0] is self.source_selector
            and args[1] is self.result_selector
            and args[2] is base.cvar
            and _unsigned_cast_bits_8616(narrowed, 16)
            and narrowed.expr is index.cvar
            and isinstance(scale_node, structured_c.CConstant)
            and type(scale_node.value) is int
            and scale_node.value == self.byte_scale
            and _unsigned_int_bits_8616(scale_node.type, 32)
        )


def _refuse_8616(
    congruence: NearReturnOperandCongruenceResult8616 | None,
    failure: NearReturnPointerExpressionFailure8616,
    *,
    normalized: bool = False,
    upstream: NearReturnOperandCongruenceFailure8616 | None = None,
) -> NearReturnPointerExpressionResult8616:
    """Keep one failed construction as an atomic refusal with closed counts.

    A refusal never claims a classified-but-unmaterialized fact:
    ``classified_fact_count`` and ``materialized_count`` stay ``0``.
    """
    stats = NearReturnPointerExpressionStats8616(1, int(normalized), 0, 0, 1)
    return NearReturnPointerExpressionResult8616(
        NearReturnPointerExpressionVerdict8616.UNKNOWN_REFUSE,
        failure,
        stats,
        callee_addr=congruence.callee_addr if congruence is not None else -1,
        congruence=congruence,
        upstream_failure=upstream,
    )


def _word_coefficient_8616(coefficient: object, expected: object) -> bool:
    """Return whether ``coefficient`` is an int matching ``expected mod 2^16``.

    The ``expected`` operand must itself be a real int; for the index scale
    it is ``self.byte_scale``, so exact equality with a residue in
    ``[0, 65536)`` also proves the retained scale's type and range.
    """
    return (
        type(coefficient) is int
        and type(expected) is int
        and coefficient % _WORD_MODULUS_8616 == expected
    )


def _selector_failure_8616(node: object) -> NearReturnPointerExpressionFailure8616 | None:
    """Classify one explicit segment selector operand, or accept it."""
    evidence = classify_near_return_selector_8616(node)
    if evidence is _SelectorEvidence8616.REJECT:
        return _F8616.SELECTOR_NOT_SIDE_EFFECT_FREE
    if evidence is not _SelectorEvidence8616.WORD:
        return _F8616.SELECTOR_DOMAIN_UNPROVEN
    return None


def _bound_proven_operands_8616(
    codegen: object,
    congruence: NearReturnOperandCongruenceResult8616,
) -> (
    tuple[NearReturnBoundOperand8616, NearReturnBoundOperand8616, int]
    | NearReturnPointerExpressionResult8616
):
    """Resolve both bound operands on the proven surface, or refuse.

    ``codegen.cfunc.addr`` is a third-party angr attribute boundary, so the
    reads use ``getattr`` defaults rather than owned dot access.
    """
    # Dynamic third-party angr codegen boundary; incomplete surfaces have no cfunc.
    function_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if type(function_addr) is not int or function_addr < 0:
        return _refuse_8616(congruence, _F8616.CODEGEN_SURFACE_UNPROVEN)
    if function_addr != congruence.callee_addr:
        return _refuse_8616(congruence, _F8616.FUNCTION_MISMATCH, normalized=True)
    if stack_variable_coordinate_registry_8616(codegen) is not congruence.registry:
        return _refuse_8616(congruence, _F8616.CODEGEN_SURFACE_UNPROVEN, normalized=True)
    operands = {operand.role: operand for operand in congruence.bound_operands}
    base = operands[NearReturnOperandRole8616.OFFSET_BASE]
    index = operands[NearReturnOperandRole8616.OFFSET_INDEX]
    # NEAR_BYTE_ADD adds the delta to the pointer argument exactly once, so a
    # proven base coefficient other than one cannot be represented this way.
    if base.coefficient % _WORD_MODULUS_8616 != 1:
        return _refuse_8616(congruence, _F8616.COEFFICIENT_FORM_UNSUPPORTED, normalized=True)
    return base, index, index.coefficient % _WORD_MODULUS_8616


def build_near_return_pointer_expression_8616(
    codegen: object,
    congruence: NearReturnOperandCongruenceResult8616,
    source_selector: object,
    result_selector: object,
    result_pointer_type: object,
) -> NearReturnPointerExpressionResult8616:
    """Construct the candidate ``NEAR_BYTE_ADD`` cast expression, or refuse.

    The builder is pure and nonpublishing: it never mutates the codegen AST,
    cvars, registry, prototype, callsite, or project state, and it decides
    neither pointer representation nor segment binding. The returned
    expression is a detached candidate pending the parent's representation
    and body-census preflight.
    """
    if not congruence.complete:
        return _refuse_8616(congruence, _F8616.CONGRUENCE_INCOMPLETE, upstream=congruence.failure)
    bound = _bound_proven_operands_8616(codegen, congruence)
    if isinstance(bound, NearReturnPointerExpressionResult8616):
        return bound
    base, index, byte_scale = bound
    for selector in (source_selector, result_selector):
        refusal = _selector_failure_8616(selector)
        if refusal is not None:
            return _refuse_8616(congruence, refusal, normalized=True)
    if _fixed16_pointer_bits_8616(result_pointer_type) != 16:
        return _refuse_8616(congruence, _F8616.RESULT_TYPE_MALFORMED, normalized=True)
    if not is_lowered_runtime_macro_8616(_NEAR_BYTE_ADD_HELPER_8616):
        return _refuse_8616(congruence, _F8616.HELPER_SURFACE_MISSING, normalized=True)

    index_u16 = structured_c.CTypeCast(None, SimTypeShort(False), index.cvar, codegen=codegen)
    index_u32 = structured_c.CTypeCast(None, SimTypeLong(False), index_u16, codegen=codegen)
    scale = structured_c.CConstant(byte_scale, SimTypeLong(False), codegen=codegen)
    product = structured_c.CBinaryOp("Mul", index_u32, scale, codegen=codegen)
    byte_term = structured_c.CTypeCast(None, SimTypeShort(False), product, codegen=codegen)
    selectors = [
        cast(structured_c.CExpression, source_selector),
        cast(structured_c.CExpression, result_selector),
    ]
    call = structured_c.CFunctionCall(
        _NEAR_BYTE_ADD_HELPER_8616, None, [*selectors, base.cvar, byte_term], codegen=codegen
    )
    expression = structured_c.CTypeCast(
        None, cast(SimTypeNearPointer16_8616, result_pointer_type), call, codegen=codegen
    )
    result = NearReturnPointerExpressionResult8616(
        NearReturnPointerExpressionVerdict8616.BOUND, None,
        NearReturnPointerExpressionStats8616(1, 1, 1, 1, 0),
        callee_addr=congruence.callee_addr, expression=expression,
        congruence=congruence, bound_operands=congruence.bound_operands,
        source_selector=cast(structured_c.CExpression, source_selector),
        result_selector=cast(structured_c.CExpression, result_selector),
        byte_scale=byte_scale,
        result_pointer_type=cast(SimTypePointer, result_pointer_type),
    )
    if not result.complete:
        raise RuntimeError("near-return candidate expression lost owned evidence")
    return result
