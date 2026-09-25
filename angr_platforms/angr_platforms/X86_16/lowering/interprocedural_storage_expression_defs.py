"""Prove structured call-argument expressions against exact IR/SSA lineage.

Layer: Types/Lowering.
Responsibility: normalize one typed callsite expression, reconstruct its
byte-executed outgoing push value, consume the IR-owned modular affine trace,
and require both projections to agree exactly. This module does not choose a
pointer segment or pointee width, project caller memory effects, infer C types,
mutate code generation, or inspect assembly/rendered C text.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..callsite_summary import (
    CallsitePushExprOp8616,
    CallsitePushSourceKind8616,
)
from ..ir import ScalarAffineExpression8616, ScalarAffineFailure8616
from ..ir.core import IRAddress
from ..ir.scalar_affine_trace import trace_scalar_affine_expression_8616
from ..ir.ssa_function import SSAFunctionArtifact
from .interprocedural_storage_contracts import StorageReachingDefinition8616
from .interprocedural_storage_physical_defs import (
    logical_push_value_8616,
    resolve_physical_store_definitions_8616,
)
from .interprocedural_storage_reaching_contracts import (
    CallArgumentDefinitionFailure8616,
    PhysicalCallArgumentPiece8616,
    SSAInstructionSite8616,
)


@dataclass(frozen=True, slots=True)
class _ExpectedAffine8616:
    """Normalized callsite expression before comparison with IR evidence."""

    width: int
    constant: int
    terms: tuple[tuple[int, int, int], ...]


def _source_kind_8616(
    source: tuple[object, ...],
) -> CallsitePushSourceKind8616 | None:
    """Decode one structured source category without textual heuristics."""
    if not source:
        return None
    raw_kind = source[0]
    if isinstance(raw_kind, CallsitePushSourceKind8616):
        return raw_kind
    if not isinstance(raw_kind, str):
        return None
    try:
        return CallsitePushSourceKind8616(raw_kind)
    except ValueError:
        return None


def _expression_op_8616(
    raw_op: object,
) -> CallsitePushExprOp8616 | None:
    """Decode one typed structured-expression operation."""
    if isinstance(raw_op, CallsitePushExprOp8616):
        return raw_op
    if not isinstance(raw_op, str):
        return None
    try:
        return CallsitePushExprOp8616(raw_op)
    except ValueError:
        return None


def _scale_expected_8616(
    value: _ExpectedAffine8616,
    factor: int,
    mask: int,
) -> _ExpectedAffine8616:
    """Apply one modular scale to an expected structured expression."""
    return _ExpectedAffine8616(
        value.width,
        value.constant * factor & mask,
        tuple(
            (offset, width, coefficient)
            for offset, width, raw_coefficient in value.terms
            if (coefficient := raw_coefficient * factor & mask) != 0
        ),
    )


def _combine_expected_8616(
    left: _ExpectedAffine8616,
    right: _ExpectedAffine8616,
    *,
    sign: int,
    mask: int,
) -> _ExpectedAffine8616:
    """Combine two normalized expected expressions modulo pointer width."""
    scaled_right = _scale_expected_8616(right, sign, mask)
    return _ExpectedAffine8616(
        left.width,
        (left.constant + scaled_right.constant) & mask,
        (*left.terms, *scaled_right.terms),
    )


def _expected_source_8616(
    source: tuple[object, ...],
    width: int,
) -> tuple[_ExpectedAffine8616 | None, CallArgumentDefinitionFailure8616 | None]:
    """Normalize a typed source tuple to modular affine terms."""
    mask = (1 << (width * 8)) - 1
    kind = _source_kind_8616(source)
    if kind is CallsitePushSourceKind8616.IMMEDIATE:
        if len(source) != 2 or not isinstance(source[1], int):
            return None, CallArgumentDefinitionFailure8616.EXPRESSION_SHAPE_CONFLICT
        return _ExpectedAffine8616(width, source[1] & mask, ()), None
    if kind is CallsitePushSourceKind8616.BP_VALUE:
        if (
            len(source) not in {2, 3}
            or not isinstance(source[1], int)
            or (len(source) == 3 and source[2] != width)
        ):
            return None, CallArgumentDefinitionFailure8616.EXPRESSION_WIDTH_CONFLICT
        return _ExpectedAffine8616(width, 0, ((source[1], width, 1),)), None
    if kind is not CallsitePushSourceKind8616.EXPR or len(source) != 3:
        return None, CallArgumentDefinitionFailure8616.EXPRESSION_SHAPE_CONFLICT
    base = source[1]
    operations = source[2]
    if not isinstance(base, tuple) or not isinstance(operations, tuple):
        return None, CallArgumentDefinitionFailure8616.EXPRESSION_SHAPE_CONFLICT
    current, failure = _expected_source_8616(base, width)
    if failure is not None or current is None:
        return None, failure or CallArgumentDefinitionFailure8616.EXPRESSION_SHAPE_CONFLICT
    for raw_operation in operations:
        current, step_failure = _apply_expected_operation_8616(
            current, raw_operation, width, mask
        )
        if step_failure is not None or current is None:
            return (
                None,
                step_failure or CallArgumentDefinitionFailure8616.EXPRESSION_SHAPE_CONFLICT,
            )
    return current, None


def _apply_expected_operation_8616(
    current: _ExpectedAffine8616,
    raw_operation: object,
    width: int,
    mask: int,
) -> tuple[_ExpectedAffine8616 | None, CallArgumentDefinitionFailure8616 | None]:
    """Apply one typed EXPR operation to the running expected affine."""
    if not isinstance(raw_operation, tuple) or len(raw_operation) != 2:
        return None, CallArgumentDefinitionFailure8616.EXPRESSION_SHAPE_CONFLICT
    op = _expression_op_8616(raw_operation[0])
    operand = raw_operation[1]
    if op in {CallsitePushExprOp8616.ADC, CallsitePushExprOp8616.SBB}:
        return None, CallArgumentDefinitionFailure8616.EXPRESSION_FLAGS_UNPROVEN
    if op in {CallsitePushExprOp8616.ADD, CallsitePushExprOp8616.SUB}:
        if not isinstance(operand, int):
            return None, CallArgumentDefinitionFailure8616.EXPRESSION_SHAPE_CONFLICT
        delta = operand if op is CallsitePushExprOp8616.ADD else -operand
        return (
            _ExpectedAffine8616(
                width,
                (current.constant + delta) & mask,
                current.terms,
            ),
            None,
        )
    if op is CallsitePushExprOp8616.SHL:
        if not isinstance(operand, int) or not 0 <= operand < width * 8:
            return None, CallArgumentDefinitionFailure8616.EXPRESSION_WIDTH_CONFLICT
        return _scale_expected_8616(current, 1 << operand, mask), None
    if op in {
        CallsitePushExprOp8616.ADD_SOURCE,
        CallsitePushExprOp8616.SUB_SOURCE,
    }:
        return _combine_source_operand_8616(current, op, operand, width, mask)
    if op in {
        CallsitePushExprOp8616.ADC_SOURCE,
        CallsitePushExprOp8616.SBB_SOURCE,
    }:
        return None, CallArgumentDefinitionFailure8616.EXPRESSION_FLAGS_UNPROVEN
    return None, CallArgumentDefinitionFailure8616.EXPRESSION_OPERATION_UNSUPPORTED


def _combine_source_operand_8616(
    current: _ExpectedAffine8616,
    op: CallsitePushExprOp8616,
    operand: object,
    width: int,
    mask: int,
) -> tuple[_ExpectedAffine8616 | None, CallArgumentDefinitionFailure8616 | None]:
    """Merge one nested source operand into the running expected affine."""
    if not isinstance(operand, tuple):
        return None, CallArgumentDefinitionFailure8616.EXPRESSION_SHAPE_CONFLICT
    right, right_failure = _expected_source_8616(operand, width)
    if right_failure is not None or right is None:
        return (
            None,
            right_failure or CallArgumentDefinitionFailure8616.EXPRESSION_SHAPE_CONFLICT,
        )
    return (
        _combine_expected_8616(
            current,
            right,
            sign=1 if op is CallsitePushExprOp8616.ADD_SOURCE else -1,
            mask=mask,
        ),
        None,
    )


def _actual_terms_8616(
    expression: ScalarAffineExpression8616,
) -> tuple[tuple[int, int, int], ...] | None:
    """Project exact IR terms to their comparable stack-source identities."""
    if any(not isinstance(term.source, IRAddress) for term in expression.terms):
        return None
    return tuple(
        sorted(
            (
                term.source.offset,
                term.source.size,
                term.coefficient,
            )
            for term in expression.terms
            if isinstance(term.source, IRAddress)
        )
    )


def _trace_failure_8616(
    failure: ScalarAffineFailure8616 | None,
) -> CallArgumentDefinitionFailure8616:
    """Map IR affine refusals to stable call-argument failures."""
    if failure is ScalarAffineFailure8616.DEFINITION_MISSING:
        return CallArgumentDefinitionFailure8616.EXPRESSION_DEFINITION_NOT_FOUND
    if failure is ScalarAffineFailure8616.DEFINITION_CONFLICT:
        return CallArgumentDefinitionFailure8616.EXPRESSION_DEFINITION_CONFLICT
    if failure is ScalarAffineFailure8616.WIDTH_CONFLICT:
        return CallArgumentDefinitionFailure8616.EXPRESSION_WIDTH_CONFLICT
    if failure is ScalarAffineFailure8616.EXPRESSION_UNSUPPORTED:
        return CallArgumentDefinitionFailure8616.EXPRESSION_OPERATION_UNSUPPORTED
    return CallArgumentDefinitionFailure8616.EXPRESSION_CONTROL_FLOW_UNPROVEN


def resolve_expression_argument_definitions_8616(
    function_ssa: SSAFunctionArtifact,
    sites: tuple[SSAInstructionSite8616, ...],
    piece: PhysicalCallArgumentPiece8616,
) -> tuple[
    tuple[StorageReachingDefinition8616, ...] | None,
    ScalarAffineExpression8616 | None,
    CallArgumentDefinitionFailure8616 | None,
]:
    """Prove one structured expression against its exact outgoing SSA value."""
    expected, expected_failure = _expected_source_8616(piece.source, piece.width)
    if expected_failure is not None or expected is None:
        return None, None, expected_failure or CallArgumentDefinitionFailure8616.EXPRESSION_SHAPE_CONFLICT
    definitions, definition_failure = resolve_physical_store_definitions_8616(
        sites,
        piece,
    )
    if definition_failure is not None or definitions is None:
        return None, None, definition_failure or CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    logical, logical_failure = logical_push_value_8616(sites, piece)
    if logical_failure is not None or logical is None:
        return None, None, logical_failure or CallArgumentDefinitionFailure8616.SOURCE_DEFINITION_NOT_FOUND
    block_addrs = {item.site.block.addr for item in logical.slices}
    if len(block_addrs) != 1:
        return None, None, CallArgumentDefinitionFailure8616.EXPRESSION_CONTROL_FLOW_UNPROVEN
    trace = trace_scalar_affine_expression_8616(
        function_ssa,
        logical.root,
        block_addr=logical.slices[0].site.block.addr,
        before_index=logical.slices[0].site.instr_index,
    )
    expression = trace.expression
    if not trace.complete or expression is None:
        return None, None, _trace_failure_8616(trace.failure)
    expected_terms = tuple(sorted(expected.terms))
    if (
        expression.width != expected.width
        or expression.constant != expected.constant
        or _actual_terms_8616(expression) != expected_terms
    ):
        return None, None, CallArgumentDefinitionFailure8616.EXPRESSION_SOURCE_MISMATCH
    return definitions, expression, None


__all__ = ["resolve_expression_argument_definitions_8616"]
