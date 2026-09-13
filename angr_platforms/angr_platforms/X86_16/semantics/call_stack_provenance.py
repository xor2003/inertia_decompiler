"""Interpret physical PUSH provenance without guessing pointer identities.

Layer: Semantics.
Responsibility: resolve exact BP-derived argument offsets or retain typed
uncertainty. Do not recover alias identities, types, or rendered C here.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from ..callsite_summary import CallsitePushExprOp8616, CallsitePushSourceKind8616
from .call_stack_effect_contracts import CallStackEffectFailure8616

_EXPRESSION_FIELD_COUNT: int = 3
_OPERAND_FIELD_COUNT: int = 2


def _expression_parts(
    source: tuple[object, ...],
) -> tuple[tuple[object, ...], tuple[object, ...]] | None:
    """Validate the base and operation sequence before interpreting either."""
    if len(source) != _EXPRESSION_FIELD_COUNT:
        return None
    base, operations = source[1:]
    if not isinstance(base, tuple) or not isinstance(operations, tuple):
        return None
    return base, operations


def _operation_kind(operation: object) -> CallsitePushExprOp8616 | None:
    """Decode the structured operation tag, retaining invalid tags as unknown."""
    if not isinstance(operation, tuple) or not operation:
        return None
    raw_op = operation[0]
    try:
        return raw_op if isinstance(raw_op, CallsitePushExprOp8616) else CallsitePushExprOp8616(raw_op)
    except (TypeError, ValueError):
        return None

def _source_kind_8616(source: object) -> CallsitePushSourceKind8616 | None:
    """Normalize one structured physical source kind without text heuristics."""
    if not isinstance(source, tuple) or not source:
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


def _expression_stack_offset_8616(
    source: tuple[object, ...],
) -> tuple[int | None, CallStackEffectFailure8616 | None]:
    """Resolve an exact BP-derived address expression or retain typed uncertainty."""
    parts = _expression_parts(source)
    if parts is None:
        return None, CallStackEffectFailure8616.ARGUMENT_SOURCES_INCOMPLETE
    base, operations = parts
    offset, failure = stack_address_offset_8616(base)
    if failure is not None:
        return None, failure
    for operation in operations:
        offset, failure = _apply_stack_operation(offset, operation)
        if failure is not None:
            return None, failure
    return offset, None


def _apply_stack_operation(
    offset: int | None, operation: object,
) -> tuple[int | None, CallStackEffectFailure8616 | None]:
    """Apply one proven constant displacement; refuse ambiguous pointer arithmetic."""
    op = _operation_kind(operation)
    if op is None or not isinstance(operation, tuple):
        return None, CallStackEffectFailure8616.ARGUMENT_SOURCES_INCOMPLETE
    if op in {CallsitePushExprOp8616.ADD, CallsitePushExprOp8616.SUB}:
        if len(operation) != _OPERAND_FIELD_COUNT or not isinstance(operation[1], int):
            return None, CallStackEffectFailure8616.ARGUMENT_SOURCES_INCOMPLETE
        if offset is not None:
            offset += operation[1] if op is CallsitePushExprOp8616.ADD else -operation[1]
        return offset, None
    if op in {
        CallsitePushExprOp8616.ADD_SOURCE,
        CallsitePushExprOp8616.ADC_SOURCE,
        CallsitePushExprOp8616.SUB_SOURCE,
        CallsitePushExprOp8616.SBB_SOURCE,
    }:
        if len(operation) != _OPERAND_FIELD_COUNT or not isinstance(operation[1], tuple):
            return None, CallStackEffectFailure8616.ARGUMENT_SOURCES_INCOMPLETE
        nested_offset, nested_failure = stack_address_offset_8616(operation[1])
        if nested_failure is not None:
            return None, nested_failure
        if offset is not None or nested_offset is not None:
            return None, CallStackEffectFailure8616.POINTER_ARGUMENT_MAY_ESCAPE
        return offset, None
    if offset is not None:
        return None, CallStackEffectFailure8616.POINTER_ARGUMENT_MAY_ESCAPE
    return offset, None


def stack_address_offset_8616(source: object) -> tuple[int | None, CallStackEffectFailure8616 | None]:
    """Return exact caller-frame address provenance from one physical PUSH source."""
    kind = _source_kind_8616(source)
    if kind is None or not isinstance(source, tuple):
        return None, CallStackEffectFailure8616.ARGUMENT_SOURCES_INCOMPLETE
    if kind is CallsitePushSourceKind8616.BP_ADDRESS:
        if len(source) < _OPERAND_FIELD_COUNT or not isinstance(source[1], int):
            return None, CallStackEffectFailure8616.ARGUMENT_SOURCES_INCOMPLETE
        return source[1], None
    if kind is CallsitePushSourceKind8616.BP_INDEX_ADDRESS:
        return None, CallStackEffectFailure8616.POINTER_ARGUMENT_MAY_ESCAPE
    if kind is CallsitePushSourceKind8616.EXPR:
        return _expression_stack_offset_8616(source)
    return None, None
