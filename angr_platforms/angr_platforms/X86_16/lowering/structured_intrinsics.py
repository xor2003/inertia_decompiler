"""Lower typed structured-codegen intrinsics before C validation.

Layer: Types/Lowering.
Responsibility: consume known pure angr C intrinsics that are not valid C APIs.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

angr may retain an AIL ``Insert`` expression as an ``_INSERT`` pseudo-call.
This pass lowers complete typed forms to exact x86 little-endian bit
operations. Its separate cleanup helper can remove a standalone form only
after proving that the value is unused and every operand is side-effect free.
Incomplete or effectful forms are retained; rewrite and CLI must not hide them.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeShort

from ..c_ast_utils import (
    _iter_c_node_occurrences_8616,
    _iter_c_nodes_deep_8616,
    _replace_c_children_8616,
)
from ..callsite_summary import StructuredCallKind8616, structured_call_kind_8616

__all__ = [
    "StructuredIntrinsicLoweringStats8616",
    "is_structured_insert_intrinsic_8616",
    "lower_structured_insert_call_8616",
    "lower_structured_insert_intrinsics_8616",
    "prune_unused_structured_insert_intrinsics_8616",
]

class _CFunctionStructuredIntrinsics8616(Protocol):
    """Third-party C function root consumed by intrinsic lowering."""

    addr: int
    statements: object


class _CodegenStructuredIntrinsics8616(Protocol):
    """Dynamic codegen contract used by intrinsic lowering."""

    cfunc: _CFunctionStructuredIntrinsics8616 | None
    _inertia_structured_intrinsic_lowering_stats_8616: StructuredIntrinsicLoweringStats8616


@dataclass(frozen=True, slots=True)
class StructuredIntrinsicLoweringStats8616:
    """Closed evidence counters for unused structured intrinsic removal."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


def is_structured_insert_intrinsic_8616(node: object) -> bool:
    """Return whether a structured call is angr's typed Insert intrinsic."""
    return (
        isinstance(node, structured_c.CFunctionCall)
        and structured_call_kind_8616(node) is StructuredCallKind8616.CODEGEN_INSERT_INTRINSIC
    )


def _expression_is_side_effect_free_8616(node: object) -> bool:
    """Return whether evaluating one structured expression has no side effect."""
    nodes = (node, *_iter_c_nodes_deep_8616(node))
    for candidate in nodes:
        if isinstance(
            candidate,
            (
                structured_c.CAssignment,
                structured_c.CDirtyExpression,
                structured_c.CMultiStatementExpression,
            ),
        ):
            return False
        if isinstance(candidate, structured_c.CFunctionCall) and not is_structured_insert_intrinsic_8616(candidate):
            return False
    return True


def _expression_width_bits_8616(expression: object) -> int | None:
    """Return the positive typed width of one structured expression."""
    expression_type = expression.type if isinstance(expression, structured_c.CExpression) else None
    if not isinstance(expression_type, SimType):
        return None
    try:
        width = expression_type.size
    except (AttributeError, ValueError):
        return None
    return width if isinstance(width, int) and width > 0 else None


def _insert_value_width_bits_8616(value: object) -> int | None:
    """Return the inserted field width, including typed segment helpers."""
    if isinstance(value, structured_c.CFunctionCall) and isinstance(value.callee_target, str):
        helper_width = {
            "SEG_U8": 8,
            "SEG_U16": 16,
            "SEG_U32": 32,
        }.get(value.callee_target.upper())
        if helper_width is not None:
            return helper_width
    return _expression_width_bits_8616(value)


def _decoded_insert_operands_8616(
    call: structured_c.CFunctionCall,
) -> tuple[object, int, object, int, int] | None:
    """Validate Insert operands; return (base, shift, value, base_width, value_width)."""
    raw_args: object = call.args
    if not isinstance(raw_args, (list, tuple)):
        return None
    args: tuple[object, ...] = tuple(raw_args)
    if len(args) != 3:
        return None
    base, offset, value = args
    if not isinstance(offset, structured_c.CConstant) or not isinstance(offset.value, int):
        return None
    base_width = _expression_width_bits_8616(base)
    result_width = _expression_width_bits_8616(call)
    value_width = _insert_value_width_bits_8616(value)
    if value_width is None:
        return None
    candidate_widths = tuple(width for width in (base_width, result_width) if width is not None)
    if not candidate_widths:
        return None
    base_width = max(candidate_widths)
    if value_width > base_width:
        return None
    shift = offset.value * 8
    if shift < 0 or shift + value_width > base_width:
        return None
    return base, shift, value, base_width, value_width


def lower_structured_insert_call_8616(
    call: object,
) -> structured_c.CExpression | None:
    """Lower one x86 little-endian Insert intrinsic to exact bit operations."""
    if not is_structured_insert_intrinsic_8616(call):
        return None
    assert isinstance(call, structured_c.CFunctionCall)
    decoded = _decoded_insert_operands_8616(call)
    if decoded is None:
        return None
    base, shift, value, base_width, value_width = decoded

    base_type = base.type if isinstance(base, structured_c.CExpression) and isinstance(base.type, SimType) else None
    operation_type = base_type or SimTypeShort(False)
    full_mask = (1 << base_width) - 1
    value_mask = (1 << value_width) - 1
    field_mask = (value_mask << shift) & full_mask
    preserve_mask = full_mask ^ field_mask

    inserted: structured_c.CExpression = structured_c.CBinaryOp(
        "And",
        value,
        structured_c.CConstant(value_mask, operation_type, codegen=call.codegen),
        codegen=call.codegen,
    )
    if shift:
        inserted = structured_c.CBinaryOp(
            "Shl",
            inserted,
            structured_c.CConstant(shift, operation_type, codegen=call.codegen),
            codegen=call.codegen,
        )
    if preserve_mask == 0:
        return inserted
    preserved = structured_c.CBinaryOp(
        "And",
        base,
        structured_c.CConstant(preserve_mask, operation_type, codegen=call.codegen),
        codegen=call.codegen,
    )
    return structured_c.CBinaryOp("Or", preserved, inserted, codegen=call.codegen)


def lower_structured_insert_intrinsics_8616(codegen: object) -> bool:
    """Lower every complete typed Insert pseudo-call in one C function."""
    typed_codegen = cast(_CodegenStructuredIntrinsics8616, codegen)
    cfunc = typed_codegen.cfunc
    if cfunc is None or cfunc.statements is None:
        typed_codegen._inertia_structured_intrinsic_lowering_stats_8616 = (
            StructuredIntrinsicLoweringStats8616(0, 0, 0, 0, 0)
        )
        return False
    root = cfunc.statements

    raw_node_ids: set[int] = set()
    classified_node_ids: set[int] = set()
    materialized_node_ids: set[int] = set()

    def transform(node: object) -> object:
        if not is_structured_insert_intrinsic_8616(node):
            return node
        raw_node_ids.add(id(node))
        replacement = lower_structured_insert_call_8616(node)
        if replacement is None:
            return node
        classified_node_ids.add(id(node))
        materialized_node_ids.add(id(node))
        return replacement

    new_root = transform(root)
    changed = new_root is not root
    if changed:
        cfunc.statements = new_root
    if _replace_c_children_8616(cfunc.statements, transform):
        changed = True
    classified_count = len(classified_node_ids)
    materialized_count = len(materialized_node_ids)
    typed_codegen._inertia_structured_intrinsic_lowering_stats_8616 = (
        StructuredIntrinsicLoweringStats8616(
            raw_fact_count=len(raw_node_ids),
            normalized_fact_count=len(raw_node_ids),
            classified_fact_count=classified_count,
            materialized_count=materialized_count,
            failure_count=max(classified_count - materialized_count, 0),
        )
    )
    return changed


def _cvariable_is_unread_elsewhere_8616(
    lhs: structured_c.CVariable,
    identity_occurrence_counts: Mapping[int, int],
) -> bool:
    """Return whether one exact variable identity has no other AST occurrence."""
    identity = lhs.unified_variable or lhs.variable
    return identity_occurrence_counts.get(id(identity), 0) <= 1


def _unused_insert_statement_8616(
    statement: object,
    identity_occurrence_counts: Mapping[int, int],
) -> structured_c.CFunctionCall | None:
    """Return a pure standalone Insert intrinsic, otherwise refuse it."""
    if isinstance(statement, structured_c.CExpressionStatement):
        expression = statement.expr
    elif (
        isinstance(statement, structured_c.CAssignment)
        and isinstance(statement.lhs, structured_c.CVariable)
        and _cvariable_is_unread_elsewhere_8616(statement.lhs, identity_occurrence_counts)
    ):
        expression = statement.rhs
    else:
        expression = statement
    if not is_structured_insert_intrinsic_8616(expression):
        return None
    assert isinstance(expression, structured_c.CFunctionCall)
    raw_args: object = expression.args
    if not isinstance(raw_args, (list, tuple)):
        return None
    if not all(_expression_is_side_effect_free_8616(argument) for argument in raw_args):
        return None
    return expression


def _insert_identity_occurrence_counts_8616(root: object) -> dict[int, int]:
    """Count uses of each unified variable identity under the root."""
    counts: dict[int, int] = {}
    for node in _iter_c_node_occurrences_8616(root):
        if isinstance(node, structured_c.CVariable):
            identity = node.unified_variable or node.variable
            identity_id = id(identity)
            counts[identity_id] = counts.get(identity_id, 0) + 1
    return counts


def _insert_statement_lists_8616(root: object) -> list[structured_c.CStatements]:
    """Collect each distinct statement-list node reachable under the root."""
    statement_lists: list[structured_c.CStatements] = []
    seen_statement_list_ids: set[int] = set()
    for node in (root, *_iter_c_nodes_deep_8616(root)):
        if not isinstance(node, structured_c.CStatements) or id(node) in seen_statement_list_ids:
            continue
        seen_statement_list_ids.add(id(node))
        statement_lists.append(node)
    return statement_lists


def _prune_statement_list_8616(
    statements_node: structured_c.CStatements,
    identity_occurrence_counts: dict[int, int],
) -> tuple[int, int, bool]:
    """Drop unused Insert statements; return (raw, dropped, changed)."""
    raw_count = 0
    dropped_count = 0
    old_statements = list(statements_node.statements or ())
    new_statements: list[object] = []
    for statement in old_statements:
        if isinstance(statement, structured_c.CExpressionStatement):
            expression = statement.expr
        elif isinstance(statement, structured_c.CAssignment):
            expression = statement.rhs
        else:
            expression = statement
        if is_structured_insert_intrinsic_8616(expression):
            raw_count += 1
        intrinsic = _unused_insert_statement_8616(statement, identity_occurrence_counts)
        if intrinsic is None:
            new_statements.append(statement)
            continue
        dropped_count += 1
    if len(new_statements) != len(old_statements):
        statements_node.statements = new_statements
        return raw_count, dropped_count, True
    return raw_count, dropped_count, False


def prune_unused_structured_insert_intrinsics_8616(codegen: object) -> bool:
    """Remove pure standalone Insert pseudo-calls whose values are unused."""
    typed_codegen = cast(_CodegenStructuredIntrinsics8616, codegen)
    cfunc = typed_codegen.cfunc
    root = cfunc.statements if cfunc is not None else None
    if root is None:
        typed_codegen._inertia_structured_intrinsic_lowering_stats_8616 = (
            StructuredIntrinsicLoweringStats8616(0, 0, 0, 0, 0)
        )
        return False

    raw_count = 0
    classified_count = 0
    changed = False
    identity_occurrence_counts = _insert_identity_occurrence_counts_8616(root)
    for statements_node in _insert_statement_lists_8616(root):
        raw, dropped, list_changed = _prune_statement_list_8616(
            statements_node,
            identity_occurrence_counts,
        )
        raw_count += raw
        classified_count += dropped
        changed = changed or list_changed
    materialized_count = classified_count

    typed_codegen._inertia_structured_intrinsic_lowering_stats_8616 = (
        StructuredIntrinsicLoweringStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=raw_count,
            classified_fact_count=classified_count,
            materialized_count=materialized_count,
            failure_count=max(classified_count - materialized_count, 0),
        )
    )
    return changed
