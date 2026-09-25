"""Fold exact byte-lane recompositions at the Widening layer.

Layer: Widening.
Responsibility: replace a complete low/high-byte projection with its shared
source only when Alias proves the assignment destination is exactly one word,
and elide the resulting identity assignment when source and destination match.
Do not infer width from rendered C, names, compiler samples, or postprocess.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimTemporaryVariable

from ..c_ast_utils import (
    _clone_c_ast_tree_8616,
    _iter_c_nodes_deep_8616,
    _same_c_expression_8616,
)
from ..codegen_metadata import get_codegen_side_metadata
from ..pipeline.errors import PipelineHardError
from ..semantics.alias_query import describe_alias_storage
from ..semantics.expression_analysis import describe_virtual_value_identity_8616


@dataclass(slots=True)
class WordProjectionRecompositionStats8616:
    """Closed evidence counters for word-projection recomposition."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    identity_elided_count: int = 0


class _CFunctionSurface8616(Protocol):
    """Narrowed current-angr C function contract used by Widening."""

    statements: object


class _CodegenSurface8616(Protocol):
    """Narrowed current-angr codegen contract used by Widening."""

    cfunc: _CFunctionSurface8616


def _unwrap_casts_8616(node: object) -> object:
    """Remove syntax-only casts from a structured expression."""
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _constant_is_8616(node: object, expected: int) -> bool:
    """Return whether a structured node is one exact integer constant."""
    node = _unwrap_casts_8616(node)
    return (
        isinstance(node, structured_c.CConstant)
        and isinstance(node.value, int)
        and node.value == expected
    )


def _masked_byte_source_8616(node: object) -> object | None:
    """Return the source beneath one or more exact low-byte masks."""
    current = _unwrap_casts_8616(node)
    masked = False
    while isinstance(current, structured_c.CBinaryOp) and current.op == "And":
        if _constant_is_8616(current.rhs, 0xFF):
            current = _unwrap_casts_8616(current.lhs)
            masked = True
            continue
        if _constant_is_8616(current.lhs, 0xFF):
            current = _unwrap_casts_8616(current.rhs)
            masked = True
            continue
        break
    return current if masked else None


def _high_byte_source_8616(node: object) -> object | None:
    """Return the source of one exact high-byte projection."""
    node = _unwrap_casts_8616(node)
    if (
        not isinstance(node, structured_c.CBinaryOp)
        or node.op != "Shl"
        or not _constant_is_8616(node.rhs, 8)
    ):
        return None
    shifted = _masked_byte_source_8616(node.lhs)
    shifted = _unwrap_casts_8616(shifted) if shifted is not None else None
    if (
        not isinstance(shifted, structured_c.CBinaryOp)
        or shifted.op != "Shr"
        or not _constant_is_8616(shifted.rhs, 8)
    ):
        return None
    return _unwrap_casts_8616(shifted.lhs)


def _word_projection_sources_8616(node: object) -> tuple[object, object] | None:
    """Return low/high sources from one complete 16-bit recomposition."""
    node = _unwrap_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Or":
        return None
    for low_node, high_node in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        low_source = _masked_byte_source_8616(low_node)
        high_source = _high_byte_source_8616(high_node)
        if low_source is not None and high_source is not None:
            return low_source, high_source
    return None


def _side_effect_free_source_8616(node: object) -> bool:
    """Accept only recursively pure value expressions for deduplication."""
    node = _unwrap_casts_8616(node)
    if isinstance(node, (structured_c.CConstant, structured_c.CVariable)):
        return True
    if isinstance(node, structured_c.CIndexedVariable):
        return _side_effect_free_source_8616(node.variable) and _side_effect_free_source_8616(
            node.index
        )
    if isinstance(node, structured_c.CBinaryOp):
        return _side_effect_free_source_8616(node.lhs) and _side_effect_free_source_8616(
            node.rhs
        )
    return False


def _word_destination_proven_8616(node: object) -> bool:
    """Return whether Alias or typed virtual identity proves one word destination."""
    facts = describe_alias_storage(node)
    if facts.domain.width == 2 and not facts.needs_synthesis():
        return True
    if (
        not isinstance(node, structured_c.CVariable)
        or not isinstance(node.variable, SimTemporaryVariable)
        or describe_virtual_value_identity_8616(node) is None
    ):
        return False
    try:
        return bool(node.type.size == 16)
    except (AttributeError, ValueError):
        return False


def _process_assignment_8616(
    assignment: structured_c.CAssignment,
    stats: WordProjectionRecompositionStats8616,
    identity_assignment_ids: set[int],
) -> None:
    """Fold one assignment when both word halves share one proven source."""
    sources = _word_projection_sources_8616(assignment.rhs)
    if sources is None:
        return
    stats.raw_fact_count += 1
    low_source, high_source = sources
    if not _same_c_expression_8616(low_source, high_source) or not _side_effect_free_source_8616(
        low_source
    ):
        stats.failure_count += 1
        return
    stats.normalized_fact_count += 1
    if not _word_destination_proven_8616(assignment.lhs):
        stats.failure_count += 1
        return
    stats.classified_fact_count += 1
    assignment.rhs = cast(structured_c.CExpression, _clone_c_ast_tree_8616(low_source))
    stats.materialized_count += 1
    if _same_c_expression_8616(assignment.lhs, low_source):
        identity_assignment_ids.add(id(assignment))


def _elide_identity_assignments_8616(
    root: object,
    identity_assignment_ids: set[int],
    stats: WordProjectionRecompositionStats8616,
) -> None:
    """Drop folded self-assignments from every statement container."""
    if not identity_assignment_ids:
        return
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, structured_c.CStatements):
            continue
        retained = [statement for statement in node.statements if id(statement) not in identity_assignment_ids]
        stats.identity_elided_count += len(node.statements) - len(retained)
        node.statements[:] = retained


def materialize_word_projection_recompositions_8616(codegen: object) -> bool:
    """Fold complete word projections while preserving destination truncation."""
    surface = cast(_CodegenSurface8616, codegen)
    try:
        root = surface.cfunc.statements
    except AttributeError:
        return False
    stats = WordProjectionRecompositionStats8616()
    assignments = tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, structured_c.CAssignment)
    )
    identity_assignment_ids: set[int] = set()
    for assignment in assignments:
        _process_assignment_8616(assignment, stats, identity_assignment_ids)
    _elide_identity_assignments_8616(root, identity_assignment_ids, stats)
    get_codegen_side_metadata(codegen)["word_projection_recomposition_8616"] = stats
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError(
            "classified word projection was not materialized",
            layer="widening",
        )
    return stats.materialized_count > 0


__all__ = [
    "WordProjectionRecompositionStats8616",
    "materialize_word_projection_recompositions_8616",
]
