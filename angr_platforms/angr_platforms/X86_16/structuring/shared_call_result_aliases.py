"""Own regenerated aliases of one proven call-result store.

Layer: Structuring.
Responsibility: keep one exact machine-call occurrence and rewrite later identity-shared assignments as proven stack copies.

Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.

This owner consumes a Lowering-produced ``CallsiteSummary8616`` and exact C AST structure. It does not
infer return storage, delete assignments, compare rendered C, or recover calls by target name. Missing
or conflicting evidence is an explicit refusal, leaving strict validation to reject duplicate calls.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBreak,
    CFunctionCall,
    CGoto,
    CReturn,
    CStatements,
    CTypeCast,
    CVariable,
)
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _clone_c_ast_tree_8616, _iter_c_nodes_deep_8616
from ..callsite_summary import CallsiteSummary8616
from ..lowering.stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616

logger: logging.Logger = logging.getLogger(__name__)

__all__ = (
    "CallResultAliasOwnershipResult8616",
    "CallResultAliasOwnershipStats8616",
    "CallResultAliasOwnershipVerdict8616",
    "CallResultAliasRefusal8616",
    "CallResultAliasRefusalReason8616",
    "materialize_shared_call_result_aliases_8616",
)


class CallResultAliasOwnershipVerdict8616(Enum):
    """Typed outcome of one Structuring call-result alias pass."""

    MATERIALIZED = "materialized"
    NO_CANDIDATE = "no_candidate"
    UNKNOWN_REFUSE = "unknown_refuse"


class CallResultAliasRefusalReason8616(Enum):
    """Evidence failures that prevent call-result alias ownership."""

    DESTINATION_NOT_EXACT_STACK = "destination_not_exact_stack"
    DESTINATION_NOT_UNIQUE = "destination_not_unique"
    STRUCTURED_ORDER_UNKNOWN = "structured_order_unknown"
    INTERVENING_EFFECT_CONFLICT = "intervening_effect_conflict"


@dataclass(frozen=True, slots=True)
class CallResultAliasRefusal8616:
    """One exact callsite whose regenerated aliases cannot be owned."""

    callsite_addr: int
    reason: CallResultAliasRefusalReason8616


@dataclass(slots=True)
class CallResultAliasOwnershipStats8616:
    """Closed evidence counters for regenerated call-result aliases."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    rewritten_assignment_count: int = 0


@dataclass(frozen=True, slots=True)
class CallResultAliasOwnershipResult8616:
    """Typed result published by the Structuring alias owner."""

    verdict: CallResultAliasOwnershipVerdict8616
    stats: CallResultAliasOwnershipStats8616
    refusals: tuple[CallResultAliasRefusal8616, ...]

    @property
    def changed(self) -> bool:
        """Return whether at least one alias assignment was rewritten."""
        return self.stats.materialized_count > 0


class _CFunctionSurface8616(Protocol):
    """Third-party C function fields consumed by this Structuring owner."""

    statements: object


class _CodegenSurface8616(Protocol):
    """Owned and third-party codegen fields consumed or published here."""

    cfunc: _CFunctionSurface8616
    _inertia_callsite_summaries: dict[int, CallsiteSummary8616]
    _inertia_call_result_alias_ownership_8616: CallResultAliasOwnershipResult8616


@dataclass(frozen=True, slots=True)
class _DirectCallAssignmentOccurrence8616:
    """One direct call assignment at an exact structured-list position."""

    call: CFunctionCall
    assignment: CAssignment
    parent: CStatements
    statement_index: int


def _canonical_stack_offset_8616(offset: int) -> int:
    """Normalize one 16-bit BP displacement to signed storage identity."""
    normalized = offset & 0xFFFF
    return normalized - 0x10000 if normalized >= 0x8000 else normalized


def _exact_bp_destination_8616(destination: object, width: object) -> bool:
    """Return whether the pair is an exact ``("bp", int-offset)`` + positive width."""
    return (
        isinstance(destination, tuple)
        and len(destination) == 2
        and destination[0] == "bp"
        and isinstance(destination[1], int)
        and isinstance(width, int)
        and width > 0
    )


def _is_exact_summary_destination_8616(
    codegen: object,
    expression: object,
    summary: CallsiteSummary8616,
) -> bool:
    """Match one C lvalue to the summary's exact BP-relative destination."""
    destination = summary.return_store_destination
    width = summary.return_store_width
    current = expression
    while isinstance(current, CTypeCast):
        current = current.expr
    if not (
        _exact_bp_destination_8616(destination, width)
        and isinstance(current, CVariable)
        and isinstance(current.variable, SimStackVariable)
    ):
        return False
    assert isinstance(destination, tuple) and isinstance(width, int)
    variable = current.variable
    machine_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
    return (
        variable.base == "bp"
        and isinstance(machine_offset, int)
        and _canonical_stack_offset_8616(machine_offset) == _canonical_stack_offset_8616(destination[1])
        and int(variable.size) == width
    )


def _direct_call_assignments_8616(
    root: CStatements,
) -> dict[int, tuple[CFunctionCall, tuple[_DirectCallAssignmentOccurrence8616, ...]]]:
    """Group physical assignment occurrences by exact shared call identity."""
    grouped: dict[int, tuple[CFunctionCall, list[_DirectCallAssignmentOccurrence8616]]] = {}
    for parent in _iter_c_nodes_deep_8616(root):
        if not isinstance(parent, CStatements) or not isinstance(parent.statements, list):
            continue
        for statement_index, statement in enumerate(parent.statements):
            if not isinstance(statement, CAssignment) or not isinstance(statement.rhs, CFunctionCall):
                continue
            call = statement.rhs
            prior = grouped.get(id(call))
            occurrences = prior[1] if prior is not None else []
            occurrences.append(
                _DirectCallAssignmentOccurrence8616(call, statement, parent, statement_index)
            )
            grouped[id(call)] = (call, occurrences)
    return {
        call_id: (call, tuple(occurrences))
        for call_id, (call, occurrences) in grouped.items()
    }


def _structured_alias_refusal_8616(
    codegen: object,
    owner: _DirectCallAssignmentOccurrence8616,
    alias: _DirectCallAssignmentOccurrence8616,
    summary: CallsiteSummary8616,
) -> CallResultAliasRefusalReason8616 | None:
    """Return why one structured alias is not dominated by its result owner."""
    if alias.parent is not owner.parent or alias.statement_index <= owner.statement_index:
        return CallResultAliasRefusalReason8616.STRUCTURED_ORDER_UNKNOWN
    intervening = owner.parent.statements[owner.statement_index + 1 : alias.statement_index]
    for statement in intervening:
        for node in _iter_c_nodes_deep_8616(statement):
            if isinstance(node, CAssignment) and _is_exact_summary_destination_8616(
                codegen, node.lhs, summary
            ):
                return CallResultAliasRefusalReason8616.INTERVENING_EFFECT_CONFLICT
            if isinstance(node, CFunctionCall) and node is not owner.call:
                return CallResultAliasRefusalReason8616.INTERVENING_EFFECT_CONFLICT
            if isinstance(node, (CBreak, CGoto, CReturn)):
                return CallResultAliasRefusalReason8616.INTERVENING_EFFECT_CONFLICT
    return None


def _refuse_8616(
    stats: CallResultAliasOwnershipStats8616,
    refusals: list[CallResultAliasRefusal8616],
    summary: CallsiteSummary8616,
    reason: CallResultAliasRefusalReason8616,
) -> None:
    """Record one typed refusal without mutating the structured AST."""
    stats.failure_count += 1
    refusals.append(CallResultAliasRefusal8616(summary.callsite_addr, reason))


def _process_call_group_8616(
    codegen: object,
    summary: CallsiteSummary8616,
    occurrences: tuple[_DirectCallAssignmentOccurrence8616, ...],
    stats: CallResultAliasOwnershipStats8616,
    refusals: list[CallResultAliasRefusal8616],
) -> None:
    """Apply the alias-ownership evidence ladder to one call group."""
    stats.raw_fact_count += 1
    if not _exact_bp_destination_8616(
        summary.return_store_destination,
        summary.return_store_width,
    ):
        _refuse_8616(
            stats,
            refusals,
            summary,
            CallResultAliasRefusalReason8616.DESTINATION_NOT_EXACT_STACK,
        )
        return
    stats.normalized_fact_count += 1
    destinations = tuple(
        occurrence
        for occurrence in occurrences
        if _is_exact_summary_destination_8616(codegen, occurrence.assignment.lhs, summary)
    )
    if len(destinations) != 1:
        _refuse_8616(
            stats,
            refusals,
            summary,
            CallResultAliasRefusalReason8616.DESTINATION_NOT_UNIQUE,
        )
        return
    owner = destinations[0]
    aliases = tuple(occurrence for occurrence in occurrences if occurrence is not owner)
    refusal_reason = next(
        (
            reason
            for alias in aliases
            if (reason := _structured_alias_refusal_8616(codegen, owner, alias, summary))
            is not None
        ),
        None,
    )
    if refusal_reason is not None:
        _refuse_8616(
            stats,
            refusals,
            summary,
            refusal_reason,
        )
        return
    stats.classified_fact_count += 1
    rewritten_assignments: set[int] = set()
    for alias in aliases:
        assignment = alias.assignment
        if id(assignment) in rewritten_assignments:
            continue
        assignment.rhs = cast(CVariable, _clone_c_ast_tree_8616(owner.assignment.lhs))
        rewritten_assignments.add(id(assignment))
        stats.rewritten_assignment_count += 1
    stats.materialized_count += 1


def materialize_shared_call_result_aliases_8616(
    codegen: object,
) -> CallResultAliasOwnershipResult8616:
    """Replace later aliases of one exact stored call result with value copies."""
    boundary = cast(_CodegenSurface8616, codegen)
    stats = CallResultAliasOwnershipStats8616()
    refusals: list[CallResultAliasRefusal8616] = []
    try:
        root = boundary.cfunc.statements
        summary_map = boundary._inertia_callsite_summaries
    except AttributeError:
        result = CallResultAliasOwnershipResult8616(
            CallResultAliasOwnershipVerdict8616.NO_CANDIDATE,
            stats,
            (),
        )
        boundary._inertia_call_result_alias_ownership_8616 = result
        return result
    if not isinstance(root, CStatements):
        result = CallResultAliasOwnershipResult8616(
            CallResultAliasOwnershipVerdict8616.NO_CANDIDATE,
            stats,
            (),
        )
        boundary._inertia_call_result_alias_ownership_8616 = result
        return result
    if not isinstance(summary_map, dict) or any(
        not isinstance(key, int) or not isinstance(summary, CallsiteSummary8616)
        for key, summary in summary_map.items()
    ):
        raise TypeError("callsite summary carrier contains an invalid owned contract")

    debug_groups: list[tuple[object, ...]] = []
    for call_id, (_call, occurrences) in _direct_call_assignments_8616(root).items():
        summary = summary_map.get(call_id)
        debug_groups.append(
            (
                None if summary is None else summary.callsite_addr,
                len(occurrences),
                None if summary is None else summary.return_used,
                None if summary is None else summary.return_store_destination,
                None if summary is None else summary.return_store_width,
                tuple(
                    (id(occurrence.parent), occurrence.statement_index)
                    for occurrence in occurrences
                ),
                tuple(
                    False
                    if summary is None
                    else _is_exact_summary_destination_8616(
                        codegen, occurrence.assignment.lhs, summary
                    )
                    for occurrence in occurrences
                ),
            )
        )
        if summary is None or summary.return_used is not True or len(occurrences) < 2:
            continue
        _process_call_group_8616(codegen, summary, occurrences, stats, refusals)

    verdict = (
        CallResultAliasOwnershipVerdict8616.UNKNOWN_REFUSE
        if stats.failure_count
        else CallResultAliasOwnershipVerdict8616.MATERIALIZED
        if stats.materialized_count
        else CallResultAliasOwnershipVerdict8616.NO_CANDIDATE
    )
    result = CallResultAliasOwnershipResult8616(verdict, stats, tuple(refusals))
    boundary._inertia_call_result_alias_ownership_8616 = result
    if os.environ.get("INERTIA_DEBUG_SHARED_CALL_RESULT_ALIASES") or os.environ.get(
        "INERTIA_DEBUG_CALL_MATERIALIZATION"
    ):
        logger.warning(
            "[shared-call-result-aliases] verdict=%s stats=%r refusals=%r groups=%r",
            result.verdict.value,
            result.stats,
            result.refusals,
            tuple(debug_groups),
        )
    return result
