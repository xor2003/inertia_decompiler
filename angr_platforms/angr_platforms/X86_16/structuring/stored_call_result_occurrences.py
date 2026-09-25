"""Own regenerated standalone calls superseded by exact result stores.

Layer: Structuring.
Responsibility: Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Retain one physical C call occurrence when Lowering proves that one exact
machine callsite materializes its return value into one exact object.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.
This owner consumes typed callsite summaries and structured C-AST order. It never
infers storage from names or rendered text. Missing, conflicting, or nonadjacent
evidence is an explicit refusal and leaves strict validation to reject the
duplicate.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CTypeCast,
    CVariable,
)
from angr.sim_variable import SimMemoryVariable, SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from ..callsite_summary import CallsiteSummary8616, structured_callsite_addr_8616
from ..pipeline.errors import PipelineHardError
from .stored_call_result_contracts import (
    StoredCallResultOccurrenceResult8616,
    StoredCallResultOccurrenceStats8616,
    StoredCallResultOccurrenceVerdict8616,
    StoredCallResultRefusal8616,
    StoredCallResultRefusalReason8616,
)

__all__ = ("materialize_stored_call_result_occurrences_8616",)


class _CFunctionSurface8616(Protocol):
    """Third-party C function fields consumed by this Structuring owner."""

    statements: object


class _CodegenSurface8616(Protocol):
    """Owned and third-party codegen fields consumed or published here."""

    cfunc: _CFunctionSurface8616
    _inertia_callsite_summaries: dict[int, CallsiteSummary8616]
    _inertia_stored_call_result_occurrences_8616: StoredCallResultOccurrenceResult8616


@dataclass(frozen=True, slots=True)
class _DirectCallOccurrence8616:
    """One direct standalone or assigned call at an exact list position."""

    call: CFunctionCall
    statement: CExpressionStatement | CAssignment
    parent: CStatements
    statement_index: int

    @property
    def is_standalone(self) -> bool:
        """Return whether this occurrence evaluates a discarded call result."""
        return isinstance(self.statement, CExpressionStatement)


def _canonical_stack_offset_8616(offset: int) -> int:
    """Normalize one 16-bit BP displacement to signed storage identity."""
    normalized = offset & 0xFFFF
    return normalized - 0x10000 if normalized >= 0x8000 else normalized


def _exact_object_destination_8616(destination: object, width: object) -> bool:
    """Return whether the pair is an exact ``(str-base, int-offset)`` + positive width."""
    return (
        isinstance(destination, tuple)
        and len(destination) == 2
        and isinstance(destination[0], str)
        and isinstance(destination[1], int)
        and isinstance(width, int)
        and width > 0
    )


def _is_exact_summary_destination_8616(expression: object, summary: CallsiteSummary8616) -> bool:
    """Match one C lvalue to the summary's exact object and width."""
    current = expression
    while isinstance(current, CTypeCast):
        current = current.expr
    if not isinstance(current, CVariable):
        return False
    destination = summary.return_store_destination
    width = summary.return_store_width
    if not _exact_object_destination_8616(destination, width):
        return False
    assert isinstance(destination, tuple) and isinstance(width, int)
    variable = current.variable
    if destination[0] == "bp" and isinstance(variable, SimStackVariable):
        return (
            variable.base == "bp"
            and isinstance(variable.offset, int)
            and _canonical_stack_offset_8616(variable.offset)
            == _canonical_stack_offset_8616(destination[1])
            and int(variable.size) == width
        )
    return (
        destination[0] == "global"
        and isinstance(variable, SimMemoryVariable)
        and not isinstance(variable, SimStackVariable)
        and isinstance(variable.addr, int)
        and variable.addr == destination[1]
        and int(variable.size) == width
    )


def _statement_containers_8616(root: object) -> tuple[CStatements, ...]:
    """Return identity-deduplicated statement containers in one C AST."""
    return tuple(
        {
            id(node): node
            for node in (root, *_iter_c_nodes_deep_8616(root))
            if isinstance(node, CStatements)
        }.values()
    )


def _direct_occurrences_8616(root: object) -> dict[int, list[_DirectCallOccurrence8616]]:
    """Group direct call statements by exact machine callsite tag."""
    grouped: defaultdict[int, list[_DirectCallOccurrence8616]] = defaultdict(list)
    for parent in _statement_containers_8616(root):
        for index, statement in enumerate(tuple(parent.statements or ())):
            call: CFunctionCall | None = None
            if isinstance(statement, CExpressionStatement) and isinstance(
                statement.expr,
                CFunctionCall,
            ):
                call = statement.expr
            elif isinstance(statement, CAssignment) and isinstance(
                statement.rhs,
                CFunctionCall,
            ):
                call = statement.rhs
            if call is None:
                continue
            callsite_addr = structured_callsite_addr_8616(call)
            if isinstance(callsite_addr, int):
                grouped[callsite_addr].append(
                    _DirectCallOccurrence8616(call, statement, parent, index)
                )
    return dict(grouped)


def _summary_evidence_key_8616(summary: CallsiteSummary8616) -> tuple[object, ...]:
    """Return the exact summary facts needed by this ownership decision."""
    return (
        summary.callsite_addr,
        summary.target_addr,
        summary.return_used,
        summary.return_store_destination,
        summary.return_store_width,
    )


def _unique_summary_inventory_8616(summary_map: dict[int, CallsiteSummary8616]) -> dict[int, CallsiteSummary8616]:
    """Return callsites whose stored-result evidence is complete and unique."""
    grouped: defaultdict[int, list[CallsiteSummary8616]] = defaultdict(list)
    for summary in summary_map.values():
        grouped[summary.callsite_addr].append(summary)
    return {
        callsite_addr: summaries[0]
        for callsite_addr, summaries in grouped.items()
        if len({_summary_evidence_key_8616(summary) for summary in summaries}) == 1
    }


def _contains_identity_8616(root: object, target: object) -> bool:
    """Return whether one structured subtree contains an exact target node."""
    return root is target or any(node is target for node in _iter_c_nodes_deep_8616(root))


def _has_unique_adjacent_order_witness_8616(
    root: object,
    standalone: _DirectCallOccurrence8616,
    assignment: _DirectCallOccurrence8616,
) -> bool:
    """Prove that the discarded call immediately precedes its stored result."""
    if standalone.parent is assignment.parent:
        return assignment.statement_index == standalone.statement_index + 1
    if len(tuple(standalone.parent.statements or ())) != 1 or len(
        tuple(assignment.parent.statements or ())
    ) != 1:
        return False
    witnesses = 0
    for container in _statement_containers_8616(root):
        statements = tuple(container.statements or ())
        standalone_indices = tuple(
            index
            for index, statement in enumerate(statements)
            if _contains_identity_8616(statement, standalone.statement)
        )
        assignment_indices = tuple(
            index
            for index, statement in enumerate(statements)
            if _contains_identity_8616(statement, assignment.statement)
        )
        if (
            len(standalone_indices) == 1
            and len(assignment_indices) == 1
            and assignment_indices[0] == standalone_indices[0] + 1
        ):
            witnesses += 1
    return witnesses == 1


def _same_call_surface_8616(
    standalone: CFunctionCall,
    assignment: CFunctionCall,
) -> bool:
    """Compare exact argument values on two clones of one typed callsite."""
    standalone_args = tuple(standalone.args or ())
    assignment_args = tuple(assignment.args or ())
    return len(standalone_args) == len(assignment_args) and all(
        _same_c_expression_8616(lhs, rhs)
        for lhs, rhs in zip(standalone_args, assignment_args, strict=True)
    )


def _refuse_8616(
    stats: StoredCallResultOccurrenceStats8616,
    refusals: list[StoredCallResultRefusal8616],
    callsite_addr: int,
    reason: StoredCallResultRefusalReason8616,
) -> None:
    """Record one typed fail-closed ownership refusal."""
    stats.failure_count += 1
    refusals.append(StoredCallResultRefusal8616(callsite_addr, reason))


def _remove_standalone_8616(occurrence: _DirectCallOccurrence8616) -> None:
    """Remove one still-uniquely-owned standalone statement or hard-fail."""
    statements = list(occurrence.parent.statements or ())
    matching_indices = tuple(
        index for index, statement in enumerate(statements) if statement is occurrence.statement
    )
    if len(matching_indices) != 1:
        raise PipelineHardError("classified stored-call occurrence lost unique ownership")
    del statements[matching_indices[0]]
    occurrence.parent.statements = statements


def _process_callsite_8616(
    root: object,
    callsite_addr: int,
    occurrences: list[_DirectCallOccurrence8616],
    standalone: tuple[_DirectCallOccurrence8616, ...],
    assigned: tuple[_DirectCallOccurrence8616, ...],
    summary_inventory: dict[int, CallsiteSummary8616],
    summary_map: dict[int, CallsiteSummary8616],
    stats: StoredCallResultOccurrenceStats8616,
    refusals: list[StoredCallResultRefusal8616],
) -> None:
    """Apply the clone-removal evidence ladder to one callsite group."""
    stats.raw_fact_count += 1
    if len(occurrences) != 2 or len(standalone) != 1 or len(assigned) != 1:
        _refuse_8616(
            stats,
            refusals,
            callsite_addr,
            StoredCallResultRefusalReason8616.OCCURRENCE_SET_AMBIGUOUS,
        )
        return
    summary = summary_inventory.get(callsite_addr)
    if summary is None:
        _refuse_8616(
            stats,
            refusals,
            callsite_addr,
            StoredCallResultRefusalReason8616.SUMMARY_MISSING_OR_CONFLICTING,
        )
        return
    assignment_statement = assigned[0].statement
    if (
        summary.return_used is not True
        or not isinstance(assignment_statement, CAssignment)
        or not _is_exact_summary_destination_8616(assignment_statement.lhs, summary)
    ):
        _refuse_8616(
            stats,
            refusals,
            callsite_addr,
            StoredCallResultRefusalReason8616.RETURN_STORE_NOT_PROVEN,
        )
        return
    stats.normalized_fact_count += 1
    if not _same_call_surface_8616(standalone[0].call, assigned[0].call):
        _refuse_8616(
            stats,
            refusals,
            callsite_addr,
            StoredCallResultRefusalReason8616.CALL_SURFACE_CONFLICT,
        )
        return
    if not _has_unique_adjacent_order_witness_8616(root, standalone[0], assigned[0]):
        _refuse_8616(
            stats,
            refusals,
            callsite_addr,
            StoredCallResultRefusalReason8616.STRUCTURED_ORDER_UNKNOWN,
        )
        return
    stats.classified_fact_count += 1
    _remove_standalone_8616(standalone[0])
    summary_map[id(assigned[0].call)] = summary
    if standalone[0].call is not assigned[0].call:
        summary_map.pop(id(standalone[0].call), None)
    stats.materialized_count += 1
    stats.removed_standalone_count += 1


def materialize_stored_call_result_occurrences_8616(
    codegen: object,
) -> StoredCallResultOccurrenceResult8616:
    """Remove only a proven adjacent standalone clone of one stored call."""
    boundary = cast(_CodegenSurface8616, codegen)
    stats = StoredCallResultOccurrenceStats8616()
    refusals: list[StoredCallResultRefusal8616] = []
    try:
        root = boundary.cfunc.statements
        summary_map = boundary._inertia_callsite_summaries
    except AttributeError:
        result = StoredCallResultOccurrenceResult8616(
            StoredCallResultOccurrenceVerdict8616.NO_CANDIDATE,
            stats,
            (),
        )
        boundary._inertia_stored_call_result_occurrences_8616 = result
        return result
    if not isinstance(summary_map, dict) or any(
        not isinstance(key, int) or not isinstance(summary, CallsiteSummary8616)
        for key, summary in summary_map.items()
    ):
        raise TypeError("callsite summary carrier contains an invalid owned contract")

    summary_inventory = _unique_summary_inventory_8616(summary_map)
    for callsite_addr, occurrences in sorted(_direct_occurrences_8616(root).items()):
        standalone = tuple(occurrence for occurrence in occurrences if occurrence.is_standalone)
        assigned = tuple(occurrence for occurrence in occurrences if not occurrence.is_standalone)
        if not standalone or not assigned:
            continue
        _process_callsite_8616(
            root,
            callsite_addr,
            occurrences,
            standalone,
            assigned,
            summary_inventory,
            summary_map,
            stats,
            refusals,
        )

    verdict = (
        StoredCallResultOccurrenceVerdict8616.UNKNOWN_REFUSE
        if stats.failure_count
        else StoredCallResultOccurrenceVerdict8616.MATERIALIZED
        if stats.materialized_count
        else StoredCallResultOccurrenceVerdict8616.NO_CANDIDATE
    )
    result = StoredCallResultOccurrenceResult8616(verdict, stats, tuple(refusals))
    boundary._inertia_stored_call_result_occurrences_8616 = result
    return result
