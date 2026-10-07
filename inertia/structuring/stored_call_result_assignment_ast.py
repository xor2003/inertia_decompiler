"""Locate structured statements carrying one stored call result.

Layer: Structuring.
Responsibility: project exact structured call occurrences from assigned and
standalone C-AST statements without interpreting rendered C text.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.

The projection accepts a call nested in a register-lane expression only when
that assignment contains exactly one call. The consuming owner must still
prove the return register and destination from typed callsite evidence before
mutating the AST.
"""

from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
)

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.pipeline.errors import PipelineHardError
from inertia.semantics.callsite_summary import CallsiteSummary8616, structured_callsite_addr_8616


@dataclass(frozen=True, slots=True)
class StoredCallResultAssignmentOccurrence8616:
    """One uniquely carried structured call at an exact statement position."""

    call: CFunctionCall
    statement: CAssignment | CExpressionStatement
    parent: CStatements
    index: int


def _statement_containers_8616(root: object) -> tuple[CStatements, ...]:
    """Return identity-deduplicated statement containers in traversal order."""
    return tuple(
        {
            id(node): node
            for node in (root, *_iter_c_nodes_deep_8616(root))
            if isinstance(node, CStatements)
        }.values()
    )


def stored_call_result_assignment_occurrences_8616(
    root: object,
) -> tuple[StoredCallResultAssignmentOccurrence8616, ...]:
    """Collect statements that carry exactly one structured call expression."""
    occurrences: list[StoredCallResultAssignmentOccurrence8616] = []
    for parent in _statement_containers_8616(root):
        for index, statement in enumerate(tuple(parent.statements or ())):
            if isinstance(statement, CExpressionStatement):
                calls = (statement.expr,) if isinstance(statement.expr, CFunctionCall) else ()
            elif isinstance(statement, CAssignment):
                calls = tuple(
                    {
                        id(call): call
                        for call in (
                            statement.rhs,
                            *_iter_c_nodes_deep_8616(statement.rhs),
                        )
                        if isinstance(call, CFunctionCall)
                    }.values()
                )
            else:
                calls = ()
            if len(calls) == 1:
                occurrences.append(
                    StoredCallResultAssignmentOccurrence8616(
                        calls[0], statement, parent, index
                    )
                )
    return tuple(occurrences)


def _summary_evidence_key_8616(summary: CallsiteSummary8616) -> tuple[object, ...]:
    """Return the summary fields authoritative for one stored result."""
    return (
        summary.callsite_addr,
        summary.target_addr,
        summary.return_used,
        summary.return_use_kind,
        summary.return_register,
        summary.return_store_destination,
        summary.return_store_width,
        summary.return_store_instruction_addr,
    )


def stored_call_result_summary_for_occurrence_8616(
    call: CFunctionCall,
    summary_map: dict[int, CallsiteSummary8616],
) -> CallsiteSummary8616 | None:
    """Resolve one call summary across structured-AST regeneration."""
    callsite_addr = structured_callsite_addr_8616(call)
    identity_summary = summary_map.get(id(call))
    if identity_summary is not None:
        if isinstance(callsite_addr, int) and identity_summary.callsite_addr != callsite_addr:
            raise PipelineHardError(
                "stored call-result summary identity conflicts with structured callsite tag"
            )
        return identity_summary
    if not isinstance(callsite_addr, int):
        return None
    candidates = tuple(
        summary for summary in summary_map.values() if summary.callsite_addr == callsite_addr
    )
    evidence = {_summary_evidence_key_8616(summary) for summary in candidates}
    return candidates[0] if candidates and len(evidence) == 1 else None


__all__ = (
    "StoredCallResultAssignmentOccurrence8616",
    "stored_call_result_assignment_occurrences_8616",
    "stored_call_result_summary_for_occurrence_8616",
)
