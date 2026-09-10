"""Materialize exact stored call results as structured assignments.

Layer: Structuring.
Responsibility: bind one typed callsite return-store fact to an existing stack
variable and its exact structured call occurrence.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.

This owner consumes binary callsite summaries and C-AST storage identities. It
never infers destinations from names or rendered C. Missing or conflicting
storage evidence is an explicit refusal; rewrite and postprocess must not repair
the call assignment later. Retargeting a same-width scalar definition must
preserve its value immediately: later reads may outlive the destination slot.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from ..c_ast_utils import _clone_c_ast_tree_8616, _iter_c_nodes_deep_8616
from ..callsite_summary import CallsiteReturnUseKind8616, CallsiteSummary8616
from ..lowering.stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616
from .stored_call_result_assignment_ast import (
    stored_call_result_assignment_occurrences_8616,
    stored_call_result_summary_for_occurrence_8616,
)
from .stored_call_result_registers import is_stored_call_return_register_destination_8616

__all__ = ("materialize_stored_call_result_assignments_8616",)


class StoredCallResultAssignmentVerdict8616(StrEnum):
    """Typed outcome of stored call-result assignment materialization."""

    NO_CANDIDATE = "no_candidate"
    MATERIALIZED = "materialized"
    UNKNOWN_REFUSE = "unknown_refuse"


class StoredCallResultAssignmentRefusalReason8616(StrEnum):
    """Reason an exact binary return store was not bound to the C AST."""

    DESTINATION_VARIABLE_MISSING = "destination_variable_missing"
    RETURN_REGISTER_CONFLICT = "return_register_conflict"


@dataclass(frozen=True, slots=True)
class StoredCallResultAssignmentRefusal8616:
    """One refused callsite and its typed reason."""

    callsite_addr: int
    reason: StoredCallResultAssignmentRefusalReason8616


@dataclass(slots=True)
class StoredCallResultAssignmentStats8616:
    """Closed evidence-loop counters for stored call-result assignments."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class StoredCallResultAssignmentResult8616:
    """Materialization result published on the active code generator."""

    verdict: StoredCallResultAssignmentVerdict8616
    stats: StoredCallResultAssignmentStats8616
    refusals: tuple[StoredCallResultAssignmentRefusal8616, ...]

    @property
    def changed(self) -> bool:
        """Return whether at least one structured assignment was created."""
        return self.stats.materialized_count > 0


class _CFunctionSurface8616(Protocol):
    """Third-party structured function root consumed by this owner."""

    statements: object


class _CodegenSurface8616(Protocol):
    """Codegen fields consumed and published by this Structuring owner."""

    cfunc: _CFunctionSurface8616
    _inertia_callsite_summaries: dict[int, CallsiteSummary8616]
    _inertia_stored_call_result_assignments_8616: StoredCallResultAssignmentResult8616


def _canonical_stack_offset_8616(offset: int) -> int:
    """Normalize one 16-bit BP displacement to signed storage identity."""
    normalized = offset & 0xFFFF
    return normalized - 0x10000 if normalized >= 0x8000 else normalized


def _statement_containers_8616(root: object) -> tuple[CStatements, ...]:
    """Return identity-deduplicated statement containers in traversal order."""
    return tuple(
        {
            id(node): node
            for node in (root, *_iter_c_nodes_deep_8616(root))
            if isinstance(node, CStatements)
        }.values()
    )


def _store_artifacts_8616(
    root: object,
    store_ins_addr: int,
) -> tuple[tuple[CStatements, CAssignment], ...]:
    """Return store artifacts without consuming scalar register definitions."""
    artifacts: list[tuple[CStatements, CAssignment]] = []
    for parent in _statement_containers_8616(root):
        artifacts.extend(
            (parent, statement)
            for statement in tuple(parent.statements or ())
            if (
                isinstance(statement, CAssignment)
                and not (
                    isinstance(statement.lhs, CVariable)
                    and isinstance(statement.lhs.variable, SimRegisterVariable)
                )
                and not any(isinstance(node, CFunctionCall) for node in _iter_c_nodes_deep_8616(statement.rhs))
                and statement.tags.get("ins_addr") == store_ins_addr
            )
        )
    return tuple(artifacts)


def _stored_stack_destination_8616(summary: CallsiteSummary8616) -> tuple[int, int] | None:
    """Return one exact BP destination and width from a value-return summary."""
    destination = summary.return_store_destination
    width = summary.return_store_width
    if (
        summary.return_used is not True
        or summary.return_use_kind is not CallsiteReturnUseKind8616.VALUE
        or not isinstance(destination, tuple)
        or len(destination) != 2
        or destination[0] != "bp"
        or not isinstance(destination[1], int)
        or not isinstance(width, int)
        or width <= 0
    ):
        return None
    return _canonical_stack_offset_8616(destination[1]), width


def _stack_destination_variable_8616(
    codegen: object,
    root: object,
    destination: tuple[int, int],
) -> CVariable | None:
    """Find an existing C variable with the exact BP storage identity."""
    offset, width = destination
    matches: list[CVariable] = []
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CVariable) or not isinstance(node.variable, SimStackVariable):
            continue
        variable = node.variable
        if (
            variable.base == "bp"
            and machine_bp_offset_for_stack_variable_8616(codegen, variable) == offset
            and int(variable.size) == width
        ):
            matches.append(node)
    return matches[0] if matches else None


def _is_exact_stack_destination_8616(
    codegen: object,
    expression: object,
    destination: tuple[int, int],
) -> bool:
    """Return whether one C lvalue owns the exact BP storage identity."""
    if not isinstance(expression, CVariable) or not isinstance(expression.variable, SimStackVariable):
        return False
    variable = expression.variable
    return (
        variable.base == "bp"
        and machine_bp_offset_for_stack_variable_8616(codegen, variable) == destination[0]
        and int(variable.size) == destination[1]
    )


def _refuse_8616(
    stats: StoredCallResultAssignmentStats8616,
    refusals: list[StoredCallResultAssignmentRefusal8616],
    callsite_addr: int,
    reason: StoredCallResultAssignmentRefusalReason8616,
) -> None:
    """Record one typed refusal without mutating the C AST."""
    stats.failure_count += 1
    refusals.append(StoredCallResultAssignmentRefusal8616(callsite_addr, reason))


def materialize_stored_call_result_assignments_8616(
    codegen: object,
) -> StoredCallResultAssignmentResult8616:
    """Bind exact stored call results to existing BP stack variables."""
    boundary = cast(_CodegenSurface8616, codegen)
    stats = StoredCallResultAssignmentStats8616()
    refusals: list[StoredCallResultAssignmentRefusal8616] = []
    try:
        root = boundary.cfunc.statements
        summary_map = boundary._inertia_callsite_summaries
    except AttributeError:
        result = StoredCallResultAssignmentResult8616(
            StoredCallResultAssignmentVerdict8616.NO_CANDIDATE, stats, ()
        )
        boundary._inertia_stored_call_result_assignments_8616 = result
        return result
    if not isinstance(summary_map, dict) or any(
        not isinstance(key, int) or not isinstance(summary, CallsiteSummary8616)
        for key, summary in summary_map.items()
    ):
        raise TypeError("callsite summary carrier contains an invalid owned contract")

    artifacts_to_remove: dict[int, tuple[CStatements, CAssignment]] = {}
    owned_call_ids: set[int] = set()
    for occurrence in stored_call_result_assignment_occurrences_8616(root):
        call_id = id(occurrence.call)
        if call_id in owned_call_ids:
            continue
        summary = stored_call_result_summary_for_occurrence_8616(occurrence.call, summary_map)
        if summary is None:
            continue
        destination = _stored_stack_destination_8616(summary)
        if destination is None:
            continue
        if (
            isinstance(occurrence.statement, CAssignment)
            and _is_exact_stack_destination_8616(codegen, occurrence.statement.lhs, destination)
        ):
            owned_call_ids.add(call_id)
            continue
        stats.raw_fact_count += 1
        destination_variable = _stack_destination_variable_8616(codegen, root, destination)
        if destination_variable is None:
            _refuse_8616(
                stats,
                refusals,
                summary.callsite_addr,
                StoredCallResultAssignmentRefusalReason8616.DESTINATION_VARIABLE_MISSING,
            )
            continue
        stats.normalized_fact_count += 1
        exact_store_statement = (
            isinstance(summary.return_store_instruction_addr, int)
            and occurrence.statement.tags.get("ins_addr") == summary.return_store_instruction_addr
        )
        if (
            isinstance(occurrence.statement, CAssignment)
            and not exact_store_statement
            and not is_stored_call_return_register_destination_8616(
                codegen,
                occurrence.statement.lhs,
                summary,
                destination[1],
            )
        ):
            _refuse_8616(
                stats,
                refusals,
                summary.callsite_addr,
                StoredCallResultAssignmentRefusalReason8616.RETURN_REGISTER_CONFLICT,
            )
            continue
        stats.classified_fact_count += 1
        lhs = cast(CVariable, _clone_c_ast_tree_8616(destination_variable))
        if isinstance(occurrence.statement, CAssignment):
            previous_lhs = occurrence.statement.lhs
            occurrence.statement.lhs = lhs
            if (
                isinstance(previous_lhs, CVariable)
                and isinstance(previous_lhs.variable, SimRegisterVariable)
                and previous_lhs.variable.size == destination[1]
            ):
                capture = CAssignment(
                    previous_lhs, _clone_c_ast_tree_8616(lhs),
                    tags=dict(occurrence.statement.tags), codegen=codegen,
                )
                captured_statements = list(occurrence.parent.statements)
                captured_statements.insert(captured_statements.index(occurrence.statement) + 1, capture)
                occurrence.parent.statements = captured_statements
        else:
            statements: list[object] = list(occurrence.parent.statements or ())
            statements[occurrence.index] = CAssignment(
                lhs,
                occurrence.call,
                tags=dict(occurrence.statement.tags),
                codegen=codegen,
            )
            occurrence.parent.statements = statements
        store_ins_addr = summary.return_store_instruction_addr
        if isinstance(store_ins_addr, int):
            for parent, artifact in _store_artifacts_8616(root, store_ins_addr):
                if artifact is not occurrence.statement:
                    artifacts_to_remove[id(artifact)] = (parent, artifact)
        owned_call_ids.add(call_id)
        summary_map[call_id] = summary
        stats.materialized_count += 1

    for parent, artifact in artifacts_to_remove.values():
        parent.statements = [
            statement for statement in tuple(parent.statements or ()) if statement is not artifact
        ]

    verdict = (
        StoredCallResultAssignmentVerdict8616.UNKNOWN_REFUSE
        if stats.failure_count
        else StoredCallResultAssignmentVerdict8616.MATERIALIZED
        if stats.materialized_count
        else StoredCallResultAssignmentVerdict8616.NO_CANDIDATE
    )
    result = StoredCallResultAssignmentResult8616(verdict, stats, tuple(refusals))
    boundary._inertia_stored_call_result_assignments_8616 = result
    return result
