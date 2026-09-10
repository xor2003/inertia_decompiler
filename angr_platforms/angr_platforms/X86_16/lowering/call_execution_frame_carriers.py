"""Prune SP execution carriers consumed by a materialized machine call.

Layer: Types/Lowering.
Responsibility: remove only the synthetic CALL stack-pointer decrement and
dephi restore, including their owned runtime-GP projection, after a typed call
expression has consumed that machine call.
Consumes alias, widening, and typed facts; it does not create those facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
This module uses exact callsite tags, physical SP identity, SSA identity, and
closed use counts. It does not inspect assembly text, rendered C, helper names,
or source/debug sidecars.
Runtime SP consumption refuses any external parent-register view, including call arguments.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
)

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..pipeline.errors import PipelineHardError
from ..semantics.expression_analysis import (
    VirtualValueIdentity8616,
    describe_virtual_value_identity_8616,
)
from .call_execution_frame_runtime import is_runtime_sp_call_decrement_8616
from .gp_register_state import runtime_gp_expression_view_8616
from .physical_registers import PhysicalRegisterView8616, physical_register_view_8616


class CallExecutionFrameCarrierStatus8616(StrEnum):
    """Typed outcome of one consumed-call frame-carrier inspection."""

    NOT_APPLICABLE = "not_applicable"
    REFUSED = "refused"
    MATERIALIZED = "materialized"


@dataclass(frozen=True, slots=True)
class CallExecutionFrameCarrierStats8616:
    """Closed evidence counts for consumed-call SP carrier pruning."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    removed_statement_count: int = 0

    def merged(
        self,
        other: CallExecutionFrameCarrierStats8616,
    ) -> CallExecutionFrameCarrierStats8616:
        """Return the field-wise sum of two evidence reports."""
        return CallExecutionFrameCarrierStats8616(
            raw_fact_count=self.raw_fact_count + other.raw_fact_count,
            normalized_fact_count=self.normalized_fact_count + other.normalized_fact_count,
            classified_fact_count=self.classified_fact_count + other.classified_fact_count,
            materialized_count=self.materialized_count + other.materialized_count,
            failure_count=self.failure_count + other.failure_count,
            removed_statement_count=(
                self.removed_statement_count + other.removed_statement_count
            ),
        )


@dataclass(frozen=True, slots=True)
class CallExecutionFrameCarrierResult8616:
    """Outcome and evidence report for one consumed machine call."""

    status: CallExecutionFrameCarrierStatus8616
    stats: CallExecutionFrameCarrierStats8616


@dataclass(frozen=True, slots=True)
class _AssignmentLocation8616:
    """One direct assignment child and its mutable statement container."""

    container: CStatements
    statement: object
    assignment: CAssignment


class _ArchitectureSurface8616(Protocol):
    """Architecture register map consumed at the dynamic angr boundary."""

    registers: dict[str, tuple[int, int]]


class _ProjectSurface8616(Protocol):
    """Project fields consumed at the dynamic angr boundary."""

    arch: _ArchitectureSurface8616


class _CFunctionSurface8616(Protocol):
    """Structured function root consumed at the dynamic angr boundary."""

    statements: object


class _CodegenSurface8616(Protocol):
    """Structured codegen fields consumed at the dynamic angr boundary."""

    project: _ProjectSurface8616
    cfunc: _CFunctionSurface8616


def _assignment_8616(statement: object) -> CAssignment | None:
    """Unwrap one standard angr expression-statement assignment container."""
    if isinstance(statement, CAssignment):
        return statement
    if isinstance(statement, CExpressionStatement) and isinstance(
        statement.expr, CAssignment
    ):
        return statement.expr
    return None


def _locations_8616(root: object) -> tuple[_AssignmentLocation8616, ...]:
    """Collect unique direct assignment locations from the structured tree."""
    locations: list[_AssignmentLocation8616] = []
    seen_statements: set[int] = set()
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CStatements):
            continue
        for statement in tuple(node.statements):
            if id(statement) in seen_statements:
                continue
            assignment = _assignment_8616(statement)
            if assignment is None:
                continue
            seen_statements.add(id(statement))
            locations.append(_AssignmentLocation8616(node, statement, assignment))
    return tuple(locations)


def _identity_count_8616(
    root: object,
    expected: VirtualValueIdentity8616,
) -> int:
    """Count unique virtual-value occurrences with one structured identity."""
    seen: set[int] = set()
    count = 0
    for node in _iter_c_nodes_deep_8616(root):
        if id(node) in seen:
            continue
        seen.add(id(node))
        if describe_virtual_value_identity_8616(node) == expected:
            count += 1
    return count


def _direct_successor_contains_call_8616(
    location: _AssignmentLocation8616,
    call: CFunctionCall,
) -> bool:
    """Prove that one consumed call immediately follows its SP carrier."""
    statements = location.container.statements
    try:
        index = next(
            idx for idx, statement in enumerate(statements) if statement is location.statement
        )
    except StopIteration:
        return False
    if index + 1 >= len(statements):
        return False
    successor = statements[index + 1]
    return successor is call or any(
        node is call for node in _iter_c_nodes_deep_8616(successor)
    )


def _result_8616(
    status: CallExecutionFrameCarrierStatus8616,
    *,
    raw: int = 0,
    normalized: int = 0,
    classified: int = 0,
    materialized: int = 0,
    removed: int = 0,
) -> CallExecutionFrameCarrierResult8616:
    """Build one fail-closed evidence result."""
    stats = CallExecutionFrameCarrierStats8616(
        raw_fact_count=raw,
        normalized_fact_count=normalized,
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=max(0, raw - materialized),
        removed_statement_count=removed,
    )
    if classified > 0 and materialized == 0:
        raise PipelineHardError(
            "classified consumed-call execution frame was not materialized"
        )
    return CallExecutionFrameCarrierResult8616(status=status, stats=stats)


def prune_consumed_call_execution_frame_carriers_8616(
    codegen: object,
    call: CFunctionCall,
    *,
    callsite_addr: int,
    return_frame_width: int,
) -> CallExecutionFrameCarrierResult8616:
    """Delete one exact virtual or runtime-GP SP carrier for ``call``."""
    boundary = cast(_CodegenSurface8616, codegen)
    try:
        root = boundary.cfunc.statements
        sp_offset, sp_size = boundary.project.arch.registers["sp"]
    except (AttributeError, KeyError, TypeError, ValueError):
        return _result_8616(CallExecutionFrameCarrierStatus8616.NOT_APPLICABLE)
    sp_view = PhysicalRegisterView8616(sp_offset, sp_size)
    locations = _locations_8616(root)
    virtual_raw_locations = tuple(
        location
        for location in locations
        if location.assignment.tags.get("ins_addr") == callsite_addr
        and isinstance(location.assignment.rhs, CBinaryOp)
        and location.assignment.rhs.op == "Sub"
    )
    runtime_raw_locations = tuple(
        location
        for location in locations
        if location.assignment.tags.get("ins_addr") == callsite_addr
        and (view := runtime_gp_expression_view_8616(location.assignment.lhs))
        is not None
        and view.parent_name == "esp"
        and view.width == 4
    )
    raw_count = len(virtual_raw_locations) + len(runtime_raw_locations)
    if raw_count == 0:
        return _result_8616(CallExecutionFrameCarrierStatus8616.NOT_APPLICABLE)

    if runtime_raw_locations:
        normalized_runtime = tuple(
            location
            for location in runtime_raw_locations
            if is_runtime_sp_call_decrement_8616(
                location.assignment,
                return_frame_width,
            )
        )
        if not (
            len(runtime_raw_locations) == 1
            and not virtual_raw_locations
            and len(normalized_runtime) == 1
            and sum(1 for node in _iter_c_nodes_deep_8616(root) if node is call) == 1
            and _direct_successor_contains_call_8616(normalized_runtime[0], call)
            and not any(
                (view := runtime_gp_expression_view_8616(node)) is not None and view.parent_name == "esp"
                for node in _iter_c_nodes_deep_8616(root, seen={id(normalized_runtime[0].statement)})
            )
        ):
            return _result_8616(
                CallExecutionFrameCarrierStatus8616.REFUSED,
                raw=raw_count,
                normalized=len(normalized_runtime),
            )
        location = normalized_runtime[0]
        location.container.statements.remove(location.statement)
        return _result_8616(
            CallExecutionFrameCarrierStatus8616.MATERIALIZED,
            raw=1,
            normalized=1,
            classified=1,
            materialized=1,
            removed=1,
        )

    normalized: list[
        tuple[
            _AssignmentLocation8616,
            VirtualValueIdentity8616,
            VirtualValueIdentity8616,
        ]
    ] = []
    for location in virtual_raw_locations:
        assignment = location.assignment
        rhs = cast(CBinaryOp, assignment.rhs)
        decrement = rhs.rhs
        base_identity = describe_virtual_value_identity_8616(rhs.lhs)
        decremented_identity = describe_virtual_value_identity_8616(assignment.lhs)
        if not (
            isinstance(decrement, CConstant)
            and decrement.value == return_frame_width
            and physical_register_view_8616(rhs.lhs) == sp_view
            and physical_register_view_8616(assignment.lhs) == sp_view
            and base_identity is not None
            and decremented_identity is not None
            and base_identity != decremented_identity
        ):
            continue
        normalized.append((location, base_identity, decremented_identity))
    if len(normalized) != 1:
        return _result_8616(
            CallExecutionFrameCarrierStatus8616.REFUSED,
            raw=raw_count,
            normalized=len(normalized),
        )

    pre_location, base_identity, decremented_identity = normalized[0]
    restore_locations = tuple(
        location
        for location in locations
        if location is not pre_location
        and location.assignment.tags.get("dephi") is True
        and describe_virtual_value_identity_8616(location.assignment.lhs)
        == base_identity
        and describe_virtual_value_identity_8616(location.assignment.rhs)
        == decremented_identity
        and physical_register_view_8616(location.assignment.lhs) == sp_view
        and physical_register_view_8616(location.assignment.rhs) == sp_view
    )
    call_occurrences = sum(
        1 for node in _iter_c_nodes_deep_8616(root) if node is call
    )
    if not (
        len(restore_locations) == 1
        and call_occurrences == 1
        and _identity_count_8616(root, base_identity) == 2
        and _identity_count_8616(root, decremented_identity) == 2
    ):
        return _result_8616(
            CallExecutionFrameCarrierStatus8616.REFUSED,
            raw=raw_count,
            normalized=1,
        )

    restore_location = restore_locations[0]
    for location in (pre_location, restore_location):
        location.container.statements.remove(location.statement)
    return _result_8616(
        CallExecutionFrameCarrierStatus8616.MATERIALIZED,
        raw=raw_count,
        normalized=1,
        classified=1,
        materialized=1,
        removed=2,
    )
