"""Consume proven machine setup after typed stack arguments are materialized.

Layer: Types/Lowering.
Responsibility: match canonical runtime-register writes and Alias-derived stack
argument coordinates to original-image setup evidence. Delete only a proven
redundant value carrier; unknown evidence keeps code. No rendered-C recovery.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr import Project
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeArray, SimTypeFixedSizeArray
from angr.sim_variable import SimStackVariable

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_setup_evidence import collect_consumed_stack_address_setup_8616
from ..callsite_summary import (
    CallsitePushSourceKind8616,
    CallsiteSummary8616,
    structured_callsite_addr_8616,
    structured_callsite_target_addr_8616,
)
from ..pipeline.errors import PipelineHardError
from ..semantics.register_entry_overwrite import ConsumedStackAddressSetup8616, RegisterEntryOverwriteVerdict8616
from .gp_register_state import runtime_gp_name_for_variable_8616
from .stack_variable_coordinates import stack_variable_coordinate_registry_8616


@dataclass(frozen=True)
class ConsumedStackSetupCensus8616:
    """Closed count of candidate carriers, proven deletions and refusals."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


class _SetupCodegen8616(Protocol):
    """Typed extension of the third-party codegen boundary."""

    _inertia_consumed_stack_setup_census_8616: ConsumedStackSetupCensus8616


def _pure_address_expression_8616(expression: object) -> bool:
    """Refuse loads/calls/dirty values in the numeric carrier being removed."""
    if isinstance(expression, c.CConstant):
        return True
    if isinstance(expression, c.CUnaryOp):
        return (
            expression.op in {"Reference", "AddressOf"}
            and isinstance(expression.operand, c.CVariable)
            and isinstance(expression.operand.variable, SimStackVariable)
        )
    if isinstance(expression, c.CTypeCast):
        return _pure_address_expression_8616(expression.expr)
    if isinstance(expression, c.CBinaryOp) and expression.op in {"Add", "Sub"}:
        return _pure_address_expression_8616(expression.lhs) and _pure_address_expression_8616(expression.rhs)
    if isinstance(expression, c.CBinaryOp) and expression.op == "And" and isinstance(expression.rhs, c.CConstant):
        return _pure_address_expression_8616(expression.lhs)
    return False


def _masked_word_parent_8616(statement: object) -> str | None:
    """Recognize only the canonical low-word write preserving the upper word."""
    if not isinstance(statement, c.CAssignment) or not isinstance(statement.lhs, c.CVariable):
        return None
    parent = runtime_gp_name_for_variable_8616(statement.lhs.variable)
    if parent not in {"eax", "ebx", "ecx", "edx", "esi", "edi"}:
        return None
    rhs = statement.rhs
    if not isinstance(rhs, c.CBinaryOp) or rhs.op != "Or":
        return None
    preserved, inserted = rhs.lhs, rhs.rhs
    if not (
        isinstance(preserved, c.CBinaryOp) and preserved.op == "And"
        and isinstance(preserved.lhs, c.CVariable)
        and runtime_gp_name_for_variable_8616(preserved.lhs.variable) == parent
        and isinstance(preserved.rhs, c.CConstant) and preserved.rhs.value == 0xFFFF0000
        and isinstance(inserted, c.CBinaryOp) and inserted.op == "And"
        and isinstance(inserted.rhs, c.CConstant) and inserted.rhs.value == 0xFFFF
        and _pure_address_expression_8616(inserted.lhs)
    ):
        return None
    return cast(str, parent)


def _stack_argument_bp_8616(codegen: object, argument: object) -> int | None:
    """Require the exact registered stack projection of an address argument."""
    if (
        isinstance(argument, c.CUnaryOp) and argument.op in {"Reference", "AddressOf"}
        and isinstance(argument.operand, c.CVariable)
    ):
        variable = argument.operand.variable
    elif isinstance(argument, c.CVariable) and isinstance(argument.variable_type, (SimTypeArray, SimTypeFixedSizeArray)):
        variable = argument.variable
    else:
        return None
    if not isinstance(variable, SimStackVariable):
        return None
    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(variable)
    return projection.bp_offset if projection is not None and projection.size > 0 else None


def _setup_request_8616(
    codegen: object, call: c.CFunctionCall, summary: CallsiteSummary8616,
    statement: c.CAssignment, parent: str,
) -> ConsumedStackAddressSetup8616 | None:
    """Match physical PUSH order to the already materialized argument list."""
    producer = statement.tags.get("ins_addr")
    sources, pushes = summary.push_arg_sources, summary.push_arg_instruction_addrs
    if not (
        isinstance(producer, int) and summary.target_addr is not None
        and structured_callsite_addr_8616(call) == summary.callsite_addr
        and structured_callsite_target_addr_8616(call) == summary.target_addr
        and call.args is not None
        and len(sources) == len(pushes) == len(call.args) == summary.arg_count
    ):
        return None
    if any(
        isinstance(node, c.CVariable) and runtime_gp_name_for_variable_8616(node.variable) == parent
        for node in _iter_c_nodes_deep_8616(call)
    ):
        return None
    requests: list[ConsumedStackAddressSetup8616] = []
    for index, source in enumerate(sources):
        if source is None or len(source) != 2 or source[0] != CallsitePushSourceKind8616.BP_ADDRESS.value:
            continue
        offset = source[1]
        if isinstance(offset, int) and _stack_argument_bp_8616(codegen, call.args[-1 - index]) == offset:
            requests.append(ConsumedStackAddressSetup8616(
                producer, pushes[index], summary.callsite_addr, summary.target_addr, offset, parent[1:],
            ))
    return requests[0] if len(requests) == 1 else None


def _proven_setup_deletion_8616(
    project: Project,
    codegen: object,
    sequence: c.CStatements,
    index: int,
    statement: c.CAssignment,
    parent: str,
    inventory: Mapping[int, CallsiteSummary8616],
) -> tuple[int, int]:
    """Return ``(normalized, classified)`` deltas for one masked-word carrier."""
    for later in sequence.statements[index + 1:]:
        call = later.expr if isinstance(later, c.CExpressionStatement) else later
        if isinstance(call, c.CFunctionCall):
            summary = inventory.get(structured_callsite_addr_8616(call) or -1)
            if summary is None:
                return 0, 0
            request = _setup_request_8616(codegen, call, summary, statement, parent)
            if request is None:
                return 0, 0
            proof = collect_consumed_stack_address_setup_8616(project, request)
            if proof.verdict is RegisterEntryOverwriteVerdict8616.PROVEN:
                return 1, 1
            return 1, 0
        if any(
            isinstance(node, c.CVariable) and runtime_gp_name_for_variable_8616(node.variable) == parent
            for node in _iter_c_nodes_deep_8616(later)
        ):
            return 0, 0
        if not isinstance(later, c.CAssignment):
            return 0, 0
    return 0, 0


def prune_consumed_stack_address_setup_8616(
    project: Project, codegen: object, root: object, inventory: Mapping[int, CallsiteSummary8616],
) -> bool:
    """Delete only machine-proven carriers with exact materialized storage."""
    raw = normalized = classified = materialized = 0
    for sequence in _iter_c_nodes_deep_8616(root):
        if not isinstance(sequence, c.CStatements):
            continue
        deletions: set[int] = set()
        for index, statement in enumerate(sequence.statements):
            parent = _masked_word_parent_8616(statement)
            if parent is None or not isinstance(statement, c.CAssignment):
                continue
            raw += 1
            normalized_hit, classified_hit = _proven_setup_deletion_8616(
                project, codegen, sequence, index, statement, parent, inventory
            )
            normalized += normalized_hit
            if classified_hit:
                classified += 1
                deletions.add(index)
        for index in sorted(deletions, reverse=True):
            del sequence.statements[index]
            materialized += 1
    census = ConsumedStackSetupCensus8616(raw, normalized, classified, materialized, raw - materialized)
    cast(_SetupCodegen8616, codegen)._inertia_consumed_stack_setup_census_8616 = census
    if classified != materialized:
        raise PipelineHardError("Consumed stack setup proof was not materialized")
    return materialized > 0
