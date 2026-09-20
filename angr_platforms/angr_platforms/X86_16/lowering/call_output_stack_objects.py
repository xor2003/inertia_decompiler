"""Recover call-addressed stack objects and project proven condition fields.

Layer: Types/Lowering.
Responsibility: turns typed stack-address, callsite, aggregate-boundary, and
``ConditionIR`` evidence into stack-object field expressions and local types.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

This module does not identify objects by callee name, source text, rendered C,
or fixed function addresses. Structuring may supply the set of conditions in a
CFG-proven chain, but object identity and field offsets are decided here.
Dynamic angr C-AST and variable-manager access is isolated behind typed
protocols; owned evidence contracts use direct fields.
"""

from __future__ import annotations

import logging
import os
from collections import OrderedDict
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CExpression,
    CExpressionStatement,
    CFunctionCall,
    CIfElse,
    CStatements,
    CStructField,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CVariableField,
)
from angr.knowledge_plugins.functions import Function
from angr.sim_type import (
    SimStruct,
    SimType,
    SimTypeArray,
    SimTypeChar,
    SimTypeLong,
    SimTypeShort,
    TypeRef,
)
from angr.sim_variable import SimRegisterVariable, SimStackVariable, SimVariable
from archinfo import Arch

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..call_target_identity import (
    resolve_x86_16_canonical_call_target_function_8616,
)
from ..caller_return_use_contracts import CallsiteReturnUseKind8616
from ..callsite_summary import (
    CallsiteReturnShape8616,
    CallsiteSummary8616,
)
from ..ir.condition_ir import ConditionIR
from ..ir.core import IRValue, MemSpace
from ..pipeline.errors import PipelineHardError
from .call_output_object_projection import (
    publish_call_output_object_projection_8616,
    synchronize_call_output_object_declaration_8616,
)
from .callsite_inventory import ensure_callsite_summary_inventory_8616 as _callsite_inventory_8616
from .condition_stack_projection_contracts import (
    ConditionStackProjectionFact8616,
    condition_stack_projection_fact_8616,
)
from .semantic_cast import CSemanticCast8616
from .stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    stack_variable_coordinate_registry_8616,
)
from .wide_call_condition_source import proven_wide_condition_callsite_8616

_LOGGER = logging.getLogger(__name__)


class _CallOutputTypesStore8616(Protocol):
    """Minimal angr type-store boundary used for local struct declarations."""

    def __setitem__(self, name: str, value: TypeRef) -> None:
        """Register one named type reference."""


class _CallOutputVariableManager8616(Protocol):
    """Minimal angr variable-manager boundary used by object lowering."""

    types: _CallOutputTypesStore8616

    def set_variable_type(self, variable: SimVariable, type_: SimType, **kwargs: object) -> None:
        """Assign one recovered variable type."""


class _CallOutputCFunction8616(Protocol):
    """Dynamic angr CFunction fields required by call-output object lowering."""

    addr: int
    statements: object
    variables_in_use: dict[SimVariable, CVariable]
    variable_manager: _CallOutputVariableManager8616

    def refresh(self) -> None:
        """Refresh local declaration groups after variable changes."""


class _CallOutputProject8616(Protocol):
    """Dynamic angr project architecture boundary."""

    arch: Arch
    kb: _CallOutputKnowledgeBase8616


class _CallOutputKnowledgeBase8616(Protocol):
    """Dynamic angr knowledge-base boundary used for callsite evidence."""

    functions: _CallOutputFunctionManager8616


class _CallOutputFunctionManager8616(Protocol):
    """Dynamic angr function lookup used by call-output lowering."""

    def function(self, *, addr: int, create: bool) -> Function | None:
        """Return one existing function without creating it."""


class _CallOutputCodegen8616(Protocol):
    """Dynamic codegen fields consumed and produced by this lowering pass."""

    cfunc: _CallOutputCFunction8616
    project: _CallOutputProject8616
    show_local_types: bool
    _inertia_callsite_summaries: dict[int, CallsiteSummary8616]
    _inertia_callsite_summary_inventory_8616: dict[int, CallsiteSummary8616]
    _inertia_call_output_stack_object_facts_8616: tuple[CallOutputStackObjectFact8616, ...]
    _inertia_call_output_stack_object_stats_8616: CallOutputStackObjectStats8616
    _inertia_wide_call_return_condition_stats_8616: WideCallReturnConditionStats8616


@dataclass(frozen=True, slots=True)
class CallOutputStackField8616:
    """One field slice proven inside a call-addressed stack object."""

    absolute_offset: int
    relative_offset: int
    width: int
    name: str


@dataclass(frozen=True, slots=True)
class CallOutputStackObjectFact8616:
    """One call-addressed stack object with a closed upper boundary."""

    callsite_addr: int
    base_offset: int
    boundary_offset: int
    base_variable: SimStackVariable
    base_cvar: CVariable
    fields: tuple[CallOutputStackField8616, ...]


@dataclass(frozen=True, slots=True)
class CallOutputStackObjectStats8616:
    """Closed evidence accounting for call-output stack-object lowering."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    def merged(self, other: CallOutputStackObjectStats8616) -> CallOutputStackObjectStats8616:
        """Return component-wise accumulated evidence counts."""
        return CallOutputStackObjectStats8616(
            raw_fact_count=self.raw_fact_count + other.raw_fact_count,
            normalized_fact_count=self.normalized_fact_count + other.normalized_fact_count,
            classified_fact_count=self.classified_fact_count + other.classified_fact_count,
            materialized_count=self.materialized_count + other.materialized_count,
            failure_count=self.failure_count + other.failure_count,
        )


@dataclass(frozen=True, slots=True)
class CallOutputConditionLoweringResult8616:
    """Result of projecting stack-object fields into one condition expression."""

    expression: CExpression
    facts: tuple[CallOutputStackObjectFact8616, ...]
    stats: CallOutputStackObjectStats8616


@dataclass(frozen=True, slots=True)
class WideCallReturnConditionStats8616:
    """Closed evidence accounting for one DX:AX wide condition join."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class WideCallReturnConditionResult8616:
    """Result of lowering one proven split-register wide comparison."""

    expression: CExpression
    stats: WideCallReturnConditionStats8616
    consumed_call: CFunctionCall | None = None
    consumed_callsite: CallsiteSummary8616 | None = None


@dataclass(frozen=True, slots=True)
class _CallAddressedStackBase8616:
    """One exact BP address passed at a typed binary callsite."""

    callsite_addr: int
    base_offset: int
    base_cvar: CVariable | None


def _strip_condition_casts_8616(expression: CExpression) -> CExpression:
    """Strip transparent C casts around one call argument."""
    current = expression
    while isinstance(current, CTypeCast):
        current = current.expr
    return current


def _referenced_stack_cvar_8616(expression: CExpression) -> CVariable | None:
    """Return the BP stack variable referenced by one call argument."""
    current = _strip_condition_casts_8616(expression)
    if not isinstance(current, CUnaryOp) or current.op not in {"Reference", "AddressOf"}:
        return None
    operand = _strip_condition_casts_8616(current.operand)
    if not isinstance(operand, CVariable):
        return None
    variable = operand.variable
    if not isinstance(variable, SimStackVariable) or variable.base != "bp" or not isinstance(variable.offset, int):
        return None
    return operand


def _condition_stack_slices_8616(conditions: tuple[ConditionIR, ...]) -> tuple[tuple[int, int, int], ...]:
    """Return unique ``(instruction, offset, width)`` condition stack slices."""
    slices: set[tuple[int, int, int]] = set()
    for condition in conditions:
        if not isinstance(condition.src_insn, int):
            continue
        for operand in (condition.lhs, condition.rhs):
            if (
                isinstance(operand, IRValue)
                and operand.space is MemSpace.SS
                and operand.name == "bp"
                and isinstance(operand.offset, int)
                and operand.size > 0
            ):
                slices.add((condition.src_insn, operand.offset, operand.size))
    return tuple(sorted(slices))


def _wide_call_return_condition_ir_8616(
    conditions: tuple[ConditionIR, ...],
) -> tuple[IRValue, IRValue] | None:
    """Return the high and low stack values from one exact wide comparison chain."""
    if len(conditions) != 3:
        return None
    high_le, high_ge, low_le = conditions
    if (high_le.op, high_ge.op, low_le.op) != ("sle", "sge", "ule"):
        return None
    if high_le.lhs != high_ge.lhs or high_le.rhs != high_ge.rhs:
        return None
    high_register = high_le.lhs
    low_register = low_le.lhs
    high_stack = high_le.rhs
    low_stack = low_le.rhs
    if not (
        isinstance(high_register, IRValue)
        and high_register.space is MemSpace.REG
        and high_register.name == "dx"
        and high_register.size == 2
        and isinstance(low_register, IRValue)
        and low_register.space is MemSpace.REG
        and low_register.name == "ax"
        and low_register.size == 2
        and isinstance(high_stack, IRValue)
        and high_stack.space is MemSpace.SS
        and high_stack.name == "bp"
        and high_stack.size == 2
        and isinstance(low_stack, IRValue)
        and low_stack.space is MemSpace.SS
        and low_stack.name == "bp"
        and low_stack.size == 2
        and high_stack.offset == low_stack.offset + 2
    ):
        return None
    return high_stack, low_stack


def _wide_call_return_condition_expression_parts_8616(
    expression: CExpression,
) -> tuple[CExpression, CExpression] | None:
    """Return high and low stack operands from the target-directed Boolean form."""
    if isinstance(expression, CUnaryOp) and expression.op == "Not":
        non_break = expression.operand
        if not isinstance(non_break, CBinaryOp) or non_break.op != "LogicalOr":
            return None
        high_lt = non_break.lhs
        gated_low = non_break.rhs
        if (
            isinstance(high_lt, CBinaryOp)
            and high_lt.op == "CmpLT"
            and isinstance(gated_low, CBinaryOp)
            and gated_low.op == "LogicalAnd"
            and isinstance(gated_low.lhs, CBinaryOp)
            and gated_low.lhs.op == "CmpEQ"
            and isinstance(gated_low.rhs, CBinaryOp)
            and gated_low.rhs.op == "CmpLE"
        ):
            return high_lt.rhs, gated_low.rhs.rhs
        return None
    if not isinstance(expression, CBinaryOp) or expression.op != "LogicalOr":
        return None
    high_gt = expression.lhs
    gated_low = expression.rhs
    if not (
        isinstance(high_gt, CBinaryOp)
        and high_gt.op == "CmpGT"
        and isinstance(gated_low, CBinaryOp)
        and gated_low.op == "LogicalAnd"
        and isinstance(gated_low.lhs, CBinaryOp)
        and gated_low.lhs.op == "CmpGE"
        and isinstance(gated_low.rhs, CBinaryOp)
        and gated_low.rhs.op == "CmpGT"
    ):
        return None
    return high_gt.rhs, gated_low.rhs.rhs


def _wide_condition_stack_cvar_8616(
    codegen: _CallOutputCodegen8616,
    high_expr: CExpression,
    low_expr: CExpression,
    high_stack: IRValue,
    low_stack: IRValue,
) -> CVariable | None:
    """Return the existing four-byte stack object proven by adjacent word views."""
    low_offset = low_stack.offset
    high_offset = high_stack.offset
    if not isinstance(low_offset, int) or not isinstance(high_offset, int) or high_offset != low_offset + 2:
        return None

    def matches_projection(
        expression: CExpression,
        expected_offset: int,
        *,
        allow_owner: bool,
    ) -> bool:
        """Match one expression through typed projection or exact stack identity."""
        projection = condition_stack_projection_fact_8616(expression)
        expected_projection = ConditionStackProjectionFact8616(
            base="bp",
            owner_offset=low_offset,
            owner_size=4,
            view_offset=expected_offset,
            view_size=2,
        )
        if isinstance(projection, ConditionStackProjectionFact8616):
            return bool(projection == expected_projection)
        direct = _strip_condition_casts_8616(expression)
        if not isinstance(direct, CVariable) or not isinstance(direct.variable, SimStackVariable):
            return False
        variable = direct.variable
        return (
            variable.base == "bp"
            and machine_bp_offset_for_stack_variable_8616(codegen, variable) == expected_offset
            and variable.size in ({2, 4} if allow_owner else {2})
        )

    if not matches_projection(low_expr, low_offset, allow_owner=True) or not matches_projection(
        high_expr,
        high_offset,
        allow_owner=False,
    ):
        return None
    candidates = tuple(
        cvar
        for variable, cvar in codegen.cfunc.variables_in_use.items()
        if isinstance(variable, SimStackVariable)
        and variable.base == "bp"
        and machine_bp_offset_for_stack_variable_8616(codegen, variable) == low_offset
        and variable.size == 4
        and isinstance(cvar, CVariable)
    )
    unique_candidates = tuple({id(candidate): candidate for candidate in candidates}.values())
    if len(unique_candidates) != 1:
        return None
    wide_cvar = unique_candidates[0]
    wide_type = SimTypeLong(True).with_arch(codegen.project.arch)
    for variable, cvar in codegen.cfunc.variables_in_use.items():
        if (
            isinstance(variable, SimStackVariable)
            and variable.base == "bp"
            and machine_bp_offset_for_stack_variable_8616(codegen, variable) == low_offset
            and variable.size == 4
        ):
            codegen.cfunc.variable_manager.set_variable_type(variable, wide_type)
            if isinstance(cvar, CVariable):
                cvar.variable_type = wide_type
    for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements):
        if not isinstance(node, CVariable):
            continue
        variable = node.variable
        if (
            isinstance(variable, SimStackVariable)
            and variable.base == "bp"
            and machine_bp_offset_for_stack_variable_8616(codegen, variable) == low_offset
            and variable.size == 4
        ):
            node.variable_type = wide_type
    codegen.show_local_types = True
    return wide_cvar


def select_wide_call_return_condition_chain_8616(
    root_condition: ConditionIR,
    conditions: tuple[ConditionIR, ...],
) -> tuple[ConditionIR, ConditionIR, ConditionIR] | None:
    """Select one unique typed DX:AX condition chain rooted at ``root_condition``."""
    candidates: list[tuple[ConditionIR, ConditionIR, ConditionIR]] = []
    for high_ge in conditions:
        if high_ge is root_condition:
            continue
        for low_le in conditions:
            if low_le is root_condition or low_le is high_ge:
                continue
            candidate = (root_condition, high_ge, low_le)
            if _wide_call_return_condition_ir_8616(candidate) is not None:
                candidates.append(candidate)
    unique = tuple(
        {
            tuple(id(condition) for condition in candidate): candidate
            for candidate in candidates
        }.values()
    )
    return unique[0] if len(unique) == 1 else None


def _wide_condition_call_8616(
    codegen: _CallOutputCodegen8616,
    conditions: tuple[ConditionIR, ...],
) -> tuple[CFunctionCall, CallsiteSummary8616] | None:
    """Return the unique typed DX:AX call proven to reach the whole chain."""
    try:
        summary_map = codegen._inertia_callsite_summaries
    except AttributeError:
        summary_map = {}
    if not isinstance(summary_map, dict):
        raise TypeError("callsite summary carrier must be a dict")
    inventory = _callsite_inventory_8616(codegen)
    candidates: dict[int, list[CFunctionCall]] = {}
    for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements):
        if not isinstance(node, CFunctionCall) or tuple(node.args or ()):
            continue
        tags = node.tags
        try:
            tagged_callsite = tags.get("ins_addr")
        except AttributeError:
            tagged_callsite = None
        summary = summary_map.get(id(node))
        if summary is None and isinstance(tagged_callsite, int):
            summary = inventory.get(tagged_callsite)
        if not isinstance(summary, CallsiteSummary8616):
            continue
        if not (
            summary.return_used is True
            and summary.return_use_kind is CallsiteReturnUseKind8616.CONDITION
            and summary.return_shape == CallsiteReturnShape8616.DX_AX.value
            and isinstance(summary.callsite_addr, int)
            and isinstance(summary.return_addr, int)
        ):
            continue
        candidates.setdefault(summary.callsite_addr, []).append(node)
    if not candidates:
        return None
    proven_callsite = proven_wide_condition_callsite_8616(codegen, conditions, frozenset(candidates))
    if proven_callsite is None:
        return None
    proven_calls = tuple({id(call): call for call in candidates[proven_callsite]}.values())
    if len(proven_calls) != 1:
        return None
    call = proven_calls[0]
    summary = inventory.get(proven_callsite) or summary_map.get(id(call))
    if not isinstance(summary, CallsiteSummary8616):
        return None
    rebound = dict(summary_map)
    rebound[id(call)] = summary
    codegen._inertia_callsite_summaries = rebound
    if isinstance(summary.target_addr, int):
        callee = resolve_x86_16_canonical_call_target_function_8616(
            codegen.project,
            summary.target_addr,
        )
        if callee is None:
            call.callee_func = None
            call.callee_target = f"sub_{summary.target_addr:x}"
        else:
            call.callee_func = cast(Function, callee)
    return call, summary


def prune_materialized_wide_condition_call_carrier_8616(
    codegen: object,
    call: CFunctionCall,
) -> int:
    """Remove the exact standalone or AX carrier consumed by a wide condition."""
    boundary = cast(_CallOutputCodegen8616, codegen)
    removed = 0
    seen: set[int] = set()
    def is_consumed_carrier(statement: object) -> bool:
        """Return whether one statement exists only to carry ``call`` through AX."""
        if statement is call:
            return True
        if isinstance(statement, CExpressionStatement):
            if statement.expr is call:
                return True
            statement = statement.expr
        if not isinstance(statement, CAssignment) or statement.rhs is not call:
            return False
        lhs = statement.lhs
        if not isinstance(lhs, CVariable) or not isinstance(lhs.variable, SimRegisterVariable):
            return False
        register_name = boundary.project.arch.translate_register_name(
            lhs.variable.reg,
            lhs.variable.size,
        )
        return isinstance(register_name, str) and register_name.lower() == "ax"

    def visit(node: object) -> None:
        """Prune carrier statements from structured statement containers."""
        nonlocal removed
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        if isinstance(node, CStatements):
            retained: list[object] = []
            for statement in tuple(node.statements):
                if is_consumed_carrier(statement):
                    removed += 1
                    continue
                retained.append(statement)
                visit(statement)
            node.statements[:] = retained
            return
        if isinstance(node, CIfElse):
            for _condition, body in tuple(node.condition_and_nodes):
                visit(body)
            visit(node.else_node)
            return
        for attr in ("body", "else_node"):
            child = getattr(node, attr, None)
            if child is not None:
                visit(child)

    visit(boundary.cfunc.statements)
    return removed


def lower_wide_call_return_condition_chain_8616(
    codegen: object,
    expression: CExpression,
    conditions: tuple[ConditionIR, ...],
) -> WideCallReturnConditionResult8616:
    """Join a proven DX:AX lexicographic condition into one signed wide comparison."""
    boundary = cast(_CallOutputCodegen8616, codegen)
    raw_count = int(len(conditions) == 3)
    normalized_count = 0
    classified_count = 0
    materialized_count = 0
    consumed_call: CFunctionCall | None = None
    consumed_callsite: CallsiteSummary8616 | None = None
    ir_pair = _wide_call_return_condition_ir_8616(conditions)
    expression_parts = _wide_call_return_condition_expression_parts_8616(expression)
    lowered = expression
    if ir_pair is not None and expression_parts is not None:
        normalized_count = 1
        call_selection = _wide_condition_call_8616(boundary, conditions)
        call, callsite = call_selection if call_selection is not None else (None, None)
        wide_stack = (
            _wide_condition_stack_cvar_8616(
                boundary, expression_parts[0], expression_parts[1], ir_pair[0], ir_pair[1],
            )
            if call is not None
            else None
        )
        if call is not None and wide_stack is not None:
            classified_count = 1
            signed_call = CSemanticCast8616(
                None,
                SimTypeLong(True).with_arch(boundary.project.arch),
                call,
                codegen=codegen,
            )
            signed_stack = CSemanticCast8616(
                None,
                SimTypeLong(True).with_arch(boundary.project.arch),
                wide_stack,
                codegen=codegen,
            )
            lowered = CBinaryOp("CmpGT", signed_call, signed_stack, codegen=codegen)
            materialized_count = 1
            consumed_call = call
            consumed_callsite = callsite
    stats = WideCallReturnConditionStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=max(0, raw_count - materialized_count),
    )
    boundary._inertia_wide_call_return_condition_stats_8616 = stats
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError("classified wide call-return condition was not materialized")
    return WideCallReturnConditionResult8616(
        expression=lowered,
        stats=stats,
        consumed_call=consumed_call,
        consumed_callsite=consumed_callsite,
    )


def _aggregate_boundaries_8616(codegen: object, root: object) -> tuple[int, ...]:
    """Return stack offsets with independently proven aggregate types."""
    offsets: set[int] = set()
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CVariable):
            continue
        variable = node.variable
        if (
            isinstance(variable, SimStackVariable)
            and variable.base == "bp"
            and isinstance((bp_offset := machine_bp_offset_for_stack_variable_8616(codegen, variable)), int)
            and isinstance(node.variable_type, (SimTypeArray, SimStruct))
        ):
            offsets.add(bp_offset)
    return tuple(sorted(offsets))


def _stack_cvar_at_base_offset_8616(
    codegen: _CallOutputCodegen8616,
    base_offset: int,
) -> CVariable | None:
    """Return the authoritative projected owner rooted at ``base_offset``."""
    projected = {
        id(projection.variable): projection.cvar
        for projection in stack_variable_coordinate_registry_8616(codegen).projections
        if projection.bp_offset == base_offset and isinstance(projection.cvar, CVariable)
    }
    if len(projected) == 1:
        return next(iter(projected.values()))
    if projected:
        return None
    candidates: dict[int, CVariable] = {}
    for variable, cvar in codegen.cfunc.variables_in_use.items():
        if (
            isinstance(variable, SimStackVariable)
            and variable.base == "bp"
            and machine_bp_offset_for_stack_variable_8616(codegen, variable) == base_offset
            and isinstance(cvar, CVariable)
        ):
            candidates[id(variable)] = cvar
    if len(candidates) != 1:
        return None
    return next(iter(candidates.values()))


def _summary_bp_address_offsets_8616(summary: CallsiteSummary8616) -> tuple[int, ...]:
    """Return exact BP-address arguments proven by one typed callsite summary."""
    offsets: list[int] = []
    for source in summary.push_arg_sources:
        if (
            isinstance(source, tuple)
            and len(source) == 2
            and source[0] == "bp_addr"
            and isinstance(source[1], int)
            and source[1] < 0
        ):
            offsets.append(source[1])
    return tuple(dict.fromkeys(offsets))


def _call_addressed_bases_8616(
    codegen: _CallOutputCodegen8616,
) -> tuple[_CallAddressedStackBase8616, ...]:
    """Return callsite-addressed stack bases from structured call arguments."""
    bases: list[_CallAddressedStackBase8616] = []
    try:
        summary_map = codegen._inertia_callsite_summaries
    except AttributeError:
        summary_map = {}
    for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements):
        if not isinstance(node, CFunctionCall):
            continue
        summary = summary_map.get(id(node))
        if summary is None:
            continue
        referenced_bases: list[CVariable] = []
        for argument in node.args:
            if not isinstance(argument, CExpression):
                continue
            base = _referenced_stack_cvar_8616(argument)
            if base is not None:
                referenced_bases.append(base)
        summary_offsets = _summary_bp_address_offsets_8616(summary)
        if len(referenced_bases) == 1 and len(summary_offsets) == 1:
            bases.append(
                _CallAddressedStackBase8616(
                    callsite_addr=summary.callsite_addr,
                    base_offset=summary_offsets[0],
                    base_cvar=referenced_bases[0],
                )
            )
            continue
        for base in referenced_bases:
            variable = cast(SimStackVariable, base.variable)
            base_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
            if base_offset is None:
                continue
            bases.append(
                _CallAddressedStackBase8616(
                    callsite_addr=summary.callsite_addr,
                    base_offset=base_offset,
                    base_cvar=base,
                )
            )
    for callsite_addr, summary in _callsite_inventory_8616(codegen).items():
        for base_offset in _summary_bp_address_offsets_8616(summary):
            base = _stack_cvar_at_base_offset_8616(codegen, base_offset)
            bases.append(
                _CallAddressedStackBase8616(
                    callsite_addr=callsite_addr,
                    base_offset=base_offset,
                    base_cvar=base,
                )
            )
    unique: dict[tuple[int, int], _CallAddressedStackBase8616] = {}
    for base in bases:
        key = base.callsite_addr, base.base_offset
        previous = unique.get(key)
        if previous is None or (previous.base_cvar is None and base.base_cvar is not None):
            unique[key] = base
    return tuple(unique.values())


def _synthetic_stack_object_base_8616(
    codegen: _CallOutputCodegen8616,
    base_offset: int,
    boundary_offset: int,
) -> CVariable:
    """Create an unregistered aggregate carrier from one closed stack extent."""
    byte_size = boundary_offset - base_offset
    if byte_size <= 0:
        raise PipelineHardError("call-output stack object must have a positive extent")
    variable = SimStackVariable(
        base_offset,
        byte_size,
        base="bp",
        name=f"stack_object_{abs(base_offset):x}",
        region=codegen.cfunc.addr,
    )
    return CVariable(
        variable,
        variable_type=SimTypeArray(SimTypeChar(False), byte_size),
        codegen=codegen,
    )


def _nonoverlapping_fields_8616(
    slices: set[tuple[int, int]],
    base_offset: int,
) -> tuple[CallOutputStackField8616, ...] | None:
    """Classify non-overlapping field slices relative to one object base."""
    ordered = sorted(slices)
    previous_end = base_offset
    fields: list[CallOutputStackField8616] = []
    for absolute_offset, width in ordered:
        if absolute_offset < previous_end:
            return None
        relative_offset = absolute_offset - base_offset
        fields.append(
            CallOutputStackField8616(
                absolute_offset=absolute_offset,
                relative_offset=relative_offset,
                width=width,
                name=f"field_{relative_offset}",
            )
        )
        previous_end = absolute_offset + width
    return tuple(fields)


def recover_call_output_stack_object_facts_8616(
    codegen: object,
    conditions: tuple[ConditionIR, ...],
) -> tuple[tuple[CallOutputStackObjectFact8616, ...], CallOutputStackObjectStats8616]:
    """Recover closed stack-object field facts for one structured condition set."""
    boundary = cast(_CallOutputCodegen8616, codegen)
    try:
        root = boundary.cfunc.statements
        call_bases = _call_addressed_bases_8616(boundary)
    except AttributeError:
        return (), CallOutputStackObjectStats8616()
    condition_slices = _condition_stack_slices_8616(conditions)
    aggregate_boundaries = _aggregate_boundaries_8616(boundary, root)
    if os.environ.get("INERTIA_DEBUG_CALL_OUTPUT_STACK_OBJECTS") == "1":
        _LOGGER.warning(
            "call-output object evidence: call_bases=%r condition_slices=%r "
            "aggregate_boundaries=%r",
            call_bases,
            condition_slices,
            aggregate_boundaries,
        )
    raw_count = len(call_bases) + len(condition_slices)
    grouped: dict[tuple[int, int, int], tuple[CVariable | None, set[tuple[int, int]]]] = {}
    failures = 0
    for instruction_addr, absolute_offset, width in condition_slices:
        candidates: list[tuple[_CallAddressedStackBase8616, int]] = []
        for call_base in call_bases:
            upper_offsets = tuple(offset for offset in aggregate_boundaries if offset > call_base.base_offset)
            if not upper_offsets:
                continue
            boundary_offset = min(upper_offsets)
            if (
                call_base.callsite_addr < instruction_addr
                and call_base.base_offset < absolute_offset
                and absolute_offset + width <= boundary_offset
            ):
                candidates.append((call_base, boundary_offset))
        if not candidates:
            continue
        call_base, boundary_offset = max(candidates, key=lambda item: item[0].callsite_addr)
        key = call_base.callsite_addr, call_base.base_offset, boundary_offset
        base_cvar = call_base.base_cvar
        stored_base, slices = grouped.setdefault(key, (base_cvar, set()))
        if (
            stored_base is not None
            and base_cvar is not None
            and stored_base.variable is not base_cvar.variable
        ):
            failures += 1
            continue
        slices.add((absolute_offset, width))

    facts: list[CallOutputStackObjectFact8616] = []
    for (callsite_addr, base_offset, boundary_offset), (base_cvar, slices) in sorted(grouped.items()):
        fields = _nonoverlapping_fields_8616(slices, base_offset)
        if not fields:
            failures += 1
            continue
        if base_cvar is None:
            base_cvar = _synthetic_stack_object_base_8616(
                boundary,
                base_offset,
                boundary_offset,
            )
        facts.append(
            CallOutputStackObjectFact8616(
                callsite_addr=callsite_addr,
                base_offset=base_offset,
                boundary_offset=boundary_offset,
                base_variable=cast(SimStackVariable, base_cvar.variable),
                base_cvar=base_cvar,
                fields=fields,
            )
        )
    stats = CallOutputStackObjectStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=len(condition_slices),
        classified_fact_count=sum(len(fact.fields) for fact in facts),
        materialized_count=0,
        failure_count=failures,
    )
    if os.environ.get("INERTIA_DEBUG_CALL_OUTPUT_STACK_OBJECTS") == "1":
        _LOGGER.warning(
            "call-output object recovery: facts=%r stats=%r",
            tuple(facts),
            stats,
        )
    return tuple(facts), stats


def _replay_call_output_stack_object_facts_8616(
    codegen: _CallOutputCodegen8616,
    conditions: tuple[ConditionIR, ...],
    previous_facts: tuple[CallOutputStackObjectFact8616, ...],
) -> tuple[CallOutputStackObjectFact8616, ...]:
    """Rebind previously proven object facts after structured AST regeneration.

    A rebuilt tree may temporarily lose the adjacent aggregate declaration that
    originally closed the object boundary. Replay still requires the exact
    typed callsite/base pair and every ConditionIR field slice. A newly visible
    aggregate boundary inside the proven object invalidates the old fact.
    """
    if not previous_facts:
        return ()
    try:
        root = codegen.cfunc.statements
        call_bases = _call_addressed_bases_8616(codegen)
    except AttributeError:
        return ()
    condition_slices = {
        (absolute_offset, width)
        for _instruction_addr, absolute_offset, width in _condition_stack_slices_8616(
            conditions
        )
    }
    aggregate_boundaries = _aggregate_boundaries_8616(codegen, root)
    replayed: list[CallOutputStackObjectFact8616] = []
    for fact in previous_facts:
        matching_bases = tuple(
            call_base
            for call_base in call_bases
            if call_base.callsite_addr == fact.callsite_addr
            and call_base.base_offset == fact.base_offset
        )
        if len(matching_bases) != 1:
            continue
        if any(
            (field.absolute_offset, field.width) not in condition_slices
            for field in fact.fields
        ):
            continue
        if any(
            fact.base_offset < boundary < fact.boundary_offset
            for boundary in aggregate_boundaries
        ):
            continue
        current_base = matching_bases[0].base_cvar or fact.base_cvar
        current_variable = current_base.variable
        if not isinstance(current_variable, SimStackVariable):
            continue
        replayed.append(
            CallOutputStackObjectFact8616(
                callsite_addr=fact.callsite_addr,
                base_offset=fact.base_offset,
                boundary_offset=fact.boundary_offset,
                base_variable=current_variable,
                base_cvar=current_base,
                fields=fact.fields,
            )
        )
    return tuple(replayed)


def _field_type_8616(width: int) -> SimType:
    """Return an unsigned scalar type for one proven field width."""
    if width == 1:
        return SimTypeChar(False)
    if width == 2:
        return SimTypeShort(False)
    if width == 4:
        return SimTypeLong(False)
    return SimTypeArray(SimTypeChar(False), width)


def _struct_type_for_fact_8616(fact: CallOutputStackObjectFact8616) -> SimStruct:
    """Build a packed generic struct preserving all proven field offsets."""
    fields: OrderedDict[str, SimType] = OrderedDict()
    cursor = 0
    for field in fact.fields:
        if field.relative_offset > cursor:
            fields[f"padding_{cursor}"] = SimTypeArray(SimTypeChar(False), field.relative_offset - cursor)
        fields[field.name] = _field_type_8616(field.width)
        cursor = field.relative_offset + field.width
    byte_size = fact.boundary_offset - fact.base_offset
    if cursor < byte_size:
        fields[f"padding_{cursor}"] = SimTypeArray(SimTypeChar(False), byte_size - cursor)
    layout = "_".join(f"{field.relative_offset}w{field.width}" for field in fact.fields)
    return SimStruct(fields, name=f"inertia_stack_object_{byte_size}_{layout}", pack=True)


def _prepare_object_type_8616(
    codegen: _CallOutputCodegen8616,
    fact: CallOutputStackObjectFact8616,
    struct_type: SimStruct,
) -> bool:
    """Publish the object type and report changes to its declaration cache."""
    publish_call_output_object_projection_8616(
        codegen, fact.base_cvar, bp_offset=fact.base_offset,
        byte_size=fact.boundary_offset - fact.base_offset,
    )
    cfunc = codegen.cfunc
    cfunc.variable_manager.types[struct_type.name] = TypeRef(struct_type.name, struct_type)
    cfunc.variable_manager.set_variable_type(fact.base_variable, struct_type, override_bot=True)
    arch_type = struct_type.with_arch(codegen.project.arch)
    cfunc.variables_in_use.setdefault(fact.base_variable, fact.base_cvar)
    for node in _iter_c_nodes_deep_8616(cfunc.statements):
        if isinstance(node, CVariable) and node.variable is fact.base_variable:
            node.variable_type = arch_type
    base_in_use = cfunc.variables_in_use.get(fact.base_variable)
    if base_in_use is not None:
        base_in_use.variable_type = arch_type
    declarations_changed = synchronize_call_output_object_declaration_8616(codegen, fact.base_cvar, arch_type)
    codegen.show_local_types = True
    return declarations_changed


def _replace_stack_fields_8616(
    expression: CExpression,
    codegen: _CallOutputCodegen8616,
    field_map: dict[int, tuple[CallOutputStackObjectFact8616, CallOutputStackField8616, SimStruct]],
) -> tuple[CExpression, int]:
    """Replace exact stack variables in one condition expression with fields."""
    if isinstance(expression, CVariableField) and not expression.var_is_ptr:
        base = expression.variable
        variable = base.variable if isinstance(base, CVariable) else None
        field_offset = expression.field.offset
        if (
            isinstance(variable, SimStackVariable)
            and isinstance((bp_offset := machine_bp_offset_for_stack_variable_8616(codegen, variable)), int)
            and isinstance(field_offset, int)
        ):
            match = field_map.get(bp_offset + field_offset)
            if (
                match is not None
                and match[0].base_offset == bp_offset
                and match[1].relative_offset == field_offset
                and match[1].name == expression.field.field
            ):
                return expression, 1
        return expression, 0
    if isinstance(expression, CVariable):
        variable = expression.variable
        if isinstance(variable, SimStackVariable):
            bp_offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
            match = field_map.get(bp_offset) if bp_offset is not None else None
            if match is not None:
                fact, field, struct_type = match
                base = CVariable(
                    fact.base_variable,
                    unified_variable=fact.base_cvar.unified_variable,
                    variable_type=struct_type,
                    vvar_id=fact.base_cvar.vvar_id,
                    codegen=codegen,
                )
                replacement = CVariableField(
                    base,
                    CStructField(struct_type, field.relative_offset, field.name, codegen=codegen),
                    var_is_ptr=False,
                    codegen=codegen,
                )
                replacement.tags = dict(expression.tags)
                return replacement, 1
        return expression, 0
    if isinstance(expression, CBinaryOp):
        lhs, lhs_count = _replace_stack_fields_8616(expression.lhs, codegen, field_map)
        rhs, rhs_count = _replace_stack_fields_8616(expression.rhs, codegen, field_map)
        expression.lhs = lhs
        expression.rhs = rhs
        return expression, lhs_count + rhs_count
    if isinstance(expression, CUnaryOp):
        operand, count = _replace_stack_fields_8616(expression.operand, codegen, field_map)
        expression.operand = operand
        return expression, count
    if isinstance(expression, CTypeCast):
        inner, count = _replace_stack_fields_8616(expression.expr, codegen, field_map)
        expression.expr = inner
        return expression, count
    return expression, 0


def lower_call_output_stack_fields_in_condition_8616(
    codegen: object,
    expression: CExpression,
    conditions: tuple[ConditionIR, ...],
) -> CallOutputConditionLoweringResult8616:
    """Project proven call-output stack fields into one condition expression."""
    boundary = cast(_CallOutputCodegen8616, codegen)
    recovered_facts, recovery_stats = recover_call_output_stack_object_facts_8616(
        codegen,
        conditions,
    )
    try:
        previous_facts = boundary._inertia_call_output_stack_object_facts_8616
    except AttributeError:
        previous_facts = ()
    replayed_facts = _replay_call_output_stack_object_facts_8616(
        boundary,
        conditions,
        previous_facts,
    )
    facts_by_key: dict[
        tuple[int, int, int, tuple[CallOutputStackField8616, ...]],
        CallOutputStackObjectFact8616,
    ] = {}
    for fact in (*recovered_facts, *replayed_facts):
        key = (
            fact.callsite_addr,
            fact.base_offset,
            fact.boundary_offset,
            fact.fields,
        )
        facts_by_key.setdefault(key, fact)
    facts = tuple(facts_by_key.values())
    classified_count = sum(len(fact.fields) for fact in facts)
    field_map: dict[int, tuple[CallOutputStackObjectFact8616, CallOutputStackField8616, SimStruct]] = {}
    for fact in facts:
        struct_type = _struct_type_for_fact_8616(fact)
        _prepare_object_type_8616(boundary, fact, struct_type)
        for field in fact.fields:
            field_map[field.absolute_offset] = fact, field, struct_type
    lowered, materialized_count = _replace_stack_fields_8616(expression, boundary, field_map)
    stats = CallOutputStackObjectStats8616(
        raw_fact_count=recovery_stats.raw_fact_count,
        normalized_fact_count=recovery_stats.normalized_fact_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=recovery_stats.failure_count
        + max(0, classified_count - materialized_count),
    )
    try:
        previous_stats = boundary._inertia_call_output_stack_object_stats_8616
    except AttributeError:
        previous_stats = CallOutputStackObjectStats8616()
    boundary._inertia_call_output_stack_object_stats_8616 = previous_stats.merged(stats)
    boundary._inertia_call_output_stack_object_facts_8616 = tuple(dict.fromkeys((*previous_facts, *facts)))
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError("classified call-output stack fields were not materialized")
    return CallOutputConditionLoweringResult8616(lowered, facts, stats)


def prune_materialized_call_output_stack_carriers_8616(codegen: object) -> int:
    """Remove declarations for field slices no longer referenced as scalars."""
    boundary = cast(_CallOutputCodegen8616, codegen)
    try:
        facts = boundary._inertia_call_output_stack_object_facts_8616
        cfunc = boundary.cfunc
    except AttributeError:
        return 0
    if not facts:
        return 0
    remaining_offsets = {
        bp_offset
        for node in _iter_c_nodes_deep_8616(cfunc.statements)
        if isinstance(node, CVariable)
        and isinstance((variable := node.variable), SimStackVariable)
        and isinstance((bp_offset := machine_bp_offset_for_stack_variable_8616(boundary, variable)), int)
    }
    projected_offsets = {field.absolute_offset for fact in facts for field in fact.fields}
    removed = 0
    for variable in tuple(cfunc.variables_in_use):
        if (
            isinstance(variable, SimStackVariable)
            and (bp_offset := machine_bp_offset_for_stack_variable_8616(boundary, variable)) in projected_offsets
            and bp_offset not in remaining_offsets
        ):
            del cfunc.variables_in_use[variable]
            removed += 1
    if removed:
        cfunc.refresh()
    return removed


__all__ = [
    "CallOutputConditionLoweringResult8616",
    "CallOutputStackField8616",
    "CallOutputStackObjectFact8616",
    "CallOutputStackObjectStats8616",
    "WideCallReturnConditionResult8616",
    "WideCallReturnConditionStats8616",
    "lower_call_output_stack_fields_in_condition_8616",
    "lower_wide_call_return_condition_chain_8616",
    "prune_materialized_call_output_stack_carriers_8616",
    "prune_materialized_wide_condition_call_carrier_8616",
    "recover_call_output_stack_object_facts_8616",
    "select_wide_call_return_condition_chain_8616",
]
