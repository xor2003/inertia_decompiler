"""Materialize proven call-return values used as structured conditions.

Layer: Structuring.
Responsibility: binds an existing structured condition to one exact typed
callsite whose AX-family return value feeds that condition.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.

This module owns only the call-to-condition CFG shape. Callsite discovery,
argument recovery, return-use classification, and register identity are
upstream typed evidence. Argument materialization remains in Types/Lowering.
Refuse ambiguous facts; never infer calls from rendered C, names, or samples.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpression,
    CFunctionCall,
    CIfElse,
    CReturn,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from archinfo import Arch

from ..c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616
from ..call_target_identity import (
    resolve_x86_16_call_target_function_8616,
    x86_16_call_targets_equivalent_8616,
)
from ..caller_return_use_contracts import CallsiteReturnUseKind8616
from ..callsite_summary import (
    CallsiteSummary8616,
    bind_structured_callsite_identity_8616,
    structured_callsite_addr_8616,
)
from ..ir.condition_ir import ConditionIR
from ..ir.core import IRValue, MemSpace
from ..lowering.call_return_stack_bindings import (
    materialize_call_return_stack_destination_8616,
)
from ..lowering.call_return_stack_stores import (
    CallReturnStackStoreEvidence8616,
    classify_call_return_stack_store_8616,
)
from ..pipeline.errors import PipelineHardError
from ..structured_tags import copy_structured_tags_8616
from .bound_call_condition import materialize_bound_call_condition_8616
from .call_return_register_index import (
    CallReturnRegisterIndex8616,
    build_call_return_register_index_8616,
)
from .call_return_register_placement import (
    CallReturnRegisterPlacementVerdict8616,
    classify_call_return_register_placement_8616,
    consume_exact_call_return_register_placement_8616,
)
from .call_return_store_placement import (
    CallReturnStorePlacement8616,
    bind_adjacent_standalone_call_store_8616,
    bind_proven_call_result_bridge_8616,
    find_adjacent_assigned_call_store_8616,
    find_adjacent_standalone_call_store_8616,
    find_proven_call_result_bridge_8616,
    is_exact_call_return_stack_destination_8616,
)
from .condition_replay import bind_condition_replay_identity_8616
from .expression_substitution import replace_exact_expression_8616


class _CallReturnFunction8616(Protocol):
    """Exact callee surface required to construct one structured call."""

    addr: int
    name: str


class _CallReturnFunctionManager8616(Protocol):
    """Third-party angr function lookup boundary."""

    def function(self, *, addr: int, create: bool) -> _CallReturnFunction8616 | None:
        """Return one exact existing function."""


class _CallReturnKnowledgeBase8616(Protocol):
    """Third-party angr knowledge-base boundary."""

    functions: _CallReturnFunctionManager8616


class _CallReturnProject8616(Protocol):
    """Project fields required by call-return condition materialization."""

    arch: Arch
    kb: _CallReturnKnowledgeBase8616


class _CallReturnCFunction8616(Protocol):
    """Structured function root owned by angr codegen."""

    statements: object


class _CallReturnCodegen8616(Protocol):
    """Owned evidence fields consumed and produced by this pass."""

    cfunc: _CallReturnCFunction8616
    _inertia_typed_conditions: object
    _inertia_callsite_summary_inventory_8616: dict[int, CallsiteSummary8616]
    _inertia_callsite_summaries: dict[int, CallsiteSummary8616]
    _inertia_call_return_condition_stats_8616: CallReturnConditionStats8616
    _inertia_call_return_store_bridges_8616: dict[int, CallReturnStoreBridgeRecord8616]


@dataclass(frozen=True, slots=True)
class CallReturnConditionStats8616:
    """Closed evidence accounting for call-return condition materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    store_bridge_materialized_count: int = 0
    store_bridge_reused_carrier_count: int = 0
    store_bridge_return_registers: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CallReturnStoreBridgeRecord8616:
    """Durable typed proof that one callsite was bound through its result store."""

    callsite_addr: int
    return_register: str
    reused_carrier_count: int


@dataclass(frozen=True, slots=True)
class _StoredCallReturnConditionResult8616:
    """One materialized value-return condition and its bridge accounting."""

    expression: CExpression
    changed: bool
    store_bridge_materialized: bool = False
    reused_carrier_count: int = 0


def structured_condition_key_8616(expression: object) -> tuple[int, int] | None:
    """Return one exact typed condition instruction/block identity."""
    for node in _iter_c_nodes_deep_8616(expression):
        tags = copy_structured_tags_8616(node.tags) if isinstance(node, CExpression) else None
        if tags is None:
            continue
        ins_addr = tags.get("ins_addr")
        block_addr = tags.get("vex_block_addr")
        if isinstance(ins_addr, int) and isinstance(block_addr, int):
            return ins_addr, block_addr
    return None


def _condition_from_structured_callsite_identity_8616(
    expression: object,
    inventory: dict[int, CallsiteSummary8616],
    conditions_by_block: dict[int, ConditionIR],
) -> ConditionIR | None:
    """Select one condition from exact structured callsite return-block identity."""
    matches: list[ConditionIR] = []
    for node in _iter_c_nodes_deep_8616(expression):
        if not isinstance(node, CFunctionCall):
            continue
        callsite_addr = structured_callsite_addr_8616(node)
        summary = inventory.get(callsite_addr) if isinstance(callsite_addr, int) else None
        condition = (
            conditions_by_block.get(summary.return_addr)
            if summary is not None and isinstance(summary.return_addr, int)
            else None
        )
        if condition is not None and condition not in matches:
            matches.append(condition)
    return matches[0] if len(matches) == 1 else None


def _return_register_slice_8616(
    project: _CallReturnProject8616,
    summary: CallsiteSummary8616,
) -> tuple[int, int] | None:
    """Resolve the summary return register through the active architecture."""
    register_name = summary.return_register
    if not isinstance(register_name, str):
        return None
    register = project.arch.registers.get(register_name.lower())
    if register is None:
        return None
    return int(register[0]), int(register[1])


def _is_constant_value_8616(value: object) -> bool:
    """Return whether one typed IR operand is an exact integer constant."""
    return isinstance(value, IRValue) and value.space is MemSpace.CONST and isinstance(value.const, int)


def _is_return_register_value_8616(
    value: object,
    register_slice: tuple[int, int],
) -> bool:
    """Return whether one typed IR operand is the exact return register."""
    return (
        isinstance(value, IRValue)
        and value.space is MemSpace.REG
        and int(value.offset) == register_slice[0]
        and int(value.size or register_slice[1]) == register_slice[1]
    )


def _condition_tests_return_register_8616(
    condition: ConditionIR,
    register_slice: tuple[int, int],
) -> bool:
    """Prove an equality-family zero test of the exact return register."""
    if condition.op not in {"eq", "ne", "zero", "nonzero"}:
        return False
    if condition.op in {"zero", "nonzero"}:
        return _is_return_register_value_8616(condition.lhs, register_slice)
    return (
        _is_return_register_value_8616(condition.lhs, register_slice)
        and _is_constant_value_8616(condition.rhs)
    ) or (
        _is_constant_value_8616(condition.lhs)
        and _is_return_register_value_8616(condition.rhs, register_slice)
    )


def _expression_return_register_count_8616(
    expression: object,
    register_slice: tuple[int, int],
) -> int:
    """Count exact structured return-register carriers in one condition."""
    count = 0
    for node in _iter_c_nodes_deep_8616(expression):
        if not isinstance(node, CVariable) or not isinstance(node.variable, SimRegisterVariable):
            continue
        variable = node.variable
        if int(variable.reg) == register_slice[0] and int(variable.size) == register_slice[1]:
            count += 1
    return count


def _replace_return_register_8616(
    expression: CExpression,
    register_slice: tuple[int, int],
    replacement: CExpression,
) -> CExpression:
    """Replace the single exact return-register leaf in a condition."""
    if isinstance(expression, CVariable) and isinstance(expression.variable, SimRegisterVariable):
        variable = expression.variable
        if int(variable.reg) == register_slice[0] and int(variable.size) == register_slice[1]:
            return replacement
        return expression
    if isinstance(expression, CBinaryOp):
        expression.lhs = _replace_return_register_8616(expression.lhs, register_slice, replacement)
        expression.rhs = _replace_return_register_8616(expression.rhs, register_slice, replacement)
    elif isinstance(expression, CUnaryOp):
        expression.operand = _replace_return_register_8616(expression.operand, register_slice, replacement)
    return expression


def _existing_callsite_count_8616(expression: object, callsite_addr: int) -> int:
    """Count already-bound calls for one exact machine callsite."""
    return sum(
        1
        for node in _iter_c_nodes_deep_8616(expression)
        if isinstance(node, CFunctionCall) and structured_callsite_addr_8616(node) == callsite_addr
    )


def _target_calls_8616(
    project: object,
    expression: object,
    target_addr: int,
) -> tuple[CFunctionCall, ...]:
    """Return calls whose exact angr callee address matches the typed target."""
    matches: list[CFunctionCall] = []
    for node in _iter_c_nodes_deep_8616(expression):
        if not isinstance(node, CFunctionCall) or node.callee_func is None:
            continue
        callee = cast(_CallReturnFunction8616, node.callee_func)
        try:
            callee_addr = callee.addr
        except AttributeError:
            continue
        if x86_16_call_targets_equivalent_8616(project, callee_addr, target_addr):
            matches.append(node)
    return tuple(matches)


def _stack_destination_count_8616(
    codegen: object,
    expression: object,
    evidence: CallReturnStackStoreEvidence8616,
) -> int:
    """Count exact uses of one proven BP-relative return-store object."""
    return sum(
        1
        for node in _iter_c_nodes_deep_8616(expression)
        if is_exact_call_return_stack_destination_8616(codegen, node, evidence)
    )


def _unique_summary_call_8616(
    project: object,
    root: object,
    summary: CallsiteSummary8616,
) -> CFunctionCall | None:
    """Resolve one structured call by exact callsite or unique target identity."""
    bound = tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CFunctionCall) and structured_callsite_addr_8616(node) == summary.callsite_addr
    )
    if len(bound) == 1:
        target_addr = summary.target_addr
        if not isinstance(target_addr, int):
            return None
        exact = _target_calls_8616(project, bound[0], target_addr)
        return bound[0] if len(exact) == 1 else None
    if bound or not isinstance(summary.target_addr, int):
        return None
    target_calls = _target_calls_8616(project, root, summary.target_addr)
    return target_calls[0] if len(target_calls) == 1 else None


def _unique_call_assignment_8616(root: object, call: CFunctionCall) -> CAssignment | None:
    """Return the unique assignment whose RHS contains the exact call node."""
    assignments = tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CAssignment)
        and any(candidate is call for candidate in _iter_c_nodes_deep_8616(node.rhs))
    )
    return assignments[0] if len(assignments) == 1 else None


def _materialize_stored_return_condition_8616(
    project: object,
    codegen: object,
    root: object,
    expression: CExpression,
    body: object,
    summary: CallsiteSummary8616,
    register_slice: tuple[int, int],
    summary_map: dict[int, CallsiteSummary8616],
) -> _StoredCallReturnConditionResult8616 | None:
    """Bind a value-return store and its branch to one exact stack local."""
    evidence = classify_call_return_stack_store_8616(summary)
    if evidence is None or evidence.width != register_slice[1]:
        return None
    call = _unique_summary_call_8616(project, root, summary)
    if call is None:
        return None
    assignment = _unique_call_assignment_8616(root, call)
    store_placement: CallReturnStorePlacement8616 | None = None
    bridge_placement: CallReturnStorePlacement8616 | None = None
    bridge_reused_carrier_count = 0
    if assignment is None:
        bridge_placement = find_proven_call_result_bridge_8616(
            root, call, evidence, codegen=codegen
        )
        store_placement = bridge_placement
        if store_placement is None:
            store_placement = find_adjacent_standalone_call_store_8616(
                root, call, evidence, codegen=codegen
            )
        if store_placement is None:
            return None
        assignment = store_placement.store_assignment
    elif not is_exact_call_return_stack_destination_8616(codegen, assignment.lhs, evidence):
        store_placement = find_adjacent_assigned_call_store_8616(
            root,
            assignment,
            call,
            evidence,
            codegen=codegen,
        )
        if store_placement is not None:
            assignment = store_placement.store_assignment
    if is_exact_call_return_stack_destination_8616(codegen, assignment.lhs, evidence):
        destination = assignment.lhs
        if not isinstance(destination, CVariable):
            return None
        register_count = _expression_return_register_count_8616(expression, register_slice)
        destination_count = _stack_destination_count_8616(codegen, expression, evidence)
        if not (
            (register_count == 1 and destination_count == 0)
            or (register_count == 0 and destination_count == 1)
        ):
            return None
        changed = False
        if register_count == 1:
            expression = _replace_return_register_8616(expression, register_slice, destination)
            changed = True
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, CReturn):
                continue
            retval = node.retval
            if not isinstance(retval, CVariable) or not isinstance(retval.variable, SimRegisterVariable):
                continue
            variable = retval.variable
            if (int(variable.reg), int(variable.size)) == register_slice:
                node.retval = destination
                changed = True
        if _stack_destination_count_8616(codegen, expression, evidence) != 1:
            return None
        if store_placement is not None:
            if bridge_placement is not None:
                reused_carrier_count = bind_proven_call_result_bridge_8616(
                    root,
                    bridge_placement,
                    call,
                    destination,
                )
                if reused_carrier_count is None:
                    return None
                bridge_reused_carrier_count = reused_carrier_count
                assignment = bridge_placement.store_assignment
            else:
                assignment = bind_adjacent_standalone_call_store_8616(
                    store_placement,
                    call,
                )
            changed = True
        _remove_redundant_return_bridge_8616(root, destination, register_slice, assignment)
        bind_structured_callsite_identity_8616(call, summary)
        summary_map[id(call)] = summary
        return _StoredCallReturnConditionResult8616(
            expression,
            changed,
            store_bridge_materialized=bridge_placement is not None,
            reused_carrier_count=bridge_reused_carrier_count,
        )
    old_lhs = assignment.lhs
    if not isinstance(old_lhs, CVariable) or not isinstance(old_lhs.variable, SimRegisterVariable):
        return None
    old_variable = old_lhs.variable
    if (int(old_variable.reg), int(old_variable.size)) != register_slice:
        return None
    definitions = sum(
        1
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, CAssignment)
        and isinstance(node.lhs, CVariable)
        and isinstance(node.lhs.variable, SimRegisterVariable)
        and (int(node.lhs.variable.reg), int(node.lhs.variable.size)) == register_slice
        and any(candidate is call for candidate in _iter_c_nodes_deep_8616(node.rhs))
    )
    if definitions != 1 or _expression_return_register_count_8616(expression, register_slice) != 1:
        return None
    destination = materialize_call_return_stack_destination_8616(
        codegen,
        evidence,
        preferred_name="err",
    )
    if not isinstance(destination, CVariable):
        return None

    def replace_return_slice(node: object) -> object:
        """Replace a cloned AX carrier in the condition or return branch."""
        if not isinstance(node, CVariable) or not isinstance(node.variable, SimRegisterVariable):
            return node
        variable = node.variable
        if (int(variable.reg), int(variable.size)) == register_slice:
            return destination
        return node

    assignment.lhs = destination
    changed = True
    changed = _replace_c_children_8616(expression, replace_return_slice) or changed
    def replace_return_statement(node: object) -> object:
        """Replace only return statements carrying this proven call result."""
        if not isinstance(node, CReturn):
            return node
        retval = node.retval
        if isinstance(retval, CVariable) and isinstance(retval.variable, SimRegisterVariable):
            variable = retval.variable
            if (int(variable.reg), int(variable.size)) == register_slice:
                node.retval = destination
        return node

    changed = _replace_c_children_8616(root, replace_return_statement) or changed
    remaining_registers = _expression_return_register_count_8616(expression, register_slice)
    if remaining_registers == 1:
        expression = _replace_return_register_8616(expression, register_slice, destination)
        changed = True
    elif remaining_registers != 0:
        return None
    if not changed or not is_exact_call_return_stack_destination_8616(
        codegen, assignment.lhs, evidence
    ):
        return None
    if _stack_destination_count_8616(codegen, expression, evidence) != 1:
        return None
    _remove_redundant_return_bridge_8616(root, destination, register_slice, assignment)
    bind_structured_callsite_identity_8616(call, summary)
    summary_map[id(call)] = summary
    return _StoredCallReturnConditionResult8616(expression, True)


def _remove_redundant_return_bridge_8616(
    root: object,
    destination: CVariable,
    register_slice: tuple[int, int],
    call_assignment: CAssignment,
) -> None:
    """Remove a redundant register-to-stack bridge only for a stack destination."""
    destination_variable = destination.variable
    if not isinstance(destination_variable, SimStackVariable):
        return
    for container in (root, *_iter_c_nodes_deep_8616(root)):
        if not isinstance(container, CStatements):
            continue
        statements = list(container.statements or ())
        filtered: list[object] = []
        for statement in statements:
            if statement is call_assignment or not isinstance(statement, CAssignment):
                filtered.append(statement)
                continue
            if not isinstance(statement.lhs, CVariable) or not isinstance(statement.rhs, CVariable):
                filtered.append(statement)
                continue
            lhs_variable = statement.lhs.variable
            if (
                not isinstance(lhs_variable, SimStackVariable)
                or lhs_variable.base != destination_variable.base
                or lhs_variable.offset != destination_variable.offset
                or lhs_variable.size != destination_variable.size
            ):
                filtered.append(statement)
                continue
            variable = statement.rhs.variable
            if not isinstance(variable, SimRegisterVariable) or (int(variable.reg), int(variable.size)) != register_slice:
                filtered.append(statement)
                continue
        if len(filtered) != len(statements):
            container.statements = filtered


def materialize_call_return_conditions_8616(project: object, codegen: object) -> bool:
    """Bind exact return-used callsites to their structured AX conditions."""
    typed_project = cast(_CallReturnProject8616, project)
    typed_codegen = cast(_CallReturnCodegen8616, codegen)
    try:
        root = typed_codegen.cfunc.statements
        inventory = typed_codegen._inertia_callsite_summary_inventory_8616
        conditions = tuple(
            condition
            for condition in cast(tuple[object, ...], typed_codegen._inertia_typed_conditions)
            if isinstance(condition, ConditionIR)
        )
    except (AttributeError, TypeError):
        return False
    if not isinstance(inventory, dict):
        raise TypeError("callsite summary inventory must be a dict")
    condition_by_key = {
        (condition.src_insn, condition.block_addr): condition
        for condition in conditions
        if isinstance(condition.src_insn, int) and isinstance(condition.block_addr, int)
    }
    conditions_by_block_candidates: dict[int, list[ConditionIR]] = {}
    for recorded_condition in conditions:
        if isinstance(recorded_condition.block_addr, int):
            conditions_by_block_candidates.setdefault(recorded_condition.block_addr, []).append(recorded_condition)
    conditions_by_block = {
        block_addr: candidates[0]
        for block_addr, candidates in conditions_by_block_candidates.items()
        if len(candidates) == 1
    }
    summaries_by_return = {
        summary.return_addr: summary
        for summary in inventory.values()
        if isinstance(summary, CallsiteSummary8616)
        and isinstance(summary.return_addr, int)
        and summary.return_used is True
        and summary.return_use_kind
        in {
            CallsiteReturnUseKind8616.CONDITION,
            CallsiteReturnUseKind8616.VALUE,
        }
        and isinstance(summary.target_addr, int)
    }
    raw = normalized = classified = materialized = failed = 0
    store_bridges = reused_carriers = 0
    store_bridge_return_registers: set[str] = set()
    changed = False
    register_assignment_index: CallReturnRegisterIndex8616 | None = None
    try:
        summary_map = typed_codegen._inertia_callsite_summaries
    except AttributeError:
        summary_map = {}
        typed_codegen._inertia_callsite_summaries = summary_map
    if not isinstance(summary_map, dict):
        raise TypeError("structured callsite summary map must be a dict")
    try:
        store_bridge_records = typed_codegen._inertia_call_return_store_bridges_8616
    except AttributeError:
        store_bridge_records = {}
        typed_codegen._inertia_call_return_store_bridges_8616 = store_bridge_records
    if not isinstance(store_bridge_records, dict) or any(
        not isinstance(callsite_addr, int) or not isinstance(record, CallReturnStoreBridgeRecord8616)
        for callsite_addr, record in store_bridge_records.items()
    ):
        raise TypeError("call-return store bridge carrier must contain typed records")
    for node in _iter_c_nodes_deep_8616(root):
        if not isinstance(node, CIfElse) or len(node.condition_and_nodes) != 1:
            continue
        expression, body = node.condition_and_nodes[0]
        key = structured_condition_key_8616(expression)
        condition = _condition_from_structured_callsite_identity_8616(
            expression,
            inventory,
            conditions_by_block,
        )
        if condition is None:
            condition = condition_by_key.get(key) if key is not None else None
        if condition is None or not isinstance(condition.block_addr, int):
            continue
        summary = summaries_by_return.get(condition.block_addr)
        if summary is None:
            continue
        raw += 1
        target_addr = summary.target_addr
        if not isinstance(target_addr, int):
            failed += 1
            continue
        register_slice = _return_register_slice_8616(typed_project, summary)
        if register_slice is None or not _condition_tests_return_register_8616(condition, register_slice):
            failed += 1
            continue
        normalized += 1
        bind_condition_replay_identity_8616(expression, condition)
        if summary.return_use_kind is CallsiteReturnUseKind8616.VALUE:
            stored_result = _materialize_stored_return_condition_8616(
                project,
                codegen,
                root,
                expression,
                body,
                summary,
                register_slice,
                summary_map,
            )
            if stored_result is None:
                failed += 1
                continue
            replacement = stored_result.expression
            node.condition_and_nodes = [(replacement, body)]
            classified += 1
            materialized += 1
            if stored_result.store_bridge_materialized and isinstance(summary.return_register, str):
                store_bridge_records[summary.callsite_addr] = CallReturnStoreBridgeRecord8616(
                    callsite_addr=summary.callsite_addr,
                    return_register=summary.return_register.lower(),
                    reused_carrier_count=stored_result.reused_carrier_count,
                )
            bridge_record = store_bridge_records.get(summary.callsite_addr)
            if (
                bridge_record is not None
                and isinstance(summary.return_register, str)
                and bridge_record.return_register == summary.return_register.lower()
            ):
                store_bridges += 1
                reused_carriers += bridge_record.reused_carrier_count
                store_bridge_return_registers.add(bridge_record.return_register)
            changed = stored_result.changed or changed
            if register_assignment_index is not None:
                register_assignment_index.invalidate()
            register_assignment_index = None
            continue
        existing_count = _existing_callsite_count_8616(expression, summary.callsite_addr)
        placement = (
            classify_call_return_register_placement_8616(
                root,
                node,
                callsite_addr=summary.callsite_addr,
                condition_producer_insn=condition.producer_insn,
                register_slice=register_slice,
                assignment_index=(
                    register_assignment_index
                    if register_assignment_index is not None
                    else (
                        register_assignment_index := build_call_return_register_index_8616(
                            root
                        )
                    )
                ),
            )
            if isinstance(condition.producer_insn, int)
            else None
        )
        if placement is not None and placement.verdict is CallReturnRegisterPlacementVerdict8616.EXACT:
            existing_call = placement.call
            if (
                existing_call is None
                or len(_target_calls_8616(project, existing_call, target_addr)) != 1
                or any(
                    len(_target_calls_8616(project, duplicate.call, target_addr)) != 1
                    for duplicate in placement.redundant_assignments
                )
            ):
                failed += 1
                continue
            if existing_count == 1:
                condition_calls = _target_calls_8616(project, expression, target_addr)
                if len(condition_calls) != 1:
                    failed += 1
                    continue
                replacement = replace_exact_expression_8616(
                    expression,
                    condition_calls[0],
                    existing_call,
                )
            elif existing_count == 0:
                unbound_target_calls = _target_calls_8616(
                    project,
                    expression,
                    target_addr,
                )
                return_register_count = _expression_return_register_count_8616(
                    expression,
                    register_slice,
                )
                if len(unbound_target_calls) == 1 and return_register_count == 0:
                    replacement = replace_exact_expression_8616(
                        expression,
                        unbound_target_calls[0],
                        existing_call,
                    )
                elif not unbound_target_calls and return_register_count == 1:
                    replacement = _replace_return_register_8616(
                        expression,
                        register_slice,
                        existing_call,
                    )
                else:
                    failed += 1
                    continue
            else:
                failed += 1
                continue
            if not consume_exact_call_return_register_placement_8616(placement):
                failed += 1
                continue
            register_assignment_index = None
            node.condition_and_nodes = [(replacement, body)]
            bind_structured_callsite_identity_8616(existing_call, summary)
            summary_map[id(existing_call)] = summary
            classified += 1
            materialized += 1
            changed = True
            continue
        if placement is not None and placement.verdict is not CallReturnRegisterPlacementVerdict8616.MISSING:
            failed += 1
            continue
        if existing_count == 1:
            exact_calls = _target_calls_8616(project, expression, target_addr)
            if len(exact_calls) != 1:
                failed += 1
                continue
            bind_structured_callsite_identity_8616(exact_calls[0], summary)
            summary_map[id(exact_calls[0])] = summary
            replacement = materialize_bound_call_condition_8616(expression, exact_calls[0], condition, codegen)
            node.condition_and_nodes = [(replacement, body)]
            changed = replacement is not expression or changed
            classified += 1
            materialized += 1
            continue
        if existing_count != 0:
            failed += 1
            continue
        if (
            register_assignment_index is None
            or register_assignment_index.bound_callsite_count(summary.callsite_addr)
            != 0
        ):
            failed += 1
            continue
        target_calls = _target_calls_8616(project, expression, target_addr)
        if len(target_calls) == 1:
            callee = resolve_x86_16_call_target_function_8616(project, target_addr)
            if callee is None or not isinstance(callee.name, str) or not callee.name:
                failed += 1
                continue
            call = CFunctionCall(callee.name, callee, [], codegen=codegen)
            bind_structured_callsite_identity_8616(call, summary)
            summary_map[id(call)] = summary
            replacement = replace_exact_expression_8616(expression, target_calls[0], call)
            node.condition_and_nodes = [(replacement, body)]
            classified += 1
            materialized += 1
            changed = True
            register_assignment_index.invalidate()
            register_assignment_index = None
            continue
        if target_calls or _expression_return_register_count_8616(expression, register_slice) != 1:
            failed += 1
            continue
        callee = resolve_x86_16_call_target_function_8616(project, target_addr)
        if callee is None or not isinstance(callee.name, str) or not callee.name:
            failed += 1
            continue
        classified += 1
        call = CFunctionCall(callee.name, callee, [], codegen=codegen)
        bind_structured_callsite_identity_8616(call, summary)
        summary_map[id(call)] = summary
        original_tags = copy_structured_tags_8616(expression.tags) or {}
        replacement = _replace_return_register_8616(expression, register_slice, call)
        if replacement is call:
            replacement = CBinaryOp(
                "CmpNE",
                call,
                CConstant(0, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
                tags=original_tags,
            )
        node.condition_and_nodes = [(replacement, body)]
        materialized += 1
        changed = True
        register_assignment_index.invalidate()
        register_assignment_index = None
    stats = CallReturnConditionStats8616(
        raw_fact_count=raw,
        normalized_fact_count=normalized,
        classified_fact_count=classified,
        materialized_count=materialized,
        failure_count=failed,
        store_bridge_materialized_count=store_bridges,
        store_bridge_reused_carrier_count=reused_carriers,
        store_bridge_return_registers=tuple(sorted(store_bridge_return_registers)),
    )
    typed_codegen._inertia_call_return_condition_stats_8616 = stats
    if stats.classified_fact_count > 0 and stats.materialized_count == 0:
        raise PipelineHardError("classified call-return conditions were not materialized")
    return changed
