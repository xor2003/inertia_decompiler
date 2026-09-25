"""Materialize CFG-oriented typed loop continuation conditions.

Layer: Structuring.
Responsibility: orient proven ``ConditionIR`` facts as structured loop continuation expressions.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup, postprocess, or CLI/reporting work here.

This pass consumes exact instruction/block identity and CFG reachability.  It
does not decode instructions, recover operands, or infer semantics from
rendered C.  Ambiguous condition ownership or continuation polarity is refused
and leaves the existing loop condition unchanged.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CDoWhileLoop,
    CExpression,
    CForLoop,
    CIfBreak,
    CIfElse,
    CStatement,
    CStatements,
    CUnaryOp,
    CVariable,
    CWhileLoop,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable

from ..c_ast_utils import (
    _clone_c_ast_tree_8616,
    _iter_c_nodes_deep_8616,
    _replace_c_children_8616,
    _same_c_expression_8616,
)
from ..ir.condition_ir import ConditionIR, ConditionRegisterUpdateIR
from ..ir.core import IRBinaryValue, IRValue, MemSpace
from .condition_lowering import lower_ir_value_to_c_expr_8616
from .loop_condition_identity import loop_condition_keys_8616
from .loop_condition_ownership import (
    CompositeLoopExitOwnershipStatus8616,
    classify_composite_loop_exit_ownership_8616,
)
from .pretest_condition_surface import pretest_condition_surface_8616

log: logging.Logger = logging.getLogger(__name__)


def _debug_loop_selection_8616(**fields: object) -> None:
    """Report exact loop-condition ownership evidence when diagnostics are enabled."""
    if os.environ.get("INERTIA_DEBUG_CONDITION_MATERIALIZATION") != "1":
        return
    details = " ".join(f"{key}={value!r}" for key, value in sorted(fields.items()))
    log.warning("[loop-condition-materialization] %s", details)


class LoopContinuationEdge8616(Enum):
    """CFG edge whose target returns to the loop condition block."""

    TAKEN = "taken"
    FALLTHROUGH = "fallthrough"


class _TaggedExpressionBoundary8616(Protocol):
    """Dynamic angr C-expression tag surface used at the Structuring boundary."""

    tags: dict[str, object]


class _LoopBoundary8616(Protocol):
    """Dynamic angr structured-loop condition slot."""

    condition: CExpression | None
    body: object


class _CodegenFunctionBoundary8616(Protocol):
    """Dynamic angr C-function identity used for register ownership."""

    addr: int


class _ArchBoundary8616(Protocol):
    """Dynamic angr architecture register surface used at the boundary."""

    registers: Mapping[str, tuple[int, int]]


class _ProjectBoundary8616(Protocol):
    """Dynamic angr project architecture surface used at the boundary."""

    arch: _ArchBoundary8616


class _CodegenBoundary8616(Protocol):
    """Dynamic angr codegen surface used for register ownership."""

    cfunc: _CodegenFunctionBoundary8616 | None
    project: _ProjectBoundary8616


@dataclass(frozen=True, slots=True)
class _RegisterUpdateMaterialization8616:
    """Internal result of one typed loop-register update materialization."""

    changed: bool = False
    target: CVariable | None = None
    update: ConditionRegisterUpdateIR | None = None


@dataclass(frozen=True, slots=True)
class LoopConditionMaterializationStats8616:
    """Evidence accounting for typed loop continuation materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    changed_count: int = 0
    taken_continuation_count: int = 0
    fallthrough_continuation_count: int = 0
    counter_update_materialized_count: int = 0
    composite_loop_exit_owned_count: int = 0

    @property
    def changed(self) -> bool:
        """Return whether at least one loop condition was replaced."""
        return self.changed_count > 0


def _condition_key_8616(condition: ConditionIR) -> tuple[int, int] | None:
    """Return the exact JCC/block identity carried by one typed condition."""
    if not isinstance(condition.src_insn, int) or not isinstance(condition.block_addr, int):
        return None
    return condition.src_insn, condition.block_addr


def _tag_pairs_8616(expression: object) -> frozenset[tuple[int, int]]:
    """Return all complete instruction/block identities in one C subtree."""
    pairs: set[tuple[int, int]] = set()
    for node in _iter_c_nodes_deep_8616(expression):
        boundary = cast(_TaggedExpressionBoundary8616, node)
        try:
            tags = boundary.tags
        except AttributeError:
            continue
        ins_addr = tags.get("ins_addr")
        block_addr = tags.get("vex_block_addr")
        if isinstance(ins_addr, int) and isinstance(block_addr, int):
            pairs.add((ins_addr, block_addr))
    return frozenset(pairs)


def _reaches_8616(successors: Mapping[int, tuple[int, ...]], start: int, target: int) -> bool:
    """Return whether an in-function CFG path reaches ``target``."""
    pending = [start]
    visited: set[int] = set()
    while pending:
        address = pending.pop()
        if address == target:
            return True
        if address in visited:
            continue
        visited.add(address)
        pending.extend(successors.get(address, ()))
    return False


def _structured_body_block_addrs_8616(body: object) -> frozenset[int]:
    """Return statement-owned blocks, excluding reused operand provenance."""
    addresses: set[int] = set()
    for node in _iter_c_nodes_deep_8616(body):
        if not isinstance(node, CStatement):
            continue
        boundary = cast(_TaggedExpressionBoundary8616, node)
        try:
            tags = boundary.tags
        except AttributeError:
            continue
        block_addr = tags.get("vex_block_addr")
        if isinstance(block_addr, int):
            addresses.add(block_addr)
    return frozenset(addresses)


def _function_region_8616(codegen: object) -> int | None:
    """Return the current function's region for shared register identities."""
    try:
        cfunc = cast(_CodegenBoundary8616, codegen).cfunc
    except AttributeError:
        return None
    return cfunc.addr if cfunc is not None else None


def _shared_loop_register_8616(
    reg: int,
    size: int,
    name: str,
    region: int | None,
) -> SimRegisterVariable:
    """Construct the shared typed register identity for one loop carrier."""
    return SimRegisterVariable(
        reg,
        size,
        ident=f"inertia-register-{name}",
        region=region if isinstance(region, int) else None,
        name=name,
    )


def _self_update_match_8616(
    node: object,
    register_name: str,
) -> tuple[CAssignment, CBinaryOp, int] | None:
    """Return the self-update triple when one node exactly matches."""
    if not isinstance(node, CAssignment) or not isinstance(node.lhs, CVariable):
        return None
    variable = node.lhs.variable
    rhs = node.rhs
    if (
        not isinstance(variable, SimRegisterVariable)
        or variable.name != register_name
        or not isinstance(rhs, CBinaryOp)
    ):
        return None
    dirty_operand = rhs.lhs
    try:
        dirty_varid = dirty_operand.dirty.varid if isinstance(dirty_operand, CDirtyExpression) else None
    except AttributeError:
        dirty_varid = None
    if (
        rhs.op not in {"Add", "Sub"}
        or not isinstance(dirty_varid, int)
        or not isinstance(rhs.rhs, CConstant)
        or not isinstance(rhs.rhs.value, int)
    ):
        return None
    return node, rhs, dirty_varid


def _replaced_register_carrier_8616(
    node: object,
    dirty_varid: int,
    source: CVariable,
) -> object:
    """Replace only the unique virtual identity proven by the self-update."""
    if not isinstance(node, CDirtyExpression):
        return node
    try:
        node_varid = node.dirty.varid
    except AttributeError:
        return node
    if node_varid != dirty_varid:
        return node
    return _clone_c_ast_tree_8616(source)


def _materialize_plain_loop_counter_update_8616(
    body: object,
    condition: ConditionIR,
    codegen: object,
) -> int:
    """Bind one proven loop-register virtual value to its unique self-update."""
    operand = condition.lhs
    if (
        not isinstance(operand, IRValue)
        or operand.space is not MemSpace.REG
        or not isinstance(operand.name, str)
    ):
        return 0

    matches = [
        match
        for node in _iter_c_nodes_deep_8616(body)
        if (match := _self_update_match_8616(node, operand.name.lower())) is not None
    ]
    if len(matches) != 1:
        return 0

    assignment, _rhs, dirty_varid = matches[0]
    variable = cast(SimRegisterVariable, assignment.lhs.variable)
    region = (
        variable.region
        if isinstance(variable.region, int)
        else _function_region_8616(codegen)
    )
    shared = _shared_loop_register_8616(
        variable.reg, variable.size, operand.name.lower(), region,
    )
    assignment.lhs.variable = shared
    assignment.lhs.unified_variable = shared
    replacement_count = 0

    def _replace_proven_register_carrier(node: object) -> object:
        """Replace only the unique virtual identity proven by the self-update."""
        nonlocal replacement_count
        replaced = _replaced_register_carrier_8616(node, dirty_varid, assignment.lhs)
        if replaced is not node:
            replacement_count += 1
        return replaced

    _replace_c_children_8616(body, _replace_proven_register_carrier)
    return int(replacement_count > 0)


def _replace_update_expression_with_target_8616(
    value: IRValue | IRBinaryValue,
    update: ConditionRegisterUpdateIR,
) -> IRValue | IRBinaryValue:
    """Replace the exact post-update value with its now-materialized target."""
    target = IRValue(MemSpace.REG, name=update.target_register, size=2)
    updated = IRBinaryValue(update.op, target, update.rhs, size=2)
    if value == updated:
        return target
    if not isinstance(value, IRBinaryValue):
        return value
    return replace(
        value,
        lhs=_replace_update_expression_with_target_8616(value.lhs, update),
        rhs=_replace_update_expression_with_target_8616(value.rhs, update),
    )


def _condition_after_materialized_register_update_8616(
    condition: ConditionIR,
    update: ConditionRegisterUpdateIR,
) -> ConditionIR:
    """Project a condition from the current register after inserting its update."""
    bindings = tuple(
        replace(
            binding,
            value=_replace_update_expression_with_target_8616(binding.value, update),
        )
        if binding.update == update
        else binding
        for binding in condition.register_bindings
    )
    return replace(condition, register_bindings=bindings)


def _bind_register_identity_to_loop_carrier_8616(
    root: object,
    source: SimRegisterVariable,
    target: CVariable,
) -> int:
    """Bind every exact use of one SSA register identity to its loop carrier."""
    if not isinstance(target.variable, SimRegisterVariable):
        return 0
    source_identity = (source.reg, source.size, source.ident, source.region)
    replacements = 0

    def _replace_source(node: object) -> object:
        """Replace only the register identity that the proven update consumes."""
        nonlocal replacements
        if not isinstance(node, CVariable) or not isinstance(node.variable, SimRegisterVariable):
            return node
        variable = node.variable
        if (variable.reg, variable.size, variable.ident, variable.region) != source_identity:
            return node
        replacement = cast(CVariable, _clone_c_ast_tree_8616(node))
        replacement.variable = target.variable
        replacement.unified_variable = target.variable
        replacements += 1
        return replacement

    _replace_c_children_8616(root, _replace_source)
    return replacements


def _latest_loop_initializer_8616(
    root: object,
    loop_body: object,
    update: ConditionRegisterUpdateIR,
    target_offset: int,
    target_size: int,
) -> CAssignment | None:
    """Return the unique latest pre-update initializer for the target register."""
    body_ids = {id(node) for node in _iter_c_nodes_deep_8616(loop_body)}
    initializers: list[tuple[int, CAssignment]] = []
    for node in _iter_c_nodes_deep_8616(root):
        if id(node) in body_ids or not isinstance(node, CAssignment):
            continue
        if not isinstance(node.lhs, CVariable) or not isinstance(node.lhs.variable, SimRegisterVariable):
            continue
        tags = _expression_tags_8616(node)
        ins_addr = tags.get("ins_addr")
        variable = node.lhs.variable
        if (
            isinstance(ins_addr, int)
            and ins_addr < update.instruction_addr
            and variable.reg == target_offset
            and variable.size == target_size
        ):
            initializers.append((ins_addr, node))
    if not initializers:
        return None
    latest_addr = max(address for address, _assignment in initializers)
    latest = tuple(
        assignment for address, assignment in initializers if address == latest_addr
    )
    return latest[0] if len(latest) == 1 else None


def _zero_xor_initializer_8616(initializer: CAssignment, codegen: object) -> None:
    """Normalize a proven ``x ^ x`` initializer to a literal zero."""
    if (
        isinstance(initializer.rhs, CBinaryOp)
        and initializer.rhs.op == "Xor"
        and _same_c_expression_8616(initializer.rhs.lhs, initializer.rhs.rhs)
    ):
        initializer.rhs = CConstant(
            0,
            initializer.rhs.type or SimTypeShort(False),
            codegen=codegen,
        )


def _marked_update_target_8616(
    loop: _LoopBoundary8616,
    update: ConditionRegisterUpdateIR,
    marker: str,
) -> CVariable | None:
    """Return an already-materialized update target inside the loop body."""
    if not isinstance(loop.body, CStatements):
        return None
    for statement in loop.body.statements or ():
        if not isinstance(statement, CAssignment):
            continue
        tags = _expression_tags_8616(statement)
        if tags.get(marker) == update.instruction_addr:
            return cast(CVariable, statement.lhs)
    return None


def _materialize_bound_loop_register_update_8616(
    root: object,
    loop: _LoopBoundary8616,
    condition: ConditionIR,
    codegen: object,
) -> _RegisterUpdateMaterialization8616:
    """Restore one Alias-proven full-register update at a structured loop tail."""
    updates = tuple(
        binding.update
        for binding in condition.register_bindings
        if binding.update is not None
    )
    if len(updates) != 1 or not isinstance(loop.body, CStatements):
        return _RegisterUpdateMaterialization8616()
    update = updates[0]
    try:
        project = cast(_CodegenBoundary8616, codegen).project
        arch = project.arch
        target_offset, target_size = arch.registers[update.target_register]
    except (AttributeError, KeyError, TypeError, ValueError):
        return _RegisterUpdateMaterialization8616()
    target_offset = int(target_offset)
    target_size = int(target_size)
    initializer = _latest_loop_initializer_8616(
        root, loop.body, update, target_offset, target_size,
    )
    if initializer is None:
        return _RegisterUpdateMaterialization8616()
    initializer_variable = cast(SimRegisterVariable, initializer.lhs.variable)
    region = (
        initializer_variable.region
        if isinstance(initializer_variable.region, int)
        else _function_region_8616(codegen)
    )
    rhs = lower_ir_value_to_c_expr_8616(
        update.rhs, project, codegen, resolve_register_name=True,
    )
    op = {"add": "Add", "and": "And", "or": "Or", "sub": "Sub", "xor": "Xor"}.get(update.op)
    if not isinstance(rhs, CExpression) or op is None:
        return _RegisterUpdateMaterialization8616()
    shared = _shared_loop_register_8616(
        target_offset, target_size, update.target_register, region,
    )
    initializer.lhs.variable = shared
    initializer.lhs.unified_variable = shared
    target = cast(CVariable, _clone_c_ast_tree_8616(initializer.lhs))
    _bind_register_identity_to_loop_carrier_8616(root, initializer_variable, target)
    _zero_xor_initializer_8616(initializer, codegen)
    marker = "inertia_typed_loop_register_update_8616"
    marked_target = _marked_update_target_8616(loop, update, marker)
    if marked_target is not None:
        return _RegisterUpdateMaterialization8616(
            target=marked_target,
            update=update,
        )
    update_assignment = CAssignment(
        cast(CVariable, _clone_c_ast_tree_8616(target)),
        CBinaryOp(
            op,
            cast(CVariable, _clone_c_ast_tree_8616(target)),
            rhs,
            codegen=codegen,
        ),
        codegen=codegen,
        tags={
            "ins_addr": update.instruction_addr,
            "vex_block_addr": condition.block_addr,
            marker: update.instruction_addr,
        },
    )
    loop.body.statements = [*(loop.body.statements or ()), update_assignment]
    return _RegisterUpdateMaterialization8616(True, target, update)


def _bind_materialized_update_target_8616(
    expression: CExpression,
    target: CVariable,
) -> int:
    """Bind full-register leaves in a lowered condition to the loop carrier."""
    target_variable = target.variable
    if not isinstance(target_variable, SimRegisterVariable):
        return 0
    replacements = 0

    def _replace_target(node: object) -> object:
        """Replace one exact physical-register view with the shared carrier."""
        nonlocal replacements
        if not isinstance(node, CVariable) or not isinstance(node.variable, SimRegisterVariable):
            return node
        if (
            node.variable.reg != target_variable.reg
            or node.variable.size != target_variable.size
        ):
            return node
        replacements += 1
        return _clone_c_ast_tree_8616(target)

    _replace_c_children_8616(expression, _replace_target)
    return replacements


def _bind_existing_loop_condition_register_8616(
    current: CExpression,
    body: object,
    condition: ConditionIR,
) -> int:
    """Bind an already-readable guard to its unique typed register identity."""
    operand = condition.lhs
    if not isinstance(operand, IRValue) or operand.space is not MemSpace.REG or not isinstance(operand.name, str):
        return 0
    candidates = {
        node.variable
        for node in _iter_c_nodes_deep_8616(body)
        if isinstance(node, CVariable)
        and isinstance(node.variable, SimRegisterVariable)
        and node.variable.name == operand.name.lower()
        and isinstance(node.variable.ident, str)
        and isinstance(node.variable.region, int)
    }
    if len(candidates) != 1:
        return 0
    shared = next(iter(candidates))
    replacement_count = 0

    def _replace_anonymous_register(node: object) -> object:
        """Replace only the typed operand's anonymous physical-register view."""
        nonlocal replacement_count
        if not isinstance(node, CVariable) or not isinstance(node.variable, SimRegisterVariable):
            return node
        variable = node.variable
        if variable.reg != shared.reg or variable.size != shared.size:
            return node
        if variable is shared and node.unified_variable is shared:
            return node
        replacement = cast(CVariable, _clone_c_ast_tree_8616(node))
        replacement.variable = shared
        replacement.unified_variable = shared
        replacement_count += 1
        return replacement

    _replace_c_children_8616(current, _replace_anonymous_register)
    return replacement_count


def _loop_header_carries_condition_register_8616(
    current: CExpression,
    condition: ConditionIR,
) -> bool:
    """Return whether an untagged header visibly carries the typed register."""
    operand = condition.lhs
    if not isinstance(operand, IRValue) or operand.space is not MemSpace.REG or not isinstance(operand.name, str):
        return False
    return any(
        isinstance(node, CVariable)
        and isinstance(node.variable, SimRegisterVariable)
        and node.variable.name == operand.name.lower()
        and node.variable.size == operand.size
        for node in _iter_c_nodes_deep_8616(current)
    )


def _enters_body_through_linear_trampoline_8616(
    successors: Mapping[int, tuple[int, ...]],
    start: int,
    body_block_addrs: frozenset[int],
    condition_block_addr: int,
) -> bool:
    """Return whether a deterministic trampoline enters the structured body.

    angr may omit a terminal jump-only block from the structured loop body.
    Following only single-successor blocks recovers that exact CFG ownership
    without allowing an enclosing loop's later re-entry to claim the edge.
    """
    current = start
    visited: set[int] = set()
    while current not in visited and current != condition_block_addr:
        if current in body_block_addrs:
            return True
        visited.add(current)
        next_blocks = successors.get(current, ())
        if len(next_blocks) != 1:
            return False
        current = next_blocks[0]
    return False


def _continuation_edge_8616(
    condition: ConditionIR,
    successors: Mapping[int, tuple[int, ...]],
    *,
    body_block_addrs: frozenset[int] = frozenset(),
) -> LoopContinuationEdge8616 | None:
    """Classify the loop-continuation edge from structured ownership or CFG reachability."""
    if not all(
        isinstance(address, int)
        for address in (condition.block_addr, condition.taken_target, condition.fallthrough_target)
    ):
        return None
    taken_target = cast(int, condition.taken_target)
    fallthrough_target = cast(int, condition.fallthrough_target)
    block_addr = cast(int, condition.block_addr)
    taken_owned = _enters_body_through_linear_trampoline_8616(
        successors,
        taken_target,
        body_block_addrs,
        block_addr,
    )
    fallthrough_owned = _enters_body_through_linear_trampoline_8616(
        successors,
        fallthrough_target,
        body_block_addrs,
        block_addr,
    )
    taken_reaches = _reaches_8616(successors, taken_target, block_addr)
    fallthrough_reaches = _reaches_8616(successors, fallthrough_target, block_addr)
    owned_edge = (
        LoopContinuationEdge8616.TAKEN
        if taken_owned and not fallthrough_owned
        else LoopContinuationEdge8616.FALLTHROUGH if fallthrough_owned and not taken_owned else None
    )
    reachable_edge = (
        LoopContinuationEdge8616.TAKEN
        if taken_reaches and not fallthrough_reaches
        else LoopContinuationEdge8616.FALLTHROUGH if fallthrough_reaches and not taken_reaches else None
    )
    if reachable_edge is not None:
        return None if owned_edge is not None and owned_edge is not reachable_edge else reachable_edge
    return owned_edge


def _consume_owned_pretest_guard_8616(
    loop: _LoopBoundary8616,
    guard: CIfBreak | CIfElse,
    codegen: object,
) -> bool:
    """Remove one exact leading break guard after promoting it to the header."""
    empty = CStatements([], codegen=codegen)
    if loop.body is guard:
        loop.body = empty
        return True
    return bool(
        _replace_c_children_8616(
            loop.body,
            lambda child: empty if child is guard else child,
        )
    )


def _expression_tags_8616(expression: CExpression | CAssignment) -> dict[str, object]:
    """Copy tags from one dynamic angr expression or assignment."""
    boundary = cast(_TaggedExpressionBoundary8616, expression)
    try:
        return dict(boundary.tags)
    except AttributeError:
        return {}


def _invert_condition_8616(condition: CExpression, codegen: object) -> CExpression:
    """Invert one already-materialized condition without recovering semantics."""
    inverted_ops = {
        "CmpEQ": "CmpNE",
        "CmpNE": "CmpEQ",
        "CmpLT": "CmpGE",
        "CmpLE": "CmpGT",
        "CmpGT": "CmpLE",
        "CmpGE": "CmpLT",
    }
    if isinstance(condition, CBinaryOp) and condition.op in inverted_ops:
        return CBinaryOp(
            inverted_ops[condition.op],
            condition.lhs,
            condition.rhs,
            codegen=codegen,
            tags=_expression_tags_8616(condition),
        )
    if isinstance(condition, CUnaryOp) and condition.op == "Not":
        return condition.operand
    return CUnaryOp(
        "Not",
        condition,
        codegen=codegen,
        tags=_expression_tags_8616(condition),
    )


def _is_owned_materialization_8616(
    expression: CExpression,
    key: tuple[int, int],
    edge: LoopContinuationEdge8616,
) -> bool:
    """Return whether this pass already materialized the exact condition fact."""
    tags = _expression_tags_8616(expression)
    return (
        tags.get("inertia_typed_loop_condition_key_8616") == key
        and tags.get("inertia_typed_loop_continuation_edge_8616") == edge.value
    )


def _mark_materialization_8616(
    expression: CExpression,
    key: tuple[int, int],
    edge: LoopContinuationEdge8616,
) -> None:
    """Record exact typed-condition ownership on a materialized expression."""
    boundary = cast(_TaggedExpressionBoundary8616, expression)
    tags = _expression_tags_8616(expression)
    tags.update(
        {
            "ins_addr": key[0],
            "vex_block_addr": key[1],
            "inertia_typed_loop_condition_bound_8616": True,
            "inertia_typed_loop_condition_key_8616": key,
            "inertia_typed_loop_continuation_edge_8616": edge.value,
        }
    )
    boundary.tags = tags


def _mark_condition_binding_8616(expression: CExpression, key: tuple[int, int]) -> None:
    """Expose unique typed loop ownership to the Validation layer."""
    boundary = cast(_TaggedExpressionBoundary8616, expression)
    tags = _expression_tags_8616(expression)
    tags.update(
        {
            "ins_addr": key[0],
            "vex_block_addr": key[1],
            "inertia_typed_loop_condition_bound_8616": True,
            "inertia_typed_loop_condition_key_8616": key,
        }
    )
    boundary.tags = tags


def _conditions_by_key_8616(
    typed_conditions: tuple[ConditionIR, ...],
) -> dict[tuple[int, int], list[ConditionIR]]:
    """Group typed conditions by their exact proven condition key."""
    conditions_by_key: dict[tuple[int, int], list[ConditionIR]] = {}
    for condition in typed_conditions:
        key = _condition_key_8616(condition)
        if key is not None:
            conditions_by_key.setdefault(key, []).append(condition)
    return conditions_by_key


@dataclass(slots=True)
class _LoopConditionTally8616:
    """Accumulated stats for the loop-condition materialization pass."""

    raw: int = 0
    normalized: int = 0
    classified: int = 0
    materialized: int = 0
    changed: int = 0
    taken: int = 0
    fallthrough: int = 0
    counter_updates: int = 0
    composite_owned: int = 0


@dataclass(slots=True)
class _LoopKeySelection8616:
    """Key-narrowing state for one structured loop boundary."""

    loop_body: object
    successors: Mapping[int, tuple[int, ...]]
    conditions_by_key: Mapping[tuple[int, int], list[ConditionIR]]
    leading_break_guard: CIfBreak | CIfElse | None
    current_keys: frozenset[tuple[int, int]]
    body_keys: frozenset[tuple[int, int]]
    body_block_addrs: frozenset[int]
    matching_keys: frozenset[tuple[int, int]]
    pretest_keys: frozenset[tuple[int, int]] = frozenset()
    owned_pretest_keys: frozenset[tuple[int, int]] = frozenset()

    def _owns_pretest_guard_8616(self, key: tuple[int, int]) -> bool:
        """Return whether the leading break guard uniquely owns one key."""
        return (
            len(self.conditions_by_key[key]) == 1
            and classify_composite_loop_exit_ownership_8616(
                self.loop_body,
                key,
                self.successors,
                leading_break_guard=self.leading_break_guard,
            ).owned_pretest_guard
            is self.leading_break_guard
        )

    def _has_continuation_edge_8616(self, key: tuple[int, int]) -> bool:
        """Return whether one key's unique condition proves a loop edge."""
        return (
            len(self.conditions_by_key[key]) == 1
            and _continuation_edge_8616(
                self.conditions_by_key[key][0],
                self.successors,
                body_block_addrs=self.body_block_addrs,
            )
            is not None
        )

    def narrow(self) -> None:
        """Narrow matching keys through pretest-guard and current-key ownership."""
        if len(self.matching_keys) > 1 and self.leading_break_guard is not None:
            self.pretest_keys = _tag_pairs_8616(
                self.leading_break_guard
            ).intersection(self.matching_keys)
            self.owned_pretest_keys = frozenset(
                key for key in self.pretest_keys if self._owns_pretest_guard_8616(key)
            )
            if len(self.owned_pretest_keys) == 1:
                self.matching_keys = self.owned_pretest_keys
        if (
            len(self.matching_keys) > 1
            and not self.pretest_keys
            and len(self.current_keys) == 1
        ):
            self.matching_keys = self.current_keys

    def resolve_continuation(self) -> None:
        """Narrow matching keys to conditions proving a continuation edge."""
        if len(self.matching_keys) > 1:
            self.matching_keys = frozenset(
                key
                for key in self.matching_keys
                if self._has_continuation_edge_8616(key)
            )


def _materialize_loop_guard_8616(
    root: object,
    loop: _LoopBoundary8616,
    current: CExpression,
    key: tuple[int, int],
    condition: ConditionIR,
    selection: _LoopKeySelection8616,
    tally: _LoopConditionTally8616,
    lower_condition: Callable[[ConditionIR], CExpression | None],
    codegen: object,
) -> None:
    """Materialize one uniquely proven continuation condition into a loop guard."""
    composite_ownership = classify_composite_loop_exit_ownership_8616(
        loop.body,
        key,
        selection.successors,
        leading_break_guard=selection.leading_break_guard,
    )
    if (
        composite_ownership.status is CompositeLoopExitOwnershipStatus8616.UNIQUE
        and composite_ownership.owned_pretest_guard is None
    ):
        tally.classified += 1
        tally.materialized += 1
        tally.composite_owned += 1
        return
    if composite_ownership.status is CompositeLoopExitOwnershipStatus8616.AMBIGUOUS or (
        not selection.current_keys
        and composite_ownership.status is not CompositeLoopExitOwnershipStatus8616.UNIQUE
        and not _loop_header_carries_condition_register_8616(current, condition)
    ):
        return
    edge = _continuation_edge_8616(
        condition,
        selection.successors,
        body_block_addrs=selection.body_block_addrs,
    )
    if edge is None:
        return
    _mark_condition_binding_8616(current, key)
    tally.classified += 1
    if edge is LoopContinuationEdge8616.TAKEN:
        tally.taken += 1
    else:
        tally.fallthrough += 1
    tally.counter_updates += _materialize_plain_loop_counter_update_8616(
        loop.body, condition, codegen,
    )
    _bind_existing_loop_condition_register_8616(current, loop.body, condition)
    update_materialization = _materialize_bound_loop_register_update_8616(
        root,
        loop,
        condition,
        codegen,
    )
    tally.counter_updates += int(update_materialization.changed)
    lowering_condition = (
        _condition_after_materialized_register_update_8616(
            condition,
            update_materialization.update,
        )
        if update_materialization.update is not None
        else condition
    )
    replacement = lower_condition(lowering_condition)
    if replacement is None:
        return
    if update_materialization.target is not None:
        _bind_materialized_update_target_8616(
            replacement,
            update_materialization.target,
        )
    if edge is LoopContinuationEdge8616.FALLTHROUGH:
        replacement = _invert_condition_8616(replacement, codegen)
    pretest_consumed = composite_ownership.owned_pretest_guard is not None
    if composite_ownership.owned_pretest_guard is not None and not _consume_owned_pretest_guard_8616(
        loop,
        composite_ownership.owned_pretest_guard,
        codegen,
    ):
        return
    tally.composite_owned += int(pretest_consumed)
    if _is_owned_materialization_8616(current, key, edge) and _same_c_expression_8616(current, replacement):
        tally.materialized += 1
        tally.changed += int(pretest_consumed)
        return
    _mark_materialization_8616(replacement, key, edge)
    loop.condition = replacement
    tally.materialized += 1
    tally.changed += 1


def _process_loop_node_8616(
    node: object,
    root: object,
    codegen: object,
    conditions_by_key: Mapping[tuple[int, int], list[ConditionIR]],
    successors: Mapping[int, tuple[int, ...]],
    lower_condition: Callable[[ConditionIR], CExpression | None],
    tally: _LoopConditionTally8616,
) -> None:
    """Materialize the proven continuation condition for one structured loop."""
    if not isinstance(node, (CForLoop, CWhileLoop, CDoWhileLoop)):
        return
    loop = cast(_LoopBoundary8616, node)
    current = loop.condition
    if not isinstance(current, CExpression):
        return
    leading_break_guard = (
        pretest_condition_surface_8616(node).leading_break_guard
        if isinstance(node, (CForLoop, CWhileLoop))
        else None
    )
    current_keys = loop_condition_keys_8616(current, _tag_pairs_8616(current), conditions_by_key, successors)
    body_keys = _tag_pairs_8616(loop.body).intersection(conditions_by_key)
    matching_keys = current_keys | body_keys
    if not matching_keys:
        return
    tally.raw += 1
    selection = _LoopKeySelection8616(
        loop_body=loop.body,
        successors=successors,
        conditions_by_key=conditions_by_key,
        leading_break_guard=leading_break_guard,
        current_keys=current_keys,
        body_keys=body_keys,
        body_block_addrs=_structured_body_block_addrs_8616(loop.body),
        matching_keys=matching_keys,
    )
    selection.narrow()
    _debug_loop_selection_8616(
        body_keys=body_keys,
        current_keys=current_keys,
        leading_guard_type=(type(leading_break_guard).__name__ if leading_break_guard is not None else None),
        matching_keys=selection.matching_keys,
        owned_pretest_keys=selection.owned_pretest_keys,
        pretest_keys=selection.pretest_keys,
    )
    selection.resolve_continuation()
    if len(selection.matching_keys) != 1:
        return
    key = next(iter(selection.matching_keys))
    candidates = conditions_by_key[key]
    if len(candidates) != 1:
        return
    tally.normalized += 1
    _materialize_loop_guard_8616(
        root,
        loop,
        current,
        key,
        candidates[0],
        selection,
        tally,
        lower_condition,
        codegen,
    )


def materialize_typed_loop_continuation_conditions_8616(
    root: object,
    codegen: object,
    typed_conditions: tuple[ConditionIR, ...],
    successors: Mapping[int, tuple[int, ...]],
    lower_condition: Callable[[ConditionIR], CExpression | None],
) -> LoopConditionMaterializationStats8616:
    """Replace loop guards only when exact typed and CFG evidence agree."""
    conditions_by_key = _conditions_by_key_8616(typed_conditions)
    tally = _LoopConditionTally8616()
    for node in _iter_c_nodes_deep_8616(root):
        _process_loop_node_8616(
            node,
            root,
            codegen,
            conditions_by_key,
            successors,
            lower_condition,
            tally,
        )

    raw_count = tally.raw
    normalized_count = tally.normalized
    classified_count = tally.classified
    materialized_count = tally.materialized
    changed_count = tally.changed
    taken_count = tally.taken
    fallthrough_count = tally.fallthrough
    counter_update_count = tally.counter_updates
    composite_loop_exit_owned_count = tally.composite_owned
    failure_count = raw_count - normalized_count + normalized_count - classified_count
    failure_count += classified_count - materialized_count
    return LoopConditionMaterializationStats8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=classified_count,
        materialized_count=materialized_count,
        failure_count=failure_count,
        changed_count=changed_count,
        taken_continuation_count=taken_count,
        fallthrough_continuation_count=fallthrough_count,
        counter_update_materialized_count=counter_update_count,
        composite_loop_exit_owned_count=composite_loop_exit_owned_count,
    )
