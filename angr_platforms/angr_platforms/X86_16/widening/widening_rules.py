"""Coordinator for deterministic widening-owned passes.

Layer: Widening.
Responsibility: owns deterministic coordination of widening-owned passes.
Consumes alias-proven storage identity and typed instruction facts before
running width promotion, coalescing, copy propagation, and local folding.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.
"""

from __future__ import annotations

import copy
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, TypeGuard, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c

from ..alias.alias_model_impl import AliasStorageFacts
from ..decoded_memory_width import decoded_memory_operand_width_8616
from ..ir.core import MemSpace
from ..lowering.runtime_segment_access import (
    build_runtime_segment_access_context_8616,
    runtime_segment_access_offset_expr_8616,
)
from ..lowering.segment_access_policy import instruction_addrs_from_node_8616
from ..lowering.segmented_lowering import _SegmentedAccess
from ..structuring.simple_loop_recovery import _function_instruction_summaries_8616
from .stack_subview_projection import materialize_contained_stack_subviews_8616
from .widening_copyprop_8616 import _widening_copy_propagation_8616
from .word_projection_recomposition import (
    materialize_word_projection_recompositions_8616,
)


def _dynamic_attr_8616(obj: object, name: str, default: object = None) -> Any:  # noqa: ANN401
    """Dynamic angr/codegen/C-AST boundary: read optional third-party attributes."""
    return getattr(obj, name, default)


def _is_segmented_access_8616(value: object) -> TypeGuard[_SegmentedAccess]:
    """Return whether a classifier result is the owned segmented-access contract."""
    return isinstance(value, _SegmentedAccess)


def _is_alias_storage_facts_8616(value: object) -> TypeGuard[AliasStorageFacts]:
    """Return whether an alias callback returned the owned alias-facts contract."""
    return isinstance(value, AliasStorageFacts)


def _pair_result_8616(value: object) -> tuple[object, object] | None:
    """Return a two-item callback result from a dynamic helper boundary."""
    if not isinstance(value, tuple) or len(value) != 2:
        return None
    return value


def run_typed_widening_pass_8616(
    project: object,
    codegen: object,
    *,
    coalesce_direct_ss_local_word_statements: Callable[..., object],
    coalesce_segmented_word_store_statements: Callable[..., object],
    copy_propagation_fn: Callable[..., object] = _widening_copy_propagation_8616,
    promote_stack_slots_from_instruction_widths: Callable[..., object] | None = None,
    materialize_stack_subviews_fn: Callable[[object], object] = materialize_contained_stack_subviews_8616,
    materialize_word_projections_fn: Callable[[object], object] = materialize_word_projection_recompositions_8616,
) -> bool:
    """Execute widening-owned passes in deterministic order.

    Order:
    1. Stack-slot width promotion from instruction evidence
    2. Alias-proven contained stack-subview materialization
    3. Word-store coalescing (SROA-like)
    4. Copy propagation (EarlyCSE-like)
    5. Alias-proven complete word-projection materialization

    This pass is the widening ownership boundary: callers provide typed helpers,
    widening decides pass ordering and changed-state aggregation.
    """
    changed = False
    if promote_stack_slots_from_instruction_widths is not None:
        changed = bool(promote_stack_slots_from_instruction_widths(project, codegen)) or changed
    changed = bool(materialize_stack_subviews_fn(codegen)) or changed
    changed = bool(coalesce_direct_ss_local_word_statements(project, codegen)) or changed
    changed = bool(coalesce_segmented_word_store_statements(project, codegen)) or changed
    changed = bool(copy_propagation_fn(codegen, enable_nested=True)) or changed
    changed = bool(materialize_word_projections_fn(codegen)) or changed
    return changed


def _insn_summary_bp_widths_8616(insn: object, widths: dict[int, int]) -> None:
    """Merge BP-mem operand widths from one decoded instruction summary."""
    for operand_kind, operand_value, operand_size in (
        (insn.op0_kind, insn.op0_value, insn.op0_size),
        (insn.op1_kind, insn.op1_value, insn.op1_size),
    ):
        if operand_kind != "bp_mem" or not isinstance(operand_value, int):
            continue
        size = int(operand_size or 0)
        if size <= 0:
            continue
        widths[int(operand_value)] = max(widths.get(int(operand_value), 0), size)


def _capstone_operand_bp_width_8616(
    insn: object,
    operands: tuple[object, ...],
    operand_index: int,
    operand: object,
    widths: dict[int, int],
) -> None:
    """Merge the BP-disp width of one capstone memory operand."""
    if int(_dynamic_attr_8616(operand, "type", -1)) != 3 or _dynamic_attr_8616(operand, "mem", None) is None:
        return
    mem = _dynamic_attr_8616(operand, "mem")
    if not _dynamic_attr_8616(mem, "base", None):
        return
    try:
        base_name = str(insn.reg_name(mem.base)).lower()
    except Exception:
        return
    if base_name != "bp":
        return
    size = decoded_memory_operand_width_8616(
        int(_dynamic_attr_8616(insn, "id", 0)),
        operand_index,
        int(_dynamic_attr_8616(operand, "size", 0) or 0),
        int(_dynamic_attr_8616(operands[0], "size", 0) or 0),
    ) or 0
    if size <= 0:
        return
    disp = int(_dynamic_attr_8616(mem, "disp", 0) or 0)
    if 0x8000 <= disp <= 0xFFFF:
        disp -= 0x10000
    widths[disp] = max(widths.get(disp, 0), size)


def _capstone_insn_bp_widths_8616(insn: object, widths: dict[int, int]) -> None:
    """Merge BP-mem widths from one capstone instruction."""
    if str(_dynamic_attr_8616(insn, "mnemonic", "")).lower() == "lea":
        return
    operands = cast(tuple[object, ...], tuple(_dynamic_attr_8616(insn, "operands", ()) or ()))
    for operand_index, operand in enumerate(operands):
        _capstone_operand_bp_width_8616(insn, operands, operand_index, operand, widths)


def _resolve_codegen_function_8616(project: object, cfunc: object, func_addr: int) -> object:
    """Resolve the angr function for ``func_addr`` or a stub namespace."""
    kb = _dynamic_attr_8616(project, "kb", None)
    functions = _dynamic_attr_8616(kb, "functions", None)
    if functions is not None:
        try:
            return functions.function(addr=int(func_addr), create=False)
        except Exception:
            pass
    return SimpleNamespace(
        addr=int(func_addr),
        size=_dynamic_attr_8616(cfunc, "size", None),
        name=_dynamic_attr_8616(cfunc, "name", None),
    )


def collect_bp_stack_access_widths_from_instructions_8616(project: object, codegen: object) -> dict[int, int]:
    """Collect BP-relative stack slot widths directly from decoded instructions."""
    cfunc = _dynamic_attr_8616(codegen, "cfunc", None)
    func_addr = _dynamic_attr_8616(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return {}

    function = _resolve_codegen_function_8616(project, cfunc, int(func_addr))

    widths: dict[int, int] = {}
    for insn in _function_instruction_summaries_8616(project, function):
        if insn.mnemonic.lower() == "lea":
            continue
        _insn_summary_bp_widths_8616(insn, widths)
    if widths:
        return widths

    block_addrs = tuple(sorted(_dynamic_attr_8616(function, "block_addrs", ()) or ()))
    if not block_addrs:
        block_addrs = (int(func_addr),)

    for block_addr in block_addrs:
        try:
            block = _dynamic_attr_8616(project, "factory").block(int(block_addr), opt_level=0)
        except Exception:
            continue
        for insn in tuple(_dynamic_attr_8616(_dynamic_attr_8616(block, "capstone", None), "insns", ()) or ()):
            _capstone_insn_bp_widths_8616(insn, widths)
    return widths


def promote_stack_slots_from_instruction_widths_8616(
    project: object,
    codegen: object,
    *,
    resolve_stack_cvar_at_offset: Callable[..., object],
    promote_direct_stack_cvariable: Callable[..., object],
    stack_type_for_size: Callable[..., object],
) -> bool:
    """Promote stack variables only when an access proves a larger storage extent.

    A decoded access width is a lower bound on the containing logical object. It
    must not narrow a wider stack variable or replace independently proven type
    signedness merely because the object is accessed one word at a time.
    """
    if _dynamic_attr_8616(codegen, "cfunc", None) is None:
        return False

    changed = False
    promoted = 0
    widths = collect_bp_stack_access_widths_from_instructions_8616(project, codegen)
    for offset, size in sorted(widths.items()):
        if size <= 1:
            continue
        cvar = resolve_stack_cvar_at_offset(codegen, offset, preferred_size=size)
        variable = _dynamic_attr_8616(cvar, "variable", None)
        if variable is None or _dynamic_attr_8616(variable, "offset", None) != offset:
            continue
        current_size = _dynamic_attr_8616(variable, "size", None)
        if isinstance(current_size, int) and current_size >= size:
            continue
        target_type = stack_type_for_size(size)
        if promote_direct_stack_cvariable(codegen, cvar, size, target_type):
            changed = True
            promoted += 1

    if widths:
        try:
            cast(Any, codegen)._inertia_stack_width_instruction_fact_count = int(
                _dynamic_attr_8616(codegen, "_inertia_stack_width_instruction_fact_count", 0) or 0
            ) + len(widths)
            cast(Any, codegen)._inertia_stack_width_instruction_materialized_count = (
                int(_dynamic_attr_8616(codegen, "_inertia_stack_width_instruction_materialized_count", 0) or 0) + promoted
            )
        except Exception:
            pass
    return changed


@dataclass
class _DirectSSLocalCtx8616:
    """Callables plus mutable flag for direct SS-local word coalescing."""

    project: object
    codegen: object
    match_ss_local_plus_const: Callable[..., object]
    match_shift_right_8_expr: Callable[..., object]
    stack_slot_identity_can_join: Callable[..., object]
    derived_stack_high_byte_follows_slot: Callable[..., object]
    same_c_expression: Callable[..., object]
    unwrap_c_casts: Callable[..., object]
    promote_direct_stack_cvariable: Callable[..., object]
    stack_type_for_size: Callable[..., object]
    match_byte_store_addr_expr: Callable[..., object]
    addr_exprs_are_byte_pair: Callable[..., object]
    resolve_stack_cvar_from_addr_expr: Callable[..., object]
    canonicalize_stack_cvar_expr: Callable[..., object]
    changed: bool = False


def _visit_structured_children_8616(node: object, visit_fn: Callable[[object], None]) -> bool:
    """Recurse into branch/loop children of ``node``; True when dispatched."""
    if isinstance(node, structured_c.CIfElse):
        for _cond, body in node.condition_and_nodes:
            visit_fn(body)
        if node.else_node is not None:
            visit_fn(node.else_node)
        return True
    if isinstance(node, structured_c.CWhileLoop) or (
        hasattr(structured_c, "CDoWhileLoop")
        and isinstance(node, _dynamic_attr_8616(structured_c, "CDoWhileLoop"))
    ):
        visit_fn(_dynamic_attr_8616(node, "condition", None))
        visit_fn(_dynamic_attr_8616(node, "body", None))
        return True
    if hasattr(structured_c, "CForLoop") and isinstance(node, _dynamic_attr_8616(structured_c, "CForLoop")):
        for attr in ("init", "condition", "iteration", "body"):
            visit_fn(_dynamic_attr_8616(node, attr, None))
        return True
    return False


def _ss_local_pair_lhs_8616(ctx: _DirectSSLocalCtx8616, stmt: object, next_stmt: object) -> object | None:
    """Return ``stmt.lhs`` when the pair is a ``SS:local+1`` high-byte join."""
    if not isinstance(stmt.lhs, structured_c.CVariable):
        return None
    matched = _pair_result_8616(ctx.match_ss_local_plus_const(next_stmt.lhs, ctx.project))
    if matched is None:
        return None
    target_cvar, extra_offset = matched
    high_expr = ctx.match_shift_right_8_expr(next_stmt.rhs)
    if not (
        (
            (extra_offset == 1 and ctx.stack_slot_identity_can_join(target_cvar, stmt.lhs))
            or ctx.derived_stack_high_byte_follows_slot(target_cvar, extra_offset, stmt.lhs)
        )
        and high_expr is not None
        and ctx.same_c_expression(ctx.unwrap_c_casts(high_expr), ctx.unwrap_c_casts(stmt.rhs))
    ):
        return None
    return stmt.lhs


def _byte_store_pair_lhs_8616(ctx: _DirectSSLocalCtx8616, stmt: object, next_stmt: object) -> object | None:
    """Resolve a word lvalue for adjacent byte-store address expressions."""
    low_addr_expr = ctx.match_byte_store_addr_expr(stmt.lhs)
    high_addr_expr = ctx.match_byte_store_addr_expr(next_stmt.lhs)
    high_expr = ctx.match_shift_right_8_expr(next_stmt.rhs)
    if not (
        low_addr_expr is not None
        and high_addr_expr is not None
        and high_expr is not None
        and ctx.addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, ctx.project)
        and ctx.same_c_expression(ctx.unwrap_c_casts(high_expr), ctx.unwrap_c_casts(stmt.rhs))
    ):
        return None
    resolved_lhs = ctx.resolve_stack_cvar_from_addr_expr(ctx.project, ctx.codegen, low_addr_expr)
    if not isinstance(resolved_lhs, structured_c.CVariable):
        return None
    return ctx.canonicalize_stack_cvar_expr(resolved_lhs, ctx.codegen)


def _direct_ss_pair_step_8616(
    statements: list[object], i: int, ctx: _DirectSSLocalCtx8616
) -> tuple[object, int] | None:
    """Try to merge statements ``i``/``i+1`` into one word assignment."""
    stmt = statements[i]
    if not (
        i + 1 < len(statements)
        and isinstance(stmt, structured_c.CAssignment)
        and isinstance(statements[i + 1], structured_c.CAssignment)
    ):
        return None
    next_stmt = statements[i + 1]
    replacement_lhs = _ss_local_pair_lhs_8616(ctx, stmt, next_stmt)
    if replacement_lhs is None:
        replacement_lhs = _byte_store_pair_lhs_8616(ctx, stmt, next_stmt)
    if not isinstance(replacement_lhs, structured_c.CVariable):
        return None
    if ctx.promote_direct_stack_cvariable(ctx.codegen, replacement_lhs, 2, ctx.stack_type_for_size(2)):
        ctx.changed = True
    return structured_c.CAssignment(replacement_lhs, stmt.rhs, codegen=ctx.codegen), 2


def _direct_ss_local_seq_8616(node: object, ctx: _DirectSSLocalCtx8616) -> None:
    """Coalesce adjacent byte assignments in one ``CStatements`` sequence."""
    new_statements = []
    i = 0
    while i < len(node.statements):
        stmt = node.statements[i]
        outcome = _direct_ss_pair_step_8616(node.statements, i, ctx)
        if outcome is not None:
            replacement, consumed = outcome
            new_statements.append(replacement)
            ctx.changed = True
            i += consumed
            continue
        _visit_direct_ss_local_8616(stmt, ctx)
        new_statements.append(stmt)
        i += 1

    if ctx.changed or new_statements != node.statements:
        node.statements = new_statements


def _visit_direct_ss_local_8616(node: object, ctx: _DirectSSLocalCtx8616) -> None:
    """Dispatch one structured-C node for direct SS-local coalescing."""
    if isinstance(node, structured_c.CStatements):
        _direct_ss_local_seq_8616(node, ctx)
        return
    _visit_structured_children_8616(node, lambda child: _visit_direct_ss_local_8616(child, ctx))


def _coalesce_direct_ss_local_word_statements(
    project: object,
    codegen: object,
    *,
    match_ss_local_plus_const: Callable[..., object],
    match_shift_right_8_expr: Callable[..., object],
    stack_slot_identity_can_join: Callable[..., object],
    derived_stack_high_byte_follows_slot: Callable[..., object],
    same_c_expression: Callable[..., object],
    unwrap_c_casts: Callable[..., object],
    promote_direct_stack_cvariable: Callable[..., object],
    stack_type_for_size: Callable[..., object],
    match_byte_store_addr_expr: Callable[..., object],
    addr_exprs_are_byte_pair: Callable[..., object],
    resolve_stack_cvar_from_addr_expr: Callable[..., object],
    canonicalize_stack_cvar_expr: Callable[..., object],
) -> bool:
    if _dynamic_attr_8616(codegen, "cfunc", None) is None:
        return False

    ctx = _DirectSSLocalCtx8616(
        project=project,
        codegen=codegen,
        match_ss_local_plus_const=match_ss_local_plus_const,
        match_shift_right_8_expr=match_shift_right_8_expr,
        stack_slot_identity_can_join=stack_slot_identity_can_join,
        derived_stack_high_byte_follows_slot=derived_stack_high_byte_follows_slot,
        same_c_expression=same_c_expression,
        unwrap_c_casts=unwrap_c_casts,
        promote_direct_stack_cvariable=promote_direct_stack_cvariable,
        stack_type_for_size=stack_type_for_size,
        match_byte_store_addr_expr=match_byte_store_addr_expr,
        addr_exprs_are_byte_pair=addr_exprs_are_byte_pair,
        resolve_stack_cvar_from_addr_expr=resolve_stack_cvar_from_addr_expr,
        canonicalize_stack_cvar_expr=canonicalize_stack_cvar_expr,
    )
    _visit_direct_ss_local_8616(
        _dynamic_attr_8616(_dynamic_attr_8616(codegen, "cfunc", None), "statements", None), ctx
    )
    return ctx.changed


@dataclass
class _QuadAddrFacts8616:
    """Address facts for the four-statement load+store probe."""

    low_load_addr: object
    high_load_addr: object
    low_store_addr: object
    high_store_addr: object
    high_store_base: object
    has_addrs: bool
    load_pair: bool
    store_pair: bool
    same_low: bool
    same_high: bool
    same_rhs: bool


@dataclass
class _WordStoreCoalesceCtx8616:
    """Callables plus mutable state for segmented word-store coalescing."""

    project: object
    codegen: object
    target_type: object
    debug_widening: bool
    runtime_access_context: object
    match_ss_local_plus_const: Callable[..., object]
    match_word_rhs_from_byte_pair: Callable[..., object]
    promote_direct_stack_cvariable: Callable[..., object]
    stack_slot_identity_can_join: Callable[..., object]
    canonicalize_stack_cvar_expr: Callable[..., object]
    match_byte_store_addr_expr: Callable[..., object]
    match_shift_right_8_expr: Callable[..., object]
    addr_exprs_are_byte_pair: Callable[..., object]
    resolve_stack_cvar_from_addr_expr: Callable[..., object]
    make_word_dereference_from_addr_expr: Callable[..., object]
    classify_segmented_addr_expr: Callable[..., object]
    describe_alias_storage: Callable[..., object]
    match_byte_load_addr_expr: Callable[..., object] | None
    same_c_expression: Callable[..., object] | None
    changed: bool = False
    promoted: bool = False


def _wstore_debug_8616(enabled: bool, reason: str, **attrs: object) -> None:
    """Emit one widening debug line when ``enabled``."""
    if not enabled:
        return
    parts = [f"reason={reason}"]
    for key in sorted(attrs):
        value = attrs[key]
        if value is None:
            value = "-"
        parts.append(f"{key}={value}")
    print("[widening.coalesce_word_store] " + " ".join(parts), file=sys.stderr)


def _same_expr_8616(ctx: _WordStoreCoalesceCtx8616, lhs: object, rhs: object) -> bool:
    """Expression equality via the configured comparator or identity."""
    if callable(ctx.same_c_expression):
        return bool(ctx.same_c_expression(lhs, rhs))
    return lhs is rhs


def _node_kind_8616(node: object) -> str:
    """Debug kind name for a node."""
    return "-" if node is None else type(node).__name__


def _node_op_8616(node: object) -> str:
    """Debug op name for a node."""
    return str(_dynamic_attr_8616(node, "op", "-")) if node is not None else "-"


def _node_child_kind_8616(node: object, attr: str) -> str:
    """Debug kind name for a node child attribute."""
    if node is None or not hasattr(node, attr):
        return "-"
    try:
        return _node_kind_8616(_dynamic_attr_8616(node, attr))
    except Exception:
        return "error"


def _node_type_bits_8616(node: object) -> str:
    """Debug bit-size string for a node type."""
    type_ = _dynamic_attr_8616(node, "type", None)
    bits = _dynamic_attr_8616(type_, "size", None)
    return "-" if bits is None else str(bits)


def _expr_width_bits_8616(node: object) -> int | None:
    """Bit width of an expression, from its type or backing variable."""
    type_ = _dynamic_attr_8616(node, "type", None)
    try:
        bits = _dynamic_attr_8616(type_, "size", None)
    except ValueError:
        bits = None
    if isinstance(bits, int):
        return bits
    variable = _dynamic_attr_8616(node, "variable", None)
    size = _dynamic_attr_8616(variable, "size", None)
    if isinstance(size, int) and size > 0:
        return size * 8
    return None


def _wstore_unwrap_casts_8616(node: object) -> object:
    """Strip ``CTypeCast`` wrappers."""
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _match_byte_load_addr_8616(ctx: _WordStoreCoalesceCtx8616, lhs: object, rhs: object) -> object | None:
    """Return the byte-load address behind ``rhs`` (or via the matcher)."""
    if callable(ctx.match_byte_load_addr_expr):
        matched = ctx.match_byte_load_addr_expr(rhs)
        if matched is not None:
            return matched
    if _expr_width_bits_8616(lhs) != 8:
        return None
    rhs = _wstore_unwrap_casts_8616(rhs)
    if not isinstance(rhs, structured_c.CUnaryOp) or rhs.op != "Dereference":
        return None
    return _wstore_unwrap_casts_8616(_dynamic_attr_8616(rhs, "operand", None))


def _same_c_variable_8616(lhs: object, rhs: object) -> bool:
    """Variable identity by object or by name."""
    if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
        return False
    lhs_var = _dynamic_attr_8616(lhs, "variable", None)
    rhs_var = _dynamic_attr_8616(rhs, "variable", None)
    if lhs_var is rhs_var:
        return True
    lhs_name = _dynamic_attr_8616(lhs, "name", None) or _dynamic_attr_8616(lhs_var, "name", None)
    rhs_name = _dynamic_attr_8616(rhs, "name", None) or _dynamic_attr_8616(rhs_var, "name", None)
    return bool(isinstance(lhs_name, str) and lhs_name and lhs_name == rhs_name)


def _is_byte_cvar_8616(node: object) -> bool:
    """True when ``node`` is a byte-width variable."""
    return isinstance(node, structured_c.CVariable) and _expr_width_bits_8616(node) == 8


def _is_word_or_wider_cvar_8616(node: object) -> bool:
    """True when ``node`` is a word-or-wider variable."""
    return isinstance(node, structured_c.CVariable) and (_expr_width_bits_8616(node) or 0) >= 16


def _match_loaded_word_pair_expr_8616(expr: object, low_var: object, high_var: object) -> bool:
    """True when ``expr`` is ``low_var | (high_var << 8)`` in either order."""
    if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Or":
        return False
    candidates = (
        (_dynamic_attr_8616(expr, "lhs", None), _dynamic_attr_8616(expr, "rhs", None)),
        (_dynamic_attr_8616(expr, "rhs", None), _dynamic_attr_8616(expr, "lhs", None)),
    )
    for low_expr, shifted_high in candidates:
        if not _same_c_variable_8616(low_expr, low_var):
            continue
        if not isinstance(shifted_high, structured_c.CBinaryOp) or shifted_high.op != "Shl":
            continue
        shift_value = _dynamic_attr_8616(_dynamic_attr_8616(shifted_high, "rhs", None), "value", None)
        if shift_value == 8 and _same_c_variable_8616(_dynamic_attr_8616(shifted_high, "lhs", None), high_var):
            return True
    return False


def _segmented_class_allows_object_rewrite_8616(classified: object) -> bool:
    """True when the classified access permits object-level rewriting."""
    if classified is None:
        return False
    allows = _dynamic_attr_8616(classified, "allows_object_rewrite", None)
    if callable(allows):
        try:
            return bool(allows())
        except Exception:
            return False
    return bool(_dynamic_attr_8616(classified, "assoc_kind", "unknown") != "over")


def _stable_segment_const_byte_pair_8616(low_class: object, high_class: object) -> bool:
    """True for a stable adjacent ``segment_const`` byte pair on ds/es."""
    if not _is_segmented_access_8616(low_class) or not _is_segmented_access_8616(high_class):
        return False
    if low_class.kind != "segment_const" or high_class.kind != "segment_const":
        return False
    if low_class.seg_name != high_class.seg_name or low_class.seg_name not in {"ds", "es"}:
        return False
    if low_class.linear is None or high_class.linear != low_class.linear + 1:
        return False
    return _segmented_class_allows_object_rewrite_8616(low_class) and _segmented_class_allows_object_rewrite_8616(
        high_class
    )


def _replace_loaded_word_pair_expr_8616(
    expr: object, low_var: object, high_var: object, replacement: object
) -> tuple[object, bool]:
    """Rewrite ``low | (high << 8)`` subexpressions to ``replacement``."""
    if _match_loaded_word_pair_expr_8616(expr, low_var, high_var):
        return replacement, True
    if isinstance(expr, structured_c.CBinaryOp):
        new_lhs, lhs_changed = _replace_loaded_word_pair_expr_8616(expr.lhs, low_var, high_var, replacement)
        new_rhs, rhs_changed = _replace_loaded_word_pair_expr_8616(expr.rhs, low_var, high_var, replacement)
        if lhs_changed or rhs_changed:
            new_expr = copy.copy(expr)
            new_expr.lhs = new_lhs
            new_expr.rhs = new_rhs
            return new_expr, True
        return expr, False
    if isinstance(expr, structured_c.CUnaryOp):
        new_operand, operand_changed = _replace_loaded_word_pair_expr_8616(
            expr.operand, low_var, high_var, replacement
        )
        if operand_changed:
            new_expr = copy.copy(expr)
            new_expr.operand = cast(structured_c.CExpression, new_operand)
            return new_expr, True
        return expr, False
    if isinstance(expr, structured_c.CTypeCast):
        new_inner, inner_changed = _replace_loaded_word_pair_expr_8616(expr.expr, low_var, high_var, replacement)
        if inner_changed:
            new_expr = copy.copy(expr)
            new_expr.expr = cast(structured_c.CExpression, new_inner)
            return new_expr, True
        return expr, False
    return expr, False


def _word_lvalue_for_addr_8616(ctx: _WordStoreCoalesceCtx8616, low_addr_expr: object) -> object | None:
    """Resolve a word-width lvalue for ``low_addr_expr``."""
    low_class = ctx.classify_segmented_addr_expr(low_addr_expr, ctx.project)
    _wstore_debug_8616(
        ctx.debug_widening,
        "word_lvalue_class",
        cls_kind=_dynamic_attr_8616(low_class, "kind", None),
        cls_seg=_dynamic_attr_8616(low_class, "seg_name", None),
        cls_assoc=_dynamic_attr_8616(low_class, "assoc_kind", None),
        cls_extra=_dynamic_attr_8616(low_class, "extra_offset", None),
        cls_base_terms=_dynamic_attr_8616(_dynamic_attr_8616(low_class, "assoc_state", None), "base_terms", None),
        cls_other_terms=_dynamic_attr_8616(_dynamic_attr_8616(low_class, "assoc_state", None), "other_terms", None),
        cls_stack_slots=len(_dynamic_attr_8616(_dynamic_attr_8616(low_class, "assoc_state", None), "stack_slots", ()) or ()),
        has_cvar=int(_dynamic_attr_8616(low_class, "cvar", None) is not None),
    )
    if _is_segmented_access_8616(low_class) and low_class.kind == "stack":
        resolved_lhs = ctx.resolve_stack_cvar_from_addr_expr(ctx.project, ctx.codegen, low_addr_expr)
        if resolved_lhs is None:
            return None
        replacement_lhs = ctx.canonicalize_stack_cvar_expr(resolved_lhs, ctx.codegen)
        if ctx.promote_direct_stack_cvariable(ctx.codegen, replacement_lhs, 2, ctx.target_type):
            ctx.promoted = True
        return replacement_lhs
    resolved_lhs = ctx.resolve_stack_cvar_from_addr_expr(ctx.project, ctx.codegen, low_addr_expr)
    if resolved_lhs is not None:
        return ctx.canonicalize_stack_cvar_expr(resolved_lhs, ctx.codegen)
    return ctx.make_word_dereference_from_addr_expr(ctx.codegen, ctx.project, low_addr_expr)


def _runtime_word_store_lvalue_8616(
    ctx: _WordStoreCoalesceCtx8616, low_lhs: object, high_lhs: object
) -> structured_c.CFunctionCall | None:
    """Join two typed adjacent runtime byte accesses into one word access."""
    for space in (MemSpace.DS, MemSpace.ES):
        low_offset = runtime_segment_access_offset_expr_8616(
            ctx.project,
            ctx.codegen,
            low_lhs,
            expected_space=space,
            width=1,
            context=ctx.runtime_access_context,
        )
        high_offset = runtime_segment_access_offset_expr_8616(
            ctx.project,
            ctx.codegen,
            high_lhs,
            expected_space=space,
            width=1,
            context=ctx.runtime_access_context,
        )
        if (
            low_offset is None
            or high_offset is None
            or not ctx.addr_exprs_are_byte_pair(low_offset, high_offset, ctx.project)
        ):
            continue
        low_access = _wstore_unwrap_casts_8616(low_lhs)
        if not isinstance(low_access, structured_c.CFunctionCall):
            return None
        low_args = tuple(low_access.args or ())
        if len(low_args) != 2:
            return None
        source_addrs = instruction_addrs_from_node_8616(low_lhs) | instruction_addrs_from_node_8616(high_lhs)
        tags: dict[str, object] = {"inertia_x86_16_runtime_segment_helper": "SEG_U16"}
        if source_addrs:
            tags["inertia_source_instruction_addrs"] = tuple(sorted(source_addrs))
        return structured_c.CFunctionCall(
            "SEG_U16",
            None,
            [low_args[0], low_offset],
            codegen=ctx.codegen,
            tags=tags,
        )
    return None


def _wstore_triple_gate_8616(
    ctx: _WordStoreCoalesceCtx8616, stmt: object, next_stmt: object, third_stmt: object
) -> bool:
    """Gate: ``low = word; high = word; word = f(low, high)`` triple."""
    return (
        isinstance(stmt, structured_c.CAssignment)
        and isinstance(next_stmt, structured_c.CAssignment)
        and isinstance(third_stmt, structured_c.CAssignment)
        and _is_byte_cvar_8616(_dynamic_attr_8616(stmt, "lhs", None))
        and _is_byte_cvar_8616(_dynamic_attr_8616(next_stmt, "lhs", None))
        and _is_word_or_wider_cvar_8616(_dynamic_attr_8616(stmt, "rhs", None))
        and _same_expr_8616(ctx, _dynamic_attr_8616(stmt, "rhs", None), _dynamic_attr_8616(next_stmt, "rhs", None))
        and _same_c_variable_8616(_dynamic_attr_8616(stmt, "rhs", None), _dynamic_attr_8616(third_stmt, "lhs", None))
    )


def _word_store_triple_step_8616(
    statements: list[object], i: int, ctx: _WordStoreCoalesceCtx8616
) -> tuple[object, int] | None:
    """Merge a loaded-word-pair triple into one assignment."""
    stmt = statements[i]
    next_stmt = statements[i + 1] if i + 1 < len(statements) else None
    third_stmt = statements[i + 2] if i + 2 < len(statements) else None
    if not _wstore_triple_gate_8616(ctx, stmt, next_stmt, third_stmt):
        return None
    rewritten_rhs, rhs_changed = _replace_loaded_word_pair_expr_8616(
        _dynamic_attr_8616(third_stmt, "rhs", None),
        _dynamic_attr_8616(stmt, "lhs", None),
        _dynamic_attr_8616(next_stmt, "lhs", None),
        _dynamic_attr_8616(stmt, "rhs", None),
    )
    if not rhs_changed:
        return None
    return (
        structured_c.CAssignment(
            _dynamic_attr_8616(third_stmt, "lhs", None),
            ctx.canonicalize_stack_cvar_expr(rewritten_rhs, ctx.codegen),
            codegen=ctx.codegen,
        ),
        3,
    )


def _wstore_quad_gate_8616(
    ctx: _WordStoreCoalesceCtx8616,
    stmt: object,
    next_stmt: object,
    third_stmt: object,
    fourth_stmt: object,
) -> bool:
    """Gate: ``low = *p; high = *(p+1); *q = low; *(q+1) = high >> 8`` quad."""
    return (
        callable(ctx.match_byte_load_addr_expr)
        and isinstance(stmt, structured_c.CAssignment)
        and isinstance(next_stmt, structured_c.CAssignment)
        and isinstance(third_stmt, structured_c.CAssignment)
        and isinstance(fourth_stmt, structured_c.CAssignment)
        and isinstance(_dynamic_attr_8616(stmt, "lhs", None), structured_c.CVariable)
        and isinstance(_dynamic_attr_8616(next_stmt, "lhs", None), structured_c.CVariable)
    )


def _quad_addr_facts_8616(
    ctx: _WordStoreCoalesceCtx8616,
    stmt: object,
    next_stmt: object,
    third_stmt: object,
    fourth_stmt: object,
) -> _QuadAddrFacts8616:
    """Collect the load/store address facts for the four-statement probe."""
    low_load_addr = _match_byte_load_addr_8616(
        ctx, _dynamic_attr_8616(stmt, "lhs", None), _dynamic_attr_8616(stmt, "rhs", None)
    )
    high_load_addr = _match_byte_load_addr_8616(
        ctx, _dynamic_attr_8616(next_stmt, "lhs", None), _dynamic_attr_8616(next_stmt, "rhs", None)
    )
    low_store_addr = ctx.match_byte_store_addr_expr(_dynamic_attr_8616(third_stmt, "lhs", None))
    high_store_addr = ctx.match_byte_store_addr_expr(_dynamic_attr_8616(fourth_stmt, "lhs", None))
    high_store_base = ctx.match_shift_right_8_expr(_dynamic_attr_8616(fourth_stmt, "rhs", None))
    has_addrs = all(
        value is not None
        for value in (low_load_addr, high_load_addr, low_store_addr, high_store_addr, high_store_base)
    )
    load_pair = (
        bool(ctx.addr_exprs_are_byte_pair(low_load_addr, high_load_addr, ctx.project)) if has_addrs else False
    )
    store_pair = (
        bool(ctx.addr_exprs_are_byte_pair(low_store_addr, high_store_addr, ctx.project)) if has_addrs else False
    )
    same_low = _same_expr_8616(ctx, low_load_addr, low_store_addr) if has_addrs else False
    same_high = _same_expr_8616(ctx, high_load_addr, high_store_addr) if has_addrs else False
    same_rhs = (
        _same_expr_8616(ctx, high_store_base, _dynamic_attr_8616(third_stmt, "rhs", None)) if has_addrs else False
    )
    return _QuadAddrFacts8616(
        low_load_addr=low_load_addr,
        high_load_addr=high_load_addr,
        low_store_addr=low_store_addr,
        high_store_addr=high_store_addr,
        high_store_base=high_store_base,
        has_addrs=has_addrs,
        load_pair=load_pair,
        store_pair=store_pair,
        same_low=same_low,
        same_high=same_high,
        same_rhs=same_rhs,
    )


def _wstore_debug_quad_8616(
    ctx: _WordStoreCoalesceCtx8616, facts: _QuadAddrFacts8616, stmt: object, next_stmt: object
) -> None:
    """Emit the four-statement probe debug dump."""
    if not (
        ctx.debug_widening
        and any(
            value is not None
            for value in (
                facts.low_load_addr,
                facts.high_load_addr,
                facts.low_store_addr,
                facts.high_store_addr,
                facts.high_store_base,
            )
        )
    ):
        return
    _wstore_debug_8616(
        ctx.debug_widening,
        "four_stmt_probe",
        low_load=_node_kind_8616(facts.low_load_addr),
        low_rhs=_node_kind_8616(_dynamic_attr_8616(stmt, "rhs", None)),
        low_rhs_op=_node_op_8616(_dynamic_attr_8616(stmt, "rhs", None)),
        low_rhs_expr=_node_child_kind_8616(_dynamic_attr_8616(stmt, "rhs", None), "expr"),
        low_rhs_operand=_node_child_kind_8616(_dynamic_attr_8616(stmt, "rhs", None), "operand"),
        low_rhs_bits=_node_type_bits_8616(_dynamic_attr_8616(stmt, "rhs", None)),
        high_load=_node_kind_8616(facts.high_load_addr),
        high_rhs=_node_kind_8616(_dynamic_attr_8616(next_stmt, "rhs", None)),
        high_rhs_op=_node_op_8616(_dynamic_attr_8616(next_stmt, "rhs", None)),
        high_rhs_expr=_node_child_kind_8616(_dynamic_attr_8616(next_stmt, "rhs", None), "expr"),
        high_rhs_operand=_node_child_kind_8616(_dynamic_attr_8616(next_stmt, "rhs", None), "operand"),
        high_rhs_bits=_node_type_bits_8616(_dynamic_attr_8616(next_stmt, "rhs", None)),
        low_store=_node_kind_8616(facts.low_store_addr),
        high_store=_node_kind_8616(facts.high_store_addr),
        high_base=_node_kind_8616(facts.high_store_base),
        load_pair=int(facts.load_pair),
        store_pair=int(facts.store_pair),
        same_low=int(facts.same_low),
        same_high=int(facts.same_high),
        same_rhs=int(facts.same_rhs),
    )


def _word_store_quad_step_8616(
    statements: list[object], i: int, ctx: _WordStoreCoalesceCtx8616
) -> tuple[object, int] | None:
    """Merge a load+store byte quad into one word assignment."""
    stmt = statements[i]
    next_stmt = statements[i + 1] if i + 1 < len(statements) else None
    third_stmt = statements[i + 2] if i + 2 < len(statements) else None
    fourth_stmt = statements[i + 3] if i + 3 < len(statements) else None
    if not _wstore_quad_gate_8616(ctx, stmt, next_stmt, third_stmt, fourth_stmt):
        return None
    facts = _quad_addr_facts_8616(ctx, stmt, next_stmt, third_stmt, fourth_stmt)
    _wstore_debug_quad_8616(ctx, facts, stmt, next_stmt)
    if not (
        facts.has_addrs
        and facts.load_pair
        and facts.store_pair
        and facts.same_low
        and facts.same_high
        and facts.same_rhs
    ):
        return None
    loaded_word = _word_lvalue_for_addr_8616(ctx, facts.low_load_addr)
    store_lhs = _word_lvalue_for_addr_8616(ctx, facts.low_store_addr)
    if loaded_word is None or store_lhs is None:
        _wstore_debug_8616(
            ctx.debug_widening,
            "four_stmt_no_lvalue",
            loaded_word=_node_kind_8616(loaded_word),
            store_lhs=_node_kind_8616(store_lhs),
        )
        return None
    rewritten_rhs, rhs_changed = _replace_loaded_word_pair_expr_8616(
        _dynamic_attr_8616(third_stmt, "rhs", None),
        _dynamic_attr_8616(stmt, "lhs", None),
        _dynamic_attr_8616(next_stmt, "lhs", None),
        loaded_word,
    )
    if not rhs_changed:
        _wstore_debug_8616(
            ctx.debug_widening,
            "four_stmt_refused",
            loaded_word=_node_kind_8616(loaded_word),
            store_lhs=_node_kind_8616(store_lhs),
            rhs_changed=0,
        )
        return None
    return (
        structured_c.CAssignment(
            store_lhs,
            ctx.canonicalize_stack_cvar_expr(rewritten_rhs, ctx.codegen),
            codegen=ctx.codegen,
        ),
        4,
    )


def _wstore_runtime_pair_8616(ctx: _WordStoreCoalesceCtx8616, stmt: object, next_stmt: object) -> object | None:
    """Word assignment for a runtime segment-helper byte pair."""
    runtime_word_lhs = _runtime_word_store_lvalue_8616(ctx, stmt.lhs, next_stmt.lhs)
    runtime_word_rhs = ctx.match_word_rhs_from_byte_pair(stmt.rhs, next_stmt.rhs, ctx.codegen, ctx.project)
    if runtime_word_lhs is None or runtime_word_rhs is None:
        return None
    return structured_c.CAssignment(runtime_word_lhs, runtime_word_rhs, codegen=ctx.codegen)


def _wstore_ss_local_pair_8616(ctx: _WordStoreCoalesceCtx8616, stmt: object, next_stmt: object) -> object | None:
    """Word assignment for an ``SS:local + 1`` high-byte store pair."""
    if not isinstance(stmt.lhs, structured_c.CVariable):
        return None
    matched = _pair_result_8616(ctx.match_ss_local_plus_const(next_stmt.lhs, ctx.project))
    if matched is None:
        return None
    target_cvar, extra_offset = matched
    rhs_word = ctx.match_word_rhs_from_byte_pair(stmt.rhs, next_stmt.rhs, ctx.codegen, ctx.project)
    if not (
        extra_offset == 1
        and isinstance(target_cvar, structured_c.CVariable)
        and target_cvar is not None
        and rhs_word is not None
        and ctx.stack_slot_identity_can_join(target_cvar, stmt.lhs)
    ):
        return None
    replacement_lhs = ctx.canonicalize_stack_cvar_expr(stmt.lhs, ctx.codegen)
    rhs_word = ctx.canonicalize_stack_cvar_expr(rhs_word, ctx.codegen)
    if ctx.promote_direct_stack_cvariable(ctx.codegen, replacement_lhs, 2, ctx.target_type):
        ctx.changed = True
    return structured_c.CAssignment(replacement_lhs, rhs_word, codegen=ctx.codegen)


def _wstore_alias_pair_unjoinable_8616(
    low_facts: object,
    high_facts: object,
    joinable_segment_const_pair: bool,
    joinable_stack_alias_pair: bool,
) -> bool:
    """True when the byte-pair alias facts cannot join into a word store."""
    if joinable_segment_const_pair or joinable_stack_alias_pair:
        return False
    return (
        not _is_alias_storage_facts_8616(low_facts)
        or not _is_alias_storage_facts_8616(high_facts)
        or low_facts.identity is None
        or high_facts.identity is None
        or not low_facts.can_join(high_facts)
    )


def _wstore_alias_pair_8616(ctx: _WordStoreCoalesceCtx8616, stmt: object, next_stmt: object) -> object | None:
    """Word assignment for an adjacent byte-store alias pair."""
    low_addr_expr = ctx.match_byte_store_addr_expr(stmt.lhs)
    high_addr_expr = ctx.match_byte_store_addr_expr(next_stmt.lhs)
    rhs_word = ctx.match_word_rhs_from_byte_pair(stmt.rhs, next_stmt.rhs, ctx.codegen, ctx.project)
    if not (
        low_addr_expr is not None
        and high_addr_expr is not None
        and rhs_word is not None
        and ctx.addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, ctx.project)
    ):
        return None
    low_facts = ctx.describe_alias_storage(low_addr_expr)
    high_facts = ctx.describe_alias_storage(high_addr_expr)
    low_class = ctx.classify_segmented_addr_expr(low_addr_expr, ctx.project)
    high_class = ctx.classify_segmented_addr_expr(high_addr_expr, ctx.project)
    joinable_segment_const_pair = _stable_segment_const_byte_pair_8616(low_class, high_class)
    joinable_stack_alias_pair = (
        _is_segmented_access_8616(low_class) and low_class.kind == "stack" and high_class is None
    )
    if _wstore_alias_pair_unjoinable_8616(
        low_facts, high_facts, joinable_segment_const_pair, joinable_stack_alias_pair
    ):
        return None
    if _is_segmented_access_8616(low_class) and low_class.kind == "stack":
        resolved_lhs = ctx.resolve_stack_cvar_from_addr_expr(ctx.project, ctx.codegen, low_addr_expr)
        if resolved_lhs is None:
            return None
        replacement_lhs = ctx.canonicalize_stack_cvar_expr(resolved_lhs, ctx.codegen)
        rhs_word = ctx.canonicalize_stack_cvar_expr(rhs_word, ctx.codegen)
        if ctx.promote_direct_stack_cvariable(ctx.codegen, replacement_lhs, 2, ctx.target_type):
            ctx.changed = True
        return structured_c.CAssignment(replacement_lhs, rhs_word, codegen=ctx.codegen)
    resolved_lhs = ctx.resolve_stack_cvar_from_addr_expr(ctx.project, ctx.codegen, low_addr_expr)
    return structured_c.CAssignment(
        resolved_lhs
        if resolved_lhs is not None
        else ctx.make_word_dereference_from_addr_expr(ctx.codegen, ctx.project, low_addr_expr),
        rhs_word,
        codegen=ctx.codegen,
    )


def _word_store_pair_step_8616(
    statements: list[object], i: int, ctx: _WordStoreCoalesceCtx8616
) -> tuple[object, int] | None:
    """Try to merge statements ``i``/``i+1`` into one word assignment."""
    stmt = statements[i]
    next_stmt = statements[i + 1] if i + 1 < len(statements) else None
    if not (isinstance(stmt, structured_c.CAssignment) and isinstance(next_stmt, structured_c.CAssignment)):
        return None
    replacement = _wstore_runtime_pair_8616(ctx, stmt, next_stmt)
    if replacement is None:
        replacement = _wstore_ss_local_pair_8616(ctx, stmt, next_stmt)
    if replacement is None:
        replacement = _wstore_alias_pair_8616(ctx, stmt, next_stmt)
    if replacement is None:
        return None
    return replacement, 2


def _coalesce_word_store_seq_8616(node: object, ctx: _WordStoreCoalesceCtx8616) -> None:
    """Coalesce adjacent byte statements in one ``CStatements`` sequence."""
    new_statements = []
    i = 0
    while i < len(node.statements):
        stmt = node.statements[i]
        outcome = (
            _word_store_triple_step_8616(node.statements, i, ctx)
            or _word_store_quad_step_8616(node.statements, i, ctx)
            or _word_store_pair_step_8616(node.statements, i, ctx)
        )
        if outcome is not None:
            replacement, consumed = outcome
            new_statements.append(replacement)
            ctx.changed = True
            i += consumed
            continue
        _visit_word_store_node_8616(stmt, ctx)
        new_statements.append(stmt)
        i += 1

    if ctx.changed or new_statements != node.statements:
        node.statements = new_statements


def _visit_word_store_node_8616(node: object, ctx: _WordStoreCoalesceCtx8616) -> None:
    """Dispatch one structured-C node for segmented word-store coalescing."""
    if isinstance(node, structured_c.CStatements):
        _coalesce_word_store_seq_8616(node, ctx)
        return
    _visit_structured_children_8616(node, lambda child: _visit_word_store_node_8616(child, ctx))


def _coalesce_segmented_word_store_statements(
    project: object,
    codegen: object,
    *,
    match_ss_local_plus_const: Callable[..., object],
    match_word_rhs_from_byte_pair: Callable[..., object],
    promote_direct_stack_cvariable: Callable[..., object],
    stack_type_for_size: Callable[..., object],
    stack_slot_identity_can_join: Callable[..., object],
    canonicalize_stack_cvar_expr: Callable[..., object],
    match_byte_store_addr_expr: Callable[..., object],
    match_shift_right_8_expr: Callable[..., object],
    addr_exprs_are_byte_pair: Callable[..., object],
    resolve_stack_cvar_from_addr_expr: Callable[..., object],
    make_word_dereference_from_addr_expr: Callable[..., object],
    classify_segmented_addr_expr: Callable[..., object],
    describe_alias_storage: Callable[..., object],
    match_byte_load_addr_expr: Callable[..., object] | None = None,
    same_c_expression: Callable[..., object] | None = None,
) -> bool:
    if _dynamic_attr_8616(codegen, "cfunc", None) is None:
        return False

    ctx = _WordStoreCoalesceCtx8616(
        project=project,
        codegen=codegen,
        target_type=stack_type_for_size(2),
        debug_widening=os.environ.get("INERTIA_DEBUG_WIDENING", "").strip().lower()
        in {"1", "true", "yes", "on"},
        runtime_access_context=build_runtime_segment_access_context_8616(codegen),
        match_ss_local_plus_const=match_ss_local_plus_const,
        match_word_rhs_from_byte_pair=match_word_rhs_from_byte_pair,
        promote_direct_stack_cvariable=promote_direct_stack_cvariable,
        stack_slot_identity_can_join=stack_slot_identity_can_join,
        canonicalize_stack_cvar_expr=canonicalize_stack_cvar_expr,
        match_byte_store_addr_expr=match_byte_store_addr_expr,
        match_shift_right_8_expr=match_shift_right_8_expr,
        addr_exprs_are_byte_pair=addr_exprs_are_byte_pair,
        resolve_stack_cvar_from_addr_expr=resolve_stack_cvar_from_addr_expr,
        make_word_dereference_from_addr_expr=make_word_dereference_from_addr_expr,
        classify_segmented_addr_expr=classify_segmented_addr_expr,
        describe_alias_storage=describe_alias_storage,
        match_byte_load_addr_expr=match_byte_load_addr_expr,
        same_c_expression=same_c_expression,
    )
    _visit_word_store_node_8616(
        _dynamic_attr_8616(_dynamic_attr_8616(codegen, "cfunc", None), "statements", None), ctx
    )
    return ctx.changed
