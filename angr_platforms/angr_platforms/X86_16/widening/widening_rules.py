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


def collect_bp_stack_access_widths_from_instructions_8616(project: object, codegen: object) -> dict[int, int]:
    """Collect BP-relative stack slot widths directly from decoded instructions."""
    cfunc = _dynamic_attr_8616(codegen, "cfunc", None)
    func_addr = _dynamic_attr_8616(cfunc, "addr", None)
    if not isinstance(func_addr, int):
        return {}

    kb = _dynamic_attr_8616(project, "kb", None)
    functions = _dynamic_attr_8616(kb, "functions", None)
    function = None
    if functions is not None:
        try:
            function = functions.function(addr=int(func_addr), create=False)
        except Exception:
            function = None
    if function is None:
        function = SimpleNamespace(
            addr=int(func_addr),
            size=_dynamic_attr_8616(cfunc, "size", None),
            name=_dynamic_attr_8616(cfunc, "name", None),
        )

    widths: dict[int, int] = {}
    for insn in _function_instruction_summaries_8616(project, function):
        if insn.mnemonic.lower() == "lea":
            continue
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
            if str(_dynamic_attr_8616(insn, "mnemonic", "")).lower() == "lea":
                continue
            operands = cast(tuple[object, ...], tuple(_dynamic_attr_8616(insn, "operands", ()) or ()))
            for operand_index, operand in enumerate(operands):
                if int(_dynamic_attr_8616(operand, "type", -1)) != 3 or _dynamic_attr_8616(operand, "mem", None) is None:
                    continue
                mem = _dynamic_attr_8616(operand, "mem")
                if not _dynamic_attr_8616(mem, "base", None):
                    continue
                try:
                    base_name = str(insn.reg_name(mem.base)).lower()
                except Exception:
                    continue
                if base_name != "bp":
                    continue
                size = decoded_memory_operand_width_8616(
                    int(_dynamic_attr_8616(insn, "id", 0)), operand_index,
                    int(_dynamic_attr_8616(operand, "size", 0) or 0),
                    int(_dynamic_attr_8616(operands[0], "size", 0) or 0),
                ) or 0
                if size <= 0:
                    continue
                disp = int(_dynamic_attr_8616(mem, "disp", 0) or 0)
                if 0x8000 <= disp <= 0xFFFF:
                    disp -= 0x10000
                widths[disp] = max(widths.get(disp, 0), size)
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

    changed = False

    def visit(node: object) -> None:
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                if (
                    i + 1 < len(node.statements)
                    and isinstance(stmt, structured_c.CAssignment)
                    and isinstance(node.statements[i + 1], structured_c.CAssignment)
                ):
                    next_stmt = node.statements[i + 1]
                    replacement = None
                    replacement_lhs = None

                    if isinstance(stmt.lhs, structured_c.CVariable):
                        matched = _pair_result_8616(match_ss_local_plus_const(next_stmt.lhs, project))
                        if matched is not None:
                            target_cvar, extra_offset = matched
                            high_expr = match_shift_right_8_expr(next_stmt.rhs)
                            if (
                                (
                                    (
                                        extra_offset == 1
                                        and stack_slot_identity_can_join(target_cvar, stmt.lhs)
                                    )
                                    or derived_stack_high_byte_follows_slot(
                                        target_cvar,
                                        extra_offset,
                                        stmt.lhs,
                                    )
                                )
                                and high_expr is not None
                                and same_c_expression(unwrap_c_casts(high_expr), unwrap_c_casts(stmt.rhs))
                            ):
                                replacement_lhs = stmt.lhs

                    if replacement_lhs is None:
                        low_addr_expr = match_byte_store_addr_expr(stmt.lhs)
                        high_addr_expr = match_byte_store_addr_expr(next_stmt.lhs)
                        high_expr = match_shift_right_8_expr(next_stmt.rhs)
                        if (
                            low_addr_expr is not None
                            and high_addr_expr is not None
                            and high_expr is not None
                            and addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project)
                            and same_c_expression(unwrap_c_casts(high_expr), unwrap_c_casts(stmt.rhs))
                        ):
                            resolved_lhs = resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
                            if isinstance(resolved_lhs, structured_c.CVariable):
                                replacement_lhs = canonicalize_stack_cvar_expr(resolved_lhs, codegen)

                    if isinstance(replacement_lhs, structured_c.CVariable):
                        if promote_direct_stack_cvariable(codegen, replacement_lhs, 2, stack_type_for_size(2)):
                            changed = True
                        replacement = structured_c.CAssignment(replacement_lhs, stmt.rhs, codegen=codegen)

                    if replacement is not None:
                        new_statements.append(replacement)
                        changed = True
                        i += 2
                        continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if changed or new_statements != node.statements:
                node.statements = new_statements
        elif isinstance(node, structured_c.CIfElse):
            for _cond, body in node.condition_and_nodes:
                visit(body)
            if node.else_node is not None:
                visit(node.else_node)
        elif isinstance(node, structured_c.CWhileLoop) or (hasattr(structured_c, "CDoWhileLoop") and isinstance(node, _dynamic_attr_8616(structured_c, "CDoWhileLoop"))):
            visit(_dynamic_attr_8616(node, "condition", None))
            visit(_dynamic_attr_8616(node, "body", None))
        elif hasattr(structured_c, "CForLoop") and isinstance(node, _dynamic_attr_8616(structured_c, "CForLoop")):
            visit(_dynamic_attr_8616(node, "init", None))
            visit(_dynamic_attr_8616(node, "condition", None))
            visit(_dynamic_attr_8616(node, "iteration", None))
            visit(_dynamic_attr_8616(node, "body", None))

    visit(_dynamic_attr_8616(_dynamic_attr_8616(codegen, "cfunc", None), "statements", None))
    return changed


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

    changed = False
    target_type = stack_type_for_size(2)
    debug_widening = os.environ.get("INERTIA_DEBUG_WIDENING", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    def _debug(reason: str, **attrs: object) -> None:
        if not debug_widening:
            return
        parts = [f"reason={reason}"]
        for key in sorted(attrs):
            value = attrs[key]
            if value is None:
                value = "-"
            parts.append(f"{key}={value}")
        print("[widening.coalesce_word_store] " + " ".join(parts), file=sys.stderr)

    def _same_expr(lhs: object, rhs: object) -> bool:
        if callable(same_c_expression):
            return bool(same_c_expression(lhs, rhs))
        return lhs is rhs

    def _node_kind(node: object) -> str:
        return "-" if node is None else type(node).__name__

    def _node_op(node: object) -> str:
        return str(_dynamic_attr_8616(node, "op", "-")) if node is not None else "-"

    def _node_child_kind(node: object, attr: str) -> str:
        if node is None or not hasattr(node, attr):
            return "-"
        try:
            return _node_kind(_dynamic_attr_8616(node, attr))
        except Exception:
            return "error"

    def _node_type_bits(node: object) -> str:
        type_ = _dynamic_attr_8616(node, "type", None)
        bits = _dynamic_attr_8616(type_, "size", None)
        return "-" if bits is None else str(bits)

    def _expr_width_bits(node: object) -> int | None:
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

    def _unwrap_casts(node: object) -> object:
        while isinstance(node, structured_c.CTypeCast):
            node = node.expr
        return node

    def _match_byte_load_addr_for_assignment(lhs: object, rhs: object) -> object | None:
        if callable(match_byte_load_addr_expr):
            matched = match_byte_load_addr_expr(rhs)
            if matched is not None:
                return matched
        if _expr_width_bits(lhs) != 8:
            return None
        rhs = _unwrap_casts(rhs)
        if not isinstance(rhs, structured_c.CUnaryOp) or rhs.op != "Dereference":
            return None
        operand = _unwrap_casts(_dynamic_attr_8616(rhs, "operand", None))
        return operand

    def _same_c_variable(lhs: object, rhs: object) -> bool:
        if not isinstance(lhs, structured_c.CVariable) or not isinstance(rhs, structured_c.CVariable):
            return False
        lhs_var = _dynamic_attr_8616(lhs, "variable", None)
        rhs_var = _dynamic_attr_8616(rhs, "variable", None)
        if lhs_var is rhs_var:
            return True
        lhs_name = _dynamic_attr_8616(lhs, "name", None) or _dynamic_attr_8616(lhs_var, "name", None)
        rhs_name = _dynamic_attr_8616(rhs, "name", None) or _dynamic_attr_8616(rhs_var, "name", None)
        return bool(isinstance(lhs_name, str) and lhs_name and lhs_name == rhs_name)

    def _is_byte_cvar(node: object) -> bool:
        return isinstance(node, structured_c.CVariable) and _expr_width_bits(node) == 8

    def _is_word_or_wider_cvar(node: object) -> bool:
        return isinstance(node, structured_c.CVariable) and (_expr_width_bits(node) or 0) >= 16

    def _match_loaded_word_pair_expr(expr: object, low_var: object, high_var: object) -> bool:
        if not isinstance(expr, structured_c.CBinaryOp) or expr.op != "Or":
            return False
        candidates = (
            (_dynamic_attr_8616(expr, "lhs", None), _dynamic_attr_8616(expr, "rhs", None)),
            (_dynamic_attr_8616(expr, "rhs", None), _dynamic_attr_8616(expr, "lhs", None)),
        )
        for low_expr, shifted_high in candidates:
            if not _same_c_variable(low_expr, low_var):
                continue
            if not isinstance(shifted_high, structured_c.CBinaryOp) or shifted_high.op != "Shl":
                continue
            shift_value = _dynamic_attr_8616(_dynamic_attr_8616(shifted_high, "rhs", None), "value", None)
            if shift_value == 8 and _same_c_variable(_dynamic_attr_8616(shifted_high, "lhs", None), high_var):
                return True
        return False

    def _segmented_class_allows_object_rewrite(classified: object) -> bool:
        if classified is None:
            return False
        allows = _dynamic_attr_8616(classified, "allows_object_rewrite", None)
        if callable(allows):
            try:
                return bool(allows())
            except Exception:
                return False
        return bool(_dynamic_attr_8616(classified, "assoc_kind", "unknown") != "over")

    def _stable_segment_const_byte_pair(low_class: object, high_class: object) -> bool:
        if not _is_segmented_access_8616(low_class) or not _is_segmented_access_8616(high_class):
            return False
        if low_class.kind != "segment_const" or high_class.kind != "segment_const":
            return False
        if low_class.seg_name != high_class.seg_name or low_class.seg_name not in {"ds", "es"}:
            return False
        if low_class.linear is None or high_class.linear != low_class.linear + 1:
            return False
        return _segmented_class_allows_object_rewrite(low_class) and _segmented_class_allows_object_rewrite(high_class)

    def _replace_loaded_word_pair_expr(
        expr: object, low_var: object, high_var: object, replacement: object
    ) -> tuple[object, bool]:
        if _match_loaded_word_pair_expr(expr, low_var, high_var):
            return replacement, True
        if isinstance(expr, structured_c.CBinaryOp):
            new_lhs, lhs_changed = _replace_loaded_word_pair_expr(expr.lhs, low_var, high_var, replacement)
            new_rhs, rhs_changed = _replace_loaded_word_pair_expr(expr.rhs, low_var, high_var, replacement)
            if lhs_changed or rhs_changed:
                new_expr = copy.copy(expr)
                new_expr.lhs = new_lhs
                new_expr.rhs = new_rhs
                return new_expr, True
            return expr, False
        if isinstance(expr, structured_c.CUnaryOp):
            new_operand, operand_changed = _replace_loaded_word_pair_expr(expr.operand, low_var, high_var, replacement)
            if operand_changed:
                new_expr = copy.copy(expr)
                new_expr.operand = cast(structured_c.CExpression, new_operand)
                return new_expr, True
            return expr, False
        if isinstance(expr, structured_c.CTypeCast):
            new_inner, inner_changed = _replace_loaded_word_pair_expr(expr.expr, low_var, high_var, replacement)
            if inner_changed:
                new_expr = copy.copy(expr)
                new_expr.expr = cast(structured_c.CExpression, new_inner)
                return new_expr, True
            return expr, False
        return expr, False

    def _word_lvalue_for_addr(low_addr_expr: object) -> object | None:
        low_class = classify_segmented_addr_expr(low_addr_expr, project)
        _debug(
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
            resolved_lhs = resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
            if resolved_lhs is None:
                return None
            replacement_lhs = canonicalize_stack_cvar_expr(resolved_lhs, codegen)
            if promote_direct_stack_cvariable(codegen, replacement_lhs, 2, target_type):
                nonlocal_changed[0] = True
            return replacement_lhs
        resolved_lhs = resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
        if resolved_lhs is not None:
            return canonicalize_stack_cvar_expr(resolved_lhs, codegen)
        return make_word_dereference_from_addr_expr(codegen, project, low_addr_expr)

    nonlocal_changed = [False]
    runtime_access_context = build_runtime_segment_access_context_8616(codegen)

    def _runtime_word_store_lvalue(low_lhs: object, high_lhs: object) -> structured_c.CFunctionCall | None:
        """Join two typed adjacent runtime byte accesses into one word access."""
        for space in (MemSpace.DS, MemSpace.ES):
            low_offset = runtime_segment_access_offset_expr_8616(
                project,
                codegen,
                low_lhs,
                expected_space=space,
                width=1,
                context=runtime_access_context,
            )
            high_offset = runtime_segment_access_offset_expr_8616(
                project,
                codegen,
                high_lhs,
                expected_space=space,
                width=1,
                context=runtime_access_context,
            )
            if (
                low_offset is None
                or high_offset is None
                or not addr_exprs_are_byte_pair(low_offset, high_offset, project)
            ):
                continue
            low_access = _unwrap_casts(low_lhs)
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
                codegen=codegen,
                tags=tags,
            )
        return None

    def visit(node: object) -> None:
        nonlocal changed

        if isinstance(node, structured_c.CStatements):
            new_statements = []
            i = 0
            while i < len(node.statements):
                stmt = node.statements[i]
                next_stmt = node.statements[i + 1] if i + 1 < len(node.statements) else None
                third_stmt = node.statements[i + 2] if i + 2 < len(node.statements) else None
                fourth_stmt = node.statements[i + 3] if i + 3 < len(node.statements) else None

                if (
                    isinstance(stmt, structured_c.CAssignment)
                    and isinstance(next_stmt, structured_c.CAssignment)
                    and isinstance(third_stmt, structured_c.CAssignment)
                    and _is_byte_cvar(_dynamic_attr_8616(stmt, "lhs", None))
                    and _is_byte_cvar(_dynamic_attr_8616(next_stmt, "lhs", None))
                    and _is_word_or_wider_cvar(_dynamic_attr_8616(stmt, "rhs", None))
                    and _same_expr(_dynamic_attr_8616(stmt, "rhs", None), _dynamic_attr_8616(next_stmt, "rhs", None))
                    and _same_c_variable(_dynamic_attr_8616(stmt, "rhs", None), _dynamic_attr_8616(third_stmt, "lhs", None))
                ):
                    rewritten_rhs, rhs_changed = _replace_loaded_word_pair_expr(
                        _dynamic_attr_8616(third_stmt, "rhs", None),
                        _dynamic_attr_8616(stmt, "lhs", None),
                        _dynamic_attr_8616(next_stmt, "lhs", None),
                        _dynamic_attr_8616(stmt, "rhs", None),
                    )
                    if rhs_changed:
                        new_statements.append(
                            structured_c.CAssignment(
                                _dynamic_attr_8616(third_stmt, "lhs", None),
                                canonicalize_stack_cvar_expr(rewritten_rhs, codegen),
                                codegen=codegen,
                            )
                        )
                        changed = True
                        i += 3
                        continue

                if (
                    callable(match_byte_load_addr_expr)
                    and isinstance(stmt, structured_c.CAssignment)
                    and isinstance(next_stmt, structured_c.CAssignment)
                    and isinstance(third_stmt, structured_c.CAssignment)
                    and isinstance(fourth_stmt, structured_c.CAssignment)
                    and isinstance(_dynamic_attr_8616(stmt, "lhs", None), structured_c.CVariable)
                    and isinstance(_dynamic_attr_8616(next_stmt, "lhs", None), structured_c.CVariable)
                ):
                    low_load_addr = _match_byte_load_addr_for_assignment(
                        _dynamic_attr_8616(stmt, "lhs", None), _dynamic_attr_8616(stmt, "rhs", None)
                    )
                    high_load_addr = _match_byte_load_addr_for_assignment(
                        _dynamic_attr_8616(next_stmt, "lhs", None), _dynamic_attr_8616(next_stmt, "rhs", None)
                    )
                    low_store_addr = match_byte_store_addr_expr(_dynamic_attr_8616(third_stmt, "lhs", None))
                    high_store_addr = match_byte_store_addr_expr(_dynamic_attr_8616(fourth_stmt, "lhs", None))
                    high_store_base = match_shift_right_8_expr(_dynamic_attr_8616(fourth_stmt, "rhs", None))
                    has_addrs = (
                        low_load_addr is not None
                        and high_load_addr is not None
                        and low_store_addr is not None
                        and high_store_addr is not None
                        and high_store_base is not None
                    )
                    load_pair = bool(addr_exprs_are_byte_pair(low_load_addr, high_load_addr, project)) if has_addrs else False
                    store_pair = (
                        bool(addr_exprs_are_byte_pair(low_store_addr, high_store_addr, project)) if has_addrs else False
                    )
                    same_low = _same_expr(low_load_addr, low_store_addr) if has_addrs else False
                    same_high = _same_expr(high_load_addr, high_store_addr) if has_addrs else False
                    same_rhs = _same_expr(high_store_base, _dynamic_attr_8616(third_stmt, "rhs", None)) if has_addrs else False
                    if debug_widening and any(
                        value is not None
                        for value in (low_load_addr, high_load_addr, low_store_addr, high_store_addr, high_store_base)
                    ):
                        _debug(
                            "four_stmt_probe",
                            low_load=_node_kind(low_load_addr),
                            low_rhs=_node_kind(_dynamic_attr_8616(stmt, "rhs", None)),
                            low_rhs_op=_node_op(_dynamic_attr_8616(stmt, "rhs", None)),
                            low_rhs_expr=_node_child_kind(_dynamic_attr_8616(stmt, "rhs", None), "expr"),
                            low_rhs_operand=_node_child_kind(_dynamic_attr_8616(stmt, "rhs", None), "operand"),
                            low_rhs_bits=_node_type_bits(_dynamic_attr_8616(stmt, "rhs", None)),
                            high_load=_node_kind(high_load_addr),
                            high_rhs=_node_kind(_dynamic_attr_8616(next_stmt, "rhs", None)),
                            high_rhs_op=_node_op(_dynamic_attr_8616(next_stmt, "rhs", None)),
                            high_rhs_expr=_node_child_kind(_dynamic_attr_8616(next_stmt, "rhs", None), "expr"),
                            high_rhs_operand=_node_child_kind(_dynamic_attr_8616(next_stmt, "rhs", None), "operand"),
                            high_rhs_bits=_node_type_bits(_dynamic_attr_8616(next_stmt, "rhs", None)),
                            low_store=_node_kind(low_store_addr),
                            high_store=_node_kind(high_store_addr),
                            high_base=_node_kind(high_store_base),
                            load_pair=int(load_pair),
                            store_pair=int(store_pair),
                            same_low=int(same_low),
                            same_high=int(same_high),
                            same_rhs=int(same_rhs),
                        )
                    if has_addrs and load_pair and store_pair and same_low and same_high and same_rhs:
                        loaded_word = _word_lvalue_for_addr(low_load_addr)
                        store_lhs = _word_lvalue_for_addr(low_store_addr)
                        if loaded_word is not None and store_lhs is not None:
                            rewritten_rhs, rhs_changed = _replace_loaded_word_pair_expr(
                                _dynamic_attr_8616(third_stmt, "rhs", None),
                                _dynamic_attr_8616(stmt, "lhs", None),
                                _dynamic_attr_8616(next_stmt, "lhs", None),
                                loaded_word,
                            )
                            if rhs_changed:
                                new_statements.append(
                                    structured_c.CAssignment(
                                        store_lhs,
                                        canonicalize_stack_cvar_expr(rewritten_rhs, codegen),
                                        codegen=codegen,
                                    )
                                )
                                changed = True
                                if nonlocal_changed[0]:
                                    changed = True
                                i += 4
                                continue
                            _debug(
                                "four_stmt_refused",
                                loaded_word=_node_kind(loaded_word),
                                store_lhs=_node_kind(store_lhs),
                                rhs_changed=0,
                            )
                        else:
                            _debug(
                                "four_stmt_no_lvalue",
                                loaded_word=_node_kind(loaded_word),
                                store_lhs=_node_kind(store_lhs),
                            )

                if isinstance(stmt, structured_c.CAssignment) and isinstance(next_stmt, structured_c.CAssignment):
                    replacement = None

                    runtime_word_lhs = _runtime_word_store_lvalue(stmt.lhs, next_stmt.lhs)
                    runtime_word_rhs = match_word_rhs_from_byte_pair(stmt.rhs, next_stmt.rhs, codegen, project)
                    if runtime_word_lhs is not None and runtime_word_rhs is not None:
                        replacement = structured_c.CAssignment(
                            runtime_word_lhs,
                            runtime_word_rhs,
                            codegen=codegen,
                        )

                    if replacement is None and isinstance(stmt.lhs, structured_c.CVariable):
                        matched = _pair_result_8616(match_ss_local_plus_const(next_stmt.lhs, project))
                        if matched is not None:
                            target_cvar, extra_offset = matched
                            rhs_word = match_word_rhs_from_byte_pair(stmt.rhs, next_stmt.rhs, codegen, project)
                            if (
                                extra_offset == 1
                                and isinstance(target_cvar, structured_c.CVariable)
                                and target_cvar is not None
                                and rhs_word is not None
                                and stack_slot_identity_can_join(target_cvar, stmt.lhs)
                            ):
                                replacement_lhs = canonicalize_stack_cvar_expr(stmt.lhs, codegen)
                                rhs_word = canonicalize_stack_cvar_expr(rhs_word, codegen)
                                if promote_direct_stack_cvariable(codegen, replacement_lhs, 2, target_type):
                                    changed = True
                                replacement = structured_c.CAssignment(replacement_lhs, rhs_word, codegen=codegen)

                    if replacement is None:
                        low_addr_expr = match_byte_store_addr_expr(stmt.lhs)
                        high_addr_expr = match_byte_store_addr_expr(next_stmt.lhs)
                        rhs_word = match_word_rhs_from_byte_pair(stmt.rhs, next_stmt.rhs, codegen, project)
                        if (
                            low_addr_expr is not None
                            and high_addr_expr is not None
                            and rhs_word is not None
                            and addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project)
                        ):
                            low_facts = describe_alias_storage(low_addr_expr)
                            high_facts = describe_alias_storage(high_addr_expr)
                            low_class = classify_segmented_addr_expr(low_addr_expr, project)
                            high_class = classify_segmented_addr_expr(high_addr_expr, project)
                            joinable_segment_const_pair = _stable_segment_const_byte_pair(low_class, high_class)
                            joinable_stack_alias_pair = (
                                _is_segmented_access_8616(low_class) and low_class.kind == "stack" and high_class is None
                            )
                            if (
                                (
                                    not _is_alias_storage_facts_8616(low_facts)
                                    or not _is_alias_storage_facts_8616(high_facts)
                                    or
                                    low_facts.identity is None
                                    or high_facts.identity is None
                                    or not low_facts.can_join(high_facts)
                                )
                                and not joinable_segment_const_pair
                                and not joinable_stack_alias_pair
                            ):
                                visit(stmt)
                                new_statements.append(stmt)
                                i += 1
                                continue
                            if _is_segmented_access_8616(low_class) and low_class.kind == "stack":
                                resolved_lhs = resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
                                if resolved_lhs is None:
                                    visit(stmt)
                                    new_statements.append(stmt)
                                    i += 1
                                    continue
                                replacement_lhs = canonicalize_stack_cvar_expr(resolved_lhs, codegen)
                                rhs_word = canonicalize_stack_cvar_expr(rhs_word, codegen)
                                if promote_direct_stack_cvariable(codegen, replacement_lhs, 2, target_type):
                                    changed = True
                                replacement = structured_c.CAssignment(replacement_lhs, rhs_word, codegen=codegen)
                            else:
                                resolved_lhs = resolve_stack_cvar_from_addr_expr(project, codegen, low_addr_expr)
                                replacement = structured_c.CAssignment(
                                    resolved_lhs
                                    if resolved_lhs is not None
                                    else make_word_dereference_from_addr_expr(codegen, project, low_addr_expr),
                                    rhs_word,
                                    codegen=codegen,
                                )

                    if replacement is not None:
                        new_statements.append(replacement)
                        changed = True
                        i += 2
                        continue

                visit(stmt)
                new_statements.append(stmt)
                i += 1

            if changed or new_statements != node.statements:
                node.statements = new_statements

        elif isinstance(node, structured_c.CIfElse):
            for _cond, body in node.condition_and_nodes:
                visit(body)
            if node.else_node is not None:
                visit(node.else_node)
        elif isinstance(node, structured_c.CWhileLoop) or (hasattr(structured_c, "CDoWhileLoop") and isinstance(node, _dynamic_attr_8616(structured_c, "CDoWhileLoop"))):
            visit(_dynamic_attr_8616(node, "condition", None))
            visit(_dynamic_attr_8616(node, "body", None))
        elif hasattr(structured_c, "CForLoop") and isinstance(node, _dynamic_attr_8616(structured_c, "CForLoop")):
            visit(_dynamic_attr_8616(node, "init", None))
            visit(_dynamic_attr_8616(node, "condition", None))
            visit(_dynamic_attr_8616(node, "iteration", None))
            visit(_dynamic_attr_8616(node, "body", None))

    visit(_dynamic_attr_8616(_dynamic_attr_8616(codegen, "cfunc", None), "statements", None))
    return changed
