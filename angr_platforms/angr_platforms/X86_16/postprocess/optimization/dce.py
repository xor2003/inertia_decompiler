"""Layer: Rewrite/Postprocess cleanup.

Responsibility: perform conservative dead-code elimination only after liveness evidence is available.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.

Conservative dead-code elimination.
Only removes plain local/temp assignments proven unread by backward liveness.
Unknown cases are refused and preserved.
"""

from __future__ import annotations

import contextlib
import os
import sys
import typing
from collections.abc import Iterable, Iterator

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFakeVariable,
    CFunctionCall,
    CIndexedVariable,
    CStatements,
    CStructField,
    CTypeCast,
    CUnaryOp,
    CVariable,
    CVariableField,
)
from angr.sim_type import SimStruct
from angr.sim_variable import (
    SimMemoryVariable,
    SimRegisterVariable,
    SimStackVariable,
    SimTemporaryVariable,
    SimVariable,
)

from ...decompiler_postprocess_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from ...lowering.stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616
from .dce_local_array_reads import is_pure_local_array_read_8616
from .dce_noop_conditionals import (
    DceNoopConditionalPruneStats8616,
    prune_explicit_empty_if_else_after_dce_8616,
)
from .dce_purity import PURE_LOCAL_BINARY_OPS_8616, PURE_LOCAL_UNARY_OPS_8616
from .dce_value_identity import assignment_reads_destination_8616, same_local_value_expression_8616
from .dce_walk import (
    DceValuePurity8616,
    _DceWalkContext8616,
    _dynamic_dce_getattr_8616,
    _dynamic_dce_setattr_8616,
    _walk_statements_8616,
)
from .local_declarations import prune_dce_proven_declarations_8616

__all__ = ["_dead_code_elimination_8616"]


def _dead_code_elimination_8616(codegen: object) -> bool:
    """Eliminate only definitely-dead assignments within each statement block.

    Dynamic boundary: this pass traverses third-party angr structured-C nodes
    and mutable codegen compatibility counters; owned Inertia facts must still
    be narrowed to typed contracts before dot access.
    """
    cfunc = _dynamic_dce_getattr_8616(codegen, "cfunc", None)
    if cfunc is None:
        return False
    root = _dynamic_dce_getattr_8616(cfunc, "statements", None)
    if root is None:
        root = cfunc
    if os.environ.get("INERTIA_DEBUG_OPTIMIZATION", "").strip().lower() in {"1", "true", "yes", "on"}:
        root_statements = _dynamic_dce_getattr_8616(root, "statements", None)
        cfunc_statements = _dynamic_dce_getattr_8616(cfunc, "statements", None)
        print(
            "[optimization] dce_root "
            f"cfunc={type(cfunc).__name__} "
            f"cfunc_statements={type(cfunc_statements).__name__ if cfunc_statements is not None else 'None'} "
            f"root={type(root).__name__} "
            f"root_len={len(root_statements) if isinstance(root_statements, list) else 'n/a'}",
            file=sys.stderr,
            flush=True,
        )

    for counter in (
        "dce_candidates",
        "dce_deleted",
        "dce_keep_live_use",
        "dce_keep_side_effect",
        "dce_keep_protected",
        "dce_keep_observable",
        "dce_keep_unknown",
        "dce_duplicate_assignment_candidates",
        "dce_duplicate_assignment_deleted",
        "dce_duplicate_assignment_refused",
        "dce_pure_expression_candidates",
        "dce_pure_expression_deleted",
        "dce_pure_expression_refused",
        "dce_dirty_value_candidates",
        "dce_dirty_value_deleted",
        "dce_dirty_value_refused",
        "dce_dead_memory_read_candidates",
        "dce_dead_memory_read_deleted",
        "dce_dead_memory_read_refused",
        "dce_arg_overwrite_artifact_candidates",
        "dce_arg_overwrite_artifact_deleted",
        "dce_arg_overwrite_artifact_refused",
        "dce_frame_anchor_candidates",
        "dce_frame_anchor_deleted",
        "dce_frame_anchor_refused",
        "dce_overwritten_local_candidates",
        "dce_overwritten_local_deleted",
        "dce_overwritten_local_refused",
        "dce_boolean_carrier_candidates",
        "dce_boolean_carrier_deleted",
        "dce_boolean_carrier_refused",
        "dce_call_cleanup_carrier_candidates",
        "dce_call_cleanup_carrier_deleted",
        "dce_call_cleanup_carrier_refused",
    ):
        if not isinstance(_dynamic_dce_getattr_8616(codegen, counter, None), int):
            _dynamic_dce_setattr_8616(codegen, counter, 0)

    def _bump_codegen_counter_8616(name: str) -> None:
        """Increment a dynamic codegen diagnostic counter."""
        # Dynamic codegen compatibility boundary.
        _dynamic_dce_setattr_8616(codegen, name, int(_dynamic_dce_getattr_8616(codegen, name, 0)) + 1)

    changed = False
    pruned_decl_keys: set[tuple[str, int | str]] = set()
    pruned_decl_names: set[str] = set()

    def _safe_attr(node: object, attr: str, default: object | None = None) -> object | None:
        try:
            return typing.cast(object | None, _dynamic_dce_getattr_8616(node, attr, default))
        except (TypeError, ValueError):
            return default

    def _var_key(node: CVariable) -> tuple[str, int | str]:
        """Return a liveness key in the Alias-owned machine-BP coordinate."""
        var = _dynamic_dce_getattr_8616(node, "variable", None)
        if var is None:
            return ("node", id(node))
        if isinstance(var, SimStackVariable) and _dynamic_dce_getattr_8616(var, "base", None) == "bp":
            offset = machine_bp_offset_for_stack_variable_8616(codegen, var)
            if isinstance(offset, int):
                return ("stack", int(offset))
        name = _dynamic_dce_getattr_8616(var, "name", None)
        if isinstance(name, str) and name:
            return ("name", name)
        node_name = _dynamic_dce_getattr_8616(node, "name", None)
        if isinstance(node_name, str) and node_name:
            return ("name", node_name)
        ident = _dynamic_dce_getattr_8616(var, "ident", None)
        if isinstance(ident, str) and ident:
            return ("ident", ident)
        return ("var", id(var))

    def _dirty_key(node: object) -> tuple[str, int | str] | None:
        if type(node).__name__ != "CDirtyExpression":
            return None
        dirty = _safe_attr(node, "dirty", None)
        dirty_text = ""
        with contextlib.suppress(Exception):
            dirty_text = str(dirty)
        if dirty_text and " object at " not in dirty_text and not dirty_text.startswith("namespace("):
            return ("dirty_text", dirty_text)
        dirty_name = _safe_attr(dirty, "name", None)
        if isinstance(dirty_name, str) and dirty_name:
            return ("dirty_name", dirty_name)
        dirty_varid = _safe_attr(dirty, "varid", None)
        if isinstance(dirty_varid, (int, str)):
            return ("dirty_varid", dirty_varid)
        dirty_idx = _safe_attr(dirty, "idx", None)
        if isinstance(dirty_idx, (int, str)):
            return ("dirty", dirty_idx)
        dirty_oident = _safe_attr(dirty, "oident", None)
        if isinstance(dirty_oident, (int, str)):
            return ("dirty_oident", dirty_oident)
        expr_idx = _safe_attr(node, "idx", None)
        if isinstance(expr_idx, (int, str)):
            return ("dirty_expr", expr_idx)
        return None

    def _dirty_has_storage_provenance_8616(node: object) -> bool:
        if type(node).__name__ != "CDirtyExpression":
            return False
        dirty = _safe_attr(node, "dirty", None)
        for attr in (
            "reg",
            "reg_offset",
            "stack_offset",
            "parameter_reg_offset",
            "parameter_stack_offset",
        ):
            value = _safe_attr(dirty, attr, None)
            if isinstance(value, int):
                return True
        return False

    def _dirty_is_storage_free_temp_8616(node: object) -> bool:
        return (
            type(node).__name__ == "CDirtyExpression"
            and bool(_dynamic_dce_getattr_8616(codegen, "_inertia_dce_allow_storage_free_dirty_8616", False))
            and not _dirty_has_storage_provenance_8616(node)
        )

    def _dirty_is_storage_free_carrier_8616(node: object) -> bool:
        return type(node).__name__ == "CDirtyExpression" and not _dirty_has_storage_provenance_8616(node)

    def _dirty_temp_cleanup_mode_8616(node: object) -> bool:
        return type(node).__name__ == "CDirtyExpression" and bool(
            # Dynamic codegen compatibility boundary.
            _dynamic_dce_getattr_8616(codegen, "_inertia_dce_allow_storage_free_dirty_8616", False)
        )

    def _node_key(node: object) -> tuple[str, int | str] | None:
        if isinstance(node, CVariable):
            return _var_key(node)
        return _dirty_key(node)

    def _iter_with_root(node: object) -> Iterator[object]:
        if node is not None:
            yield node
        yield from _iter_c_nodes_deep_8616(node)

    def _lhs_variable_8616(lhs: object) -> CVariable | None:
        if isinstance(lhs, CVariable):
            return lhs
        for child in _iter_c_nodes_deep_8616(lhs):
            if isinstance(child, CVariable):
                return child
        variable = _dynamic_dce_getattr_8616(lhs, "variable", None)
        if isinstance(variable, SimVariable):
            try:
                return CVariable(variable, variable, None)
            except Exception:
                return None
        return None

    def _var_name(node: CVariable) -> str:
        var = _dynamic_dce_getattr_8616(node, "variable", None)
        name = _dynamic_dce_getattr_8616(var, "name", None)
        if isinstance(name, str) and name:
            return name
        node_name = _dynamic_dce_getattr_8616(node, "name", None)
        return node_name if isinstance(node_name, str) else ""

    def _is_observable_lvalue(lhs: object) -> bool:
        if isinstance(lhs, (CUnaryOp, CStructField, CBinaryOp, CIndexedVariable, CVariableField)):
            return True
        if isinstance(lhs, CFunctionCall):
            return True
        if isinstance(lhs, CVariable):
            var = _dynamic_dce_getattr_8616(lhs, "variable", None)
            if isinstance(var, (SimStackVariable, SimRegisterVariable)):
                return False
            if isinstance(var, SimMemoryVariable):
                return True
            region = _dynamic_dce_getattr_8616(var, "region", None)
            if isinstance(region, str) and region.lower() in {"global", "argument", "arg"}:
                return True
        return False

    def _rhs_has_side_effects(rhs: object) -> bool:
        if rhs is None:
            return False
        for node in _iter_c_nodes_deep_8616(rhs):
            if isinstance(node, CFunctionCall) and not _is_pure_generated_helper_call_8616(node):
                return True
        return False

    def _call_name_8616(call: CFunctionCall) -> str | None:
        target = _dynamic_dce_getattr_8616(call, "callee_target", None)
        if isinstance(target, str) and target:
            return target
        target_name = _dynamic_dce_getattr_8616(target, "name", None)
        if isinstance(target_name, str) and target_name:
            return target_name
        callee = _dynamic_dce_getattr_8616(call, "callee", None)
        if isinstance(callee, str) and callee:
            return callee
        callee = _dynamic_dce_getattr_8616(call, "callee_func", None)
        if isinstance(callee, str) and callee:
            return callee
        name = _dynamic_dce_getattr_8616(callee, "name", None)
        return name if isinstance(name, str) and name else None

    def _is_pure_address_helper_call_8616(call: CFunctionCall) -> bool:
        return _call_name_8616(call) in {"MK_FP", "SEG_PTR"}

    def _is_pure_memory_read_helper_call_8616(call: CFunctionCall) -> bool:
        return _call_name_8616(call) in {"MEM_U8", "MEM_U16", "MEM_U32", "SEG_U8", "SEG_U16", "SEG_U32"}

    def _is_pure_generated_helper_call_8616(call: CFunctionCall) -> bool:
        return _is_pure_address_helper_call_8616(call) or _is_pure_memory_read_helper_call_8616(call)

    def _standalone_expression_is_definitely_dead_8616(stmt: object) -> bool:
        if not isinstance(stmt, CUnaryOp) or _dynamic_dce_getattr_8616(stmt, "op", None) != "Dereference":
            return False

        saw_pure_address_helper = False
        for node in _iter_with_root(stmt):
            if isinstance(node, CAssignment):
                return False
            if isinstance(node, CFunctionCall):
                if not _is_pure_address_helper_call_8616(node):
                    return False
                saw_pure_address_helper = True
                continue
            if isinstance(node, CUnaryOp):
                op = _dynamic_dce_getattr_8616(node, "op", None)
                if node is stmt and op == "Dereference":
                    continue
                if op in {"Reference", "AddressOf", "Neg", "Not", "BitNot"}:
                    continue
                return False
            if isinstance(node, CBinaryOp) and _dynamic_dce_getattr_8616(node, "op", None) not in {
                "Add",
                "Sub",
                "Mul",
                "Mull",
                "Shl",
                "Shr",
                "And",
                "Or",
                "Xor",
            }:
                return False
        return saw_pure_address_helper

    def _standalone_expression_payload_8616(stmt: object) -> object:
        if isinstance(stmt, CExpressionStatement):
            return _dynamic_dce_getattr_8616(stmt, "expr", None)
        return stmt

    def _is_structured_or_control_statement_8616(stmt: object) -> bool:
        if type(stmt).__name__ in {
            "CBreak",
            "CContinue",
            "CForLoop",
            "CGoto",
            "CIfBreak",
            "CIfElse",
            "CReturn",
            "CSwitchCase",
            "CWhileLoop",
        }:
            return True
        for attr in (
            "body",
            "condition",
            "condition_and_nodes",
            "cond",
            "default",
            "else_node",
            "iftrue",
            "iffalse",
            "ret_exprs",
            "retval",
            "statements",
            "true_node",
            "false_node",
        ):
            # Dynamic angr/codegen structured-C compatibility boundary.
            if _dynamic_dce_getattr_8616(stmt, attr, None) is not None:
                return True
        return False

    def _expr_is_discardable_dead_value_8616(expr: object) -> bool:
        """True when evaluating expr has no observable effect if its value is unused."""
        if expr is None:
            return False
        if (
            isinstance(expr, CVariableField)
            and _expr_value_purity_8616(expr) is DceValuePurity8616.GLOBAL_MEMORY_READ
        ):
            return True
        saw_discardable_artifact = False
        for node in _iter_with_root(expr):
            if isinstance(node, CAssignment):
                return False
            if isinstance(node, CFunctionCall):
                if not _is_pure_generated_helper_call_8616(node):
                    return False
                saw_discardable_artifact = True
                continue
            if isinstance(node, CStructField):
                return False
            if isinstance(node, CFakeVariable):
                return False
            if type(node).__name__ == "CDirtyExpression":
                if not (
                    _dirty_is_storage_free_temp_8616(node)
                    or bool(_dynamic_dce_getattr_8616(codegen, "_inertia_dce_allow_dirty_value_reads_8616", False))
                ):
                    return False
                saw_discardable_artifact = True
                continue
            if isinstance(node, CTypeCast):
                continue
            if isinstance(node, CUnaryOp):
                if _dynamic_dce_getattr_8616(node, "op", None) in (
                    PURE_LOCAL_UNARY_OPS_8616 | {"Dereference", "Reference", "AddressOf"}
                ):
                    if _dynamic_dce_getattr_8616(node, "op", None) == "Dereference":
                        saw_discardable_artifact = True
                    continue
                return False
            if (
                isinstance(node, CBinaryOp)
                and _dynamic_dce_getattr_8616(node, "op", None) not in PURE_LOCAL_BINARY_OPS_8616
            ):
                return False
        return saw_discardable_artifact

    def _is_plain_local_lvalue_8616(lhs: object) -> bool:
        if not isinstance(lhs, CVariable):
            return False
        var = _dynamic_dce_getattr_8616(lhs, "variable", None)
        if isinstance(var, SimStackVariable):
            return True
        return bool(isinstance(var, SimRegisterVariable))

    def _is_frame_anchor_stack_lvalue_8616(lhs: object) -> bool:
        if not isinstance(lhs, CVariable):
            return False
        var = lhs.variable
        return isinstance(var, SimStackVariable) and var.base == "bp" and var.offset == 0

    def _expr_is_pure_local_value_8616(expr: object) -> bool:
        if expr is None or _rhs_has_side_effects(expr):
            return False
        for node in _iter_with_root(expr):
            if isinstance(node, CFunctionCall):
                return False
            if isinstance(node, CStructField):
                return False
            if isinstance(node, CFakeVariable):
                return False
            if type(node).__name__ == "CDirtyExpression":
                if not (
                    _dirty_is_storage_free_temp_8616(node)
                    or bool(_dynamic_dce_getattr_8616(codegen, "_inertia_dce_allow_dirty_value_reads_8616", False))
                ):
                    return False
                continue
            if isinstance(node, CUnaryOp) and _dynamic_dce_getattr_8616(node, "op", None) in {
                "Dereference",
                "Reference",
                "AddressOf",
            }:
                return False
            if isinstance(node, CVariable):
                var = _dynamic_dce_getattr_8616(node, "variable", None)
                if isinstance(var, (SimStackVariable, SimRegisterVariable, SimTemporaryVariable)):
                    continue
                if isinstance(var, SimMemoryVariable):
                    return False
        return True

    def _merge_value_purity_8616(*items: DceValuePurity8616) -> DceValuePurity8616:
        if any(item is DceValuePurity8616.UNKNOWN for item in items):
            return DceValuePurity8616.UNKNOWN
        if any(item is DceValuePurity8616.GLOBAL_MEMORY_READ for item in items):
            return DceValuePurity8616.GLOBAL_MEMORY_READ
        return DceValuePurity8616.LOCAL_VALUE

    def _is_direct_memory_variable_8616(node: object) -> bool:
        if not isinstance(node, CVariable):
            return False
        return isinstance(_dynamic_dce_getattr_8616(node, "variable", None), SimMemoryVariable)

    def _is_global_indexed_read_8616(node: object) -> bool:
        if not isinstance(node, CIndexedVariable):
            return False
        base = _dynamic_dce_getattr_8616(node, "variable", None)
        if not _is_direct_memory_variable_8616(base):
            return False
        index = _dynamic_dce_getattr_8616(node, "index", None)
        return _expr_value_purity_8616(index) is DceValuePurity8616.LOCAL_VALUE

    def _address_expr_is_pure_global_read_address_8616(expr: object) -> bool:
        if expr is None:
            return False
        if isinstance(expr, CTypeCast):
            return _address_expr_is_pure_global_read_address_8616(_dynamic_dce_getattr_8616(expr, "expr", None))
        if isinstance(expr, CConstant):
            return True
        if isinstance(expr, CVariable):
            var = _dynamic_dce_getattr_8616(expr, "variable", None)
            return isinstance(var, (SimStackVariable, SimRegisterVariable))
        if isinstance(expr, CIndexedVariable):
            return _is_global_indexed_read_8616(expr)
        if isinstance(expr, CFunctionCall):
            return _is_pure_address_helper_call_8616(expr)
        if isinstance(expr, CUnaryOp):
            op = _dynamic_dce_getattr_8616(expr, "op", None)
            operand = _dynamic_dce_getattr_8616(expr, "operand", None)
            if op in {"Reference", "AddressOf"}:
                return _is_direct_memory_variable_8616(operand) or _is_global_indexed_read_8616(operand)
            if op in {"Neg", "Not", "BitNot"}:
                return _address_expr_is_pure_global_read_address_8616(operand)
            return False
        if isinstance(expr, CBinaryOp) and _dynamic_dce_getattr_8616(expr, "op", None) in {
            "Add",
            "Sub",
            "Mul", "Mull",
            "Shl",
            "Shr",
            "And",
            "Or",
            "Xor",
        }:
            return _address_expr_is_pure_global_read_address_8616(
                _dynamic_dce_getattr_8616(expr, "lhs", None)
            ) and _address_expr_is_pure_global_read_address_8616(_dynamic_dce_getattr_8616(expr, "rhs", None))
        return False

    def _address_expr_has_global_read_anchor_8616(expr: object) -> bool:
        if expr is None:
            return False
        if isinstance(expr, CTypeCast):
            return _address_expr_has_global_read_anchor_8616(_dynamic_dce_getattr_8616(expr, "expr", None))
        if isinstance(expr, CIndexedVariable):
            return _is_global_indexed_read_8616(expr)
        if isinstance(expr, CFunctionCall):
            return _is_pure_address_helper_call_8616(expr)
        if isinstance(expr, CUnaryOp):
            op = _dynamic_dce_getattr_8616(expr, "op", None)
            operand = _dynamic_dce_getattr_8616(expr, "operand", None)
            if op in {"Reference", "AddressOf"}:
                return _is_direct_memory_variable_8616(operand) or _is_global_indexed_read_8616(operand)
            if op in {"Neg", "Not", "BitNot"}:
                return _address_expr_has_global_read_anchor_8616(operand)
            return False
        if isinstance(expr, CBinaryOp):
            return _address_expr_has_global_read_anchor_8616(
                _dynamic_dce_getattr_8616(expr, "lhs", None)
            ) or _address_expr_has_global_read_anchor_8616(_dynamic_dce_getattr_8616(expr, "rhs", None))
        return False

    def _expr_value_purity_8616(
        expr: object,
        visiting: set[int] | None = None,
    ) -> DceValuePurity8616:
        """Classify RHS purity, refusing cyclic C-AST expression graphs."""
        if expr is None or _rhs_has_side_effects(expr):
            return DceValuePurity8616.UNKNOWN
        active = visiting if visiting is not None else set()
        marker = id(expr)
        if marker in active:
            return DceValuePurity8616.UNKNOWN
        active.add(marker)
        try:
            if isinstance(expr, CConstant):
                return DceValuePurity8616.LOCAL_VALUE
            if type(expr).__name__ == "CDirtyExpression":
                return (
                    DceValuePurity8616.LOCAL_VALUE
                    if _dirty_is_storage_free_temp_8616(expr)
                    or bool(_dynamic_dce_getattr_8616(codegen, "_inertia_dce_allow_dirty_value_reads_8616", False))
                    else DceValuePurity8616.UNKNOWN
                )
            if isinstance(expr, CTypeCast):
                return _expr_value_purity_8616(_dynamic_dce_getattr_8616(expr, "expr", None), active)
            if isinstance(expr, CVariable):
                var = _dynamic_dce_getattr_8616(expr, "variable", None)
                if isinstance(var, (SimStackVariable, SimRegisterVariable, SimTemporaryVariable)):
                    return DceValuePurity8616.LOCAL_VALUE
                if isinstance(var, SimMemoryVariable):
                    return DceValuePurity8616.GLOBAL_MEMORY_READ
                return DceValuePurity8616.UNKNOWN
            if isinstance(expr, CIndexedVariable):
                return (
                    DceValuePurity8616.GLOBAL_MEMORY_READ
                    if _is_global_indexed_read_8616(expr)
                    else DceValuePurity8616.UNKNOWN
                )
            if isinstance(expr, CVariableField):
                base_purity = _expr_value_purity_8616(
                    _dynamic_dce_getattr_8616(expr, "variable", None),
                    active,
                )
                # Reading an already-typed aggregate value is not pointer dereferencing.
                local_value_projection = (
                    base_purity is DceValuePurity8616.LOCAL_VALUE
                    and not expr.var_is_ptr and isinstance(expr.variable.type, SimStruct)
                )
                if local_value_projection:
                    return DceValuePurity8616.LOCAL_VALUE
                return (
                    DceValuePurity8616.GLOBAL_MEMORY_READ
                    if base_purity is DceValuePurity8616.GLOBAL_MEMORY_READ
                    else DceValuePurity8616.UNKNOWN
                )
            if isinstance(expr, CFunctionCall):
                if _is_pure_address_helper_call_8616(expr):
                    return DceValuePurity8616.LOCAL_VALUE
                if _is_pure_memory_read_helper_call_8616(expr):
                    return DceValuePurity8616.GLOBAL_MEMORY_READ
                return DceValuePurity8616.UNKNOWN
            if isinstance(expr, CUnaryOp):
                op = _dynamic_dce_getattr_8616(expr, "op", None)
                operand = _dynamic_dce_getattr_8616(expr, "operand", None)
                if op == "Dereference":
                    if is_pure_local_array_read_8616(expr):
                        return DceValuePurity8616.LOCAL_VALUE
                    return (
                        DceValuePurity8616.GLOBAL_MEMORY_READ
                        if _address_expr_is_pure_global_read_address_8616(operand)
                        and _address_expr_has_global_read_anchor_8616(operand)
                        else DceValuePurity8616.UNKNOWN
                    )
                if op in {"Reference", "AddressOf"}:
                    return (
                        DceValuePurity8616.LOCAL_VALUE
                        if _address_expr_is_pure_global_read_address_8616(expr)
                        else DceValuePurity8616.UNKNOWN
                    )
                if op in PURE_LOCAL_UNARY_OPS_8616:
                    return _expr_value_purity_8616(operand, active)
                return DceValuePurity8616.UNKNOWN
            if (
                isinstance(expr, CBinaryOp)
                and _dynamic_dce_getattr_8616(expr, "op", None) in PURE_LOCAL_BINARY_OPS_8616
            ):
                return _merge_value_purity_8616(
                    _expr_value_purity_8616(_dynamic_dce_getattr_8616(expr, "lhs", None), active),
                    _expr_value_purity_8616(_dynamic_dce_getattr_8616(expr, "rhs", None), active),
                )
            return DceValuePurity8616.UNKNOWN
        finally:
            active.remove(marker)

    def _expr_is_discardable_value_8616(expr: object) -> bool:
        return _expr_value_purity_8616(expr) in {
            DceValuePurity8616.LOCAL_VALUE,
            DceValuePurity8616.GLOBAL_MEMORY_READ,
        }

    def _expr_contains_memory_read_shape_8616(expr: object) -> bool:
        for node in _iter_with_root(expr):
            if isinstance(node, CUnaryOp) and _dynamic_dce_getattr_8616(node, "op", None) == "Dereference":
                return True
            if isinstance(node, CIndexedVariable):
                return True
            if isinstance(node, CFunctionCall) and _is_pure_memory_read_helper_call_8616(node):
                return True
            if _is_direct_memory_variable_8616(node):
                return True
        return False

    def _rhs_evaluation_is_proven_unobservable_8616(expr: object) -> bool:
        """True when evaluating an overwritten RHS cannot affect program state."""
        if expr is None or _rhs_has_side_effects(expr):
            return False
        if _expr_contains_memory_read_shape_8616(expr):
            return False
        for node in _iter_with_root(expr):
            if isinstance(node, CAssignment):
                return False
            if isinstance(node, CFunctionCall) and not _is_pure_address_helper_call_8616(node):
                return False
            if isinstance(node, CStructField):
                return False
            if isinstance(node, CIndexedVariable):
                return False
            if isinstance(node, CFakeVariable):
                continue
            if type(node).__name__ == "CDirtyExpression":
                continue
            if isinstance(node, CVariable):
                var = node.variable
                if isinstance(var, SimMemoryVariable):
                    return False
                continue
            if isinstance(node, CTypeCast):
                continue
            if isinstance(node, CUnaryOp):
                if node.op in (PURE_LOCAL_UNARY_OPS_8616 | {"Reference", "AddressOf"}):
                    continue
                return False
            if isinstance(node, CBinaryOp) and node.op not in PURE_LOCAL_BINARY_OPS_8616:
                return False
        return True

    def _dirty_lhs_delete_proven_8616(lhs: object, rhs: object) -> bool:
        if _dirty_is_storage_free_temp_8616(lhs):
            return (
                _expr_is_discardable_dead_value_8616(rhs)
                or _rhs_is_pure_stack_base_carrier_8616(rhs)
                or _expr_is_pure_local_value_8616(rhs)
            )
        return (
            _dirty_has_storage_provenance_8616(lhs)
            and _expr_is_discardable_dead_value_8616(rhs)
            and _expr_contains_memory_read_shape_8616(rhs)
        )

    def _transparent_empty_8616(stmt: object) -> bool:
        if not isinstance(stmt, CStatements):
            return False
        return all(_transparent_empty_8616(child) for child in list(_dynamic_dce_getattr_8616(stmt, "statements", ()) or ()))

    def _transparent_single_assignment_8616(stmt: object) -> CAssignment | None:
        if isinstance(stmt, CAssignment):
            return stmt
        if not isinstance(stmt, CStatements):
            return None
        # Dynamic angr/codegen structured-C compatibility boundary.
        nested: list[object] = list(_dynamic_dce_getattr_8616(stmt, "statements", ()) or ())
        if len(nested) != 1:
            return None
        return _transparent_single_assignment_8616(nested[0])

    def _transparent_first_assignment_8616(stmt: object) -> CAssignment | None:
        if isinstance(stmt, CAssignment):
            return stmt
        if not isinstance(stmt, CStatements):
            return None
        for child in list(_dynamic_dce_getattr_8616(stmt, "statements", ()) or ()):
            if _transparent_empty_8616(child):
                continue
            return _transparent_first_assignment_8616(child)
        return None

    def _transparent_last_assignment_8616(stmt: object) -> CAssignment | None:
        if isinstance(stmt, CAssignment):
            return stmt
        if not isinstance(stmt, CStatements):
            return None
        for child in reversed(list(_dynamic_dce_getattr_8616(stmt, "statements", ()) or ())):
            if _transparent_empty_8616(child):
                continue
            return _transparent_last_assignment_8616(child)
        return None

    def _duplicate_assignment_pair_is_definitely_dead_8616(
        first_assignment: object,
        second_assignment: object,
    ) -> bool:
        if not isinstance(first_assignment, CAssignment) or not isinstance(second_assignment, CAssignment):
            return False
        if not same_local_value_expression_8616(first_assignment.lhs, second_assignment.lhs):
            return False
        if not same_local_value_expression_8616(first_assignment.rhs, second_assignment.rhs):
            return False
        lhs = _dynamic_dce_getattr_8616(second_assignment, "lhs", None)
        rhs = _dynamic_dce_getattr_8616(second_assignment, "rhs", None)
        return (
            _is_plain_local_lvalue_8616(lhs)
            and _expr_is_pure_local_value_8616(rhs)
            and not assignment_reads_destination_8616(lhs, rhs)
        )

    def _adjacent_duplicate_assignment_is_definitely_dead_8616(first: object, second: object) -> bool:
        first_assignment = _transparent_last_assignment_8616(first)
        second_assignment = _transparent_first_assignment_8616(second)
        return _duplicate_assignment_pair_is_definitely_dead_8616(first_assignment, second_assignment)

    def _remove_first_transparent_assignment_8616(
        stmt: object,
        assignment: CAssignment,
    ) -> tuple[object | None, bool]:
        if isinstance(stmt, CAssignment):
            if stmt is assignment:
                return None, True
            return stmt, False
        if not isinstance(stmt, CStatements):
            return stmt, False

        nested = list(_dynamic_dce_getattr_8616(stmt, "statements", ()) or ())
        for index, child in enumerate(nested):
            if _transparent_empty_8616(child):
                continue
            first_assignment = _transparent_first_assignment_8616(child)
            if first_assignment is None:
                return stmt, False
            new_child, removed = _remove_first_transparent_assignment_8616(child, assignment)
            if not removed:
                return stmt, False
            if new_child is None or _transparent_empty_8616(new_child):
                del nested[index]
            else:
                nested = [new_child if nested_index == index else nested_item for nested_index, nested_item in enumerate(nested)]
            stmt.statements = nested
            if not nested:
                return None, True
            return stmt, True
        return stmt, False

    def _prune_adjacent_duplicate_assignments_8616(statements: object) -> bool:
        nonlocal changed
        stmts = list(_dynamic_dce_getattr_8616(statements, "statements", ()) or ())
        if len(stmts) < 2:
            return False
        new_stmts: list[object] = []
        block_changed = False
        i = 0
        while i < len(stmts):
            stmt = stmts[i]
            next_stmt = stmts[i + 1] if i + 1 < len(stmts) else None
            stmt_assignment = _transparent_last_assignment_8616(stmt)
            next_assignment = _transparent_first_assignment_8616(next_stmt)
            if isinstance(stmt_assignment, CAssignment) and isinstance(next_assignment, CAssignment):
                same_assignment = _same_c_expression_8616(
                    _dynamic_dce_getattr_8616(stmt_assignment, "lhs", None),
                    _dynamic_dce_getattr_8616(next_assignment, "lhs", None),
                ) and _same_c_expression_8616(
                    _dynamic_dce_getattr_8616(stmt_assignment, "rhs", None),
                    _dynamic_dce_getattr_8616(next_assignment, "rhs", None),
                )
                if same_assignment:
                    typing.cast(typing.Any, codegen).dce_duplicate_assignment_candidates = int(_dynamic_dce_getattr_8616(codegen, "dce_duplicate_assignment_candidates", 0)) + 1
                    if _adjacent_duplicate_assignment_is_definitely_dead_8616(stmt, next_stmt):
                        pruned_next_stmt, removed = _remove_first_transparent_assignment_8616(
                            next_stmt,
                            next_assignment,
                        )
                        if not removed:
                            typing.cast(typing.Any, codegen).dce_duplicate_assignment_refused = int(_dynamic_dce_getattr_8616(codegen, "dce_duplicate_assignment_refused", 0)) + 1
                            new_stmts.append(stmt)
                            i += 1
                            continue
                        typing.cast(typing.Any, codegen).dce_candidates = int(_dynamic_dce_getattr_8616(codegen, "dce_candidates", 0)) + 1
                        typing.cast(typing.Any, codegen).dce_deleted = int(_dynamic_dce_getattr_8616(codegen, "dce_deleted", 0)) + 1
                        typing.cast(typing.Any, codegen).dce_duplicate_assignment_deleted = int(_dynamic_dce_getattr_8616(codegen, "dce_duplicate_assignment_deleted", 0)) + 1
                        new_stmts.append(stmt)
                        if pruned_next_stmt is not None:
                            new_stmts.append(pruned_next_stmt)
                        changed = True
                        block_changed = True
                        i += 2
                        continue
                    typing.cast(typing.Any, codegen).dce_duplicate_assignment_refused = int(_dynamic_dce_getattr_8616(codegen, "dce_duplicate_assignment_refused", 0)) + 1
            new_stmts.append(stmt)
            i += 1
        if block_changed:
            # Dynamic angr/codegen statement-block compatibility boundary.
            typing.cast(typing.Any, statements).statements = new_stmts
        return block_changed

    def _rhs_is_pure_stack_base_carrier_8616(rhs: object) -> bool:
        if rhs is None or _rhs_has_side_effects(rhs):
            return False
        saw_stack_base = isinstance(rhs, CFakeVariable) and _dynamic_dce_getattr_8616(rhs, "name", None) == "stack_base"
        for node in _iter_with_root(rhs):
            if isinstance(node, CFakeVariable) and _dynamic_dce_getattr_8616(node, "name", None) == "stack_base":
                saw_stack_base = True
                continue
            if isinstance(node, CFunctionCall):
                return False
            if isinstance(node, CUnaryOp) and _dynamic_dce_getattr_8616(node, "op", None) not in {"Reference", "AddressOf"}:
                return False
            if isinstance(node, CBinaryOp) and _dynamic_dce_getattr_8616(node, "op", None) not in {"Add", "Sub"}:
                return False
        return saw_stack_base

    def _callsite_materialization_complete_or_no_calls_8616() -> bool:
        if hasattr(codegen, "_inertia_callsite_materialization_stats"):
            try:
                from ...callsite_stack_metadata import _callsite_materialization_complete_8616

                return bool(_callsite_materialization_complete_8616(codegen))
            except Exception:
                return False
        for node in _iter_c_nodes_deep_8616(root):
            if isinstance(node, CFunctionCall) and not _is_pure_generated_helper_call_8616(node):
                return False
        return True

    def _callsite_materialization_proven_complete_8616() -> bool:
        if not hasattr(codegen, "_inertia_callsite_materialization_stats"):
            return False
        try:
            from ...callsite_stack_metadata import _callsite_materialization_complete_8616

            return bool(_callsite_materialization_complete_8616(codegen))
        except Exception:
            return False

    def _debug_node_shape_8616(node: object) -> str:
        def _expr_shape(expr: object, depth: int = 0) -> str:
            if expr is None:
                return "None"
            name = type(expr).__name__
            if depth >= 2:
                return name
            if isinstance(expr, CBinaryOp):
                return (
                    f"{name}:{expr.op}("
                    f"{_expr_shape(expr.lhs, depth + 1)},"
                    f"{_expr_shape(expr.rhs, depth + 1)})"
                )
            if isinstance(expr, CUnaryOp):
                return f"{name}:{expr.op}({_expr_shape(expr.operand, depth + 1)})"
            if isinstance(expr, CFunctionCall):
                return f"{name}:{_call_name_8616(expr)}"
            return name

        parts = [type(node).__name__]
        for attr in (
            "condition",
            "cond",
            "expr",
            "body",
            "else_node",
            "iftrue",
            "iffalse",
            "true_node",
            "false_node",
        ):
            # Dynamic angr/codegen structured-C compatibility boundary.
            child = _dynamic_dce_getattr_8616(node, attr, None)
            if child is not None:
                parts.append(f"{attr}={type(child).__name__}")
        # Dynamic angr/codegen structured-C compatibility boundary.
        statements = _dynamic_dce_getattr_8616(node, "statements", None)
        if statements is not None:
            items = list(statements or ())
            parts.append(
                "statements=["
                + ",".join(type(item).__name__ for item in items[:8])
                + (",..." if len(items) > 8 else "")
                + "]"
            )
        # Dynamic angr/codegen structured-C compatibility boundary.
        pairs = _dynamic_dce_getattr_8616(node, "condition_and_nodes", None)
        if pairs:
            pair_shapes = []
            for pair in tuple(pairs)[:4]:
                if not isinstance(pair, (tuple, list)) or len(pair) < 2:
                    pair_shapes.append(type(pair).__name__)
                    continue
                cond, body = pair[0], pair[1]
                pair_shapes.append(f"{_expr_shape(cond)}->{type(body).__name__}")
            parts.append("condition_and_nodes=[" + ",".join(pair_shapes) + "]")
        return " ".join(parts)

    def _iter_switch_case_bodies_8616(cases: object) -> Iterator[object]:
        if isinstance(cases, dict):
            yield from cases.values()
            return
        case_items = tuple(cases) if isinstance(cases, Iterable) else ()
        for item in case_items:
            if isinstance(item, tuple):
                if len(item) >= 2:
                    yield item[1]
                continue
            yield item

    def _iter_statement_blocks(root: object) -> Iterator[object]:
        seen: set[int] = set()
        stack = [root]
        while stack:
            node = stack.pop()
            if node is None:
                continue
            node_id = id(node)
            if node_id in seen:
                continue
            seen.add(node_id)
            if hasattr(node, "statements"):
                yield node
                for stmt in list(_dynamic_dce_getattr_8616(node, "statements", ()) or ()):
                    stack.append(stmt)  # noqa: PERF402
            for attr in (
                "condition",
                "cond",
                "body",
                "else_node",
                "iftrue",
                "iffalse",
                "true_node",
                "false_node",
                "expr",
                "retval",
            ):
                child = _dynamic_dce_getattr_8616(node, attr, None)
                if child is not None:
                    stack.append(child)
            for pair in _dynamic_dce_getattr_8616(node, "condition_and_nodes", ()) or ():
                if len(pair) >= 2:
                    stack.append(pair[0])
                    stack.append(pair[1])
            cases = _dynamic_dce_getattr_8616(node, "cases", None)
            stack.extend(_iter_switch_case_bodies_8616(cases))
            default = _dynamic_dce_getattr_8616(node, "default", None)
            if default is not None:
                stack.append(default)

    def _collect_stmt_reads(stmt: object) -> set[tuple[str, int | str]]:
        reads: set[tuple[str, int | str]] = set()

        def _collect_expr(expr: object) -> None:
            for node in _iter_with_root(expr):
                key = _node_key(node)
                if key is not None:
                    reads.add(key)

        if isinstance(stmt, CAssignment):
            rhs = _dynamic_dce_getattr_8616(stmt, "rhs", None)
            _collect_expr(rhs)
            lhs = _dynamic_dce_getattr_8616(stmt, "lhs", None)
            if (
                (isinstance(lhs, CUnaryOp)
                and _dynamic_dce_getattr_8616(lhs, "op", None) in {"Dereference", "Reference"})
                or isinstance(lhs, (CFunctionCall, CIndexedVariable, CStructField, CTypeCast, CVariableField))
            ):
                _collect_expr(lhs)
            return reads

        condition_roots = []
        for attr in ("condition", "cond", "expr", "retval"):
            child = _dynamic_dce_getattr_8616(stmt, attr, None)
            if child is not None:
                condition_roots.append(child)
        condition_and_nodes = _dynamic_dce_getattr_8616(stmt, "condition_and_nodes", None)
        if condition_and_nodes:
            for pair in condition_and_nodes:
                if len(pair) >= 1:
                    condition_roots.append(pair[0])
        if condition_roots:
            for child in condition_roots:
                _collect_expr(child)
            return reads

        # Structured containers own child statement blocks; their parent block
        # only semantically reads the container guard. Counting the whole child
        # body here creates fake "outside" uses for nested dead assignments.
        for attr in (
            "statements",
            "body",
            "else_node",
            "iftrue",
            "iffalse",
            "true_node",
            "false_node",
            "cases",
            "default",
        ):
            if _dynamic_dce_getattr_8616(stmt, attr, None) is not None:
                return reads

        _collect_expr(stmt)
        return reads

    def _collect_nested_stmt_reads(stmt: object) -> set[tuple[str, int | str]]:
        reads = set(_collect_stmt_reads(stmt))
        work: list[object] = []
        seen: set[int] = set()
        for attr in (
            "body",
            "else_node",
            "iftrue",
            "iffalse",
            "true_node",
            "false_node",
            "default",
        ):
            child = _dynamic_dce_getattr_8616(stmt, attr, None)
            if child is not None:
                work.append(child)
        for pair in _dynamic_dce_getattr_8616(stmt, "condition_and_nodes", ()) or ():
            if len(pair) >= 2:
                work.append(pair[1])
        cases = _dynamic_dce_getattr_8616(stmt, "cases", None)
        work.extend(_iter_switch_case_bodies_8616(cases))

        while work:
            node = work.pop()
            if node is None:
                continue
            node_id = id(node)
            if node_id in seen:
                continue
            seen.add(node_id)
            if hasattr(node, "statements"):
                for child_stmt in list(_dynamic_dce_getattr_8616(node, "statements", ()) or ()):
                    reads.update(_collect_stmt_reads(child_stmt))
                    work.append(child_stmt)
                continue
            reads.update(_collect_stmt_reads(node))
        return reads

    def _collect_read_counts_by_block(
        root: object,
    ) -> tuple[dict[tuple[str, int | str], int], dict[int, dict[tuple[str, int | str], int]]]:
        total_reads: dict[tuple[str, int | str], int] = {}
        block_reads: dict[int, dict[tuple[str, int | str], int]] = {}
        for block in _iter_statement_blocks(root):
            local_reads: dict[tuple[str, int | str], int] = {}
            for stmt in list(_dynamic_dce_getattr_8616(block, "statements", ()) or ()):
                for key in _collect_stmt_reads(stmt):
                    total_reads[key] = total_reads.get(key, 0) + 1
                for key in _collect_stmt_reads(stmt):
                    local_reads[key] = local_reads.get(key, 0) + 1
            block_reads[id(block)] = local_reads
        return total_reads, block_reads

    def _collect_loop_backedge_reads_by_block_8616(
        root: object,
    ) -> dict[int, frozenset[tuple[str, int | str]]]:
        """Return reads that remain live across each structured loop backedge.

        A source variable written near the end of a loop body may feed a read
        near the beginning of the next iteration. Straight-line backward
        liveness cannot see that edge. AIL virtual values are SSA identities,
        however, and cannot be loop-carried through a same-identity backedge;
        preserving them here retains dead post-materialization carrier cycles.
        """
        mutable_reads: dict[int, set[tuple[str, int | str]]] = {}
        for container in _iter_statement_blocks(root):
            statements = tuple(_dynamic_dce_getattr_8616(container, "statements", ()) or ())
            for stmt in statements:
                if type(stmt).__name__ not in {"CDoWhileLoop", "CForLoop", "CWhileLoop"}:
                    continue
                body = _dynamic_dce_getattr_8616(stmt, "body", None)
                if body is None:
                    continue
                body_blocks = tuple(_iter_statement_blocks(body))
                loop_reads = set(_collect_stmt_reads(stmt))
                for body_block in body_blocks:
                    for body_stmt in tuple(_dynamic_dce_getattr_8616(body_block, "statements", ()) or ()):
                        loop_reads.update(_collect_stmt_reads(body_stmt))
                for body_block in body_blocks:
                    mutable_reads.setdefault(id(body_block), set()).update(
                        key for key in loop_reads if not key[0].startswith("dirty")
                    )
        return {block_id: frozenset(reads) for block_id, reads in mutable_reads.items()}

    def _collect_observable_read_counts_8616(root: object) -> dict[tuple[str, int | str], int]:
        reads: dict[tuple[str, int | str], int] = {}
        for block in _iter_statement_blocks(root):
            # Dynamic angr/codegen statement-block compatibility boundary.
            for stmt in list(_dynamic_dce_getattr_8616(block, "statements", ()) or ()):
                if not isinstance(stmt, CAssignment):
                    for key in _collect_stmt_reads(stmt):
                        reads[key] = reads.get(key, 0) + 1
                    continue
                rhs = stmt.rhs
                if _dirty_is_storage_free_carrier_8616(stmt.lhs) and not _rhs_has_side_effects(
                    rhs
                ) and not _expr_contains_memory_read_shape_8616(rhs):
                    continue
                for key in _collect_stmt_reads(stmt):
                    reads[key] = reads.get(key, 0) + 1
        return reads

    def _collect_storage_free_dirty_carrier_read_counts_8616(root: object) -> dict[tuple[str, int | str], int]:
        reads: dict[tuple[str, int | str], int] = {}
        for block in _iter_statement_blocks(root):
            # Dynamic angr/codegen statement-block compatibility boundary.
            for stmt in list(_dynamic_dce_getattr_8616(block, "statements", ()) or ()):
                if not isinstance(stmt, CAssignment):
                    continue
                rhs = stmt.rhs
                if not _dirty_is_storage_free_carrier_8616(stmt.lhs) or _rhs_has_side_effects(
                    rhs
                ) or _expr_contains_memory_read_shape_8616(rhs):
                    continue
                for key in _collect_stmt_reads(stmt):
                    reads[key] = reads.get(key, 0) + 1
        return reads

    def _collect_dirty_carrier_read_counts_8616(root: object) -> dict[tuple[str, int | str], int]:
        reads: dict[tuple[str, int | str], int] = {}
        for block in _iter_statement_blocks(root):
            # Dynamic angr/codegen statement-block compatibility boundary.
            for stmt in list(_dynamic_dce_getattr_8616(block, "statements", ()) or ()):
                if not isinstance(stmt, CAssignment):
                    continue
                rhs = stmt.rhs
                if _dirty_key(stmt.lhs) is None or _rhs_has_side_effects(rhs):
                    continue
                for key in _collect_stmt_reads(stmt):
                    reads[key] = reads.get(key, 0) + 1
        return reads

    def _is_temp_like_var(var_node: CVariable) -> bool:
        name = _var_name(var_node)
        if not name:
            return False
        return name.startswith(("vvar_", "tmp_", "ir_"))

    def _lhs_key_and_name_8616(lhs: object) -> tuple[tuple[str, int | str] | None, tuple[str, str] | None, bool]:
        dirty_key = _dirty_key(lhs)
        if dirty_key is not None:
            # Dirty expressions carry VEX/AIL virtual register and flag
            # provenance. They are not ordinary emitted C temporaries, and DCE
            # must not delete them without a stronger typed proof that later
            # materialization no longer needs the carrier.
            if _dirty_is_storage_free_temp_8616(lhs):
                return dirty_key, ("dirty", str(dirty_key[1])), True
            return dirty_key, ("dirty", str(dirty_key[1])), False
        if _is_observable_lvalue(lhs):
            return None, None, False
        lhs_var = _lhs_variable_8616(lhs)
        if lhs_var is None:
            return None, None, False
        return _var_key(lhs_var), ("name", _var_name(lhs_var)), _is_temp_like_var(lhs_var)

    def _argument_keys_8616() -> tuple[set[tuple[str, int | str]], set[tuple[str, str]]]:
        # Dynamic codegen compatibility boundary.
        cfunc_obj = _dynamic_dce_getattr_8616(codegen, "cfunc", None)
        keys: set[tuple[str, int | str]] = set()
        name_keys: set[tuple[str, str]] = set()
        for arg in tuple(_dynamic_dce_getattr_8616(cfunc_obj, "arg_list", ()) or ()):
            if not isinstance(arg, CVariable):
                continue
            keys.add(_var_key(arg))
            name = _var_name(arg)
            if name:
                name_keys.add(("name", name))
        prototype = _dynamic_dce_getattr_8616(cfunc_obj, "functy", None) or _dynamic_dce_getattr_8616(cfunc_obj, "prototype", None)
        for name in tuple(_dynamic_dce_getattr_8616(prototype, "arg_names", ()) or ()):
            if isinstance(name, str) and name:
                name_keys.add(("name", name))
        return keys, name_keys

    def _stack_offset_from_plain_lvalue_8616(lhs: object) -> int | None:
        """Return the proven machine-BP offset for a plain stack lvalue."""
        lhs_var = _lhs_variable_8616(lhs)
        if lhs_var is None:
            return None
        variable = _dynamic_dce_getattr_8616(lhs_var, "variable", None)
        if not isinstance(variable, SimStackVariable):
            return None
        offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
        return int(offset) if isinstance(offset, int) else None

    def _has_direct_stack_write_evidence_for_offset_8616(offset: int | None) -> bool:
        if not isinstance(offset, int):
            return False
        for attr, offset_key in (
            ("_inertia_direct_stack_move_evidence_8616", "dst_offset"),
            ("_inertia_direct_stack_update_evidence_8616", "offset"),
        ):
            evidence = _dynamic_dce_getattr_8616(codegen, attr, ()) or ()
            for item in evidence:
                pairs = (
                    tuple(item.items())
                    if isinstance(item, dict)
                    else tuple(item)
                    if isinstance(item, (tuple, list))
                    else ()
                )
                for pair in pairs:
                    if not isinstance(pair, (tuple, list)) or len(pair) != 2:
                        continue
                    key_item, value = pair
                    if key_item == offset_key and value == offset:
                        return True
        return False

    def _node_has_instruction_evidence_8616(node: object) -> bool:
        for item in _iter_with_root(node):
            tags = _dynamic_dce_getattr_8616(item, "tags", None)
            if isinstance(tags, dict) and isinstance(tags.get("ins_addr"), int):
                return True
        return False

    consumed_boolean_carrier_addrs = frozenset(
        address
        for address in (
            _dynamic_dce_getattr_8616(
                codegen,
                "_inertia_consumed_direct_global_boolean_carrier_ins_addrs_8616",
                (),
            )
            or ()
        )
        if isinstance(address, int)
    )

    def _stmt_is_consumed_boolean_carrier_8616(stmt: object) -> bool:
        """Return whether semantic lowering consumed this exact instruction."""
        tags = _dynamic_dce_getattr_8616(stmt, "tags", None)
        ins_addr = tags.get("ins_addr") if isinstance(tags, dict) else None
        return isinstance(ins_addr, int) and ins_addr in consumed_boolean_carrier_addrs

    consumed_call_cleanup_carrier_addrs = frozenset(
        address
        for address in (
            _dynamic_dce_getattr_8616(
                codegen,
                "_inertia_consumed_call_cleanup_carrier_ins_addrs_8616",
                (),
            )
            or ()
        )
        if isinstance(address, int)
    )

    def _stmt_is_consumed_call_cleanup_carrier_8616(stmt: object) -> bool:
        """Return whether call lowering consumed this exact cleanup instruction."""
        tags = _dynamic_dce_getattr_8616(stmt, "tags", None)
        ins_addr = tags.get("ins_addr") if isinstance(tags, dict) else None
        return (
            isinstance(ins_addr, int)
            and ins_addr in consumed_call_cleanup_carrier_addrs
        )

    def _is_function_argument_lvalue_8616(
        lhs: object,
        key: tuple[str, int | str],
        name_key: tuple[str, str] | None,
    ) -> bool:
        argument_keys, argument_name_keys = _argument_keys_8616()
        if key in argument_keys or (name_key is not None and name_key in argument_name_keys):
            return True
        offset = _stack_offset_from_plain_lvalue_8616(lhs)
        return isinstance(offset, int) and offset >= 4

    def _drop_pruned_codegen_declarations_8616() -> bool:
        """Remove declaration table entries whose generated assignments were eliminated."""
        if not pruned_decl_keys:
            return False
        referenced_keys = {_var_key(node) for node in _iter_with_root(root) if isinstance(node, CVariable)}
        argument_keys, _argument_names = _argument_keys_8616()
        dead_keys = frozenset(pruned_decl_keys - referenced_keys - argument_keys)
        return prune_dce_proven_declarations_8616(
            codegen, dead_keys=dead_keys, key_of=_var_key,
        )

    def _collect_defined_keys_8616(root_node: object) -> set[tuple[str, int | str]]:
        defined: set[tuple[str, int | str]] = set()
        for node in _iter_with_root(root_node):
            if not isinstance(node, CAssignment):
                continue
            lhs_key, _lhs_name_key, _lhs_temp_like = _lhs_key_and_name_8616(_dynamic_dce_getattr_8616(node, "lhs", None))
            if lhs_key is not None:
                defined.add(lhs_key)
        return defined

    def _rhs_is_unproven_dirty_register_carrier_8616(
        rhs: object,
        defined_keys: set[tuple[str, int | str]],
    ) -> bool:
        while isinstance(rhs, CTypeCast):
            rhs = _dynamic_dce_getattr_8616(rhs, "expr", None)
        if type(rhs).__name__ != "CDirtyExpression":
            return False
        key = _dirty_key(rhs)
        if key is None or key in defined_keys:
            return False
        dirty = _safe_attr(rhs, "dirty", None)
        has_register_provenance = any(
            isinstance(_safe_attr(dirty, attr, None), int) for attr in ("reg", "reg_offset", "parameter_reg_offset")
        )
        has_stack_provenance = any(
            isinstance(_safe_attr(dirty, attr, None), int) for attr in ("stack_offset", "parameter_stack_offset")
        )
        return has_register_provenance and not has_stack_provenance

    def _is_dead_argument_overwrite_artifact_8616(
        stmt: object,
        lhs: object,
        rhs: object,
        key: tuple[str, int | str],
        name_key: tuple[str, str] | None,
        defined_keys: set[tuple[str, int | str]],
    ) -> bool:
        if not _is_plain_local_lvalue_8616(lhs):
            return False
        if not _is_function_argument_lvalue_8616(lhs, key, name_key):
            return False
        if _has_direct_stack_write_evidence_for_offset_8616(_stack_offset_from_plain_lvalue_8616(lhs)):
            return False
        if _rhs_has_side_effects(rhs):
            return False
        return _rhs_is_unproven_dirty_register_carrier_8616(rhs, defined_keys)

    def _protected_var_keys() -> set[tuple[str, int | str]]:
        """Keep Lowering's live save definitions even after AST rebinding."""
        protected: set[tuple[str, int | str]] = set()
        # Earlier passes can clone/rebind locals independently of side metadata.
        for node in _iter_c_nodes_deep_8616(root):
            if (isinstance(node, CAssignment) and isinstance(node.lhs, CVariable)
                    and isinstance(node.tags, dict) and "inertia_x86_16_gp_stack_save" in node.tags):
                protected.add(_var_key(node.lhs))
        attrs = (
            "_inertia_callsite_arg_sources",
            "_inertia_stack_variable_bindings",
            "_inertia_stack_canonicalization_bridges",
            "_inertia_tail_validation_widened_carriers",
            "_inertia_linear_recurrence_state",
            "_inertia_gp_stack_restore_snapshots_8616",
        )
        for attr in attrs:
            obj = _dynamic_dce_getattr_8616(codegen, attr, None)
            if obj is None:
                continue
            work = [obj]
            seen: set[int] = set()
            while work:
                cur = work.pop()
                cur_id = id(cur)
                if cur_id in seen:
                    continue
                seen.add(cur_id)
                if isinstance(cur, CVariable):
                    protected.add(_var_key(cur))
                    continue
                if isinstance(cur, dict):
                    work.extend(cur.values())
                    work.extend(cur.keys())
                    continue
                if isinstance(cur, (list, tuple, set, frozenset)):
                    work.extend(cur)
                    continue
                name = cur if isinstance(cur, str) else _dynamic_dce_getattr_8616(cur, "name", None)
                if isinstance(name, str) and name:
                    protected.add(("name", name))
        return protected

    def _direct_stack_move_evidence_pairs_8616() -> frozenset[tuple[int, int]]:
        """Return exact machine-BP and instruction identities for proven moves."""
        pairs: set[tuple[int, int]] = set()
        evidence = _dynamic_dce_getattr_8616(
            codegen,
            "_inertia_direct_stack_move_evidence_8616",
            (),
        ) or ()
        for item in evidence:
            values = (
                dict(item.items())
                if isinstance(item, dict)
                else dict(item)
                if isinstance(item, (tuple, list))
                else {}
            )
            offset = values.get("dst_offset")
            ins_addr = values.get("ins_addr")
            if isinstance(offset, int) and isinstance(ins_addr, int):
                pairs.add((offset, ins_addr))
        return frozenset(pairs)

    def _direct_stack_update_evidence_pairs_8616() -> frozenset[tuple[int, int]]:
        pairs: set[tuple[int, int]] = set()
        # Dynamic codegen evidence compatibility boundary.
        evidence = _dynamic_dce_getattr_8616(codegen, "_inertia_direct_stack_update_evidence_8616", ()) or ()
        for item in evidence:
            values = dict(item.items()) if isinstance(item, dict) else dict(item) if isinstance(item, (tuple, list)) else {}
            offset = values.get("offset")
            ins_addr = values.get("ins_addr")
            if isinstance(offset, int) and isinstance(ins_addr, int):
                pairs.add((offset, ins_addr))
        return frozenset(pairs)

    direct_stack_move_evidence_pairs = _direct_stack_move_evidence_pairs_8616()
    direct_stack_update_evidence_pairs = _direct_stack_update_evidence_pairs_8616()

    def _stmt_is_direct_stack_move_evidence_8616(stmt: object, lhs: object) -> bool:
        """Return whether a statement materializes one exact proven stack move."""
        offset = _stack_offset_from_plain_lvalue_8616(lhs)
        if not isinstance(offset, int):
            return False
        for node in _iter_with_root(stmt):
            tags = _dynamic_dce_getattr_8616(node, "tags", None)
            if isinstance(tags, dict) and (offset, tags.get("ins_addr")) in direct_stack_move_evidence_pairs:
                return True
        return False

    def _stmt_is_direct_stack_update_evidence_8616(stmt: object, lhs: object) -> bool:
        offset = _stack_offset_from_plain_lvalue_8616(lhs)
        if not isinstance(offset, int):
            return False
        for node in _iter_with_root(stmt):
            # Dynamic angr/codegen statement compatibility boundary.
            tags = _dynamic_dce_getattr_8616(node, "tags", None)
            if isinstance(tags, dict) and (offset, tags.get("ins_addr")) in direct_stack_update_evidence_pairs:
                return True
        return False

    protected = _protected_var_keys()
    debug_optimization = os.environ.get("INERTIA_DEBUG_OPTIMIZATION", "").strip().lower() in {"1", "true", "yes", "on"}
    if debug_optimization:
        block_count = 0
        stmt_count = 0
        assign_count = 0
        class_counts: dict[str, int] = {}
        lhs_counts: dict[str, int] = {}
        lhs_samples: list[str] = []
        for dbg_block in _iter_statement_blocks(root):
            block_count += 1
            for dbg_stmt in list(_dynamic_dce_getattr_8616(dbg_block, "statements", ()) or ()):
                stmt_count += 1
                cls_name = type(dbg_stmt).__name__
                class_counts[cls_name] = class_counts.get(cls_name, 0) + 1
                if isinstance(dbg_stmt, CAssignment):
                    assign_count += 1
                    lhs = _dynamic_dce_getattr_8616(dbg_stmt, "lhs", None)
                    lhs_name = type(lhs).__name__
                    lhs_counts[lhs_name] = lhs_counts.get(lhs_name, 0) + 1
                    if len(lhs_samples) < 6:
                        name = ""
                        with contextlib.suppress(Exception):
                            if isinstance(lhs, CVariable):
                                name = _var_name(lhs)
                            else:
                                attrs = [
                                    attr
                                    for attr in (
                                        "variable",
                                        "expr",
                                        "expression",
                                        "dirty_expr",
                                        "operand",
                                        "operands",
                                        "cvariable",
                                        "variable_node",
                                    )
                                    if hasattr(lhs, attr)
                                ]
                                public = [
                                    attr
                                    for attr in dir(lhs)
                                    if not attr.startswith("_")
                                    and attr
                                    not in {
                                        "c_repr",
                                        "c_repr_chunks",
                                        "c_repr_chunks_annotated",
                                        "c_repr_chunks_with_addr",
                                    }
                                ][:16]
                                dirty = _dynamic_dce_getattr_8616(lhs, "dirty", None)
                                idx = _dynamic_dce_getattr_8616(lhs, "idx", None)
                                dirty_attrs = [
                                    attr
                                    for attr in dir(dirty)
                                    if not attr.startswith("_")
                                    and attr not in {"copy", "likes", "matches", "replace", "tag"}
                                ][:12]
                                name = (
                                    f"attrs={attrs} public={public} idx={idx!r} "
                                    f"dirty={type(dirty).__name__} dirty_public={dirty_attrs}"
                                )
                        lhs_samples.append(f"{lhs_name}:{name}")
        top_classes = ",".join(f"{name}:{count}" for name, count in sorted(class_counts.items())[:8])
        top_lhs = ",".join(f"{name}:{count}" for name, count in sorted(lhs_counts.items())[:8])
        print(
            "[optimization] dce_walk "
            f"blocks={block_count} stmts={stmt_count} assignments={assign_count} "
            f"classes={top_classes} lhs={top_lhs} samples={';'.join(lhs_samples)}",
            file=sys.stderr,
            flush=True,
        )
        if os.environ.get("INERTIA_DEBUG_OPTIMIZATION_PATHS", "").strip().lower() in {"1", "true", "yes", "on"}:

            def _expr_debug_label_8616(expr: object) -> str:
                if isinstance(expr, CVariable):
                    return _var_name(expr)
                if isinstance(expr, CBinaryOp):
                    return f"({_expr_debug_label_8616(_dynamic_dce_getattr_8616(expr, 'lhs', None))} {_dynamic_dce_getattr_8616(expr, 'op', '?')} {_expr_debug_label_8616(_dynamic_dce_getattr_8616(expr, 'rhs', None))})"
                if type(expr).__name__ == "CDirtyExpression":
                    return str(_dirty_key(expr) or "dirty")
                value = _dynamic_dce_getattr_8616(expr, "value", None)
                if isinstance(value, (int, str)):
                    return str(value)
                return type(expr).__name__

            def _dump_assignment_paths_8616(node: object, path: str, seen_paths: set[int]) -> None:
                if node is None or id(node) in seen_paths:
                    return
                seen_paths.add(id(node))
                if hasattr(node, "statements"):
                    statements = list(_dynamic_dce_getattr_8616(node, "statements", ()) or ())
                    for index, stmt in enumerate(statements):
                        stmt_path = f"{path}.{index}"
                        if isinstance(stmt, CAssignment):
                            print(
                                "[optimization] dce_path "
                                f"path={stmt_path} parent_len={len(statements)} "
                                f"lhs={_expr_debug_label_8616(_dynamic_dce_getattr_8616(stmt, 'lhs', None))} "
                                f"rhs={_expr_debug_label_8616(_dynamic_dce_getattr_8616(stmt, 'rhs', None))} "
                                f"stmt_type={type(stmt).__name__}",
                                file=sys.stderr,
                                flush=True,
                            )
                        _dump_assignment_paths_8616(stmt, stmt_path, seen_paths)
                for attr in ("body", "else_node", "iftrue", "iffalse", "true_node", "false_node"):
                    child = _dynamic_dce_getattr_8616(node, attr, None)
                    if child is not None:
                        _dump_assignment_paths_8616(child, f"{path}.{attr}", seen_paths)
                # Dynamic angr/codegen structured-C compatibility boundary.
                for pair_index, pair in enumerate(_dynamic_dce_getattr_8616(node, "condition_and_nodes", ()) or ()):
                    if len(pair) >= 2:
                        _dump_assignment_paths_8616(pair[1], f"{path}.cond{pair_index}", seen_paths)
                # Dynamic angr/codegen structured-C compatibility boundary.
                for case_index, body in enumerate(_iter_switch_case_bodies_8616(_dynamic_dce_getattr_8616(node, "cases", None))):
                    _dump_assignment_paths_8616(body, f"{path}.case{case_index}", seen_paths)
                # Dynamic angr/codegen structured-C compatibility boundary.
                default = _dynamic_dce_getattr_8616(node, "default", None)
                if default is not None:
                    _dump_assignment_paths_8616(default, f"{path}.default", seen_paths)

            _dump_assignment_paths_8616(root, "root", set())

    walk_context = _DceWalkContext8616(
        codegen=codegen,
        debug_optimization=debug_optimization,
        protected=protected,
        pruned_decl_keys=pruned_decl_keys,
        pruned_decl_names=pruned_decl_names,
        changed=changed,
        bump_codegen_counter=_bump_codegen_counter_8616,
        call_name=_call_name_8616,
        callsite_materialization_complete_or_no_calls=_callsite_materialization_complete_or_no_calls_8616,
        callsite_materialization_proven_complete=_callsite_materialization_proven_complete_8616,
        collect_nested_stmt_reads=_collect_nested_stmt_reads,
        collect_stmt_reads=_collect_stmt_reads,
        debug_node_shape=_debug_node_shape_8616,
        dirty_is_storage_free_temp=_dirty_is_storage_free_temp_8616,
        dirty_key=_dirty_key,
        dirty_lhs_delete_proven=_dirty_lhs_delete_proven_8616,
        dirty_temp_cleanup_mode=_dirty_temp_cleanup_mode_8616,
        expr_contains_memory_read_shape=_expr_contains_memory_read_shape_8616,
        expr_is_discardable_dead_value=_expr_is_discardable_dead_value_8616,
        expr_is_discardable_value=_expr_is_discardable_value_8616,
        expr_is_pure_local_value=_expr_is_pure_local_value_8616,
        expr_value_purity=_expr_value_purity_8616,
        has_direct_stack_write_evidence_for_offset=_has_direct_stack_write_evidence_for_offset_8616,
        is_dead_argument_overwrite_artifact=_is_dead_argument_overwrite_artifact_8616,
        is_frame_anchor_stack_lvalue=_is_frame_anchor_stack_lvalue_8616,
        is_function_argument_lvalue=_is_function_argument_lvalue_8616,
        is_observable_lvalue=_is_observable_lvalue,
        is_plain_local_lvalue=_is_plain_local_lvalue_8616,
        is_pure_generated_helper_call=_is_pure_generated_helper_call_8616,
        is_structured_or_control_statement=_is_structured_or_control_statement_8616,
        iter_with_root=_iter_with_root,
        lhs_key_and_name=_lhs_key_and_name_8616,
        lhs_variable=_lhs_variable_8616,
        node_has_instruction_evidence=_node_has_instruction_evidence_8616,
        prune_adjacent_duplicate_assignments=_prune_adjacent_duplicate_assignments_8616,
        rhs_evaluation_is_proven_unobservable=_rhs_evaluation_is_proven_unobservable_8616,
        rhs_has_side_effects=_rhs_has_side_effects,
        rhs_is_pure_stack_base_carrier=_rhs_is_pure_stack_base_carrier_8616,
        rhs_is_unproven_dirty_register_carrier=_rhs_is_unproven_dirty_register_carrier_8616,
        stack_offset_from_plain_lvalue=_stack_offset_from_plain_lvalue_8616,
        standalone_expression_is_definitely_dead=_standalone_expression_is_definitely_dead_8616,
        standalone_expression_payload=_standalone_expression_payload_8616,
        stmt_is_consumed_boolean_carrier=_stmt_is_consumed_boolean_carrier_8616,
        stmt_is_consumed_call_cleanup_carrier=_stmt_is_consumed_call_cleanup_carrier_8616,
        stmt_is_direct_stack_move_evidence=_stmt_is_direct_stack_move_evidence_8616,
        stmt_is_direct_stack_update_evidence=_stmt_is_direct_stack_update_evidence_8616,
    )

    # Iterate to a fixed point: once the tail of a pure flag/setup chain is
    # deleted, earlier assignments in the same chain become provably unused.
    noop_conditional_stats = DceNoopConditionalPruneStats8616()
    for _ in range(128):
        total_reads, block_reads = _collect_read_counts_by_block(root)
        loop_backedge_reads = _collect_loop_backedge_reads_by_block_8616(root)
        observable_reads = _collect_observable_read_counts_8616(root)
        dirty_carrier_reads = _collect_storage_free_dirty_carrier_read_counts_8616(root)
        all_dirty_carrier_reads = _collect_dirty_carrier_read_counts_8616(root)
        defined_keys = _collect_defined_keys_8616(root)
        pass_changed = False
        for block in _iter_statement_blocks(root):
            pass_changed = (
                _walk_statements_8616(
                    walk_context,
                    block,
                    total_reads,
                    block_reads,
                    loop_backedge_reads,
                    defined_keys,
                    observable_reads,
                    dirty_carrier_reads,
                    all_dirty_carrier_reads,
                )
                or pass_changed
            )
        noop_iteration = prune_explicit_empty_if_else_after_dce_8616(
            tuple(_iter_statement_blocks(root)),
            condition_is_pure=lambda condition: bool(
                _expr_is_discardable_dead_value_8616(condition)
                or _expr_is_pure_local_value_8616(condition)
            ),
        )
        noop_conditional_stats = noop_conditional_stats.merge(noop_iteration)
        if not noop_iteration.closed:
            raise RuntimeError("DCE no-op conditional evidence did not close")
        pass_changed = noop_iteration.changed or pass_changed
        walk_context.changed = noop_iteration.changed or walk_context.changed
        if not pass_changed:
            break
    _dynamic_dce_setattr_8616(
        codegen,
        "_inertia_dce_noop_conditional_prune_stats_8616",
        noop_conditional_stats,
    )
    changed = walk_context.changed
    changed = _drop_pruned_codegen_declarations_8616() or changed
    if debug_optimization:
        print(
            "[optimization] dce_counters "
            f"dce_candidates={int(_dynamic_dce_getattr_8616(codegen, 'dce_candidates', 0) or 0)} "
            f"dce_deleted={int(_dynamic_dce_getattr_8616(codegen, 'dce_deleted', 0) or 0)} "
            f"dce_keep_live_use={int(_dynamic_dce_getattr_8616(codegen, 'dce_keep_live_use', 0) or 0)} "
            f"dce_keep_side_effect={int(_dynamic_dce_getattr_8616(codegen, 'dce_keep_side_effect', 0) or 0)} "
            f"dce_keep_protected={int(_dynamic_dce_getattr_8616(codegen, 'dce_keep_protected', 0) or 0)} "
            f"dce_keep_observable={int(_dynamic_dce_getattr_8616(codegen, 'dce_keep_observable', 0) or 0)} "
            f"dce_keep_unknown={int(_dynamic_dce_getattr_8616(codegen, 'dce_keep_unknown', 0) or 0)} "
            f"dce_dirty_value_candidates={int(_dynamic_dce_getattr_8616(codegen, 'dce_dirty_value_candidates', 0) or 0)} "
            f"dce_dirty_value_deleted={int(_dynamic_dce_getattr_8616(codegen, 'dce_dirty_value_deleted', 0) or 0)} "
            f"dce_dirty_value_refused={int(_dynamic_dce_getattr_8616(codegen, 'dce_dirty_value_refused', 0) or 0)} "
            f"dce_dead_memory_read_candidates={int(_dynamic_dce_getattr_8616(codegen, 'dce_dead_memory_read_candidates', 0) or 0)} "
            f"dce_dead_memory_read_deleted={int(_dynamic_dce_getattr_8616(codegen, 'dce_dead_memory_read_deleted', 0) or 0)} "
            f"dce_dead_memory_read_refused={int(_dynamic_dce_getattr_8616(codegen, 'dce_dead_memory_read_refused', 0) or 0)} "
            f"dce_pure_expression_candidates={int(_dynamic_dce_getattr_8616(codegen, 'dce_pure_expression_candidates', 0) or 0)} "
            f"dce_pure_expression_deleted={int(_dynamic_dce_getattr_8616(codegen, 'dce_pure_expression_deleted', 0) or 0)} "
            f"dce_pure_expression_refused={int(_dynamic_dce_getattr_8616(codegen, 'dce_pure_expression_refused', 0) or 0)}",
            file=sys.stderr,
            flush=True,
        )
    return changed
