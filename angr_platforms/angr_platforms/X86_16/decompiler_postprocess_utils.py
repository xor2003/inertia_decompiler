"""Shared C AST utilities for postprocess consumers.

Layer: Rewrite/Postprocess cleanup.
Responsibility: provide syntax-only helpers for already-rendered angr C AST nodes.

This module should stay boring: traversal helpers, child replacement, constant
inspection, and syntactic matchers for already-rendered C nodes. It is allowed
to describe C AST shapes, but it must not decide semantic truth.

Ownership rule:
- Keep this module syntax-only and compatibility-oriented.
- If a caller can prove semantic evidence in alias/lowering/structuring, that
  logic must live there and this module should only pass through proven tokens.
- As structured proof coverage improves, trim any shape-based heuristics and
  migrate callers to the owning layer.

Current migration debt:
- several matchers recognize real-mode linear/segmented memory and BP-stack
  patterns from rendered C shapes;
- helper functions expose global/stack address extraction used by late
  materialization passes.

Those semantic identities belong in alias, stack lowering, segmented memory
lowering, and typed Value/Address facts before C rendering. As those layers
mature, keep only generic AST traversal here and delete shape matchers whose
callers can consume structured facts instead.

Do not add new recovery logic, text parsing, compiler-specific patterns, or
validation exceptions here. New helpers should be syntax-only utilities used by
postprocess passes after evidence has already been collected.

Dynamic attribute access in this module is limited to the angr codegen/C AST
boundary, where structured-codegen node classes expose version-dependent child
attributes.
"""

from __future__ import annotations

import builtins
import re
import typing
from collections.abc import Callable, Iterator
from contextlib import suppress
from functools import lru_cache
from typing import Any, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable

from .c_ast_utils import (
    _safe_assign_cfunc_statements_8616,
    _structured_codegen_node_8616,
)
from .c_ast_utils import _same_c_expression_8616 as _shared_same_c_expression_8616
from .lowering.real_mode_linear import _stack_base_bp_bias_8616, _stack_pointer_carrier_offset_8616

_SEGMENT_REGISTER_NAMES_8616 = {"cs", "ds", "es", "ss"}
_LINEAR_TEMP_NAME_RE_8616 = re.compile(r"(?:v\d+|vvar_\d+|ir_\d+|tmp_\d+)(?:\{[^}]+\})?$")
_STRUCTURED_NON_CHILD_ATTRS_8616 = frozenset({"codegen", "idx", "tags"})
_STRUCTURED_CHILD_ATTRS_BY_CLASS_8616 = {
    "CAILBlock": ("block",),
    "CAssignment": ("lhs", "rhs"),
    "CBinaryOp": ("lhs", "rhs"),
    "CDoWhileLoop": ("condition", "body"),
    "CExpressionStatement": ("expr",),
    "CForLoop": ("initializer", "condition", "iterator", "body"),
    "CFunction": ("arg_list", "statements"),
    "CFunctionCall": ("callee_target", "callee_func", "args"),
    "CITE": ("cond", "iftrue", "iffalse"),
    "CIfBreak": ("condition",),
    "CIfElse": ("condition_and_nodes", "else_node"),
    "CIncompleteSwitchCase": ("head", "cases"),
    "CIndexedVariable": ("variable", "index"),
    "CMultiStatementExpression": ("stmts", "expr"),
    "CReturn": ("retval",),
    "CStatements": ("statements",),
    "CSwitchCase": ("switch", "cases", "default"),
    "CTypeCast": ("expr",),
    "CUnaryOp": ("operand",),
    "CVEXCCallExpression": ("callee", "operands"),
    "CVariableField": ("variable", "field"),
    "CWhileLoop": ("condition", "body"),
}


def _dynamic_c_ast_getattr_8616(obj: object, name: str, default: object = None) -> Any:
    """Read an attribute across the dynamic angr codegen/C AST boundary."""
    return builtins.getattr(obj, name, default)


def _dynamic_c_ast_setattr_8616(obj: object, name: str, value: object) -> None:
    """Set an attribute across the dynamic angr codegen/C AST boundary."""
    builtins.setattr(obj, name, value)


def _strip_typed_name_suffix_8616(name: object) -> str | None:
    if not isinstance(name, str):
        return None
    if name.endswith("}"):
        brace_pos = name.find("{")
        if brace_pos >= 0:
            return name[:brace_pos]
    return name


def _is_linear_temp_name_8616(name: object) -> bool:
    normalized = _strip_typed_name_suffix_8616(name)
    return isinstance(normalized, str) and _LINEAR_TEMP_NAME_RE_8616.fullmatch(normalized) is not None


__all__ = [
    "_c_constant_value_8616",
    "_global_memory_addr_8616",
    "_is_shifted_high_byte_8616",
    "_iter_c_nodes_deep_8616",
    "_make_word_global_8616",
    "_match_bp_stack_dereference_8616",
    "_match_bp_stack_load_8616",
    "_match_real_mode_linear_expr_8616",
    "_match_real_mode_segmented_store_shape_8616",
    "_match_segmented_dereference_8616",
    "_replace_c_children_8616",
    "_safe_assign_cfunc_statements_8616",
    "_same_c_expression_8616",
    "_segment_reg_name_8616",
    "_stack_bp_displacement_8616",
    "_structured_codegen_node_8616",
]


def _unwrap_statements_8616(node: object) -> tuple[object, ...]:
    """Safely extract statement children from any C AST container node.

    CStatements is not iterable in some angr versions.  This function
    unwraps both plain lists and CStatements wrappers into a tuple.
    """
    if node is None:
        return ()
    if isinstance(node, CStatements):
        return tuple(_dynamic_c_ast_getattr_8616(node, "statements", ()) or ())
    if isinstance(node, (list, tuple)):
        return tuple(node)
    raw = _dynamic_c_ast_getattr_8616(node, "statements", ())
    if isinstance(raw, CStatements):
        return tuple(raw.statements)
    if isinstance(raw, (list, tuple)):
        return tuple(raw)
    return ()


@lru_cache(maxsize=256)
def _structured_slot_names_for_type_8616(value_type: type) -> tuple[str, ...]:
    attrs: list[str] = []
    if value_type is object:
        return ()

    for cls in value_type.mro():
        slots = _dynamic_c_ast_getattr_8616(cls, "__slots__", ())
        if not slots:
            continue
        if isinstance(slots, str):
            slots = (slots,)
        for slot in slots:
            if isinstance(slot, str) and not slot.startswith("_") and slot not in _STRUCTURED_NON_CHILD_ATTRS_8616:
                attrs.append(slot)  # noqa: PERF401

    seen = set()
    ordered: list[str] = []
    for attr in attrs:
        if attr in seen:
            continue
        seen.add(attr)
        ordered.append(attr)
    return tuple(ordered)


def _structured_slot_names_8616(value: object) -> tuple[str, ...]:
    def _impl() -> tuple[str, ...]:
        child_attrs = _STRUCTURED_CHILD_ATTRS_BY_CLASS_8616.get(type(value).__name__)
        if child_attrs is not None:
            return child_attrs

        base_attrs = _structured_slot_names_for_type_8616(cast(Any, type(value)))
        if not hasattr(value, "__dict__"):
            return base_attrs

        attrs: list[str] = list(base_attrs)
        try:
            dynamic_keys = tuple(value.__dict__.keys())
        except Exception:
            dynamic_keys = ()
        if not dynamic_keys:
            return base_attrs
        attrs.extend(
            attr
            for attr in dynamic_keys
            if (isinstance(attr, str) and not attr.startswith("_") and attr not in _STRUCTURED_NON_CHILD_ATTRS_8616)
        )
        if not attrs:
            return ()

        seen = set()
        ordered: list[str] = []
        for attr in attrs:
            if attr in seen:
                continue
            seen.add(attr)
            ordered.append(attr)
        return tuple(ordered)

    return _impl()


def _iter_c_node_children_8616(value: object, seen_values: set[int] | None = None) -> Iterator[object]:
    if seen_values is None:
        seen_values = set()

    stack = [value]
    while stack:
        current = stack.pop()
        try:
            current_id = id(current)
        except Exception:
            continue
        if current_id in seen_values:
            continue
        seen_values.add(current_id)

        if _structured_codegen_node_8616(current):
            yield current
            continue

        if isinstance(current, (str, bytes)):
            continue

        if isinstance(current, dict):
            with suppress(Exception):
                stack.extend(tuple(current.values()))
            continue

        if isinstance(current, (list, tuple, set)):
            with suppress(Exception):
                stack.extend(tuple(current))
            continue

        # Do not traverse arbitrary iterables here. Some structured-codegen
        # objects expose iterable adapters that are not part of the emitted AST
        # body, which can leak detached nodes into analyses.


def _c_constant_value_8616(node: object) -> int | None:
    if isinstance(node, CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _segment_reg_name_8616(node: object, project: object) -> str | None:
    if not isinstance(node, CVariable):
        return None
    variable = _dynamic_c_ast_getattr_8616(node, "variable", None)
    if not isinstance(variable, SimRegisterVariable):
        return None
    project_view = cast(Any, project)
    reg_name = project_view.arch.register_names.get(variable.reg)
    if isinstance(reg_name, str) and reg_name in _SEGMENT_REGISTER_NAMES_8616:
        return reg_name
    return None


def _match_real_mode_linear_expr_8616(
    node: object, project: object, codegen: object | None = None
) -> tuple[str | None, int | None]:
    def _impl() -> tuple[str | None, int | None]:
        def _maybe_resolve(term: object) -> object:
            if codegen is None:
                return term
            return _resolve_stack_bp_term_8616(term, project, codegen)

        if isinstance(node, CBinaryOp) and node.op == "Shl":
            for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
                if _c_constant_value_8616(maybe_scale) != 4:
                    continue
                seg_name = _segment_reg_name_8616(_maybe_resolve(maybe_seg), project)
                if seg_name is not None:
                    return seg_name, 0

        if isinstance(node, CBinaryOp) and node.op == "Mul":
            for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
                if _c_constant_value_8616(maybe_scale) != 16:
                    continue
                seg_name = _segment_reg_name_8616(_maybe_resolve(maybe_seg), project)
                if seg_name is not None:
                    return seg_name, 0

        if not isinstance(node, CBinaryOp) or node.op != "Add":
            return None, None

        for maybe_mul, maybe_const in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
            linear = _c_constant_value_8616(maybe_const)
            if linear is None:
                continue
            maybe_mul = _maybe_resolve(maybe_mul)
            if not isinstance(maybe_mul, CBinaryOp):
                continue
            if maybe_mul.op == "Mul":
                for maybe_seg, maybe_scale in ((maybe_mul.lhs, maybe_mul.rhs), (maybe_mul.rhs, maybe_mul.lhs)):
                    if _c_constant_value_8616(maybe_scale) != 16:
                        continue
                    seg_name = _segment_reg_name_8616(_maybe_resolve(maybe_seg), project)
                    if seg_name is not None:
                        return seg_name, linear
            if maybe_mul.op == "Shl":
                for maybe_seg, maybe_scale in ((maybe_mul.lhs, maybe_mul.rhs), (maybe_mul.rhs, maybe_mul.lhs)):
                    if _c_constant_value_8616(maybe_scale) != 4:
                        continue
                    seg_name = _segment_reg_name_8616(_maybe_resolve(maybe_seg), project)
                    if seg_name is not None:
                        return seg_name, linear
        return None, None

    return _impl()


def _match_real_mode_segmented_store_shape_8616(
    node: object, project: object
) -> tuple[str | None, tuple[tuple[int, object], ...]]:
    """Match a real-mode dereference shaped as one segment base plus explicit offset terms.

    This stays stricter than "lhs contains ss somewhere": the node must be a real
    memory dereference and its address must decompose into exactly one positive
    segment-base term plus zero or more signed offset terms.
    """

    def _strip_casts(expr: object) -> object:
        while isinstance(expr, CTypeCast):
            expr = expr.expr
        return expr

    def _segment_base_name(expr: object) -> str | None:
        expr = _strip_casts(expr)
        if isinstance(expr, CBinaryOp) and expr.op == "Shl":
            for maybe_seg, maybe_scale in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                if _c_constant_value_8616(maybe_scale) == 4:
                    return _segment_reg_name_8616(maybe_seg, project)
        if isinstance(expr, CBinaryOp) and expr.op == "Mul":
            for maybe_seg, maybe_scale in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
                if _c_constant_value_8616(maybe_scale) == 16:
                    return _segment_reg_name_8616(maybe_seg, project)
        return None

    def _collect_signed_terms(expr: object, sign: int, out: list[tuple[int, object]]) -> None:
        expr = _strip_casts(expr)
        if isinstance(expr, CBinaryOp) and expr.op == "Add":
            _collect_signed_terms(expr.lhs, sign, out)
            _collect_signed_terms(expr.rhs, sign, out)
            return
        if isinstance(expr, CBinaryOp) and expr.op == "Sub":
            _collect_signed_terms(expr.lhs, sign, out)
            _collect_signed_terms(expr.rhs, -sign, out)
            return
        out.append((sign, expr))

    node = _strip_casts(node)
    if not isinstance(node, CUnaryOp) or node.op != "Dereference":
        return None, ()

    signed_terms: list[tuple[int, object]] = []
    _collect_signed_terms(node.operand, 1, signed_terms)

    segment_name: str | None = None
    offset_terms: list[tuple[int, object]] = []
    for sign, term in signed_terms:
        base_name = _segment_base_name(term)
        if base_name is None:
            offset_terms.append((sign, term))
            continue
        if sign != 1 or segment_name is not None:
            return None, ()
        segment_name = base_name

    if segment_name is None:
        return None, ()
    return segment_name, tuple(offset_terms)


def _match_segmented_dereference_8616(node: object, project: object) -> tuple[str | None, int | None]:
    while isinstance(node, CTypeCast):
        node = node.expr
    if not isinstance(node, CUnaryOp) or node.op != "Dereference":
        return None, None
    operand = node.operand
    while isinstance(operand, CTypeCast):
        operand = operand.expr
    return _match_real_mode_linear_expr_8616(operand, project)


def _replace_c_children_8616(
    node: object,
    transform: Callable[[object], object],
    seen: set[int] | None = None,
    *,
    should_process_child: Callable[[object, str], bool] | None = None,
) -> bool:
    scalar_attrs = (
        "lhs",
        "rhs",
        "expr",
        "operand",
        "variable",
        "index",
        "condition",
        "cond",
        "initializer",
        "iterator",
        "body",
        "iffalse",
        "iftrue",
        "switch",
        "default",
        "callee_target",
        "else_node",
        "retval",
    )
    list_attrs = ("args", "operands", "statements")

    def _process_scalar_attr(current: object, attr: str, node_stack: list[object]) -> bool:
        if should_process_child is not None and not bool(should_process_child(current, attr)):
            return False
        if not hasattr(current, attr):
            return False
        try:
            value = _dynamic_c_ast_getattr_8616(current, attr)
        except Exception:
            return False
        if not _structured_codegen_node_8616(value):
            return False
        new_value = transform(value)
        changed_local = False
        if new_value is not value:
            _dynamic_c_ast_setattr_8616(current, attr, new_value)
            changed_local = True
            value = new_value
        node_stack.append(value)
        return changed_local

    def _process_list_attr(current: object, attr: str, node_stack: list[object]) -> bool:
        if not hasattr(current, attr):
            return False
        try:
            items = _dynamic_c_ast_getattr_8616(current, attr)
        except Exception:
            return False
        if not items:
            return False
        changed_local = False
        new_items = None
        for idx, item in enumerate(items):
            if not _structured_codegen_node_8616(item):
                continue
            transformed_item = transform(item)
            if transformed_item is not item:
                if new_items is None:
                    new_items = list(items)
                new_items[idx] = transformed_item
                changed_local = True
            else:
                transformed_item = item
            node_stack.append(transformed_item)
        if new_items is None:
            return changed_local
        # Preserve CStatements wrapper on nested 'statements' attributes.
        # Setting a plain list breaks downstream passes expecting .statements
        # on structured nodes (e.g. CIfElse, CWhileLoop, CForLoop).
        if attr == "statements" and isinstance(items, CStatements):
            new_items = CStatements(statements=new_items, codegen=_dynamic_c_ast_getattr_8616(current, "codegen", None))
        _dynamic_c_ast_setattr_8616(current, attr, new_items)
        return changed_local

    def _process_condition_pairs(current: object, node_stack: list[object]) -> bool:
        if not hasattr(current, "condition_and_nodes"):
            return False
        try:
            pairs = _dynamic_c_ast_getattr_8616(current, "condition_and_nodes")
        except Exception:
            pairs = None
        if not pairs:
            return False
        pair_changed = False
        new_pairs = []
        for cond, body in pairs:
            new_cond = transform(cond) if _structured_codegen_node_8616(cond) else cond
            new_body = transform(body) if _structured_codegen_node_8616(body) else body
            if new_cond is not cond or new_body is not body:
                pair_changed = True
            if _structured_codegen_node_8616(new_cond):
                node_stack.append(new_cond)
            if _structured_codegen_node_8616(new_body):
                node_stack.append(new_body)
            new_pairs.append((new_cond, new_body))
        if pair_changed:
            typing.cast(typing.Any, current).condition_and_nodes = new_pairs
        return pair_changed

    def _process_switch_cases(current: object, node_stack: list[object]) -> bool:
        if not hasattr(current, "cases"):
            return False
        try:
            # Dynamic angr codegen boundary: CSwitchCase exposes cases structurally.
            cases = _dynamic_c_ast_getattr_8616(current, "cases")
        except Exception:
            return False
        if not cases:
            return False
        changed_local = False
        new_cases = []
        for item in cases:
            if not isinstance(item, tuple) or len(item) != 2:
                new_cases.append(item)
                continue
            case_value, case_body = item
            new_value = transform(case_value) if _structured_codegen_node_8616(case_value) else case_value
            new_body = transform(case_body) if _structured_codegen_node_8616(case_body) else case_body
            if new_value is not case_value or new_body is not case_body:
                changed_local = True
            if _structured_codegen_node_8616(new_value):
                node_stack.append(new_value)
            if _structured_codegen_node_8616(new_body):
                node_stack.append(new_body)
            new_cases.append((new_value, new_body))
        if changed_local:
            # Dynamic angr codegen boundary: update CSwitchCase child cases.
            typing.cast(typing.Any, current).cases = new_cases
        return changed_local

    if seen is None:
        seen = set()
    changed = False
    node_stack = [node]

    while node_stack:
        current = node_stack.pop()
        if not _structured_codegen_node_8616(current):
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)

        child_attrs = frozenset(_structured_slot_names_8616(current))
        for attr in scalar_attrs:
            if attr not in child_attrs:
                continue
            if _process_scalar_attr(current, attr, node_stack):
                changed = True
        for attr in list_attrs:
            if attr not in child_attrs:
                continue
            if _process_list_attr(current, attr, node_stack):
                changed = True
        if "condition_and_nodes" in child_attrs and _process_condition_pairs(current, node_stack):
            changed = True
        if "cases" in child_attrs and _process_switch_cases(current, node_stack):
            changed = True

    return changed


def _iter_c_nodes_deep_8616(node: object, seen: set[int] | None = None) -> Iterator[object]:
    if seen is None:
        seen = set()
    if not _structured_codegen_node_8616(node):
        return

    node_stack = [node]
    while node_stack:
        current = node_stack.pop()
        if not _structured_codegen_node_8616(current):
            continue
        node_id = id(current)
        if node_id in seen:
            continue
        seen.add(node_id)
        yield current

        for attr in _structured_slot_names_8616(current):
            try:
                value = _dynamic_c_ast_getattr_8616(current, attr)
            except Exception:
                continue
            if _structured_codegen_node_8616(value):
                node_stack.append(value)
            elif isinstance(value, (dict, list, tuple, set)):
                node_stack.extend(_iter_c_node_children_8616(value, set()))


def _global_memory_addr_8616(node: object) -> int | None:
    if not isinstance(node, CVariable):
        return None
    variable = _dynamic_c_ast_getattr_8616(node, "variable", None)
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = _dynamic_c_ast_getattr_8616(variable, "addr", None)
    return addr if isinstance(addr, int) else None


def _make_word_global_8616(codegen: Any, addr: int) -> CVariable:
    from angr.analyses.decompiler.structured_codegen.c import CVariable
    from angr.sim_type import SimTypeShort

    return CVariable(
        SimMemoryVariable(addr, 2, name=f"g_{addr:x}", region=codegen.cfunc.addr),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _same_c_expression_8616(lhs: object, rhs: object) -> bool:
    """Delegate expression identity to the shared typed boundary owner."""
    return _shared_same_c_expression_8616(lhs, rhs)


def _same_call_target_8616(lhs: CFunctionCall, rhs: CFunctionCall) -> bool:
    lhs_func = _dynamic_c_ast_getattr_8616(lhs, "callee_func", None)
    rhs_func = _dynamic_c_ast_getattr_8616(rhs, "callee_func", None)
    if lhs_func is not None or rhs_func is not None:
        if lhs_func is None or rhs_func is None:
            return False
        lhs_addr = _dynamic_c_ast_getattr_8616(lhs_func, "addr", None)
        rhs_addr = _dynamic_c_ast_getattr_8616(rhs_func, "addr", None)
        if isinstance(lhs_addr, int) or isinstance(rhs_addr, int):
            return bool(lhs_addr == rhs_addr)
        return bool(
            _dynamic_c_ast_getattr_8616(lhs_func, "name", None)
            == _dynamic_c_ast_getattr_8616(rhs_func, "name", None)
        )
    lhs_target = _dynamic_c_ast_getattr_8616(lhs, "callee_target", None)
    rhs_target = _dynamic_c_ast_getattr_8616(rhs, "callee_target", None)
    if lhs_target is None or rhs_target is None:
        return lhs_target is rhs_target
    return _same_c_expression_8616(lhs_target, rhs_target)


def _is_shifted_high_byte_8616(high_expr: object, low_expr: object) -> bool:
    if not isinstance(high_expr, CBinaryOp) or high_expr.op != "Shr":
        return False
    if _c_constant_value_8616(high_expr.rhs) != 8:
        return False
    return _same_c_expression_8616(high_expr.lhs, low_expr)


def _single_assignment_expr_for_variable_8616(codegen: object, target: object) -> object | None:
    cfunc = _dynamic_c_ast_getattr_8616(codegen, "cfunc", None)
    root = _dynamic_c_ast_getattr_8616(cfunc, "statements", None)
    if root is None:
        return None

    def _iter_statement_nodes(node: object) -> Iterator[object]:
        stack = [node]
        seen: set[int] = set()
        while stack:
            current = stack.pop()
            if not _structured_codegen_node_8616(current):
                continue
            current_id = id(current)
            if current_id in seen:
                continue
            seen.add(current_id)
            yield current

            nested_statements = _dynamic_c_ast_getattr_8616(current, "statements", None)
            if isinstance(nested_statements, (list, tuple)):
                for item in reversed(tuple(nested_statements)):
                    stack.append(item)  # noqa: PERF402

            body = _dynamic_c_ast_getattr_8616(current, "body", None)
            if body is not None:
                stack.append(body)

            else_node = _dynamic_c_ast_getattr_8616(current, "else_node", None)
            if else_node is not None:
                stack.append(else_node)

            condition_and_nodes = _dynamic_c_ast_getattr_8616(current, "condition_and_nodes", None)
            if isinstance(condition_and_nodes, (list, tuple)):
                for pair in reversed(tuple(condition_and_nodes)):
                    if isinstance(pair, tuple):
                        for item in reversed(pair):
                            stack.append(item)  # noqa: PERF402

    matches = []
    for stmt in _iter_statement_nodes(root):
        if not isinstance(stmt, CAssignment):
            continue
        lhs = _dynamic_c_ast_getattr_8616(stmt, "lhs", None)
        if not isinstance(lhs, CVariable):
            continue
        if not _same_c_expression_8616(lhs, target):
            continue
        matches.append(_dynamic_c_ast_getattr_8616(stmt, "rhs", None))
        if len(matches) > 1:
            return None
    return matches[0] if len(matches) == 1 else None


def _resolve_stack_bp_term_8616(
    node: object,
    project: object | None = None,
    codegen: object | None = None,
    seen: set[int] | None = None,
) -> object:
    def _impl() -> object:
        nonlocal seen
        if seen is None:
            seen = set()
        if id(node) in seen:
            return node
        seen.add(id(node))

        if isinstance(node, CTypeCast):
            resolved = _resolve_stack_bp_term_8616(node.expr, project, codegen, seen)
            return resolved if resolved is not node.expr else node

        if not isinstance(node, CVariable) or codegen is None:
            return node

        variable = _dynamic_c_ast_getattr_8616(node, "variable", None)
        if variable is None:
            return node
        name = _strip_typed_name_suffix_8616(_dynamic_c_ast_getattr_8616(node, "name", None) or _dynamic_c_ast_getattr_8616(variable, "name", None))
        should_follow_single_assignment = _is_linear_temp_name_8616(name)
        if isinstance(variable, SimStackVariable):
            should_follow_single_assignment = True
        if not should_follow_single_assignment:
            return node

        replacement = _single_assignment_expr_for_variable_8616(codegen, node)
        if replacement is None:
            return node
        resolved_replacement = _resolve_stack_bp_term_8616(replacement, project, codegen, seen)
        if isinstance(variable, SimStackVariable):
            stack_disp = _stack_bp_displacement_8616(resolved_replacement, project, codegen, seen=seen)
            if stack_disp is None:
                return node
        return resolved_replacement

    return _impl()


def _stack_bp_displacement_8616(
    node: object,
    project: object | None = None,
    codegen: object | None = None,
    seen: set[int] | None = None,
) -> int | None:
    if seen is None:
        seen = set()
    total = 0
    stack_offsets: list[int] = []
    found_stack_ref = False

    def collect(term: object) -> None:
        nonlocal total
        nonlocal found_stack_ref

        term = _resolve_stack_bp_term_8616(term, project, codegen, seen)

        if isinstance(term, CTypeCast):
            collect(term.expr)
            return

        const = _c_constant_value_8616(term)
        if const is not None:
            total += const
            return

        if isinstance(term, CVariable):
            stack_base_bias = _stack_base_bp_bias_8616(term, codegen)
            if isinstance(stack_base_bias, int):
                stack_offsets.append(stack_base_bias)
                found_stack_ref = True
                return

        if isinstance(term, CUnaryOp) and term.op == "Reference":
            operand = term.operand
            if isinstance(operand, CVariable):
                variable = _dynamic_c_ast_getattr_8616(operand, "variable", None)
                if isinstance(variable, SimStackVariable):
                    offset = _dynamic_c_ast_getattr_8616(variable, "offset", None)
                    if isinstance(offset, int):
                        stack_offsets.append(offset)
                        found_stack_ref = True
                else:
                    stack_base_bias = _stack_base_bp_bias_8616(operand, codegen)
                    if isinstance(stack_base_bias, int):
                        stack_offsets.append(stack_base_bias)
                        found_stack_ref = True
            return

        if project is not None and codegen is not None:
            pointer_offset = _stack_pointer_carrier_offset_8616(term, project, codegen, seen)
            if isinstance(pointer_offset, int):
                stack_offsets.append(pointer_offset)
                found_stack_ref = True
                return

        if isinstance(term, CBinaryOp) and term.op == "Add":
            collect(term.lhs)
            collect(term.rhs)
            return

        if isinstance(term, CBinaryOp) and term.op == "Sub":
            collect(term.lhs)
            rhs_const = _c_constant_value_8616(term.rhs)
            if rhs_const is not None:
                total -= rhs_const
                return
            return

        if isinstance(term, CBinaryOp) and term.op in {"Mul", "Shl"}:
            # Segment-scale terms and byte-widening terms are not part of the bp displacement itself.
            if project is not None:
                seg_name, _linear = _match_real_mode_linear_expr_8616(term, project, codegen)
                if seg_name == "ss":
                    return
            return

        return

    collect(node)
    if not found_stack_ref:
        return None
    if len(stack_offsets) != 1:
        return None
    return stack_offsets[0] + total


def _match_bp_stack_dereference_8616(
    node: object, project: object, codegen: object | None = None
) -> int | None:
    def _impl() -> int | None:
        nonlocal node
        while isinstance(node, CTypeCast):
            node = node.expr
        if not isinstance(node, CUnaryOp) or node.op != "Dereference":
            return None

        operand = node.operand
        while isinstance(operand, CTypeCast):
            operand = operand.expr

        def _flatten_add_sub(term: object, sign: int = 1) -> list[tuple[object, int]]:
            while isinstance(term, CTypeCast):
                term = term.expr
            if isinstance(term, CBinaryOp) and term.op == "Add":
                return _flatten_add_sub(term.lhs, sign) + _flatten_add_sub(term.rhs, sign)
            if isinstance(term, CBinaryOp) and term.op == "Sub":
                return _flatten_add_sub(term.lhs, sign) + _flatten_add_sub(term.rhs, -sign)
            return [(term, sign)]

        terms = _flatten_add_sub(operand)
        if not terms:
            return None

        const_total = 0
        has_ss_segment = False
        non_segment_terms: list[tuple[object, int]] = []
        for term, sign in terms:
            value = _c_constant_value_8616(term)
            if value is not None:
                const_total += sign * value
                continue
            seg_name, linear = _match_real_mode_linear_expr_8616(term, project, codegen)
            if seg_name == "ss":
                has_ss_segment = True
                if isinstance(linear, int):
                    const_total += sign * linear
                continue
            non_segment_terms.append((term, sign))

        if not has_ss_segment:
            return None
        if len(non_segment_terms) != 1:
            return None

        addr_term, sign = non_segment_terms[0]
        if sign != 1:
            return None
        base_disp = _stack_bp_displacement_8616(addr_term, project, codegen)
        if base_disp is None:
            return None
        return base_disp + const_total

    return _impl()


def _match_bp_stack_load_8616(node: object, project: object, codegen: object | None = None) -> int | None:
    def _impl() -> int | None:
        direct = _match_bp_stack_dereference_8616(node, project, codegen)
        if direct is not None:
            return direct

        if not isinstance(node, CBinaryOp):
            return None

        if node.op == "Mul":
            pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
            for maybe_load, maybe_scale in pairs:
                if _c_constant_value_8616(maybe_scale) != 0x100:
                    continue
                direct = _match_bp_stack_dereference_8616(maybe_load, project)
                if direct is not None:
                    return direct

        if node.op == "Shl":
            pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
            for maybe_load, maybe_scale in pairs:
                if _c_constant_value_8616(maybe_scale) != 8:
                    continue
                direct = _match_bp_stack_dereference_8616(maybe_load, project, codegen)
                if direct is not None:
                    return direct

        return None

    return _impl()
