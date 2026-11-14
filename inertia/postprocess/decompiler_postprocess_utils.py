# cython: language_level=3, infer_types=True
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

Package ownership contract (canonical inertia/postprocess package):
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from
rendered text, COD, source, or CLI/reporting evidence here.
"""

from __future__ import annotations
import cython

import builtins
import re
import typing
from collections.abc import Callable, Iterator
from contextlib import suppress
from dataclasses import dataclass, field
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

from inertia.lowering.c_ast_utils import (
    _safe_assign_cfunc_statements_8616,
    _structured_codegen_node_8616,
)
from inertia.lowering.c_ast_utils import _same_c_expression_8616 as _shared_same_c_expression_8616
from inertia.lowering.real_mode_linear import _stack_base_bp_bias_8616, _stack_pointer_carrier_offset_8616
import dataclasses
import operator

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


@cython.ccall
def _dynamic_c_ast_getattr_8616(obj: object, name: object, default: object = None) -> Any:
    """Read an attribute across the dynamic angr codegen/C AST boundary."""
    return builtins.getattr(obj, name, default)


@cython.ccall
def _dynamic_c_ast_setattr_8616(obj: object, name: object, value: object) -> None:
    """Set an attribute across the dynamic angr codegen/C AST boundary."""
    builtins.setattr(obj, name, value)


@cython.ccall
def _strip_typed_name_suffix_8616(name: object) -> object:
    if not isinstance(name, str):
        return None
    if name.endswith("}"):
        brace_pos = name.find("{")
        if brace_pos >= 0:
            return name[:brace_pos]
    return name


@cython.ccall
def _is_linear_temp_name_8616(name: object) -> cython.bint:
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


@cython.ccall
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
    attr: object
    cls: object
    slot: object
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
                attrs.append(slot)

    seen = set()
    ordered: list[str] = []
    for attr in attrs:
        if attr in seen:
            continue
        seen.add(attr)
        ordered.append(attr)
    return tuple(ordered)


def _structured_slot_names_8616(value: object) -> object:
    def _impl() -> object:
        child_attrs: object
        attr: object
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
            for attr in iter(dynamic_keys)
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


def _iter_c_node_children_8616(value: object, seen_values: object = None) -> Iterator[object]:
    current: object
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


@cython.ccall
def _c_constant_value_8616(node: object) -> int | None:
    if isinstance(node, CConstant) and isinstance(node.value, int):
        return node.value
    return None


@cython.ccall
def _segment_reg_name_8616(node: object, project: object) -> object:
    reg_name: object
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


@cython.ccall
def _segment_scale_term_8616(
    expr: object,
    expected_op: object,
    expected_scale: cython.longlong,
    resolve: Callable[[object], object],
    project: object,
) -> object:
    """Match ``expr op scale`` shaped segment terms; first named base wins."""
    seg_name: object
    maybe_scale: object
    maybe_seg: object
    if not isinstance(expr, CBinaryOp) or operator.ne(expr.op, expected_op):
        return None
    for maybe_seg, maybe_scale in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
        if operator.ne(_c_constant_value_8616(maybe_scale), expected_scale):
            continue
        seg_name = _segment_reg_name_8616(resolve(maybe_seg), project)
        if seg_name is not None:
            return seg_name
    return None


@cython.ccall
def _match_linear_add_term_8616(
    node: CBinaryOp,
    resolve: Callable[[object], object],
    project: object,
) -> tuple[str | None, int | None]:
    """Match ``seg*16 + linear`` / ``seg<<4 + linear`` add-shaped addresses."""
    linear: object
    seg_name: object
    maybe_const: object
    maybe_mul: object
    for maybe_mul, maybe_const in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        linear = _c_constant_value_8616(maybe_const)
        if linear is None:
            continue
        maybe_mul = resolve(maybe_mul)
        if not isinstance(maybe_mul, CBinaryOp):
            continue
        seg_name = _segment_scale_term_8616(maybe_mul, "Mul", 16, resolve, project)
        if seg_name is None:
            seg_name = _segment_scale_term_8616(maybe_mul, "Shl", 4, resolve, project)
        if seg_name is not None:
            return seg_name, linear
    return None, None


def _match_real_mode_linear_expr_8616(
    node: object, project: object, codegen: object | None = None
) -> object:
    seg_name: object
    def resolve(term: object) -> object:
        if codegen is None:
            return term
        return _resolve_stack_bp_term_8616(term, project, codegen)

    seg_name = _segment_scale_term_8616(node, "Shl", 4, resolve, project)
    if seg_name is not None:
        return seg_name, 0
    seg_name = _segment_scale_term_8616(node, "Mul", 16, resolve, project)
    if seg_name is not None:
        return seg_name, 0

    if not isinstance(node, CBinaryOp) or node.op != "Add":
        return None, None
    return _match_linear_add_term_8616(node, resolve, project)


@cython.ccall
def _strip_c_casts_8616(expr: object) -> object:
    """Unwrap nested CTypeCast nodes to their underlying expression."""
    while isinstance(expr, CTypeCast):
        expr = expr.expr
    return expr


@cython.ccall
def _segment_base_name_8616(expr: object, project: object) -> object:
    """Name the segment register of a ``seg<<4``/``seg*16`` shaped term."""
    maybe_scale: object
    maybe_seg: object
    expr = _strip_c_casts_8616(expr)
    if isinstance(expr, CBinaryOp) and expr.op == "Shl":
        for maybe_seg, maybe_scale in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
            if _c_constant_value_8616(maybe_scale) == 4:
                return _segment_reg_name_8616(maybe_seg, project)
    if isinstance(expr, CBinaryOp) and expr.op == "Mul":
        for maybe_seg, maybe_scale in ((expr.lhs, expr.rhs), (expr.rhs, expr.lhs)):
            if _c_constant_value_8616(maybe_scale) == 16:
                return _segment_reg_name_8616(maybe_seg, project)
    return None


@cython.ccall
def _collect_signed_terms_8616(
    expr: object, sign: cython.longlong, out: object
) -> None:
    """Flatten an Add/Sub tree into ``(sign, leaf-term)`` pairs."""
    expr = _strip_c_casts_8616(expr)
    if isinstance(expr, CBinaryOp) and expr.op == "Add":
        _collect_signed_terms_8616(expr.lhs, sign, out)
        _collect_signed_terms_8616(expr.rhs, sign, out)
        return
    if isinstance(expr, CBinaryOp) and expr.op == "Sub":
        _collect_signed_terms_8616(expr.lhs, sign, out)
        _collect_signed_terms_8616(expr.rhs, -sign, out)
        return
    out.append((sign, expr))


@cython.ccall
def _match_real_mode_segmented_store_shape_8616(
    node: object, project: object
) -> tuple[str | None, tuple[tuple[cython.longlong, object], ...]]:
    """Match a real-mode dereference shaped as one segment base plus explicit offset terms.

    This stays stricter than "lhs contains ss somewhere": the node must be a real
    memory dereference and its address must decompose into exactly one positive
    segment-base term plus zero or more signed offset terms.
    """
    base_name: object
    segment_name: object
    sign: object
    term: object
    node = _strip_c_casts_8616(node)
    if not isinstance(node, CUnaryOp) or node.op != "Dereference":
        return None, ()

    signed_terms: list[tuple[cython.longlong, object]] = []
    _collect_signed_terms_8616(node.operand, 1, signed_terms)

    segment_name = None
    offset_terms: list[tuple[cython.longlong, object]] = []
    for sign, term in signed_terms:
        base_name = _segment_base_name_8616(term, project)
        if base_name is None:
            offset_terms.append((sign, term))
            continue
        if sign != 1 or segment_name is not None:
            return None, ()
        segment_name = base_name

    if segment_name is None:
        return None, ()
    return segment_name, tuple(offset_terms)


@cython.ccall
def _match_segmented_dereference_8616(node: object, project: object) -> object:
    while isinstance(node, CTypeCast):
        node = node.expr
    if not isinstance(node, CUnaryOp) or node.op != "Dereference":
        return None, None
    operand = node.operand
    while isinstance(operand, CTypeCast):
        operand = operand.expr
    return _match_real_mode_linear_expr_8616(operand, project)


_C_SCALAR_CHILD_ATTRS_8616 = (
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
_C_LIST_CHILD_ATTRS_8616 = ("args", "operands", "statements")


@cython.ccall
def _process_scalar_c_child_8616(
    current: object,
    attr: object,
    node_stack: object,
    transform: Callable[[object], object],
    should_process_child: object,
) -> cython.bint:
    """Transform one scalar C-AST child slot and push it for traversal."""
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


@cython.ccall
def _process_list_c_child_8616(
    current: object,
    attr: object,
    node_stack: object,
    transform: Callable[[object], object],
) -> cython.bint:
    """Transform one list-valued C-AST child slot in place."""
    new_items: object
    idx: object
    item: object
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


@cython.ccall
def _process_condition_pair_children_8616(
    current: object,
    node_stack: object,
    transform: Callable[[object], object],
) -> cython.bint:
    """Transform CIfElse-style condition/body pairs and queue the nodes."""
    body: object
    cond: object
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


@cython.ccall
def _process_switch_case_children_8616(
    current: object,
    node_stack: object,
    transform: Callable[[object], object],
) -> cython.bint:
    """Transform CSwitchCase case value/body pairs and queue the nodes."""
    item: object
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


@cython.ccall
def _replace_one_c_node_children_8616(
    current: object,
    child_attrs: object,
    node_stack: object,
    transform: Callable[[object], object],
    should_process_child: Callable[[object, str], bool] | None,
) -> cython.bint:
    """Transform all declared child slots of one structured C node."""
    attr: object
    changed = False
    for attr in _C_SCALAR_CHILD_ATTRS_8616:
        if attr not in child_attrs:
            continue
        if _process_scalar_c_child_8616(current, attr, node_stack, transform, should_process_child):
            changed = True
    for attr in _C_LIST_CHILD_ATTRS_8616:
        if attr not in child_attrs:
            continue
        if _process_list_c_child_8616(current, attr, node_stack, transform):
            changed = True
    if "condition_and_nodes" in child_attrs and _process_condition_pair_children_8616(current, node_stack, transform):
        changed = True
    if "cases" in child_attrs and _process_switch_case_children_8616(current, node_stack, transform):
        changed = True
    return changed


@cython.ccall
def _replace_c_children_8616(
    node: object,
    transform: Callable[[object], object],
    seen: object = None,
    *,
    should_process_child: Callable[[object, str], bool] | None = None,
) -> cython.bint:
    current: object
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
        if _replace_one_c_node_children_8616(
            current, child_attrs, node_stack, transform, should_process_child
        ):
            changed = True

    return changed


def _iter_c_nodes_deep_8616(node: object, seen: object = None) -> Iterator[object]:
    current: object
    attr: object
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


@cython.ccall
def _global_memory_addr_8616(node: object) -> int | None:
    if not isinstance(node, CVariable):
        return None
    variable = _dynamic_c_ast_getattr_8616(node, "variable", None)
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = _dynamic_c_ast_getattr_8616(variable, "addr", None)
    return addr if isinstance(addr, int) else None


@cython.ccall
def _make_word_global_8616(codegen: Any, addr: cython.longlong) -> CVariable:
    from angr.analyses.decompiler.structured_codegen.c import CVariable
    from angr.sim_type import SimTypeShort

    return CVariable(
        SimMemoryVariable(addr, 2, name=f"g_{addr:x}", region=codegen.cfunc.addr),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


@cython.ccall
def _same_c_expression_8616(lhs: object, rhs: object) -> cython.bint:
    """Delegate expression identity to the shared typed boundary owner."""
    return _shared_same_c_expression_8616(lhs, rhs)


@cython.ccall
def _same_call_target_8616(lhs: CFunctionCall, rhs: CFunctionCall) -> cython.bint:
    lhs_func: object
    lhs_target: object
    rhs_func: object
    rhs_target: object
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
            operator.eq(_dynamic_c_ast_getattr_8616(lhs_func, "name", None), _dynamic_c_ast_getattr_8616(rhs_func, "name", None))
        )
    lhs_target = _dynamic_c_ast_getattr_8616(lhs, "callee_target", None)
    rhs_target = _dynamic_c_ast_getattr_8616(rhs, "callee_target", None)
    if lhs_target is None or rhs_target is None:
        return lhs_target is rhs_target
    return _same_c_expression_8616(lhs_target, rhs_target)


@cython.ccall
def _is_shifted_high_byte_8616(high_expr: object, low_expr: object) -> cython.bint:
    if not isinstance(high_expr, CBinaryOp) or high_expr.op != "Shr":
        return False
    if _c_constant_value_8616(high_expr.rhs) != 8:
        return False
    return _same_c_expression_8616(high_expr.lhs, low_expr)


@cython.ccall
def _push_statement_children_8616(current: object, stack: object) -> None:
    """Queue the statement-bearing slots of one structured node."""
    body: object
    else_node: object
    item: object
    pair: object
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


def _iter_statement_nodes_8616(node: object) -> Iterator[object]:
    """Depth-first iteration over statement-bearing structured codegen slots."""
    current: object
    stack = [node]
    seen: set[cython.longlong] = set()
    while stack:
        current = stack.pop()
        if not _structured_codegen_node_8616(current):
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        yield current
        _push_statement_children_8616(current, stack)


@cython.ccall
def _single_assignment_expr_for_variable_8616(codegen: object, target: object) -> object | None:
    root: object
    stmt: object
    cfunc = _dynamic_c_ast_getattr_8616(codegen, "cfunc", None)
    root = _dynamic_c_ast_getattr_8616(cfunc, "statements", None)
    if root is None:
        return None

    matches = []
    for stmt in _iter_statement_nodes_8616(root):
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


@cython.ccall
def _resolve_variable_bp_term_8616(
    node: CVariable,
    project: object | None,
    codegen: object,
    seen: object,
) -> object:
    """Follow a single-assignment variable toward its defining BP term."""
    replacement: object
    stack_disp: object
    variable: object
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


@cython.ccall
def _resolve_stack_bp_term_8616(
    node: object,
    project: object | None = None,
    codegen: object | None = None,
    seen: object = None,
) -> object:
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

    return _resolve_variable_bp_term_8616(node, project, codegen, seen)


@cython.dataclasses.dataclass
class _StackBpDispCollect8616:
    """Accumulate the BP-relative displacement of one address expression."""

    project: object | None
    codegen: object | None
    seen: object
    total: cython.longlong = 0
    stack_offsets: object = field(default_factory=list)
    found_stack_ref: cython.bint = False

    @cython.ccall
    def collect(self, term: object) -> None:
        """Fold one address term into the displacement total and stack-offset list."""
        const: object
        term = _resolve_stack_bp_term_8616(term, self.project, self.codegen, self.seen)

        if isinstance(term, CTypeCast):
            self.collect(term.expr)
            return

        const = _c_constant_value_8616(term)
        if const is not None:
            self.total += const
            return

        if self._collect_reference(term):
            return
        if self._collect_pointer_carrier(term):
            return
        self._collect_binary(term)

    @cython.ccall
    def _collect_reference(self, term: object) -> cython.bint:
        if isinstance(term, CVariable):
            stack_base_bias = _stack_base_bp_bias_8616(term, self.codegen)
            if isinstance(stack_base_bias, int):
                self.stack_offsets.append(stack_base_bias)
                self.found_stack_ref = True
                return True

        if not isinstance(term, CUnaryOp) or term.op != "Reference":
            return False
        operand = term.operand
        if isinstance(operand, CVariable):
            variable = _dynamic_c_ast_getattr_8616(operand, "variable", None)
            if isinstance(variable, SimStackVariable):
                offset = _dynamic_c_ast_getattr_8616(variable, "offset", None)
                if isinstance(offset, int):
                    self.stack_offsets.append(offset)
                    self.found_stack_ref = True
            else:
                stack_base_bias = _stack_base_bp_bias_8616(operand, self.codegen)
                if isinstance(stack_base_bias, int):
                    self.stack_offsets.append(stack_base_bias)
                    self.found_stack_ref = True
        return True

    @cython.ccall
    def _collect_pointer_carrier(self, term: object) -> cython.bint:
        if self.project is None or self.codegen is None:
            return False
        pointer_offset = _stack_pointer_carrier_offset_8616(term, self.project, self.codegen, self.seen)
        if isinstance(pointer_offset, int):
            self.stack_offsets.append(pointer_offset)
            self.found_stack_ref = True
            return True
        return False

    @cython.ccall
    def _collect_binary(self, term: object) -> None:
        rhs_const: object
        if isinstance(term, CBinaryOp) and term.op == "Add":
            self.collect(term.lhs)
            self.collect(term.rhs)
            return

        if isinstance(term, CBinaryOp) and term.op == "Sub":
            self.collect(term.lhs)
            rhs_const = _c_constant_value_8616(term.rhs)
            if rhs_const is not None:
                self.total -= rhs_const
            return

        if isinstance(term, CBinaryOp) and term.op in {"Mul", "Shl"}:
            # Segment-scale terms and byte-widening terms are not part of the bp displacement itself.
            if self.project is not None:
                _match_real_mode_linear_expr_8616(term, self.project, self.codegen)
            return


@cython.ccall
def _stack_bp_displacement_8616(
    node: object,
    project: object | None = None,
    codegen: object | None = None,
    seen: object = None,
) -> int | None:
    if seen is None:
        seen = set()
    collect = _StackBpDispCollect8616(project=project, codegen=codegen, seen=seen)
    collect.collect(node)
    if not collect.found_stack_ref:
        return None
    if len(collect.stack_offsets) != 1:
        return None
    return collect.stack_offsets[0] + collect.total


@cython.ccall
def _flatten_add_sub_terms_8616(term: object, sign: cython.longlong = 1) -> object:
    """Flatten an Add/Sub tree into ``(leaf-term, sign)`` pairs."""
    while isinstance(term, CTypeCast):
        term = term.expr
    if isinstance(term, CBinaryOp) and term.op == "Add":
        return _flatten_add_sub_terms_8616(term.lhs, sign) + _flatten_add_sub_terms_8616(term.rhs, sign)
    if isinstance(term, CBinaryOp) and term.op == "Sub":
        return _flatten_add_sub_terms_8616(term.lhs, sign) + _flatten_add_sub_terms_8616(term.rhs, -sign)
    return [(term, sign)]


@cython.ccall
def _classify_deref_terms_8616(
    terms: object, project: object, codegen: object | None
) -> tuple[cython.longlong, cython.bint, list[tuple[object, cython.longlong]]]:
    """Split flattened terms into constant total, ss-segment flag, and rest."""
    value: object
    sign: object
    term: object
    const_total = 0
    has_ss_segment = False
    non_segment_terms: list[tuple[object, cython.longlong]] = []
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
    return const_total, has_ss_segment, non_segment_terms


@cython.ccall
def _match_bp_stack_dereference_8616(
    node: object, project: object, codegen: object | None = None
) -> int | None:
    base_disp: object
    node = _strip_c_casts_8616(node)
    if not isinstance(node, CUnaryOp) or node.op != "Dereference":
        return None

    operand = _strip_c_casts_8616(node.operand)
    terms = _flatten_add_sub_terms_8616(operand)
    if not terms:
        return None

    const_total, has_ss_segment, non_segment_terms = _classify_deref_terms_8616(terms, project, codegen)

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


@cython.ccall
def _scaled_deref_bp_disp_8616(
    node: CBinaryOp,
    expected_op: object,
    expected_scale: cython.longlong,
    project: object,
    codegen: object | None,
) -> int | None:
    """Match ``deref * scale`` / ``deref << bits`` shaped BP stack loads."""
    direct: object
    maybe_load: object
    maybe_scale: object
    if operator.ne(node.op, expected_op):
        return None
    for maybe_load, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        if operator.ne(_c_constant_value_8616(maybe_scale), expected_scale):
            continue
        direct = _match_bp_stack_dereference_8616(maybe_load, project, codegen)
        if direct is not None:
            return direct
    return None


@cython.ccall
def _match_bp_stack_load_8616(node: object, project: object, codegen: object | None = None) -> int | None:
    direct: object
    direct = _match_bp_stack_dereference_8616(node, project, codegen)
    if direct is not None:
        return direct

    if not isinstance(node, CBinaryOp):
        return None

    # The Mul arm intentionally resolves without a codegen context.
    direct = _scaled_deref_bp_disp_8616(node, "Mul", 0x100, project, None)
    if direct is not None:
        return direct
    return _scaled_deref_bp_disp_8616(node, "Shl", 8, project, codegen)
