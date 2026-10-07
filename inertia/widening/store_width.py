"""Typed store-width joins after alias compatibility proof.

Layer: Widening.
Responsibility: owns typed store-width joins after alias compatibility proof.
Consumes alias-proven storage identity and instruction width evidence before
coalescing byte/word stores.
Do not join values from rendered text, cosmetic shape, postprocess, or
CLI/reporting evidence.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, TypeGuard, cast

import angr
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable


class _SegmentedGlobalAccessLike8616(Protocol):
    """Structural view of lowering-owned segmented global access classifications."""

    kind: str
    linear: int | None


def _is_segmented_global_access_8616(value: object) -> TypeGuard[_SegmentedGlobalAccessLike8616]:
    """Return whether a dynamic angr/codegen boundary result names a linear global access."""
    kind = getattr(value, "kind", None)
    linear = getattr(value, "linear", None)
    return kind == "global" and isinstance(linear, int)


def _global_memory_addr(node: object) -> int | None:
    """Read a global address from dynamic angr/codegen boundary CVariable metadata."""
    if not isinstance(node, structured_c.CVariable):
        return None
    variable = getattr(node, "variable", None)
    if not isinstance(variable, SimMemoryVariable):
        return None
    addr = getattr(variable, "addr", None)
    return addr if isinstance(addr, int) else None


def _global_load_addr(node: object, _project: angr.Project) -> int | None:
    return _global_memory_addr(node)


def _match_scaled_high_byte(
    node: object,
    project: angr.Project,
    *,
    c_constant_value: Callable[[object], object],
    global_load_addr: Callable[[object, angr.Project], int | None],
) -> int | None:
    if not isinstance(node, structured_c.CBinaryOp):
        return None

    if node.op == "Mul":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if c_constant_value(maybe_scale) != 0x100:
                continue
            addr = global_load_addr(maybe_load, project)
            if addr is not None:
                return addr

    if node.op == "Shl":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if c_constant_value(maybe_scale) != 8:
                continue
            addr = global_load_addr(maybe_load, project)
            if addr is not None:
                return addr

    return None


def _extract_dereference_addr_expr(node: object) -> object | None:
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        return None
    operand = node.operand
    if isinstance(operand, structured_c.CTypeCast):
        return cast(object, operand.expr)
    return cast(object, operand)


def _safe_type_bits(node: object) -> int | None:
    """Read bit width from dynamic angr/codegen boundary C AST type metadata."""
    try:
        return getattr(getattr(node, "type", None), "size", None)
    except ValueError:
        return None


def _match_byte_load_addr_expr(node: object, *, unwrap_c_casts: Callable[[object], object]) -> object | None:
    node = unwrap_c_casts(node)
    addr_expr = _extract_dereference_addr_expr(node)
    if addr_expr is None:
        return None
    bits = _safe_type_bits(unwrap_c_casts(node))
    if bits not in {8, None}:
        return None
    return addr_expr


def _match_byte_store_addr_expr(node: object) -> object | None:
    addr_expr = _extract_dereference_addr_expr(node)
    if addr_expr is None:
        return None
    bits = _safe_type_bits(node)
    if bits not in {8, 16, None}:
        return None
    return addr_expr


def _match_shifted_high_byte_addr_expr(
    node: object,
    *,
    unwrap_c_casts: Callable[[object], object],
    c_constant_value: Callable[[object], object],
    match_byte_load_addr_expr: Callable[[object], object | None],
) -> object | None:
    node = unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return None

    if node.op == "Mul":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if c_constant_value(unwrap_c_casts(maybe_scale)) == 0x100:
                return match_byte_load_addr_expr(unwrap_c_casts(maybe_load))

    if node.op == "Shl":
        pairs = ((node.lhs, node.rhs), (node.rhs, node.lhs))
        for maybe_load, maybe_scale in pairs:
            if c_constant_value(unwrap_c_casts(maybe_scale)) == 8:
                return match_byte_load_addr_expr(unwrap_c_casts(maybe_load))

    return None


def _addr_exprs_are_same_or_byte_pair(
    low_addr_expr: object,
    high_addr_expr: object,
    project: angr.Project,
    *,
    addr_exprs_are_same: Callable[[object, object, angr.Project], bool],
    addr_exprs_are_byte_pair: Callable[[object, object, angr.Project], bool],
) -> tuple[bool, bool]:
    return (
        addr_exprs_are_same(low_addr_expr, high_addr_expr, project),
        addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project),
    )


def _match_word_pair_low_addr_expr(
    node: object,
    project: angr.Project,
    *,
    unwrap_c_casts: Callable[[object], object],
    match_byte_load_addr_expr: Callable[[object], object | None],
    match_shifted_high_byte_addr_expr: Callable[[object], object | None],
    addr_exprs_are_byte_pair: Callable[[object, object, angr.Project], object],
) -> object | None:
    node = unwrap_c_casts(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op not in {"Or", "Add"}:
        return None

    for low_expr, high_expr in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        low_addr_expr = match_byte_load_addr_expr(unwrap_c_casts(low_expr))
        high_addr_expr = match_shifted_high_byte_addr_expr(high_expr)
        if low_addr_expr is None or high_addr_expr is None:
            continue
        if addr_exprs_are_byte_pair(low_addr_expr, high_addr_expr, project):
            return low_addr_expr

    return None


def _make_word_dereference_from_addr_expr(
    codegen: object, project: angr.Project, addr_expr: object
) -> structured_c.CUnaryOp:
    word_type = SimTypeShort(False)
    ptr_type = SimTypePointer(word_type).with_arch(project.arch)
    typed_addr_expr = cast(structured_c.CExpression, addr_expr)
    return structured_c.CUnaryOp(
        "Dereference",
        structured_c.CTypeCast(None, ptr_type, typed_addr_expr, codegen=codegen),
        codegen=codegen,
    )


def _match_word_dereference_addr_expr(node: object) -> object | None:
    addr_expr = _extract_dereference_addr_expr(node)
    if addr_expr is None:
        return None
    bits = _safe_type_bits(node)
    if bits != 16:
        return None
    return addr_expr


def _high_byte_store_addr(
    node: object,
    project: angr.Project,
    *,
    classify_segmented_dereference: Callable[[object, angr.Project], object],
) -> int | None:
    classified = classify_segmented_dereference(node, project)
    if not _is_segmented_global_access_8616(classified):
        return None
    return classified.linear
