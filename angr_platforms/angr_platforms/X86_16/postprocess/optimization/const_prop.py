"""Layer: Rewrite/Postprocess cleanup.

Responsibility: fold constant expressions after semantics are already proven.
Consumes already-proven IR, alias, widening, typed, and structuring facts.
Do not recover new semantics, storage identity, types, call signatures, control flow, or facts from rendered text, COD, source, or CLI/reporting evidence here.
The codegen and C AST objects cross a dynamic third-party angr boundary; keep
dynamic attribute access limited to preserving existing C AST codegen metadata.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator

from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CStatements,
    CUnaryOp,
)
from angr.sim_type import SimTypeInt

from ...decompiler_postprocess_utils import _c_constant_value_8616


def _iter_c_statements_safe_8616(node: object) -> Iterator[object]:
    """Yield individual CStatements, descending into CStatements containers."""
    if isinstance(node, CStatements):
        for stmt in node.statements:
            yield from _iter_c_statements_safe_8616(stmt)
        return
    if isinstance(node, (list, tuple)):
        for item in node:
            yield from _iter_c_statements_safe_8616(item)
        return
    yield node


# Default type for 86_16 constant folding: unsigned 16-bit int
_CONST_DEFAULT_TYPE = SimTypeInt(signed=False)

_CONST_PROP_BINARY_OPS: dict[str, Callable[[int, int], int | None]] = {
    "Add": lambda a, b: a + b,
    "Sub": lambda a, b: a - b,
    "Mul": lambda a, b: a * b,
    "And": lambda a, b: a & b,
    "Or": lambda a, b: a | b,
    "Xor": lambda a, b: a ^ b,
    "Shl": lambda a, b: a << b if 0 <= b < 16 else None,
    "Shr": lambda a, b: a >> b if 0 <= b < 16 else None,
    "Div": lambda a, b: a // b if b != 0 else None,
}


def _folded_constant_8616(value: int, *, codegen: object | None = None) -> CConstant:
    """Build the 16-bit default typed constant used by cleanup folding."""
    return CConstant(int(value), _CONST_DEFAULT_TYPE, codegen=codegen)


def _is_const_expr(node: object) -> bool:
    """Return whether an already-recovered C AST expression is constant-only."""
    if isinstance(node, CConstant):
        return True
    if isinstance(node, CBinaryOp):
        return _is_const_expr(node.lhs) and _is_const_expr(node.rhs)
    if isinstance(node, CUnaryOp) and node.op in ("Neg", "Not"):
        return _is_const_expr(node.operand)
    return False


def _eval_const_expr(node: object) -> int | None:
    """Evaluate a constant-only C AST expression without inferring new facts."""

    def _impl() -> int | None:
        if isinstance(node, CConstant):
            return _c_constant_value_8616(node)
        if isinstance(node, CBinaryOp):
            a = _eval_const_expr(node.lhs)
            b = _eval_const_expr(node.rhs)
            if a is None or b is None:
                return None
            fn = _CONST_PROP_BINARY_OPS.get(node.op)
            if fn is None:
                return None
            return fn(a, b)
        if isinstance(node, CUnaryOp):
            operand = _eval_const_expr(node.operand)
            if operand is None:
                return None
            if node.op == "Neg":
                return -operand
            if node.op == "Not":
                return int(not operand)
        return None

    return _impl()


def _fold_binary_op_8616(node: CBinaryOp, node_codegen: object | None) -> bool:
    """Fold a binary operator node across the dynamic third-party angr C AST boundary."""
    a_val = _eval_const_expr(node.lhs)
    b_val = _eval_const_expr(node.rhs)
    if a_val is not None and b_val is not None:
        fn = _CONST_PROP_BINARY_OPS.get(node.op)
        if fn is not None:
            result = fn(a_val, b_val)
            if result is not None:
                node.lhs = _folded_constant_8616(result, codegen=node_codegen)
                node.rhs = _folded_constant_8616(0, codegen=node_codegen)
                node.op = "Add"
                return True

    # Fold: X + 0 → X, X - 0 → X
    if isinstance(node.rhs, CConstant):
        rhs_val = _c_constant_value_8616(node.rhs)
        if rhs_val == 0 and node.op in ("Add", "Sub"):
            return True
    return False


def _fold_unary_op_8616(node: CUnaryOp, node_codegen: object | None) -> bool:
    """Fold a unary operator node across the dynamic third-party angr C AST boundary."""
    operand_val = _eval_const_expr(node.operand)
    if operand_val is None:
        return False
    if node.op == "Neg":
        node.operand = _folded_constant_8616(-operand_val, codegen=node_codegen)
        return True
    if node.op == "Not":
        node.operand = _folded_constant_8616(int(not operand_val), codegen=node_codegen)
        return True
    return False


def _fold_constants_in_node(node: object, *, codegen: object | None = None) -> bool:
    """Fold constant sub-expressions in one C AST node."""
    node_codegen = getattr(node, "codegen", None) or codegen
    if isinstance(node, CBinaryOp):
        return _fold_binary_op_8616(node, node_codegen)
    if isinstance(node, CUnaryOp):
        return _fold_unary_op_8616(node, node_codegen)
    return False


def _constant_propagation_8616(stmts: object, codegen: object | None = None) -> bool:
    """Fold constant sub-expressions in C statements."""
    changed = False
    for stmt in _iter_c_statements_safe_8616(stmts):
        if _fold_constants_in_node(stmt, codegen=codegen):
            changed = True
    return changed
