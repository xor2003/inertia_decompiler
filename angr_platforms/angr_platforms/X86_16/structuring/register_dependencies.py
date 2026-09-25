"""Resolve proven same-block data-register dependencies for return expressions.

Layer: Structuring.
Responsibility: replace AIL data-register reads with their unique reaching
same-block assignments before a return expression is structured.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.

This module does not infer stack identity, segmented addresses, types, or
calling conventions. Memory addresses are deliberately opaque here; later
lowering owns their conversion to typed ``Address``/stack variables.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from angr import ailment
from angr.ailment.expression import Expression

type RegisterNameResolver8616 = Callable[[object], str | None]
type TemporaryResolver8616 = Callable[[object, Sequence[object], int], object]
type ExpressionCopier8616 = Callable[[object], object]

_DATA_REGISTERS_8616 = frozenset(
    {
        "ax",
        "bx",
        "cx",
        "dx",
        "al",
        "ah",
        "bl",
        "bh",
        "cl",
        "ch",
        "dl",
        "dh",
    }
)


def _register_view_8616(expr: object) -> tuple[int, int] | None:
    """Return the byte interval for one concrete AIL register expression."""
    if not isinstance(expr, ailment.Expr.Register):
        return None
    if not isinstance(expr.reg_offset, int) or not isinstance(expr.bits, int) or expr.bits <= 0:
        return None
    return expr.reg_offset, max(expr.bits // 8, 1)


def _register_views_overlap_8616(lhs: tuple[int, int], rhs: tuple[int, int]) -> bool:
    """Return whether two byte-addressed register views overlap."""
    lhs_start, lhs_size = lhs
    rhs_start, rhs_size = rhs
    return lhs_start < rhs_start + rhs_size and rhs_start < lhs_start + lhs_size


def _reaching_register_source_8616(
    expr: ailment.Expr.Register,
    statements: Sequence[object],
    *,
    before_index: int,
    resolve_temporaries: TemporaryResolver8616,
) -> tuple[object, int] | None:
    """Find one exact reaching definition, refusing calls and partial writes."""
    wanted = _register_view_8616(expr)
    if wanted is None:
        return None
    for index in range(before_index - 1, -1, -1):
        statement = statements[index]
        if isinstance(statement, ailment.Stmt.SideEffectStatement) and isinstance(statement.expr, ailment.Expr.Call):
            return None
        if not isinstance(statement, ailment.Stmt.Assignment):
            continue
        if isinstance(statement.src, ailment.Expr.Call):
            return None
        written = _register_view_8616(statement.dst)
        if written is None or not _register_views_overlap_8616(wanted, written):
            continue
        if written != wanted:
            return None
        return resolve_temporaries(statement.src, statements, index), index
    return None


def resolve_same_block_data_register_dependencies_8616(
    expr: object,
    statements: Sequence[object],
    *,
    before_index: int,
    register_name: RegisterNameResolver8616,
    resolve_temporaries: TemporaryResolver8616,
    copy_expression: ExpressionCopier8616,
    active_views: frozenset[tuple[int, int]] = frozenset(),
    depth: int = 0,
) -> object:
    """Substitute exact reaching data-register assignments in an AIL expression.

    Ambiguous, overlapping, cyclic, call-clobbered, and non-data-register reads
    are retained unchanged. ``Load.addr`` is not traversed because segmented
    address identity belongs to lowering rather than return structuring.
    """
    if depth > 8 or expr is None:
        return expr
    if isinstance(expr, ailment.Expr.Register):
        return _resolve_register_leaf_8616(
            expr,
            statements,
            before_index=before_index,
            register_name=register_name,
            resolve_temporaries=resolve_temporaries,
            copy_expression=copy_expression,
            active_views=active_views,
            depth=depth,
        )
    if isinstance(expr, ailment.Expr.Load):
        return expr
    return _resolve_composite_children_8616(
        expr,
        statements,
        before_index=before_index,
        register_name=register_name,
        resolve_temporaries=resolve_temporaries,
        copy_expression=copy_expression,
        active_views=active_views,
        depth=depth,
    )


def _resolve_register_leaf_8616(
    expr: ailment.Expr.Register,
    statements: Sequence[object],
    *,
    before_index: int,
    register_name: RegisterNameResolver8616,
    resolve_temporaries: TemporaryResolver8616,
    copy_expression: ExpressionCopier8616,
    active_views: frozenset[tuple[int, int]],
    depth: int,
) -> object:
    """Substitute one proven reaching source for a data-register leaf."""
    view = _register_view_8616(expr)
    if view is None or view in active_views or register_name(expr) not in _DATA_REGISTERS_8616:
        return expr
    reaching = _reaching_register_source_8616(
        expr,
        statements,
        before_index=before_index,
        resolve_temporaries=resolve_temporaries,
    )
    if reaching is None:
        return expr
    source, source_index = reaching
    return resolve_same_block_data_register_dependencies_8616(
        source,
        statements,
        before_index=source_index,
        register_name=register_name,
        resolve_temporaries=resolve_temporaries,
        copy_expression=copy_expression,
        active_views=active_views | {view},
        depth=depth + 1,
    )


def _resolve_composite_children_8616(
    expr: object,
    statements: Sequence[object],
    *,
    before_index: int,
    register_name: RegisterNameResolver8616,
    resolve_temporaries: TemporaryResolver8616,
    copy_expression: ExpressionCopier8616,
    active_views: frozenset[tuple[int, int]],
    depth: int,
) -> object:
    """Copy one composite expression and resolve each child operand."""

    def resolve(child: Expression) -> Expression:
        resolved = resolve_same_block_data_register_dependencies_8616(
            child,
            statements,
            before_index=before_index,
            register_name=register_name,
            resolve_temporaries=resolve_temporaries,
            copy_expression=copy_expression,
            active_views=active_views,
            depth=depth + 1,
        )
        return resolved if isinstance(resolved, Expression) else child

    result = copy_expression(expr)
    if not isinstance(result, Expression):
        return expr
    if isinstance(result, ailment.Expr.BinaryOp):
        result.operands = [resolve(operand) for operand in result.operands]
    elif isinstance(result, ailment.Expr.UnaryOp):
        result.operand = resolve(result.operand)
    elif isinstance(result, ailment.Expr.ITE):
        result.cond = resolve(result.cond)
        result.iftrue = resolve(result.iftrue)
        result.iffalse = resolve(result.iffalse)
    return result
