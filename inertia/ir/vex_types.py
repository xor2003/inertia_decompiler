"""Resolve external VEX expression widths without changing their semantics.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization. This module only translates pyvex type metadata into byte widths.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from typing import Protocol, cast

__all__ = ("vex_expr_size_bytes",)


class _VexConstantBoundary(Protocol):
    """Type metadata exposed by an external pyvex constant."""

    type: object


class _VexResultSizeCallable(Protocol):
    """Callable result-size surface exposed by real pyvex expressions."""

    def __call__(self, type_environment: object) -> object:
        """Return the expression width in bits for one VEX type environment."""
        ...


class _VexExpressionBoundary(Protocol):
    """Dynamic pyvex fields needed for width resolution."""

    con: _VexConstantBoundary | None
    result_size: object
    ty: object


_VEX_TYPE_BYTES: dict[str, int] = {
    "Ity_I1": 1,
    "Ity_I8": 1,
    "Ity_I16": 2,
    "Ity_I32": 4,
    "Ity_I64": 8,
    "Ity_I128": 16,
    "Ity_I256": 32,
}


def _type_token_size(expr: object) -> int | None:
    """Resolve expression or constant type tokens at the pyvex boundary."""
    boundary = cast(_VexExpressionBoundary, expr)
    try:
        expression_type = boundary.ty
    except AttributeError:
        expression_type = None
    type_size = _VEX_TYPE_BYTES.get(str(expression_type or ""))
    if type_size is not None:
        return type_size
    try:
        constant = boundary.con
    except AttributeError:
        # Bare Exit destinations expose their type directly, without .con.
        constant = cast(_VexConstantBoundary, expr)
    if constant is None:
        return None
    try:
        return _VEX_TYPE_BYTES.get(str(constant.type))
    except AttributeError:
        return None


def _callable_result_size_bits(expr: object, type_environment: object | None) -> int | None:
    """Call pyvex's result-size method when its owning type environment exists."""
    if type_environment is None:
        return None
    try:
        result_size = cast(_VexExpressionBoundary, expr).result_size
    except AttributeError:
        return None
    if not callable(result_size):
        return None
    try:
        raw_bits = cast(_VexResultSizeCallable, result_size)(type_environment)
        bits = int(cast(int, raw_bits))
    except (TypeError, ValueError):
        return None
    return bits if bits > 0 else None


def vex_expr_size_bytes(
    expr: object | None,
    *,
    type_environment: object | None = None,
    default: int = 2,
) -> int:
    """Return one external VEX expression width in bytes.

    Real pyvex ``result_size`` methods return bits and require the IRSB type
    environment. Numeric ``result_size`` fields are retained as byte-valued
    compatibility input for synthetic test boundaries.
    """
    if expr is None:
        return default
    bits = _callable_result_size_bits(expr, type_environment)
    if bits is not None:
        return max(1, (bits + 7) // 8)
    type_size = _type_token_size(expr)
    if type_size is not None:
        return type_size
    try:
        result_size = cast(_VexExpressionBoundary, expr).result_size
    except AttributeError:
        return default
    if isinstance(result_size, int) and result_size > 0:
        return result_size
    return default
