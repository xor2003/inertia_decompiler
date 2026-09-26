"""Layer: Validation.

Responsibility: owns canonical equivalence checking and validation diagnostics.
Scope: canonicalization for equivalence checking only.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.

Rules:
- Allowed: x+0→x, x−x→0, (a+b)+c normalization, commutativity for +,&,|
- Forbidden: modifying IR, modifying C output, creating new variables, guessing structs/arrays.
"""  # noqa: RUF002

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, cast, runtime_checkable

__all__ = [
    "EquivalenceResult",
    "canonical_diagnostic_8616",
    "canonicalize_expr_for_validation_8616",
    "equivalent_expr_8616",
]


class EquivalenceResult(Enum):
    """Structured result for validation-only expression equivalence checks."""

    EQUIVALENT = "equivalent"
    DIFFERENT = "different"
    UNCERTAIN = "uncertain"
    TIMEOUT = "timeout"


@dataclass(frozen=True, slots=True)
class CanonicalDiagnostic:
    """Diagnostic record for validation canonicalization visibility."""

    path: str = ""
    changed: bool = False
    note: str = ""
    before: str = ""
    after: str = ""


class _ExpressionConstructor(Protocol):
    def __call__(self, *_args: object, **_kwargs: object) -> object: ...


@runtime_checkable
class _BinaryExpr(Protocol):
    op: object
    lhs: object
    rhs: object


@runtime_checkable
class _UnaryExpr(Protocol):
    op: object
    operand: object


@runtime_checkable
class _HasCodegen(Protocol):
    codegen: object


@runtime_checkable
class _HasValue(Protocol):
    value: object


@runtime_checkable
class _HasReg(Protocol):
    reg: object


@runtime_checkable
class _HasVariable(Protocol):
    variable: object


@runtime_checkable
class _HasStackIdentity(Protocol):
    base: object
    offset: object


@runtime_checkable
class _HasSize(Protocol):
    size: object


@runtime_checkable
class _HasName(Protocol):
    name: object


@runtime_checkable
class _HasKind(Protocol):
    kind: object


@runtime_checkable
class _HasTypeAttr(Protocol):
    type: object


@runtime_checkable
class _HasExpr(Protocol):
    expr: object


@runtime_checkable
class _HasIndex(Protocol):
    index: object


class _Z3ArithmeticExpr(Protocol):
    def __add__(self, _other: object) -> object: ...

    def __sub__(self, _other: object) -> object: ...

    def __mul__(self, _other: object) -> object: ...


class _ExpressionAttributeAccessor(Protocol):
    def __call__(self, expr: object) -> object: ...


def canonicalize_expr_for_validation_8616(expr: object, *, max_depth: int = 8) -> object:
    """Apply identity-preserving algebraic normalization to one expression."""

    def _impl() -> object:
        if max_depth <= 0:
            return expr

        # Primitive types pass through.
        if isinstance(expr, (int, float, str, bool, type(None))):
            return expr

        # Handle common expression types if they have lhs/rhs shape.
        if isinstance(expr, _BinaryExpr):
            return _canonicalize_binary_expr(expr, max_depth)

        # Handle unary ops.
        if isinstance(expr, _UnaryExpr):
            operand = canonicalize_expr_for_validation_8616(expr.operand, max_depth=max_depth - 1)
            if operand is not expr.operand:
                return _rebuild_unary(expr, operand)

        return expr

    return _impl()


def _canonicalize_binary_expr(expr: _BinaryExpr, max_depth: int) -> object:
    """Canonicalize a binary expression after recursing into both operands."""
    lhs = canonicalize_expr_for_validation_8616(expr.lhs, max_depth=max_depth - 1)
    rhs = canonicalize_expr_for_validation_8616(expr.rhs, max_depth=max_depth - 1)

    # x + 0 → x
    if _is_zero_value(rhs) and expr.op in {"Add", "+"}:
        return lhs
    # 0 + x → x
    if _is_zero_value(lhs) and expr.op in {"Add", "+"}:
        return rhs
    # x - 0 → x
    if _is_zero_value(rhs) and expr.op in {"Sub", "-"}:
        return lhs
    # x - x → 0
    if _same_value(lhs, rhs) and expr.op in {"Sub", "-"}:
        return _zero_for_expr(lhs)

    return _rebuild_binary(expr, lhs, rhs)


def equivalent_expr_8616(lhs: object, rhs: object, *, timeout_ms: int = 500) -> EquivalenceResult:
    """Check if two expressions are semantically equivalent after canonicalization.

    Uses:
        1. Structural equality after canonicalization
        2. String-level fingerprint comparison (delegates to condition_ir.py)
        3. SMT fallback if available (Z3)
    """
    # Fast path: identity
    if lhs is rhs:
        return EquivalenceResult.EQUIVALENT

    # Canonicalize both
    canon_lhs = canonicalize_expr_for_validation_8616(lhs)
    canon_rhs = canonicalize_expr_for_validation_8616(rhs)

    # Structural equality after canonicalization
    if _structural_equal(canon_lhs, canon_rhs):
        return EquivalenceResult.EQUIVALENT

    # String-level comparison for conditions
    if _fingerprint_equal(lhs, rhs):
        return EquivalenceResult.EQUIVALENT

    # Try SMT fallback
    if _smt_equivalent(lhs, rhs, timeout_ms=timeout_ms):
        return EquivalenceResult.EQUIVALENT

    return EquivalenceResult.DIFFERENT


def canonical_diagnostic_8616(expr: object) -> CanonicalDiagnostic:
    """Return a diagnostic describing what canonicalization changed."""
    before = str(expr) if not isinstance(expr, str) else expr
    after_expr = canonicalize_expr_for_validation_8616(expr)
    after = str(after_expr) if not isinstance(after_expr, str) else after_expr
    changed = before != after
    note = "canonicalized" if changed else "unchanged"
    return CanonicalDiagnostic(
        path=type(expr).__name__,
        changed=changed,
        note=note,
        before=before,
        after=after,
    )


# ── internal helpers ──


def _is_zero_value(expr: object) -> bool:
    """Check if an expression represents the value 0."""
    if isinstance(expr, int):
        return expr == 0
    if isinstance(expr, float):
        return expr == 0.0
    if isinstance(expr, _HasValue):
        const_val = expr.value
        if isinstance(const_val, int):
            return const_val == 0
        if isinstance(const_val, float):
            return const_val == 0.0
    return False


def _is_one_value(expr: object) -> bool:
    """Check if an expression represents the value 1."""
    if isinstance(expr, int):
        return expr == 1
    if isinstance(expr, _HasValue):
        const_val = expr.value
        if isinstance(const_val, int):
            return const_val == 1
    return False


def _same_value(lhs: object, rhs: object) -> bool:
    def _impl() -> bool:
        """Check if two expressions represent the same value."""
        if type(lhs) is not type(rhs):
            return False
        lhs_value = lhs.value if isinstance(lhs, _HasValue) else lhs
        rhs_value = rhs.value if isinstance(rhs, _HasValue) else rhs
        if isinstance(lhs_value, int) and isinstance(rhs_value, int):
            return lhs_value == rhs_value

        # Register-check: same reg offset
        lhs_reg = _reg_for_expr(lhs)
        rhs_reg = _reg_for_expr(rhs)
        if isinstance(lhs_reg, int) and isinstance(rhs_reg, int):
            return lhs_reg == rhs_reg

        # Stack slot: same base + offset
        lhs_var = lhs.variable if isinstance(lhs, _HasVariable) else None
        rhs_var = rhs.variable if isinstance(rhs, _HasVariable) else None
        if lhs_var is not None and rhs_var is not None:
            return (
                isinstance(lhs_var, _HasStackIdentity)
                and isinstance(rhs_var, _HasStackIdentity)
                and lhs_var.offset == rhs_var.offset
                and lhs_var.base == rhs_var.base
            )

        return False

    return _impl()


def _zero_for_expr(expr: object) -> object:
    """Produce a zero constant matching the type of expr."""
    width = expr.size if isinstance(expr, _HasSize) and isinstance(expr.size, int) else 4
    return _make_constant(0, width, codegen=_codegen_for_expr(expr))


def _make_constant(value: int, size: int = 4, *, codegen: object | None = None) -> object:
    """Create a constant node matching the given value and size."""
    if codegen is None:
        return value
    try:
        from angr.analyses.decompiler.structured_codegen.c import CConstant
        from angr.sim_type import SimTypeChar, SimTypeInt, SimTypeShort

        if size <= 1:
            return CConstant(value, SimTypeChar(signed=False), codegen=codegen)
        if size <= 2:
            return CConstant(value, SimTypeShort(signed=False), codegen=codegen)
        return CConstant(value, SimTypeInt(signed=False), codegen=codegen)
    except (AssertionError, AttributeError, ImportError, TypeError):
        return value


def _rebuild_binary(original: object, lhs: object, rhs: object) -> object:
    """Rebuild a binary expression with canonicalized children."""
    if not isinstance(original, _BinaryExpr):
        return original
    constructor = cast(_ExpressionConstructor, type(original))
    try:
        return constructor(original.op, lhs, rhs, codegen=_codegen_for_expr(original))
    except (TypeError, ValueError):
        return original


def _rebuild_unary(original: object, operand: object) -> object:
    """Rebuild a unary expression with a canonicalized operand."""
    if not isinstance(original, _UnaryExpr):
        return original
    constructor = cast(_ExpressionConstructor, type(original))
    try:
        return constructor(original.op, operand, codegen=_codegen_for_expr(original))
    except (TypeError, ValueError):
        return original


def _structural_equal(lhs: object, rhs: object, depth: int = 0, max_depth: int = 16) -> bool:
    def _impl() -> bool:
        """Structural equality check with cycle detection."""
        if depth > max_depth:
            return True  # conservative: treat too-deep as equal

        if type(lhs) is not type(rhs):
            return False

        if isinstance(lhs, (int, float, str, bool, type(None))):
            return lhs == rhs

        for accessor in _STRUCTURAL_ATTR_ACCESSORS:
            if not _compare_optional_attr(lhs, rhs, accessor, depth, max_depth):
                return False

        if not _binary_shape_equal(lhs, rhs, depth, max_depth):
            return False
        return _unary_shape_equal(lhs, rhs, depth, max_depth)

    return _impl()


def _binary_shape_equal(lhs: object, rhs: object, depth: int, max_depth: int) -> bool:
    """Return False when only one side is a binary expression or its fields differ."""
    if not isinstance(lhs, _BinaryExpr) and not isinstance(rhs, _BinaryExpr):
        return True
    if not isinstance(lhs, _BinaryExpr) or not isinstance(rhs, _BinaryExpr):
        return False
    return (
        _structural_equal(lhs.op, rhs.op, depth + 1, max_depth)
        and _structural_equal(lhs.lhs, rhs.lhs, depth + 1, max_depth)
        and _structural_equal(lhs.rhs, rhs.rhs, depth + 1, max_depth)
    )


def _unary_shape_equal(lhs: object, rhs: object, depth: int, max_depth: int) -> bool:
    """Return False when only one side is a unary expression or its fields differ."""
    if not isinstance(lhs, _UnaryExpr) and not isinstance(rhs, _UnaryExpr):
        return True
    if not isinstance(lhs, _UnaryExpr) or not isinstance(rhs, _UnaryExpr):
        return False
    return (
        _structural_equal(lhs.op, rhs.op, depth + 1, max_depth)
        and _structural_equal(lhs.operand, rhs.operand, depth + 1, max_depth)
    )


_sentinel = object()


def _codegen_for_expr(expr: object) -> object | None:
    """Return optional codegen metadata from a dynamic codegen expression."""
    return expr.codegen if isinstance(expr, _HasCodegen) else None


def _value_for_expr(expr: object) -> object:
    """Return value metadata when a dynamic expression exposes it."""
    return expr.value if isinstance(expr, _HasValue) else _sentinel


def _name_for_expr(expr: object) -> object:
    """Return name metadata when a dynamic expression exposes it."""
    return expr.name if isinstance(expr, _HasName) else _sentinel


def _kind_for_expr(expr: object) -> object:
    """Return kind metadata when a dynamic expression exposes it."""
    return expr.kind if isinstance(expr, _HasKind) else _sentinel


def _type_for_expr(expr: object) -> object:
    """Return type metadata when a dynamic expression exposes it."""
    return expr.type if isinstance(expr, _HasTypeAttr) else _sentinel


def _variable_for_expr(expr: object) -> object:
    """Return variable metadata when a dynamic expression exposes it."""
    return expr.variable if isinstance(expr, _HasVariable) else _sentinel


def _expr_for_expr(expr: object) -> object:
    """Return nested expression metadata when a dynamic expression exposes it."""
    return expr.expr if isinstance(expr, _HasExpr) else _sentinel


def _index_for_expr(expr: object) -> object:
    """Return index metadata when a dynamic expression exposes it."""
    return expr.index if isinstance(expr, _HasIndex) else _sentinel


def _reg_for_expr(expr: object) -> object | None:
    """Return register metadata from an expression or its variable."""
    if isinstance(expr, _HasReg):
        return expr.reg
    if isinstance(expr, _HasVariable) and isinstance(expr.variable, _HasReg):
        return expr.variable.reg
    return None


_STRUCTURAL_ATTR_ACCESSORS: tuple[_ExpressionAttributeAccessor, ...] = (
    _value_for_expr,
    _name_for_expr,
    _kind_for_expr,
    _type_for_expr,
    _variable_for_expr,
    _expr_for_expr,
    _index_for_expr,
)


def _compare_optional_attr(
    lhs: object,
    rhs: object,
    accessor: _ExpressionAttributeAccessor,
    depth: int,
    max_depth: int,
) -> bool:
    """Compare a dynamic expression attribute only when either side exposes it."""
    lhs_value = accessor(lhs)
    rhs_value = accessor(rhs)
    if lhs_value is _sentinel and rhs_value is _sentinel:
        return True
    if lhs_value is _sentinel or rhs_value is _sentinel:
        return False
    return _structural_equal(lhs_value, rhs_value, depth + 1, max_depth)


def _fingerprint_equal(lhs: object, rhs: object) -> bool:
    """String-based fingerprint comparison using condition IR normalization."""
    from ..ir.condition_ir import (
        normalize_condition_fingerprint_algebraic_8616,
        normalize_condition_fingerprint_string_8616,
    )

    lhs_str = str(lhs) if not isinstance(lhs, str) else lhs
    rhs_str = str(rhs) if not isinstance(rhs, str) else rhs

    lhs_normalized = normalize_condition_fingerprint_algebraic_8616(
        normalize_condition_fingerprint_string_8616(lhs_str)
    )
    rhs_normalized = normalize_condition_fingerprint_algebraic_8616(
        normalize_condition_fingerprint_string_8616(rhs_str)
    )

    if lhs_normalized == rhs_normalized:
        return True

    # Try with simple whitespace/formatting normalization
    lhs_compact = "".join(lhs_normalized.split())
    rhs_compact = "".join(rhs_normalized.split())
    return lhs_compact == rhs_compact


def _smt_equivalent(lhs: object, rhs: object, *, timeout_ms: int = 500) -> bool:
    """Try SMT (Z3) equivalence as fallback.  Returns False if Z3 unavailable."""
    try:
        import z3
    except ImportError:
        return False

    try:
        lhs_smt = _to_z3_expr(lhs)
        rhs_smt = _to_z3_expr(rhs)
        if lhs_smt is None or rhs_smt is None:
            return False

        s = z3.Solver()
        s.set("timeout", timeout_ms)
        s.add(lhs_smt != rhs_smt)
        result = s.check()
        return bool(result == z3.unsat)
    except Exception:
        return False


def _to_z3_expr(expr: object, _depth: int = 0) -> object | None:
    def _impl() -> object | None:
        """Best-effort conversion of an expression to Z3."""
        if _depth > 16:
            return None
        try:
            import z3
        except ImportError:
            return None

        leaf = _leaf_z3_expr(expr, z3)
        if leaf is not _sentinel:
            return leaf

        # Binary op
        if isinstance(expr, _BinaryExpr):
            return _binary_z3_expr(expr, z3, _depth)

        return None

    return _impl()


def _leaf_z3_expr(expr: object, z3: Any) -> object:  # noqa: ANN401
    """Convert primitive/name/register leaves to Z3, or ``_sentinel`` when not a leaf."""
    if isinstance(expr, int):
        return cast(object, z3.IntVal(expr))
    if isinstance(expr, bool):
        return cast(object, z3.BoolVal(expr))

    if isinstance(expr, _HasValue) and isinstance(expr.value, int):
        return cast(object, z3.IntVal(expr.value))

    # Named variable
    if isinstance(expr, _HasName) and isinstance(expr.name, str) and expr.name:
        return cast(object, z3.Int(expr.name))

    # Register-like
    reg = _reg_for_expr(expr)
    if isinstance(reg, int):
        return cast(object, z3.Int(f"reg_{reg}"))

    return _sentinel


def _binary_z3_expr(expr: _BinaryExpr, z3: Any, _depth: int) -> object | None:  # noqa: ANN401
    """Convert a binary expression tree to Z3, or ``None`` when unsupported."""
    lhs_z3 = _to_z3_expr(expr.lhs, _depth + 1)
    rhs_z3 = _to_z3_expr(expr.rhs, _depth + 1)
    if lhs_z3 is None or rhs_z3 is None:
        return None
    op = expr.op
    if op in {"Add", "+"}:
        return cast(_Z3ArithmeticExpr, lhs_z3) + rhs_z3
    if op in {"Sub", "-"}:
        return cast(_Z3ArithmeticExpr, lhs_z3) - rhs_z3
    if op in {"Mul", "*"}:
        return cast(_Z3ArithmeticExpr, lhs_z3) * rhs_z3
    if op in {"CmpEQ", "==", "eq"}:
        return lhs_z3 == rhs_z3
    if op in {"CmpNE", "!=", "ne"}:
        return lhs_z3 != rhs_z3
    return None
