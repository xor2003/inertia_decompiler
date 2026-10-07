"""Guard variable-recovery subprocess helpers with width-safe coercions.

Layer: CLI/fallback/reporting.
Responsibility: install bounded angr variable-recovery guards without owning type recovery semantics.

Dynamic attributes here are limited to third-party angr/claripy variable-recovery compatibility boundaries.
"""

from __future__ import annotations

import sys
import typing
from collections.abc import Callable
from typing import Any, Protocol, cast

type ContextSuffixCallbacks = tuple[Callable[[object], tuple[object, object, object]], Callable[[object], str]]
type GuardHandler = Callable[[Any, Any], object]


class _DerivedTypeVariableFactory8616(Protocol):
    """Third-party typevars constructors supported by the compatibility guard."""

    DerivedTypeVariable: Callable[[object, object], object]
    new_dtv: Callable[..., object]


def _derived_type_variable_8616(typevars: object, typevar: object, label: object) -> object:
    """Build a derived type variable across supported third-party angr APIs."""
    factory = cast(_DerivedTypeVariableFactory8616, typevars)
    try:
        return factory.DerivedTypeVariable(typevar, label)
    except AttributeError:
        return factory.new_dtv(typevar, label=label)


def _coerce_bv_width_8616(data: object, bits: int) -> object:
    data_bv = cast(Any, data)
    size = data_bv.size()
    if size == bits:
        return data
    if size > bits:
        try:
            return data_bv[bits - 1 : 0]
        except Exception:
            return data
    try:
        return data_bv.zero_extend(bits - size)
    except Exception:
        return data


def _sign_bit_is_set_8616(data: object) -> bool:
    data_bv = cast(Any, data)
    try:
        size = int(data_bv.size())
    except Exception:
        return False
    if size <= 0:
        return False
    try:
        # Dynamic angr boundary: claripy AST concreteness is optional by expression kind.
        if getattr(data_bv, "concrete", False):
            # Dynamic angr boundary: concrete_value exists only for concrete claripy ASTs.
            value = int(data_bv.concrete_value)
            return bool(value & (1 << (size - 1)))
    except Exception:
        return False
    return False


def _widen_sub_operand_8616(data: object, bits: int) -> object:
    data_bv = cast(Any, data)
    size = data_bv.size()
    if size == bits:
        return data
    if size > bits:
        try:
            return data_bv[bits - 1 : 0]
        except Exception:
            return data
    extend_by = bits - size
    if _sign_bit_is_set_8616(data):
        try:
            return data_bv.sign_extend(extend_by)
        except Exception:
            pass
    try:
        return data_bv.zero_extend(extend_by)
    except Exception:
        return data


def _narrow_bv_width_8616(data: object, bits: int, state: object) -> object:
    data_bv = cast(Any, data)
    state_obj = cast(Any, state)
    current = data_bv.size()
    if current == bits:
        return data
    if current > bits:
        try:
            return data_bv[bits - 1 : 0]
        except Exception:
            return state_obj.top(bits)
    try:
        return data_bv.zero_extend(bits - current)
    except Exception:
        return state_obj.top(bits)


def _log_size_mismatch_once_8616(
    self: object,
    expr: object,
    r0: object,
    r1: object,
    project: object,
    context_suffix: ContextSuffixCallbacks,
) -> None:
    expr_obj = cast(Any, expr)
    r0_obj = cast(Any, r0)
    r1_obj = cast(Any, r1)
    mismatch_seen = None
    if project is not None:
        # Dynamic angr boundary: diagnostic seen-set is attached to third-party Project objects.
        mismatch_seen = getattr(project, "_inertia_size_mismatch_seen", None)
        if not isinstance(mismatch_seen, set):
            mismatch_seen = set()
            # Dynamic angr boundary: diagnostic seen-set is attached to third-party Project objects.
            typing.cast(typing.Any, project)._inertia_size_mismatch_seen = mismatch_seen
    else:
        # Dynamic angr boundary: guard instance storage is attached to angr's variable-recovery engine.
        mismatch_seen = getattr(self, "_inertia_size_mismatch_seen", None)
    if not isinstance(mismatch_seen, set):
        mismatch_seen = set()
        if project is not None:
            # Dynamic angr boundary: diagnostic seen-set is attached to third-party Project objects.
            typing.cast(typing.Any, project)._inertia_size_mismatch_seen = mismatch_seen
        else:
            self_any = cast(Any, self)
            self_any._inertia_size_mismatch_seen = mismatch_seen
    function_addr, _function_name, _slice_addr = context_suffix[0](project)
    mismatch_key = (function_addr, r0_obj.data.size(), r1_obj.data.size(), expr_obj.bits)
    if mismatch_key in mismatch_seen:
        return
    mismatch_seen.add(mismatch_key)
    print(
        "[dbg] clinic:variable-recovery-size-mismatch "
        f"op=Sub lhs_bits={r0_obj.data.size()} rhs_bits={r1_obj.data.size()} expr_bits={expr_obj.bits}"
        f"{context_suffix[1](project)}",
        file=sys.stderr,
    )
    sys.stderr.flush()


def _log_variable_recovery_guard_fallback_once_8616(
    self: object,
    expr: object,
    ex: Exception,
    project: object,
    context_suffix: ContextSuffixCallbacks,
) -> None:
    seen = None
    if project is not None:
        # Dynamic angr boundary: fallback seen-set is attached to third-party Project objects.
        seen = getattr(project, "_inertia_variable_recovery_guard_fallback_seen", None)
        if not isinstance(seen, set):
            seen = set()
            # Dynamic angr boundary: fallback seen-set is attached to third-party Project objects.
            typing.cast(typing.Any, project)._inertia_variable_recovery_guard_fallback_seen = seen
    else:
        # Dynamic angr boundary: guard instance storage is attached to angr's variable-recovery engine.
        seen = getattr(self, "_inertia_variable_recovery_guard_fallback_seen", None)
    if not isinstance(seen, set):
        seen = set()
        if project is not None:
            # Dynamic angr boundary: fallback seen-set is attached to third-party Project objects.
            typing.cast(typing.Any, project)._inertia_variable_recovery_guard_fallback_seen = seen
        else:
            self_any = cast(Any, self)
            self_any._inertia_variable_recovery_guard_fallback_seen = seen
    function_addr, _function_name, _slice_addr = context_suffix[0](project)
    key = (function_addr, type(expr).__name__, type(ex).__name__, str(ex))
    if key in seen:
        return
    seen.add(key)
    print(
        "[dbg] clinic:variable-recovery-guard-fallback "
        f"expr={type(expr).__name__} error={type(ex).__name__}: {ex}"
        f"{context_suffix[1](project)}",
        file=sys.stderr,
    )
    sys.stderr.flush()


def build_guarded_handle_binop_sub_8616(
    *,
    richr_cls: Callable[..., object],
    typevars_module: object,
    project: object,
    context_suffix: ContextSuffixCallbacks,
) -> GuardHandler:
    """Build an angr Sub binop handler guarded against width mismatches."""

    def _guarded_handle_binop_sub(self: object, expr: object) -> object:
        self_engine = cast(Any, self)
        expr_obj = cast(Any, expr)
        typevars = cast(Any, typevars_module)
        try:
            arg0, arg1 = expr_obj.operands
            r0, r1 = self_engine._expr_pair(arg0, arg1)
            mismatch_bits = r0.data.size() != r1.data.size()
            unresolved_mismatch = False

            if r0.data.size() == r1.data.size() == expr_obj.bits:
                compute = r0.data - r1.data
            else:
                compute_bits = max(r0.data.size(), r1.data.size(), expr_obj.bits)
                lhs = cast(Any, _widen_sub_operand_8616(r0.data, compute_bits))
                rhs = cast(Any, _widen_sub_operand_8616(r1.data, compute_bits))
                if lhs.size() == rhs.size() == compute_bits:
                    wide = lhs - rhs
                    compute = _narrow_bv_width_8616(wide, expr_obj.bits, self_engine.state)
                else:
                    unresolved_mismatch = True
                    compute = self_engine.state.top(expr_obj.bits)
            if mismatch_bits and unresolved_mismatch:
                _log_size_mismatch_once_8616(self, expr, r0, r1, project, context_suffix)

            type_constraints = set()
            if r0.typevar is not None and r1.data.concrete and isinstance(r0.typevar, typevars.TypeVariable):
                typevar = _derived_type_variable_8616(
                    typevars,
                    r0.typevar,
                    typevars.SubN(r1.data.concrete_value),
                )
            else:
                typevar = typevars.TypeVariable()
                if r0.typevar is not None and r1.typevar is not None:
                    type_constraints.add(typevars.Sub(r0.typevar, r1.typevar, typevar))
        except Exception as ex:
            _log_variable_recovery_guard_fallback_once_8616(self, expr, ex, project, context_suffix)
            # Dynamic angr boundary: expr.bits may be missing on malformed third-party nodes.
            compute = self_engine.state.top(getattr(expr_obj, "bits", 1) or 1)
            typevar = typevars.TypeVariable()
            type_constraints = set()

        return richr_cls(compute, typevar=typevar, type_constraints=type_constraints)

    return _guarded_handle_binop_sub


def build_guarded_handle_binop_mul_8616(
    *,
    richr_cls: Callable[..., object],
    typevars_module: object,
    project: object,
    context_suffix: ContextSuffixCallbacks,
) -> GuardHandler:
    """Build an angr Mul binop handler guarded against width mismatches."""

    def _guarded_handle_binop_mul(self: object, expr: object) -> object:
        self_engine = cast(Any, self)
        expr_obj = cast(Any, expr)
        typevars = cast(Any, typevars_module)
        try:
            arg0, arg1 = expr_obj.operands
            r0, r1 = self_engine._expr_pair(arg0, arg1)
            mismatch_bits = r0.data.size() != r1.data.size()
            unresolved_mismatch = False

            if r0.data.size() == r1.data.size() == expr_obj.bits:
                compute = r0.data * r1.data
            else:
                compute_bits = max(r0.data.size(), r1.data.size(), expr_obj.bits)
                lhs = cast(Any, _coerce_bv_width_8616(r0.data, compute_bits))
                rhs = cast(Any, _coerce_bv_width_8616(r1.data, compute_bits))
                if lhs.size() == rhs.size() == compute_bits:
                    wide = lhs * rhs
                    compute = _narrow_bv_width_8616(wide, expr_obj.bits, self_engine.state)
                else:
                    unresolved_mismatch = True
                    compute = self_engine.state.top(expr_obj.bits)
            if mismatch_bits and unresolved_mismatch:
                _log_size_mismatch_once_8616(self, expr, r0, r1, project, context_suffix)

            typevar = typevars.TypeVariable()
            type_constraints = set()
            if r0.typevar is not None and r1.typevar is not None and hasattr(typevars, "Mul"):
                type_constraints.add(typevars.Mul(r0.typevar, r1.typevar, typevar))
        except Exception as ex:
            _log_variable_recovery_guard_fallback_once_8616(self, expr, ex, project, context_suffix)
            # Dynamic angr boundary: expr.bits may be missing on malformed third-party nodes.
            compute = self_engine.state.top(getattr(expr_obj, "bits", 1) or 1)
            typevar = typevars.TypeVariable()
            type_constraints = set()

        return richr_cls(compute, typevar=typevar, type_constraints=type_constraints)

    return _guarded_handle_binop_mul
