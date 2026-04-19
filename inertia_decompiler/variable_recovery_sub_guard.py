from __future__ import annotations

import sys
from typing import Any


def _coerce_bv_width_8616(data: Any, bits: int) -> Any:
    size = data.size()
    if size == bits:
        return data
    if size > bits:
        try:
            return data[bits - 1 : 0]
        except Exception:
            return data
    try:
        return data.zero_extend(bits - size)
    except Exception:
        return data


def _sign_bit_is_set_8616(data: Any) -> bool:
    try:
        size = int(data.size())
    except Exception:
        return False
    if size <= 0:
        return False
    try:
        if getattr(data, "concrete", False):
            value = int(getattr(data, "concrete_value"))
            return bool(value & (1 << (size - 1)))
    except Exception:
        return False
    return False


def _widen_sub_operand_8616(data: Any, bits: int) -> Any:
    size = data.size()
    if size == bits:
        return data
    if size > bits:
        try:
            return data[bits - 1 : 0]
        except Exception:
            return data
    extend_by = bits - size
    if _sign_bit_is_set_8616(data):
        try:
            return data.sign_extend(extend_by)
        except Exception:
            pass
    try:
        return data.zero_extend(extend_by)
    except Exception:
        return data


def _narrow_bv_width_8616(data: Any, bits: int, state: Any) -> Any:
    current = data.size()
    if current == bits:
        return data
    if current > bits:
        try:
            return data[bits - 1 : 0]
        except Exception:
            return state.top(bits)
    try:
        return data.zero_extend(bits - current)
    except Exception:
        return state.top(bits)


def _log_size_mismatch_once_8616(self: Any, expr: Any, r0: Any, r1: Any, project: Any, context_suffix) -> None:
    mismatch_seen = None
    if project is not None:
        mismatch_seen = getattr(project, "_inertia_size_mismatch_seen", None)
        if not isinstance(mismatch_seen, set):
            mismatch_seen = set()
            setattr(project, "_inertia_size_mismatch_seen", mismatch_seen)
    else:
        mismatch_seen = getattr(self, "_inertia_size_mismatch_seen", None)
    if not isinstance(mismatch_seen, set):
        mismatch_seen = set()
        if project is not None:
            setattr(project, "_inertia_size_mismatch_seen", mismatch_seen)
        else:
            self._inertia_size_mismatch_seen = mismatch_seen
    function_addr, _function_name, _slice_addr = context_suffix[0](project)
    mismatch_key = (function_addr, r0.data.size(), r1.data.size(), expr.bits)
    if mismatch_key in mismatch_seen:
        return
    mismatch_seen.add(mismatch_key)
    print(
        "[dbg] clinic:variable-recovery-size-mismatch "
        f"op=Sub lhs_bits={r0.data.size()} rhs_bits={r1.data.size()} expr_bits={expr.bits}"
        f"{context_suffix[1](project)}",
        file=sys.stderr,
    )
    sys.stderr.flush()


def build_guarded_handle_binop_sub_8616(*, richr_cls, typevars_module, project, context_suffix):
    def _guarded_handle_binop_sub(self, expr):
        arg0, arg1 = expr.operands
        r0, r1 = self._expr_pair(arg0, arg1)
        if r0.data.size() != r1.data.size():
            _log_size_mismatch_once_8616(self, expr, r0, r1, project, context_suffix)

        if r0.data.size() == r1.data.size() == expr.bits:
            compute = r0.data - r1.data
        else:
            compute_bits = max(r0.data.size(), r1.data.size(), expr.bits)
            lhs = _widen_sub_operand_8616(r0.data, compute_bits)
            rhs = _widen_sub_operand_8616(r1.data, compute_bits)
            if lhs.size() == rhs.size() == compute_bits:
                wide = lhs - rhs
                compute = _narrow_bv_width_8616(wide, expr.bits, self.state)
            else:
                compute = self.state.top(expr.bits)

        type_constraints = set()
        if r0.typevar is not None and r1.data.concrete and isinstance(r0.typevar, typevars_module.TypeVariable):
            typevar = typevars_module.new_dtv(r0.typevar, label=typevars_module.SubN(r1.data.concrete_value))
        else:
            typevar = typevars_module.TypeVariable()
            if r0.typevar is not None and r1.typevar is not None:
                type_constraints.add(typevars_module.Sub(r0.typevar, r1.typevar, typevar))

        return richr_cls(compute, typevar=typevar, type_constraints=type_constraints)

    return _guarded_handle_binop_sub
