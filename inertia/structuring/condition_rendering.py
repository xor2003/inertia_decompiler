"""Render ConditionIR to C-like strings.

Layer: Structuring.
Responsibility: owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.

AGENTS rule: No flag-based conditions, no tmp-based conditions.
If signedness cannot be expressed safely in C, use explicit helper form
(e.g. ``s16_lt(lhs, rhs)``, ``u16_lt(lhs, rhs)``).
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from inertia.ir.condition_ir import ConditionIR

_EXPLICIT_HELPER_COMPARISONS_8616: dict[str, str] = {
    "slt": "s16_lt",
    "sle": "s16_le",
    "sgt": "s16_gt",
    "sge": "s16_ge",
    "ult": "u16_lt",
    "ule": "u16_le",
    "ugt": "u16_gt",
    "uge": "u16_ge",
}

_NATIVE_COMPARISON_SYMBOLS_8616: dict[str, str] = {
    "eq": "==",
    "ne": "!=",
    "slt": "<",
    "sle": "<=",
    "sgt": ">",
    "sge": ">=",
    "ult": "<",
    "ule": "<=",
    "ugt": ">",
    "uge": ">=",
}

__all__ = (
    "render_condition_ir_8616",
    "render_condition_ir_native_8616",
    "render_condition_operand_8616",
)


@runtime_checkable
class _ConditionOperandMapping8616(Protocol):
    def to_dict(self) -> dict[str, object]:
        """Return a structured representation for condition rendering."""
        ...


def render_condition_ir_8616(cond: ConditionIR) -> str | None:
    """Render a ConditionIR to a C-like condition string."""
    lhs_str = render_condition_operand_8616(cond.lhs)
    rhs_str = render_condition_operand_8616(cond.rhs) if cond.rhs is not None else None

    op = cond.op

    if op == "zero":
        return f"{lhs_str} == 0"
    if op == "nonzero":
        return f"{lhs_str} != 0"

    if op == "eq":
        return f"{lhs_str} == {rhs_str}"
    if op == "ne":
        return f"{lhs_str} != {rhs_str}"

    helper = _EXPLICIT_HELPER_COMPARISONS_8616.get(op)
    if helper and rhs_str is not None:
        return f"{helper}({lhs_str}, {rhs_str})"

    return None


def render_condition_ir_native_8616(cond: ConditionIR) -> str | None:
    """Render using native C operators (when unsigned/signed semantics are safe).

    This is for use when type analysis has proven signedness.
    """
    lhs_str = render_condition_operand_8616(cond.lhs)
    rhs_str = render_condition_operand_8616(cond.rhs) if cond.rhs is not None else None

    op = cond.op

    if op == "zero":
        return f"{lhs_str} == 0"
    if op == "nonzero":
        return f"{lhs_str} != 0"
    if op == "eq":
        return f"{lhs_str} == {rhs_str}"
    if op == "ne":
        return f"{lhs_str} != {rhs_str}"

    sym = _NATIVE_COMPARISON_SYMBOLS_8616.get(op)
    if sym and rhs_str is not None:
        return f"{lhs_str} {sym} {rhs_str}"

    return None


def render_condition_operand_8616(value: object) -> str:
    """Format an operand value to a string representation."""
    if value is None:
        return "0"
    if isinstance(value, int):
        if value >= 0:
            return f"0x{value:x}"
        return str(value)
    if isinstance(value, _ConditionOperandMapping8616):
        d = value.to_dict()
        if d.get("space") == "reg" and d.get("name"):
            return str(d["name"])
        if d.get("space") == "const" and d.get("const") is not None:
            return str(d["const"])
        return str(d)
    return str(value)
