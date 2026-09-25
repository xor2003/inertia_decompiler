"""ALU operand and comparison semantics for typed IR conditions.

Layer: Semantics.
Responsibility: owns instruction effects, flags, branch meaning, and expression interpretation.
This module maps VEX-like operands into typed IR values and conditions.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from pyvex.lifting.util.vex_helper import Type

from ..addressing_helpers import type_for_bits
from ..ir.condition_ir import build_condition_ir_8616, harmonize_condition_args_8616
from ..ir.core import IRCondition, IRValue, MemSpace
from ..ir.regs import REG16_OFFSET_MAP, register_name_from_offset

__all__ = (
    "binary_operation",
    "binary_operation_with_carry",
    "build_carry_compare_condition_8616",
    "build_compare_condition_8616",
    "compare_operation",
    "masked_shift_count",
    "rotate_count",
    "rotate_left_operation",
    "rotate_right_operation",
    "rotate_through_carry_count",
    "rotate_through_carry_left_state",
    "rotate_through_carry_right_state",
    "shift_left_operation",
    "shift_right_arithmetic_operation",
    "shift_right_operation",
    "unary_operation",
)


_SymbolicValue8616 = Any
_ValueGetter8616 = Callable[[], _SymbolicValue8616]
_ValueSetter8616 = Callable[[_SymbolicValue8616], None]
_DynamicOperator8616 = Callable[..., _SymbolicValue8616]
_FlagUpdater8616 = Callable[..., object]


def _dynamic_vex_attr_8616(obj: object | None, name: str, default: object | None = None) -> object | None:
    """Dynamic VEX/emulator boundary: read optional pyvex or callback attributes."""
    if obj is None:
        return default
    try:
        # Dynamic third-party VEX/emulator boundary: symbolic objects do not expose an owned contract.
        return getattr(obj, name, default)
    except Exception:
        return default


def _dynamic_flag_callback_name_8616(update_flags: object) -> str:
    """Dynamic flag-callback boundary: return the external callback name."""
    name = _dynamic_vex_attr_8616(update_flags, "__name__", "")
    return name if isinstance(name, str) else ""


def _type_name_for_operand(value: object) -> str:
    ty = _dynamic_vex_attr_8616(value, "ty")
    ty_name = _dynamic_vex_attr_8616(ty, "name")
    return str(ty_name if ty_name is not None else ty or type(value).__name__)


def _size_bytes_from_operand(value: object) -> int:
    width = _dynamic_vex_attr_8616(value, "width")
    if isinstance(width, int) and width > 0:
        return max(1, (width + 7) // 8)
    ty = _dynamic_vex_attr_8616(value, "ty")
    ty_name = _dynamic_vex_attr_8616(ty, "name", str(ty or ""))
    if not isinstance(ty_name, str):
        ty_name = str(ty_name)
    if ty_name.startswith("Ity_I"):
        try:
            bits = int(ty_name[5:])
        except ValueError:
            bits = 0
        if bits > 0:
            return max(1, bits // 8)
    return 0


def _int_condition_value_8616(value: int, hinted_size: int) -> IRValue:
    """Return the sized CONST lane for a Python int operand."""
    size = hinted_size or 1
    if hinted_size <= 0:
        if not -(1 << 7) <= value < (1 << 8):
            size = 2
        if not -(1 << 15) <= value < (1 << 16):
            size = 4
    return IRValue(MemSpace.CONST, const=value, size=size, expr=("int",))


def _mapped_reg_offset_value_8616(value: object, reg_offset: int, hinted_size: int) -> IRValue:
    """Return the REG lane for a VEX offset inside REG16_OFFSET_MAP."""
    return IRValue(
        MemSpace.REG,
        name=register_name_from_offset(reg_offset),
        offset=reg_offset,
        size=_size_bytes_from_operand(value) or hinted_size,
        expr=(_type_name_for_operand(value),),
    )


def _reg_name_value_8616(value: object, reg_name: str, hinted_size: int) -> IRValue:
    """Return the REG lane for a dynamic register-name operand."""
    reg_offset = _dynamic_vex_attr_8616(value, "offset")
    return IRValue(
        MemSpace.REG,
        name=reg_name.lower(),
        offset=int(reg_offset) if isinstance(reg_offset, int) else 0,
        size=_size_bytes_from_operand(value) or hinted_size,
        expr=(_type_name_for_operand(value),),
    )


def _condition_value_from_operand(value: object, *, size_hint: int = 0) -> IRValue:
    """Lower one operand boundary value into a typed IRValue."""
    hinted_size = int(size_hint or 0)
    if isinstance(value, bool):
        return IRValue(MemSpace.CONST, const=int(value), size=max(1, hinted_size), expr=("bool",))
    if isinstance(value, int):
        return _int_condition_value_8616(value, hinted_size)
    value_const = _dynamic_vex_attr_8616(value, "value")
    if isinstance(value_const, int):
        size = _size_bytes_from_operand(value) or hinted_size
        return IRValue(MemSpace.CONST, const=value_const, size=size, expr=("vex_const",))

    reg_offset = _dynamic_vex_attr_8616(value, "reg")
    if isinstance(reg_offset, int) and int(reg_offset) in REG16_OFFSET_MAP:
        return _mapped_reg_offset_value_8616(value, reg_offset, hinted_size)

    dynamic_reg_name = _dynamic_vex_attr_8616(value, "reg_name")
    if isinstance(dynamic_reg_name, str) and dynamic_reg_name:
        return _reg_name_value_8616(value, dynamic_reg_name, hinted_size)

    reg_offset = _dynamic_vex_attr_8616(value, "offset")
    if isinstance(reg_offset, int) and int(reg_offset) in REG16_OFFSET_MAP:
        return _mapped_reg_offset_value_8616(value, reg_offset, hinted_size)

    tmp = _dynamic_vex_attr_8616(value, "tmp")
    if isinstance(tmp, int):
        return IRValue(
            MemSpace.TMP,
            name=f"tmp_{tmp}",
            size=_size_bytes_from_operand(value) or hinted_size,
            expr=("tmp",),
        )

    return IRValue(
        MemSpace.TMP,
        name=type(value).__name__,
        size=_size_bytes_from_operand(value) or hinted_size,
        expr=(
            _type_name_for_operand(value),
        ),
    )


def _same_condition_operand_8616(lhs: object, rhs: object) -> bool:
    if lhs is rhs:
        return True
    try:
        return lhs == rhs
    except Exception:
        return False


def build_compare_condition_8616(lhs: object, rhs: object, update_flags: object) -> IRCondition | None:
    """Build typed comparison IR from a two-operand flag update callback."""
    name = _dynamic_flag_callback_name_8616(update_flags)
    target_size = max(_size_bytes_from_operand(lhs), _size_bytes_from_operand(rhs))
    lhs_value = _condition_value_from_operand(lhs, size_hint=target_size)
    rhs_value = _condition_value_from_operand(rhs, size_hint=target_size)
    lhs_value, rhs_value = harmonize_condition_args_8616(lhs_value, rhs_value, size=target_size)
    if name in {"update_eflags_inc", "update_eflags_dec"}:
        boundary = (1 << (max(1, target_size) * 8)) - 1 if name.endswith("_inc") else 1
        return build_condition_ir_8616(
            "compare",
            lhs_value,
            IRValue(MemSpace.CONST, const=boundary, size=max(1, target_size), expr=(name, "zero_boundary")),
            expr=(name,),
        )
    if name == "update_eflags_sub":
        if _same_condition_operand_8616(lhs, rhs):
            return build_condition_ir_8616(
                "eq",
                lhs_value,
                rhs_value,
                expr=(name, "same_operand"),
            )
        if rhs_value.space == MemSpace.CONST and rhs_value.const == 0:
            return build_condition_ir_8616(
                "nonzero",
                lhs_value,
                expr=(name, "rhs_zero"),
            )
        return build_condition_ir_8616(
            "compare",
            lhs_value,
            rhs_value,
            expr=(name,),
        )
    if name in {"update_eflags_and", "update_eflags_or", "update_eflags_xor"}:
        if _same_condition_operand_8616(lhs, rhs):
            return build_condition_ir_8616(
                "nonzero",
                lhs_value,
                expr=(name, "same_operand"),
            )
        return build_condition_ir_8616(
            "nonzero",
            lhs_value,
            rhs_value,
            expr=(name,),
        )
    return None


def build_carry_compare_condition_8616(
    lhs: object,
    rhs: object,
    carry: object,
    update_flags: object,
) -> IRCondition | None:
    """Build typed comparison IR from an ADC/SBB-style flag update callback."""
    name = _dynamic_flag_callback_name_8616(update_flags)
    if name not in {"update_eflags_adc", "update_eflags_sbb"}:
        return None
    target_size = max(_size_bytes_from_operand(lhs), _size_bytes_from_operand(rhs), _size_bytes_from_operand(carry))
    lhs_value = _condition_value_from_operand(lhs, size_hint=target_size)
    rhs_value = _condition_value_from_operand(rhs, size_hint=target_size)
    carry_value = _condition_value_from_operand(carry, size_hint=target_size)
    lhs_value, rhs_value = harmonize_condition_args_8616(lhs_value, rhs_value, size=target_size)
    return build_condition_ir_8616(
        "carry_compare",
        lhs_value,
        rhs_value,
        carry_value,
        expr=(name,),
    )


def _record_last_condition_from_update_flags(
    emu: object | None,
    lhs: object,
    rhs: object,
    update_flags: object,
) -> None:
    owner = _dynamic_vex_attr_8616(update_flags, "__self__")
    set_last_condition = _dynamic_vex_attr_8616(owner, "set_last_condition")
    if not callable(set_last_condition):
        return
    condition = build_compare_condition_8616(lhs, rhs, update_flags)
    if condition is not None:
        set_last_condition(condition)


def _record_last_condition_from_carry_update_flags(
    emu: object | None,
    lhs: object,
    rhs: object,
    carry: object,
    update_flags: object,
) -> None:
    owner = _dynamic_vex_attr_8616(update_flags, "__self__")
    set_last_condition = _dynamic_vex_attr_8616(owner, "set_last_condition")
    if not callable(set_last_condition):
        return
    condition = build_carry_compare_condition_8616(lhs, rhs, carry, update_flags)
    if condition is not None:
        set_last_condition(condition)


def binary_operation(
    emu: object,
    get_lhs: _ValueGetter8616,
    get_rhs: _ValueGetter8616,
    set_result: _ValueSetter8616,
    update_flags: _FlagUpdater8616,
    operator: _DynamicOperator8616,
) -> None:
    """Emit flags from pre-write operands, then apply a binary ALU result."""
    lhs, rhs = get_lhs(), get_rhs()
    result = operator(lhs, rhs)
    update_flags(lhs, rhs)
    _record_last_condition_from_update_flags(emu, lhs, rhs, update_flags)
    set_result(result)


def binary_operation_with_carry(
    emu: _SymbolicValue8616,
    get_lhs: _ValueGetter8616,
    get_rhs: _ValueGetter8616,
    set_result: _ValueSetter8616,
    update_flags: _FlagUpdater8616,
    operator: _DynamicOperator8616,
    width_bits: int,
) -> None:
    """Emit flags from pre-write operands, then apply a carry-aware result."""
    lhs, rhs = get_lhs(), get_rhs()
    carry = emu.is_carry()
    if hasattr(carry, "cast_to"):
        carry = carry.cast_to(type_for_bits(width_bits))
    else:
        carry = emu.constant(int(bool(carry)), type_for_bits(width_bits))
    result = operator(lhs, rhs, carry)
    update_flags(lhs, rhs, carry)
    _record_last_condition_from_carry_update_flags(emu, lhs, rhs, carry, update_flags)
    set_result(result)


def compare_operation(
    get_lhs: _ValueGetter8616,
    get_rhs: _ValueGetter8616,
    update_flags: _FlagUpdater8616,
) -> None:
    """Run a compare-only ALU operation and record its typed flag condition."""
    lhs = get_lhs()
    rhs = get_rhs()
    update_flags(lhs, rhs)
    _record_last_condition_from_update_flags(None, lhs, rhs, update_flags)


def unary_operation(
    get_value: _ValueGetter8616,
    set_result: _ValueSetter8616,
    update_flags: _FlagUpdater8616 | None,
    operator: _DynamicOperator8616,
) -> None:
    """Emit flags from the pre-write operand, then apply a unary result."""
    value = get_value()
    if update_flags is not None:
        update_flags(value)
        _record_last_condition_from_update_flags(None, value, 0, update_flags)
    set_result(operator(value))


def masked_shift_count(
    emu: _SymbolicValue8616,
    count: _SymbolicValue8616,
    width_bits: int,
    mask: int = 0x1F,
) -> _SymbolicValue8616:
    """Mask an x86 shift count to the architecturally active bits."""
    value_type = type_for_bits(width_bits)
    if isinstance(count, int):
        return emu.constant(count & mask, value_type)
    try:
        constant_count = count.value
    except (AttributeError, ValueError):
        constant_count = None
    if isinstance(constant_count, int):
        return emu.constant(constant_count & mask, value_type)
    count_v = count.cast_to(value_type)
    return count_v & emu.constant(mask, value_type)


def rotate_count(
    emu: _SymbolicValue8616,
    count: _SymbolicValue8616,
    modulo: int,
    width_bits: int,
    mask: int = 0x1F,
) -> _SymbolicValue8616:
    """Normalize a rotate count for the target operand width."""
    return masked_shift_count(emu, count, width_bits, mask) % emu.constant(modulo, type_for_bits(width_bits))


def rotate_through_carry_count(
    emu: _SymbolicValue8616,
    count: _SymbolicValue8616,
    width_bits: int,
    mask: int = 0x1F,
) -> _SymbolicValue8616:
    """Normalize a rotate-through-carry count for the target width."""
    return masked_shift_count(emu, count, width_bits, mask) % emu.constant(width_bits + 1, type_for_bits(width_bits))


def shift_left_operation(
    emu: _SymbolicValue8616,
    get_value: _ValueGetter8616,
    set_result: _ValueSetter8616,
    update_flags: _FlagUpdater8616,
    count: _SymbolicValue8616,
    width_bits: int,
) -> None:
    """Update flags from the pre-write value, then apply a logical left shift."""
    value = get_value()
    shift = masked_shift_count(emu, count, width_bits)
    update_flags(value, shift)
    set_result(value << shift)


def shift_right_operation(
    emu: _SymbolicValue8616,
    get_value: _ValueGetter8616,
    set_result: _ValueSetter8616,
    update_flags: _FlagUpdater8616,
    count: _SymbolicValue8616,
    width_bits: int,
) -> None:
    """Update flags from the pre-write value, then apply a logical right shift."""
    value = get_value()
    shift = masked_shift_count(emu, count, width_bits)
    update_flags(value, shift)
    set_result(value >> shift)


def shift_right_arithmetic_operation(
    emu: _SymbolicValue8616,
    get_value: _ValueGetter8616,
    set_result: _ValueSetter8616,
    update_flags: _FlagUpdater8616,
    count: _SymbolicValue8616,
    width_bits: int,
) -> None:
    """Update flags from the pre-write value, then apply an arithmetic shift."""
    value = get_value()
    shift = masked_shift_count(emu, count, width_bits)
    update_flags(value, shift)
    set_result(value.sar(shift))


def rotate_left_operation(
    emu: _SymbolicValue8616,
    get_value: _ValueGetter8616,
    set_result: _ValueSetter8616,
    update_flags: _FlagUpdater8616,
    count: _SymbolicValue8616,
    width_bits: int,
) -> None:
    """Update flags from the pre-write value, then apply a rotate-left result."""
    value = get_value()
    shift = rotate_count(emu, count, width_bits, width_bits)
    width = emu.constant(width_bits, type_for_bits(width_bits))
    mask = emu.constant((1 << width_bits) - 1, type_for_bits(width_bits))
    update_flags(value, count)
    set_result(((value << shift) | (value >> (width - shift))) & mask)


def rotate_right_operation(
    emu: _SymbolicValue8616,
    get_value: _ValueGetter8616,
    set_result: _ValueSetter8616,
    update_flags: _FlagUpdater8616,
    count: _SymbolicValue8616,
    width_bits: int,
) -> None:
    """Update flags from the pre-write value, then apply a rotate-right result."""
    value = get_value()
    shift = rotate_count(emu, count, width_bits, width_bits)
    width = emu.constant(width_bits, type_for_bits(width_bits))
    mask = emu.constant((1 << width_bits) - 1, type_for_bits(width_bits))
    update_flags(value, count)
    set_result(((value >> shift) | (value << (width - shift))) & mask)


def rotate_through_carry_left_state(
    emu: _SymbolicValue8616,
    value: _SymbolicValue8616,
    count: _SymbolicValue8616,
    width_bits: int,
    ite_value: _DynamicOperator8616,
) -> tuple[_SymbolicValue8616, _SymbolicValue8616 | None, _SymbolicValue8616 | None]:
    """Return result, carry, and overflow for rotate-through-carry left."""
    shift = rotate_through_carry_count(emu, count, width_bits)
    shift_value = emu._const_u8_value(shift)
    mask = emu.constant((1 << width_bits) - 1, type_for_bits(width_bits))
    one = emu.constant(1, Type.int_8)
    carry_in = emu.get_carry().cast_to(Type.int_1)

    if shift_value == 0:
        return value, None, None
    if shift_value == 1:
        result = ((value << one) | carry_in.cast_to(type_for_bits(width_bits))) & mask
        carry_out = value[width_bits - 1].cast_to(Type.int_1)
        overflow = result[width_bits - 1].cast_to(Type.int_1) ^ carry_out
        return result, carry_out, overflow

    result = value
    carry = carry_in
    selected_result = value
    selected_carry = carry_in.cast_to(type_for_bits(width_bits))
    for step in range(1, width_bits + 1):
        shifted_out = result[width_bits - 1].cast_to(Type.int_1)
        result = ((result << one) | carry.cast_to(type_for_bits(width_bits))) & mask
        carry = shifted_out
        cond = shift == emu.constant(step, type_for_bits(width_bits))
        selected_result = ite_value(cond, result, selected_result)
        selected_carry = ite_value(cond, carry.cast_to(type_for_bits(width_bits)), selected_carry)
    overflow = selected_result[width_bits - 1].cast_to(Type.int_1) ^ selected_carry.cast_to(Type.int_1)
    return selected_result, selected_carry.cast_to(Type.int_1), overflow


def rotate_through_carry_right_state(
    emu: _SymbolicValue8616,
    value: _SymbolicValue8616,
    count: _SymbolicValue8616,
    width_bits: int,
    ite_value: _DynamicOperator8616,
) -> tuple[_SymbolicValue8616, _SymbolicValue8616 | None, _SymbolicValue8616 | None]:
    """Return result, carry, and overflow for rotate-through-carry right."""
    shift = rotate_through_carry_count(emu, count, width_bits)
    shift_value = emu._const_u8_value(shift)
    mask = emu.constant((1 << width_bits) - 1, type_for_bits(width_bits))
    one = emu.constant(1, Type.int_8)
    carry_in = emu.get_carry().cast_to(Type.int_1)

    if shift_value == 0:
        return value, None, None
    if shift_value == 1:
        result = (value >> one) | (carry_in.cast_to(type_for_bits(width_bits)) << (width_bits - 1))
        carry_out = value[0].cast_to(Type.int_1)
        overflow = result[width_bits - 1].cast_to(Type.int_1) ^ result[width_bits - 2].cast_to(Type.int_1)
        return result & mask, carry_out, overflow

    result = value
    carry = carry_in
    selected_result = value
    selected_carry = carry_in.cast_to(type_for_bits(width_bits))
    for step in range(1, width_bits + 1):
        shifted_out = result[0].cast_to(Type.int_1)
        result = (result >> one) | (carry.cast_to(type_for_bits(width_bits)) << (width_bits - 1))
        carry = shifted_out
        cond = shift == emu.constant(step, type_for_bits(width_bits))
        selected_result = ite_value(cond, result & mask, selected_result)
        selected_carry = ite_value(cond, carry.cast_to(type_for_bits(width_bits)), selected_carry)
    overflow = selected_result[width_bits - 1].cast_to(Type.int_1) ^ selected_result[width_bits - 2].cast_to(Type.int_1)
    return selected_result & mask, selected_carry.cast_to(Type.int_1), overflow
