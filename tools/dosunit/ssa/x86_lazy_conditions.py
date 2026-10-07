"""Exact integer branch conditions for admitted VEX i386 flag thunks.

Layer: dosunit SSA semantics.
Responsibility: own arithmetic-thunk admission and Z3 branch predicates together,
preserving modular widths and incoming carry while refusing unmodeled thunks.
Only condition predicates and CF projections are modeled; undefined auxiliary flags, shifts,
rotations and multiplication are not newly admitted by this owner.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    import z3


class X86Condition(IntEnum):
    """VEX condition codes paired with their architectural complements."""

    OVERFLOW = 0
    NO_OVERFLOW = 1
    BELOW = 2
    ABOVE_EQUAL = 3
    ZERO = 4
    NONZERO = 5
    BELOW_EQUAL = 6
    ABOVE = 7
    SIGN = 8
    NO_SIGN = 9
    PARITY = 10
    NO_PARITY = 11
    LESS = 12
    GREATER_EQUAL = 13
    LESS_EQUAL = 14
    GREATER = 15


class LazyArithmetic(Enum):
    """Admitted VEX dependency interpretations, independent of instruction text."""

    COPY = "copy"
    ADD = "add"
    SUBTRACT = "subtract"
    ADD_CARRY = "add_carry"
    SUBTRACT_BORROW = "subtract_borrow"
    LOGIC = "logic"
    INCREMENT = "increment"
    DECREMENT = "decrement"


@dataclass(frozen=True, slots=True)
class X86ConditionContract:
    """One exact admitted condition, arithmetic interpretation and operand width."""

    condition: X86Condition
    arithmetic: LazyArithmetic
    operand_width: int


@dataclass(frozen=True, slots=True)
class _BranchFlags:
    """Only the five defined flags observed by architectural Jcc predicates."""

    carry: z3.BoolRef
    parity: z3.BoolRef
    zero: z3.BoolRef
    sign: z3.BoolRef
    overflow: z3.BoolRef


_ARITHMETIC_GROUPS: tuple[LazyArithmetic, ...] = (
    LazyArithmetic.ADD, LazyArithmetic.SUBTRACT, LazyArithmetic.ADD_CARRY,
    LazyArithmetic.SUBTRACT_BORROW, LazyArithmetic.LOGIC,
    LazyArithmetic.INCREMENT, LazyArithmetic.DECREMENT,
)


def condition_contract(condition: int | None, cc_op: int | None) -> X86ConditionContract | None:
    """Admit COPY or the VEX byte/word/dword arithmetic groups numbered1..21."""
    if type(condition) is not int or type(cc_op) is not int or not 0 <= condition <= 15:
        return None
    if cc_op == 0:
        return X86ConditionContract(X86Condition(condition), LazyArithmetic.COPY, 32)
    if not 1 <= cc_op <= 21:
        return None
    group, width_index = divmod(cc_op - 1, 3)
    return X86ConditionContract(X86Condition(condition), _ARITHMETIC_GROUPS[group], 8 << width_index)


def _low_width(value: z3.BitVecRef, width: int) -> z3.BitVecRef:
    """Discard high dependency bits or zero-extend an explicitly narrower input."""
    import z3

    if value.size() < width:
        return z3.ZeroExt(width - value.size(), value)
    # Z3's polymorphic Extract annotation also includes sequence expressions.
    return cast("z3.BitVecRef", z3.Extract(width - 1, 0, value))


def _equal(left: z3.BitVecRef, right: z3.BitVecRef | int) -> z3.BoolRef:
    """Narrow Z3's overloaded equality result at the bitvector API boundary."""
    return cast("z3.BoolRef", left == right)


def _set_bit(value: z3.BitVecRef, position: int) -> z3.BoolRef:
    """Read one architectural flag or sign bit as a Boolean predicate."""
    import z3

    bit = cast("z3.BitVecRef", z3.Extract(position, position, value))
    return _equal(bit, z3.BitVecVal(1, 1))


def _result_flags(result: z3.BitVecRef, carry: z3.BoolRef, overflow: z3.BoolRef) -> _BranchFlags:
    """Derive ZF/SF and even low-byte parity without auxiliary-flag assumptions."""
    import z3

    parity = z3.BitVecVal(1, 1)
    for position in range(8):
        parity = parity ^ z3.Extract(position, position, result)
    return _BranchFlags(carry, _equal(parity, z3.BitVecVal(1, 1)), _equal(result, 0),
                        _set_bit(result, result.size() - 1), overflow)


def _binary_flags(kind: X86ConditionContract, left: z3.BitVecRef,
                  dependency2: z3.BitVecRef, ndep: z3.BitVecRef) -> _BranchFlags:
    """Decode ADC/SBB's XOR dependency and prove carry with a widened operation."""
    import z3

    uses_carry = kind.arithmetic in {LazyArithmetic.ADD_CARRY, LazyArithmetic.SUBTRACT_BORROW}
    old_carry = _low_width(ndep, kind.operand_width) & 1 if uses_carry else z3.BitVecVal(0, kind.operand_width)
    right = dependency2 ^ old_carry if uses_carry else dependency2
    subtract = kind.arithmetic in {LazyArithmetic.SUBTRACT, LazyArithmetic.SUBTRACT_BORROW}
    wide_left, wide_right, wide_carry = (z3.ZeroExt(1, value) for value in (left, right, old_carry))
    if subtract:
        result = left - right - old_carry
        carry = z3.ULT(wide_left, wide_right + wide_carry)
        overflow_bits = (left ^ right) & (left ^ result)
    else:
        result = left + right + old_carry
        carry = _set_bit(wide_left + wide_right + wide_carry, kind.operand_width)
        overflow_bits = ~(left ^ right) & (left ^ result)
    return _result_flags(result, carry, _set_bit(overflow_bits, kind.operand_width - 1))


def _branch_flags(kind: X86ConditionContract, dep1: z3.BitVecRef,
                  dep2: z3.BitVecRef, ndep: z3.BitVecRef) -> _BranchFlags:
    """Interpret result dependencies and the saved carry exactly for each family."""
    import z3

    if kind.arithmetic is LazyArithmetic.COPY:
        return _BranchFlags(*(_set_bit(_low_width(dep1, 32), bit) for bit in (0, 2, 6, 7, 11)))
    left = _low_width(dep1, kind.operand_width)
    if kind.arithmetic is LazyArithmetic.LOGIC:
        return _result_flags(left, z3.BoolVal(False), z3.BoolVal(False))
    if kind.arithmetic in {LazyArithmetic.INCREMENT, LazyArithmetic.DECREMENT}:
        sign = 1 << (kind.operand_width - 1)
        overflow_result = sign if kind.arithmetic is LazyArithmetic.INCREMENT else sign - 1
        return _result_flags(left, _set_bit(ndep, 0), _equal(left, overflow_result))
    return _binary_flags(kind, left, _low_width(dep2, kind.operand_width), ndep)


def exact_condition(kind: X86ConditionContract, dep1: z3.BitVecRef,
                    dep2: z3.BitVecRef, ndep: z3.BitVecRef, *, output_width: int) -> z3.BitVecRef:
    """Return the exact zero/one VEX result for a fully admitted branch contract."""
    import z3

    flags = _branch_flags(kind, dep1, dep2, ndep)
    signed_less = z3.Xor(flags.sign, flags.overflow)
    predicates = (flags.overflow, flags.carry, flags.zero, z3.Or(flags.carry, flags.zero),
                  flags.sign, flags.parity, signed_less, z3.Or(flags.zero, signed_less))
    condition = kind.condition.value
    predicate = predicates[condition // 2]
    if condition & 1:
        predicate = z3.Not(predicate)
    return cast("z3.BitVecRef", z3.If(predicate, z3.BitVecVal(1, output_width), z3.BitVecVal(0, output_width)))


def carry_contract(cc_op: int | None) -> X86ConditionContract | None:
    """Admit the architectural CF projection of the same exact arithmetic owner.

    The BELOW predicate is exactly CF. This admits no new arithmetic thunk,
    auxiliary flag or complete EFLAGS interpretation.
    """
    return condition_contract(X86Condition.BELOW.value, cc_op)


def exact_carry(kind: X86ConditionContract, dep1: z3.BitVecRef,
                dep2: z3.BitVecRef, ndep: z3.BitVecRef, *, output_width: int) -> z3.BitVecRef:
    """Materialize only a validated CF contract as a zero-or-one bitvector."""
    if kind.condition is not X86Condition.BELOW:
        raise ValueError("carry materialization requires the BELOW/CF contract")
    return exact_condition(kind, dep1, dep2, ndep, output_width=output_width)
