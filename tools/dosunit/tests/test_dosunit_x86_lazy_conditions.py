"""Exact lazy conditions agree with independently executed i386 instructions."""

from __future__ import annotations

import pytest
import z3
from unicorn import UC_ARCH_X86, UC_MODE_32, Uc
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_EFLAGS

import tools.dosunit.compare.straightline_ssa as S

OPERATIONS = (
    (1, "00d8", "01d8"), (4, "28d8", "29d8"),
    (7, "10d8", "11d8"), (10, "18d8", "19d8"),
    (13, "20d8", "21d8"), (16, "fec0", "ffc0"), (19, "fec8", "ffc8"),
)


def _conditions(flags: int) -> tuple[bool, ...]:
    """Decode architectural branch predicates from independently observed flags."""
    carry, parity, zero, sign, overflow = (bool(flags & (1 << bit)) for bit in (0, 2, 6, 7, 11))
    positive = (overflow, carry, zero, carry or zero, sign, parity,
                sign != overflow, zero or sign != overflow)
    return tuple(value for flag in positive for value in (flag, not flag))


@pytest.mark.parametrize("base,byte_code,wide_code", OPERATIONS)
@pytest.mark.parametrize("bits", (8, 16, 32))
def test_arithmetic_conditions_match_native_flags(base, byte_code, wide_code, bits):
    """All sixteen Jcc predicates retain width, parity, carry and overflow."""
    code = bytes.fromhex(byte_code if bits == 8 else ("66" if bits == 16 else "") + wide_code)
    mask, sign = (1 << bits) - 1, 1 << (bits - 1)
    vectors = ((0, 0), (0, 1), (1, mask), (mask, 1), (sign - 1, 1),
               (sign, 1), (sign, mask), (mask, mask), (0x55, 0xaa))
    machine = Uc(UC_ARCH_X86, UC_MODE_32)
    machine.mem_map(0x100000, 0x1000)
    machine.mem_write(0x100000, code)
    for left, right in vectors:
        for old_carry in (0, 1):
            machine.reg_write(UC_X86_REG_EAX, left)
            machine.reg_write(UC_X86_REG_EBX, right)
            machine.reg_write(UC_X86_REG_EFLAGS, 2 | old_carry)
            machine.emu_start(0x100000, 0x100000 + len(code), count=1)
            result = machine.reg_read(UC_X86_REG_EAX) & mask
            flags = machine.reg_read(UC_X86_REG_EFLAGS)
            dep1 = result if base in (13, 16, 19) else left
            dep2 = right ^ old_carry if base in (7, 10) else right
            cc_op = base + (0 if bits == 8 else 1 if bits == 16 else 2)
            for condition, expected in enumerate(_conditions(flags)):
                args = [z3.BitVecVal(value, 32) for value in (condition, cc_op, dep1, dep2, old_carry)]
                actual = S._z3_apply("summary_x86g_calculate_condition", 32, args, z3)
                assert z3.is_bv_value(z3.simplify(actual)), (cc_op, condition, "abstract condition")
                assert z3.simplify(actual).as_long() == int(expected), (cc_op, condition, left, right, old_carry)


def test_copy_conditions_match_observed_native_flags():
    """COPY reads the supplied architectural flags without inventing arithmetic."""
    machine = Uc(UC_ARCH_X86, UC_MODE_32)
    machine.mem_map(0x100000, 0x1000)
    machine.mem_write(0x100000, b"\x90")
    for flags in (2, 0x8d7, 0x846, 0x83, 0x2c7):
        machine.reg_write(UC_X86_REG_EFLAGS, flags)
        machine.emu_start(0x100000, 0x100001, count=1)
        flags = machine.reg_read(UC_X86_REG_EFLAGS)
        for condition, expected in enumerate(_conditions(flags)):
            args = [z3.BitVecVal(value, 32) for value in (condition, 0, flags, 0, 0)]
            actual = S._z3_apply("summary_x86g_calculate_condition", 32, args, z3)
            assert z3.is_bv_value(z3.simplify(actual)), (condition, "abstract COPY condition")
            assert z3.simplify(actual).as_long() == int(expected)


@pytest.mark.parametrize("cc_op", (22, 25, 28, 31, 34, 37, 40, 0xffffffff))
def test_unmodeled_lazy_operations_remain_uninterpreted(cc_op):
    """Shifts, rotations, multiplication and invalid thunks remain refused."""
    args = [z3.BitVecVal(value, 32) for value in (4, cc_op, 1, 2, 0)]
    actual = S._z3_apply("summary_x86g_calculate_condition", 32, args, z3)
    assert not z3.is_bv_value(z3.simplify(actual))


@pytest.mark.parametrize("driver", ("msc8", "bc5"))
@pytest.mark.parametrize("case", ("self", "equivalent", "changed"))
def test_real_binary_zero_condition_has_checked_verdict(driver, case):
    """Both public adapter seams prove ADD/LEA zero parity and reject inversion."""
    import angr
    from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane

    from tools.dosunit.compare.flat32_call_composition import compare_functions_with_calls

    original = bytes.fromhex("01d8 0f94c2 0fb6d2 c3")
    equivalent = bytes.fromhex("8d0418 85c0 0f94c2 0fb6d2 c3")
    changed = bytes.fromhex("8d0418 85c0 0f95c2 0fb6d2 c3")
    candidate = original if case == "self" else equivalent if case == "equivalent" else changed
    base = 0x100000
    oracle_project = angr.load_shellcode(original, arch="x86", load_address=base)
    candidate_project = angr.load_shellcode(candidate, arch="x86", load_address=base)
    with _driver_lane(driver) as lane, lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            oracle_project, candidate_project,
            oracle_entry=base, candidate_entry=base,
            oracle_functions={base: len(original)}, candidate_functions={base: len(candidate)},
            outputs=lane.adapter.GPRS, timeout_ms=5000,
        )
    assert result["status"] == ("failed" if case == "changed" else "passed"), result
    assert not result.get("assumptions")


def test_nonconstant_and_invalid_conditions_stay_abstract():
    """Unknown arithmetic or condition identifiers never enter the exact owner."""
    for condition in (16, 0xffffffff):
        args = [z3.BitVecVal(value, 32) for value in (condition, 3, 1, 2, 0)]
        assert not z3.is_bv_value(z3.simplify(S._z3_apply("summary_x86g_calculate_condition", 32, args, z3)))
    for unknown in (0, 1):
        args = [z3.BitVecVal(value, 32) for value in (4, 3, 1, 2, 0)]
        args[unknown] = z3.BitVec("unknown_condition_or_operation", 32)
        assert not z3.is_bv_value(z3.simplify(S._z3_apply("summary_x86g_calculate_condition", 32, args, z3)))
