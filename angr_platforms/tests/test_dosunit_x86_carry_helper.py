"""Layer: Tests.

Responsibility: independent native carry observations and mutation controls
for exact VEX carry thunks without admitting complete EFLAGS.
"""

import pytest
import z3
from unicorn import UC_ARCH_X86, UC_MODE_32, Uc
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_EFLAGS

from tools.dosunit import straightline_ssa as S

OPERATIONS = ((1, '00d8', '01d8'), (4, '28d8', '29d8'),
              (7, '10d8', '11d8'), (10, '18d8', '19d8'),
              (13, '20d8', '21d8'), (16, 'fec0', 'ffc0'), (19, 'fec8', 'ffc8'))


@pytest.mark.parametrize('base,byte_code,wide_code', OPERATIONS)
@pytest.mark.parametrize('bits', (8, 16, 32))
def test_carry_only_helper_matches_native(base: int, byte_code: str, wide_code: str, bits: int) -> None:
    """Carry/borrow and preserved INC/DEC carry agree with actual instructions."""
    code = bytes.fromhex(byte_code if bits == 8 else ('66' if bits == 16 else '') + wide_code)
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
            expected = machine.reg_read(UC_X86_REG_EFLAGS) & 1
            dep1 = result if base in (13, 16, 19) else left
            dep2 = right ^ old_carry if base in (7, 10) else right
            cc_op = base + (0 if bits == 8 else 1 if bits == 16 else 2)
            args = [z3.BitVecVal(value, 32) for value in (cc_op, dep1, dep2, old_carry)]
            actual = z3.simplify(S._z3_apply('summary_x86g_calculate_eflags_c', 32, args, z3))
            assert z3.is_bv_value(actual), (cc_op, 'abstract carry')
            assert actual.as_long() == expected, (cc_op, left, right, old_carry)


def test_copy_carry_masks_every_other_bit() -> None:
    """COPY exposes only CF even when all other arithmetic flags are set."""
    for flags in (0, 1, 0xfffffffe, 0xffffffff, 0x8d6, 0x8d7):
        args = [z3.BitVecVal(value, 32) for value in (0, flags, 0, 0)]
        actual = z3.simplify(S._z3_apply('summary_x86g_calculate_eflags_c', 32, args, z3))
        assert z3.is_bv_value(actual)
        assert actual.as_long() == flags & 1


def test_carry_materialization_refuses_a_different_condition_contract() -> None:
    """A caller cannot accidentally materialize another predicate as carry."""
    from tools.dosunit.x86_lazy_conditions import condition_contract, exact_carry

    kind = condition_contract(0, 3)
    assert kind is not None
    args = [z3.BitVecVal(value, 32) for value in (1, 2, 0)]
    with pytest.raises(ValueError, match='BELOW/CF contract'):
        exact_carry(kind, *args, output_width=32)


def test_symbolic_and_malformed_carry_calls_remain_abstract() -> None:
    """Unknown ids, arity and operand sorts cannot obtain exact CF evidence."""
    cases = [
        [z3.BitVec('unknown_cc_op', 32), z3.BitVecVal(1, 32), z3.BitVecVal(2, 32), z3.BitVecVal(0, 32)],
        [z3.BitVecVal(3, 32)],
        [z3.BitVecVal(3, 32), z3.BoolVal(True), z3.BitVecVal(2, 32), z3.BitVecVal(0, 32)],
    ]
    for args in cases:
        actual = S._z3_apply('summary_x86g_calculate_eflags_c', 32, args, z3)
        assert not z3.is_bv_value(z3.simplify(actual))


@pytest.mark.parametrize('cc_op', tuple(range(22)))
def test_carry_admission_and_evaluation_have_one_contract(cc_op: int) -> None:
    """Direct and referenced concrete ids have the evaluator's exact scope."""
    def literal(value: int) -> dict[str, str | int]:
        """Encode a concrete SSA operation dependency."""
        return {'op': 'const', 'value': hex(value), 'width': 32}
    term = {'op': 'summary_x86g_calculate_eflags_c', 'args': [
        {'ref': 'operation'}, literal(1), literal(2), literal(0),
    ]}
    assert not S._x86_lazy_flag_summary_is_uninterpreted(term, {'operation': literal(cc_op)})


@pytest.mark.parametrize('cc_op', (22, 25, 28, 31, 34, 37, 40, 0xffffffff))
def test_unmodeled_carry_and_all_flags_remain_abstract(cc_op: int) -> None:
    """Extending defined carry cannot admit unmodeled operations or full EFLAGS."""
    args = [z3.BitVecVal(value, 32) for value in (cc_op, 1, 2, 0)]
    assert not z3.is_bv_value(z3.simplify(S._z3_apply('summary_x86g_calculate_eflags_c', 32, args, z3)))
    args[0] = z3.BitVecVal(3, 32)
    assert not z3.is_bv_value(z3.simplify(S._z3_apply('summary_x86g_calculate_eflags_all', 32, args, z3)))


@pytest.mark.parametrize('driver', ('msc8', 'bc5'))
@pytest.mark.parametrize('case', ('self', 'equivalent', 'changed'))
def test_native_carry_boolean_return_projection(driver: str, case: str) -> None:
    """Both adapters agree on NEG/SBB versus NEG/SETB return and reject SETAE."""
    import angr
    from test_flat32_comparator_lane import _driver_lane

    from tools.dosunit.flat32_call_composition import compare_functions_with_calls

    original = bytes.fromhex('f7d8 19c0 f7d8 c3')
    equivalent = bytes.fromhex('f7d8 0f92c0 0fb6c0 c3')
    changed = bytes.fromhex('f7d8 0f93c0 0fb6c0 c3')
    candidate = original if case == 'self' else equivalent if case == 'equivalent' else changed
    base = 0x100000
    oracle_project = angr.load_shellcode(original, arch='x86', load_address=base)
    candidate_project = angr.load_shellcode(candidate, arch='x86', load_address=base)
    with _driver_lane(driver) as lane, lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            oracle_project, candidate_project,
            oracle_entry=base, candidate_entry=base,
            oracle_functions={base: len(original)}, candidate_functions={base: len(candidate)},
            outputs=lane.adapter.GPRS, timeout_ms=5000,
        )
    assert result['status'] == ('failed' if case == 'changed' else 'passed'), result
    assert not result.get('assumptions')
