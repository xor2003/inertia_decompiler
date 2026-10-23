"""Layer: Tests.

Responsibility: independent native carry observations and mutation controls
for exact VEX carry thunks and defined complete arithmetic flags.
"""

import pytest
import z3
from unicorn import UC_ARCH_X86, UC_MODE_32, Uc
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_EFLAGS

import tools.dosunit.compare.straightline_ssa as S

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
    from tools.dosunit.ssa.x86_lazy_conditions import condition_contract, exact_carry

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
    """Unmodeled operations cannot obtain exact carry or complete flag evidence."""
    args = [z3.BitVecVal(value, 32) for value in (cc_op, 1, 2, 0)]
    assert not z3.is_bv_value(z3.simplify(S._z3_apply('summary_x86g_calculate_eflags_c', 32, args, z3)))
    assert not z3.is_bv_value(z3.simplify(S._z3_apply('summary_x86g_calculate_eflags_all', 32, args, z3)))


@pytest.mark.parametrize('driver', ('msc8', 'bc5'))
@pytest.mark.parametrize('case', ('self', 'equivalent', 'changed'))
def test_native_carry_boolean_return_projection(driver: str, case: str) -> None:
    """Both adapters agree on NEG/SBB versus NEG/SETB return and reject SETAE."""
    import angr

    from tools.dosunit.compare.flat32_call_composition import compare_functions_with_calls
    from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane

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


@pytest.mark.parametrize("base,byte_code,wide_code", tuple(row for row in OPERATIONS if row[0] != 13))
@pytest.mark.parametrize("bits", (8, 16, 32))
def test_defined_all_flags_match_native(base: int, byte_code: str, wide_code: str, bits: int) -> None:
    """Six defined arithmetic flags agree with independent native execution."""
    code = bytes.fromhex(byte_code if bits == 8 else ("66" if bits == 16 else "") + wide_code)
    mask, sign = (1 << bits) - 1, 1 << (bits - 1)
    vectors = ((0, 0), (0, 1), (1, mask), (mask, 1), (sign - 1, 1),
               (sign, 1), (sign, mask), (mask, mask), (0x55, 0xaa), (15, 1), (16, 1))
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
            expected = machine.reg_read(UC_X86_REG_EFLAGS) & 0x8d5
            dep1 = result if base in (16, 19) else left
            dep2 = right ^ old_carry if base in (7, 10) else right
            cc_op = base + (0 if bits == 8 else 1 if bits == 16 else 2)
            args = [z3.BitVecVal(value, 32) for value in (cc_op, dep1, dep2, old_carry)]
            actual = z3.simplify(S._z3_apply("summary_x86g_calculate_eflags_all", 32, args, z3))
            assert z3.is_bv_value(actual), (cc_op, "abstract flags")
            assert actual.as_long() == expected, (cc_op, left, right, old_carry)


def test_all_flags_copy_masks_nonarithmetic_bits() -> None:
    """COPY returns only the six flag bits supplied by its dependency."""
    for value in (0, 0xffffffff, 0x8d5, 0x240202, 0x10):
        args = [z3.BitVecVal(x, 32) for x in (0, value, 0, 0)]
        actual = z3.simplify(S._z3_apply("summary_x86g_calculate_eflags_all", 32, args, z3))
        assert z3.is_bv_value(actual)
        assert actual.as_long() == value & 0x8d5


@pytest.mark.parametrize("cc_op", tuple(range(22)))
def test_all_flags_admission_matches_evaluator(cc_op: int) -> None:
    """Logic AF stays undefined; complete supported arithmetic is exact."""
    args = [{"op": "const", "value": hex(x), "width": 32} for x in (cc_op, 1, 2, 0)]
    term = {"op": "summary_x86g_calculate_eflags_all", "args": args}
    assert S._x86_lazy_flag_summary_is_uninterpreted(term, {}) == (cc_op in (13, 14, 15))


@pytest.mark.parametrize("flipped", (0, 1, 4, 16, 64, 128, 2048))
def test_all_flags_comparison_rejects_each_changed_bit(flipped: int) -> None:
    """Known ADD flags prove exactly and each mutated flag produces a real mismatch."""
    args = [{"op": "const", "value": hex(x), "width": 32} for x in (3, 15, 1, 0)]
    term = {"op": "summary_x86g_calculate_eflags_all", "width": 32, "args": args}
    oracle = {"inputs": [], "assignments": [{"id": "flags", **term}], "outputs": {"eax": {"ref": "flags"}}}
    candidate = {"inputs": [], "assignments": [], "outputs": {
        "eax": {"op": "const", "width": 32, "value": hex(16 ^ flipped)}}}
    result = S._compare_functions(oracle, candidate, timeout_ms=1000)
    assert result["status"] == ("passed" if flipped == 0 else "failed"), result


@pytest.mark.parametrize("op,arity,mask", (
    ("summary_x86g_calculate_eflags_c", 4, 1),
    ("summary_x86g_calculate_condition", 5, 1),
    ("summary_x86g_calculate_eflags_all", 4, 0x8d5),
))
def test_abstract_flags_preserve_architectural_result_range(op: str, arity: int, mask: int) -> None:
    """Unknown thunk semantics may choose flag bits but never unrelated high bits."""
    args = [z3.BitVec("flag_input_" + str(i), 32) for i in range(arity)]
    result = S._z3_apply(op, 32, args, z3)
    solver = z3.Solver()
    solver.add(result & ~mask != 0)
    assert solver.check() == z3.unsat
    for value in (0, mask):
        solver = z3.Solver()
        solver.add(result == value)
        assert solver.check() == z3.sat
    term = {"op": op, "args": [{"op": "input", "name": "unknown", "width": 32}] * arity}
    assert S._x86_lazy_flag_summary_is_uninterpreted(term, {})


@pytest.mark.parametrize("mask,expected", ((0xfffff72a, "passed"), (1, "refused")))
def test_abstract_flag_range_proves_only_impossible_bits(mask: int, expected: str) -> None:
    """Range evidence proves absent bits but cannot assert the value of a live flag."""
    names = ("cc_op", "cc_dep1", "cc_dep2", "cc_ndep")
    inputs = [{"name": name, "width": 32} for name in names]
    call = {"id": "flags", "op": "summary_x86g_calculate_eflags_all", "width": 32,
            "args": [{"op": "input", "name": name, "width": 32} for name in names]}
    projected = {"id": "bits", "op": "and", "width": 32,
                 "args": [{"ref": "flags"}, {"op": "const", "value": hex(mask), "width": 32}]}
    oracle = {"inputs": inputs, "assignments": [call, projected], "outputs": {"eax": {"ref": "bits"}}}
    candidate = {"inputs": [], "assignments": [], "outputs": {
        "eax": {"op": "const", "value": "0x0", "width": 32}}}
    result = S._compare_functions(oracle, candidate, timeout_ms=1000)
    assert result["status"] == expected, result


@pytest.mark.parametrize("condition", tuple(range(16)))
def test_unknown_condition_projects_same_abstract_flags(condition: int) -> None:
    """All Jcc predicates must agree with the same unknown arithmetic flags."""
    from tools.dosunit.ssa.x86_lazy_conditions import condition_contract, exact_condition

    args = [z3.BitVec("shared_flag_" + str(i), 32) for i in range(4)]
    flags = S._z3_apply("summary_x86g_calculate_eflags_all", 32, args, z3)
    actual = S._z3_apply("summary_x86g_calculate_condition", 32,
                         [z3.BitVecVal(condition, 32), *args], z3)
    kind = condition_contract(condition, 0)
    assert kind is not None
    expected = exact_condition(kind, flags, z3.BitVecVal(0, 32), z3.BitVecVal(0, 32), output_width=32)
    solver = z3.Solver()
    solver.add(actual != expected)
    assert solver.check() == z3.unsat


def test_unknown_carry_projects_same_abstract_flags() -> None:
    """CF is bit zero of the same unknown helper result, not a second choice."""
    args = [z3.BitVec("shared_carry_" + str(i), 32) for i in range(4)]
    flags = S._z3_apply("summary_x86g_calculate_eflags_all", 32, args, z3)
    carry = S._z3_apply("summary_x86g_calculate_eflags_c", 32, args, z3)
    solver = z3.Solver()
    solver.add(carry != flags & 1)
    assert solver.check() == z3.unsat


@pytest.mark.parametrize("opcode,cc_op,left_shift", (("d1e0", 24, True), ("d1e8", 27, False), ("d1f8", 27, False)))
def test_dword_shift_carry_matches_native(opcode: str, cc_op: int, left_shift: bool) -> None:
    """A dword shift has defined CF for every nonzero masked count."""
    from unicorn.x86_const import UC_X86_REG_ECX

    machine = Uc(UC_ARCH_X86, UC_MODE_32)
    machine.mem_map(0x100000, 0x1000)
    code = bytes.fromhex("d3" + opcode[2:])
    machine.mem_write(0x100000, code)
    for value in (0, 1, 0x80000000, 0xffffffff, 0x12345678):
        for count in (1, 2, 15, 16, 17, 31):
            machine.reg_write(UC_X86_REG_EAX, value)
            machine.reg_write(UC_X86_REG_ECX, count)
            machine.reg_write(UC_X86_REG_EFLAGS, 2)
            machine.emu_start(0x100000, 0x100000 + len(code), count=1)
            result = machine.reg_read(UC_X86_REG_EAX)
            signed_value = value if value < 0x80000000 else value - (1 << 32)
            previous = ((value << (count - 1)) if left_shift else
                        (signed_value if opcode == "d1f8" else value) >> (count - 1)) & 0xffffffff
            args = [z3.BitVecVal(x, 32) for x in (cc_op, result, previous, 0)]
            carry = z3.simplify(S._z3_apply("summary_x86g_calculate_eflags_c", 32, args, z3))
            assert z3.is_bv_value(carry)
            assert carry.as_long() == machine.reg_read(UC_X86_REG_EFLAGS) & 1
    args = [z3.BitVecVal(x, 32) for x in (cc_op, 1, 2, 0)]
    assert not z3.is_bv_value(z3.simplify(S._z3_apply("summary_x86g_calculate_eflags_all", 32, args, z3)))


@pytest.mark.parametrize("opcode,candidate", (("d1e0", "c1e81f"), ("d1e8", "83e001"), ("d1f8", "83e001")))
@pytest.mark.parametrize("changed", (False, True))
def test_native_dword_shift_carry_return(opcode: str, candidate: str, changed: bool) -> None:
    """Carry materialization equals bit extraction; a changed return still fails."""
    import angr

    from tools.dosunit.compare.flat32_call_composition import compare_functions_with_calls

    original = bytes.fromhex(opcode + "19c0f7d8c3")
    rebuilt = bytes.fromhex(candidate + ("83f001" if changed else "") + "c3")
    base = 0x100000
    from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane

    with _driver_lane("msc8") as lane, lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            angr.load_shellcode(original, arch="x86", load_address=base),
            angr.load_shellcode(rebuilt, arch="x86", load_address=base),
            oracle_entry=base, candidate_entry=base,
            oracle_functions={base: len(original)}, candidate_functions={base: len(rebuilt)},
            outputs=("eax",), timeout_ms=5000,
        )
    assert result["status"] == ("failed" if changed else "passed"), result


@pytest.mark.parametrize("cc_op,bits", ((24, 32), (27, 1)))
def test_shift_carry_contract_preserves_only_required_dependencies(cc_op: int, bits: int) -> None:
    """Carry-only shift admission cannot leak into full flag or branch admission."""
    from tools.dosunit.ssa.x86_lazy_conditions import (
        all_flags_contract,
        carry_contract,
        condition_contract,
        condition_dependency_bits,
        exact_condition,
    )

    kind = carry_contract(cc_op)
    assert kind is not None
    assert condition_dependency_bits(kind) == (0, bits, 0)
    assert all_flags_contract(cc_op) is None
    assert condition_contract(2, cc_op) is None
    with pytest.raises(ValueError, match="only carry"):
        exact_condition(kind, *[z3.BitVecVal(0, 32)] * 3, output_width=32)


@pytest.mark.parametrize("cc_op", (22, 23, 25, 26))
def test_narrow_shift_carry_is_not_unconditionally_admitted(cc_op: int) -> None:
    """Wide masked counts can leave narrow shift carry undefined."""
    from tools.dosunit.ssa.x86_lazy_conditions import carry_contract

    assert carry_contract(cc_op) is None


@pytest.mark.parametrize("count,expected", ((0, 1), (32, 1), (1, 0), (33, 0)))
def test_native_shift_zero_count_preserves_incoming_carry(count: int, expected: int) -> None:
    """Masked zero keeps STC carry; a nonzero shift of zero clears carry."""
    import angr

    from tools.dosunit.compare.flat32_call_composition import compare_functions_with_calls
    from tools.dosunit.tests.test_flat32_comparator_lane import _driver_lane

    original = bytes.fromhex("31c0f9c1e0") + bytes([count]) + bytes.fromhex("19c0f7d8c3")
    rebuilt = bytes.fromhex("b8") + expected.to_bytes(4, "little") + bytes.fromhex("c3")
    base = 0x100000
    with _driver_lane("msc8") as lane, lane.adapter.installed(region=True):
        result = compare_functions_with_calls(
            angr.load_shellcode(original, arch="x86", load_address=base),
            angr.load_shellcode(rebuilt, arch="x86", load_address=base),
            oracle_entry=base, candidate_entry=base,
            oracle_functions={base: len(original)}, candidate_functions={base: len(rebuilt)},
            outputs=("eax",), timeout_ms=5000,
        )
    assert result["status"] == "passed", result


def test_symbolic_shift_guard_and_cyclic_selector_remain_unresolved() -> None:
    """Selector folding cannot choose an input-dependent branch or follow cycles."""
    from tools.dosunit.ssa.ssa_constant_terms import constant_flag_selector

    selector = {"op": "ite", "width": 32, "args": [
        {"op": "input", "name": "guard", "width": 1},
        {"op": "const", "value": "0x18", "width": 32},
        {"op": "const", "value": "0x0", "width": 32},
    ]}
    assert constant_flag_selector(selector, {}) is None
    assert constant_flag_selector({"ref": "cycle"}, {"cycle": {"ref": "cycle"}}) is None


@pytest.mark.parametrize("other", (4, 255))
def test_guarded_carry_selector_admission_and_evaluation(other: int) -> None:
    """A finite SUB32/SUB8 choice is exact; an unknown arm remains abstract."""
    guard = z3.BitVec("selector_guard", 1)
    left, right = z3.BitVecs("selector_left selector_right", 32)
    selector = z3.If(guard != 0, z3.BitVecVal(6, 32), z3.BitVecVal(other, 32))
    actual = S._z3_apply("summary_x86g_calculate_eflags_c", 32,
                         [selector, left, right, z3.BitVecVal(0, 32)], z3)
    def literal(value):
        return {"op": "const", "width": 32, "value": hex(value)}
    choice = {"op": "ite", "width": 32, "args": [
        {"op": "input", "name": "selector_guard", "width": 1}, literal(6), literal(other)]}
    term = {"op": "summary_x86g_calculate_eflags_c", "width": 32,
            "args": [choice, literal(0), literal(0), literal(0)]}
    assert S._x86_lazy_flag_summary_is_uninterpreted(term, {}) == (other == 255)
    if other == 4:
        predicate = z3.If(guard != 0, z3.ULT(left, right),
                          z3.ULT(z3.Extract(7, 0, left), z3.Extract(7, 0, right)))
        expected = z3.If(predicate, z3.BitVecVal(1, 32), z3.BitVecVal(0, 32))
        solver = z3.Solver()
        solver.add(actual != expected)
        assert solver.check() == z3.unsat


@pytest.mark.parametrize("arms", ([None, None], [0, 6], [{"ref": "missing"}, {"ref": "missing"}]))
def test_malformed_guarded_flag_selector_remains_unresolved(arms) -> None:
    """Incomplete guarded selectors cannot obtain exact flag admission."""
    from tools.dosunit.ssa.ssa_constant_terms import flag_selector_choices

    term = {"op": "ite", "width": 32, "args": [
        {"op": "input", "name": "guard", "width": 1}, *arms]}
    assert flag_selector_choices(term, {}) is None
