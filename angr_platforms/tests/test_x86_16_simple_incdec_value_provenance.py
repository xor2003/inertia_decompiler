"""Regress exact value and condition provenance through optimized arithmetic."""

from types import SimpleNamespace

import angr
import pytest
import pyvex
from angr import options as o
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir import IRBinaryValue, IRValue, MemSpace
from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.lift_86_16 import Instruction_ANY


@pytest.mark.parametrize("opcode", ["2bc0", "29c0", "33c0", "31c0", "2bc9", "33c9"])
def test_self_zeroing_register_write_has_no_incoming_value_dependency(opcode):
    """Publish zero before native SSA can invent an incoming-register carrier."""
    arch = Arch86_16()
    block = pyvex.lift(bytes.fromhex(opcode + "7400"), 0x100, arch, opt_level=0, max_inst=1)
    register = "cx" if opcode.endswith("c9") else "ax"
    writes = [statement.data for statement in block.statements
              if isinstance(statement, pyvex.stmt.Put) and statement.offset == arch.registers[register][0]]
    assert len(writes) == 1
    assert isinstance(writes[0], pyvex.expr.Const)
    assert writes[0].con.value == 0
    assert writes[0].result_size(block.tyenv) == 16


@pytest.mark.parametrize("opcode,flag_mask", [("2bc0", 0x8D5), ("33c0", 0x8C5)])
@pytest.mark.parametrize("initial", [0, 0x8000, 0xFFFF])
def test_self_zeroing_preserves_upper_register_and_defined_flags(opcode, flag_mask, initial):
    """Zero AX without clearing upper EAX or losing defined flag effects."""
    project = angr.load_shellcode(bytes.fromhex(opcode), arch=Arch86_16(), load_address=0x100)
    state = project.factory.blank_state(
        addr=0x100, add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
    )
    state.regs.eax = 0xA5A50000 | initial
    state.regs.flags = 0xED7
    successors = project.factory.successors(state, num_inst=1).flat_successors
    assert len(successors) == 1
    result = successors[0]
    assert result.solver.eval(result.regs.eax) == 0xA5A50000
    flags = result.solver.eval(result.regs.flags)
    assert flags & flag_mask == 0x44
    assert flags & 0x600 == 0x600


@pytest.mark.parametrize("opcode,expected", [("2bc1", 0xFFFD), ("33c1", 5)])
def test_distinct_register_arithmetic_keeps_value_dependency(opcode, expected):
    """Different source registers are not zeroing idioms."""
    project = angr.load_shellcode(bytes.fromhex(opcode), arch=Arch86_16(), load_address=0x100)
    state = project.factory.blank_state(
        addr=0x100, add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
    )
    state.regs.ax, state.regs.cx = 3, 6
    successors = project.factory.successors(state, num_inst=1).flat_successors
    assert len(successors) == 1
    assert successors[0].solver.eval(successors[0].regs.ax) == expected


@pytest.mark.parametrize("opcode", ["2bc0", "33c0"])
@pytest.mark.parametrize("initial", [0, 0x8000, 0xFFFF])
def test_self_zeroing_branch_uses_new_zero_condition(opcode, initial):
    """The optimized logical path must not branch using stale incoming flags."""
    project = angr.load_shellcode(
        bytes.fromhex(opcode + "7502909090"), arch=Arch86_16(), load_address=0x100,
    )
    state = project.factory.blank_state(
        addr=0x100, add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
    )
    state.regs.eax, state.regs.flags = 0xA5A50000 | initial, 0
    successors = project.factory.successors(state, num_inst=2).flat_successors
    assert len(successors) == 1
    assert successors[0].addr == 0x104
    assert successors[0].solver.eval(successors[0].regs.eax) == 0xA5A50000


@pytest.mark.parametrize("address_bits", [16, 32])
@pytest.mark.parametrize(
    ("opcode", "initial", "incoming_flags", "expected", "target"),
    [
        (0x41, 0xFFFF, 1, 0, 0x103),
        (0x41, 0, 0x41, 1, 0x105),
        (0x49, 1, 1, 0, 0x103),
        (0x49, 2, 0x41, 1, 0x105),
    ],
)
def test_simple_incdec_jnz_executes_new_zero_flag(
    address_bits, opcode, initial, incoming_flags, expected, target
) -> None:
    """Branch on INC/DEC's result, not stale flags, retaining incoming carry."""
    code = bytes([opcode, 0x75, 2, 0x90, 0x90, 0x90])
    project = angr.load_shellcode(code, arch=Arch86_16(), load_address=0x100)
    project.arch.bits = address_bits
    state = project.factory.blank_state(
        addr=0x100,
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
    )
    state.regs.cx = initial
    state.regs.flags = incoming_flags
    successors = project.factory.successors(state, num_inst=2).flat_successors
    assert len(successors) == 1
    result = successors[0]
    assert result.solver.eval(result.regs.cx) == expected
    assert result.addr == target
    assert result.solver.eval(result.regs.flags) & 1 == incoming_flags & 1


@pytest.mark.parametrize("opcode,delta,overflow_input", [(0x40, 1, 0x7FFF), (0x48, -1, 0x8000)])
@pytest.mark.parametrize("initial", [0, 1, 0x7FFE, 0x7FFF, 0x8000, 0x8001, 0xFFFF])
@pytest.mark.parametrize("carry", [0, 1])
def test_simple_incdec_jge_preserves_signed_overflow_semantics(opcode, delta, overflow_input, initial, carry):
    project = angr.load_shellcode(bytes([opcode, 0x7D, 2, 0x90, 0x90, 0x90]), arch=Arch86_16(), load_address=0x100)
    state = project.factory.blank_state(
        addr=0x100, add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
    )
    state.regs.ax, state.regs.flags = initial, 0x880 | carry
    successors = project.factory.successors(state, num_inst=2).flat_successors
    assert len(successors) == 1
    result = successors[0]
    expected = (initial + delta) & 0xFFFF
    sign, overflow = expected >> 15, int(initial == overflow_input)
    assert result.solver.eval(result.regs.ax) == expected
    assert result.solver.eval(result.regs.flags) & 0x881 == (sign << 7) | (overflow << 11) | carry
    assert result.addr == (0x105 if sign == overflow else 0x103)


def test_simple_inc_preserves_exact_stack_value_for_following_cmp(monkeypatch) -> None:
    """An optimized INC must expose the incremented value to a later CMP."""
    monkeypatch.delenv("INERTIA_ENABLE_AFFINE_SWITCH_CONDITIONS", raising=False)
    original_index_state = dict(
        Instruction_ANY._inertia_condition_index_reg_state_8616
    )
    original_value_state = dict(
        Instruction_ANY._inertia_condition_reg_value_state_8616
    )
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction.arch = Arch86_16()
    instruction.addr = 0x400D
    instruction.cs = SimpleNamespace(size=3)
    flag_inputs = []
    monkeypatch.setattr(instruction, "emu", SimpleNamespace(
        _inertia_current_block_addr=0x4000, update_eflags_inc=flag_inputs.append
    ), raising=False)
    instruction._get_reg16 = lambda reg_name: 4
    instruction._const16 = lambda value: value
    instruction._next_instruction_is_simple_jcc = lambda: False
    instruction.put = lambda val, reg: None

    try:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = {}
        Instruction_ANY._inertia_condition_reg_value_state_8616 = {}
        instruction._set_condition_index_reg_stack_state_8616(
            "ax",
            ("bp", 0xFFFC, -4),
        )
        instruction.addr = 0x4010
        instruction.cs = SimpleNamespace(size=1)

        assert instruction._lift_simple_incdec_reg16_8616(
            "inc_reg16",
            ("inc_reg16", "ax"),
        )
        assert flag_inputs == [4]
        instruction.addr = 0x4011
        instruction.cs = SimpleNamespace(size=3)
        operands = instruction._condition_operands_from_cmp_semantics_8616(
            ("cmp_reg_mem16", "ax", ("bp", 4, 4)),
        )
        assert operands is not None
        lhs, rhs = operands
    finally:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = (
            original_index_state
        )
        Instruction_ANY._inertia_condition_reg_value_state_8616 = (
            original_value_state
        )

    assert lhs == IRBinaryValue(
        "add",
        IRValue(
            MemSpace.SS,
            name="bp",
            offset=-4,
            size=2,
            expr=("cmp-stack", "bp"),
        ),
        IRValue(
            MemSpace.CONST,
            const=1,
            size=2,
            expr=("cmp-imm",),
        ),
        size=2,
    )
    assert rhs == IRValue(
        MemSpace.SS,
        name="bp",
        offset=4,
        size=2,
        expr=("cmp-stack", "bp"),
    )


def test_machine_block_preserves_inc_stack_value_in_cmp_condition(monkeypatch) -> None:
    """The real MOV/INC/CMP/JLE sequence must cache ``stack + 1 <= arg``."""
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    monkeypatch.setattr(
        Instruction_ANY,
        "_inertia_pending_condition_sources_by_addr",
        {},
    )
    monkeypatch.setattr(
        Instruction_ANY,
        "_inertia_condition_index_reg_state_8616",
        {},
    )
    monkeypatch.setattr(
        Instruction_ANY,
        "_inertia_condition_reg_value_state_8616",
        {},
    )

    pyvex.lift(
        bytes.fromhex("8b46fc403b46047e0390c3"),
        0x4000,
        Arch86_16(),
        opt_level=0,
    )

    condition = Instruction_ANY._inertia_module_condition_cache[0x4000][0]
    assert isinstance(condition, ConditionIR)
    assert condition.op == "sle"
    assert condition.lhs == IRBinaryValue(
        "add",
        IRValue(
            MemSpace.SS,
            name="bp",
            offset=-4,
            size=2,
            expr=("cmp-stack", "bp"),
        ),
        IRValue(
            MemSpace.CONST,
            const=1,
            size=2,
            expr=("cmp-imm",),
        ),
        size=2,
    )
    assert condition.rhs == IRValue(
        MemSpace.SS,
        name="bp",
        offset=4,
        size=2,
        expr=("cmp-stack", "bp"),
    )


def test_machine_block_keeps_distinct_shifted_indices_in_byte_cmp(monkeypatch) -> None:
    """Full-lift SHL must retain each stack-derived indexed DS address."""
    monkeypatch.setattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    monkeypatch.setattr(
        Instruction_ANY,
        "_inertia_pending_condition_sources_by_addr",
        {},
    )
    monkeypatch.setattr(
        Instruction_ANY,
        "_inertia_condition_index_reg_state_8616",
        {},
    )
    monkeypatch.setattr(
        Instruction_ANY,
        "_inertia_condition_reg_value_state_8616",
        {},
    )

    pyvex.lift(
        bytes.fromhex(
            "ff06aa0b8b5efed1e38b76fcd1e68a844c0b38874c0b7c0390c3"
        ),
        0x4000,
        Arch86_16(),
        opt_level=0,
    )

    condition = Instruction_ANY._inertia_module_condition_cache[0x4000][0]
    assert isinstance(condition, ConditionIR)
    assert condition.op == "slt"
    assert condition.lhs == IRValue(
        MemSpace.DS,
        offset=0xB4C,
        size=1,
        index=IRValue(
            MemSpace.SS,
            name="bp",
            offset=-2,
            size=2,
            expr=("cmp-stack", "bp"),
        ),
        index_shift=1,
        memory_access_size=1,
        memory_access_insn=0x4012,
    )
    assert condition.rhs == IRValue(
        MemSpace.DS,
        offset=0xB4C,
        size=1,
        index=IRValue(
            MemSpace.SS,
            name="bp",
            offset=-4,
            size=2,
            expr=("cmp-stack", "bp"),
        ),
        index_shift=1,
        memory_access_size=1,
        memory_access_insn=0x400E,
    )
