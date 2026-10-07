from __future__ import annotations

from types import SimpleNamespace

from inertia.semantics.branch_target_return import (
    BranchTargetReturnEffectKind8616,
    TerminalAxReturnEffectKind8616,
    TerminalAxReturnOperandKind8616,
    branch_target_return_effect_8616,
    terminal_ax_return_effect_8616,
)
from inertia.semantics.return_register_preservation import (
    instruction_preserves_return_registers_8616,
)


class _Insn:
    def __init__(self, mnemonic: str, operands=()):
        self.mnemonic = mnemonic
        self.operands = tuple(operands)

    def reg_name(self, reg: int) -> str:
        return {1: "ax", 2: "dx", 3: "bp", 4: "ah", 5: "al", 6: "cl", 7: "cx", 8: "sp"}.get(reg, "")


def _reg_operand(reg: int):
    return SimpleNamespace(type=1, reg=reg)


def _imm_operand(value: int):
    return SimpleNamespace(type=2, imm=value)


def _mem_operand(*, base: int = 0, index: int = 0, disp: int = 0, size: int = 2):
    return SimpleNamespace(type=3, mem=SimpleNamespace(base=base, index=index, disp=disp), size=size)


def _no_target(_insn: object) -> int | None:
    return None


def test_branch_target_return_effect_classifies_mov_register_immediate():
    effect = branch_target_return_effect_8616(
        _Insn("mov", [_reg_operand(1), _imm_operand(0xFFFF)]),
        _no_target,
    )

    assert effect.kind is BranchTargetReturnEffectKind8616.MOV_REG_IMM
    assert effect.dst_reg == "ax"
    assert effect.imm == 0xFFFF


def test_branch_target_return_effect_classifies_register_self_clear():
    effect = branch_target_return_effect_8616(
        _Insn("sub", [_reg_operand(1), _reg_operand(1)]),
        _no_target,
    )

    assert effect.kind is BranchTargetReturnEffectKind8616.MOV_REG_IMM
    assert effect.dst_reg == "ax"
    assert effect.imm == 0


def test_branch_target_return_effect_classifies_stack_load():
    effect = branch_target_return_effect_8616(
        _Insn("mov", [_reg_operand(2), _mem_operand(base=3, disp=-4, size=2)]),
        _no_target,
    )

    assert effect.kind is BranchTargetReturnEffectKind8616.MOV_REG_STACK
    assert effect.dst_reg == "dx"
    assert effect.mem_disp == -4
    assert effect.mem_size == 2


def test_branch_target_return_effect_classifies_direct_global_load():
    effect = branch_target_return_effect_8616(
        _Insn("mov", [_reg_operand(1), _mem_operand(disp=0x1234, size=1)]),
        _no_target,
    )

    assert effect.kind is BranchTargetReturnEffectKind8616.MOV_REG_DIRECT_GLOBAL
    assert effect.dst_reg == "ax"
    assert effect.mem_disp == 0x1234
    assert effect.mem_size == 1


def test_branch_target_return_effect_classifies_ax_alu_immediate():
    effect = branch_target_return_effect_8616(
        _Insn("sub", [_reg_operand(1), _imm_operand(3)]),
        _no_target,
    )

    assert effect.kind is BranchTargetReturnEffectKind8616.AX_ALU_IMM
    assert effect.op == "Sub"
    assert effect.imm == 3


def test_branch_target_return_effect_classifies_ax_incdec():
    effect = branch_target_return_effect_8616(
        _Insn("inc", [_reg_operand(1)]),
        _no_target,
    )

    assert effect.kind is BranchTargetReturnEffectKind8616.AX_INCDEC
    assert effect.op == "Add"


def test_branch_target_return_effect_classifies_jump_target():
    insn = _Insn("jmp")

    effect = branch_target_return_effect_8616(insn, lambda _insn: 0x4567)

    assert effect.kind is BranchTargetReturnEffectKind8616.JUMP
    assert effect.jump_target == 0x4567


def test_branch_target_return_effect_classifies_return():
    effect = branch_target_return_effect_8616(_Insn("ret"), _no_target)

    assert effect.kind is BranchTargetReturnEffectKind8616.RETURN


def test_branch_target_return_effect_classifies_return_register_preserving_epilogue_steps():
    instructions = (
        _Insn("leave"),
        _Insn("nop"),
        _Insn("pop", [_reg_operand(3)]),
        _Insn("mov", [_reg_operand(8), _reg_operand(3)]),
    )

    assert all(instruction_preserves_return_registers_8616(insn) for insn in instructions)


def test_branch_target_return_effect_refuses_return_register_pop():
    assert not instruction_preserves_return_registers_8616(
        _Insn("pop", [_reg_operand(1)])
    )


def test_branch_target_return_effect_classifies_conditional_control_boundary():
    effect = branch_target_return_effect_8616(
        _Insn("jne", [_imm_operand(0x1234)]),
        _no_target,
    )

    assert effect.kind is BranchTargetReturnEffectKind8616.CONTROL_BOUNDARY


def test_branch_target_return_effect_refuses_unrelated_instruction():
    effect = branch_target_return_effect_8616(
        _Insn("mov", [_reg_operand(4), _imm_operand(1)]),
        _no_target,
    )

    assert effect.kind is BranchTargetReturnEffectKind8616.OTHER


def test_terminal_ax_return_effect_classifies_call_clobber():
    effect = terminal_ax_return_effect_8616(_Insn("call"))

    assert effect.kind is TerminalAxReturnEffectKind8616.CALL_CLOBBER


def test_terminal_ax_return_effect_classifies_software_interrupt_clobber():
    effect = terminal_ax_return_effect_8616(_Insn("int", [_imm_operand(0x33)]))

    assert effect.kind is TerminalAxReturnEffectKind8616.CALL_CLOBBER


def test_terminal_ax_return_effect_excludes_microsoft_x87_interrupt_escape():
    effect = terminal_ax_return_effect_8616(_Insn("int", [_imm_operand(0x34)]))

    assert effect.kind is TerminalAxReturnEffectKind8616.OTHER


def test_terminal_ax_return_effect_classifies_clear_ah_to_zero():
    effect = terminal_ax_return_effect_8616(
        _Insn("sub", [_reg_operand(4), _reg_operand(4)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.CLEAR_AH_TO_ZERO


def test_terminal_ax_return_effect_classifies_mov_register_immediate():
    effect = terminal_ax_return_effect_8616(
        _Insn("mov", [_reg_operand(6), _imm_operand(3)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_IMM
    assert effect.dst_reg == "cl"
    assert effect.imm == 3


def test_terminal_ax_return_effect_classifies_stack_load():
    effect = terminal_ax_return_effect_8616(
        _Insn("mov", [_reg_operand(5), _mem_operand(base=3, disp=5, size=1)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_STACK
    assert effect.dst_reg == "al"
    assert effect.mem_disp == 5
    assert effect.mem_size == 1


def test_terminal_ax_return_effect_classifies_high_byte_stack_load():
    effect = terminal_ax_return_effect_8616(
        _Insn("mov", [_reg_operand(4), _mem_operand(base=3, disp=7, size=1)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_STACK
    assert effect.dst_reg == "ah"
    assert effect.mem_disp == 7
    assert effect.mem_size == 1


def test_terminal_ax_return_effect_classifies_direct_global_load():
    effect = terminal_ax_return_effect_8616(
        _Insn("mov", [_reg_operand(1), _mem_operand(disp=0x2345, size=2)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_DIRECT_GLOBAL
    assert effect.dst_reg == "ax"
    assert effect.mem_disp == 0x2345
    assert effect.mem_size == 2


def test_terminal_ax_return_effect_classifies_ax_alu_immediate():
    effect = terminal_ax_return_effect_8616(
        _Insn("shl", [_reg_operand(1), _imm_operand(1)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.AX_ALU_IMM
    assert effect.op == "Shl"
    assert effect.imm == 1


def test_terminal_ax_return_effect_classifies_ax_incdec():
    effect = terminal_ax_return_effect_8616(
        _Insn("dec", [_reg_operand(1)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.AX_INCDEC
    assert effect.op == "Sub"


def test_terminal_ax_return_effect_classifies_al_shl_immediate():
    effect = terminal_ax_return_effect_8616(
        _Insn("shl", [_reg_operand(5), _imm_operand(2)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.AL_SHL_IMM
    assert effect.op == "Shl"
    assert effect.imm == 2


def test_terminal_ax_return_effect_classifies_ax_shr_cl():
    effect = terminal_ax_return_effect_8616(
        _Insn("shr", [_reg_operand(1), _reg_operand(6)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.AX_SHR_CL
    assert effect.op == "Shr"


def test_terminal_ax_return_effect_classifies_cx_shl_immediate():
    effect = terminal_ax_return_effect_8616(
        _Insn("shl", [_reg_operand(7), _imm_operand(8)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.CX_SHL_IMM
    assert effect.op == "Shl"
    assert effect.imm == 8


def test_terminal_ax_return_effect_classifies_ax_or_cx():
    effect = terminal_ax_return_effect_8616(
        _Insn("or", [_reg_operand(1), _reg_operand(7)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.AX_OR_CX
    assert effect.op == "Or"


def test_terminal_ax_return_effect_classifies_ax_add_dx_register_value():
    effect = terminal_ax_return_effect_8616(_Insn("add", [_reg_operand(1), _reg_operand(2)]))

    assert effect.kind is TerminalAxReturnEffectKind8616.REG_ALU_VALUE
    assert effect.dst_reg == "ax"
    assert effect.rhs_kind is TerminalAxReturnOperandKind8616.REGISTER
    assert effect.rhs_reg == "dx"
    assert effect.op == "Add"


def test_terminal_ax_return_effect_classifies_al_alu_immediate_value():
    effect = terminal_ax_return_effect_8616(
        _Insn("xor", [_reg_operand(5), _imm_operand(0x80)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.REG_ALU_VALUE
    assert effect.dst_reg == "al"
    assert effect.rhs_kind is TerminalAxReturnOperandKind8616.IMM
    assert effect.op == "Xor"
    assert effect.imm == 0x80


def test_terminal_ax_return_effect_classifies_al_alu_stack_value():
    effect = terminal_ax_return_effect_8616(
        _Insn("add", [_reg_operand(5), _mem_operand(base=3, disp=7, size=1)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.REG_ALU_VALUE
    assert effect.dst_reg == "al"
    assert effect.rhs_kind is TerminalAxReturnOperandKind8616.STACK
    assert effect.op == "Add"
    assert effect.mem_disp == 7
    assert effect.mem_size == 1


def test_terminal_ax_return_effect_classifies_ax_alu_direct_global_value():
    effect = terminal_ax_return_effect_8616(
        _Insn("sub", [_reg_operand(1), _mem_operand(disp=0x3456, size=2)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.REG_ALU_VALUE
    assert effect.dst_reg == "ax"
    assert effect.rhs_kind is TerminalAxReturnOperandKind8616.DIRECT_GLOBAL
    assert effect.op == "Sub"
    assert effect.mem_disp == 0x3456
    assert effect.mem_size == 2


def test_terminal_ax_return_effect_keeps_ax_alu_immediate_specific_effect():
    effect = terminal_ax_return_effect_8616(
        _Insn("add", [_reg_operand(1), _imm_operand(5)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.AX_ALU_IMM
    assert effect.op == "Add"
    assert effect.imm == 5


def test_terminal_ax_return_effect_classifies_ax_mul_stack_value():
    effect = terminal_ax_return_effect_8616(
        _Insn("imul", [_mem_operand(base=3, disp=-2, size=2)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.AX_MUL_VALUE
    assert effect.dst_reg == "ax"
    assert effect.rhs_kind is TerminalAxReturnOperandKind8616.STACK
    assert effect.op == "Mul"
    assert effect.mem_disp == -2
    assert effect.mem_size == 2


def test_terminal_ax_return_effect_refuses_indexed_alu_memory_value():
    effect = terminal_ax_return_effect_8616(
        _Insn("add", [_reg_operand(5), _mem_operand(base=3, index=1, disp=5, size=1)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.OTHER


def test_terminal_ax_return_effect_refuses_unrelated_instruction():
    effect = terminal_ax_return_effect_8616(
        _Insn("sub", [_reg_operand(3), _reg_operand(3)]),
    )

    assert effect.kind is TerminalAxReturnEffectKind8616.OTHER
