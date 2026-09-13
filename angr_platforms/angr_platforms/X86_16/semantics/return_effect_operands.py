"""Typed return effects and decoded scalar operand interpretation.

Layer: Semantics.
Responsibility: classify instruction effects used by branch-target return recovery.
Owns instruction effects, flags, branch meaning, and expression interpretation.
This module decodes structured capstone instruction objects into typed effects.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
Do not build C AST nodes, materialize stack/global objects, perform CFG
structuring, rewrite output, or make CLI/reporting decisions here.
Dynamic third-party capstone compatibility boundary: capstone instruction and
operand wrappers expose external attributes, so documented ``getattr`` use is
allowed only at that boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_DS, X86_REG_SS

from ..msvc_x87_interrupts import is_msvc_x87_emulation_interrupt_8616

_BINARY_OPERAND_COUNT_8616 = 2


class BranchTargetReturnEffectKind8616(Enum):
    """Kinds of branch-target return effects understood by the decompiler."""

    MOV_REG_IMM = "mov_reg_imm"
    MOV_REG_STACK = "mov_reg_stack"
    MOV_REG_DIRECT_GLOBAL = "mov_reg_direct_global"
    AX_ALU_IMM = "ax_alu_imm"
    AX_INCDEC = "ax_incdec"
    JUMP = "jump"
    RETURN = "return"
    CONTROL_BOUNDARY = "control_boundary"
    OTHER = "other"


class TerminalAxReturnEffectKind8616(Enum):
    """Kinds of terminal AX-return instruction effects understood by semantics."""

    CALL_CLOBBER = "call_clobber"
    CLEAR_AH_TO_ZERO = "clear_ah_to_zero"
    MOV_REG_IMM = "mov_reg_imm"
    MOV_REG_STACK = "mov_reg_stack"
    MOV_REG_DIRECT_GLOBAL = "mov_reg_direct_global"
    AX_ALU_IMM = "ax_alu_imm"
    AX_INCDEC = "ax_incdec"
    AL_SHL_IMM = "al_shl_imm"
    AX_SHR_CL = "ax_shr_cl"
    CX_SHL_IMM = "cx_shl_imm"
    AX_OR_CX = "ax_or_cx"
    REG_ALU_VALUE = "reg_alu_value"
    AX_MUL_VALUE = "ax_mul_value"
    OTHER = "other"


class TerminalAxReturnOperandKind8616(Enum):
    """Operand source kinds for terminal AX-return value effects."""

    IMM = "imm"
    REGISTER = "register"
    STACK = "stack"
    DIRECT_GLOBAL = "direct_global"


@dataclass(frozen=True, slots=True)
class BranchTargetReturnEffect8616:
    """Typed effect extracted from one branch-target instruction."""

    kind: BranchTargetReturnEffectKind8616
    dst_reg: str | None = None
    imm: int | None = None
    op: str | None = None
    mem_disp: int | None = None
    mem_size: int | None = None
    jump_target: int | None = None


@dataclass(frozen=True, slots=True)
class TerminalAxReturnEffect8616:
    """Typed effect extracted from one terminal AX-return instruction."""

    kind: TerminalAxReturnEffectKind8616
    dst_reg: str | None = None
    rhs_kind: TerminalAxReturnOperandKind8616 | None = None
    rhs_reg: str | None = None
    imm: int | None = None
    op: str | None = None
    mem_disp: int | None = None
    mem_size: int | None = None


def _operand_kind_8616(operand: object) -> int:
    """Return a capstone operand kind from the dynamic capstone boundary."""
    # Dynamic third-party capstone boundary: operand kind is decoded by capstone wrappers.
    return int(getattr(operand, "type", -1))


def _is_software_interrupt_boundary_8616(
    mnemonic: str,
    operands: tuple[object, ...],
) -> bool:
    """Classify software interrupts while excluding Microsoft x87 escapes."""
    if mnemonic not in {"int", "int1", "int3", "into"}:
        return False
    return not (
        mnemonic == "int"
        and len(operands) == 1
        and _operand_kind_8616(operands[0]) == X86_OP_IMM
        and is_msvc_x87_emulation_interrupt_8616(int(getattr(operands[0], "imm", -1)))
    )


def _register_name_8616(insn: object, operand: object) -> str:
    """Return the lower-case register name for a capstone register operand."""
    # Dynamic third-party capstone boundary: register ids are decoded by capstone wrappers.
    reg = getattr(operand, "reg", None)
    # Dynamic third-party capstone boundary: register-name rendering is provided by capstone.
    reg_name = getattr(insn, "reg_name", None)
    if not isinstance(reg, int) or not callable(reg_name):
        return ""
    return str(reg_name(reg)).lower()


def _memory_base_index_8616(insn: object, mem: object) -> tuple[str | None, int, int]:
    """Return memory base register name plus raw base/index ids from capstone."""
    # Dynamic third-party capstone boundary: memory operand base is decoded by capstone wrappers.
    base = int(getattr(mem, "base", 0) or 0)
    # Dynamic third-party capstone boundary: memory operand index is decoded by capstone wrappers.
    index = int(getattr(mem, "index", 0) or 0)
    # Dynamic third-party capstone boundary: register-name rendering is provided by capstone.
    reg_name = getattr(insn, "reg_name", None)
    base_name = str(reg_name(base)).lower() if base and callable(reg_name) else None
    return base_name, base, index


def _memory_uses_segment_8616(mem: object, expected: int) -> bool:
    """Require the implicit default or its matching explicit segment override."""
    # Dynamic Capstone boundary: absent segment means the addressing-mode default.
    return getattr(mem, "segment", 0) in {0, expected}


def _terminal_value_operand_8616(
    insn: object,
    operand: object,
) -> tuple[TerminalAxReturnOperandKind8616, int | None, int | None, int | None, str | None] | None:
    """Classify a register, immediate, BP-stack, or direct-global operand."""
    if _operand_kind_8616(operand) == X86_OP_REG:
        register = _register_name_8616(insn, operand)
        return (TerminalAxReturnOperandKind8616.REGISTER, None, None, None, register) if register else None
    if _operand_kind_8616(operand) == X86_OP_IMM:
        # Dynamic third-party capstone boundary: immediate payload is decoded by capstone.
        return TerminalAxReturnOperandKind8616.IMM, int(getattr(operand, "imm", 0) or 0), None, None, None
    if _operand_kind_8616(operand) != X86_OP_MEM:
        return None
    # Dynamic third-party capstone boundary: memory operand payload is decoded by capstone.
    mem = getattr(operand, "mem", None)
    if mem is None:
        return None
    base_name, base, index = _memory_base_index_8616(insn, mem)
    # Dynamic third-party capstone boundary: memory operand size is decoded by capstone.
    size = int(getattr(operand, "size", 0) or 2)
    # Dynamic third-party capstone boundary: displacement is decoded by capstone.
    disp = int(getattr(mem, "disp", 0) or 0)
    if base_name == "bp" and index == 0 and _memory_uses_segment_8616(mem, X86_REG_SS):
        return TerminalAxReturnOperandKind8616.STACK, None, disp, size, None
    if base == 0 and index == 0 and _memory_uses_segment_8616(mem, X86_REG_DS):
        return TerminalAxReturnOperandKind8616.DIRECT_GLOBAL, None, disp, size, None
    return None


def _self_cleared_register_8616(
    insn: object, mnemonic: str, operands: tuple[object, ...],
) -> str | None:
    """Identify SUB/XOR of one register with itself, independent of flags.

    This classifies only the resulting register value. It does not authorize
    deleting the instruction or ignoring its flag effects.
    """
    if mnemonic not in {"sub", "xor"} or len(operands) != _BINARY_OPERAND_COUNT_8616:
        return None
    if any(_operand_kind_8616(operand) != X86_OP_REG for operand in operands):
        return None
    destination = _register_name_8616(insn, operands[0])
    source = _register_name_8616(insn, operands[1])
    return destination if destination and destination == source else None


def _terminal_value_arithmetic_effect_8616(
    insn: object, mnemonic: str, operands: tuple[object, ...],
) -> TerminalAxReturnEffect8616 | None:
    """Classify return arithmetic with a decoded scalar source."""
    if (
        mnemonic in {"add", "sub", "xor"}
        and len(operands) == _BINARY_OPERAND_COUNT_8616
        and _operand_kind_8616(operands[0]) == X86_OP_REG
        and _register_name_8616(insn, operands[0]) == "al"
    ):
        value_operand = _terminal_value_operand_8616(insn, operands[1])
        if value_operand is None:
            return TerminalAxReturnEffect8616(TerminalAxReturnEffectKind8616.OTHER)
        rhs_kind, rhs_imm, mem_disp, mem_size, rhs_reg = value_operand
        return TerminalAxReturnEffect8616(
            TerminalAxReturnEffectKind8616.REG_ALU_VALUE,
            dst_reg="al",
            rhs_kind=rhs_kind,
            rhs_reg=rhs_reg,
            imm=rhs_imm,
            op={"add": "Add", "sub": "Sub", "xor": "Xor"}[mnemonic],
            mem_disp=mem_disp,
            mem_size=mem_size,
        )
    if (
        mnemonic in {"add", "sub"}
        and len(operands) == _BINARY_OPERAND_COUNT_8616
        and _operand_kind_8616(operands[0]) == X86_OP_REG
        and _register_name_8616(insn, operands[0]) == "ax"
    ):
        value_operand = _terminal_value_operand_8616(insn, operands[1])
        if value_operand is None or value_operand[0] is TerminalAxReturnOperandKind8616.IMM:
            return TerminalAxReturnEffect8616(TerminalAxReturnEffectKind8616.OTHER, dst_reg="ax")
        rhs_kind, rhs_imm, mem_disp, mem_size, rhs_reg = value_operand
        return TerminalAxReturnEffect8616(
            TerminalAxReturnEffectKind8616.REG_ALU_VALUE,
            dst_reg="ax",
            rhs_kind=rhs_kind,
            rhs_reg=rhs_reg,
            imm=rhs_imm,
            op={"add": "Add", "sub": "Sub"}[mnemonic],
            mem_disp=mem_disp,
            mem_size=mem_size,
        )
    if mnemonic in {"mul", "imul"} and len(operands) == 1:
        value_operand = _terminal_value_operand_8616(insn, operands[0])
        if value_operand is None:
            return TerminalAxReturnEffect8616(TerminalAxReturnEffectKind8616.OTHER)
        rhs_kind, rhs_imm, mem_disp, mem_size, rhs_reg = value_operand
        return TerminalAxReturnEffect8616(
            TerminalAxReturnEffectKind8616.AX_MUL_VALUE, dst_reg="ax",
            rhs_kind=rhs_kind,
            rhs_reg=rhs_reg,
            imm=rhs_imm,
            op="Mul",
            mem_disp=mem_disp,
            mem_size=mem_size,
        )
    return None
