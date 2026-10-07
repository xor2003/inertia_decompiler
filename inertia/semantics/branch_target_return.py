"""Branch-target and terminal-return instruction classification.

Layer: Semantics.
Responsibility: classify decoded instructions into typed return-value effects.
Shared contracts and scalar operand interpretation live in return_effect_operands.
These projections do not authorize discarding flag effects or rewriting C.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable

from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_DS, X86_REG_SS

from .return_effect_operands import (
    _BINARY_OPERAND_COUNT_8616,
    BranchTargetReturnEffect8616,
    BranchTargetReturnEffectKind8616,
    TerminalAxReturnEffect8616,
    TerminalAxReturnEffectKind8616,
    TerminalAxReturnOperandKind8616,
    _is_software_interrupt_boundary_8616,
    _memory_base_index_8616,
    _memory_uses_segment_8616,
    _operand_kind_8616,
    _register_name_8616,
    _self_cleared_register_8616,
    _terminal_value_arithmetic_effect_8616,
)


def _branch_move_effect_8616(
    insn: object, mnemonic: str, operands: tuple[object, ...],
) -> BranchTargetReturnEffect8616 | None:
    """Classify a branch-return register move from decoded operands."""
    if (
        mnemonic == "mov"
        and len(operands) == _BINARY_OPERAND_COUNT_8616
        and _operand_kind_8616(operands[0]) == X86_OP_REG
        and _register_name_8616(insn, operands[0]) in {"ax", "dx"}
    ):
        dst_reg = _register_name_8616(insn, operands[0])
        rhs = operands[1]
        if _operand_kind_8616(rhs) == X86_OP_IMM:
            # Dynamic third-party capstone boundary: immediate payload is decoded by capstone.
            imm = int(getattr(rhs, "imm", 0) or 0)
            return BranchTargetReturnEffect8616(
                BranchTargetReturnEffectKind8616.MOV_REG_IMM,
                dst_reg=dst_reg,
                imm=imm,
            )
        if _operand_kind_8616(rhs) == X86_OP_MEM:
            # Dynamic third-party capstone boundary: memory operand payload is decoded by capstone.
            mem = getattr(rhs, "mem", None)
            if mem is None:
                return BranchTargetReturnEffect8616(BranchTargetReturnEffectKind8616.OTHER)
            base_name, base, index = _memory_base_index_8616(insn, mem)
            # Dynamic third-party capstone boundary: memory operand size is decoded by capstone.
            size = int(getattr(rhs, "size", 0) or 2)
            # Dynamic third-party capstone boundary: displacement is decoded by capstone.
            disp = int(getattr(mem, "disp", 0) or 0)
            if base_name == "bp" and index == 0 and _memory_uses_segment_8616(mem, X86_REG_SS):
                return BranchTargetReturnEffect8616(
                    BranchTargetReturnEffectKind8616.MOV_REG_STACK,
                    dst_reg=dst_reg,
                    mem_disp=disp,
                    mem_size=size,
                )
            if base == 0 and index == 0 and _memory_uses_segment_8616(mem, X86_REG_DS):
                return BranchTargetReturnEffect8616(
                    BranchTargetReturnEffectKind8616.MOV_REG_DIRECT_GLOBAL,
                    dst_reg=dst_reg,
                    mem_disp=disp,
                    mem_size=size,
                )
    return None


def _terminal_move_effect_8616(
    insn: object, mnemonic: str, operands: tuple[object, ...],
) -> TerminalAxReturnEffect8616 | None:
    """Classify immediate and memory moves into terminal return carriers."""
    if (
        mnemonic == "mov"
        and len(operands) == _BINARY_OPERAND_COUNT_8616
        and _operand_kind_8616(operands[0]) == X86_OP_REG
        and _register_name_8616(insn, operands[0]) in {"al", "ah", "cl", "cx", "ax", "dx"}
    ):
        dst_reg = _register_name_8616(insn, operands[0])
        rhs = operands[1]
        if _operand_kind_8616(rhs) == X86_OP_IMM:
            # Dynamic third-party capstone boundary: immediate payload is decoded by capstone.
            imm = int(getattr(rhs, "imm", 0) or 0)
            return TerminalAxReturnEffect8616(
                TerminalAxReturnEffectKind8616.MOV_REG_IMM,
                dst_reg=dst_reg,
                imm=imm,
            )
        if _operand_kind_8616(rhs) == X86_OP_MEM:
            # Dynamic third-party capstone boundary: memory operand payload is decoded by capstone.
            mem = getattr(rhs, "mem", None)
            if mem is None:
                return TerminalAxReturnEffect8616(TerminalAxReturnEffectKind8616.OTHER)
            base_name, base, index = _memory_base_index_8616(insn, mem)
            # Dynamic third-party capstone boundary: memory operand size is decoded by capstone.
            size = int(getattr(rhs, "size", 0) or 2)
            # Dynamic third-party capstone boundary: displacement is decoded by capstone.
            disp = int(getattr(mem, "disp", 0) or 0)
            if base_name == "bp" and index == 0 and _memory_uses_segment_8616(mem, X86_REG_SS):
                return TerminalAxReturnEffect8616(
                    TerminalAxReturnEffectKind8616.MOV_REG_STACK,
                    dst_reg=dst_reg,
                    mem_disp=disp,
                    mem_size=size,
                )
            if base == 0 and index == 0 and _memory_uses_segment_8616(mem, X86_REG_DS):
                return TerminalAxReturnEffect8616(
                    TerminalAxReturnEffectKind8616.MOV_REG_DIRECT_GLOBAL,
                    dst_reg=dst_reg,
                    mem_disp=disp,
                    mem_size=size,
                )
    return None


def _terminal_fixed_arithmetic_effect_8616(
    insn: object, mnemonic: str, operands: tuple[object, ...],
) -> TerminalAxReturnEffect8616 | None:
    """Classify fixed-register arithmetic and split-value shift operations."""
    if (
        mnemonic in {"add", "sub", "shl"}
        and len(operands) == _BINARY_OPERAND_COUNT_8616
        and _operand_kind_8616(operands[0]) == X86_OP_REG
        and _register_name_8616(insn, operands[0]) == "ax"
        and _operand_kind_8616(operands[1]) == X86_OP_IMM
    ):
        # Dynamic third-party capstone boundary: immediate payload is decoded by capstone.
        imm = int(getattr(operands[1], "imm", 0) or 0)
        return TerminalAxReturnEffect8616(
            TerminalAxReturnEffectKind8616.AX_ALU_IMM,
            imm=imm,
            op={"add": "Add", "sub": "Sub", "shl": "Shl"}[mnemonic],
        )
    if (
        mnemonic in {"inc", "dec"}
        and len(operands) == 1
        and _operand_kind_8616(operands[0]) == X86_OP_REG
        and _register_name_8616(insn, operands[0]) == "ax"
    ):
        return TerminalAxReturnEffect8616(
            TerminalAxReturnEffectKind8616.AX_INCDEC,
            op="Add" if mnemonic == "inc" else "Sub",
        )
    if (
        mnemonic == "shl"
        and len(operands) == _BINARY_OPERAND_COUNT_8616
        and _operand_kind_8616(operands[0]) == X86_OP_REG
        and _register_name_8616(insn, operands[0]) == "al"
        and _operand_kind_8616(operands[1]) == X86_OP_IMM
    ):
        # Dynamic third-party capstone boundary: immediate payload is decoded by capstone.
        imm = int(getattr(operands[1], "imm", 0) or 0)
        return TerminalAxReturnEffect8616(TerminalAxReturnEffectKind8616.AL_SHL_IMM, imm=imm, op="Shl")
    is_ax_shift_by_cl = (
        mnemonic == "shr"
        and len(operands) == _BINARY_OPERAND_COUNT_8616
        and _operand_kind_8616(operands[0]) == X86_OP_REG
        and _operand_kind_8616(operands[1]) == X86_OP_REG
        and _register_name_8616(insn, operands[0]) == "ax"
        and _register_name_8616(insn, operands[1]) == "cl"
    )
    if is_ax_shift_by_cl:
        return TerminalAxReturnEffect8616(TerminalAxReturnEffectKind8616.AX_SHR_CL, op="Shr")
    if (
        mnemonic == "shl"
        and len(operands) == _BINARY_OPERAND_COUNT_8616
        and _operand_kind_8616(operands[0]) == X86_OP_REG
        and _register_name_8616(insn, operands[0]) == "cx"
        and _operand_kind_8616(operands[1]) == X86_OP_IMM
    ):
        # Dynamic third-party capstone boundary: immediate payload is decoded by capstone.
        imm = int(getattr(operands[1], "imm", 0) or 0)
        return TerminalAxReturnEffect8616(TerminalAxReturnEffectKind8616.CX_SHL_IMM, imm=imm, op="Shl")
    is_ax_or_cx = (
        mnemonic == "or"
        and len(operands) == _BINARY_OPERAND_COUNT_8616
        and _operand_kind_8616(operands[0]) == X86_OP_REG
        and _operand_kind_8616(operands[1]) == X86_OP_REG
        and _register_name_8616(insn, operands[0]) == "ax"
        and _register_name_8616(insn, operands[1]) == "cx"
    )
    if is_ax_or_cx:
        return TerminalAxReturnEffect8616(TerminalAxReturnEffectKind8616.AX_OR_CX, op="Or")
    return None


def branch_target_return_effect_8616(
    insn: object,
    branch_target_imm: Callable[[object], int | None],
) -> BranchTargetReturnEffect8616:
    """Classify one capstone instruction for branch-target return recovery."""
    # Dynamic third-party capstone boundary: instruction mnemonic is decoded by capstone wrappers.
    mnemonic = str(getattr(insn, "mnemonic", "")).lower()
    # Dynamic third-party capstone boundary: operands are decoded by capstone wrappers.
    operands = tuple(getattr(insn, "operands", ()) or ())
    cleared = _self_cleared_register_8616(insn, mnemonic, operands)
    if cleared in {"ax", "dx"}:
        return BranchTargetReturnEffect8616(
            BranchTargetReturnEffectKind8616.MOV_REG_IMM, dst_reg=cleared, imm=0,
        )
    effect = _branch_move_effect_8616(insn, mnemonic, operands)
    if effect is not None:
        return effect
    if (
        mnemonic in {"add", "sub", "shl"}
        and len(operands) == _BINARY_OPERAND_COUNT_8616
        and _operand_kind_8616(operands[0]) == X86_OP_REG
        and _register_name_8616(insn, operands[0]) == "ax"
        and _operand_kind_8616(operands[1]) == X86_OP_IMM
    ):
        # Dynamic third-party capstone boundary: immediate payload is decoded by capstone.
        imm = int(getattr(operands[1], "imm", 0) or 0)
        return BranchTargetReturnEffect8616(
            BranchTargetReturnEffectKind8616.AX_ALU_IMM,
            imm=imm,
            op={"add": "Add", "sub": "Sub", "shl": "Shl"}[mnemonic],
        )
    if (
        mnemonic in {"inc", "dec"}
        and len(operands) == 1
        and _operand_kind_8616(operands[0]) == X86_OP_REG
        and _register_name_8616(insn, operands[0]) == "ax"
    ):
        return BranchTargetReturnEffect8616(
            BranchTargetReturnEffectKind8616.AX_INCDEC,
            op="Add" if mnemonic == "inc" else "Sub",
        )
    if mnemonic in {"jmp", "ljmp"}:
        target = branch_target_imm(insn)
        return BranchTargetReturnEffect8616(
            BranchTargetReturnEffectKind8616.JUMP,
            jump_target=int(target) if target is not None else None,
        )
    if mnemonic in {"ret", "retf", "iret"}:
        return BranchTargetReturnEffect8616(BranchTargetReturnEffectKind8616.RETURN)
    if mnemonic.startswith("j") or mnemonic in {
        "call",
        "lcall",
        "loop",
        "loope",
        "loopne",
    } or _is_software_interrupt_boundary_8616(mnemonic, operands):
        return BranchTargetReturnEffect8616(
            BranchTargetReturnEffectKind8616.CONTROL_BOUNDARY
        )
    return BranchTargetReturnEffect8616(BranchTargetReturnEffectKind8616.OTHER)


def terminal_ax_return_effect_8616(insn: object) -> TerminalAxReturnEffect8616:
    """Classify one capstone instruction for terminal AX-return recovery."""
    # Dynamic third-party capstone boundary: instruction mnemonic is decoded by capstone wrappers.
    mnemonic = str(getattr(insn, "mnemonic", "")).lower()
    # Dynamic third-party capstone boundary: operands are decoded by capstone wrappers.
    operands = tuple(getattr(insn, "operands", ()) or ())
    cleared = _self_cleared_register_8616(insn, mnemonic, operands)
    if cleared in {"ax", "dx"}:
        return TerminalAxReturnEffect8616(
            TerminalAxReturnEffectKind8616.MOV_REG_IMM, dst_reg=cleared, imm=0,
        )
    if cleared == "ah":
        return TerminalAxReturnEffect8616(TerminalAxReturnEffectKind8616.CLEAR_AH_TO_ZERO)
    if mnemonic in {"call", "lcall"} or _is_software_interrupt_boundary_8616(
        mnemonic,
        operands,
    ):
        return TerminalAxReturnEffect8616(TerminalAxReturnEffectKind8616.CALL_CLOBBER)
    effect = _terminal_move_effect_8616(insn, mnemonic, operands)
    if effect is not None:
        return effect
    effect = _terminal_fixed_arithmetic_effect_8616(insn, mnemonic, operands)
    if effect is not None:
        return effect
    effect = _terminal_value_arithmetic_effect_8616(insn, mnemonic, operands)
    if effect is not None:
        return effect
    fallback_dst_reg = (
        _register_name_8616(insn, operands[0])
        if operands and _operand_kind_8616(operands[0]) == X86_OP_REG
        else None
    )
    return TerminalAxReturnEffect8616(
        TerminalAxReturnEffectKind8616.OTHER,
        dst_reg=fallback_dst_reg,
    )


__all__ = [
    "BranchTargetReturnEffect8616",
    "BranchTargetReturnEffectKind8616",
    "TerminalAxReturnEffect8616",
    "TerminalAxReturnEffectKind8616",
    "TerminalAxReturnOperandKind8616",
    "branch_target_return_effect_8616",
    "terminal_ax_return_effect_8616",
]
