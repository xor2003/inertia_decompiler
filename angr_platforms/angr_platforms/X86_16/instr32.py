"""Layer: Frontend/runtime.

Responsibility: implement operand-size-32 opcode behavior reachable from the 16-bit frontend.
Forbidden: decompiler postprocess repair, source/COD-backed semantics, or validation gating.

Dynamic value boundary: PyVEX expression arithmetic uses the shared ``VexExpr``
adapter from ``instr_base``; decoded instruction state remains concrete and typed.
"""

from __future__ import annotations

from collections.abc import Callable

from pyvex.lifting.util import JumpKind, Type

from .addressing_helpers import advance_eip32, load_far_pointer, load_resolved_operand, store_resolved_operand
from .alu_helpers import (
    binary_operation,
    binary_operation_with_carry,
    compare_operation,
    masked_shift_count,
    unary_operation,
)
from .debug import ERROR, INFO
from .emulator import Emulator
from .exception import EXP_UD
from .exec import OpcodeExecHandler
from .instr_base import InstrBase, VexExpr, _vex_expr
from .instruction import CHK_IMM8, CHK_IMM16, CHK_IMM32, CHK_MODRM, CHK_MOFFS, CHK_PTR16, InstrData, InstrFlags
from .jcc_condition import _consume_last_condition_branch_8616
from .regs import coerce_reg32_t, reg8_t, reg16_t, reg32_t, sgreg_t
from .semantics.alu_semantics import rotate_through_carry_left_state, rotate_through_carry_right_state
from .stack_helpers import (
    branch_rel8,
    branch_rel32,
    emit_far_call32,
    emit_far_jump32,
    emit_near_call32,
    emit_near_jump32,
    enter32,
    far_return_ip32,
    leave32,
    near_relative_target32,
    pop32,
    pop32_register,
    pop_all32,
    pop_flags32,
    pop_segment32,
    push32_register,
    push_all32,
    push_flags32,
    push_immediate32,
    push_segment32,
    return_far32,
    return_near32,
)
from .string_helpers import (
    repeat_jump,
    repeat_prefix_cond,
    string_advance_indices,
    string_compare_values,
    string_load,
    string_source_segment,
    string_store,
)
from .vex_value_contract import require_vex_value_8616 as _require_vex_value


class Instr32(InstrBase):
    """Implement operand-size-32 instruction effects for the x86 frontend."""

    _opcode_template_instrfuncs: list[OpcodeExecHandler | None] | None = None
    _opcode_template_chk: list[int | InstrFlags] | None = None

    def __init__(self, emu: Emulator, instr: InstrData) -> None:
        """Initialize 32-bit opcode handlers for one decoded instruction."""
        super().__init__(emu, instr, mode32=True)  # X86Instruction
        cls = type(self)
        template_funcs = cls._opcode_template_instrfuncs
        template_chk = cls._opcode_template_chk
        if template_funcs is not None and template_chk is not None:
            self.instrfuncs = template_funcs.copy()
            self.chk = template_chk.copy()
            return
        sf = self.set_funcflag

        sf(0x01, self.add_rm32_r32, CHK_MODRM)
        sf(0x03, self.add_r32_rm32, CHK_MODRM)
        sf(0x05, self.add_eax_imm32, CHK_IMM32)
        sf(0x06, self.push_es, 0)
        sf(0x07, self.pop_es, 0)
        sf(0x09, self.or_rm32_r32, CHK_MODRM)
        sf(0x0B, self.or_r32_rm32, CHK_MODRM)
        sf(0x0D, self.or_eax_imm32, CHK_IMM32)
        sf(0x0E, self.push_cs, 0)
        sf(0x11, self.adc_rm32_r32, CHK_MODRM)
        sf(0x13, self.adc_r32_rm32, CHK_MODRM)
        sf(0x15, self.adc_eax_imm32, CHK_IMM32)
        sf(0x16, self.push_ss, 0)
        sf(0x17, self.pop_ss, 0)
        sf(0x19, self.sbb_rm32_r32, CHK_MODRM)
        sf(0x1B, self.sbb_r32_rm32, CHK_MODRM)
        sf(0x1D, self.sbb_eax_imm32, CHK_IMM32)
        sf(0x1E, self.push_ds, 0)
        sf(0x1F, self.pop_ds, 0)
        sf(0x21, self.and_rm32_r32, CHK_MODRM)
        sf(0x23, self.and_r32_rm32, CHK_MODRM)
        sf(0x25, self.and_eax_imm32, CHK_IMM32)
        sf(0x29, self.sub_rm32_r32, CHK_MODRM)
        sf(0x2B, self.sub_r32_rm32, CHK_MODRM)
        sf(0x2D, self.sub_eax_imm32, CHK_IMM32)
        sf(0x31, self.xor_rm32_r32, CHK_MODRM)
        sf(0x33, self.xor_r32_rm32, CHK_MODRM)
        sf(0x35, self.xor_eax_imm32, CHK_IMM32)
        sf(0x39, self.cmp_rm32_r32, CHK_MODRM)
        sf(0x3B, self.cmp_r32_rm32, CHK_MODRM)
        sf(0x3D, self.cmp_eax_imm32, CHK_IMM32)

        self._register_opcode_range(0x40, 0x47, self.inc_r32, 0)
        self._register_opcode_range(0x48, 0x4F, self.dec_r32, 0)
        self._register_opcode_range(0x50, 0x57, self.push_r32, 0)
        self._register_opcode_range(0x58, 0x5F, self.pop_r32, 0)

        sf(0x60, self.pushad, 0)
        sf(0x61, self.popad, 0)
        sf(0x62, self.bound_r32_m32, CHK_MODRM)
        sf(0x68, self.push_imm32, CHK_IMM32)
        sf(0x69, self.imul_r32_rm32_imm32, CHK_MODRM | CHK_IMM32)
        sf(0x6A, self.push_imm8, CHK_IMM8)
        sf(0x6B, self.imul_r32_rm32_imm8, CHK_MODRM | CHK_IMM8)
        sf(0x6D, self.insd_m32_dx, 0)
        sf(0x6F, self.outsd_dx_m32, 0)
        sf(0x85, self.test_rm32_r32, CHK_MODRM)
        sf(0x87, self.xchg_r32_rm32, CHK_MODRM)
        sf(0x89, self.mov_rm32_r32, CHK_MODRM)
        sf(0x8B, self.mov_r32_rm32, CHK_MODRM)
        sf(0x8C, self.mov_rm32_sreg, CHK_MODRM)
        sf(0x8D, self.lea_r32_m32, CHK_MODRM)
        sf(0x8F, self.code_8f, CHK_MODRM)

        self._register_opcode_range(0x91, 0x97, self.xchg_r32_eax, 0)

        sf(0x98, self.cwde, 0)
        sf(0x99, self.cdq, 0)
        sf(0x9A, self.callf_ptr16_32, CHK_PTR16 | CHK_IMM32)
        sf(0x9C, self.pushf, 0)
        sf(0x9D, self.popf, 0)
        sf(0xA1, self.mov_eax_moffs32, CHK_MOFFS)
        sf(0xA3, self.mov_moffs32_eax, CHK_MOFFS)
        sf(0xA5, self.movsd_m32_m32, 0)
        sf(0xA6, self.cmps_m8_m8, 0)
        sf(0xA7, self.cmps_m32_m32, 0)
        sf(0xA9, self.test_eax_imm32, CHK_IMM32)
        sf(0xAB, self.stosd_m32_eax, 0)
        sf(0xAD, self.lodsd_eax_m32, 0)
        sf(0xAF, self.scasd_eax_m32, 0)

        self._register_opcode_range(0xB8, 0xBF, self.mov_r32_imm32, CHK_IMM32)

        sf(0xC2, self.ret_imm16, CHK_IMM16)
        sf(0xC3, self.ret, 0)
        sf(0xC4, self.les_r32_m16_32, CHK_MODRM)
        sf(0xC5, self.lds_r32_m16_32, CHK_MODRM)
        sf(0xC7, self.mov_rm32_imm32, CHK_MODRM | CHK_IMM32)
        sf(0xC8, self.enter, CHK_IMM16 | CHK_IMM8)
        sf(0xC9, self.leave, 0)
        sf(0xCA, self.retf_imm16, CHK_IMM16)
        sf(0xCB, self.retf, 0)
        sf(0xE5, self.in_eax_imm8, CHK_IMM8)
        sf(0xE7, self.out_imm8_eax, CHK_IMM8)
        sf(0xE8, self.call_rel32, CHK_IMM32)
        sf(0xE9, self.jmp_rel32, CHK_IMM32)
        sf(0xEA, self.jmpf_ptr16_32, CHK_PTR16 | CHK_IMM32)
        sf(0xE0, self.loopne, CHK_IMM8)
        sf(0xE1, self.loope, CHK_IMM8)
        sf(0xE2, self.loop, CHK_IMM8)
        sf(0xE3, self.jcxz_rel8, CHK_IMM8)
        sf(0xED, self.in_eax_dx, 0)
        sf(0xEF, self.out_dx_eax, 0)

        sf(0x0F80, self.jo_rel32, CHK_IMM32)
        sf(0x0F81, self.jno_rel32, CHK_IMM32)
        sf(0x0F82, self.jb_rel32, CHK_IMM32)
        sf(0x0F83, self.jnb_rel32, CHK_IMM32)
        sf(0x0F84, self.jz_rel32, CHK_IMM32)
        sf(0x0F85, self.jnz_rel32, CHK_IMM32)
        sf(0x0F86, self.jbe_rel32, CHK_IMM32)
        sf(0x0F87, self.ja_rel32, CHK_IMM32)
        sf(0x0F88, self.js_rel32, CHK_IMM32)
        sf(0x0F89, self.jns_rel32, CHK_IMM32)
        sf(0x0F8A, self.jp_rel32, CHK_IMM32)
        sf(0x0F8B, self.jnp_rel32, CHK_IMM32)
        sf(0x0F8C, self.jl_rel32, CHK_IMM32)
        sf(0x0F8D, self.jnl_rel32, CHK_IMM32)
        sf(0x0F8E, self.jle_rel32, CHK_IMM32)
        sf(0x0F8F, self.jnle_rel32, CHK_IMM32)

        sf(0x0FA0, self.push_fs, 0)
        sf(0x0FA1, self.pop_fs, 0)
        sf(0x0FA8, self.push_gs, 0)
        sf(0x0FA9, self.pop_gs, 0)
        sf(0x0FAF, self.imul_r32_rm32, CHK_MODRM)
        sf(0x0FB2, self.lss_r32_m16_32, CHK_MODRM)
        sf(0x0FB4, self.lfs_r32_m16_32, CHK_MODRM)
        sf(0x0FB5, self.lgs_r32_m16_32, CHK_MODRM)
        sf(0x0FA4, self.shld_rm32_r32_imm8, CHK_MODRM | CHK_IMM8)
        sf(0x0FA5, self.shld_rm32_r32_cl, CHK_MODRM)
        sf(0x0FA3, self.bt_rm32_r32, CHK_MODRM)
        sf(0x0FAB, self.bts_rm32_r32, CHK_MODRM)
        sf(0x0FAC, self.shrd_rm32_r32_imm8, CHK_MODRM | CHK_IMM8)
        sf(0x0FAD, self.shrd_rm32_r32_cl, CHK_MODRM)
        sf(0x0FBC, self.bsf_r32_rm32, CHK_MODRM)
        sf(0x0FBD, self.bsr_r32_rm32, CHK_MODRM)
        sf(0x0FB3, self.btr_rm32_r32, CHK_MODRM)
        sf(0x0FBA, self.code_0fba, CHK_MODRM | CHK_IMM8)
        sf(0x0FBB, self.btc_rm32_r32, CHK_MODRM)
        sf(0x0FB6, self.movzx_r32_rm8, CHK_MODRM)
        sf(0x0FB7, self.movzx_r32_rm16, CHK_MODRM)
        sf(0x0FBE, self.movsx_r32_rm8, CHK_MODRM)
        sf(0x0FBF, self.movsx_r32_rm16, CHK_MODRM)

        sf(0x81, self.code_81, CHK_MODRM | CHK_IMM32)
        sf(0x83, self.code_83, CHK_MODRM | CHK_IMM8)
        sf(0xC1, self.code_c1, CHK_MODRM | CHK_IMM8)
        sf(0xD1, self.code_d1, CHK_MODRM)
        sf(0xD3, self.code_d3, CHK_MODRM)
        sf(0xF7, self.code_f7, CHK_MODRM)
        sf(0xFF, self.code_ff, CHK_MODRM)
        sf(0x0F00, self.code_0f00, CHK_MODRM)
        sf(0x0F01, self.code_0f01, CHK_MODRM)
        cls._opcode_template_instrfuncs = self.instrfuncs.copy()
        cls._opcode_template_chk = self.chk.copy()

    def add_rm32_r32(self) -> None:
        """Execute decoded ``ADD_RM32_R32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_rm32, self.get_r32, self.set_rm32, self.emu.update_eflags_add, lambda lhs, rhs: lhs + rhs
        )

    def adc_rm32_r32(self) -> None:
        """Execute decoded ``ADC_RM32_R32`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_rm32,
            self.get_r32,
            self.set_rm32,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            32,
        )

    def add_r32_rm32(self) -> None:
        """Execute decoded ``ADD_R32_RM32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_r32, self.get_rm32, self.set_r32, self.emu.update_eflags_add, lambda lhs, rhs: lhs + rhs
        )

    def adc_r32_rm32(self) -> None:
        """Execute decoded ``ADC_R32_RM32`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_r32,
            self.get_rm32,
            self.set_r32,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            32,
        )

    def adc_eax_imm32(self) -> None:
        """Add an immediate and carry flag to EAX."""
        binary_operation_with_carry(
            self.emu,
            lambda: self.emu.get_gpreg(reg32_t.EAX),
            lambda: self.instr.imm32,
            lambda value: self.emu.set_gpreg(reg32_t.EAX, value),
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            32,
        )

    def sbb_rm32_r32(self) -> None:
        """Subtract a register and borrow from a 32-bit r/m operand."""
        binary_operation_with_carry(
            self.emu,
            self.get_rm32,
            self.get_r32,
            self.set_rm32,
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            32,
        )

    def sbb_r32_rm32(self) -> None:
        """Subtract a 32-bit r/m operand and borrow from a register."""
        binary_operation_with_carry(
            self.emu,
            self.get_r32,
            self.get_rm32,
            self.set_r32,
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            32,
        )

    def sbb_eax_imm32(self) -> None:
        """Subtract an immediate and borrow from EAX."""
        binary_operation_with_carry(
            self.emu,
            lambda: self.emu.get_gpreg(reg32_t.EAX),
            lambda: self.instr.imm32,
            lambda value: self.emu.set_gpreg(reg32_t.EAX, value),
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            32,
        )

    def add_eax_imm32(self) -> None:
        """Execute decoded ``ADD_EAX_IMM32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            lambda: self.emu.get_gpreg(reg32_t.EAX),
            lambda: self.instr.imm32,
            lambda value: self.emu.set_gpreg(reg32_t.EAX, value),
            self.emu.update_eflags_add,
            lambda lhs, rhs: lhs + rhs,
        )

    def push_es(self) -> None:
        """Execute decoded ``PUSH_ES`` semantics through frontend emulator effects."""
        push_segment32(self._active_stack_emulator(), sgreg_t.ES)

    def push_cs(self) -> None:
        """Push CS using the operand-size-32 stack form."""
        push_segment32(self._active_stack_emulator(), sgreg_t.CS)

    def push_fs(self) -> None:
        """Push FS using the operand-size-32 stack form."""
        push_segment32(self._active_stack_emulator(), sgreg_t.FS)

    def pop_fs(self) -> None:
        """Pop a 32-bit stack slot into FS."""
        pop_segment32(self._active_stack_emulator(), sgreg_t.FS)

    def push_gs(self) -> None:
        """Push GS using the operand-size-32 stack form."""
        push_segment32(self._active_stack_emulator(), sgreg_t.GS)

    def pop_gs(self) -> None:
        """Pop a 32-bit stack slot into GS."""
        pop_segment32(self._active_stack_emulator(), sgreg_t.GS)

    def pop_es(self) -> None:
        """Execute decoded ``POP_ES`` semantics through frontend emulator effects."""
        pop_segment32(self._active_stack_emulator(), sgreg_t.ES)

    def or_rm32_r32(self) -> None:
        """Execute decoded ``OR_RM32_R32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_rm32, self.get_r32, self.set_rm32, self.emu.update_eflags_or, lambda lhs, rhs: lhs | rhs
        )

    def or_r32_rm32(self) -> None:
        """Execute decoded ``OR_R32_RM32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_r32, self.get_rm32, self.set_r32, self.emu.update_eflags_or, lambda lhs, rhs: lhs | rhs
        )

    def or_eax_imm32(self) -> None:
        """Execute decoded ``OR_EAX_IMM32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            lambda: self.emu.get_gpreg(reg32_t.EAX),
            lambda: self.instr.imm32,
            lambda value: self.emu.set_gpreg(reg32_t.EAX, value),
            self.emu.update_eflags_or,
            lambda lhs, rhs: lhs | rhs,
        )

    def push_ss(self) -> None:
        """Execute decoded ``PUSH_SS`` semantics through frontend emulator effects."""
        push_segment32(self._active_stack_emulator(), sgreg_t.SS)

    def pop_ss(self) -> None:
        """Execute decoded ``POP_SS`` semantics through frontend emulator effects."""
        pop_segment32(self._active_stack_emulator(), sgreg_t.SS)

    def push_ds(self) -> None:
        """Execute decoded ``PUSH_DS`` semantics through frontend emulator effects."""
        push_segment32(self._active_stack_emulator(), sgreg_t.DS)

    def pop_ds(self) -> None:
        """Execute decoded ``POP_DS`` semantics through frontend emulator effects."""
        pop_segment32(self._active_stack_emulator(), sgreg_t.DS)

    def and_rm32_r32(self) -> None:
        """Execute decoded ``AND_RM32_R32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_rm32, self.get_r32, self.set_rm32, self.emu.update_eflags_and, lambda lhs, rhs: lhs & rhs
        )

    def and_r32_rm32(self) -> None:
        """Execute decoded ``AND_R32_RM32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_r32, self.get_rm32, self.set_r32, self.emu.update_eflags_and, lambda lhs, rhs: lhs & rhs
        )

    def and_eax_imm32(self) -> None:
        """Execute decoded ``AND_EAX_IMM32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            lambda: self.emu.get_gpreg(reg32_t.EAX),
            lambda: self.instr.imm32,
            lambda value: self.emu.set_gpreg(reg32_t.EAX, value),
            self.emu.update_eflags_and,
            lambda lhs, rhs: lhs & rhs,
        )

    def sub_rm32_r32(self) -> None:
        """Execute decoded ``SUB_RM32_R32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_rm32, self.get_r32, self.set_rm32, self.emu.update_eflags_sub, lambda lhs, rhs: lhs - rhs
        )

    def sub_r32_rm32(self) -> None:
        """Execute decoded ``SUB_R32_RM32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_r32, self.get_rm32, self.set_r32, self.emu.update_eflags_sub, lambda lhs, rhs: lhs - rhs
        )

    def sub_eax_imm32(self) -> None:
        """Execute decoded ``SUB_EAX_IMM32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            lambda: self.emu.get_gpreg(reg32_t.EAX),
            lambda: self.instr.imm32,
            lambda value: self.emu.set_gpreg(reg32_t.EAX, value),
            self.emu.update_eflags_sub,
            lambda lhs, rhs: lhs - rhs,
        )

    def xor_rm32_r32(self) -> None:
        """Execute decoded ``XOR_RM32_R32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_rm32, self.get_r32, self.set_rm32, self.emu.update_eflags_xor, lambda lhs, rhs: lhs ^ rhs
        )

    def xor_r32_rm32(self) -> None:
        """Execute decoded ``XOR_R32_RM32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_r32, self.get_rm32, self.set_r32, self.emu.update_eflags_xor, lambda lhs, rhs: lhs ^ rhs
        )

    def xor_eax_imm32(self) -> None:
        """Execute decoded ``XOR_EAX_IMM32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            lambda: self.emu.get_gpreg(reg32_t.EAX),
            lambda: self.instr.imm32,
            lambda value: self.emu.set_gpreg(reg32_t.EAX, value),
            self.emu.update_eflags_xor,
            lambda lhs, rhs: lhs ^ rhs,
        )

    def cmp_rm32_r32(self) -> None:
        """Execute decoded ``CMP_RM32_R32`` semantics through frontend emulator effects."""
        compare_operation(self.get_rm32, self.get_r32, self.emu.update_eflags_sub)

    def cmp_r32_rm32(self) -> None:
        """Execute decoded ``CMP_R32_RM32`` semantics through frontend emulator effects."""
        compare_operation(self.get_r32, self.get_rm32, self.emu.update_eflags_sub)

    def cmp_eax_imm32(self) -> None:
        """Execute decoded ``CMP_EAX_IMM32`` semantics through frontend emulator effects."""
        compare_operation(lambda: self.emu.get_gpreg(reg32_t.EAX), lambda: self.instr.imm32, self.emu.update_eflags_sub)

    def inc_r32(self) -> None:
        """Execute decoded ``INC_R32`` semantics through frontend emulator effects."""
        reg = coerce_reg32_t(self.instr.opcode & ((1 << 3) - 1))
        unary_operation(
            lambda: self.emu.get_gpreg(reg),
            lambda value: self.emu.set_gpreg(reg, value),
            self.emu.update_eflags_inc,
            lambda value: value + 1,
        )

    def dec_r32(self) -> None:
        """Execute decoded ``DEC_R32`` semantics through frontend emulator effects."""
        reg = coerce_reg32_t(self.instr.opcode & ((1 << 3) - 1))
        unary_operation(
            lambda: self.emu.get_gpreg(reg),
            lambda value: self.emu.set_gpreg(reg, value),
            self.emu.update_eflags_dec,
            lambda value: value - 1,
        )

    def push_r32(self) -> None:
        """Execute decoded ``PUSH_R32`` semantics through frontend emulator effects."""
        reg = coerce_reg32_t(self.instr.opcode & ((1 << 3) - 1))
        push32_register(self._active_stack_emulator(), reg)

    def pop_r32(self) -> None:
        """Execute decoded ``POP_R32`` semantics through frontend emulator effects."""
        reg = coerce_reg32_t(self.instr.opcode & ((1 << 3) - 1))
        pop32_register(self._active_stack_emulator(), reg)

    def code_8f(self) -> None:
        """Dispatch the architecturally defined ``POP r/m32`` group member."""
        self._dispatch_modrm_reg((self.pop_rm32, None, None, None, None, None, None, None), "0x8f")

    def pop_rm32(self) -> None:
        """Pop a doubleword from the active stack into a 32-bit r/m operand."""
        self.set_rm32(pop32(self._active_stack_emulator()))

    def pushad(self) -> None:
        """Execute decoded ``PUSHAD`` semantics through frontend emulator effects."""
        push_all32(self._active_stack_emulator())

    def popad(self) -> None:
        """Execute decoded ``POPAD`` semantics through frontend emulator effects."""
        pop_all32(self._active_stack_emulator())

    def bound_r32_m32(self) -> None:
        """Check a signed register against a pair of signed 32-bit memory bounds."""
        if self.instr.modrm.mod == 3:
            raise Exception(EXP_UD)
        reg = _vex_expr(self.get_r32()).signed
        operand = self._resolved_rm_operand(32)
        step_type = Type.int_32 if self.instr.address_bits == 32 else Type.int_16
        lower = _vex_expr(self.emu.get_data32(operand.segment, operand.offset)).signed
        base_offset = operand.offset if isinstance(operand.offset, int) else _require_vex_value(operand.offset)
        upper_offset = base_offset + self.emu.constant(4, step_type)
        upper = _vex_expr(self.emu.get_data32(operand.segment, upper_offset)).signed
        out_of_range = (reg < lower) | (reg > upper)
        lifter_instruction = self.emu.lifter_instruction
        if lifter_instruction is None:
            raise RuntimeError("BOUND exception emission requires an active lifter instruction")
        lifter_instruction.jump(out_of_range, 0xFF005, JumpKind.Call)

    def _loop_counter_nonzero(self) -> VexExpr:
        """Decrement the address-sized lifted counter; refuse concrete values before mutation."""
        if self.instr.address_bits == 32:
            counter = _require_vex_value(self.emu.get_gpreg(reg32_t.ECX)) - self.emu.constant(1, Type.int_32)
            self.emu.set_gpreg(reg32_t.ECX, counter)
            nonzero = counter != self.emu.constant(0, Type.int_32)
        else:
            counter = _require_vex_value(self.emu.get_gpreg(reg16_t.CX)) - self.emu.constant(1, Type.int_16)
            self.emu.set_gpreg(reg16_t.CX, counter)
            nonzero = counter != self.emu.constant(0, Type.int_16)
        return _require_vex_value(nonzero).cast_to(Type.int_1)

    def loop(self) -> None:
        """Execute LOOP using CX or ECX according to the effective address size."""
        lifter_instruction = self.emu.lifter_instruction
        if lifter_instruction is None:
            raise RuntimeError("LOOP condition publication requires an active lifter instruction")
        counter_name, counter_size = ("ecx", 4) if self.instr.address_bits == 32 else ("cx", 2)
        lifter_instruction.record_loop_counter_condition_8616(
            counter_name, counter_size, self.instr.imm8, self.instr.size
        )
        branch_rel8(
            self._active_stack_emulator(),
            self._loop_counter_nonzero(),
            self.instr.imm8,
            self.instr.size,
        )

    def loopne(self) -> None:
        """Execute LOOPNE with the address-size-selected counter."""
        condition = self._loop_counter_nonzero() & ~self.emu.is_zero()
        branch_rel8(
            self._active_stack_emulator(), condition, self.instr.imm8, self.instr.size
        )

    def loope(self) -> None:
        """Execute LOOPE with the address-size-selected counter."""
        condition = self._loop_counter_nonzero() & self.emu.is_zero()
        branch_rel8(
            self._active_stack_emulator(), condition, self.instr.imm8, self.instr.size
        )

    def jcxz_rel8(self) -> None:
        """Execute JCXZ or JECXZ according to the effective address size."""
        if self.instr.address_bits == 32:
            condition = self.emu.get_gpreg(reg32_t.ECX) == self.emu.constant(0, Type.int_32)
        else:
            condition = self.emu.get_gpreg(reg16_t.CX) == self.emu.constant(0, Type.int_16)
        branch_rel8(
            self._active_stack_emulator(),
            _require_vex_value(condition).cast_to(Type.int_1),
            self.instr.imm8,
            self.instr.size,
        )

    def push_imm32(self) -> None:
        """Execute decoded ``PUSH_IMM32`` semantics through frontend emulator effects."""
        push_immediate32(self._active_stack_emulator(), self.instr.imm32)

    def imul_r32_rm32_imm32(self) -> None:
        """Execute decoded ``IMUL_R32_RM32_IMM32`` semantics through frontend emulator effects."""
        rm32_s = _vex_expr(self.get_rm32())
        self.set_r32(rm32_s * self.instr.imm32)
        self.emu.update_eflags_imul(rm32_s, self.instr.imm32)

    def push_imm8(self) -> None:
        """Execute decoded ``PUSH_IMM8`` semantics through frontend emulator effects."""
        immediate = _vex_expr(self.emu.constant(self.instr.imm8, Type.int_8)).cast_to(
            Type.int_32, signed=True
        )
        push_immediate32(self._active_stack_emulator(), immediate)

    def enter(self) -> None:
        """Create an operand-size-32 stack frame with a five-bit nesting level."""
        enter32(self._active_stack_emulator(), self.instr.imm16, self.instr.imm8 & 0x1F)

    def imul_r32_rm32_imm8(self) -> None:
        """Execute decoded ``IMUL_R32_RM32_IMM8`` semantics through frontend emulator effects."""
        rm32_s = _vex_expr(self.get_rm32())
        self.set_r32(rm32_s * self.instr.imm8)
        self.emu.update_eflags_imul(rm32_s, self.instr.imm8)

    def test_rm32_r32(self) -> None:
        """Execute decoded ``TEST_RM32_R32`` semantics through frontend emulator effects."""
        compare_operation(self.get_rm32, self.get_r32, self.emu.update_eflags_and)

    def xchg_r32_rm32(self) -> None:
        """Execute decoded ``XCHG_R32_RM32`` semantics through frontend emulator effects."""
        r32 = self.get_r32()
        if self.instr.modrm.mod == 3:
            rm32 = self.get_rm32()
            self.set_r32(rm32)
            self.set_rm32(r32)
            return

        operand = self._resolved_rm_operand(32)
        rm32 = load_resolved_operand(self.emu, operand)
        self.set_r32(rm32)
        store_resolved_operand(self.emu, operand, r32)

    def mov_rm32_r32(self) -> None:
        """Execute decoded ``MOV_RM32_R32`` semantics through frontend emulator effects."""
        r32 = self.get_r32()
        self.set_rm32(r32)

    def mov_r32_rm32(self) -> None:
        """Execute decoded ``MOV_R32_RM32`` semantics through frontend emulator effects."""
        rm32 = self.get_rm32()
        self.set_r32(rm32)

    def mov_rm32_sreg(self) -> None:
        """Execute decoded ``MOV_RM32_SREG`` semantics through frontend emulator effects."""
        sreg = self.get_sreg()
        if self.instr.modrm.mod == 3:
            self.emu.set_gpreg(coerce_reg32_t(self.instr.modrm.rm), _vex_expr(sreg).cast_to(Type.int_32))
        else:
            self.set_rm16(sreg)

    def lea_r32_m32(self) -> None:
        """Execute decoded ``LEA_R32_M32`` semantics through frontend emulator effects."""
        _, addr = self._resolved_rm_address()
        if self.effective_address_bits() == 16:
            addr = _vex_expr(addr).cast_to(Type.int_32)
        self.set_r32(addr)

    def xchg_r32_eax(self) -> None:
        """Execute decoded ``XCHG_R32_EAX`` semantics through frontend emulator effects."""
        reg = coerce_reg32_t(self.instr.opcode & 0b111)
        r32 = self.emu.get_gpreg(reg)
        eax = self.emu.get_gpreg(reg32_t.EAX)
        self.emu.set_gpreg(reg, eax)
        self.emu.set_gpreg(reg32_t.EAX, r32)

    def cwde(self) -> None:
        """Execute decoded ``CWDE`` semantics through frontend emulator effects."""
        ax_s = _vex_expr(self.emu.get_gpreg(reg16_t.AX)).cast_to(Type.int_32, signed=True)
        self.emu.set_gpreg(reg32_t.EAX, ax_s)

    def cdq(self) -> None:
        """Execute decoded ``CDQ`` semantics through frontend emulator effects."""
        eax = _vex_expr(self.emu.get_gpreg(reg32_t.EAX)).signed
        self.emu.set_gpreg(reg32_t.EDX, eax.sar(self.emu.constant(31, Type.int_8)))

    def callf_ptr16_32(self) -> None:
        """Execute decoded ``CALLF_PTR16_32`` semantics through frontend emulator effects."""
        emit_far_call32(
            self._active_stack_emulator(),
            self.instr.ptr16,
            self.instr.imm32,
            far_return_ip32(self._active_stack_emulator(), self.instr.size),
        )

    def pushf(self) -> None:
        """Execute decoded ``PUSHF`` semantics through frontend emulator effects."""
        push_flags32(self._active_stack_emulator())

    def popf(self) -> None:
        """Execute decoded ``POPF`` semantics through frontend emulator effects."""
        pop_flags32(self._active_stack_emulator())

    def mov_eax_moffs32(self) -> None:
        """Execute decoded ``MOV_EAX_MOFFS32`` semantics through frontend emulator effects."""
        self.emu.set_gpreg(reg32_t.EAX, self.get_moffs32())

    def mov_moffs32_eax(self) -> None:
        """Execute decoded ``MOV_MOFFS32_EAX`` semantics through frontend emulator effects."""
        self.set_moffs32(self.emu.get_gpreg(reg32_t.EAX))

    def _string_index_regs(self) -> tuple[reg16_t | reg32_t, reg16_t | reg32_t]:
        """Return source and destination index registers selected by address size."""
        if self.instr.address_bits == 32:
            return reg32_t.ESI, reg32_t.EDI
        return reg16_t.SI, reg16_t.DI

    def movsd_m32_m32(self) -> None:
        """Move one dword between string operands and honor REP and address size."""
        emu = self._active_string_emulator()
        repeat_cond = repeat_prefix_cond(emu, self.instr)
        si_reg, di_reg = self._string_index_regs()
        si = self.emu.get_gpreg(si_reg)
        di = self.emu.get_gpreg(di_reg)
        value = string_load(emu, string_source_segment(self.instr), si, 4)
        string_store(emu, sgreg_t.ES, di, value, 4)
        string_advance_indices(emu, 4, si_reg, di_reg)
        if repeat_cond is not None:
            repeat_jump(emu, self.instr, repeat_cond)

    def stosd_m32_eax(self) -> None:
        """Store EAX through the address-size-selected destination index."""
        emu = self._active_string_emulator()
        repeat_cond = repeat_prefix_cond(emu, self.instr)
        _, di_reg = self._string_index_regs()
        di = self.emu.get_gpreg(di_reg)
        string_store(emu, sgreg_t.ES, di, self.emu.get_gpreg(reg32_t.EAX), 4)
        string_advance_indices(emu, 4, di_reg)
        if repeat_cond is not None:
            repeat_jump(emu, self.instr, repeat_cond)

    def lodsd_eax_m32(self) -> None:
        """Load EAX through the address-size-selected source index."""
        emu = self._active_string_emulator()
        repeat_cond = repeat_prefix_cond(emu, self.instr)
        si_reg, _ = self._string_index_regs()
        si = self.emu.get_gpreg(si_reg)
        self.emu.set_gpreg(reg32_t.EAX, string_load(emu, string_source_segment(self.instr), si, 4))
        string_advance_indices(emu, 4, si_reg)
        if repeat_cond is not None:
            repeat_jump(emu, self.instr, repeat_cond)

    def scasd_eax_m32(self) -> None:
        """Compare EAX with ES:[DI/EDI] and honor repeat termination."""
        emu = self._active_string_emulator()
        repeat_cond = repeat_prefix_cond(emu, self.instr)
        _, di_reg = self._string_index_regs()
        di = self.emu.get_gpreg(di_reg)
        value = string_load(emu, sgreg_t.ES, di, 4)
        string_compare_values(self.emu.get_gpreg(reg32_t.EAX), value, self.emu.update_eflags_sub)
        string_advance_indices(emu, 4, di_reg)
        if repeat_cond is not None:
            repeat_jump(emu, self.instr, repeat_cond, zf_sensitive=True)

    def insd_m32_dx(self) -> None:
        """Input one dword from DX into ES:[DI/EDI]."""
        emu = self._active_string_emulator()
        repeat_cond = repeat_prefix_cond(emu, self.instr)
        _, di_reg = self._string_index_regs()
        di = self.emu.get_gpreg(di_reg)
        dx = _vex_expr(self.emu.get_gpreg(reg16_t.DX))
        string_store(emu, sgreg_t.ES, di, self.emu.in_io32(dx), 4)
        string_advance_indices(emu, 4, di_reg)
        if repeat_cond is not None:
            repeat_jump(emu, self.instr, repeat_cond)

    def outsd_dx_m32(self) -> None:
        """Output one dword from DS:[SI/ESI] to DX."""
        emu = self._active_string_emulator()
        repeat_cond = repeat_prefix_cond(emu, self.instr)
        si_reg, _ = self._string_index_regs()
        si = self.emu.get_gpreg(si_reg)
        dx = _vex_expr(self.emu.get_gpreg(reg16_t.DX))
        self.emu.out_io32(dx, string_load(emu, string_source_segment(self.instr), si, 4))
        string_advance_indices(emu, 4, si_reg)
        if repeat_cond is not None:
            repeat_jump(emu, self.instr, repeat_cond)

    def cmps_m8_m8(self) -> None:
        """Execute decoded ``CMPS_M8_M8`` semantics through frontend emulator effects."""
        emu = self._active_string_emulator()
        repeat_cond = repeat_prefix_cond(emu, self.instr)

        si_reg, di_reg = self._string_index_regs()
        si = self.emu.get_gpreg(si_reg)
        di = self.emu.get_gpreg(di_reg)
        m8_s = string_load(emu, string_source_segment(self.instr), si, 1)
        m8_d = string_load(emu, sgreg_t.ES, di, 1)
        string_compare_values(m8_s, m8_d, self.emu.update_eflags_sub)
        string_advance_indices(emu, 1, reg32_t.ESI, reg32_t.EDI)

        if repeat_cond is not None:
            repeat_jump(emu, self.instr, repeat_cond, zf_sensitive=True)

    def cmps_m32_m32(self) -> None:
        """Execute decoded ``CMPS_M32_M32`` semantics through frontend emulator effects."""
        emu = self._active_string_emulator()
        repeat_cond = repeat_prefix_cond(emu, self.instr)

        si_reg, di_reg = self._string_index_regs()
        si = self.emu.get_gpreg(si_reg)
        di = self.emu.get_gpreg(di_reg)
        m32_s = string_load(emu, string_source_segment(self.instr), si, 4)
        m32_d = string_load(emu, sgreg_t.ES, di, 4)
        string_compare_values(m32_s, m32_d, self.emu.update_eflags_sub)
        string_advance_indices(emu, 4, si_reg, di_reg)

        if repeat_cond is not None:
            repeat_jump(emu, self.instr, repeat_cond, zf_sensitive=True)

    def test_eax_imm32(self) -> None:
        """Execute decoded ``TEST_EAX_IMM32`` semantics through frontend emulator effects."""
        compare_operation(lambda: self.emu.get_gpreg(reg32_t.EAX), lambda: self.instr.imm32, self.emu.update_eflags_and)

    def mov_r32_imm32(self) -> None:
        """Execute decoded ``MOV_R32_IMM32`` semantics through frontend emulator effects."""
        reg = self.instr.opcode & ((1 << 3) - 1)
        self.emu.set_gpreg(coerce_reg32_t(reg), self.instr.imm32)

    def ret(self) -> None:
        """Execute decoded ``RET`` semantics through frontend emulator effects."""
        return_near32(self._active_stack_emulator())

    def ret_imm16(self) -> None:
        """Return through a dword IP and release an immediate byte count from SP."""
        return_near32(self._active_stack_emulator(), stack_adjust=self.instr.imm16)

    def retf_imm16(self) -> None:
        """Return through a 16:32 far frame and release an immediate byte count."""
        return_far32(self._active_stack_emulator(), stack_adjust=self.instr.imm16)

    def retf(self, _instr: dict[str, object] | None = None) -> None:
        """Return through a 16:32 far frame."""
        return_far32(self._active_stack_emulator())

    def mov_rm32_imm32(self) -> None:
        """Execute decoded ``MOV_RM32_IMM32`` semantics through frontend emulator effects."""
        self.set_rm32(self.instr.imm32)

    def leave(self) -> None:
        """Execute decoded ``LEAVE`` semantics through frontend emulator effects."""
        leave32(self._active_stack_emulator())

    def in_eax_imm8(self) -> None:
        """Execute decoded ``IN_EAX_IMM8`` semantics through frontend emulator effects."""
        self.emu.set_gpreg(reg32_t.EAX, self.emu.in_io32(self.instr.imm8))

    def out_imm8_eax(self) -> None:
        """Execute decoded ``OUT_IMM8_EAX`` semantics through frontend emulator effects."""
        eax = self.emu.get_gpreg(reg32_t.EAX)
        self.emu.out_io32(self.instr.imm8, eax)

    def call_rel32(self) -> None:
        """Execute decoded ``CALL_REL32`` semantics through frontend emulator effects."""
        target = near_relative_target32(
            self._active_stack_emulator(), self.instr.imm32, self.instr.size
        )
        emit_near_call32(
            self._active_stack_emulator(),
            target,
            far_return_ip32(self._active_stack_emulator(), self.instr.size),
        )

    def jmp_rel32(self) -> None:
        """Execute decoded ``JMP_REL32`` semantics through frontend emulator effects."""
        target = near_relative_target32(
            self._active_stack_emulator(), self.instr.imm32, self.instr.size
        )
        emit_near_jump32(self._active_stack_emulator(), target)

    def jmpf_ptr16_32(self) -> None:
        """Execute decoded ``JMPF_PTR16_32`` semantics through frontend emulator effects."""
        emit_far_jump32(self._active_stack_emulator(), self.instr.ptr16, self.instr.imm32)

    def in_eax_dx(self) -> None:
        """Execute decoded ``IN_EAX_DX`` semantics through frontend emulator effects."""
        dx = self.emu.get_gpreg(reg16_t.DX)
        self.emu.set_gpreg(reg32_t.EAX, self.emu.in_io32(_vex_expr(dx)))

    def out_dx_eax(self) -> None:
        """Execute decoded ``OUT_DX_EAX`` semantics through frontend emulator effects."""
        dx = self.emu.get_gpreg(reg16_t.DX)
        eax = self.emu.get_gpreg(reg32_t.EAX)
        self.emu.out_io32(_vex_expr(dx), eax)

    def jo_rel32(self) -> None:
        """Execute decoded ``JO_REL32`` semantics through frontend emulator effects."""
        branch_rel32(
            self._active_stack_emulator(), self.emu.is_overflow(), self.instr.imm32, self.instr.size
        )

    def jno_rel32(self) -> None:
        """Execute decoded ``JNO_REL32`` semantics through frontend emulator effects."""
        branch_rel32(
            self._active_stack_emulator(), ~self.emu.is_overflow(), self.instr.imm32, self.instr.size
        )

    def jb_rel32(self) -> None:
        """Execute decoded ``JB_REL32`` semantics through frontend emulator effects."""
        branch_rel32(
            self._active_stack_emulator(),
            self._branch_cond_8616("jb", self.emu.is_carry()),
            self.instr.imm32,
            self.instr.size,
        )

    def jnb_rel32(self) -> None:
        """Execute decoded ``JNB_REL32`` semantics through frontend emulator effects."""
        branch_rel32(
            self._active_stack_emulator(),
            self._branch_cond_8616("jnb", ~self.emu.is_carry()),
            self.instr.imm32,
            self.instr.size,
        )

    def jz_rel32(self) -> None:
        """Execute decoded ``JZ_REL32`` semantics through frontend emulator effects."""
        branch_rel32(
            self._active_stack_emulator(),
            self._branch_cond_8616("jz", self.emu.is_zero()),
            self.instr.imm32,
            self.instr.size,
        )

    def jnz_rel32(self) -> None:
        """Execute decoded ``JNZ_REL32`` semantics through frontend emulator effects."""
        branch_rel32(
            self._active_stack_emulator(),
            self._branch_cond_8616("jnz", ~self.emu.is_zero()),
            self.instr.imm32,
            self.instr.size,
        )

    def jbe_rel32(self) -> None:
        """Execute decoded ``JBE_REL32`` semantics through frontend emulator effects."""
        branch_rel32(
            self._active_stack_emulator(),
            self._branch_cond_8616("jbe", self.emu.is_carry() | self.emu.is_zero()),
            self.instr.imm32,
            self.instr.size,
        )

    def ja_rel32(self) -> None:
        """Execute decoded ``JA_REL32`` semantics through frontend emulator effects."""
        branch_rel32(
            self._active_stack_emulator(),
            self._branch_cond_8616("ja", ~(self.emu.is_carry() | self.emu.is_zero())),
            self.instr.imm32,
            self.instr.size,
        )

    def js_rel32(self) -> None:
        """Execute decoded ``JS_REL32`` semantics through frontend emulator effects."""
        branch_rel32(self._active_stack_emulator(), self.emu.is_sign(), self.instr.imm32, self.instr.size)

    def jns_rel32(self) -> None:
        """Execute decoded ``JNS_REL32`` semantics through frontend emulator effects."""
        branch_rel32(self._active_stack_emulator(), ~self.emu.is_sign(), self.instr.imm32, self.instr.size)

    def jp_rel32(self) -> None:
        """Execute decoded ``JP_REL32`` semantics through frontend emulator effects."""
        branch_rel32(self._active_stack_emulator(), self.emu.is_parity(), self.instr.imm32, self.instr.size)

    def jnp_rel32(self) -> None:
        """Execute decoded ``JNP_REL32`` semantics through frontend emulator effects."""
        branch_rel32(self._active_stack_emulator(), ~self.emu.is_parity(), self.instr.imm32, self.instr.size)

    def jl_rel32(self) -> None:
        """Execute decoded ``JL_REL32`` semantics through frontend emulator effects."""
        branch_rel32(
            self._active_stack_emulator(),
            self._branch_cond_8616("jl", self.emu.is_sign() != self.emu.is_overflow()),
            self.instr.imm32,
            self.instr.size,
        )

    def jnl_rel32(self) -> None:
        """Execute decoded ``JNL_REL32`` semantics through frontend emulator effects."""
        branch_rel32(
            self._active_stack_emulator(),
            self._branch_cond_8616("jge", self.emu.is_sign() == self.emu.is_overflow()),
            self.instr.imm32,
            self.instr.size,
        )

    def jle_rel32(self) -> None:
        """Execute decoded ``JLE_REL32`` semantics through frontend emulator effects."""
        branch_rel32(
            self._active_stack_emulator(),
            self._branch_cond_8616("jle", self.emu.is_zero() | (self.emu.is_sign() != self.emu.is_overflow())),
            self.instr.imm32,
            self.instr.size,
        )

    def jnle_rel32(self) -> None:
        """Execute decoded ``JNLE_REL32`` semantics through frontend emulator effects."""
        branch_rel32(
            self._active_stack_emulator(),
            self._branch_cond_8616("jg", ~self.emu.is_zero() & (self.emu.is_sign() == self.emu.is_overflow())),
            self.instr.imm32,
            self.instr.size,
        )

    def imul_r32_rm32(self) -> None:
        """Execute decoded ``IMUL_R32_RM32`` semantics through frontend emulator effects."""
        r32_s = _vex_expr(self.get_r32())
        rm32_s = _vex_expr(self.get_rm32())
        self.set_r32(r32_s * rm32_s)
        self.emu.update_eflags_imul(r32_s, rm32_s)

    def _load_pointer_segment32(self, segment: sgreg_t) -> None:
        """Load a 16:32 memory pointer into the ModR/M register and segment."""
        source_segment, source_offset = self._resolved_rm_address()
        offset, selector = load_far_pointer(
            self.emu,
            source_segment,
            source_offset,
            32,
            self.effective_address_bits(),
        )
        self.set_r32(offset)
        self.emu.set_sgreg(segment, selector)

    def lss_r32_m16_32(self) -> None:
        """Load a 16:32 pointer and its selector into SS."""
        self._load_pointer_segment32(sgreg_t.SS)

    def lfs_r32_m16_32(self) -> None:
        """Load a 16:32 pointer and its selector into FS."""
        self._load_pointer_segment32(sgreg_t.FS)

    def lgs_r32_m16_32(self) -> None:
        """Load a 16:32 pointer and its selector into GS."""
        self._load_pointer_segment32(sgreg_t.GS)

    def les_r32_m16_32(self) -> None:
        """Load a 16:32 pointer and its selector into ES."""
        self._load_pointer_segment32(sgreg_t.ES)

    def lds_r32_m16_32(self) -> None:
        """Load a 16:32 pointer and its selector into DS."""
        self._load_pointer_segment32(sgreg_t.DS)

    def _double_shift32(self, *, left: bool, count: VexExpr | int) -> None:
        """Execute a 32-bit SHLD/SHRD operation with a masked 80386 count."""
        dst = _vex_expr(self.get_rm32())
        src = _vex_expr(self.get_r32())
        masked = _vex_expr(masked_shift_count(self.emu, count, 32)).cast_to(Type.int_8)
        inverse = self.emu.constant(32, Type.int_8) - masked
        shifted = (dst << masked) | (src >> inverse) if left else (dst >> masked) | (src << inverse)
        result = self._ite_value(masked == self.emu.constant(0, Type.int_8), dst, shifted.cast_to(Type.int_32))
        self.set_rm32(result)
        self.emu.update_eflags_double_shift(dst, result, masked, left=left)

    def _bit_operation32(self, operation: str, *, immediate: bool = False) -> None:
        """Apply one 32-bit BT-family operation, including memory bit strings."""
        index = _vex_expr(
            self.emu.constant(self.instr.imm8 & 0xFF, Type.int_32)
            if immediate
            else self.get_r32()
        )
        bit = (index & self.emu.constant(31, Type.int_32)).cast_to(Type.int_8)
        if self.instr.modrm.mod == 3:
            value = _vex_expr(self.get_rm32())

            def write_register(result: object) -> None:
                self.set_rm32(result)

            write: Callable[[object], None] = write_register
        else:
            operand = self._resolved_rm_operand(32)
            offset = operand.offset
            if not immediate:
                displacement = (index.signed.sar(self.emu.constant(5, Type.int_8)) * 4).cast_to(
                    Type.int_32 if self.effective_address_bits() == 32 else Type.int_16
                )
                offset = offset + displacement
            value = _vex_expr(self.emu.get_data32(operand.segment, offset))

            def write_memory(result: object) -> None:
                self.emu.put_data32(operand.segment, offset, result)

            write = write_memory
        mask = self.emu.constant(1, Type.int_32) << bit
        carry = ((value >> bit) & self.emu.constant(1, Type.int_32)).cast_to(Type.int_1)
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        self.emu.set_gpreg(reg16_t.FLAGS, self.emu.set_carry(flags, carry))
        if operation == "set":
            write(value | mask)
        elif operation == "reset":
            write(value & ~mask)
        elif operation == "complement":
            write(value ^ mask)

    def bt_rm32_r32(self) -> None:
        """Test a register-indexed bit and copy it to CF."""
        self._bit_operation32("test")

    def bts_rm32_r32(self) -> None:
        """Test and set a register-indexed bit."""
        self._bit_operation32("set")

    def btr_rm32_r32(self) -> None:
        """Test and reset a register-indexed bit."""
        self._bit_operation32("reset")

    def btc_rm32_r32(self) -> None:
        """Test and complement a register-indexed bit."""
        self._bit_operation32("complement")

    def code_0fba(self) -> None:
        """Dispatch immediate-index BT/BTS/BTR/BTC group members."""
        self._dispatch_modrm_reg(
            (None, None, None, None, self.bt_rm32_imm8, self.bts_rm32_imm8, self.btr_rm32_imm8, self.btc_rm32_imm8),
            "0x0fba",
            lambda reg: ERROR("invalid 0x0fba /%d\n", reg),
        )

    def bt_rm32_imm8(self) -> None:
        """Test an immediate-indexed bit and copy it to CF."""
        self._bit_operation32("test", immediate=True)

    def bts_rm32_imm8(self) -> None:
        """Test and set an immediate-indexed bit."""
        self._bit_operation32("set", immediate=True)

    def btr_rm32_imm8(self) -> None:
        """Test and reset an immediate-indexed bit."""
        self._bit_operation32("reset", immediate=True)

    def btc_rm32_imm8(self) -> None:
        """Test and complement an immediate-indexed bit."""
        self._bit_operation32("complement", immediate=True)

    def shld_rm32_r32_imm8(self) -> None:
        """Double-precision left shift using an immediate count."""
        self._double_shift32(left=True, count=self.instr.imm8)

    def shld_rm32_r32_cl(self) -> None:
        """Double-precision left shift using CL."""
        self._double_shift32(left=True, count=self.emu.get_gpreg(reg8_t.CL))

    def shrd_rm32_r32_imm8(self) -> None:
        """Double-precision right shift using an immediate count."""
        self._double_shift32(left=False, count=self.instr.imm8)

    def shrd_rm32_r32_cl(self) -> None:
        """Double-precision right shift using CL."""
        self._double_shift32(left=False, count=self.emu.get_gpreg(reg8_t.CL))

    def _bit_scan32(self, *, reverse: bool) -> None:
        """Scan a 32-bit source and update the destination and zero flag."""
        src = _vex_expr(self.get_rm32())
        old = _vex_expr(self.get_r32())
        result = old
        indices = range(32) if reverse else range(31, -1, -1)
        for index in indices:
            bit = src & self.emu.constant(1 << index, Type.int_32)
            result = self._ite_value(bit != self.emu.constant(0, Type.int_32), self.emu.constant(index, Type.int_32), result)
        is_zero = src == self.emu.constant(0, Type.int_32)
        self.set_r32(self._ite_value(is_zero, old, result))
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        self.emu.set_gpreg(reg16_t.FLAGS, self.emu.set_zero(flags, is_zero))

    def bsf_r32_rm32(self) -> None:
        """Find the least-significant set bit in a 32-bit operand."""
        self._bit_scan32(reverse=False)

    def bsr_r32_rm32(self) -> None:
        """Find the most-significant set bit in a 32-bit operand."""
        self._bit_scan32(reverse=True)

    def movzx_r32_rm8(self) -> None:
        """Execute decoded ``MOVZX_R32_RM8`` semantics through frontend emulator effects."""
        rm8 = _vex_expr(self.get_rm8()).cast_to(Type.int_32)
        self.set_r32(rm8)

    def movzx_r32_rm16(self) -> None:
        """Execute decoded ``MOVZX_R32_RM16`` semantics through frontend emulator effects."""
        rm16 = _vex_expr(self.get_rm16()).cast_to(Type.int_32)
        self.set_r32(rm16)

    def movsx_r32_rm8(self) -> None:
        """Execute decoded ``MOVSX_R32_RM8`` semantics through frontend emulator effects."""
        rm8_s = _vex_expr(self.get_rm8()).cast_to(Type.int_32, signed=True)
        self.set_r32(rm8_s)

    def movsx_r32_rm16(self) -> None:
        """Execute decoded ``MOVSX_R32_RM16`` semantics through frontend emulator effects."""
        rm16_s = _vex_expr(self.get_rm16()).cast_to(Type.int_32, signed=True)
        self.set_r32(rm16_s)

    def code_81(self) -> None:
        """Execute decoded ``CODE_81`` semantics through frontend emulator effects."""
        self._dispatch_modrm_reg(
            (
                self.add_rm32_imm32,
                self.or_rm32_imm32,
                self.adc_rm32_imm32,
                self.sbb_rm32_imm32,
                self.and_rm32_imm32,
                self.sub_rm32_imm32,
                self.xor_rm32_imm32,
                self.cmp_rm32_imm32,
            ),
            "0x81",
            lambda reg: ERROR("not implemented: 0x81 /%d\n", reg),
        )

    def code_83(self) -> None:
        """Execute decoded ``CODE_83`` semantics through frontend emulator effects."""
        self._dispatch_modrm_reg(
            (
                self.add_rm32_imm8,
                self.or_rm32_imm8,
                self.adc_rm32_imm8,
                self.sbb_rm32_imm8,
                self.and_rm32_imm8,
                self.sub_rm32_imm8,
                self.xor_rm32_imm8,
                self.cmp_rm32_imm8,
            ),
            "0x83",
            lambda reg: ERROR("not implemented: 0x83 /%d\n", reg),
        )

    def code_c1(self) -> None:
        """Execute decoded ``CODE_C1`` semantics through frontend emulator effects."""
        self._dispatch_modrm_reg(
            (
                self.rol_rm32_imm8,
                self.ror_rm32_imm8,
                self.rcl_rm32_imm8,
                self.rcr_rm32_imm8,
                self.shl_rm32_imm8,
                self.shr_rm32_imm8,
                self.sal_rm32_imm8,
                self.sar_rm32_imm8,
            ),
            "0xc1",
            lambda reg: ERROR("not implemented: 0xc1 /%d\n", reg),
        )

    def code_d3(self) -> None:
        """Execute decoded ``CODE_D3`` semantics through frontend emulator effects."""
        self._dispatch_modrm_reg(
            (
                self.rol_rm32_cl,
                self.ror_rm32_cl,
                self.rcl_rm32_cl,
                self.rcr_rm32_cl,
                self.shl_rm32_cl,
                self.shr_rm32_cl,
                self.sal_rm32_cl,
                self.sar_rm32_cl,
            ),
            "0xd3",
            lambda reg: ERROR("not implemented: 0xd3 /%d\n", reg),
        )

    def code_d1(self) -> None:
        """Dispatch count-one 32-bit rotate and shift group members."""
        self._dispatch_modrm_reg(
            (
                self.rol_rm32_1,
                self.ror_rm32_1,
                self.rcl_rm32_1,
                self.rcr_rm32_1,
                self.shl_rm32_1,
                self.shr_rm32_1,
                self.sal_rm32_1,
                self.sar_rm32_1,
            ),
            "0xd1",
            lambda reg: ERROR("not implemented: 0xd1 /%d\n", reg),
        )

    def code_f7(self) -> None:
        """Execute decoded ``CODE_F7`` semantics through frontend emulator effects."""
        self._dispatch_modrm_reg(
            (
                self.test_rm32_imm32,
                self.test_rm32_imm32,
                self.not_rm32,
                self.neg_rm32,
                self.mul_edx_eax_rm32,
                self.imul_edx_eax_rm32,
                self.div_edx_eax_rm32,
                self.idiv_edx_eax_rm32,
            ),
            "0xf7",
            lambda reg: ERROR("not implemented: 0xf7 /%d\n", reg),
        )

    def code_ff(self) -> None:
        """Execute decoded ``CODE_FF`` semantics through frontend emulator effects."""
        self._dispatch_modrm_reg(
            (
                self.inc_rm32,
                self.dec_rm32,
                self.call_rm32,
                self.callf_m16_32,
                self.jmp_rm32,
                self.jmpf_m16_32,
                self.push_rm32,
                None,
            ),
            "0xff",
            lambda reg: ERROR("not implemented: 0xff /%d\n", reg),
        )

    def code_0f00(self) -> None:
        """Execute decoded ``CODE_0F00`` semantics through frontend emulator effects."""
        self._dispatch_modrm_reg(
            (None, None, None, self.ltr_rm16),
            "0x0f00",
            lambda reg: ERROR("not implemented: 0x0f00 /%d\n", reg),
        )

    def code_0f01(self) -> None:
        """Execute decoded ``CODE_0F01`` semantics through frontend emulator effects."""
        self._dispatch_modrm_reg(
            (None, None, None, None),
            "0x0f01",
            lambda reg: ERROR("not implemented: 0x0f01 /%d\n", reg),
        )

    def add_rm32_imm32(self) -> None:
        """Execute decoded ``ADD_RM32_IMM32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm32,
            self.set_rm32,
            self.emu.update_eflags_add,
            lambda lhs, rhs: lhs + rhs,
        )

    def or_rm32_imm32(self) -> None:
        """Execute decoded ``OR_RM32_IMM32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm32,
            self.set_rm32,
            self.emu.update_eflags_or,
            lambda lhs, rhs: lhs | rhs,
        )

    def adc_rm32_imm32(self) -> None:
        """Execute decoded ``ADC_RM32_IMM32`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm32,
            self.set_rm32,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            32,
        )

    def sbb_rm32_imm32(self) -> None:
        """Execute decoded ``SBB_RM32_IMM32`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm32,
            self.set_rm32,
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            32,
        )

    def and_rm32_imm32(self) -> None:
        """Execute decoded ``AND_RM32_IMM32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm32,
            self.set_rm32,
            self.emu.update_eflags_and,
            lambda lhs, rhs: lhs & rhs,
        )

    def sub_rm32_imm32(self) -> None:
        """Execute decoded ``SUB_RM32_IMM32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm32,
            self.set_rm32,
            self.emu.update_eflags_sub,
            lambda lhs, rhs: lhs - rhs,
        )

    def xor_rm32_imm32(self) -> None:
        """Execute decoded ``XOR_RM32_IMM32`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm32,
            self.set_rm32,
            self.emu.update_eflags_xor,
            lambda lhs, rhs: lhs ^ rhs,
        )

    def cmp_rm32_imm32(self) -> None:
        """Execute decoded ``CMP_RM32_IMM32`` semantics through frontend emulator effects."""
        compare_operation(self.get_rm32, lambda: self.instr.imm32, self.emu.update_eflags_sub)

    def add_rm32_imm8(self) -> None:
        """Execute decoded ``ADD_RM32_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm8,
            self.set_rm32,
            self.emu.update_eflags_add,
            lambda lhs, rhs: lhs + rhs,
        )

    def or_rm32_imm8(self) -> None:
        """Execute decoded ``OR_RM32_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm8,
            self.set_rm32,
            self.emu.update_eflags_or,
            lambda lhs, rhs: lhs | rhs,
        )

    def adc_rm32_imm8(self) -> None:
        """Execute decoded ``ADC_RM32_IMM8`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm8,
            self.set_rm32,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            32,
        )

    def sbb_rm32_imm8(self) -> None:
        """Execute decoded ``SBB_RM32_IMM8`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm8,
            self.set_rm32,
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            32,
        )

    def and_rm32_imm8(self) -> None:
        """Execute decoded ``AND_RM32_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm8,
            self.set_rm32,
            self.emu.update_eflags_and,
            lambda lhs, rhs: lhs & rhs,
        )

    def sub_rm32_imm8(self) -> None:
        """Execute decoded ``SUB_RM32_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm8,
            self.set_rm32,
            self.emu.update_eflags_sub,
            lambda lhs, rhs: lhs - rhs,
        )

    def xor_rm32_imm8(self) -> None:
        """Execute decoded ``XOR_RM32_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm8,
            self.set_rm32,
            self.emu.update_eflags_xor,
            lambda lhs, rhs: lhs ^ rhs,
        )

    def cmp_rm32_imm8(self) -> None:
        """Execute decoded ``CMP_RM32_IMM8`` semantics through frontend emulator effects."""
        compare_operation(self.get_rm32, lambda: self.instr.imm8, self.emu.update_eflags_sub)

    def shl_rm32_imm8(self) -> None:
        """Execute decoded ``SHL_RM32_IMM8`` semantics through frontend emulator effects."""
        rm32 = self.get_rm32()
        count = _vex_expr(masked_shift_count(self.emu, self.instr.imm8, 32)).cast_to(Type.int_8)
        self.set_rm32(rm32 << count)
        self.emu.update_eflags_shl(rm32, self.instr.imm8)

    def _rotate32(self, *, left: bool, count: VexExpr | int) -> None:
        """Rotate a 32-bit r/m operand and update defined ROL/ROR flags."""
        value = _vex_expr(self.get_rm32())
        count_value = self.emu.constant(count, Type.int_8) if isinstance(count, int) else count
        masked = (_vex_expr(count_value).cast_to(Type.int_8) & self.emu.constant(0x1F, Type.int_8))
        inverse = self.emu.constant(32, Type.int_8) - masked
        rotated = (value << masked) | (value >> inverse) if left else (value >> masked) | (value << inverse)
        result = self._ite_value(masked == self.emu.constant(0, Type.int_8), value, rotated.cast_to(Type.int_32))
        self.set_rm32(result)
        if left:
            self.emu.update_eflags_rol(value, masked)
        else:
            self.emu.update_eflags_ror(value, masked)

    def _rotate_carry32(self, *, left: bool, count: VexExpr | int) -> None:
        """Rotate a 32-bit r/m operand through CF on the architectural 33-bit ring."""
        value = _vex_expr(self.get_rm32())
        count_value = self.emu.constant(count, Type.int_8) if isinstance(count, int) else count
        masked = _vex_expr(count_value).cast_to(Type.int_8) & self.emu.constant(0x1F, Type.int_8)
        helper = rotate_through_carry_left_state if left else rotate_through_carry_right_state
        result, carry, overflow = helper(self.emu, value, masked, 32, self._ite_value)
        if carry is None:
            self.set_rm32(value)
            return
        self.set_rm32(result)
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        flags = self.emu.set_carry(flags, carry.cast_to(Type.int_1))
        flags = self.emu.set_overflow(
            flags,
            self._ite_value(masked == self.emu.constant(1, Type.int_8), overflow, self.emu.get_flag(11)),
        )
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def rol_rm32_imm8(self) -> None:
        """Rotate a 32-bit operand left by an immediate count."""
        self._rotate32(left=True, count=self.instr.imm8)

    def ror_rm32_imm8(self) -> None:
        """Rotate a 32-bit operand right by an immediate count."""
        self._rotate32(left=False, count=self.instr.imm8)

    def rcl_rm32_imm8(self) -> None:
        """Rotate a 32-bit operand left through carry by an immediate count."""
        self._rotate_carry32(left=True, count=self.instr.imm8)

    def rcr_rm32_imm8(self) -> None:
        """Rotate a 32-bit operand right through carry by an immediate count."""
        self._rotate_carry32(left=False, count=self.instr.imm8)

    def rol_rm32_1(self) -> None:
        """Rotate a 32-bit operand left once."""
        self._rotate32(left=True, count=1)

    def ror_rm32_1(self) -> None:
        """Rotate a 32-bit operand right once."""
        self._rotate32(left=False, count=1)

    def rcl_rm32_1(self) -> None:
        """Rotate a 32-bit operand left through carry once."""
        self._rotate_carry32(left=True, count=1)

    def rcr_rm32_1(self) -> None:
        """Rotate a 32-bit operand right through carry once."""
        self._rotate_carry32(left=False, count=1)

    def rol_rm32_cl(self) -> None:
        """Rotate a 32-bit operand left by CL."""
        self._rotate32(left=True, count=self.emu.get_gpreg(reg8_t.CL))

    def ror_rm32_cl(self) -> None:
        """Rotate a 32-bit operand right by CL."""
        self._rotate32(left=False, count=self.emu.get_gpreg(reg8_t.CL))

    def rcl_rm32_cl(self) -> None:
        """Rotate a 32-bit operand left through carry by CL."""
        self._rotate_carry32(left=True, count=self.emu.get_gpreg(reg8_t.CL))

    def rcr_rm32_cl(self) -> None:
        """Rotate a 32-bit operand right through carry by CL."""
        self._rotate_carry32(left=False, count=self.emu.get_gpreg(reg8_t.CL))

    def shl_rm32_1(self) -> None:
        """Shift a 32-bit r/m operand left once."""
        rm32 = _vex_expr(self.get_rm32())
        self.set_rm32(rm32 << 1)
        self.emu.update_eflags_shl(rm32, 1)

    def shr_rm32_1(self) -> None:
        """Shift a 32-bit r/m operand right logically once."""
        rm32 = _vex_expr(self.get_rm32())
        self.set_rm32(rm32 >> 1)
        self.emu.update_eflags_shr(rm32, 1)

    def sal_rm32_1(self) -> None:
        """Shift a 32-bit r/m operand arithmetically left once."""
        rm32 = _vex_expr(self.get_rm32())
        self.set_rm32(rm32 << 1)
        self.emu.update_eflags_shl(rm32, 1)

    def sar_rm32_1(self) -> None:
        """Shift a 32-bit r/m operand right arithmetically once."""
        rm32 = _vex_expr(self.get_rm32())
        self.set_rm32(rm32.sar(self.emu.constant(1, Type.int_8)))
        self.emu.update_eflags_sar(rm32, 1)

    def shr_rm32_imm8(self) -> None:
        """Execute decoded ``SHR_RM32_IMM8`` semantics through frontend emulator effects."""
        rm32 = self.get_rm32()
        count = _vex_expr(masked_shift_count(self.emu, self.instr.imm8, 32)).cast_to(Type.int_8)
        self.set_rm32(rm32 >> count)
        self.emu.update_eflags_shr(rm32, self.instr.imm8)

    def sal_rm32_imm8(self) -> None:
        """Execute decoded ``SAL_RM32_IMM8`` semantics through frontend emulator effects."""
        rm32_s = self.get_rm32()
        count = _vex_expr(masked_shift_count(self.emu, self.instr.imm8, 32)).cast_to(Type.int_8)
        self.set_rm32(rm32_s << count)
        self.emu.update_eflags_shl(rm32_s, self.instr.imm8)

    def sar_rm32_imm8(self) -> None:
        """Execute decoded ``SAR_RM32_IMM8`` semantics through frontend emulator effects."""
        rm32_s = _vex_expr(self.get_rm32())
        count = _vex_expr(masked_shift_count(self.emu, self.instr.imm8, 32)).cast_to(Type.int_8)
        self.set_rm32(rm32_s.sar(count))
        self.emu.update_eflags_sar(rm32_s, self.instr.imm8)

    def shl_rm32_cl(self) -> None:
        """Execute decoded ``SHL_RM32_CL`` semantics through frontend emulator effects."""
        rm32 = self.get_rm32()
        cl = _vex_expr(masked_shift_count(self.emu, self.emu.get_gpreg(reg8_t.CL), 32)).cast_to(Type.int_8)
        self.set_rm32(rm32 << cl)
        self.emu.update_eflags_shl(rm32, cl)

    def shr_rm32_cl(self) -> None:
        """Execute decoded ``SHR_RM32_CL`` semantics through frontend emulator effects."""
        rm32 = self.get_rm32()
        cl = _vex_expr(masked_shift_count(self.emu, self.emu.get_gpreg(reg8_t.CL), 32)).cast_to(Type.int_8)
        self.set_rm32(rm32 >> cl)
        self.emu.update_eflags_shr(rm32, cl)

    def sal_rm32_cl(self) -> None:
        """Execute decoded ``SAL_RM32_CL`` semantics through frontend emulator effects."""
        rm32_s = self.get_rm32()
        cl = _vex_expr(masked_shift_count(self.emu, self.emu.get_gpreg(reg8_t.CL), 32)).cast_to(Type.int_8)
        self.set_rm32(rm32_s << cl)
        self.emu.update_eflags_shl(rm32_s, cl)

    def sar_rm32_cl(self) -> None:
        """Execute decoded ``SAR_RM32_CL`` semantics through frontend emulator effects."""
        rm32_s = _vex_expr(self.get_rm32())
        cl = _vex_expr(masked_shift_count(self.emu, self.emu.get_gpreg(reg8_t.CL), 32)).cast_to(Type.int_8)
        self.set_rm32(rm32_s.sar(cl))
        self.emu.update_eflags_sar(rm32_s, cl)

    def test_rm32_imm32(self) -> None:
        """Execute decoded ``TEST_RM32_IMM32`` semantics through frontend emulator effects."""
        self.emu.set_gpreg(reg32_t.EIP, advance_eip32(self.emu, 4))
        compare_operation(self.get_rm32, lambda: self.instr.imm32, self.emu.update_eflags_and)

    def not_rm32(self) -> None:
        """Execute decoded ``NOT_RM32`` semantics through frontend emulator effects."""
        unary_operation(self.get_rm32, self.set_rm32, None, lambda value: ~value)

    def neg_rm32(self) -> None:
        """Execute decoded ``NEG_RM32`` semantics through frontend emulator effects."""
        unary_operation(
            self.get_rm32,
            self.set_rm32,
            self.emu.update_eflags_neg,
            lambda value: (_vex_expr(value).signed * -1).cast_to(Type.int_32),
        )

    def mul_edx_eax_rm32(self) -> None:
        """Execute decoded ``MUL_EDX_EAX_RM32`` semantics through frontend emulator effects."""
        rm32 = _vex_expr(self.get_rm32())
        eax = _vex_expr(self.emu.get_gpreg(reg32_t.EAX))
        val = eax.cast_to(Type.int_64) * rm32.cast_to(Type.int_64)
        self.emu.set_gpreg(reg32_t.EAX, val.cast_to(Type.int_32))
        self.emu.set_gpreg(reg32_t.EDX, (val >> 32).cast_to(Type.int_32))
        self.emu.update_eflags_mul(eax, rm32)

    def imul_edx_eax_rm32(self) -> None:
        """Execute decoded ``IMUL_EDX_EAX_RM32`` semantics through frontend emulator effects."""
        rm32_s = _vex_expr(self.get_rm32()).signed
        eax_s = _vex_expr(self.emu.get_gpreg(reg32_t.EAX)).signed
        val_s = eax_s.widen_signed(Type.int_64) * rm32_s.widen_signed(Type.int_64)
        self.emu.set_gpreg(reg32_t.EAX, val_s.cast_to(Type.int_32))
        self.emu.set_gpreg(reg32_t.EDX, (val_s.signed >> 32).cast_to(Type.int_32))
        self.emu.update_eflags_imul(eax_s, rm32_s)

    def div_edx_eax_rm32(self) -> None:
        """Execute decoded ``DIV_EDX_EAX_RM32`` semantics through frontend emulator effects."""
        rm32 = _vex_expr(self.get_rm32()).cast_to(Type.int_64)
        val = (_vex_expr(self.emu.get_gpreg(reg32_t.EDX)).cast_to(Type.int_64) << 32) | _vex_expr(
            self.emu.get_gpreg(reg32_t.EAX)
        ).cast_to(Type.int_64)
        self._divide_error_if(rm32 == self.emu.constant(0, Type.int_64))
        quotient = val // rm32
        self._divide_error_if(quotient > self.emu.constant(0xFFFFFFFF, Type.int_64))
        self.emu.set_gpreg(reg32_t.EAX, quotient.cast_to(Type.int_32))
        self.emu.set_gpreg(reg32_t.EDX, (val % rm32).cast_to(Type.int_32))

    def idiv_edx_eax_rm32(self) -> None:
        """Execute decoded ``IDIV_EDX_EAX_RM32`` semantics through frontend emulator effects."""
        rm32_s = _vex_expr(self.get_rm32()).cast_to(Type.int_64, signed=True)
        val_s = (
            (_vex_expr(self.emu.get_gpreg(reg32_t.EDX)).cast_to(Type.int_64, signed=True) << 32)
            | _vex_expr(self.emu.get_gpreg(reg32_t.EAX)).cast_to(Type.int_64)
        ).signed
        self._divide_error_if(rm32_s == self.emu.constant(0, Type.int_64))
        quotient = val_s // rm32_s
        remainder = val_s - quotient * rm32_s
        signed_quotient = quotient.signed
        self._divide_error_if(
            (signed_quotient < _require_vex_value(self.emu.constant(0xFFFFFFFF80000000, Type.int_64)).signed)
            | (signed_quotient > _require_vex_value(self.emu.constant(0x000000007FFFFFFF, Type.int_64)).signed)
        )
        self.emu.set_gpreg(reg32_t.EAX, quotient.cast_to(Type.int_32))
        self.emu.set_gpreg(reg32_t.EDX, remainder.cast_to(Type.int_32))

    def inc_rm32(self) -> None:
        """Execute decoded ``INC_RM32`` semantics through frontend emulator effects."""
        unary_operation(self.get_rm32, self.set_rm32, self.emu.update_eflags_inc, lambda value: value + 1)

    def dec_rm32(self) -> None:
        """Execute decoded ``DEC_RM32`` semantics through frontend emulator effects."""
        unary_operation(self.get_rm32, self.set_rm32, self.emu.update_eflags_dec, lambda value: value - 1)

    def call_rm32(self) -> None:
        """Execute decoded ``CALL_RM32`` semantics through frontend emulator effects."""
        rm32 = self.get_rm32()
        emit_near_call32(
            self._active_stack_emulator(),
            rm32,
            far_return_ip32(self._active_stack_emulator(), self.instr.size),
        )

    def callf_m16_32(self) -> None:
        """Execute decoded ``CALLF_M16_32`` semantics through frontend emulator effects."""
        seg, offset = self._resolved_rm_address()
        eip, cs = load_far_pointer(
            self.emu,
            seg,
            offset,
            32,
            address_bits=self.effective_address_bits(),
        )
        INFO(2, "cs = 0x%04x, eip = 0x%08x", cs, eip)
        emit_far_call32(
            self._active_stack_emulator(), cs, eip, far_return_ip32(self._active_stack_emulator(), self.instr.size)
        )

    def jmp_rm32(self) -> None:
        """Execute decoded ``JMP_RM32`` semantics through frontend emulator effects."""
        rm32 = self.get_rm32()
        emit_near_jump32(self._active_stack_emulator(), rm32)

    def jmpf_m16_32(self) -> None:
        """Execute decoded ``JMPF_M16_32`` semantics through frontend emulator effects."""
        seg, offset = self._resolved_rm_address()
        eip, sel = load_far_pointer(
            self.emu,
            seg,
            offset,
            32,
            address_bits=self.effective_address_bits(),
        )
        emit_far_jump32(self._active_stack_emulator(), sel, eip)

    def push_rm32(self) -> None:
        """Execute decoded ``PUSH_RM32`` semantics through frontend emulator effects."""
        rm32 = self.get_rm32()
        push_immediate32(self._active_stack_emulator(), rm32)

    def _branch_cond_8616(self, kind: str, fallback: VexExpr) -> VexExpr:
        """Prefer a transferred typed branch condition over the flag fallback."""
        lifter_instruction = self.emu.lifter_instruction
        if lifter_instruction is None:
            raise RuntimeError("condition transfer requires an active lifter instruction")
        direct = _consume_last_condition_branch_8616(lifter_instruction, self.emu, kind)
        return fallback if direct is None else direct
