"""Layer: Frontend/runtime.

Responsibility: provide shared opcode handlers for instruction lifting/emulation.
Forbidden: decompiler semantic repair, source/COD-backed behavior, or rewrite cleanup.

Dynamic value boundary: PyVEX expressions overload Python operators at runtime;
``VexExpr`` is confined to those third-party expression values and active lifter hooks.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from types import MethodType
from typing import TYPE_CHECKING, Any, cast

from pyvex.lifting.util import JumpKind
from pyvex.lifting.util.vex_helper import Type

from .addressing_helpers import load_resolved_operand, store_resolved_operand
from .alu_helpers import (
    binary_operation,
    binary_operation_with_carry,
    compare_operation,
    masked_shift_count,
    rotate_count,
    rotate_left_operation,
    rotate_right_operation,
    rotate_through_carry_left_state,
    rotate_through_carry_right_state,
    shift_left_operation,
    shift_right_arithmetic_operation,
    shift_right_operation,
    unary_operation,
)
from .emu import EmuInstr
from .exception import EXP_GP
from .exec import ExecInstr, OpcodeExecHandler
from .instruction import CHK_IMM8, CHK_IMM16, CHK_MODRM, CHK_MOFFS, MAX_OPCODE, InstrData, InstrFlags
from .interrupt_contract import interrupt_core_addr_8616
from .msvc_x87_interrupts import is_msvc_x87_emulation_interrupt_8616, msvc_x87_escape_opcode_8616
from .parse import ParseInstr
from .regs import coerce_reg8_t, coerce_reg32_t, reg8_t, reg16_t
from .stack_helpers import StackEmulator, branch_rel8, return_far16, return_interrupt16
from .string_helpers import StringEmulator
from .vex_value_contract import require_vex_value_8616 as _require_vex_value

if TYPE_CHECKING:
    from .emulator import Emulator

CHSZ_NONE: int = 0
CHSZ_OP: int = 1
CHSZ_AD: int = 2


logger: logging.Logger = logging.getLogger(__name__)

type BoundOpcodeHandler = Callable[[], None]
type OpcodeRegistrationHandler = OpcodeExecHandler | BoundOpcodeHandler
type VexExpr = Any


def _vex_expr(value: object) -> VexExpr:
    """Expose one concrete-or-PyVEX runtime value at the third-party boundary."""
    return cast(VexExpr, value)


def _unbound_opcode_handler(func: OpcodeRegistrationHandler) -> OpcodeExecHandler:
    """Normalize a bound or unbound owned opcode handler for table storage."""
    if isinstance(func, MethodType):
        return cast(OpcodeExecHandler, func.__func__)
    return cast(OpcodeExecHandler, func)


class InstrBase(ExecInstr, ParseInstr, EmuInstr):  # type: ignore[misc, unused-ignore] # dynamic frontend mixins
    """Provide shared byte-width opcode semantics for the x86 frontend runtime."""

    _base_opcode_template_instrfuncs: list[OpcodeExecHandler | None] | None = None
    _base_opcode_template_chk: list[int | InstrFlags] | None = None

    def __init__(self, emu: Emulator, instr: InstrData, mode32: bool) -> None:
        """Initialize shared opcode tables for one decoded-instruction runtime."""
        super().__init__(emu)
        super(ExecInstr, self).__init__(emu, instr, mode32)  # ParseInstr
        super(ParseInstr, self).__init__(emu, instr, mode32)  # EmuInstr
        self.emu = emu
        self.emu.active_instruction = self
        # Keep opcode tables in fixed-size arrays for fast indexed access.
        self.instrfuncs: list[OpcodeExecHandler | None]
        self.chk: list[int | InstrFlags]
        if not isinstance(self.instrfuncs, list) or len(self.instrfuncs) != MAX_OPCODE:
            self.instrfuncs = [None] * MAX_OPCODE
        if not isinstance(self.chk, list) or len(self.chk) != MAX_OPCODE:
            self.chk = [InstrFlags()] * MAX_OPCODE
        self.chsz_ad = False
        cls = type(self)
        base_funcs = cls._base_opcode_template_instrfuncs
        base_chk = cls._base_opcode_template_chk
        if base_funcs is not None and base_chk is not None:
            self.instrfuncs = base_funcs.copy()
            self.chk = base_chk.copy()
            return
        sf = self.set_funcflag

        sf(0x00, self.add_rm8_r8, CHK_MODRM)
        sf(0x02, self.add_r8_rm8, CHK_MODRM)
        sf(0x04, self.add_al_imm8, CHK_IMM8)
        sf(0x08, self.or_rm8_r8, CHK_MODRM)
        sf(0x0A, self.or_r8_rm8, CHK_MODRM)
        sf(0x0C, self.or_al_imm8, CHK_IMM8)
        sf(0x10, self.adc_rm8_r8, CHK_MODRM)
        sf(0x12, self.adc_r8_rm8, CHK_MODRM)
        sf(0x20, self.and_rm8_r8, CHK_MODRM)
        sf(0x22, self.and_r8_rm8, CHK_MODRM)
        sf(0x24, self.and_al_imm8, CHK_IMM8)
        sf(0x27, self.daa, 0)
        sf(0x28, self.sub_rm8_r8, CHK_MODRM)
        sf(0x2A, self.sub_r8_rm8, CHK_MODRM)
        sf(0x2C, self.sub_al_imm8, CHK_IMM8)
        sf(0x2F, self.das, 0)
        sf(0x30, self.xor_rm8_r8, CHK_MODRM)
        sf(0x32, self.xor_r8_rm8, CHK_MODRM)
        sf(0x34, self.xor_al_imm8, CHK_IMM8)
        sf(0x37, self.aaa, 0)
        sf(0x38, self.cmp_rm8_r8, CHK_MODRM)
        sf(0x3A, self.cmp_r8_rm8, CHK_MODRM)
        sf(0x3C, self.cmp_al_imm8, CHK_IMM8)
        sf(0x3F, self.aas, 0)
        sf(0x70, self.jo_rel8, CHK_IMM8)
        sf(0x71, self.jno_rel8, CHK_IMM8)
        sf(0x72, self.jb_rel8, CHK_IMM8)
        sf(0x73, self.jnb_rel8, CHK_IMM8)
        sf(0x74, self.jz_rel8, CHK_IMM8)
        sf(0x75, self.jnz_rel8, CHK_IMM8)
        sf(0x76, self.jbe_rel8, CHK_IMM8)
        sf(0x77, self.ja_rel8, CHK_IMM8)
        sf(0x78, self.js_rel8, CHK_IMM8)
        sf(0x79, self.jns_rel8, CHK_IMM8)
        sf(0x7A, self.jp_rel8, CHK_IMM8)
        sf(0x7B, self.jnp_rel8, CHK_IMM8)
        sf(0x7C, self.jl_rel8, CHK_IMM8)
        sf(0x7D, self.jnl_rel8, CHK_IMM8)
        sf(0x7E, self.jle_rel8, CHK_IMM8)
        sf(0x7F, self.jnle_rel8, CHK_IMM8)
        sf(0x84, self.test_rm8_r8, CHK_MODRM)
        sf(0x86, self.xchg_r8_rm8, CHK_MODRM)
        sf(0x88, self.mov_rm8_r8, CHK_MODRM)
        sf(0x8A, self.mov_r8_rm8, CHK_MODRM)
        sf(0x8E, self.mov_sreg_rm16, CHK_MODRM)
        sf(0x90, self.nop, 0)
        sf(0x9B, self.wait, 0)
        sf(0x9E, self.sahf, 0)
        sf(0x9F, self.lahf, 0)
        sf(0xA0, self.mov_al_moffs8, CHK_MOFFS)
        sf(0xA2, self.mov_moffs8_al, CHK_MOFFS)
        sf(0xA8, self.test_al_imm8, CHK_IMM8)
        self._register_opcode_range(0xB0, 0xB7, self.mov_r8_imm8, CHK_IMM8)
        sf(0xC6, self.mov_rm8_imm8, CHK_MODRM | CHK_IMM8)
        sf(0xCA, self.retf_imm16, CHK_IMM16)
        sf(0xCB, self.retf, 0)
        sf(0xCC, self.int3, 0)
        sf(0xCD, self.int_imm8, CHK_IMM8)
        sf(0xCF, self.iret, 0)
        sf(0xD0, self.code_d0_d2, CHK_MODRM)
        sf(0xD2, self.code_d0_d2, CHK_MODRM)
        sf(0xD4, self.aam, CHK_IMM8)
        sf(0xD5, self.aad, CHK_IMM8)
        sf(0xD6, self.salc, 0)
        sf(0xD8, self.esc, CHK_MODRM)
        sf(0xD9, self.esc, CHK_MODRM)
        sf(0xDA, self.esc, CHK_MODRM)
        sf(0xDB, self.esc, CHK_MODRM)
        sf(0xDC, self.esc, CHK_MODRM)
        sf(0xDD, self.esc, CHK_MODRM)
        sf(0xDE, self.esc, CHK_MODRM)
        sf(0xDF, self.esc, CHK_MODRM)
        sf(0xE4, self.in_al_imm8, CHK_IMM8)
        sf(0xE6, self.out_imm8_al, CHK_IMM8)
        sf(0xEB, self.jmp, CHK_IMM8)
        sf(0xEC, self.in_al_dx, 0)
        sf(0xEE, self.out_dx_al, 0)
        sf(0xF5, self.cmc, 0)
        sf(0xF8, self.clc, 0)
        sf(0xF9, self.stc, 0)
        sf(0xFA, self.cli, 0)
        sf(0xFB, self.sti, 0)
        sf(0xFC, self.cld, 0)
        sf(0xFD, self.std, 0)
        sf(0xF4, self.hlt, 0)

        sf(0x0F20, self.mov_r32_crn, CHK_MODRM)
        sf(0x0F22, self.mov_crn_r32, CHK_MODRM)
        sf(0x0F90, self.seto_rm8, CHK_MODRM)
        sf(0x0F91, self.setno_rm8, CHK_MODRM)
        sf(0x0F92, self.setb_rm8, CHK_MODRM)
        sf(0x0F93, self.setnb_rm8, CHK_MODRM)
        sf(0x0F94, self.setz_rm8, CHK_MODRM)
        sf(0x0F95, self.setnz_rm8, CHK_MODRM)
        sf(0x0F96, self.setbe_rm8, CHK_MODRM)
        sf(0x0F97, self.seta_rm8, CHK_MODRM)
        sf(0x0F98, self.sets_rm8, CHK_MODRM)
        sf(0x0F99, self.setns_rm8, CHK_MODRM)
        sf(0x0F9A, self.setp_rm8, CHK_MODRM)
        sf(0x0F9B, self.setnp_rm8, CHK_MODRM)
        sf(0x0F9C, self.setl_rm8, CHK_MODRM)
        sf(0x0F9D, self.setnl_rm8, CHK_MODRM)
        sf(0x0F9E, self.setle_rm8, CHK_MODRM)
        sf(0x0F9F, self.setnle_rm8, CHK_MODRM)

        sf(0x80, self.code_80, CHK_MODRM | CHK_IMM8)
        sf(0x82, self.code_82, CHK_MODRM | CHK_IMM8)
        sf(0xC0, self.code_c0, CHK_MODRM | CHK_IMM8)
        sf(0xF6, self.code_f6, CHK_MODRM)
        sf(0xFE, self.code_fe, CHK_MODRM)
        cls._base_opcode_template_instrfuncs = self.instrfuncs.copy()
        cls._base_opcode_template_chk = self.chk.copy()

    def _ite_value(self, cond: VexExpr, when_true: VexExpr, when_false: VexExpr) -> VexExpr:
        lifter_instruction = self.emu.lifter_instruction
        if lifter_instruction is None:
            raise RuntimeError("conditional VEX values require an active lifter instruction")
        expr = lifter_instruction.irsb_c.ite(
            cond.cast_to(Type.int_1).rdt,
            when_true.rdt,
            when_false.rdt,
        )
        return self.emu._vv(expr)

    def _active_stack_emulator(self) -> StackEmulator:
        """Return the runtime stack surface after checking active lift state."""
        if self.emu.irsb is None or self.emu.lifter_instruction is None:
            raise RuntimeError("stack control-flow effects require an active lifter instruction")
        return cast(StackEmulator, self.emu)

    def _active_string_emulator(self) -> StringEmulator:
        """Return the string-helper surface after checking active lift state."""
        if self.emu.lifter_instruction is None:
            raise RuntimeError("string instruction effects require an active lifter instruction")
        return cast(StringEmulator, self.emu)

    def _dispatch_modrm_reg(
        self,
        handlers: Sequence[BoundOpcodeHandler | None],
        opcode: str,
        on_missing: Callable[[int], None] | None = None,
    ) -> None:
        reg = self.instr.modrm.reg
        if 0 <= reg < len(handlers):
            handler = handlers[reg]
            if handler is not None:
                handler()
                return
        if on_missing is not None:
            on_missing(reg)
            return
        raise RuntimeError(f"not implemented: {opcode} /{reg}")

    def _register_opcode_range(
        self,
        start: int,
        end: int,
        func: OpcodeRegistrationHandler,
        flags: int,
    ) -> None:
        instrfuncs = self.instrfuncs
        chk = self.chk
        handler = _unbound_opcode_handler(func)
        for opcode in range(start, end + 1):
            instrfuncs[opcode] = handler
            chk[opcode] = flags

    def code_d0_d2(self) -> None:
        """Handle the x86 Group-2 byte shifts/rotates used by opcodes 0xD0 and 0xD2.

        Keeping this as an explicit dispatch table makes it easier to audit when
        a real sample trips over one of the rarely used `/digit` encodings.
        """
        reg = self.instr.modrm.reg
        handler = GROUP2_BYTE_SHIFT_ROTATE_HANDLERS.get(reg)
        if handler is None:
            raise RuntimeError(f"not implemented: 0xd0_d2 /{reg}")
        handler(self)

    def set_funcflag(self, opcode: int, func: OpcodeRegistrationHandler, flags: int) -> None:
        """Register one decoded opcode handler and its operand-presence flags."""
        if opcode >> 8 == 0x0F:
            opcode = (opcode & 0xFF) | 0x0100
        assert opcode < 0x200
        self.instrfuncs[opcode] = _unbound_opcode_handler(func)
        self.chk[opcode] = flags

    def imm8_value(self) -> VexExpr:
        """Return the immediate byte as a typed frontend runtime value."""
        return self.emu.constant(self.instr.imm8, Type.int_8)

    def add_rm8_r8(self) -> None:
        """Execute decoded ``ADD_RM8_R8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_rm8, self.get_r8, self.set_rm8, self.emu.update_eflags_add, lambda lhs, rhs: lhs + rhs
        )

    def adc_rm8_r8(self) -> None:
        """Execute decoded ``ADC_RM8_R8`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_rm8,
            self.get_r8,
            self.set_rm8,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            8,
        )

    def add_r8_rm8(self) -> None:
        """Execute decoded ``ADD_R8_RM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_r8, self.get_rm8, self.set_r8, self.emu.update_eflags_add, lambda lhs, rhs: lhs + rhs
        )

    def adc_r8_rm8(self) -> None:
        """Execute decoded ``ADC_R8_RM8`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_r8,
            self.get_rm8,
            self.set_r8,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            8,
        )

    def adc_al_imm8(self) -> None:
        """Execute decoded ``ADC_AL_IMM8`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            lambda: _vex_expr(self.emu.get_gpreg(reg8_t.AL)),
            self.imm8_value,
            lambda value: self.emu.set_gpreg(reg8_t.AL, value),
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            8,
        )

    def add_al_imm8(self) -> None:
        """Execute decoded ``ADD_AL_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            lambda: _vex_expr(self.emu.get_gpreg(reg8_t.AL)),
            self.imm8_value,
            lambda value: self.emu.set_gpreg(reg8_t.AL, value),
            self.emu.update_eflags_add,
            lambda lhs, rhs: lhs + rhs,
        )

    def or_rm8_r8(self) -> None:
        """Execute decoded ``OR_RM8_R8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_rm8, self.get_r8, self.set_rm8, self.emu.update_eflags_or, lambda lhs, rhs: lhs | rhs
        )

    def or_r8_rm8(self) -> None:
        """Execute decoded ``OR_R8_RM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_r8, self.get_rm8, self.set_r8, self.emu.update_eflags_or, lambda lhs, rhs: lhs | rhs
        )

    def or_al_imm8(self) -> None:
        """Execute decoded ``OR_AL_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            lambda: _vex_expr(self.emu.get_gpreg(reg8_t.AL)),
            self.imm8_value,
            lambda value: self.emu.set_gpreg(reg8_t.AL, value),
            self.emu.update_eflags_or,
            lambda lhs, rhs: lhs | rhs,
        )

    def and_rm8_r8(self) -> None:
        """Execute decoded ``AND_RM8_R8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_rm8, self.get_r8, self.set_rm8, self.emu.update_eflags_and, lambda lhs, rhs: lhs & rhs
        )

    def and_r8_rm8(self) -> None:
        """Execute decoded ``AND_R8_RM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_r8, self.get_rm8, self.set_r8, self.emu.update_eflags_and, lambda lhs, rhs: lhs & rhs
        )

    def and_al_imm8(self) -> None:
        """Execute decoded ``AND_AL_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            lambda: _vex_expr(self.emu.get_gpreg(reg8_t.AL)),
            self.imm8_value,
            lambda value: self.emu.set_gpreg(reg8_t.AL, value),
            self.emu.update_eflags_and,
            lambda lhs, rhs: lhs & rhs,
        )

    def sub_rm8_r8(self) -> None:
        """Execute decoded ``SUB_RM8_R8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_rm8, self.get_r8, self.set_rm8, self.emu.update_eflags_sub, lambda lhs, rhs: lhs - rhs
        )

    def sub_r8_rm8(self) -> None:
        """Execute decoded ``SUB_R8_RM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_r8, self.get_rm8, self.set_r8, self.emu.update_eflags_sub, lambda lhs, rhs: lhs - rhs
        )

    def sub_al_imm8(self) -> None:
        """Execute decoded ``SUB_AL_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            lambda: _vex_expr(self.emu.get_gpreg(reg8_t.AL)),
            self.imm8_value,
            lambda value: self.emu.set_gpreg(reg8_t.AL, value),
            self.emu.update_eflags_sub,
            lambda lhs, rhs: lhs - rhs,
        )

    def sbb_rm8_r8(self) -> None:
        """Execute decoded ``SBB_RM8_R8`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_rm8,
            self.get_r8,
            self.set_rm8,
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            8,
        )

    def sbb_r8_rm8(self) -> None:
        """Execute decoded ``SBB_R8_RM8`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_r8,
            self.get_rm8,
            self.set_r8,
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            8,
        )

    def sbb_al_imm8(self) -> None:
        """Execute decoded ``SBB_AL_IMM8`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            lambda: _vex_expr(self.emu.get_gpreg(reg8_t.AL)),
            self.imm8_value,
            lambda value: self.emu.set_gpreg(reg8_t.AL, value),
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            8,
        )

    def xor_rm8_r8(self) -> None:
        """Execute decoded ``XOR_RM8_R8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_rm8, self.get_r8, self.set_rm8, self.emu.update_eflags_xor, lambda lhs, rhs: lhs ^ rhs
        )

    def xor_r8_rm8(self) -> None:
        """Execute decoded ``XOR_R8_RM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu, self.get_r8, self.get_rm8, self.set_r8, self.emu.update_eflags_xor, lambda lhs, rhs: lhs ^ rhs
        )

    def xor_al_imm8(self) -> None:
        """Execute decoded ``XOR_AL_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            lambda: _vex_expr(self.emu.get_gpreg(reg8_t.AL)),
            self.imm8_value,
            lambda value: self.emu.set_gpreg(reg8_t.AL, value),
            self.emu.update_eflags_xor,
            lambda lhs, rhs: lhs ^ rhs,
        )

    def cmp_rm8_r8(self) -> None:
        """Execute decoded ``CMP_RM8_R8`` semantics through frontend emulator effects."""
        compare_operation(self.get_rm8, self.get_r8, self.emu.update_eflags_sub)

    def cmp_r8_rm8(self) -> None:
        """Execute decoded ``CMP_R8_RM8`` semantics through frontend emulator effects."""
        compare_operation(self.get_r8, self.get_rm8, self.emu.update_eflags_sub)

    def cmp_al_imm8(self) -> None:
        """Execute decoded ``CMP_AL_IMM8`` semantics through frontend emulator effects."""
        compare_operation(
            lambda: _vex_expr(self.emu.get_gpreg(reg8_t.AL)),
            self.imm8_value,
            self.emu.update_eflags_sub,
        )

    def jo_rel8(self) -> None:
        """Emit the decoded ``JO`` short conditional branch."""
        branch_rel8(self._active_stack_emulator(), self.emu.is_overflow(), self.instr.imm8, self.instr.size)

    def jno_rel8(self) -> None:
        """Emit the decoded ``JNO`` short conditional branch."""
        branch_rel8(self._active_stack_emulator(), ~self.emu.is_overflow(), self.instr.imm8, self.instr.size)

    def jb_rel8(self) -> None:
        """Emit the decoded ``JB`` short conditional branch."""
        branch_rel8(self._active_stack_emulator(), self.emu.is_carry(), self.instr.imm8, self.instr.size)

    def jnb_rel8(self) -> None:  # jae
        """Emit the decoded ``JNB`` short conditional branch."""
        branch_rel8(self._active_stack_emulator(), ~self.emu.is_carry(), self.instr.imm8, self.instr.size)

    def jz_rel8(self) -> None:
        """Emit the decoded ``JZ`` short conditional branch."""
        branch_rel8(self._active_stack_emulator(), self.emu.is_zero(), self.instr.imm8, self.instr.size)

    def jnz_rel8(self) -> None:
        """Emit the decoded ``JNZ`` short conditional branch."""
        branch_rel8(self._active_stack_emulator(), ~self.emu.is_zero(), self.instr.imm8, self.instr.size)

    def jbe_rel8(self) -> None:
        """Emit the decoded ``JBE`` short conditional branch."""
        branch_rel8(
            self._active_stack_emulator(),
            self.emu.is_carry() | self.emu.is_zero(),
            self.instr.imm8,
            self.instr.size,
        )

    def ja_rel8(self) -> None:
        """Emit the decoded ``JA`` short conditional branch."""
        branch_rel8(
            self._active_stack_emulator(),
            ~(self.emu.is_carry() | self.emu.is_zero()),
            self.instr.imm8,
            self.instr.size,
        )

    def js_rel8(self) -> None:
        """Emit the decoded ``JS`` short conditional branch."""
        branch_rel8(self._active_stack_emulator(), self.emu.is_sign(), self.instr.imm8, self.instr.size)

    def jns_rel8(self) -> None:
        """Emit the decoded ``JNS`` short conditional branch."""
        branch_rel8(self._active_stack_emulator(), ~self.emu.is_sign(), self.instr.imm8, self.instr.size)

    def jp_rel8(self) -> None:
        """Emit the decoded ``JP`` short conditional branch."""
        branch_rel8(self._active_stack_emulator(), self.emu.is_parity(), self.instr.imm8, self.instr.size)

    def jnp_rel8(self) -> None:
        """Emit the decoded ``JNP`` short conditional branch."""
        branch_rel8(self._active_stack_emulator(), ~self.emu.is_parity(), self.instr.imm8, self.instr.size)

    def jl_rel8(self) -> None:
        """Emit the decoded ``JL`` short conditional branch."""
        branch_rel8(
            self._active_stack_emulator(),
            self.emu.is_sign() != self.emu.is_overflow(),
            self.instr.imm8,
            self.instr.size,
        )

    def jnl_rel8(self) -> None:  # jge
        """Emit the decoded ``JNL`` short conditional branch."""
        branch_rel8(
            self._active_stack_emulator(),
            ~(self.emu.is_sign() != self.emu.is_overflow()),
            self.instr.imm8,
            self.instr.size,
        )

    def jle_rel8(self) -> None:
        """Emit the decoded ``JLE`` short conditional branch."""
        branch_rel8(
            self._active_stack_emulator(),
            self.emu.is_zero() | (self.emu.is_sign() != self.emu.is_overflow()),
            self.instr.imm8,
            self.instr.size,
        )

    def jnle_rel8(self) -> None:
        """Emit the decoded ``JNLE`` short conditional branch."""
        branch_rel8(
            self._active_stack_emulator(),
            ~self.emu.is_zero() & (self.emu.is_sign() == self.emu.is_overflow()),
            self.instr.imm8,
            self.instr.size,
        )

    def test_rm8_r8(self) -> None:
        """Execute decoded ``TEST_RM8_R8`` semantics through frontend emulator effects."""
        compare_operation(self.get_rm8, self.get_r8, self.emu.update_eflags_and)

    def xchg_r8_rm8(self) -> None:
        """Execute decoded ``XCHG_R8_RM8`` semantics through frontend emulator effects."""
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        if self.instr.modrm.mod == 3:
            self.set_r8(rm8)
            self.set_rm8(r8)
            return

        operand = self._resolved_rm_operand(8)
        self.set_r8(rm8)
        store_resolved_operand(self.emu, operand, r8)

    def mov_rm8_r8(self) -> None:
        """Execute decoded ``MOV_RM8_R8`` semantics through frontend emulator effects."""
        r8 = self.get_r8()
        self.set_rm8(r8)

    def mov_r8_rm8(self) -> None:
        """Execute decoded ``MOV_R8_RM8`` semantics through frontend emulator effects."""
        rm8 = self.get_rm8()
        self.set_r8(rm8)

    def mov_sreg_rm16(self) -> None:
        """Execute decoded ``MOV_SREG_RM16`` semantics through frontend emulator effects."""
        rm16 = self.get_rm16()
        self.set_sreg(rm16)

    def nop(self) -> None:
        """Execute decoded ``NOP`` semantics through frontend emulator effects."""

    def wait(self) -> None:
        """Execute decoded ``WAIT`` semantics through frontend emulator effects."""
        # WAIT only stalls until TEST is asserted; architecturally it is a no-op
        # for the real-mode concrete verifier we are using here.
        self.nop()

    def lahf(self) -> None:
        """Execute decoded ``LAHF`` semantics through frontend emulator effects."""
        flags = _vex_expr(self.emu.get_gpreg(reg16_t.FLAGS)).cast_to(Type.int_8)
        flags_low = flags & self.emu.constant(0xD5, Type.int_8)
        self.emu.set_gpreg(reg8_t.AH, flags_low | self.emu.constant(0x02, Type.int_8))

    def lohf(self) -> None:
        """Execute decoded ``LOHF`` semantics through frontend emulator effects."""
        self.lahf()

    def sahf(self) -> None:
        """Execute decoded ``SAHF`` semantics through frontend emulator effects."""
        flags = _vex_expr(self.emu.get_gpreg(reg16_t.FLAGS))
        ah = _vex_expr(self.emu.get_gpreg(reg8_t.AH)).cast_to(Type.int_16)
        preserved = flags & self.emu.constant(0xFF2A, Type.int_16)
        new_bits = ah & self.emu.constant(0x00D5, Type.int_16)
        self.emu.set_gpreg(reg16_t.FLAGS, preserved | new_bits | self.emu.constant(0x0002, Type.int_16))

    def mov_al_moffs8(self) -> None:
        """Execute decoded ``MOV_AL_MOFFS8`` semantics through frontend emulator effects."""
        self.emu.set_gpreg(reg8_t.AL, self.get_moffs8())

    def mov_moffs8_al(self) -> None:
        """Execute decoded ``MOV_MOFFS8_AL`` semantics through frontend emulator effects."""
        self.set_moffs8(_vex_expr(self.emu.get_gpreg(reg8_t.AL)))

    def test_al_imm8(self) -> None:
        """Execute decoded ``TEST_AL_IMM8`` semantics through frontend emulator effects."""
        compare_operation(
            lambda: _vex_expr(self.emu.get_gpreg(reg8_t.AL)), lambda: self.instr.imm8, self.emu.update_eflags_and
        )

    def salc(self) -> None:
        """Execute decoded ``SALC`` semantics through frontend emulator effects."""
        value = self._ite_value(
            self.emu.is_carry().cast_to(Type.int_1),
            self.emu.constant(0xFF, Type.int_8),
            self.emu.constant(0x00, Type.int_8),
        )
        self.emu.set_gpreg(reg8_t.AL, value)

    def esc(self) -> None:
        """Execute decoded ``ESC`` semantics through frontend emulator effects."""
        if self.instr.modrm.mod != 3:
            operand = self._resolved_rm_operand(8)
            load_resolved_operand(self.emu, operand)

    def mov_r8_imm8(self) -> None:
        """Execute decoded ``MOV_R8_IMM8`` semantics through frontend emulator effects."""
        reg = self.instr.opcode & 0b111
        self.emu.set_gpreg(coerce_reg8_t(reg), self.instr.imm8)

    def mov_rm8_imm8(self) -> None:
        """Execute decoded ``MOV_RM8_IMM8`` semantics through frontend emulator effects."""
        self.set_rm8(self.emu.constant(self.instr.imm8, Type.int_8))

    def _update_adjust_flags(
        self,
        result: VexExpr,
        *,
        af: VexExpr | None = None,
        cf: VexExpr | None = None,
        of: VexExpr | None = None,
    ) -> None:
        flags = _vex_expr(self.emu.get_gpreg(reg16_t.FLAGS))
        low = result.cast_to(Type.int_8)
        if af is not None:
            flags = self.emu.set_flag(flags, 4, af)
        if cf is not None:
            flags = self.emu.set_carry(flags, cf)
        if of is not None:
            flags = self.emu.set_overflow(flags, of)
        flags = self.emu.set_parity(flags, self.emu.chk_parity(low))
        flags = self.emu.set_zero(flags, low == self.emu.constant(0, Type.int_8))
        flags = self.emu.set_sign(flags, low[7])
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def daa(self) -> None:
        """Execute decoded ``DAA`` semantics through frontend emulator effects."""
        al = _vex_expr(self.emu.get_gpreg(reg8_t.AL))
        af = self.emu.get_flag(4)
        cf = self.emu.is_carry()
        low_adjust = ((al & self.emu.constant(0x0F, Type.int_8)) > self.emu.constant(9, Type.int_8)).cast_to(
            Type.int_1
        ) | af
        high_adjust = (al > self.emu.constant(0x99, Type.int_8)).cast_to(Type.int_1) | cf

        overflow = self._ite_value(
            cf.cast_to(Type.int_1),
            ((al >= self.emu.constant(0x1A, Type.int_8)) & (al <= self.emu.constant(0x7F, Type.int_8))).cast_to(
                Type.int_1
            ),
            ((al >= self.emu.constant(0x7A, Type.int_8)) & (al <= self.emu.constant(0x7F, Type.int_8))).cast_to(
                Type.int_1
            ),
        )

        result = al
        low_added = result + self.emu.constant(0x06, Type.int_8)
        result = self._ite_value(low_adjust.cast_to(Type.int_1), low_added, result)

        high_added = result + self.emu.constant(0x60, Type.int_8)
        result = self._ite_value(high_adjust.cast_to(Type.int_1), high_added, result)
        self.emu.set_gpreg(reg8_t.AL, result)
        self._update_adjust_flags(
            result,
            af=low_adjust.cast_to(Type.int_1),
            cf=high_adjust.cast_to(Type.int_1),
            of=overflow,
        )

    def das(self) -> None:
        """Execute decoded ``DAS`` semantics through frontend emulator effects."""
        al = _vex_expr(self.emu.get_gpreg(reg8_t.AL))
        af = self.emu.get_flag(4)
        cf = self.emu.is_carry()
        old_sign = al[7]

        low_adjust = ((al & self.emu.constant(0x0F, Type.int_8)) > self.emu.constant(9, Type.int_8)).cast_to(
            Type.int_1
        ) | af
        high_adjust = (al > self.emu.constant(0x99, Type.int_8)).cast_to(Type.int_1) | cf

        cf_after_low = self._ite_value(
            high_adjust,
            self.emu.constant(1, Type.int_1),
            (al <= self.emu.constant(0x05, Type.int_8)).cast_to(Type.int_1),
        )
        cf_final = self._ite_value(
            low_adjust.cast_to(Type.int_1),
            cf_after_low,
            high_adjust.cast_to(Type.int_1),
        )

        result = al
        result = self._ite_value(high_adjust, result - self.emu.constant(0x60, Type.int_8), result)
        result = self._ite_value(low_adjust, result - self.emu.constant(0x06, Type.int_8), result)
        self.emu.set_gpreg(reg8_t.AL, result)
        overflow = old_sign.cast_to(Type.int_1) & (result[7].cast_to(Type.int_1) ^ self.emu.constant(1, Type.int_1))
        self._update_adjust_flags(
            result,
            af=low_adjust.cast_to(Type.int_1),
            cf=cf_final,
            of=overflow,
        )

    def aaa(self) -> None:
        """Execute decoded ``AAA`` semantics through frontend emulator effects."""
        ax = _vex_expr(self.emu.get_gpreg(reg16_t.AX))
        al = _vex_expr(self.emu.get_gpreg(reg8_t.AL))
        af = self.emu.get_flag(4)
        low_adjust = ((al & self.emu.constant(0x0F, Type.int_8)) > self.emu.constant(9, Type.int_8)).cast_to(Type.int_1)
        adjust = low_adjust | af

        result_ax = self._ite_value(adjust, ax + self.emu.constant(0x0106, Type.int_16), ax)
        self.emu.set_gpreg(reg16_t.AX, result_ax)
        new_al = self._ite_value(adjust, al + self.emu.constant(6, Type.int_8), al)
        masked_al = new_al & self.emu.constant(0x0F, Type.int_8)
        self.emu.set_gpreg(reg8_t.AL, masked_al)

        overflow = ((al >= self.emu.constant(0x7A, Type.int_8)) & (al <= self.emu.constant(0x7F, Type.int_8))).cast_to(
            Type.int_1
        )
        sign = ((al >= self.emu.constant(0x7A, Type.int_8)) & (al <= self.emu.constant(0xF9, Type.int_8))).cast_to(
            Type.int_1
        )
        zero = (new_al == self.emu.constant(0, Type.int_8)).cast_to(Type.int_1)
        flags = _vex_expr(self.emu.get_gpreg(reg16_t.FLAGS))
        flags = self.emu.set_flag(flags, 4, adjust)
        flags = self.emu.set_carry(flags, adjust)
        flags = self.emu.set_overflow(flags, overflow)
        flags = self.emu.set_sign(flags, sign)
        flags = self.emu.set_zero(flags, zero)
        flags = self.emu.set_parity(flags, self.emu.chk_parity(new_al))
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def aas(self) -> None:
        """Execute decoded ``AAS`` semantics through frontend emulator effects."""
        ax = _vex_expr(self.emu.get_gpreg(reg16_t.AX))
        al = _vex_expr(self.emu.get_gpreg(reg8_t.AL))
        af = self.emu.get_flag(4)
        low_adjust = ((al & self.emu.constant(0x0F, Type.int_8)) > self.emu.constant(9, Type.int_8)).cast_to(Type.int_1)
        adjust = low_adjust | af

        result_ax = self._ite_value(adjust, ax - self.emu.constant(0x0106, Type.int_16), ax)
        self.emu.set_gpreg(reg16_t.AX, result_ax)
        pre_mask_al = result_ax.cast_to(Type.int_8)
        masked_al = pre_mask_al & self.emu.constant(0x0F, Type.int_8)
        self.emu.set_gpreg(reg8_t.AL, masked_al)

        overflow = self._ite_value(
            low_adjust,
            self.emu.constant(0, Type.int_1),
            self._ite_value(
                af,
                ((al >= self.emu.constant(0x80, Type.int_8)) & (al <= self.emu.constant(0x85, Type.int_8))).cast_to(
                    Type.int_1
                ),
                self.emu.constant(0, Type.int_1),
            ),
        )
        sign = self._ite_value(
            low_adjust,
            (al > self.emu.constant(0x85, Type.int_8)).cast_to(Type.int_1),
            self._ite_value(
                af,
                ((al < self.emu.constant(0x06, Type.int_8)) | (al > self.emu.constant(0x85, Type.int_8))).cast_to(
                    Type.int_1
                ),
                (al >= self.emu.constant(0x80, Type.int_8)).cast_to(Type.int_1),
            ),
        )
        flags = _vex_expr(self.emu.get_gpreg(reg16_t.FLAGS))
        flags = self.emu.set_flag(flags, 4, adjust)
        flags = self.emu.set_carry(flags, adjust)
        flags = self.emu.set_overflow(flags, overflow)
        flags = self.emu.set_sign(flags, sign)
        flags = self.emu.set_zero(flags, (pre_mask_al == self.emu.constant(0, Type.int_8)).cast_to(Type.int_1))
        flags = self.emu.set_parity(flags, self.emu.chk_parity(pre_mask_al))
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def aam(self) -> None:
        """Retain AAM's zero-base divide error before changing AX or flags."""
        base = _vex_expr(self.emu.constant(self.instr.imm8 & 0xFF, Type.int_8))
        if self.instr.imm8 & 0xFF == 0:
            self._divide_error_if(base == self.emu.constant(0, Type.int_8))
            return
        al = _vex_expr(self.emu.get_gpreg(reg8_t.AL))
        ah = al // base
        new_al = al % base
        self.emu.set_gpreg(reg8_t.AH, ah)
        self.emu.set_gpreg(reg8_t.AL, new_al)
        self._update_adjust_flags(
            new_al,
            af=self.emu.constant(0, Type.int_1),
            cf=self.emu.constant(0, Type.int_1),
            of=self.emu.constant(0, Type.int_1),
        )

    def aad(self) -> None:
        """Execute decoded ``AAD`` semantics through frontend emulator effects."""
        base = _vex_expr(self.emu.constant(self.instr.imm8 & 0xFF, Type.int_8))
        ah = _vex_expr(self.emu.get_gpreg(reg8_t.AH))
        al = _vex_expr(self.emu.get_gpreg(reg8_t.AL))
        ax = ah.cast_to(Type.int_16) * base.cast_to(Type.int_16) + al.cast_to(Type.int_16)
        new_al = ax.cast_to(Type.int_8)
        self.emu.set_gpreg(reg8_t.AL, new_al)
        self.emu.set_gpreg(reg8_t.AH, self.emu.constant(0, Type.int_8))
        self._update_adjust_flags(
            new_al,
            af=self.emu.constant(0, Type.int_1),
            cf=self.emu.constant(0, Type.int_1),
            of=self.emu.constant(0, Type.int_1),
        )

    def retf_imm16(self) -> None:
        """Execute decoded ``RETF_IMM16`` semantics through frontend emulator effects."""
        return_far16(self._active_stack_emulator(), self.instr.imm16)

    def retf(self, _instr: dict[str, object] | None = None) -> None:
        """Execute decoded ``RETF`` semantics through frontend emulator effects."""
        return_far16(self._active_stack_emulator())

    def int3(self) -> None:
        """Execute decoded ``INT3`` semantics through frontend emulator effects."""
        self.instr.imm8 = 3
        self.int_imm8()

    def int_imm8(self) -> None:
        """Execute decoded ``INT_IMM8`` semantics through frontend emulator effects."""
        vector = self.instr.imm8 & 0xFF
        if self.instr.msvc_x87_escape and msvc_x87_escape_opcode_8616(vector) is not None:
            self.esc()
            return
        if is_msvc_x87_emulation_interrupt_8616(vector) and vector == 0x3D:
            self.wait()
            return
        next_ip = _vex_expr(self.emu.get_ip()) + self.emu.constant(self.instr.size, Type.int_16)
        lifter_instruction = self.emu.lifter_instruction
        if lifter_instruction is None:
            raise RuntimeError("interrupt lifting requires an active lifter instruction")
        lifter_instruction.put(next_ip.cast_to(Type.int_32), "ip_at_syscall")
        # Model real-mode interrupts as synthetic call targets so CFG/decompilation
        # can treat them like normal helper functions.
        self.emu.set_gpreg(reg16_t.IP, self.emu.constant(vector, Type.int_16))
        lifter_instruction.jump(None, interrupt_core_addr_8616(vector), JumpKind.Call)

    def iret(self, _instr: dict[str, object] | None = None) -> None:
        """Return through the operand-size-selected real-mode interrupt frame."""
        if self.instr.operand_bits == 32:
            from .stack_helpers import return_interrupt32

            return_interrupt32(self._active_stack_emulator())
            return
        return_interrupt16(self._active_stack_emulator())

    def in_al_imm8(self) -> None:
        """Use the unsigned 8-bit immediate port, independent of signed decoding."""
        self.emu.set_gpreg(reg8_t.AL, self.emu.in_io8(self.instr.imm8 & 0xFF))

    def out_imm8_al(self) -> None:
        """Use the unsigned 8-bit immediate port, independent of signed decoding."""
        al = _vex_expr(self.emu.get_gpreg(reg8_t.AL))
        self.emu.out_io8(self.instr.imm8 & 0xFF, al)

    def jmp(self) -> None:
        """Execute decoded ``JMP`` semantics through frontend emulator effects."""
        branch_rel8(self._active_stack_emulator(), True, self.instr.imm8, self.instr.size)

    def in_al_dx(self) -> None:
        """Execute decoded ``IN_AL_DX`` semantics through frontend emulator effects."""
        dx = _vex_expr(self.emu.get_gpreg(reg16_t.DX))
        self.emu.set_gpreg(reg8_t.AL, self.emu.in_io8(dx))

    def out_dx_al(self) -> None:
        """Execute decoded ``OUT_DX_AL`` semantics through frontend emulator effects."""
        dx = _vex_expr(self.emu.get_gpreg(reg16_t.DX))
        al = _vex_expr(self.emu.get_gpreg(reg8_t.AL))
        self.emu.out_io8(dx, al)

    def cmc(self) -> None:
        """Execute decoded ``CMC`` semantics through frontend emulator effects."""
        flags = _vex_expr(self.emu.get_gpreg(reg16_t.FLAGS))
        self.emu.set_gpreg(reg16_t.FLAGS, flags ^ self.emu.constant(0x0001, Type.int_16))

    def clc(self) -> None:
        """Execute decoded ``CLC`` semantics through frontend emulator effects."""
        flags = _vex_expr(self.emu.get_gpreg(reg16_t.FLAGS))
        self.emu.set_gpreg(reg16_t.FLAGS, flags & self.emu.constant(0xFFFE, Type.int_16))

    def stc(self) -> None:
        """Execute decoded ``STC`` semantics through frontend emulator effects."""
        flags = _vex_expr(self.emu.get_gpreg(reg16_t.FLAGS))
        self.emu.set_gpreg(reg16_t.FLAGS, flags | self.emu.constant(0x0001, Type.int_16))

    def cli(self) -> None:
        """Execute decoded ``CLI`` semantics through frontend emulator effects."""
        self.emu.set_interrupt(False)

    def sti(self) -> None:
        """Execute decoded ``STI`` semantics through frontend emulator effects."""
        self.emu.set_interrupt(True)

    def cld(self) -> None:
        """Execute decoded ``CLD`` semantics through frontend emulator effects."""
        self.emu.set_direction(False)

    def std(self) -> None:
        """Execute decoded ``STD`` semantics through frontend emulator effects."""
        self.emu.set_direction(True)

    def hlt(self) -> None:
        """Execute decoded ``HLT`` semantics through frontend emulator effects."""
        if not self.emu.chk_ring(0):
            raise Exception(EXP_GP)
        self.emu.do_halt(True)

    def ltr_rm16(self) -> None:
        """Execute decoded ``LTR_RM16`` semantics through frontend emulator effects."""
        if not self.emu.chk_ring(0):
            raise Exception(EXP_GP)
        rm16 = self.get_rm16()
        if not isinstance(rm16, int):
            raise TypeError("LTR requires a concrete selector")
        self.set_tr(rm16)

    def mov_r32_crn(self) -> None:
        """Execute decoded ``MOV_R32_CRN`` semantics through frontend emulator effects."""
        crn = self.get_crn()
        self.emu.set_gpreg(coerce_reg32_t(self.instr.modrm.rm), crn)

    def mov_crn_r32(self) -> None:
        """Execute decoded ``MOV_CRN_R32`` semantics through frontend emulator effects."""
        if not self.emu.chk_ring(0):
            raise Exception(EXP_GP)
        r32 = self.emu.get_gpreg(coerce_reg32_t(self.instr.modrm.rm))
        if not isinstance(r32, int):
            raise TypeError("MOV to a control register requires a concrete value")
        self.set_crn(r32)

    def seto_rm8(self) -> None:
        """Store the decoded ``SETO`` condition result in the byte destination."""
        self.set_rm8(self.emu.is_overflow())

    def setno_rm8(self) -> None:
        """Store the decoded ``SETNO`` condition result in the byte destination."""
        self.set_rm8(self.emu.is_overflow() == self.emu.constant(0, Type.int_1))

    def setb_rm8(self) -> None:
        """Store the decoded ``SETB`` condition result in the byte destination."""
        self.set_rm8(self.emu.is_carry())

    def setnb_rm8(self) -> None:
        """Store the decoded ``SETNB`` condition result in the byte destination."""
        self.set_rm8(self.emu.is_carry() == self.emu.constant(0, Type.int_1))

    def setz_rm8(self) -> None:
        """Store the decoded ``SETZ`` condition result in the byte destination."""
        self.set_rm8(self.emu.is_zero())

    def setnz_rm8(self) -> None:
        """Store the decoded ``SETNZ`` condition result in the byte destination."""
        self.set_rm8(self.emu.is_zero() == self.emu.constant(0, Type.int_1))

    def setbe_rm8(self) -> None:
        """Store the decoded ``SETBE`` condition result in the byte destination."""
        self.set_rm8(_vex_expr(self.emu.is_carry()) | _vex_expr(self.emu.is_zero()))

    def seta_rm8(self) -> None:
        """Store the decoded ``SETA`` condition result in the byte destination."""
        carry_or_zero = _vex_expr(self.emu.is_carry()) | _vex_expr(self.emu.is_zero())
        self.set_rm8(carry_or_zero == self.emu.constant(0, Type.int_1))

    def sets_rm8(self) -> None:
        """Store the decoded ``SETS`` condition result in the byte destination."""
        self.set_rm8(self.emu.is_sign())

    def setns_rm8(self) -> None:
        """Store the decoded ``SETNS`` condition result in the byte destination."""
        self.set_rm8(self.emu.is_sign() == self.emu.constant(0, Type.int_1))

    def setp_rm8(self) -> None:
        """Store the decoded ``SETP`` condition result in the byte destination."""
        self.set_rm8(self.emu.is_parity())

    def setnp_rm8(self) -> None:
        """Store the decoded ``SETNP`` condition result in the byte destination."""
        self.set_rm8(self.emu.is_parity() == self.emu.constant(0, Type.int_1))

    def setl_rm8(self) -> None:
        """Store the decoded ``SETL`` condition result in the byte destination."""
        self.set_rm8(self.emu.is_sign() != self.emu.is_overflow())

    def setnl_rm8(self) -> None:
        """Store the decoded ``SETNL`` condition result in the byte destination."""
        self.set_rm8(self.emu.is_sign() == self.emu.is_overflow())

    def setle_rm8(self) -> None:
        """Store the decoded ``SETLE`` condition result in the byte destination."""
        signed_less = _vex_expr(self.emu.is_sign()) != _vex_expr(self.emu.is_overflow())
        self.set_rm8(_vex_expr(self.emu.is_zero()) | _vex_expr(signed_less))

    def setnle_rm8(self) -> None:
        """Store the decoded ``SETNLE`` condition result in the byte destination."""
        nonzero = self.emu.is_zero() == self.emu.constant(0, Type.int_1)
        signed_ge = _vex_expr(self.emu.is_sign()) == _vex_expr(self.emu.is_overflow())
        self.set_rm8(_vex_expr(nonzero) & _vex_expr(signed_ge))

    def code_80(self) -> None:
        """Dispatch opcode group ``80`` by its decoded ModR/M extension."""
        self._dispatch_modrm_reg(
            (
                self.add_rm8_imm8,
                self.or_rm8_imm8,
                self.adc_rm8_imm8,
                self.sbb_rm8_imm8,
                self.and_rm8_imm8,
                self.sub_rm8_imm8,
                self.xor_rm8_imm8,
                self.cmp_rm8_imm8,
            ),
            "0x80",
        )

    def code_82(self) -> None:
        """Dispatch opcode group ``82`` by its decoded ModR/M extension."""
        self.code_80()

    def code_c0(self) -> None:
        """Dispatch opcode group ``C0`` by its decoded ModR/M extension."""
        self._dispatch_modrm_reg(
            (
                self.rol_rm8_imm8,
                self.ror_rm8_imm8,
                self.rcl_rm8_imm8,
                self.rcr_rm8_imm8,
                self.shl_rm8_imm8,
                self.shr_rm8_imm8,
                self.sal_rm8_imm8,
                self.sar_rm8_imm8,
            ),
            "0xc0",
        )

    def code_f6(self) -> None:
        """Dispatch opcode group ``F6`` by its decoded ModR/M extension."""
        self._dispatch_modrm_reg(
            (
                self.test_rm8_imm8,
                self.test_rm8_imm8,
                self.not_rm8,
                self.neg_rm8,
                self.mul_ax_al_rm8,
                self.imul_ax_al_rm8,
                self.div_al_ah_rm8,
                self.idiv_al_ah_rm8,
            ),
            "0xf6",
        )

    def code_fe(self) -> None:
        """Dispatch opcode group ``FE`` by its decoded ModR/M extension."""
        self._dispatch_modrm_reg((self.inc_rm8, self.dec_rm8), "0xfe")

    def _group2_rm8_count(self) -> VexExpr:
        """Resolve the implicit shift/rotate count for opcodes 0xD0 and 0xD2.

        0xD0 uses a fixed count of 1, while 0xD2 uses CL.
        """
        if self.instr.opcode == 0xD2:
            return _vex_expr(self.emu.get_gpreg(reg8_t.CL))
        return self.emu.constant(1, Type.int_8)

    def _masked_shift_count8(self, count: VexExpr) -> VexExpr:
        return masked_shift_count(self.emu, count, 8)

    def _rotate_count8(self, count: VexExpr, modulo: int) -> VexExpr:
        return rotate_count(self.emu, count, modulo, 8)

    def shl_rm8(self) -> None:
        """Execute decoded ``SHL_RM8`` semantics through frontend emulator effects."""
        shift_left_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_shl,
            self._group2_rm8_count(),
            8,
        )

    def rol_rm8(self) -> None:
        """Execute decoded ``ROL_RM8`` semantics through frontend emulator effects."""
        rotate_left_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_rol,
            self._group2_rm8_count(),
            8,
        )

    def ror_rm8(self) -> None:
        """Execute decoded ``ROR_RM8`` semantics through frontend emulator effects."""
        rotate_right_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_ror,
            self._group2_rm8_count(),
            8,
        )

    def rcl_rm8(self) -> None:
        """Execute decoded ``RCL_RM8`` semantics through frontend emulator effects."""
        rm8 = self.get_rm8()
        count = self._group2_rm8_count()
        self._rcl_rm8(rm8, count)

    def rcr_rm8(self) -> None:
        """Execute decoded ``RCR_RM8`` semantics through frontend emulator effects."""
        rm8 = self.get_rm8()
        count = self._group2_rm8_count()
        self._rcr_rm8(rm8, count)

    def shr_rm8(self) -> None:
        """Execute decoded ``SHR_RM8`` semantics through frontend emulator effects."""
        shift_right_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_shr,
            self._group2_rm8_count(),
            8,
        )

    def sar_rm8(self) -> None:
        """Execute decoded ``SAR_RM8`` semantics through frontend emulator effects."""
        shift_right_arithmetic_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_sar,
            self._group2_rm8_count(),
            8,
        )

    def inc_rm8(self) -> None:
        """Execute decoded ``INC_RM8`` semantics through frontend emulator effects."""
        unary_operation(self.get_rm8, self.set_rm8, self.emu.update_eflags_inc, lambda value: value + 1)

    def dec_rm8(self) -> None:
        """Execute decoded ``DEC_RM8`` semantics through frontend emulator effects."""
        unary_operation(self.get_rm8, self.set_rm8, self.emu.update_eflags_dec, lambda value: value - 1)

    def add_rm8_imm8(self) -> None:
        """Execute decoded ``ADD_RM8_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm8,
            self.imm8_value,
            self.set_rm8,
            self.emu.update_eflags_add,
            lambda lhs, rhs: lhs + rhs,
        )

    def or_rm8_imm8(self) -> None:
        """Execute decoded ``OR_RM8_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm8,
            self.imm8_value,
            self.set_rm8,
            self.emu.update_eflags_or,
            lambda lhs, rhs: lhs | rhs,
        )

    def adc_rm8_imm8(self) -> None:
        """Execute decoded ``ADC_RM8_IMM8`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_rm8,
            self.imm8_value,
            self.set_rm8,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            8,
        )

    def sbb_rm8_imm8(self) -> None:
        """Execute decoded ``SBB_RM8_IMM8`` semantics through frontend emulator effects."""
        binary_operation_with_carry(
            self.emu,
            self.get_rm8,
            self.imm8_value,
            self.set_rm8,
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            8,
        )

    def and_rm8_imm8(self) -> None:
        """Execute decoded ``AND_RM8_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm8,
            self.imm8_value,
            self.set_rm8,
            self.emu.update_eflags_and,
            lambda lhs, rhs: lhs & rhs,
        )

    def sub_rm8_imm8(self) -> None:
        """Execute decoded ``SUB_RM8_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm8,
            self.imm8_value,
            self.set_rm8,
            self.emu.update_eflags_sub,
            lambda lhs, rhs: lhs - rhs,
        )

    def xor_rm8_imm8(self) -> None:
        """Execute decoded ``XOR_RM8_IMM8`` semantics through frontend emulator effects."""
        binary_operation(
            self.emu,
            self.get_rm8,
            self.imm8_value,
            self.set_rm8,
            self.emu.update_eflags_xor,
            lambda lhs, rhs: lhs ^ rhs,
        )

    def cmp_rm8_imm8(self) -> None:
        """Execute decoded ``CMP_RM8_IMM8`` semantics through frontend emulator effects."""
        compare_operation(
            self.get_rm8,
            self.imm8_value,
            self.emu.update_eflags_sub,
        )

    def shl_rm8_imm8(self) -> None:
        """Execute decoded ``SHL_RM8_IMM8`` semantics through frontend emulator effects."""
        shift_left_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_shl,
            self.instr.imm8,
            8,
        )

    def rol_rm8_imm8(self) -> None:
        """Execute decoded ``ROL_RM8_IMM8`` semantics through frontend emulator effects."""
        rotate_left_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_rol,
            self.instr.imm8,
            8,
        )

    def ror_rm8_imm8(self) -> None:
        """Execute decoded ``ROR_RM8_IMM8`` semantics through frontend emulator effects."""
        rotate_right_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_ror,
            self.instr.imm8,
            8,
        )

    def rcl_rm8_imm8(self) -> None:
        """Execute decoded ``RCL_RM8_IMM8`` semantics through frontend emulator effects."""
        rm8 = self.get_rm8()
        count = self.emu.constant(self.instr.imm8, Type.int_8)
        self._rcl_rm8(rm8, count)

    def rcr_rm8_imm8(self) -> None:
        """Execute decoded ``RCR_RM8_IMM8`` semantics through frontend emulator effects."""
        rm8 = self.get_rm8()
        count = self.emu.constant(self.instr.imm8, Type.int_8)
        self._rcr_rm8(rm8, count)

    def shr_rm8_imm8(self) -> None:
        """Execute decoded ``SHR_RM8_IMM8`` semantics through frontend emulator effects."""
        shift_right_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_shr,
            self.instr.imm8,
            8,
        )

    def sal_rm8_imm8(self) -> None:
        """Execute decoded ``SAL_RM8_IMM8`` semantics through frontend emulator effects."""
        shift_left_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_shl,
            self.instr.imm8,
            8,
        )

    def sar_rm8_imm8(self) -> None:
        """Execute decoded ``SAR_RM8_IMM8`` semantics through frontend emulator effects."""
        shift_right_arithmetic_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_sar,
            self.instr.imm8,
            8,
        )

    def _rcl_rm8(self, value: VexExpr, count: VexExpr) -> None:
        result, cf, overflow = rotate_through_carry_left_state(self.emu, value, count, 8, self._ite_value)
        if cf is None:
            self.set_rm8(value)
            return
        self.set_rm8(result)
        flags = _vex_expr(self.emu.get_gpreg(reg16_t.FLAGS))
        flags = self.emu.set_carry(flags, cf)
        one = (count & self.emu.constant(0x1F, Type.int_8)) == self.emu.constant(1, Type.int_8)
        flags = self.emu.set_overflow(
            flags, self._ite_value(one, overflow, self.emu.get_flag(11))
        )
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def _rcr_rm8(self, value: VexExpr, count: VexExpr) -> None:
        result, cf, overflow = rotate_through_carry_right_state(self.emu, value, count, 8, self._ite_value)
        if cf is None:
            self.set_rm8(value)
            return
        self.set_rm8(result)
        flags = _vex_expr(self.emu.get_gpreg(reg16_t.FLAGS))
        flags = self.emu.set_carry(flags, cf)
        one = (count & self.emu.constant(0x1F, Type.int_8)) == self.emu.constant(1, Type.int_8)
        flags = self.emu.set_overflow(
            flags, self._ite_value(one, overflow, self.emu.get_flag(11))
        )
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def test_rm8_imm8(self) -> None:
        """Execute decoded ``TEST_RM8_IMM8`` semantics through frontend emulator effects."""
        compare_operation(self.get_rm8, lambda: self.instr.imm8, self.emu.update_eflags_and)

    def not_rm8(self) -> None:
        """Execute decoded ``NOT_RM8`` semantics through frontend emulator effects."""
        rm8 = _vex_expr(self.get_rm8())
        self.set_rm8(~rm8)

    def neg_rm8(self) -> None:
        """Execute decoded ``NEG_RM8`` semantics through frontend emulator effects."""
        unary_operation(
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_neg,
            lambda value: self.emu.constant(0, Type.int_8) - value,
        )

    def mul_ax_al_rm8(self) -> None:
        """Execute decoded ``MUL_AX_AL_RM8`` semantics through frontend emulator effects."""
        rm8 = _vex_expr(self.get_rm8())
        al = _vex_expr(self.emu.get_gpreg(reg8_t.AL))
        val = al.cast_to(Type.int_16) * rm8.cast_to(Type.int_16)
        self.emu.set_gpreg(reg16_t.AX, val)
        self.emu.update_eflags_mul(al, rm8)

    def imul_ax_al_rm8(self) -> None:
        """Execute decoded ``IMUL_AX_AL_RM8`` semantics through frontend emulator effects."""
        rm8_s = _vex_expr(self.get_rm8()).signed
        al_s = _vex_expr(self.emu.get_gpreg(reg8_t.AL)).signed
        val_s = al_s * rm8_s
        self.emu.set_gpreg(reg16_t.AX, val_s)
        self.emu.update_eflags_imul(al_s, rm8_s)

    def div_al_ah_rm8(self) -> None:
        """Execute decoded ``DIV_AL_AH_RM8`` semantics through frontend emulator effects."""
        rm8 = _vex_expr(self.get_rm8()).cast_to(Type.int_16)
        ax = _vex_expr(self.emu.get_gpreg(reg16_t.AX))
        self._divide_error_if(rm8 == self.emu.constant(0, Type.int_16))
        quotient = ax // rm8
        self._divide_error_if(quotient > self.emu.constant(0xFF, Type.int_16))
        self.emu.set_gpreg(reg8_t.AL, quotient)
        self.emu.set_gpreg(reg8_t.AH, ax % rm8)

    def idiv_al_ah_rm8(self) -> None:
        """Execute decoded ``IDIV_AL_AH_RM8`` semantics through frontend emulator effects."""
        rm8_s = _vex_expr(self.get_rm8()).cast_to(Type.int_16, signed=True)
        ax_s = _vex_expr(self.emu.get_gpreg(reg16_t.AX)).signed
        self._divide_error_if(rm8_s == self.emu.constant(0, Type.int_16))
        quotient = ax_s // rm8_s
        remainder = ax_s - quotient * rm8_s
        signed_quotient = quotient.signed
        self._divide_error_if(
            (signed_quotient < _require_vex_value(self.emu.constant(0xFF80, Type.int_16)).signed)
            | (signed_quotient > _require_vex_value(self.emu.constant(0x007F, Type.int_16)).signed)
        )
        self.emu.set_gpreg(reg8_t.AL, quotient)
        self.emu.set_gpreg(reg8_t.AH, remainder)

    def _divide_error_if(self, condition: VexExpr) -> None:
        """Emit a native-VEX-compatible conditional x86 divide-error exit."""
        lifter_instruction = self.emu.lifter_instruction
        if lifter_instruction is None:
            raise RuntimeError("divide-error lifting requires an active lifter instruction")
        target = _require_vex_value(self.emu.constant(0, Type.int_32))
        guard = condition.cast_to(Type.int_1)
        lifter_instruction.irsb_c.add_exit(
            guard.rdt,
            target.rdt,
            "Ijk_SigFPE_IntDiv",
            lifter_instruction.arch.ip_offset,
        )

    def set_chsz_ad(self, ad: bool) -> None:
        """Set whether address-size override semantics are active."""
        self.chsz_ad = ad


# Keep executable handlers in the table so owned dispatch remains statically
# checkable; entries 4 and 6 intentionally share SHL because SAL is its alias.
GROUP2_BYTE_SHIFT_ROTATE_HANDLERS: dict[int, Callable[[InstrBase], None]] = {
    0: InstrBase.rol_rm8,
    1: InstrBase.ror_rm8,
    2: InstrBase.rcl_rm8,
    3: InstrBase.rcr_rm8,
    4: InstrBase.shl_rm8,
    5: InstrBase.shr_rm8,
    6: InstrBase.shl_rm8,
    7: InstrBase.sar_rm8,
}
