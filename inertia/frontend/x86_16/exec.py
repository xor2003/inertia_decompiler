"""Layer: Frontend/runtime.

Responsibility: dispatch decoded opcodes and register/memory operands for emulator execution.
Forbidden: decompiler output repair, alias/type ownership, or source-backed semantics.
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Protocol, cast

from pyvex.lifting.util.syntax_wrapper import VexValue

from inertia.frontend.x86_16.addressing_helpers import (
    ResolvedMemoryOperand,
    resolve_linear_operand,
    resolve_modrm16_address,
    resolve_modrm32_address,
)
from inertia.frontend.x86_16.regs import (
    coerce_reg8_t,
    coerce_reg16_t,
    coerce_reg32_t,
    coerce_sgreg_t,
    reg8_t,
    reg16_t,
    reg32_t,
    sgreg_t,
)

from .emulator import Emulator
from .instruction import InstrData, X86Instruction
from .processor import RegisterValue


class _ExecEmulatorHooks(Protocol):
    """Runtime hooks required by decoded instruction execution."""

    def set_gpreg(self, n: reg8_t | reg16_t | reg32_t, value: object) -> None:
        """Write a general-purpose register."""
        ...

    def get_gpreg(self, n: reg8_t | reg16_t | reg32_t | VexValue) -> RegisterValue:
        """Read a general-purpose register."""
        ...

    def put_data32(self, seg: object, addr: object, value: object) -> None:
        """Write 32-bit segmented data."""
        ...

    def get_data32(self, seg: object, addr: object) -> object:
        """Read 32-bit segmented data."""
        ...

    def put_data16(self, seg: object, addr: object, val: object) -> None:
        """Write 16-bit segmented data."""
        ...

    def get_data16(self, seg: object, addr: object) -> object:
        """Read 16-bit segmented data."""
        ...

    def put_data8(self, seg: object, addr: object, value: object) -> None:
        """Write 8-bit segmented data."""
        ...

    def get_data8(self, seg: object, addr: object) -> object:
        """Read 8-bit segmented data."""
        ...

    def set_segment(self, reg: sgreg_t, sel: object) -> None:
        """Write a segment register."""
        ...

    def get_segment(self, reg: sgreg_t | VexValue) -> object:
        """Read a segment register."""
        ...

    def set_crn(self, n: int, value: int) -> None:
        """Write a control register."""
        ...

    def get_crn(self, n: int) -> int | VexValue:
        """Read a concrete or lifted control-register value."""
        ...


type OpcodeExecHandler = Callable[["ExecInstr"], None]


class ExecInstr(X86Instruction):  # type: ignore[misc, unused-ignore]  # dynamic frontend base contract
    """Execute decoded frontend instructions through emulator register/memory hooks."""

    def __init__(self, emu: _ExecEmulatorHooks, instr: InstrData | None = None, mode32: bool = False) -> None:
        """Initialize opcode dispatch state while preserving legacy MRO construction."""
        # The base instruction slot is typed as the full emulator; execution only
        # requires this narrower structural hook surface at the runtime boundary.
        self.emu = cast(Emulator, emu)
        if instr is not None:
            self.instr = instr
            self.mode32 = mode32
            self.chsz_ad = False
        self.instrfuncs: list[OpcodeExecHandler | None] = [None] * 0x200

    def exec(self) -> bool:
        """Dispatch the decoded opcode to its registered frontend runtime handler."""
        opcode = self.instr.opcode

        if opcode >> 8 == 0x0F:
            opcode = (opcode & 0xFF) | 0x0100

        handler = self.instrfuncs[opcode]
        if handler is None:
            print(f"not implemented OPCODE 0x{opcode:02x}", file=sys.stderr)
            return False

        handler(self)
        return True

    def set_rm32(self, value: object) -> None:
        """Write a 32-bit ModR/M destination through register or memory hooks."""
        if self.instr.modrm.mod == 3:
            self.emu.set_gpreg(coerce_reg32_t(self.instr.modrm.rm), value)
            return
        operand = self._resolved_rm_operand(32)
        self.emu.put_data32(operand.segment, operand.offset, value)

    def get_rm32(self) -> object:
        """Read a 32-bit ModR/M source through register or memory hooks."""
        if self.instr.modrm.mod == 3:
            return self.emu.get_gpreg(coerce_reg32_t(self.instr.modrm.rm))
        operand = self._resolved_rm_operand(32)
        return self.emu.get_data32(operand.segment, operand.offset)

    def set_r32(self, value: object) -> None:
        """Write the 32-bit ModR/M register field."""
        self.emu.set_gpreg(coerce_reg32_t(self.instr.modrm.reg), value)

    def get_r32(self) -> object:
        """Read the 32-bit ModR/M register field."""
        return self.emu.get_gpreg(coerce_reg32_t(self.instr.modrm.reg))

    def set_moffs32(self, value: object) -> None:
        """Write a 32-bit direct memory-offset operand."""
        operand = self._resolved_moffs_operand(32)
        self.emu.put_data32(operand.segment, operand.offset, value)

    def get_moffs32(self) -> object:
        """Read a 32-bit direct memory-offset operand."""
        operand = self._resolved_moffs_operand(32)
        return self.emu.get_data32(operand.segment, operand.offset)

    def set_rm16(self, value: object) -> None:
        """Write a 16-bit ModR/M destination through register or memory hooks."""
        if self.instr.modrm.mod == 3:
            self.emu.set_gpreg(coerce_reg16_t(self.instr.modrm.rm), value)
            return
        operand = self._resolved_rm_operand(16)
        self.emu.put_data16(operand.segment, operand.offset, value)

    def get_rm16(self) -> object:
        """Read a 16-bit ModR/M source through register or memory hooks."""
        if self.instr.modrm.mod == 3:
            return self.emu.get_gpreg(coerce_reg16_t(self.instr.modrm.rm))
        operand = self._resolved_rm_operand(16)
        return self.emu.get_data16(operand.segment, operand.offset)

    def set_r16(self, value: object) -> None:
        """Write the 16-bit ModR/M register field."""
        self.emu.set_gpreg(coerce_reg16_t(self.instr.modrm.reg), value)

    def get_r16(self) -> object:
        """Read the 16-bit ModR/M register field."""
        return self.emu.get_gpreg(coerce_reg16_t(self.instr.modrm.reg))

    def set_moffs16(self, value: object) -> None:
        """Write a 16-bit direct memory-offset operand."""
        operand = self._resolved_moffs_operand(16)
        self.emu.put_data16(operand.segment, operand.offset, value)

    def get_moffs16(self) -> object:
        """Read a 16-bit direct memory-offset operand."""
        operand = self._resolved_moffs_operand(16)
        return self.emu.get_data16(operand.segment, operand.offset)

    def set_rm8(self, value: object) -> None:
        """Write an 8-bit ModR/M destination through register or memory hooks."""
        if self.instr.modrm.mod == 3:
            self.emu.set_gpreg(coerce_reg8_t(self.instr.modrm.rm), value)
            return
        operand = self._resolved_rm_operand(8)
        self.emu.put_data8(operand.segment, operand.offset, value)

    def get_rm8(self) -> object:
        """Read an 8-bit ModR/M source through register or memory hooks."""
        if self.instr.modrm.mod == 3:
            return self.emu.get_gpreg(coerce_reg8_t(self.instr.modrm.rm))
        operand = self._resolved_rm_operand(8)
        return self.emu.get_data8(operand.segment, operand.offset)

    def set_r8(self, value: object) -> None:
        """Write the 8-bit ModR/M register field."""
        self.emu.set_gpreg(coerce_reg8_t(self.instr.modrm.reg), value)

    def get_r8(self) -> object:
        """Read the 8-bit ModR/M register field."""
        return self.emu.get_gpreg(coerce_reg8_t(self.instr.modrm.reg))

    def set_moffs8(self, value: object) -> None:
        """Write an 8-bit direct memory-offset operand."""
        operand = self._resolved_moffs_operand(8)
        self.emu.put_data8(operand.segment, operand.offset, value)

    def get_moffs8(self) -> object:
        """Read an 8-bit direct memory-offset operand."""
        operand = self._resolved_moffs_operand(8)
        return self.emu.get_data8(operand.segment, operand.offset)

    def get_m(self) -> object:
        """Return the effective memory address for the decoded ModR/M operand."""
        return self.calc_modrm()

    def _resolved_rm_operand(self, width_bits: int) -> ResolvedMemoryOperand:
        seg, addr = self._resolved_rm_address()
        return resolve_linear_operand(
            self.emu,
            seg,
            addr,
            width_bits,
            self.effective_address_bits(),
        )

    def _resolved_rm_address(self) -> tuple[sgreg_t, object]:
        addr = self.calc_modrm()
        seg = self.select_segment()
        return seg, addr

    def _resolved_moffs_operand(self, width_bits: int) -> ResolvedMemoryOperand:
        self.instr.segment = sgreg_t.DS.value
        seg = self.select_segment()
        offset = self.instr.moffs
        return resolve_linear_operand(
            self.emu,
            seg,
            offset,
            width_bits,
            self.effective_address_bits(),
        )

    def set_sreg(self, value: object) -> None:
        """Write the segment register selected by the ModR/M register field."""
        self.emu.set_segment(coerce_sgreg_t(self.instr.modrm.reg), value)

    def get_sreg(self) -> object:
        """Read the segment register selected by the ModR/M register field."""
        return self.emu.get_segment(coerce_sgreg_t(self.instr.modrm.reg))

    def set_crn(self, value: int) -> None:
        """Write the control register selected by the ModR/M register field."""
        print(f"set CR{self.instr.modrm.reg} = {value:x}")
        self.emu.set_crn(self.instr.modrm.reg, value)

    def get_crn(self) -> int | VexValue:
        """Read the control register selected by the ModR/M register field."""
        return self.emu.get_crn(self.instr.modrm.reg)

    def calc_modrm(self) -> object:
        """Calculate the execution address for a memory ModR/M operand."""
        assert self.instr.modrm.mod != 3

        self.instr.segment = sgreg_t.DS.value
        if self.effective_address_bits() == 32:
            return self.calc_modrm32()
        else:
            return self.calc_modrm16()

    def calc_modrm16(self) -> object:
        """Calculate a 16-bit effective address and selected segment."""
        segment, addr = resolve_modrm16_address(self.emu, self.instr.modrm, self.instr.disp8, self.instr.disp16)
        self.instr.segment = segment.value
        return addr

    def calc_modrm32(self) -> object:
        """Calculate a 32-bit effective address and selected segment."""
        segment, addr = resolve_modrm32_address(
            self.emu, self.instr.modrm, self.instr.sib, self.instr.disp8, self.instr.disp32
        )
        self.instr.segment = segment.value
        return addr
