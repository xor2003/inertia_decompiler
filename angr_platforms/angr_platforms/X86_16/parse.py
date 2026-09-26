"""Layer: Frontend/runtime.

Responsibility: parse instruction prefixes, operands, and width state for the lifter.
Forbidden: decompiler semantic recovery, source/COD-backed repair, or validation acceptance.
"""

from __future__ import annotations

import logging
import struct

from pyvex.lifting.util import ParseError

from .addressing_helpers import decode_width_case_for_profile, decode_width_profile
from .emulator import Emulator
from .instruction import (
    CHK_IMM8,
    CHK_IMM16,
    CHK_IMM32,
    CHK_MODRM,
    CHK_MOFFS,
    CHK_PTR16,
    MAX_OPCODE,
    REPNZ,
    REPZ,
    InstrData,
    InstrFlags,
    X86Instruction,
)
from .msvc_x87_interrupts import is_msvc_x87_emulation_interrupt_8616, msvc_x87_escape_opcode_8616
from .regs import sgreg_t

_CONTROL_FLOW_BY_OPCODE_8616: dict[int, str] = {
    0xCC: "interrupt",
    0xCD: "interrupt",
    0xCE: "interrupt",
    0xCF: "iret",
    0xC2: "near_ret",
    0xC3: "near_ret",
    0xCA: "far_ret",
    0xCB: "far_ret",
    0x9A: "far_call",
    0xE8: "near_call",
    0xEA: "far_jump",
    0xE9: "near_jump",
    0xEB: "near_jump",
}

_CONTROL_FLOW_FF_REG_8616: dict[int, str] = {
    2: "near_call",
    3: "far_call",
    4: "near_jump",
    5: "far_jump",
}

_CONDITIONAL_JUMP_OPCODES_8616: set[int] = {
    0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
    0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F,
    0x0F80, 0x0F81, 0x0F82, 0x0F83, 0x0F84, 0x0F85, 0x0F86, 0x0F87,
    0x0F88, 0x0F89, 0x0F8A, 0x0F8B, 0x0F8C, 0x0F8D, 0x0F8E, 0x0F8F,
    0xE0, 0xE1, 0xE2, 0xE3,
}

CHSZ_NONE: int = 0
CHSZ_OP: int = 1
CHSZ_AD: int = 2

_SEGMENT_PREFIX_BY_CODE_8616: dict[int, sgreg_t] = {
    0x26: sgreg_t.ES,
    0x2E: sgreg_t.CS,
    0x36: sgreg_t.SS,
    0x3E: sgreg_t.DS,
    0x64: sgreg_t.FS,
    0x65: sgreg_t.GS,
}

_PREFIX_CHSZ_BY_CODE_8616: dict[int, int] = {
    0x66: CHSZ_OP,
    0x67: CHSZ_AD,
}

_PREFIX_REPEAT_BY_CODE_8616: dict[int, object] = {
    0xF2: REPNZ,
    0xF3: REPZ,
}

logger: logging.Logger = logging.getLogger(__name__)


class ParseInstr(X86Instruction):
    """Parse x86 instruction bytes into frontend decode metadata."""

    def __init__(self, emu: Emulator, instr: InstrData, mode32: bool) -> None:
        """Bind parser state to the current emulator byte stream and instruction record."""
        super().__init__(emu, instr, mode32)
        self.emu: Emulator = emu
        self.chk: list[int | InstrFlags] = [InstrFlags()] * MAX_OPCODE
        self.chsz: int = CHSZ_NONE
        self.chsz_ad: bool = False

    def parse_prefix(self) -> int:
        """Consume instruction prefixes and return the operand/address-size override mask."""

        def _impl() -> int:
            chsz = 0
            prefix_len = 0

            while True:
                # code = self.emu.get_code8_(bitstream)
                raw_code = self.emu.bitstream.peek("uint:8")
                if not isinstance(raw_code, int):
                    raise ParseError(f"Expected byte prefix at {self.emu.bitstream.bytepos:08x}, got {raw_code!r}")
                code = raw_code
                chsz, is_prefix = self._consume_prefix_8616(code, chsz)
                if not is_prefix:
                    self.chsz = chsz
                    self.chsz_ad = bool(chsz & CHSZ_AD)
                    self.instr.prefix_len = prefix_len
                    return chsz

                self.emu.bitstream.read("uint:8")
                self.instr.prefix = code
                prefix_len += 1

        return _impl()
        # self.emu.update_eip(1)

    def _consume_prefix_8616(self, code: int, chsz: int) -> tuple[int, bool]:
        """Apply one prefix byte; return the updated override mask and whether it was a prefix."""
        segment = _SEGMENT_PREFIX_BY_CODE_8616.get(code)
        if segment is not None:
            self.instr.pre_segment = segment
            return chsz, True
        size_flag = _PREFIX_CHSZ_BY_CODE_8616.get(code)
        if size_flag is not None:
            return chsz | size_flag, True
        repeat = _PREFIX_REPEAT_BY_CODE_8616.get(code)
        if repeat is not None:
            self.instr.pre_repeat = repeat
            return chsz, True
        if code == 0xF0:
            # LOCK is a valid real-mode prefix. For our current single-core
            # verifier path it does not change architectural results, so we
            # keep it as a consumed prefix and let the following opcode lift.
            return chsz, True
        return chsz, False

    def parse(self) -> None:
        """Parse opcode, operands, immediates, and normalized decode metadata."""

        def _impl() -> None:
            start = self.emu.bitstream.bytepos
            widths = decode_width_profile(
                self.emu.is_mode32(),
                bool(self.chsz & CHSZ_OP),
                bool(self.chsz & CHSZ_AD),
            )
            self.instr.operand_bits = widths.operand_bits
            self.instr.address_bits = widths.address_bits
            self.instr.width_case = decode_width_case_for_profile(widths.operand_bits, widths.address_bits).name
            self.instr.displacement_bits = 0
            self.parse_opcode()

            opcode = self.instr.opcode
            if opcode >> 8 == 0x0F:
                opcode = (opcode & 0xFF) | 0x0100

            opcode_entry = self.chk[opcode] if opcode < len(self.chk) else InstrFlags()
            if isinstance(opcode_entry, InstrFlags):
                logger.error(
                    "Unknown opcode at %08x: %02x, next bytes: %08x",
                    self.emu.bitstream.bytepos,
                    opcode,
                    self.emu.bitstream.peek("uint:32"),
                )
                raise ParseError(
                    f"Unknown opcode {self.emu.bitstream.bytepos:08x}: {opcode:02x}{self.emu.bitstream.peek('uint:32'):08x}"
                )
                # sys.exit(1)
            opcode_flags = opcode_entry
            if opcode_flags & CHK_MODRM:
                self.parse_modrm_sib_disp()

            self._decode_immediates_8616(opcode, opcode_flags)

            self.instr.size = max(self.instr.size, self.instr.prefix_len + (self.emu.bitstream.bytepos - start))
            self.instr.repeat_class = self._repeat_class_name()
            self.instr.control_flow_class = self._classify_control_flow(opcode)

        return _impl()

    def _decode_immediates_8616(self, opcode: int, opcode_flags: int) -> None:
        """Decode flag-selected immediates and moffs for the current instruction."""
        if opcode_flags & CHK_IMM32:
            self.instr.imm32 = self.emu.get_code32(0)
            # self.emu.update_eip(4)
        if opcode_flags & CHK_IMM16:
            self.instr.imm16 = self.emu.get_code16(0)
            # self.emu.update_eip(2)
        if opcode_flags & CHK_IMM8:
            self.instr.imm8 = struct.unpack("b", struct.pack("B", self.emu.get_code8(0)))[0]
            remaining_bits = self.emu.bitstream.len - self.emu.bitstream.pos
            if (
                opcode == 0xCD
                and msvc_x87_escape_opcode_8616(self.instr.imm8) is not None
                and remaining_bits >= 8
            ):
                self.instr.msvc_x87_escape = True
                self.parse_modrm_sib_disp()
            # self.emu.update_eip(1)
        if opcode_flags & CHK_PTR16:
            self.instr.ptr16 = self.emu.get_code16(0)
            # self.emu.update_eip(2)

        if opcode_flags & CHK_MOFFS:
            self.parse_moffs()

        if opcode == 0xF6 and self.instr.modrm.reg in (0, 1):  # test
            self.instr.imm8 = self.emu.get_code8(0)
        if opcode == 0xF7 and self.instr.modrm.reg in (0, 1):  # test
            if self.instr.operand_bits == 32:
                self.instr.imm32 = self.emu.get_code32(0)
            else:
                self.instr.imm16 = self.emu.get_code16(0)

    def _repeat_class_name(self) -> str:
        if self.instr.pre_repeat == REPZ:
            return "repz"
        if self.instr.pre_repeat == REPNZ:
            return "repnz"
        return "none"

    def _classify_control_flow(self, opcode: int) -> str:
        def _impl() -> str:
            if opcode == 0xCD and (
                self.instr.msvc_x87_escape
                or (is_msvc_x87_emulation_interrupt_8616(self.instr.imm8) and (self.instr.imm8 & 0xFF) == 0x3D)
            ):
                return "none"
            fixed = _CONTROL_FLOW_BY_OPCODE_8616.get(opcode)
            if fixed is not None:
                return fixed
            if opcode == 0xFF:
                return _CONTROL_FLOW_FF_REG_8616.get(self.instr.modrm.reg, "none")
            if opcode in _CONDITIONAL_JUMP_OPCODES_8616:
                return "conditional_jump"
            return "none"

        return _impl()

    def parse_opcode(self) -> None:
        """Parse the one-byte or 0F-prefixed opcode."""
        self.instr.opcode = self.emu.get_code8(0)
        # self.emu.update_eip(1)

        # two byte opcode
        if self.instr.opcode == 0x0F:
            self.instr.opcode = (self.instr.opcode << 8) + self.emu.get_code8(0)
            # self.emu.update_eip(1)
        logger.debug(f"opcode: {self.instr.opcode:0x}")

    def parse_modrm_sib_disp(self) -> None:
        """Parse ModR/M, optional SIB, and displacement bytes."""
        modrm = self.emu.get_code8(0)
        self.instr.modrm.mod = modrm >> 6
        self.instr.modrm.reg = (modrm >> 3) & 0b111
        self.instr.modrm.rm = modrm & 0b111
        # self.emu.update_eip(1)

        if self.instr.address_bits == 32:
            self.parse_modrm32()
        else:
            self.parse_modrm16()

    def parse_modrm32(self) -> None:
        """Parse 32-bit addressing displacement and SIB fields."""
        if self.instr.modrm.mod != 3 and self.instr.modrm.rm == 4:
            sib = self.emu.get_code8(0)
            self.instr.sib.scale = sib >> 6
            self.instr.sib.index = (sib >> 3) & 0b111
            self.instr.sib.base = sib & 0b111
            # self.emu.update_eip(1)

        if (
            self.instr.modrm.mod == 2
            or (self.instr.modrm.mod == 0 and self.instr.modrm.rm == 5)
            or (self.instr.modrm.mod == 0 and self.instr.sib.base == 5)
        ):
            self.instr.disp32 = self.emu.get_code32(0)
            self.instr.displacement_bits = 32
            # self.emu.update_eip(4)
        elif self.instr.modrm.mod == 1:
            self.instr.disp8 = struct.unpack("b", struct.pack("B", self.emu.get_code8(0)))[0]
            self.instr.displacement_bits = 8
            # self.emu.update_eip(1)

    def parse_modrm16(self) -> None:
        """Parse 16-bit addressing displacement fields."""
        if (self.instr.modrm.mod == 0 and self.instr.modrm.rm == 6) or self.instr.modrm.mod == 2:
            self.instr.disp16 = self.emu.get_code16(0)
            self.instr.displacement_bits = 16
            # self.emu.update_eip(2)
        elif self.instr.modrm.mod == 1:
            self.instr.disp8 = struct.unpack("b", struct.pack("B", self.emu.get_code8(0)))[0]
            self.instr.displacement_bits = 8
            # self.emu.update_eip(1)

    def parse_moffs(self) -> None:
        """Parse a direct memory offset operand for the active address size."""
        if self.instr.address_bits == 32:
            self.instr.moffs = self.emu.get_code32(0)
            self.instr.displacement_bits = 32
            # self.emu.update_eip(4)
        else:
            self.instr.moffs = self.emu.get_code16(0)
            self.instr.displacement_bits = 16
            # self.emu.update_eip(2)
