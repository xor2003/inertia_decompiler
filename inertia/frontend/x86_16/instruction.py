"""Layer: Frontend/runtime.

Responsibility: define decoded instruction data and operand metadata for the lifter.
Forbidden: decompiler structuring, alias/type recovery, or rendered-C cleanup.
"""

from __future__ import annotations

from inertia.frontend.x86_16.addressing_helpers import (
    WidthProfile,
    address_width_bits,
    decode_width_case,
    decode_width_case_for_profile,
    operand_width_bits,
)
from inertia.frontend.x86_16.regs import sgreg_t

from .emulator import Emulator

# Constants for repeat prefixes
NONE: int = 0
REPZ: int = 1
REPNZ: int = 2

# Constants for instruction flags
CHK_MODRM: int = 1 << 0
CHK_IMM32: int = 1 << 1
CHK_IMM16: int = 1 << 2
CHK_IMM8: int = 1 << 3
CHK_PTR16: int = 1 << 4
CHK_MOFFS: int = 1 << 5

MAX_OPCODE: int = 0x200


# ModR/M byte structure
class ModRM:
    """Decoded ModR/M byte fields used by frontend parsing and execution."""

    __slots__ = ("mod", "reg", "rm")

    def __init__(self) -> None:
        """Initialize an empty ModR/M operand descriptor."""
        self.rm: int = 0  # Register/memory operand
        self.reg: int = 0  # Register operand or opcode extension
        self.mod: int = 0  # Addressing mode


# SIB byte structure
class SIB:
    """Decoded scale-index-base byte fields used by 32-bit addressing forms."""

    __slots__ = ("base", "index", "scale")

    def __init__(self) -> None:
        """Initialize an empty SIB operand descriptor."""
        self.base: int = 0  # Base register
        self.index: int = 0  # Index register
        self.scale: int = 0  # Scaling factor


# X86Instruction data structure
class InstrData:
    """Mutable decoded instruction record shared by parse, exec, and emulation layers."""

    __slots__ = (
        "address_bits",
        "control_flow_class",
        "disp8",
        "disp16",
        "disp32",
        "displacement_bits",
        "imm8",
        "imm16",
        "imm32",
        "invalid_lock",
        "invalid_opcode_extension",
        "mode32",
        "modrm",
        "moffs",
        "msvc_x87_escape",
        "opcode",
        "operand_bits",
        "pre_repeat",
        "pre_segment",
        "prefix",
        "prefix_len",
        "ptr16",
        "repeat_class",
        "segment",
        "sib",
        "size",
        "width_case",
    )

    def __init__(self) -> None:
        """Initialize a decoded instruction record with neutral frontend defaults."""
        self.prefix: int = 0  # X86Instruction prefix
        self.pre_segment: sgreg_t | None = None  # Segment override prefix
        self.pre_repeat: int = NONE  # Repeat prefix

        self.segment: int = 0  # Default segment register
        self.opcode: int = 0  # Opcode
        self.modrm: ModRM = ModRM()  # ModR/M byte
        self.sib: SIB = SIB()  # SIB byte
        self.disp8: int = 0  # 8-bit displacement
        self.disp16: int = 0  # 16-bit displacement
        self.disp32: int = 0  # 32-bit displacement
        self.imm8: int = 0  # 8-bit immediate value
        self.imm16: int = 0  # 16-bit immediate value
        self.imm32: int = 0  # 32-bit immediate value
        self.invalid_lock: bool = False  # LOCK prefix rejected for this opcode/form
        self.invalid_opcode_extension: bool = False  # Reserved ModR/M opcode extension
        self.msvc_x87_escape: bool = False  # INT byte stream consumed as an MSVC x87 ESC payload
        self.ptr16: int = 0  # 16-bit far pointer
        self.moffs: int = 0  # Memory offset
        self.prefix_len: int = 0  # number of prefix bytes consumed
        self.size: int = 0  # total instruction size in bytes including prefixes
        self.operand_bits: int = 0  # normalized effective operand width
        self.address_bits: int = 0  # normalized effective address width
        self.displacement_bits: int = 0  # normalized displacement width, if any
        self.mode32: bool = False  # active processor width mode for string/repeat helpers
        self.repeat_class: str = "none"  # normalized repeat prefix class
        self.control_flow_class: str = "none"  # normalized control-transfer family
        self.width_case: str = ""  # normalized decode matrix case label


def describe_x86_16_instruction_metadata_surface() -> dict[str, object]:
    """Describe normalized decode metadata exposed to architecture checks."""
    return {
        "normalized_fields": (
            "width_case",
            "operand_bits",
            "address_bits",
            "displacement_bits",
            "repeat_class",
            "control_flow_class",
        ),
        "repeat_classes": ("none", "repz", "repnz"),
        "control_flow_classes": (
            "none",
            "interrupt",
            "iret",
            "near_ret",
            "far_ret",
            "near_call",
            "far_call",
            "near_jump",
            "far_jump",
            "conditional_jump",
        ),
    }


# Base class for instruction handlers
class X86Instruction:
    """Shared decoded-instruction view for parser, executor, and emulator handlers."""

    __slots__ = ("chsz_ad", "emu", "instr", "mode32")

    def __init__(self, emu: Emulator, instr: InstrData, mode32: bool) -> None:
        """Bind emulator state and decoded instruction metadata."""
        self.emu = emu
        self.instr = instr
        self.mode32 = mode32
        self.instr.mode32 = mode32
        self.chsz_ad = False

    def select_segment(self) -> sgreg_t:
        """Return the active segment override or decoded default segment."""
        seg = self.instr.pre_segment if self.instr.pre_segment is not None else self.instr.segment
        return sgreg_t(seg)

    def effective_operand_bits(self) -> int:
        """Return the normalized operand width for this instruction."""
        return self.instr.operand_bits or operand_width_bits(self.mode32, False)

    def effective_address_bits(self) -> int:
        """Return the normalized address width for this instruction."""
        return self.instr.address_bits or address_width_bits(self.mode32, self.chsz_ad)

    def repeat_kind(self) -> str:
        """Return the normalized repeat-prefix class."""
        return self.instr.repeat_class or "none"

    def control_flow_kind(self) -> str:
        """Return the normalized control-flow class."""
        return self.instr.control_flow_class or "none"

    def width_profile(self) -> WidthProfile:
        """Return the combined operand/address width profile."""
        return WidthProfile(
            operand_bits=self.effective_operand_bits(),
            address_bits=self.effective_address_bits(),
        )

    def width_case_name(self) -> str:
        """Return the decode matrix case name for the effective widths."""
        if self.instr.width_case:
            return self.instr.width_case
        try:
            return decode_width_case_for_profile(self.effective_operand_bits(), self.effective_address_bits()).name
        except ValueError:
            return decode_width_case(self.mode32, False, False).name


# Class for executing instructions


class InstrFlags:
    """Opcode operand-presence flags consumed by parser and opcode tables."""

    __slots__ = ("imm8", "imm16", "imm32", "modrm", "moffs", "moffs8", "ptr16")

    def __init__(self) -> None:
        """Initialize an opcode flag record with no operands required."""
        self.modrm = False
        self.imm32 = False
        self.imm16 = False
        self.imm8 = False
        self.ptr16 = False
        self.moffs = False
        self.moffs8 = False

    @property
    def flags(self) -> int:
        """Returns a byte representation of the flags."""
        return (
            (self.modrm << 0)
            | (self.imm32 << 1)
            | (self.imm16 << 2)
            | (self.imm8 << 3)
            | (self.ptr16 << 4)
            | (self.moffs << 5)
            | (self.moffs8 << 6)
        )

    @flags.setter
    def flags(self, value: int) -> None:
        """Sets the flags from a byte representation."""
        self.modrm = bool(value & 1)
        self.imm32 = bool(value & (1 << 1))
        self.imm16 = bool(value & (1 << 2))
        self.imm8 = bool(value & (1 << 3))
        self.ptr16 = bool(value & (1 << 4))
        self.moffs = bool(value & (1 << 5))
        self.moffs8 = bool(value & (1 << 6))
