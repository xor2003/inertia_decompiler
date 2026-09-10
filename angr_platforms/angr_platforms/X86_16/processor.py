"""Layer: Frontend/runtime.

Responsibility: model processor registers and segment state for lifting/emulation.
Forbidden: decompiler alias/type ownership, source-backed recovery, or rendered-C cleanup.
"""

from __future__ import annotations

from typing import Any, cast

from pyvex.const import get_type_size, is_int_ty
from pyvex.expr import Binop, Const, Get, Load, Unop
from pyvex.lifting.util.syntax_wrapper import VexValue
from pyvex.lifting.util.vex_helper import Type
from pyvex.stmt import Put

from .cr import CR
from .direction_step import lifted_direction_step_8616
from .eflags import Eflags
from .regs import dtreg_t, reg8_t, reg16_t, reg32_t, register_name_8616, sgreg_t

# Constants for general-purpose registers

# Constants for segment registers

# Constants for descriptor table registers


type RegisterName = reg8_t | reg16_t | reg32_t | sgreg_t
type RegisterValue = int | VexValue

TYPES: dict[type[RegisterName], object] = {
    reg8_t: Type.int_8,
    reg16_t: Type.int_16,
    reg32_t: Type.int_32,
    sgreg_t: Type.int_16,
}

# General-purpose register structure


class GPRegister:
    """Concrete general-purpose register storage."""

    def __init__(self) -> None:
        """Initialize the register with a zero concrete value."""
        self.reg32: int = 0  # 32-bit register value

    @property
    def reg16(self) -> int:
        """Return the low 16-bit view."""
        return self.reg32 & 0xFFFF

    @reg16.setter
    def reg16(self, value: int) -> None:
        """Set the low 16-bit view."""
        self.reg32 = (self.reg32 & 0xFFFF0000) | (value & 0xFFFF)

    @property
    def reg8_l(self) -> int:
        """Return the low 8-bit view."""
        return self.reg32 & 0xFF

    @reg8_l.setter
    def reg8_l(self, value: int) -> None:
        """Set the low 8-bit view."""
        self.reg32 = (self.reg32 & 0xFFFFFF00) | (value & 0xFF)

    @property
    def reg8_h(self) -> int:
        """Return the high byte of the low 16-bit view."""
        return (self.reg32 >> 8) & 0xFF

    @reg8_h.setter
    def reg8_h(self, value: int) -> None:
        """Set the high byte of the low 16-bit view."""
        self.reg32 = (self.reg32 & 0xFFFF00FF) | ((value & 0xFF) << 8)


# Segment register cache structure


class SGRegCache:
    """Cached descriptor state for a segment register."""

    def __init__(self) -> None:
        """Initialize the cached descriptor with a flat zero base."""
        self.base: int = 0  # Base address of the segment
        self.limit: int = 0  # Limit of the segment
        self.flags: SegDescFlags = SegDescFlags()  # Flags for the segment descriptor


# Segment descriptor flags structure


class SegDescFlags:
    """Packed segment descriptor flags."""

    def __init__(self) -> None:
        """Initialize all descriptor flags to zero."""
        self.raw: int = 0  # Raw flags value

    @property
    def type(self) -> int:
        """Return the descriptor type field."""
        return self.raw & 0xF

    @type.setter
    def type(self, value: int) -> None:
        """Set the descriptor type field."""
        self.raw = (self.raw & 0xFFF0) | (value & 0xF)

    @property
    def S(self) -> bool:
        """Return the descriptor kind flag."""
        return bool(self.raw & (1 << 4))

    @S.setter
    def S(self, value: bool | int) -> None:
        """Set the descriptor kind flag."""
        self.raw = (self.raw & ~(1 << 4)) | (int(value) << 4)

    @property
    def DPL(self) -> int:
        """Return the descriptor privilege level."""
        return (self.raw >> 5) & 3

    @DPL.setter
    def DPL(self, value: int) -> None:
        """Set the descriptor privilege level."""
        self.raw = (self.raw & ~(3 << 5)) | (value << 5)

    @property
    def P(self) -> bool:
        """Return whether the descriptor is present."""
        return bool(self.raw & (1 << 7))

    @P.setter
    def P(self, value: bool | int) -> None:
        """Set whether the descriptor is present."""
        self.raw = (self.raw & ~(1 << 7)) | (int(value) << 7)

    @property
    def AVL(self) -> bool:
        """Return the available-for-system-software flag."""
        return bool(self.raw & (1 << 8))

    @AVL.setter
    def AVL(self, value: bool | int) -> None:
        """Set the available-for-system-software flag."""
        self.raw = (self.raw & ~(1 << 8)) | (int(value) << 8)

    @property
    def DB(self) -> bool:
        """Return the default operand-size flag."""
        return bool(self.raw & (1 << 10))

    @DB.setter
    def DB(self, value: bool | int) -> None:
        """Set the default operand-size flag."""
        self.raw = (self.raw & ~(1 << 10)) | (int(value) << 10)

    @property
    def G(self) -> bool:
        """Return the descriptor granularity flag."""
        return bool(self.raw & (1 << 11))

    @G.setter
    def G(self, value: bool | int) -> None:
        """Set the descriptor granularity flag."""
        self.raw = (self.raw & ~(1 << 11)) | (int(value) << 11)


# Segment register structure
class SGRegister:
    """Segment selector and cached descriptor state."""

    def __init__(self) -> None:
        """Initialize a zero segment selector."""
        self.raw: int = 0  # Raw segment selector value
        self.cache: SGRegCache = SGRegCache()  # Cached segment descriptor information

    @property
    def RPL(self) -> int:
        """Return the selector requested privilege level."""
        return self.raw & 3

    @RPL.setter
    def RPL(self, value: int) -> None:
        """Set the selector requested privilege level."""
        self.raw = (self.raw & ~3) | (value & 3)

    @property
    def TI(self) -> bool:
        """Return whether the selector targets the LDT."""
        return bool(self.raw & (1 << 2))

    @TI.setter
    def TI(self, value: bool | int) -> None:
        """Set whether the selector targets the LDT."""
        self.raw = (self.raw & ~(1 << 2)) | (int(value) << 2)

    @property
    def index(self) -> int:
        """Return the selector table index."""
        return (self.raw >> 3) & 0x1FFF

    @index.setter
    def index(self, value: int) -> None:
        """Set the selector table index."""
        self.raw = (self.raw & 0x7) | ((value & 0x1FFF) << 3)


# Descriptor table register structure
class DTRegister:
    """Descriptor table register storage."""

    def __init__(self) -> None:
        """Initialize an empty descriptor table register."""
        self.selector: int = 0  # Selector for LDTR and TR
        self.base: int = 0  # Base address of the descriptor table
        self.limit: int = 0  # Limit of the descriptor table


# Processor class
class Processor(Eflags, CR):  # type: ignore[misc, unused-ignore] # dynamic frontend mixins
    """Concrete/VEX processor register model used by the X86_16 frontend."""

    def __init__(self) -> None:
        """Initialize reset-state processor registers and descriptor caches."""
        super().__init__()
        self.lifter_instruction: Any | None = None
        self.vex_offsets: dict[str, int] | None = None
        self._is_mode32: bool = False
        self._last_condition: object | None = None
        self.flags: int = 0
        self.eip: int = 0  # X86Instruction pointer
        self.gpregs: list[GPRegister] = [
            GPRegister() for _ in range(reg32_t.GPREGS_COUNT.value)
        ]  # General-purpose registers
        self.sgregs: list[SGRegister] = [SGRegister() for _ in range(sgreg_t.SGREGS_COUNT.value)]  # Segment registers
        self.dtregs: list[DTRegister] = [
            DTRegister() for _ in range(dtreg_t.DTREGS_COUNT.value)
        ]  # Descriptor table registers

        self.halt: bool = False

        self.set_eip(0xFFFF0)
        self.set_crn(0, 0x60000010)
        self.set_eflags(2)

        self.sgregs[sgreg_t.CS.value].raw = 0xF000
        self.sgregs[sgreg_t.CS.value].cache.base = 0xFFFF0000
        self.sgregs[sgreg_t.CS.value].cache.flags.type = 0x18  # Code segment
        for i in range(sgreg_t.SGREGS_COUNT.value):
            self.sgregs[i].cache.limit = 0xFFFF
            self.sgregs[i].cache.flags.P = 1
            self.sgregs[i].cache.flags.S = 1
            self.sgregs[i].cache.flags.type = 0x10  # Data segment

        self.dtregs[dtreg_t.IDTR.value].base = 0
        self.dtregs[dtreg_t.IDTR.value].limit = 0xFFFF
        self.dtregs[dtreg_t.GDTR.value].base = 0
        self.dtregs[dtreg_t.GDTR.value].limit = 0xFFFF
        self.dtregs[dtreg_t.LDTR.value].base = 0
        self.dtregs[dtreg_t.LDTR.value].limit = 0xFFFF

    def set_last_condition(self, condition: object) -> None:
        """Remember the most recent frontend condition expression."""
        self._last_condition = condition

    def get_last_condition(self) -> object | None:
        """Return the most recent frontend condition expression, if any."""
        return self._last_condition

    def clear_last_condition(self) -> None:
        """Clear the remembered frontend condition expression."""
        self._last_condition = None

    def dump_regs(self) -> None:
        """Print a human-readable register dump for debugging."""
        gpreg_name = ["EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"]
        sgreg_name = ["ES", "CS", "SS", "DS", "FS", "GS"]
        dtreg_name = ["GDTR", "IDTR", "LDTR", " TR "]

        print(f"EIP = 0x{self.eip:08x}")
        for i in range(reg32_t.GPREGS_COUNT.value):
            print(
                f"{gpreg_name[i]} = 0x{self.gpregs[i].reg32:08x} : 0x{self.gpregs[i].reg16:04x} (0x{self.gpregs[i].reg8_h:02x}/0x{self.gpregs[i].reg8_l:02x})",
            )
        print(f"EFLAGS = 0x{self.get_eflags():08x}")

        for i in range(sgreg_t.SGREGS_COUNT.value):
            cache = self.sgregs[i].cache
            print(
                f"{sgreg_name[i]} = 0x{self.sgregs[i].raw:04x} {{base = 0x{cache.base:08x}, limit = {cache.limit:08x}, flags = {cache.flags.raw:04x}}}",
            )

        for i in range(dtreg_t.LDTR.value):
            print(
                f"{dtreg_name[i]} =        {{base = 0x{self.dtregs[i].base:08x}, limit = {self.dtregs[i].limit:08x}}}",
            )
        for i in range(dtreg_t.LDTR.value, dtreg_t.DTREGS_COUNT.value):
            print(
                f"{dtreg_name[i]} = 0x{self.dtregs[i].selector:04x} {{base = 0x{self.dtregs[i].base:08x}, limit = {self.dtregs[i].limit:08x}}}",
            )

        for i in range(5):
            print(f"CR{i}=0x{self.get_crn(i):08x} ", end="")
        print()

    def get_eip(self) -> int:
        """Return the concrete 32-bit instruction pointer."""
        return self.eip

    @staticmethod
    def _reg8_base(reg: reg8_t) -> reg16_t:
        return reg16_t(reg.value & 0b11)

    @staticmethod
    def _reg8_is_high(reg: reg8_t) -> bool:
        return bool(reg.value >= 4)

    def get_ip(self) -> RegisterValue:
        """Return the 16-bit instruction pointer view."""
        if self.lifter_instruction is None:
            return self.eip & 0xFFFF
        if self.vex_offsets is None:
            raise ValueError("vex_offsets not initialized for lifting mode")
        offset = self.vex_offsets.get("ip", 0)
        return VexValue(self.lifter_instruction, self.lifter_instruction.rdreg(offset, Type.int_16))

    def get_gpreg(self, n: reg8_t | reg16_t | reg32_t | VexValue) -> RegisterValue:
        """Return a general-purpose register in concrete or VEX lifting mode."""

        def _impl() -> RegisterValue:
            if isinstance(n, VexValue):
                if self.lifter_instruction is not None:
                    return n
                raise ValueError("Cannot get gpreg from a non-constant VexValue without an active lifter instruction")
            name = register_name_8616(n)
            if isinstance(n, reg8_t):
                if self.lifter_instruction is not None:
                    if self.vex_offsets is None:
                        raise ValueError("vex_offsets not initialized for lifting mode")
                    base_name = register_name_8616(self._reg8_base(n))
                    offset = self.vex_offsets[base_name] + int(self._reg8_is_high(n))
                    return VexValue(self.lifter_instruction, self.lifter_instruction.rdreg(offset, Type.int_8))
                base = self.get_gpreg(self._reg8_base(n))
                if not isinstance(base, int):
                    raise TypeError("Concrete register reads must return integers")
                if self._reg8_is_high(n):
                    return (base >> 8) & 0xFF
                return base & 0xFF
            if self.lifter_instruction is not None:
                if self.vex_offsets is None:
                    raise ValueError("vex_offsets not initialized for lifting mode")
                offset = self.vex_offsets.get(name, 0)
                return VexValue(self.lifter_instruction, self.lifter_instruction.rdreg(offset, TYPES[type(n)]))
            # concrete mode
            if isinstance(n, reg32_t):
                idx = n.value
                if idx < reg32_t.GPREGS_COUNT.value:
                    return self.gpregs[idx].reg32
                elif idx == reg32_t.EIP.value:
                    return self.eip
                elif idx == reg32_t.EFLAGS.value:
                    return self.flags
            elif isinstance(n, reg16_t):
                idx = n.value
                if idx < reg32_t.GPREGS_COUNT.value:  # 8 for 16-bit views
                    return self.gpregs[idx].reg16
                elif idx == reg16_t.IP.value:
                    return self.eip & 0xFFFF
                elif idx == reg16_t.FLAGS.value:
                    return self.flags & 0xFFFF
            raise ValueError(f"Cannot get gpreg {n} without lifter_instruction in concrete mode")

        return _impl()

    def constant(self, n: int, type_: object = Type.int_8) -> RegisterValue:
        """Keep concrete values; encode lifted integers as width-bounded bits."""
        if self.lifter_instruction is not None:
            if is_int_ty(type_):
                n &= (1 << get_type_size(type_)) - 1
            return VexValue(self.lifter_instruction, self.lifter_instruction.mkconst(n, type_))
        return n

    def get_direction_step(self, value_type: object = Type.int_16) -> RegisterValue:
        """Return the architectural string-index step as ``+1`` or ``-1``."""
        if self.lifter_instruction is None:
            return -1 if self.flags & 0x0400 else 1
        flags = self.get_gpreg(reg16_t.FLAGS)
        return cast(RegisterValue, self._lifted_direction_step_from_flags(flags).cast_to(value_type))

    def _lifted_direction_step_from_flags(self, flags_value: object) -> VexValue:
        """Derive the lifted string-index step from authoritative architectural FLAGS."""
        if self.lifter_instruction is None:
            raise RuntimeError("Lifted direction-step recovery requires an active lifter instruction")
        return lifted_direction_step_8616(self.lifter_instruction, flags_value)

    def _sync_lifted_direction_step(self, flags_value: object) -> None:
        """Synchronize the derived artificial VEX direction step after a FLAGS write."""
        if self.lifter_instruction is None:
            return
        if self.vex_offsets is None:
            raise ValueError("vex_offsets not initialized for lifting mode")
        step = self._lifted_direction_step_from_flags(flags_value)
        self.lifter_instruction._append_stmt(Put(step.rdt, self.vex_offsets["d"]))

    def get_sgreg(self, n: sgreg_t | VexValue) -> RegisterValue:
        """Return a segment register in concrete or VEX lifting mode."""
        if isinstance(n, VexValue):
            if self.lifter_instruction is not None:
                return n
            raise ValueError("Cannot get sgreg from a non-constant VexValue without an active lifter instruction")
        name = register_name_8616(n)
        if self.lifter_instruction is not None:
            if self.vex_offsets is None:
                raise ValueError("vex_offsets not initialized for lifting mode")
            offset = self.vex_offsets.get(name, 0)
            return VexValue(self.lifter_instruction, self.lifter_instruction.rdreg(offset, Type.int_16))
        return self.sgregs[n.value].raw

    def get_segment(self, n: sgreg_t | VexValue) -> RegisterValue:
        """Return a segment register alias."""
        return self.get_sgreg(n)

    def get_carry(self) -> RegisterValue:
        """Return the carry flag value from FLAGS bit 0."""
        flags = self.get_gpreg(reg16_t.FLAGS)
        if isinstance(flags, int):
            return flags & 1
        return cast(RegisterValue, flags[0])

    def set_carry_flag(self, flags: object, carry: object) -> object:
        """Set the carry flag and return the updated FLAGS value."""
        flags = super().set_carry(flags, carry)
        self.set_gpreg(reg16_t.FLAGS, flags)
        return flags

    def set_overflow_flag(self, flags: object, overflow: object) -> object:
        """Set the overflow flag and return the updated FLAGS value."""
        flags = super().set_overflow(flags, overflow)
        self.set_gpreg(reg16_t.FLAGS, flags)
        return flags

    def get_dtreg_selector(self, n: int) -> int:
        """Return a descriptor table register selector."""
        # assert n < dtreg_t.DTREGS_COUNT.value
        return self.dtregs[n].selector

    def get_dtreg_base(self, n: int) -> int:
        """Return a descriptor table base address."""
        assert n < dtreg_t.DTREGS_COUNT.value
        return self.dtregs[n].base

    def get_dtreg_limit(self, n: int) -> int:
        """Return a descriptor table limit."""
        assert n < dtreg_t.DTREGS_COUNT.value
        return self.dtregs[n].limit

    def set_eip(self, value: object) -> None:
        """Set the 32-bit instruction pointer."""
        self.set_gpreg(reg32_t.EIP, value)

    def set_ip(self, value: object) -> None:
        """Set the 16-bit instruction pointer view."""
        if self.lifter_instruction is None:
            if not isinstance(value, int):
                raise TypeError(f"Cannot set IP from non-concrete value of type {type(value)} in concrete mode")
            self.eip = (self.eip & 0xFFFF0000) | (value & 0xFFFF)
            return
        self.set_gpreg(reg16_t.IP, value)

    def set_gpreg(self, n: object, value: object) -> None:
        """Set a general-purpose register in concrete or VEX lifting mode."""
        if not isinstance(n, (reg8_t, reg16_t, reg32_t)):
            raise TypeError(f"Unsupported general-purpose register {n!r}")

        def _impl() -> None:
            nonlocal value
            name = register_name_8616(n)
            if isinstance(n, reg8_t):
                base_reg = self._reg8_base(n)
                if self.lifter_instruction is not None:
                    if self.vex_offsets is None:
                        raise ValueError("vex_offsets not initialized for lifting mode")
                    base_name = register_name_8616(base_reg)
                    offset = self.vex_offsets[base_name] + int(self._reg8_is_high(n))
                    if isinstance(value, int):
                        value = self.constant(value, Type.int_8)
                    if isinstance(value, VexValue):
                        value = cast(VexValue, value.cast_to(Type.int_8)).rdt
                    self.lifter_instruction._append_stmt(Put(cast(Any, value), offset))
                    return

                if not isinstance(value, int):
                    raise TypeError(f"Cannot set {n} from non-concrete value of type {type(value)} in concrete mode")
                idx = base_reg.value
                if self._reg8_is_high(n):
                    self.gpregs[idx].reg8_h = value
                else:
                    self.gpregs[idx].reg8_l = value
                return
            if self.lifter_instruction is not None:
                if self.vex_offsets is None:
                    raise ValueError("vex_offsets not initialized for lifting mode")
                offset = self.vex_offsets.get(name, 0)
                is_flags_register = (
                    (isinstance(n, reg16_t) and n is reg16_t.FLAGS)
                    or (isinstance(n, reg32_t) and n is reg32_t.EFLAGS)
                )
                flags_value = value if is_flags_register else None
                if isinstance(value, int):
                    value = self.constant(value, TYPES[type(n)])
                if isinstance(value, VexValue):
                    value = value.rdt
                self.lifter_instruction._append_stmt(Put(cast(Any, value), offset))
                if flags_value is not None:
                    self._sync_lifted_direction_step(flags_value)
                return
            # concrete mode
            if isinstance(value, int):
                if isinstance(n, reg32_t):
                    idx = n.value
                    if idx < reg32_t.GPREGS_COUNT.value:
                        self.gpregs[idx].reg32 = value
                    elif idx == reg32_t.EIP.value:
                        self.eip = value
                    elif idx == reg32_t.EFLAGS.value:
                        self.flags = value
                    return
                elif isinstance(n, reg16_t):
                    idx = n.value
                    if idx < reg32_t.GPREGS_COUNT.value:
                        self.gpregs[idx].reg16 = value
                    elif idx == reg16_t.IP.value:
                        self.eip = (self.eip & 0xFFFF0000) | (value & 0xFFFF)
                    elif idx == reg16_t.FLAGS.value:
                        self.flags = (self.flags & 0xFFFF0000) | (value & 0xFFFF)
                    return
            raise TypeError(f"Cannot set {n} from non-concrete value of type {type(value)} in concrete mode")

        return _impl()

    def set_sgreg(self, n: sgreg_t, reg: object) -> None:
        """Set a segment register in concrete or VEX lifting mode."""
        name = register_name_8616(n)
        if self.lifter_instruction is not None:
            if self.vex_offsets is None:
                raise ValueError("vex_offsets not initialized for lifting mode")
            offset = self.vex_offsets.get(name, 0)
            if isinstance(reg, int):
                reg = self.constant(reg, Type.int_16)
            if isinstance(reg, VexValue):
                reg = reg.rdt
            self.lifter_instruction._append_stmt(Put(cast(Any, reg), offset))
            return
        if isinstance(reg, (Get, Const, Binop, Load, Unop)):
            return
        if not isinstance(reg, int):
            raise TypeError(f"Cannot set segment {n} from non-concrete value of type {type(reg)}")
        self.sgregs[n.value].raw = reg

    def set_segment(self, n: sgreg_t, value: object) -> None:
        """Set a segment register alias."""
        self.set_sgreg(n, value)

    def set_dtreg(self, n: int, sel: int, base: int, limit: int) -> None:
        """Set a descriptor table register."""
        assert n < dtreg_t.DTREGS_COUNT.value
        self.dtregs[n].selector = sel
        self.dtregs[n].base = base
        self.dtregs[n].limit = limit

    def update_eip(self, value: object) -> RegisterValue:
        """Add a value to EIP and return the updated value."""
        return self.update_gpreg(reg32_t.EIP, value)

    def update_ip(self, value: object) -> RegisterValue:
        """Add a value to IP and return the updated value."""
        return self.update_gpreg(reg16_t.IP, value)

    def update_gpreg(self, n: reg16_t | reg32_t, value: object) -> RegisterValue:
        """Apply a register delta, retaining known decrements as typed subtraction."""
        result = self.get_gpreg(n)
        if self.lifter_instruction is not None:
            if isinstance(value, int):
                amount = self.constant(abs(value), TYPES[type(n)])
                result = result - amount if value < 0 else result + amount
            else:
                if not isinstance(value, VexValue):
                    value = VexValue(self.lifter_instruction, self.lifter_instruction._settmp(value))
                result = result + cast(VexValue, value)
        else:
            if not isinstance(result, int) or not isinstance(value, int):
                raise TypeError("Concrete register update requires concrete integer values")
            result = result + value
        self.set_gpreg(n, result)
        return result

    def is_halt(self) -> bool:
        """Return whether the processor is halted."""
        return self.halt

    def do_halt(self, h: bool) -> None:
        """Set the processor halt state."""
        self.halt = h

    def is_mode32(self) -> bool:
        """Return whether the frontend currently executes 32-bit code."""
        return self._is_mode32

    def set_mode32(self, value: bool) -> None:
        """Set the processor width mode for next instruction decode."""
        self._is_mode32 = bool(value)

    def set_lifter_instruction(self, lifter_instruction: object | None) -> None:
        """Set the active PyVEX lifter instruction context."""
        self.lifter_instruction = cast(Any | None, lifter_instruction)
