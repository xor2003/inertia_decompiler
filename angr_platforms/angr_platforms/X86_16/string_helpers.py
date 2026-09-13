"""Layer: Helper boundary (frontend instruction execution).

Responsibility: execute string-instruction repeat, segment, direction, and branch helper effects.
Forbidden: replacing string-instruction semantics with source-backed or rendered-C rewrites.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, TypeGuard, cast, runtime_checkable

from pyvex.lifting.util import JumpKind
from pyvex.lifting.util.vex_helper import Type

from .alu_helpers import compare_operation
from .instruction import REPNZ, REPZ
from .regs import reg16_t, reg32_t, sgreg_t

_WORD_BYTES = 2
_DWORD_BYTES = 4
_WIDE_ADDRESS_BITS = 32


@runtime_checkable
class _RdtCarrier(Protocol):
    rdt: object


class _CastableToRdt(Protocol):
    rdt: object

    def cast_to(self, ty: object) -> object:
        """Return this expression cast to the requested VEX helper type."""
        ...


class _AddSubValue(Protocol):
    def __add__(self, other: object) -> object:
        """Return this VEX value plus another helper value."""
        ...

    def __sub__(self, other: object) -> object:
        """Return this VEX value minus another helper value."""
        ...


class _AndValue(Protocol):
    def __and__(self, other: object) -> object:
        """Return this VEX condition conjoined with another helper value."""
        ...


class _StringIrsbCustomizer(Protocol):
    def ite(self, _condition: object, _when_true: object, _when_false: object) -> object:
        """Return a VEX if-then-else expression."""
        ...


class StringInstruction(Protocol):
    """Decoded string-instruction metadata consumed by shared helpers."""

    @property
    def pre_segment(self) -> sgreg_t | None:
        """Return the optional decoded segment override."""
        ...

    @property
    def pre_repeat(self) -> int:
        """Return the decoded repeat-prefix value."""
        ...

    @property
    def repeat_class(self) -> str:
        """Return the normalized repeat-prefix class."""
        ...

    @property
    def address_bits(self) -> int:
        """Return the effective string address width."""
        ...

    @property
    def mode32(self) -> bool:
        """Return whether string indices use 32-bit registers."""
        ...

    @property
    def size(self) -> int:
        """Return the encoded instruction size including prefixes."""
        ...


class _StringLifterInstruction(Protocol):
    addr: int
    irsb_c: _StringIrsbCustomizer

    def jump(self, _condition: object, _target: object, _jumpkind: object) -> None:
        """Emit a VEX jump for the active string instruction."""
        ...

    def record_loop_counter_condition_8616(
        self,
        counter_name: str,
        counter_size: int,
        displacement: int,
        instruction_size: int,
    ) -> None:
        """Publish an exact typed post-decrement counter continuation."""
        ...


class StringEmulator(Protocol):
    """Active VEX emulator surface required by string-instruction helpers."""

    lifter_instruction: _StringLifterInstruction

    def is_direction(self) -> _CastableToRdt:
        """Return the current direction-flag expression."""
        ...

    def get_direction_step(self, value_type: object = Type.int_16) -> object:
        """Return the normalized architectural string-index step."""
        ...

    def constant(self, value: int, ty: object) -> object:
        """Return a VEX constant wrapper for the requested helper type."""
        ...

    def _vv(self, expr: object) -> object:
        """Wrap a raw VEX expression in the emulator's value carrier."""
        ...

    def get_gpreg(self, reg: object) -> object:
        """Read a general-purpose register from emulator state."""
        ...

    def set_gpreg(self, reg: object, value: object) -> None:
        """Write a general-purpose register in emulator state."""
        ...

    def is_zero(self) -> object:
        """Return the current zero-flag expression."""
        ...

    def get_data8(self, segment: sgreg_t, offset: object) -> object:
        """Read an 8-bit segmented value."""
        ...

    def get_data16(self, segment: sgreg_t, offset: object) -> object:
        """Read a 16-bit segmented value."""
        ...

    def get_data32(self, segment: sgreg_t, offset: object) -> object:
        """Read a 32-bit segmented value."""
        ...

    def put_data8(self, segment: sgreg_t, offset: object, value: object) -> None:
        """Store an 8-bit segmented value."""
        ...

    def put_data16(self, segment: sgreg_t, offset: object, value: object) -> None:
        """Store a 16-bit segmented value."""
        ...

    def put_data32(self, segment: sgreg_t, offset: object, value: object) -> None:
        """Store a 32-bit segmented value."""
        ...


def _has_rdt(value: object) -> TypeGuard[_RdtCarrier]:
    return isinstance(value, _RdtCarrier)


def _rdt_or_self(value: object) -> object:
    return value.rdt if _has_rdt(value) else value


def string_delta(emu: StringEmulator, width: int, value_type: str = Type.int_16) -> object:
    """Return a width-typed signed index delta implied by the direction flag."""
    step = cast(_AddSubValue, emu.get_direction_step(value_type))
    if width == 1:
        return step
    doubled = cast(_AddSubValue, step + step)
    return doubled if width == _WORD_BYTES else doubled + doubled


def string_source_segment(instr: StringInstruction) -> sgreg_t:
    """Return the source segment for a string instruction."""
    if instr.pre_segment is not None:
        return sgreg_t(instr.pre_segment)
    return sgreg_t.DS


def repeat_kind(instr: StringInstruction) -> str:
    """Return the normalized repeat prefix class for a string instruction."""
    normalized = instr.repeat_class
    if normalized not in (None, ""):
        return normalized
    if instr.pre_repeat == REPZ:
        return "repz"
    if instr.pre_repeat == REPNZ:
        return "repnz"
    return "none"


def repeat_prefix_cond(emu: StringEmulator, instr: StringInstruction) -> _CastableToRdt | bool | None:
    """Consume CX and return whether a repeated string operation should continue."""
    if repeat_kind(instr) == "none":
        return None

    counter_reg = reg32_t.ECX if instr.address_bits == _WIDE_ADDRESS_BITS else reg16_t.CX
    counter_type = Type.int_32 if instr.address_bits == _WIDE_ADDRESS_BITS else Type.int_16
    counter = cast(_AddSubValue, emu.get_gpreg(counter_reg))
    zero = emu.constant(0, counter_type)
    execute_operation = counter != zero
    fallthrough = emu.constant(emu.lifter_instruction.addr + instr.size, Type.int_32)
    if isinstance(execute_operation, bool):
        if not execute_operation:
            emu.lifter_instruction.jump(None, fallthrough, JumpKind.Boring)
    else:
        repeat_target = emu.constant(emu.lifter_instruction.addr, Type.int_32)
        emu.lifter_instruction.jump(execute_operation, repeat_target, JumpKind.Boring)
    # Re-read after the conditional Exit so AIL block splitting cannot strand
    # a VEX temporary defined only in the predecessor block.
    remaining_counter = cast(_AddSubValue, emu.get_gpreg(counter_reg))
    remaining = remaining_counter - emu.constant(1, counter_type)
    emu.set_gpreg(counter_reg, remaining)
    return cast(_CastableToRdt | bool, remaining != zero)


def repeat_jump(
    emu: StringEmulator,
    instr: StringInstruction,
    repeat_cond: _CastableToRdt | bool | None,
    zf_sensitive: bool = False,
) -> None:
    """Use the header count guard for non-comparing REP, preserving native SSA.

    An internal zero-count exit plus a conditional tail confuses native
    head-controlled-loop state selection. Count-only operations return to the
    existing header guard; compare/scan operations still need their ZF test.
    """
    if repeat_cond is None:
        return

    cond: object = repeat_cond if isinstance(repeat_cond, bool) else repeat_cond.cast_to(Type.int_1)
    if not zf_sensitive:
        known_condition = cond if isinstance(cond, bool) else cond.rdt if _has_rdt(cond) else None
        if known_condition is not False:
            repeat_target = emu.constant(emu.lifter_instruction.addr, Type.int_32)
            emu.lifter_instruction.jump(None, repeat_target, JumpKind.Boring)
        return
    kind = repeat_kind(instr)
    if kind == "repz":
        cond = cast(_AndValue, cond) & emu.is_zero()
    elif kind == "repnz":
        cond = cast(_AndValue, cond) & (emu.is_zero() == emu.constant(0, Type.int_1))
    repeat_target = emu.constant(emu.lifter_instruction.addr, Type.int_32)
    if isinstance(cond, bool):
        if not cond:
            return
        emu.lifter_instruction.jump(None, repeat_target, JumpKind.Boring)
        return
    cond_value = cond.rdt if _has_rdt(cond) else None

    if isinstance(cond_value, bool):
        if not cond_value:
            return
        emu.lifter_instruction.jump(None, repeat_target, JumpKind.Boring)
        return

    emu.lifter_instruction.jump(cond, repeat_target, JumpKind.Boring)


def string_advance_indices(emu: StringEmulator, width: int, *regs: object) -> object:
    """Advance each string index register according to direction flag and width."""
    delta: object | None = None
    for reg in regs:
        delta = string_delta(emu, width, Type.int_32 if isinstance(reg, reg32_t) else Type.int_16)
        emu.set_gpreg(reg, cast(_AddSubValue, emu.get_gpreg(reg)) + delta)
    return delta if delta is not None else string_delta(emu, width)


def string_compare_values(lhs: object, rhs: object, update_flags: Callable[[object, object], object]) -> None:
    """Compare two string operands through the caller-provided flag updater."""
    compare_operation(lambda: lhs, lambda: rhs, update_flags)


def string_load(emu: StringEmulator, segment: sgreg_t, offset: object, width: int) -> object:
    """Load a segmented string operand with the requested width."""
    if width == 1:
        return emu.get_data8(segment, offset)
    if width == _WORD_BYTES:
        return emu.get_data16(segment, offset)
    if width == _DWORD_BYTES:
        return emu.get_data32(segment, offset)
    raise ValueError(f"unsupported string width: {width}")


def string_store(emu: StringEmulator, segment: sgreg_t, offset: object, value: object, width: int) -> None:
    """Store a segmented string operand with the requested width."""
    if width == 1:
        emu.put_data8(segment, offset, value)
        return
    if width == _WORD_BYTES:
        emu.put_data16(segment, offset, value)
        return
    if width == _DWORD_BYTES:
        emu.put_data32(segment, offset, value)
        return
    raise ValueError(f"unsupported string width: {width}")
