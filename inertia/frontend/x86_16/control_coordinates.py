"""Architectural return offsets and loader control coordinates.

Layer: frontend control semantics.
Responsibility: own the conversion between CS-relative IP/EIP values stored
in architectural return frames and loader-linear VEX control destinations.
CALL saves an offset; RET composes that offset with CS. Concrete and symbolic
frontend execution use the same width and segment rules.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import IntEnum, StrEnum
from typing import Protocol, cast

from pyvex.lifting.util.vex_helper import Type


class ControlWidth(IntEnum):
    """Explicit width of a saved offset or a frontend control projection."""

    WORD = 16
    DWORD = 32


class ControlAddressDomain(StrEnum):
    """Coordinate supplied by the execution adapter for instruction/control PC.

    Loader analysis supplies linear loaded addresses. Native instruction
    execution supplies architectural offsets. This affects PC projection,
    never the ISA value stored in a return frame or the segment registers.
    """

    LOADER_LINEAR = "loader_linear"
    ARCHITECTURAL_OFFSET = "architectural_offset"


class NearTargetDomain(StrEnum):
    """Coordinate of a near branch operand before execution-domain projection.

    Relative decoding already produces execution control. Register and memory
    operands hold architectural IP/EIP offsets, requiring CS in loader mode.
    """

    EXECUTION_CONTROL = "execution_control"
    ARCHITECTURAL_OFFSET = "architectural_offset"


class CoordinateExpr(Protocol):
    """Typed arithmetic surface of a symbolic frontend control value."""

    def __add__(self, other: object) -> CoordinateExpr:
        """Build a bitvector sum."""
        ...

    def __sub__(self, other: object) -> CoordinateExpr:
        """Build a bitvector difference."""
        ...

    def __lshift__(self, other: object) -> CoordinateExpr:
        """Shift by the VEX-required eight-bit count."""
        ...

    def cast_to(self, ty: object) -> CoordinateExpr:
        """Project or extend to an explicit VEX width."""
        ...


type CoordinateValue = int | CoordinateExpr
type CoordinateConstant = Callable[[object, object], CoordinateExpr]


def _expression(value: CoordinateValue, ty: object, constant: CoordinateConstant) -> CoordinateExpr:
    """Represent concrete and symbolic operands at the requested width."""
    return constant(value, ty) if isinstance(value, int) else value.cast_to(ty)


def _type_for(width: ControlWidth) -> str:
    """Choose the VEX type for an explicitly declared control width."""
    if width is ControlWidth.WORD:
        return cast(str, Type.int_16)
    if width is ControlWidth.DWORD:
        return cast(str, Type.int_32)
    raise ValueError("control width must be WORD or DWORD")


def architectural_offset(
    linear: CoordinateValue, cs: CoordinateValue, width: ControlWidth,
    constant: CoordinateConstant, *,
    domain: ControlAddressDomain = ControlAddressDomain.LOADER_LINEAR,
) -> CoordinateValue:
    """Compute the exact saved IP/EIP, with modular architectural width.

    A loaded instruction address is not a saved return word. The saved value
    is ``linear_next - (CS << 4)`` modulo the operand width. The CS register
    remains a sixteen-bit segment selector even for a dword return frame.
    """
    ty = _type_for(width)
    if domain is ControlAddressDomain.ARCHITECTURAL_OFFSET:
        if isinstance(linear, int):
            return linear & ((1 << width.value) - 1)
        return linear.cast_to(ty)
    if isinstance(linear, int) and isinstance(cs, int):
        return (linear - ((cs & 0xFFFF) << 4)) & ((1 << width.value) - 1)
    address = _expression(linear, Type.int_32, constant)
    segment = _expression(cs, Type.int_16, constant).cast_to(Type.int_32)
    base = segment << constant(4, Type.int_8)
    return (address - base).cast_to(ty)


def linear_continuation(
    cs: CoordinateValue, offset: CoordinateValue, offset_width: ControlWidth,
    constant: CoordinateConstant, *, control_width: ControlWidth = ControlWidth.DWORD,
    domain: ControlAddressDomain = ControlAddressDomain.LOADER_LINEAR,
) -> CoordinateValue:
    """Compose a saved offset with CS into an explicit VEX control domain.

    Loader-linear execution requires dword control to retain the complete
    physical destination, including for word return offsets. Word projection
    is available only for explicitly declared compatibility observations;
    it must not replace a loaded control destination. Neither projection
    changes the offset stored in guest memory.
    """
    offset_ty, control_ty = _type_for(offset_width), _type_for(control_width)
    if domain is ControlAddressDomain.ARCHITECTURAL_OFFSET:
        if isinstance(offset, int):
            return offset & ((1 << offset_width.value) - 1) & ((1 << control_width.value) - 1)
        return offset.cast_to(offset_ty).cast_to(control_ty)
    if isinstance(cs, int) and isinstance(offset, int):
        value = ((cs & 0xFFFF) << 4) + (offset & ((1 << offset_width.value) - 1))
        return value & ((1 << control_width.value) - 1)
    segment = _expression(cs, Type.int_16, constant).cast_to(Type.int_32)
    ip = _expression(offset, offset_ty, constant).cast_to(Type.int_32)
    return ((segment << constant(4, Type.int_8)) + ip).cast_to(control_ty)


def relative_offset(
    linear_next: CoordinateValue, cs: CoordinateValue,
    displacement: CoordinateValue, width: ControlWidth,
    constant: CoordinateConstant, *,
    domain: ControlAddressDomain = ControlAddressDomain.LOADER_LINEAR,
) -> CoordinateValue:
    """Add a relative displacement after projecting to architectural IP/EIP.

    Width wrapping applies to the CS-relative offset, never to a loader page.
    The result is an architectural offset, not a loaded destination.
    """
    offset = architectural_offset(linear_next, cs, width, constant, domain=domain)
    mask = (1 << width.value) - 1
    displacement_bits = displacement & mask if isinstance(displacement, int) else displacement
    if isinstance(offset, int) and isinstance(displacement_bits, int):
        return (offset + displacement_bits) & mask
    ty = _type_for(width)
    return (_expression(offset, ty, constant)
            + _expression(displacement_bits, ty, constant)).cast_to(ty)


def relative_continuation(
    linear_next: CoordinateValue, cs: CoordinateValue,
    displacement: CoordinateValue, width: ControlWidth,
    constant: CoordinateConstant, *,
    domain: ControlAddressDomain = ControlAddressDomain.LOADER_LINEAR,
) -> CoordinateValue:
    """Compose a width-wrapped relative IP/EIP into full loaded control."""
    offset = relative_offset(linear_next, cs, displacement, width, constant, domain=domain)
    return linear_continuation(cs, offset, width, constant,
                               control_width=ControlWidth.DWORD, domain=domain)
