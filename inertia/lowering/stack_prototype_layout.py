"""Project typed function prototypes onto the 16-bit BP stack ABI.

Layer: Types/Lowering.
Responsibility: derive exact contiguous stack slots from already-owned argument
types so contained word views do not become duplicate function arguments.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Forbidden: assembly, source, symbol-name, or rendered-C inference.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimType, SimTypeFunction
from angr.sim_variable import SimStackVariable
from archinfo import Arch

from .argument_frame_base import proven_first_argument_machine_bp_offset_8616
from .stack_storage_evidence import proven_bp_entry_sp_delta_8616


@dataclass(frozen=True, slots=True)
class StackPrototypeArgument8616:
    """One typed argument's exact storage slot in a near-call BP frame."""

    offset: int
    storage_width: int
    argument_type: SimType


class _PrototypeCFunction8616(Protocol):
    """Third-party C-function fields used to resolve one argument owner."""

    arg_list: Sequence[object] | None
    functy: object
    prototype: object


class _PrototypeProject8616(Protocol):
    """Third-party project field used for ABI type widths."""

    arch: Arch


class _PrototypeCodegen8616(Protocol):
    """Third-party codegen fields used for exact argument resolution."""

    cfunc: _PrototypeCFunction8616 | None
    project: _PrototypeProject8616


def stack_prototype_argument_layout_8616(
    prototype: object,
    arch: Arch,
    *,
    first_argument_bp_offset: int = 4,
) -> tuple[StackPrototypeArgument8616, ...]:
    """Return a contiguous argument layout, or no layout when a type lacks size evidence.

    ``first_argument_bp_offset`` is the proven machine-BP argument base: 4 for a
    near frame and 6 for a far frame whose retf reserves ``BP+4..+5`` for CS.
    """
    if not isinstance(prototype, SimTypeFunction):
        return ()
    byte_width = arch.byte_width
    if not isinstance(byte_width, int) or byte_width <= 0:
        return ()
    cursor = first_argument_bp_offset
    layout: list[StackPrototypeArgument8616] = []
    for raw_type in prototype.args or ():
        if not isinstance(raw_type, SimType):
            return ()
        argument_type = raw_type
        try:
            if argument_type._arch is None:  # third-party SimType boundary
                argument_type = cast(SimType, argument_type.with_arch(arch))
            size_bits = argument_type.size
        except (AttributeError, TypeError, ValueError):
            return ()
        if not isinstance(size_bits, int) or size_bits <= 0 or size_bits % byte_width != 0:
            return ()
        value_width = size_bits // byte_width
        storage_width = max(2, (value_width + 1) & ~1)
        layout.append(StackPrototypeArgument8616(cursor, storage_width, argument_type))
        cursor += storage_width
    return tuple(layout)


def stack_prototype_cvar_for_machine_bp_range_8616(
    codegen: object,
    bp_offset: int,
    size: int,
) -> structured_c.CVariable | None:
    """Resolve one exact argument CVariable without mutating global coordinates."""
    try:
        boundary = cast(_PrototypeCodegen8616, codegen)
        cfunc = boundary.cfunc
        arch = boundary.project.arch
    except AttributeError:
        return None
    if cfunc is None or size <= 0:
        return None
    try:
        prototype = (
            cfunc.functy
            if isinstance(cfunc.functy, SimTypeFunction)
            else cfunc.prototype
        )
    except AttributeError:
        return None
    layout = stack_prototype_argument_layout_8616(
        prototype,
        arch,
        first_argument_bp_offset=proven_first_argument_machine_bp_offset_8616(codegen),
    )
    arguments = tuple(cfunc.arg_list or ())
    delta = proven_bp_entry_sp_delta_8616(codegen)
    if len(layout) != len(arguments) or not isinstance(delta, int):
        return None
    matches = tuple(
        candidate
        for slot, candidate in zip(layout, arguments, strict=True)
        if slot.offset == bp_offset
        and slot.storage_width == size
        and isinstance(candidate, structured_c.CVariable)
        and isinstance(candidate.variable, SimStackVariable)
        and candidate.variable.base == "bp"
        and candidate.variable.offset == slot.offset + delta
        and candidate.variable.size == slot.storage_width
    )
    return matches[0] if len(matches) == 1 else None


__all__ = [
    "StackPrototypeArgument8616",
    "stack_prototype_argument_layout_8616",
    "stack_prototype_cvar_for_machine_bp_range_8616",
]
