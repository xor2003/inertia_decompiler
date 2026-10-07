"""Prove decoded instructions preserve a register's exact value.

Layer: Semantics.
Responsibility: classify exact identity operations on decoded x86-16 register
values for downstream Alias and recovery-metadata consumers.
Forbidden: source/COD/rendered-C inference or call-argument materialization.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum
from typing import Protocol, cast

from capstone import CsError
from capstone.x86_const import X86_OP_REG

from inertia.frontend.x86_16.arch_86_16 import Arch86_16

__all__ = (
    "AxValueView8616",
    "ByteReturnExtensionKind8616",
    "decoded_ax_read_view_8616",
    "decoded_byte_return_extension_8616",
    "decoded_instruction_preserves_register_value_8616",
    "decoded_instruction_self_clears_register_8616",
    "decoded_register_bit_effects_8616",
    "register_value_family_8616",
    "register_value_projection_8616",
)


class _Operand8616(Protocol):
    """Capstone operand fields needed for identity classification."""

    type: int
    reg: int


class _DecodedInstruction8616(Protocol):
    """Capstone instruction fields needed for identity classification."""

    operands: Sequence[_Operand8616]

    def reg_name(self, reg_id: int) -> str:
        """Return the backend register name for ``reg_id``."""
        ...

    def regs_access(self) -> tuple[Sequence[int], Sequence[int]]:
        """Return exact registers read and written by this instruction."""
        ...


class _Instruction8616(Protocol):
    """Decoded instruction wrapper consumed at the frontend boundary."""

    mnemonic: str
    insn: _DecodedInstruction8616


class AxValueView8616(StrEnum):
    """Exact AX-family view read by one caller instruction."""

    AL = "al"
    AH = "ah"
    AX = "ax"


class ByteReturnExtensionKind8616(StrEnum):
    """Binary-proven promotion of a returned AL value to AX."""

    SIGN_EXTEND_AL_TO_AX = "sign_extend_al_to_ax"
    ZERO_EXTEND_AL_TO_AX = "zero_extend_al_to_ax"


_REGISTER_VALUE_VIEWS_8616: dict[str, tuple[str, int, int]] = {
    name: (register.name, offset, size)
    for register in Arch86_16.register_list
    for name, offset, size in ((register.name, 0, register.size), *register.subregisters)
}
_REGISTER_VALUE_FAMILIES_8616: dict[str, frozenset[str]] = {
    parent: frozenset(name for name, view in _REGISTER_VALUE_VIEWS_8616.items() if view[0] == parent)
    for parent, _offset, _size in _REGISTER_VALUE_VIEWS_8616.values()
}


def register_value_family_8616(register: str) -> frozenset[str]:
    """Return names sharing architectural storage, including 80386 parents."""
    normalized = register.lower()
    view = _REGISTER_VALUE_VIEWS_8616.get(normalized)
    return _REGISTER_VALUE_FAMILIES_8616[view[0]] if view is not None else frozenset({normalized})


def register_value_projection_8616(writer: str, reader: str) -> tuple[int, int] | None:
    """Return bit shift and width when a writer completely covers a reader.

    Storage-family membership alone is not coverage: AL excludes AH, and AX
    excludes the upper EAX word. Layout comes from the Frontend register owner.
    """
    written = _REGISTER_VALUE_VIEWS_8616.get(writer.lower())
    requested = _REGISTER_VALUE_VIEWS_8616.get(reader.lower())
    if written is None or requested is None:
        return None
    parent, offset, size = written
    read_parent, read_offset, read_size = requested
    if parent != read_parent or read_offset < offset or read_offset + read_size > offset + size:
        return None
    return (read_offset - offset) * 8, read_size * 8


def _register_overlap_mask_8616(tracked: str, other: str) -> int | None:
    """Return overlapping bits relative to the tracked architectural view."""
    left = _REGISTER_VALUE_VIEWS_8616.get(tracked.lower())
    right = _REGISTER_VALUE_VIEWS_8616.get(other.lower())
    if left is None or right is None:
        return None
    if left[0] != right[0]:
        return 0
    start = max(left[1], right[1])
    end = min(left[1] + left[2], right[1] + right[2])
    return ((1 << ((end - start) * 8)) - 1) << ((start - left[1]) * 8) if end > start else 0


def decoded_register_bit_effects_8616(instruction: object, register: str) -> tuple[int, int] | None:
    """Return incoming read and written bit masks, or refuse missing detail.

    Masks are relative to the requested view. Zero idioms consume no incoming
    value even though Capstone reports their repeated register as a read.
    """
    decoded = _decoded_instruction_surface_8616(instruction)
    if decoded is None or register_value_projection_8616(register, register) is None:
        return None
    try:
        read_ids, write_ids = decoded.regs_access()
        masks = [0, 0]
        for index, register_ids in enumerate((read_ids, write_ids)):
            for register_id in register_ids:
                name = decoded.reg_name(register_id)
                mask = _register_overlap_mask_8616(register, name)
                if mask is None:
                    return None
                if index == 0 and decoded_instruction_self_clears_register_8616(instruction, name):
                    continue
                masks[index] |= mask
    except (AttributeError, TypeError, ValueError, CsError):
        return None
    return masks[0], masks[1]


def _decoded_instruction_surface_8616(
    instruction: object,
) -> _DecodedInstruction8616 | None:
    """Normalize wrapped test instructions and direct Capstone instructions."""
    wrapped = cast(_Instruction8616, instruction)
    candidates: tuple[_DecodedInstruction8616, ...]
    try:
        candidates = (wrapped.insn, cast(_DecodedInstruction8616, instruction))
    except (AttributeError, CsError):
        candidates = (cast(_DecodedInstruction8616, instruction),)
    for decoded in candidates:
        try:
            tuple(decoded.operands)
            _ = decoded.reg_name
        except (AttributeError, TypeError, CsError):
            continue
        return decoded
    return None


def _same_decoded_register_pair_8616(instruction: object) -> str | None:
    """Return the normalized register repeated by a two-register instruction."""
    decoded = _decoded_instruction_surface_8616(instruction)
    if decoded is None:
        return None
    operands = tuple(decoded.operands)
    if len(operands) != 2 or any(operand.type != X86_OP_REG for operand in operands):
        return None
    try:
        lhs_name = decoded.reg_name(operands[0].reg).lower()
        rhs_name = decoded.reg_name(operands[1].reg).lower()
    except (AttributeError, TypeError):
        return None
    return lhs_name if lhs_name == rhs_name else None


def decoded_ax_read_view_8616(instruction: object) -> AxValueView8616 | None:
    """Return the exact AX-family view read by one decoded instruction."""
    decoded = _decoded_instruction_surface_8616(instruction)
    if decoded is None:
        return None
    try:
        read_ids, _written_ids = decoded.regs_access()
        names = {decoded.reg_name(reg_id).lower() for reg_id in read_ids}
    except (AttributeError, TypeError):
        names = {
            decoded.reg_name(operand.reg).lower()
            for operand in decoded.operands
            if operand.type == X86_OP_REG
        }
    if "ax" in names or {"al", "ah"}.issubset(names):
        return AxValueView8616.AX
    if "al" in names:
        return AxValueView8616.AL
    if "ah" in names:
        return AxValueView8616.AH
    return None


def decoded_byte_return_extension_8616(
    instruction: object,
) -> ByteReturnExtensionKind8616 | None:
    """Classify an exact caller-side AL-to-AX promotion instruction."""
    decoded = cast(_Instruction8616, instruction)
    try:
        mnemonic = decoded.mnemonic.lower()
    except AttributeError:
        return None
    if mnemonic == "cbw":
        return ByteReturnExtensionKind8616.SIGN_EXTEND_AL_TO_AX
    if mnemonic in {"sub", "xor"} and _same_decoded_register_pair_8616(instruction) == "ah":
        return ByteReturnExtensionKind8616.ZERO_EXTEND_AL_TO_AX
    return None


def decoded_instruction_preserves_register_value_8616(
    instruction: object,
    register: str,
) -> bool:
    """Prove an exact same-register identity operation preserves ``register``.

    Flag effects are intentionally outside this value-only fact. Any dynamic
    boundary failure remains unknown and therefore refuses preservation.
    """
    decoded = cast(_Instruction8616, instruction)
    try:
        mnemonic = decoded.mnemonic.lower()
    except AttributeError:
        return False
    repeated = _same_decoded_register_pair_8616(decoded)
    return mnemonic in {"and", "mov", "or"} and repeated in register_value_family_8616(register)


def decoded_instruction_self_clears_register_8616(
    instruction: object,
    register: str,
) -> bool:
    """Prove a zero idiom clears every bit of the requested register view.

    A word clear covers its byte views; a byte clear neither clears the other
    byte nor the parent word. Register-family overlap alone is insufficient.
    """
    decoded = cast(_Instruction8616, instruction)
    try:
        mnemonic = decoded.mnemonic.lower()
    except AttributeError:
        return False
    repeated = _same_decoded_register_pair_8616(decoded)
    normalized = register.lower()
    covers_view = register_value_projection_8616(repeated or "", normalized) is not None
    return mnemonic in {"sub", "xor"} and covers_view
