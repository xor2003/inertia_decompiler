"""Resolve stack addresses through immutable typed SP/BP captures.

Layer: Alias.
Responsibility: retain function-entry-relative frame-pointer values at explicit
IR reads and affine operations, without reinterpreting captures as current state.
Owns storage identity. Do not perform lowering, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from ..ir.core import IRAddress, IRInstr, IRValue, MemSpace
from ..semantics.register_value_preservation import register_value_family_8616

_FRAME_REGISTERS = frozenset({"sp", "bp"})
_FRAME_FAMILIES = {name: register_value_family_8616(name) for name in _FRAME_REGISTERS}
_WORD_BYTES = 2
_BINARY_OPERAND_COUNT = 2
type FrameRegister8616 = Literal["sp", "bp"]


@dataclass(frozen=True, slots=True)
class StackFrameBase8616:
    """One explicitly identified frame register in entry-SP coordinates."""

    register: FrameRegister8616
    entry_sp_offset: int


@dataclass(slots=True)
class StackPointerSnapshots8616:
    """Block-local frame values, including explicitly unknown captures."""

    offsets: dict[int, int | None] = field(default_factory=dict)

    def value_offset(self, value: IRValue, current_sp: int | None, current_bp: int | None) -> int | None:
        """Resolve the exact producer value, never adding its displacement twice."""
        if value.size < _WORD_BYTES:
            return None
        if value.source_tmp is not None:
            return self.offsets.get(value.source_tmp)
        if value.space is not MemSpace.REG or value.name not in _FRAME_REGISTERS or value.expr:
            return None
        base = current_sp if value.name == "sp" else current_bp
        return None if base is None else base + value.offset

    def observe(
        self, instruction: IRInstr, current_sp: int | None, current_bp: int | None = None,
    ) -> None:
        """Record explicit frame reads and affine temporary definitions."""
        destination = instruction.dst
        source = instruction.args[0] if instruction.args else None
        if (
            not isinstance(destination, IRValue)
            or destination.space is not MemSpace.TMP
            or destination.source_tmp is None
        ):
            return
        result = None
        if instruction.op == "MOV" and isinstance(source, IRValue):
            result = self.value_offset(source, current_sp, current_bp)
        elif instruction.op in {"Iop_Add16", "Iop_Sub16"}:
            result = self._affine_offset(instruction, current_sp, current_bp)
        self.offsets[destination.source_tmp] = result

    def _affine_offset(self, instruction: IRInstr, sp: int | None, bp: int | None) -> int | None:
        """Resolve a frame coordinate plus/minus one exact integer."""
        if len(instruction.args) != _BINARY_OPERAND_COUNT:
            return None
        left, right = instruction.args
        if not isinstance(left, IRValue) or not isinstance(right, IRValue):
            return None
        if instruction.op == "Iop_Add16" and left.space is MemSpace.CONST:
            left, right = right, left
        base = self.value_offset(left, sp, bp)
        if base is None or right.space is not MemSpace.CONST or right.const is None or right.offset != 0:
            return None
        delta = right.const if instruction.op == "Iop_Add16" else -right.const
        return base + delta

    def updated_register(
        self, register: FrameRegister8616, instruction: IRInstr, sp: int | None, bp: int | None,
    ) -> int | None:
        """Transfer a word-frame register, refusing wide/unknown clobbers."""
        current = sp if register == "sp" else bp
        destination = instruction.dst
        if not isinstance(destination, IRValue) or destination.space is not MemSpace.REG:
            return current
        if destination.name not in _FRAME_FAMILIES[register]:
            return current
        exact_word = destination.name == register and destination.size == _WORD_BYTES
        source = instruction.args[0] if instruction.args else None
        if instruction.op != "MOV" or not exact_word or not isinstance(source, IRValue):
            return None
        return self.value_offset(source, sp, bp)

    def address_base(
        self, address: IRAddress, current_sp: int | None, current_bp: int | None = None,
    ) -> StackFrameBase8616 | None:
        """Return the exact captured base or refuse an unavailable capture."""
        if len(address.base) != 1 or address.base[0] not in _FRAME_REGISTERS:
            return None
        register: FrameRegister8616 = "sp" if address.base[0] == "sp" else "bp"
        current = current_sp if register == "sp" else current_bp
        if not address.base_values:
            return None if current is None else StackFrameBase8616(register, current)
        if len(address.base_values) != 1:
            return None
        base = address.base_values[0]
        if base.space is not MemSpace.REG or base.name != register or base.offset != 0:
            return None
        offset = self.value_offset(base, current_sp, current_bp)
        return None if offset is None else StackFrameBase8616(register, offset)
