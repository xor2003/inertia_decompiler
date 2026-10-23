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

from inertia.ir.constant_flow import IRConstantFlow8616
from inertia.ir.core import IRAddress, IRInstr, IRValue, MemSpace
from inertia.semantics.register_value_preservation import register_value_family_8616

_FRAME_REGISTERS = frozenset({"sp", "bp"})
_FRAME_FAMILIES = {name: register_value_family_8616(name) for name in _FRAME_REGISTERS}
_GENERAL_WORD_REGISTERS = frozenset({"ax", "bx", "cx", "dx", "si", "di"})
_GENERAL_WORD_BY_ALIAS = {
    alias: register
    for register in _GENERAL_WORD_REGISTERS
    for alias in register_value_family_8616(register)
}
_WORD_BYTES = 2
_BINARY_OPERAND_COUNT = 2
type FrameRegister8616 = Literal["sp", "bp"]


def _plain_word_register(value: IRValue, register: str) -> bool:
    """Require a live, undecorated word view of one canonical register."""
    exact_storage = value.name == register and value.size == _WORD_BYTES and value.offset == 0
    undecorated = value.expr is None and value.index is None and value.index_shift == 0
    live_value = value.version is None and value.source_tmp is None
    unprojected = value.active_unary is None and value.call_output is None
    return exact_storage and undecorated and live_value and unprojected


@dataclass(frozen=True, slots=True)
class StackFrameBase8616:
    """One explicitly identified frame register in entry-SP coordinates."""

    register: FrameRegister8616
    entry_sp_offset: int


@dataclass(slots=True)
class StackPointerSnapshots8616:
    """Frame values and exact word-register copies in entry-SP coordinates.

    Temporary values are immutable captures. General registers describe live
    storage and lose their coordinate on any unmodeled overlapping write.
    """

    offsets: dict[int, int | None] = field(default_factory=dict)
    register_offsets: dict[str, int] = field(default_factory=dict)

    def value_offset(self, value: IRValue, current_sp: int | None, current_bp: int | None) -> int | None:
        """Resolve the exact producer value, never adding its displacement twice."""
        if value.size < _WORD_BYTES:
            return None
        if value.source_tmp is not None:
            return self.offsets.get(value.source_tmp)
        if value.space is not MemSpace.REG or value.expr:
            return None
        if value.name in _GENERAL_WORD_REGISTERS:
            if not _plain_word_register(value, value.name):
                return None
            return self.register_offsets.get(value.name)
        if value.name not in _FRAME_REGISTERS:
            return None
        base = current_sp if value.name == "sp" else current_bp
        return None if base is None else base + value.offset

    def observe(
        self,
        instruction: IRInstr,
        current_sp: int | None,
        current_bp: int | None = None,
        *,
        constants: IRConstantFlow8616 | None = None,
    ) -> None:
        """Record explicit frame reads and affine temporary definitions."""
        if instruction.op in {"CALL", "INT", "INTERRUPT", "SYSCALL", "IRET"}:
            # No general-register preservation follows from an SP-only effect.
            self.register_offsets.clear()
        destination = instruction.dst
        source = instruction.args[0] if instruction.args else None
        if isinstance(destination, IRValue) and destination.space is MemSpace.REG:
            self._observe_general_register(instruction, current_sp, current_bp, constants)
            return
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
            result = self._affine_offset(instruction, current_sp, current_bp, constants)
        self.offsets[destination.source_tmp] = result

    def _numeric_operand_8616(
        self, value: IRValue, constants: IRConstantFlow8616 | None,
    ) -> int | None:
        """Resolve one operand as a plain integer, never an SP coordinate.

        A literal CONST carries its own number; any other operand requires a
        proven constant from the supplied constant-flow owner. Register values
        resolved this way are numeric words only — a proven ``ax = 0`` is a
        data constant, never an entry-SP-relative coordinate.
        """
        if value.space is MemSpace.CONST:
            return value.const if value.const is not None and value.offset == 0 else None
        if constants is None:
            return None
        return constants.constant(value)

    def _observe_general_register(
        self,
        instruction: IRInstr,
        sp: int | None,
        bp: int | None,
        constants: IRConstantFlow8616 | None = None,
    ) -> None:
        """Transfer exact MOVs and affine adds; other writes kill aliases."""
        destination = instruction.dst
        if not isinstance(destination, IRValue) or destination.name is None:
            return
        register = _GENERAL_WORD_BY_ALIAS.get(destination.name.lower())
        if register is None:
            return
        source = instruction.args[0] if instruction.args else None
        result = None
        exact_word = _plain_word_register(destination, register)
        if instruction.op == "MOV" and exact_word and isinstance(source, IRValue):
            result = self.value_offset(source, sp, bp)
        elif instruction.op in {"Iop_Add16", "Iop_Sub16"} and exact_word:
            result = self._affine_offset(instruction, sp, bp, constants)
        self.register_offsets.pop(register, None)
        if result is not None:
            self.register_offsets[register] = result

    def _affine_offset(
        self,
        instruction: IRInstr,
        sp: int | None,
        bp: int | None,
        constants: IRConstantFlow8616 | None = None,
    ) -> int | None:
        """Resolve a frame coordinate plus/minus one exact integer."""
        if len(instruction.args) != _BINARY_OPERAND_COUNT:
            return None
        left, right = instruction.args
        if not isinstance(left, IRValue) or not isinstance(right, IRValue):
            return None
        if instruction.op == "Iop_Add16" and left.space is MemSpace.CONST:
            left, right = right, left
        base = self.value_offset(left, sp, bp)
        operand = self._numeric_operand_8616(right, constants)
        if base is None or operand is None:
            return None
        return base + operand if instruction.op == "Iop_Add16" else base - operand

    def updated_register(
        self,
        register: FrameRegister8616,
        instruction: IRInstr,
        sp: int | None,
        bp: int | None,
        *,
        constants: IRConstantFlow8616 | None = None,
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
        if not exact_word:
            return None
        if instruction.op == "MOV" and isinstance(source, IRValue):
            return self.value_offset(source, sp, bp)
        if instruction.op in {"Iop_Add16", "Iop_Sub16"}:
            if len(instruction.args) != _BINARY_OPERAND_COUNT:
                return None
            left, right = instruction.args
            if not isinstance(left, IRValue) or not isinstance(right, IRValue):
                return None
            if instruction.op == "Iop_Add16" and left.space is MemSpace.CONST:
                left, right = right, left
            base = self.value_offset(left, sp, bp)
            operand = self._numeric_operand_8616(right, constants)
            if base is None or operand is None:
                return None
            return base + operand if instruction.op == "Iop_Add16" else base - operand
        return None

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
