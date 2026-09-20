"""Exact local constant values for typed instruction consumers.

Layer: IR.
Responsibility: preserve constants and immutable temporary identities within
one basic block. Unknown operations stay unknown; calls invalidate register
knowledge. This proves values only, never memory aliases or C replacements.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import operator
from collections.abc import Callable
from dataclasses import dataclass, field

from ..semantics.register_value_preservation import (
    register_value_family_8616,
    register_value_projection_8616,
)
from .core import IRInstr, IRValue, MemSpace

_BINARY: dict[str, Callable[[int, int], int]] = {
    "Add": operator.add, "Sub": operator.sub, "And": operator.and_,
    "Or": operator.or_, "Xor": operator.xor, "Shl": operator.lshift,
    "Shr": operator.rshift,
}
_OPERATIONS: dict[str, tuple[str, int]] = {f"Iop_{name}{bits}": (name, bits) for name in _BINARY for bits in (8, 16, 32, 64)}
_CONVERSIONS: dict[str, tuple[int, int, bool]] = {
    f"Iop_{source}{sign}to{target}": (source, target, sign == "S")
    for source in (1, 8, 16, 32, 64) for target in (1, 8, 16, 32, 64)
    for sign in (("U", "S") if source < target else ("",)) if source != target
}


@dataclass(frozen=True, slots=True)
class _Value:
    """One immutable value identity, optionally known as an integer."""

    identity: int
    bits: int
    constant: int | None


@dataclass(slots=True)
class IRConstantFlow8616:
    """Consume instructions in order; create a fresh instance per IR block."""

    _registers: dict[str, _Value] = field(default_factory=dict)
    _temporaries: dict[int, _Value] = field(default_factory=dict)
    _identity: int = 0

    def _new(self, bits: int, constant: int | None = None) -> _Value:
        """Allocate an immutable width-normalized definition."""
        self._identity += 1
        return _Value(self._identity, bits, None if constant is None else constant & ((1 << bits) - 1))

    def _register(self, name: str) -> _Value | None:
        """Read an exact register view from the authoritative storage layout."""
        name = name.lower()
        layout = register_value_projection_8616(name, name)
        if layout is None:
            return None
        if name not in self._registers:
            for writer, known in self._registers.items():
                projection = register_value_projection_8616(writer, name)
                if projection is not None and known.constant is not None:
                    shift, bits = projection
                    return self._new(bits, known.constant >> shift)
            self._registers[name] = self._new(layout[1])
        return self._registers[name]

    def _read(self, value: object) -> _Value | None:
        """Prefer the original temporary definition over its register label."""
        if not isinstance(value, IRValue) or value.offset or value.index is not None or value.call_output is not None:
            return None
        if value.size not in {1, 2, 4, 8}:
            return None
        if value.source_tmp is not None:
            result = self._temporaries.get(value.source_tmp)
        elif value.space is MemSpace.CONST and value.const is not None:
            result = self._new(value.size * 8, value.const)
        elif value.space is MemSpace.REG and value.name is not None:
            result = self._register(value.name)
        else:
            return None
        if result is None:
            return None
        return self._project(value, result)

    def _project(self, value: IRValue, result: _Value) -> _Value | None:
        """Apply explicit integer conversions, not descriptive expression labels."""
        for operation in value.expr or ():
            conversion = _CONVERSIONS.get(operation)
            if conversion is not None:
                source, target, signed = conversion
                constant = result.constant
                if constant is None:
                    return None
                constant &= (1 << source) - 1
                if signed and constant & (1 << (source - 1)):
                    constant -= 1 << source
                result = self._new(target, constant)
            elif operation not in _OPERATIONS or value.source_tmp is None:
                return None
        if result.constant is not None:
            return self._new(value.size * 8, result.constant)
        return result if result.bits == value.size * 8 else None

    def constant(self, value: object) -> int | None:
        """Read a proven value at the current program point; never guess zero."""
        result = self._read(value)
        return None if result is None else result.constant

    def _result(self, instruction: IRInstr) -> _Value | None:
        """Evaluate only explicitly supported pure bitvector operations."""
        arguments = instruction.args
        if instruction.op == "MOV" and len(arguments) == 1:
            return self._read(arguments[0])
        operation = _OPERATIONS.get(instruction.op)
        if operation is None or len(arguments) != 2:
            return None
        left, right = (self._read(argument) for argument in arguments)
        if left is None or right is None:
            return None
        name, bits = operation
        if left.bits != bits or (name not in {"Shr", "Shl"} and right.bits != bits):
            return None
        if name in {"Sub", "Xor"} and left.identity == right.identity:
            return self._new(bits, 0)
        if left.constant is None or right.constant is None:
            return None
        if name in {"Shr", "Shl"} and not 0 <= right.constant < bits:
            return None
        return self._new(bits, _BINARY[name](left.constant, right.constant))

    def observe(self, instruction: IRInstr) -> None:
        """Publish each definition after reading operands from the old state."""
        if instruction.op == "CALL":
            self._registers.clear()
        destination = instruction.dst
        if not isinstance(destination, IRValue) or destination.size not in {1, 2, 4, 8}:
            return
        result = self._result(instruction)
        if result is None or result.bits != destination.size * 8:
            result = self._new(destination.size * 8)
        if destination.space is MemSpace.TMP and destination.source_tmp is not None:
            self._temporaries[destination.source_tmp] = result
        elif destination.space is MemSpace.REG and destination.name is not None:
            # Partial writes invalidate wider views; do not invent upper bits.
            name = destination.name.lower()
            for alias in register_value_family_8616(name):
                self._registers.pop(alias, None)
            self._registers[name] = result
