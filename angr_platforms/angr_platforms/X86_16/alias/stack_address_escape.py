"""Conservatively track frame-derived values through one SSA block.

Layer: Alias.
Responsibility: refuse private-storage reasoning when a derived frame address
escapes through a store or an outgoing general register. This is a data-use
census, not permission to delete memory effects.
Owns storage identity only. Do not infer C locals or types, widen adjacent
ranges, structure control flow, rewrite generated C, or inspect rendered text.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from ..ir.core import IRAddress, IRBinaryValue, IRInstr, IRValue, MemSpace
from ..ir.ssa import SSABlock
from ..ir.ssa_function import SSAFunctionArtifact
from ..ir.stack_extent_evidence import StackExtentEvidence8616

type _ValueKey = tuple[str, str | int | None, int | None]
_STORE_OPERAND_COUNT = 2
_STACK_MODULUS = 1 << 16
_WORD_BYTES = 2
_DWORD_BYTES = 4


class StackAddressEscape8616(IntEnum):
    """Dataflow result; unknown evidence is never permission to delete."""

    NO_DERIVED_ADDRESS_ESCAPE = 0
    DERIVED_ADDRESS_ESCAPE = 1
    UNKNOWN_REFUSE = 2


@dataclass(slots=True)
class _StackCells:
    """Track derived-address state through exact SS byte stores and loads."""

    evidence: StackExtentEvidence8616
    cells: dict[int, StackAddressEscape8616] = field(default_factory=dict)

    def _keys(self, instruction: IRInstr, index: int) -> tuple[int, ...] | None:
        """Resolve circular byte cells only for a complete exact SS access."""
        if not instruction.args or not isinstance(instruction.args[0], IRAddress):
            return None
        address = instruction.args[0]
        if address.size > _STACK_MODULUS:
            return None
        offset = self.evidence.address_entry_offset(self.evidence.block_addr, index, address)
        if offset is None:
            return None
        return tuple((offset + displacement) % _STACK_MODULUS for displacement in range(address.size))

    def load(self, instruction: IRInstr, index: int) -> StackAddressEscape8616:
        """Require a reaching state for every byte, not merely a matching base."""
        keys = self._keys(instruction, index)
        if not keys:
            return StackAddressEscape8616.UNKNOWN_REFUSE
        return max(self.cells.get(key, StackAddressEscape8616.UNKNOWN_REFUSE) for key in keys)

    def store(self, instruction: IRInstr, index: int, state: StackAddressEscape8616) -> None:
        """Unknown SS coordinates invalidate previously tracked byte states."""
        address = instruction.args[0]
        if isinstance(address, IRAddress) and address.space not in {MemSpace.SS, MemSpace.UNKNOWN}:
            return
        keys = self._keys(instruction, index)
        if keys is None:
            self.cells.clear()
        else:
            self.cells.update((key, state) for key in keys)


def _key(value: IRValue) -> _ValueKey:
    """Use block-local VEX temporary identity or exact scalar SSA identity."""
    if value.space is MemSpace.TMP and value.source_tmp is not None:
        return value.space.value, value.source_tmp, None
    return value.space.value, value.name, value.version


def _value_escape(
    value: object, states: dict[_ValueKey, StackAddressEscape8616],
    frame_registers: frozenset[tuple[str, int]],
) -> StackAddressEscape8616:
    """Follow typed data operands; never interpret address operands as loads."""
    if isinstance(value, IRBinaryValue):
        return max(_value_escape(value.lhs, states, frame_registers), _value_escape(value.rhs, states, frame_registers))
    if not isinstance(value, IRValue):
        return StackAddressEscape8616.UNKNOWN_REFUSE
    if value.index is not None:
        base = states.get(_key(value), StackAddressEscape8616.UNKNOWN_REFUSE)
        return max(base, _value_escape(value.index, states, frame_registers))
    if value.space is MemSpace.CONST:
        return StackAddressEscape8616.NO_DERIVED_ADDRESS_ESCAPE
    if (value.name, value.version) in frame_registers and value.space is MemSpace.REG:
        return StackAddressEscape8616.DERIVED_ADDRESS_ESCAPE
    if _key(value) in states:
        return states[_key(value)]
    # Incoming general registers predate this allocation. This does not prove
    # that memory reached through them is disjoint from the frame.
    if value.space is MemSpace.REG and value.version == 0:
        return StackAddressEscape8616.NO_DERIVED_ADDRESS_ESCAPE
    return StackAddressEscape8616.UNKNOWN_REFUSE


def _store_escape(
    instruction: IRInstr, states: dict[_ValueKey, StackAddressEscape8616],
    frame_registers: frozenset[tuple[str, int]],
) -> StackAddressEscape8616:
    """Inspect stored data without treating the store address as escaping data."""
    if instruction.op != "STORE":
        return StackAddressEscape8616.NO_DERIVED_ADDRESS_ESCAPE
    if len(instruction.args) != _STORE_OPERAND_COUNT:
        return StackAddressEscape8616.UNKNOWN_REFUSE
    return _value_escape(instruction.args[1], states, frame_registers)


def _definition_state(
    instruction: IRInstr, states: dict[_ValueKey, StackAddressEscape8616],
    frame_registers: frozenset[tuple[str, int]],
    memory: _StackCells, index: int,
) -> StackAddressEscape8616:
    """Retain unknown loaded data instead of substituting its address taint."""
    if instruction.op == "LOAD":
        return memory.load(instruction, index)
    return max(
        (_value_escape(value, states, frame_registers) for value in instruction.args),
        default=StackAddressEscape8616.UNKNOWN_REFUSE,
    )


def _complete_output_write(destination: IRValue, widths: dict[str, int]) -> bool:
    """Do not let a partial overwrite discard a wider pointer's retained bits."""
    if destination.name is None:
        return False
    return (
        destination.size in {_WORD_BYTES, _DWORD_BYTES}
        and destination.size >= widths.get(destination.name, destination.size)
    )


def classify_stack_address_escape_8616(
    block: SSABlock, evidence: StackExtentEvidence8616,
) -> StackAddressEscape8616:
    """Census stores and outgoing non-frame registers, refusing opaque data.

    Calls, reads, allocation lifetime and possible memory aliases require
    independent proof. Loads do not turn their address operand into a loaded
    pointer value; their data is unknown here. Architectural frame/control and
    status registers are not general-register address outputs.
    """
    if not evidence.complete or evidence.block_addr != block.addr:
        return StackAddressEscape8616.UNKNOWN_REFUSE
    frame_registers = frozenset((item.name, item.version) for item in evidence.coordinates)
    states: dict[_ValueKey, StackAddressEscape8616] = {}
    outgoing: dict[str, StackAddressEscape8616] = {}
    outgoing_widths: dict[str, int] = {}
    excluded_outputs = {"sp", "ip", "flags", "d"}
    memory = _StackCells(evidence)
    for index, instruction in enumerate(block.instrs):
        if instruction.op in {"CALL", "UNKNOWN"}:
            return StackAddressEscape8616.UNKNOWN_REFUSE
        escaped = _store_escape(instruction, states, frame_registers)
        if escaped is not StackAddressEscape8616.NO_DERIVED_ADDRESS_ESCAPE:
            return escaped
        if instruction.op == "STORE":
            memory.store(instruction, index, escaped)
        destination = instruction.dst
        if destination is None:
            continue
        state = _definition_state(instruction, states, frame_registers, memory, index)
        key = _key(destination)
        if key in states:
            return StackAddressEscape8616.UNKNOWN_REFUSE
        states[key] = state
        if destination.space is MemSpace.REG and destination.name not in excluded_outputs:
            if destination.name is None or not _complete_output_write(destination, outgoing_widths):
                return StackAddressEscape8616.UNKNOWN_REFUSE
            outgoing[destination.name] = state
            outgoing_widths[destination.name] = destination.size
    return max(outgoing.values(), default=StackAddressEscape8616.NO_DERIVED_ADDRESS_ESCAPE)


def classify_function_stack_address_escape_8616(
    function: SSAFunctionArtifact, evidence: tuple[StackExtentEvidence8616, ...],
) -> StackAddressEscape8616:
    """Require one complete entry-to-return block before publishing closure.

    Block-local incoming register assumptions cannot be composed across joins
    or used for a non-entry slice. Explicit RET evidence is mandatory.
    """
    if len(function.blocks) != 1 or len(evidence) != 1 or function.phi_nodes:
        return StackAddressEscape8616.UNKNOWN_REFUSE
    block = function.blocks[0]
    if block.addr != function.function_addr or not block.instrs:
        return StackAddressEscape8616.UNKNOWN_REFUSE
    if block.instrs[-1].op != "RET" or any(instruction.op == "RET" for instruction in block.instrs[:-1]):
        return StackAddressEscape8616.UNKNOWN_REFUSE
    return classify_stack_address_escape_8616(block, evidence[0])
