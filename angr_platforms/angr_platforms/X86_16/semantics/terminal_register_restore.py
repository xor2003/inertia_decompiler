"""Classify balanced entry-save and terminal-restore register sites.

Layer: Semantics.
Responsibility: identify exact POP instructions that restore entry-saved
registers without treating those restores as newly computed return values.

Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol, cast

__all__ = ["terminal_register_restore_sites_8616"]


class _OperandBoundary8616(Protocol):
    """Capstone register operand fields consumed by restore classification."""

    type: int
    reg: int


class _InstructionBoundary8616(Protocol):
    """Capstone instruction fields consumed by restore classification."""

    address: int
    bytes: Sequence[int]
    mnemonic: str
    operands: tuple[_OperandBoundary8616, ...]

    def reg_name(self, reg_id: int) -> str:
        """Return an architecture register name."""


def _inner_instruction_8616(instruction: object) -> object:
    """Return an angr wrapper's underlying Capstone instruction."""
    try:
        return cast(object, instruction.insn)  # type: ignore[attr-defined]
    except AttributeError:
        return instruction


def _register_operand_name_8616(instruction: object) -> str | None:
    """Return one exact register operand name, or refuse the instruction."""
    inner = cast(_InstructionBoundary8616, _inner_instruction_8616(instruction))
    try:
        operands = tuple(inner.operands)
    except (AttributeError, TypeError):
        return None
    if len(operands) != 1 or operands[0].type != 1:
        return None
    try:
        return str(inner.reg_name(operands[0].reg)).lower()
    except (AttributeError, TypeError, ValueError):
        return None


def _instruction_mnemonic_8616(instruction: object) -> str:
    """Return a normalized Capstone mnemonic."""
    try:
        return str(cast(_InstructionBoundary8616, _inner_instruction_8616(instruction)).mnemonic).lower()
    except (AttributeError, TypeError, ValueError):
        return ""


def _instruction_address_8616(instruction: object) -> int | None:
    """Return an exact Capstone instruction address."""
    try:
        address = cast(_InstructionBoundary8616, _inner_instruction_8616(instruction)).address
    except AttributeError:
        return None
    return address if isinstance(address, int) else None


def _instruction_bytes_8616(instruction: object) -> bytes | None:
    """Return exact decoded bytes for duplicate-site arbitration."""
    try:
        raw_bytes = cast(_InstructionBoundary8616, _inner_instruction_8616(instruction)).bytes
        decoded = bytes(raw_bytes)
    except (AttributeError, TypeError, ValueError):
        return None
    return decoded or None


def _address_ordered_unique_instructions_8616(
    instructions_by_block: Mapping[int, tuple[object, ...]],
) -> tuple[object, ...] | None:
    """Normalize overlapping blocks by exact address and byte identity.

    Frontend block extents may overlap at loop headers. Equal instruction bytes
    prove that those views describe one site; conflicting or byte-less duplicate
    evidence is refused instead of choosing one block by iteration order.
    """
    by_address: dict[int, tuple[bytes | None, object]] = {}
    for instructions in instructions_by_block.values():
        for instruction in instructions:
            instruction_addr = _instruction_address_8616(instruction)
            if instruction_addr is None:
                continue
            instruction_bytes = _instruction_bytes_8616(instruction)
            existing = by_address.get(instruction_addr)
            if existing is None:
                by_address[instruction_addr] = (instruction_bytes, instruction)
                continue
            existing_bytes, _existing_instruction = existing
            if (
                existing_bytes is None
                or instruction_bytes is None
                or existing_bytes != instruction_bytes
            ):
                return None
    return tuple(by_address[address][1] for address in sorted(by_address))


def terminal_register_restore_sites_8616(
    instructions_by_block: Mapping[int, tuple[object, ...]],
    entry_addr: int,
) -> frozenset[int]:
    """Return balanced restore sites using complete decoded block evidence.

    The current semantic contract intentionally preserves the legacy ordering:
    entry saves are the leading PUSH sequence and restores are the POP sequence
    immediately preceding the first address-ordered return. The Frontend owns
    byte decoding; this owner only classifies register-transfer meaning.
    """
    entry_saves = _entry_save_registers_8616(instructions_by_block.get(entry_addr, ()))
    if not entry_saves:
        return frozenset()

    ordered = _address_ordered_unique_instructions_8616(instructions_by_block)
    if ordered is None:
        return frozenset()
    terminal_index = next(
        (
            index
            for index, instruction in enumerate(ordered)
            if _instruction_mnemonic_8616(instruction) in {"ret", "retf", "iret"}
        ),
        None,
    )
    if terminal_index is None:
        return frozenset()

    restores = _terminal_restore_registers_8616(ordered[:terminal_index])
    if tuple(name for name, _address in restores) != tuple(entry_saves):
        return frozenset()
    return frozenset(address for _name, address in restores)


def _entry_save_registers_8616(entry_instructions: tuple[object, ...]) -> list[str]:
    """Collect the leading PUSH register sequence for the entry block."""
    entry_saves: list[str] = []
    for instruction in entry_instructions:
        if _instruction_mnemonic_8616(instruction) != "push":
            break
        register_name = _register_operand_name_8616(instruction)
        if register_name is None:
            break
        entry_saves.append(register_name)
    return entry_saves


def _terminal_restore_registers_8616(
    pre_terminal: tuple[object, ...] | list[object],
) -> list[tuple[str, int]]:
    """Collect the POP register/address sequence before the first return."""
    restores: list[tuple[str, int]] = []
    for instruction in reversed(pre_terminal):
        if _instruction_mnemonic_8616(instruction) != "pop":
            break
        register_name = _register_operand_name_8616(instruction)
        address = _instruction_address_8616(instruction)
        if register_name is None or address is None:
            break
        restores.append((register_name, address))
    return restores
