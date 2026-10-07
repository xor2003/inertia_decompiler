from __future__ import annotations

from dataclasses import dataclass

from inertia.semantics.terminal_register_restore import (
    terminal_register_restore_sites_8616,
)


@dataclass(frozen=True, slots=True)
class _Operand:
    type: int
    reg: int


@dataclass(frozen=True, slots=True)
class _Instruction:
    address: int
    bytes: bytes
    mnemonic: str
    operands: tuple[_Operand, ...] = ()

    def reg_name(self, reg_id: int) -> str:
        return {1: "bp", 2: "si"}[reg_id]


def _frame_instruction(
    address: int,
    raw_bytes: bytes,
    mnemonic: str,
    register_id: int | None = None,
) -> _Instruction:
    operands = () if register_id is None else (_Operand(1, register_id),)
    return _Instruction(address, raw_bytes, mnemonic, operands)


def test_terminal_restore_deduplicates_exact_overlapping_block_sites() -> None:
    loop_instruction = _frame_instruction(0x100B, b"\x8b\x5e\xfe", "mov")
    instructions_by_block = {
        0x1000: (
            _frame_instruction(0x1000, b"\x55", "push", 1),
            _frame_instruction(0x1001, b"\x8b\xec", "mov"),
            loop_instruction,
        ),
        0x100B: (
            _frame_instruction(0x100B, b"\x8b\x5e\xfe", "mov"),
            _frame_instruction(0x100E, b"\xd1\xe3", "shl"),
        ),
        0x1021: (
            _frame_instruction(0x1021, b"\x8b\xe5", "mov"),
            _frame_instruction(0x1023, b"\x5d", "pop", 1),
            _frame_instruction(0x1024, b"\xc3", "ret"),
        ),
    }

    assert terminal_register_restore_sites_8616(instructions_by_block, 0x1000) == frozenset({0x1023})


def test_terminal_restore_refuses_conflicting_duplicate_site_bytes() -> None:
    instructions_by_block = {
        0x1000: (
            _frame_instruction(0x1000, b"\x55", "push", 1),
            _frame_instruction(0x1001, b"\x90", "nop"),
        ),
        0x1001: (_frame_instruction(0x1001, b"\xcc", "int3"),),
        0x1002: (
            _frame_instruction(0x1002, b"\x5d", "pop", 1),
            _frame_instruction(0x1003, b"\xc3", "ret"),
        ),
    }

    assert terminal_register_restore_sites_8616(instructions_by_block, 0x1000) == frozenset()
