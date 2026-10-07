from __future__ import annotations

from types import SimpleNamespace

import bitstring
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import IRBinaryValue, IRValue, MemSpace
from inertia.frontend.x86_16.lift_86_16 import Instruction_ANY


def _register_operand(register_id: int) -> SimpleNamespace:
    return SimpleNamespace(type=1, size=2, reg=register_id)


def _indexed_word_operand(register_id: int, displacement: int) -> SimpleNamespace:
    memory = SimpleNamespace(base=register_id, index=0, disp=displacement)
    return SimpleNamespace(type=3, size=2, mem=memory)


def _stack_word_operand(register_id: int, displacement: int) -> SimpleNamespace:
    memory = SimpleNamespace(base=register_id, index=0, disp=displacement)
    return SimpleNamespace(type=3, size=2, mem=memory)


def test_indexed_word_mov_and_cmp_receive_typed_frontend_semantics() -> None:
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    bx_id = 1
    si_id = 2
    ax_id = 3
    register_names = {bx_id: "bx", si_id: "si", ax_id: "ax"}
    instruction.cs = SimpleNamespace(
        mnemonic="mov",
        reg_name=register_names.__getitem__,
    )

    mov_semantics = instruction._match_simple_binary_semantics_8616(
        (_register_operand(ax_id), _indexed_word_operand(si_id, 0x56)),
    )
    instruction.cs.mnemonic = "cmp"
    cmp_semantics = instruction._match_simple_binary_semantics_8616(
        (_indexed_word_operand(bx_id, 0x56), _register_operand(ax_id)),
    )

    assert mov_semantics == ("mov_reg_indexed_abs16", "ax", ("si", 0x56, 0x56))
    assert cmp_semantics == ("cmp_indexed_abs_reg16", ("bx", 0x56, 0x56), "ax")


def test_indexed_word_cmp_keeps_distinct_stack_derived_indices() -> None:
    original_index_state = dict(Instruction_ANY._inertia_condition_index_reg_state_8616)
    original_value_state = dict(Instruction_ANY._inertia_condition_reg_value_state_8616)
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction.arch = Arch86_16()
    instruction.addr = 0x1050
    instruction.cs = SimpleNamespace(size=4)
    instruction.emu = SimpleNamespace(_inertia_current_block_addr=0x1050)

    try:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = {
            "si": (IRValue(MemSpace.SS, name="bp", offset=-2, size=2), 1),
        }
        Instruction_ANY._inertia_condition_reg_value_state_8616 = {}
        instruction._set_condition_reg_indexed_value_8616(
            "ax",
            ("si", 0x56, 0x56),
            width_bits=16,
        )
        Instruction_ANY._inertia_condition_index_reg_state_8616["bx"] = (
            IRValue(MemSpace.SS, name="bp", offset=-6, size=2),
            1,
        )
        instruction.addr = 0x1054

        operands = instruction._condition_operands_from_cmp_semantics_8616(
            ("cmp_indexed_abs_reg16", ("bx", 0x56, 0x56), "ax"),
        )
    finally:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = original_index_state
        Instruction_ANY._inertia_condition_reg_value_state_8616 = original_value_state

    assert operands == (
        IRValue(
            MemSpace.DS,
            offset=0x56,
            size=2,
            index=IRValue(MemSpace.SS, name="bp", offset=-6, size=2),
            index_shift=1,
            memory_access_size=2,
            memory_access_insn=0x1054,
        ),
        IRValue(
            MemSpace.DS,
            offset=0x56,
            size=2,
            index=IRValue(MemSpace.SS, name="bp", offset=-2, size=2),
            index_shift=1,
            memory_access_size=2,
            memory_access_insn=0x1050,
        ),
    )


def test_affine_stack_index_survives_add_shift_and_indexed_load() -> None:
    """Preserve ShellSort's BP-4 + BP-2 index before the DS byte load."""
    original_index_state = dict(Instruction_ANY._inertia_condition_index_reg_state_8616)
    original_value_state = dict(Instruction_ANY._inertia_condition_reg_value_state_8616)
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    instruction.arch = Arch86_16()
    instruction.addr = 0x1047
    instruction.cs = SimpleNamespace(size=3)
    instruction.emu = SimpleNamespace(_inertia_current_block_addr=0x1047)
    row = IRValue(MemSpace.SS, name="bp", offset=-4, size=2, expr=("cmp-stack", "bp"))
    offset = IRValue(MemSpace.SS, name="bp", offset=-2, size=2, expr=("cmp-stack", "bp"))

    try:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = {}
        Instruction_ANY._inertia_condition_reg_value_state_8616 = {}
        instruction._set_condition_index_reg_stack_state_8616("bx", ("bp", 0xFFFC, -4))
        instruction.addr = 0x104A
        instruction.condition_value_semantics = (
            "add_reg_mem16",
            "bx",
            ("bp", 0xFFFE, -2),
        )
        instruction._transfer_full_lift_condition_value_semantics_8616()
        instruction._shift_condition_index_reg_state_8616("bx", 1)
        value = instruction._condition_indexed_ds_value_8616(
            ("bx", 0xB4A, 0xB4A),
            Instruction_ANY._inertia_condition_index_reg_state_8616["bx"],
            width_bits=8,
            memory_access_insn=0x1050,
        )
    finally:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = original_index_state
        Instruction_ANY._inertia_condition_reg_value_state_8616 = original_value_state

    assert value == IRValue(
        MemSpace.DS,
        offset=0xB4A,
        size=1,
        index=IRBinaryValue("add", row, offset, size=2),
        index_shift=1,
        memory_access_size=1,
        memory_access_insn=0x1050,
    )


def test_register_add_is_classified_before_value_transfer() -> None:
    original_index_state = dict(Instruction_ANY._inertia_condition_index_reg_state_8616)
    original_value_state = dict(Instruction_ANY._inertia_condition_reg_value_state_8616)
    instruction = Instruction_ANY.__new__(Instruction_ANY)
    bx_id = 1
    bp_id = 2
    register_names = {bx_id: "bx", bp_id: "bp"}
    instruction.arch = Arch86_16()
    instruction.addr = 0x1047
    instruction.cs = SimpleNamespace(
        mnemonic="mov",
        size=3,
        reg_name=register_names.__getitem__,
    )
    instruction.emu = SimpleNamespace(_inertia_current_block_addr=0x1043)

    try:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = {}
        Instruction_ANY._inertia_condition_reg_value_state_8616 = {}
        instruction.addr = 0x104A
        instruction.cs.mnemonic = "add"
        semantics = instruction._match_simple_binary_semantics_8616(
            (_register_operand(bx_id), _stack_word_operand(bp_id, -2)),
        )
    finally:
        Instruction_ANY._inertia_condition_index_reg_state_8616 = original_index_state
        Instruction_ANY._inertia_condition_reg_value_state_8616 = original_value_state

    assert semantics == ("add_reg_mem16", "bx", ("bp", 0xFFFE, -2))


def test_register_add_keeps_normal_lift_and_typed_transfer_side_channel() -> None:
    instruction = Instruction_ANY(
        bitstring.ConstBitStream(bytes=b"\x03\x5e\xfe"),
        Arch86_16(),
        0x104A,
    )

    assert instruction.simple_semantics is None
    assert instruction.condition_value_semantics == (
        "add_reg_mem16",
        "bx",
        ("bp", 0xFFFE, -2),
    )
