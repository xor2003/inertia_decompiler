from __future__ import annotations

from dataclasses import dataclass

from inertia.lowering.far_pointer_segmented_load_evidence import (
    FarPointerSegmentRegister8616,
    FarPointerStackValueSource8616,
    recover_far_pointer_segmented_loads_8616,
)
from capstone.x86_const import (
    X86_INS_ADD,
    X86_INS_LES,
    X86_INS_MOV,
    X86_INS_SUB,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
)

_AX = 1
_BP = 2
_BX = 3
_DX = 4
_ES = 5
_REGISTER_NAMES = {_AX: "ax", _BP: "bp", _BX: "bx", _DX: "dx", _ES: "es"}


@dataclass(frozen=True, slots=True)
class _Memory:
    segment: int | None = None
    base: int | None = None
    index: int | None = None
    displacement: int | None = None


@dataclass(frozen=True, slots=True)
class _Operand:
    kind: int
    register: int | None = None
    size: int | None = None
    immediate: int | None = None
    memory: _Memory | None = None


@dataclass(frozen=True, slots=True)
class _Instruction:
    raw: object
    instruction_id: int
    address: int
    operands: tuple[_Operand, ...]


def _register_name(_raw: object, register: int | None) -> str | None:
    return _REGISTER_NAMES.get(register)


def _reg(register: int) -> _Operand:
    return _Operand(X86_OP_REG, register=register, size=2)


def _imm(value: int) -> _Operand:
    return _Operand(X86_OP_IMM, size=2, immediate=value)


def _mem(*, base: int, displacement: int, size: int, segment: int | None = None) -> _Operand:
    return _Operand(
        X86_OP_MEM,
        size=size,
        memory=_Memory(segment=segment, base=base, displacement=displacement),
    )


def _indexed_mem(*, base: int, index: int, displacement: int, size: int) -> _Operand:
    return _Operand(
        X86_OP_MEM,
        size=size,
        memory=_Memory(base=base, index=index, displacement=displacement),
    )


def _overlay_load_sequence(*, overlap_segment_destination: bool = False) -> tuple[_Instruction, ...]:
    instructions = [
        _Instruction(None, X86_INS_MOV, 0x1010, (_reg(_AX), _mem(base=_BP, displacement=4, size=2))),
        _Instruction(None, X86_INS_MOV, 0x1012, (_mem(base=_BP, displacement=-6, size=2), _reg(_AX))),
    ]
    if overlap_segment_destination:
        instructions.append(
            _Instruction(None, X86_INS_MOV, 0x1014, (_mem(base=_BP, displacement=-5, size=2), _reg(_AX)))
        )
    instructions.extend(
        (
            _Instruction(None, X86_INS_LES, 0x1016, (_reg(_BX), _mem(base=_BP, displacement=-8, size=4))),
            _Instruction(None, X86_INS_MOV, 0x1018, (_reg(_DX), _mem(base=_BX, displacement=24, size=2, segment=_ES))),
        )
    )
    return tuple(instructions)


def _constant_offset_load_sequence(
    *,
    overwrite_offset: bool = False,
    unknown_offset_write: bool = False,
) -> tuple[_Instruction, ...]:
    instructions = [
        _Instruction(None, X86_INS_SUB, 0x1000, (_reg(_AX), _reg(_AX))),
        _Instruction(None, X86_INS_ADD, 0x1002, (_reg(_AX), _imm(36))),
        _Instruction(None, X86_INS_MOV, 0x1005, (_mem(base=_BP, displacement=-4, size=2), _reg(_AX))),
        _Instruction(None, X86_INS_MOV, 0x1008, (_reg(_DX), _mem(base=_BP, displacement=4, size=2))),
        _Instruction(None, X86_INS_MOV, 0x100B, (_mem(base=_BP, displacement=-2, size=2), _reg(_DX))),
    ]
    if overwrite_offset:
        instructions.append(
            _Instruction(None, X86_INS_MOV, 0x100E, (_mem(base=_BP, displacement=-4, size=2), _reg(_DX)))
        )
    if unknown_offset_write:
        instructions.append(
            _Instruction(
                None,
                X86_INS_MOV,
                0x100F,
                (_indexed_mem(base=_BP, index=_BX, displacement=-4, size=2), _reg(_DX)),
            )
        )
    instructions.extend(
        (
            _Instruction(None, X86_INS_LES, 0x1011, (_reg(_BX), _mem(base=_BP, displacement=-4, size=4))),
            _Instruction(None, X86_INS_MOV, 0x1014, (_reg(_DX), _mem(base=_BX, displacement=0, size=2, segment=_ES))),
        )
    )
    return tuple(instructions)


def test_far_pointer_load_retains_exact_copied_segment_source() -> None:
    evidence = recover_far_pointer_segmented_loads_8616(
        _overlay_load_sequence(),
        register_name=_register_name,
        segment_name=_register_name,
    )

    assert len(evidence) == 1
    assert evidence[0].segment_register is FarPointerSegmentRegister8616.ES
    assert evidence[0].pointer_source.segment_value_source == FarPointerStackValueSource8616(4, 2)
    assert evidence[0].displacement == 24


def test_far_pointer_load_refuses_overwritten_segment_source_identity() -> None:
    evidence = recover_far_pointer_segmented_loads_8616(
        _overlay_load_sequence(overlap_segment_destination=True),
        register_name=_register_name,
        segment_name=_register_name,
    )

    assert len(evidence) == 1
    assert evidence[0].pointer_source.segment_value_source is None


def test_far_pointer_load_retains_exact_constant_offset() -> None:
    """Carry a same-block constant into the typed far-pointer stack pair."""
    evidence = recover_far_pointer_segmented_loads_8616(
        _constant_offset_load_sequence(),
        register_name=_register_name,
        segment_name=_register_name,
    )

    assert len(evidence) == 1
    assert evidence[0].pointer_source.offset_constant == 36


def test_far_pointer_load_invalidates_overwritten_constant_offset() -> None:
    """Refuse a constant after any overlapping stack write replaces it."""
    evidence = recover_far_pointer_segmented_loads_8616(
        _constant_offset_load_sequence(overwrite_offset=True),
        register_name=_register_name,
        segment_name=_register_name,
    )

    assert len(evidence) == 1
    assert evidence[0].pointer_source.offset_constant is None


def test_far_pointer_load_refuses_constant_after_unknown_stack_write() -> None:
    """Refuse an offset constant after an unresolved BP-relative write."""
    evidence = recover_far_pointer_segmented_loads_8616(
        _constant_offset_load_sequence(unknown_offset_write=True),
        register_name=_register_name,
        segment_name=_register_name,
    )

    assert len(evidence) == 1
    assert evidence[0].pointer_source.offset_constant is None
