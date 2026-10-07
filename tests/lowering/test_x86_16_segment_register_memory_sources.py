"""Regress typed segment-register memory-source evidence.

These tests use normalized instruction views only. They do not use COD text,
assembly strings, rendered C, or source-level names as semantic evidence.
"""

from types import SimpleNamespace

from inertia.ir.core import AddressStatus, MemSpace, SegmentOrigin
from inertia.lowering.register_constant_segmented_store import (
    recover_segment_register_memory_sources_8616,
)
from capstone.x86_const import X86_INS_MOV, X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_INVALID


def _operand(
    kind: int,
    *,
    register: int | None = None,
    immediate: int | None = None,
    size: int = 2,
    segment: int = X86_REG_INVALID,
    displacement: int = 0,
) -> SimpleNamespace:
    """Build one normalized operand fixture."""
    memory = None
    if kind == X86_OP_MEM:
        memory = SimpleNamespace(
            segment=segment,
            base=X86_REG_INVALID,
            index=X86_REG_INVALID,
            displacement=displacement,
        )
    return SimpleNamespace(
        kind=kind,
        register=register,
        immediate=immediate,
        size=size,
        memory=memory,
    )


def _instruction(address: int, *operands: SimpleNamespace) -> SimpleNamespace:
    """Build one normalized MOV instruction fixture."""
    return SimpleNamespace(
        raw=SimpleNamespace(),
        instruction_id=X86_INS_MOV,
        address=address,
        operands=operands,
    )


def _register_name(_raw: object, register: int | None) -> str | None:
    """Resolve the synthetic register identifiers used by this fixture."""
    return {1: "es", 2: "ax"}.get(register)


def _segment_name(raw: object, register: int | None) -> str | None:
    """Resolve an absent override to architectural DS."""
    return "ds" if register in {None, 0, X86_REG_INVALID} else _register_name(raw, register)


def test_segment_memory_source_is_attached_to_each_exact_store() -> None:
    instructions = (
        _instruction(0x1000, _operand(X86_OP_REG, register=1), _operand(X86_OP_MEM, displacement=0x700A)),
        _instruction(
            0x1004,
            _operand(X86_OP_MEM, segment=1, displacement=2),
            _operand(X86_OP_IMM, immediate=27),
        ),
        _instruction(0x100B, _operand(X86_OP_REG, register=1), _operand(X86_OP_MEM, displacement=0x700C)),
        _instruction(
            0x100F,
            _operand(X86_OP_MEM, segment=1, displacement=2),
            _operand(X86_OP_IMM, immediate=25),
        ),
    )

    facts = recover_segment_register_memory_sources_8616(
        instructions,
        register_name=_register_name,
        segment_name=_segment_name,
    )

    assert tuple((fact.ins_addr, fact.segment_name, fact.source.offset) for fact in facts) == (
        (0x1004, "es", 0x700A),
        (0x100F, "es", 0x700C),
    )
    assert all(fact.source.space is MemSpace.DS for fact in facts)
    assert all(fact.source.status is AddressStatus.STABLE for fact in facts)
    assert all(fact.source.segment_origin is SegmentOrigin.PROVEN for fact in facts)


def test_unknown_segment_overwrite_erases_memory_source() -> None:
    instructions = (
        _instruction(0x1000, _operand(X86_OP_REG, register=1), _operand(X86_OP_MEM, displacement=0x700A)),
        _instruction(0x1004, _operand(X86_OP_REG, register=1), _operand(X86_OP_REG, register=2)),
        _instruction(
            0x1006,
            _operand(X86_OP_MEM, segment=1, displacement=2),
            _operand(X86_OP_IMM, immediate=27),
        ),
    )

    assert not recover_segment_register_memory_sources_8616(
        instructions,
        register_name=_register_name,
        segment_name=_segment_name,
    )
