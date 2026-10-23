"""Artifact-summary SSA binding counts must not materialize full SSA views.

``build_x86_16_ir_function_artifact_summary`` consumes only
``len(SSABlock.bindings)``; the owned counter shares the real builder's
definition-eligibility predicate, so the summary never pays for rewriting,
version allocation, or cache publication merely to count definitions.
"""


import pytest

from inertia.ir import ssa, vex_import
from inertia.ir.core import (
    IRAddress,
    IRBinaryValue,
    IRBlock,
    IRCondition,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
)

pytestmark = pytest.mark.decompiler


def _reg(name: str, **fields: object) -> IRValue:
    return IRValue(MemSpace.REG, name=name, **fields)


def _const(value: int) -> IRValue:
    return IRValue(MemSpace.CONST, const=value)


def _tmp(index: int) -> IRValue:
    return IRValue(MemSpace.TMP, source_tmp=index)


def _mem(space: MemSpace = MemSpace.DS, offset: int = 0) -> IRValue:
    return IRValue(space, offset=offset)


def _instrs(*rows: IRInstr) -> IRBlock:
    return IRBlock(0x1000, instrs=rows)


def _binding_count(block: IRBlock) -> int:
    return ssa._block_local_ssa_binding_count_8616(block)


@pytest.mark.parametrize(
    ("instrs", "expected"),
    [
        ((), 0),
        ((IRInstr("RET", None, ()),), 0),
        ((IRInstr("MOV", _reg("ax"), (_const(1),)),), 1),
        ((IRInstr("MOV", _tmp(4), (_reg("ax"),)),), 1),
        ((IRInstr("STle", _mem(MemSpace.DS, 0x20), (_reg("ax"),)),), 1),
        ((IRInstr("PUT", _mem(MemSpace.SS, -4), (_reg("sp"),)),), 1),
        ((IRInstr("NOP", IRValue(MemSpace.CONST, const=0x10), ()),), 0),
        ((IRInstr("NOP", IRValue(MemSpace.UNKNOWN), ()),), 0),
        ((IRInstr("CALL", _reg("bx"), (_reg("bx"),)),), 0),
        ((IRInstr("CALL", None, (_reg("bx"),)),), 0),
        (
            (
                IRInstr("MOV", _reg("ax"), (_const(1),)),
                IRInstr("MOV", _reg("ax"), (_const(2),)),
                IRInstr("MOV", _reg("ax"), (_const(3),)),
            ),
            3,
        ),
        # Read-before-write: the arg use never binds, the dst still does.
        ((IRInstr("ADD", _reg("ax"), (_reg("ax"), _const(1))),), 1),
        (
            (
                IRInstr("MOV", _reg("ax"), (_const(1),)),
                IRInstr("ADD", _reg("ax"), (_reg("ax"), _const(1))),
            ),
            2,
        ),
        # Nested condition/address/value args never bind.
        (
            (
                IRInstr(
                    "Jcc",
                    None,
                    (
                        IRCondition(
                            op="CmpLT",
                            args=(
                                _reg("ax"),
                                IRBinaryValue("Add", _reg("bx"), _const(4)),
                            ),
                        ),
                        IRAddress(MemSpace.DS, base_values=(_reg("si"),)),
                    ),
                ),
            ),
            0,
        ),
        # CALL dst is an input target; a following MOV still binds normally.
        (
            (
                IRInstr("CALL", _reg("bx"), (_reg("bx"),)),
                IRInstr("MOV", _reg("ax"), (_tmp(7),)),
            ),
            1,
        ),
    ],
)
def test_binding_count_matches_real_builder(
    instrs: tuple[IRInstr, ...], expected: int
) -> None:
    """The counter equals ``len(bindings)`` of the materialized SSA view."""
    block = _instrs(*instrs)
    real = ssa.build_x86_16_block_local_ssa(block)
    assert _binding_count(block) == len(real.bindings) == expected


def test_counter_does_not_rewrite_publish_or_mutate() -> None:
    """The count is read-only: no cache entry, no source mutation."""
    block = _instrs(
        IRInstr("MOV", _reg("ax"), (_const(1),)),
        IRInstr("MOV", _tmp(4), (_reg("ax"),)),
    )
    before = block.to_dict()
    assert _binding_count(block) == 2
    assert ssa._cached_block_local_ssa_8616(block) is None
    assert block.to_dict() == before


def test_summary_binding_count_matches_real_builder() -> None:
    """The artifact summary reports the real SSA binding count."""
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            _instrs(
                IRInstr("MOV", _reg("ax"), (_const(1),)),
                IRInstr("CALL", _reg("bx"), (_reg("bx"),)),
                IRInstr("MOV", _reg("ax"), (_reg("ax"),)),
            ),
            IRBlock(0x1040, instrs=(IRInstr("MOV", _tmp(1), (_reg("ax"),)),)),
        ),
    )
    expected = sum(
        len(ssa.build_x86_16_block_local_ssa(block).bindings)
        for block in artifact.blocks
    )
    summary = vex_import.build_x86_16_ir_function_artifact_summary(artifact)
    assert summary["ssa_binding_count"] == expected == 3
    for key in (
        "block_count",
        "instruction_count",
        "refusal_count",
        "frame_slot_count",
        "frame_refusal_count",
    ):
        assert key in summary


def test_summary_never_materializes_full_ssa(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Building the count must not invoke the full SSA materialization path."""
    def refuse(_block: IRBlock) -> ssa.SSABlock:
        raise AssertionError("full SSA materialization invoked")

    monkeypatch.setattr(
        ssa, "_build_x86_16_block_local_ssa_uncached", refuse
    )
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            _instrs(
                IRInstr("MOV", _reg("ax"), (_const(1),)),
                IRInstr("MOV", _reg("ax"), (_reg("ax"),)),
            ),
        ),
    )
    summary = vex_import.build_x86_16_ir_function_artifact_summary(artifact)
    assert summary["ssa_binding_count"] == 2
