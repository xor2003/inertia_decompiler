"""Focused controls: a CALL dst is an input target, never an SSA definition.

Layer: IR regression tests.
Responsibility: prove the block-local SSA builder rewrites a CALL target with
pre-call versions and emits no binding for it, and the shared scalar-definition
index preserves that same input-only contract. Typed IR objects only; no mocks.
"""

from __future__ import annotations

import pytest
from angr_platforms.X86_16.ir.core import (
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
)
from angr_platforms.X86_16.ir.scalar_definitions import (
    ScalarDefinition8616,
    build_scalar_definition_index_8616,
    reaching_scalar_definitions_8616,
)
from angr_platforms.X86_16.ir.ssa import SSABlock, build_x86_16_block_local_ssa
from angr_platforms.X86_16.ir.ssa_function import (
    SSAFunctionArtifact,
    build_x86_16_function_ssa,
)

_ENTRY = 0x105BC


def _tmp(tmp_id: int, size: int = 2) -> IRValue:
    """A TMP value carrying its producer identity."""
    return IRValue(MemSpace.TMP, name=f"t{tmp_id}", size=size, source_tmp=tmp_id)


def _reg(name: str, size: int = 2, source_tmp: int | None = None) -> IRValue:
    """A REG value, optionally tagged with a capturing temporary."""
    return IRValue(MemSpace.REG, name=name, size=size, source_tmp=source_tmp)


def _const(value: int, size: int = 2) -> IRValue:
    """A CONST operand."""
    return IRValue(MemSpace.CONST, const=value, size=size)


def _mov(dst: IRValue, src: IRValue) -> IRInstr:
    """A scalar MOV instruction."""
    return IRInstr(op="MOV", dst=dst, args=(src,), size=src.size or dst.size, addr=_ENTRY)


def _ssa(instrs: list[IRInstr]) -> SSABlock:
    """Build block-local SSA over one block."""
    return build_x86_16_block_local_ssa(
        IRBlock(addr=_ENTRY, instrs=tuple(instrs))
    )


def _bound_pairs(ssa_block: SSABlock) -> list[tuple[int, str | None, int | None]]:
    """Compact (instr_index, name, version) view of every emitted binding."""
    return [
        (binding.instr_index, binding.target.name, binding.version)
        for binding in ssa_block.bindings
    ]


def test_call_tmp_target_is_an_input_not_a_definition() -> None:
    """MOV t1; CALL dst=t1; MOV t2<-t1 binds only the two MOVs."""
    block = _ssa([
        _mov(_tmp(1), _reg("ax")),                      # 0: t1 = ax
        IRInstr("CALL", _tmp(1), (_const(0x1234, 4),), size=0, addr=_ENTRY),  # 1
        _mov(_tmp(2), _tmp(1)),                         # 2: t2 = t1
    ])
    assert _bound_pairs(block) == [(0, "t1", 0), (2, "t2", 0)]
    call_dst = block.instrs[1].dst
    assert call_dst is not None
    assert call_dst.version == 0 and call_dst.source_tmp == 1
    later_use = block.instrs[2].args[0]
    assert isinstance(later_use, IRValue) and later_use.version == 0


def test_call_register_target_without_definition_is_live_in() -> None:
    """A CALL register target with no prior definition reads live-in v0."""
    block = _ssa([
        IRInstr("CALL", _reg("ax"), (_const(0x1234, 4),), size=0, addr=_ENTRY),
    ])
    dst = block.instrs[0].dst
    assert dst is not None and dst.version == 0
    assert _bound_pairs(block) == []


def test_register_output_after_call_target_still_binds() -> None:
    """A real MOV definition of the same register binds independently after."""
    block = _ssa([
        IRInstr("CALL", _reg("ax"), (_const(0x1234, 4),), size=0, addr=_ENTRY),
        _mov(_reg("ax"), _const(0x55, 2)),
    ])
    assert _bound_pairs(block) == [(1, "ax", 1)]
    call_dst = block.instrs[0].dst
    assert call_dst is not None and call_dst.version == 0
    mov_dst = block.instrs[1].dst
    assert mov_dst is not None and mov_dst.version == 1


def test_non_call_overwrite_versions_unchanged() -> None:
    """Repeated TMP definitions still version 0,1 and reads follow them."""
    block = _ssa([
        _mov(_tmp(1), _const(0x11, 2)),
        _mov(_tmp(1), _const(0x22, 2)),
        _mov(_tmp(2), _tmp(1)),
    ])
    assert _bound_pairs(block) == [(0, "t1", 0), (1, "t1", 1), (2, "t2", 0)]
    use = block.instrs[2].args[0]
    assert isinstance(use, IRValue) and use.version == 1


def test_call_target_does_not_clobber_snapshot_captures() -> None:
    """A CALL target read does not disturb the MOV capture snapshot table."""
    block = _ssa([
        _mov(_tmp(1), _reg("sp")),
        IRInstr("CALL", _reg("sp", source_tmp=1), (), size=0, addr=_ENTRY),
        _mov(_tmp(2), _reg("sp", source_tmp=1)),
    ])
    assert _bound_pairs(block) == [(0, "t1", 0), (2, "t2", 0)]
    call_dst = block.instrs[1].dst
    assert call_dst is not None and call_dst.version == 0


def test_const_call_target_stays_unversioned() -> None:
    """A CONST call target is rewritten without any version decoration."""
    block = _ssa([
        IRInstr("CALL", _const(0x1234, 4), (), size=0, addr=_ENTRY),
    ])
    assert block.instrs[0].dst is not None
    assert block.instrs[0].dst.version is None
    assert _bound_pairs(block) == []


def _function(instrs: list[IRInstr], use_ssa: bool) -> IRFunctionArtifact | SSAFunctionArtifact:
    """Choose the exact raw or locally generated function projection."""
    raw = IRFunctionArtifact(_ENTRY, (IRBlock(_ENTRY, tuple(instrs)),))
    return build_x86_16_function_ssa(raw) if use_ssa else raw


@pytest.mark.parametrize("use_ssa", [False, True])
def test_scalar_index_call_target_retains_the_true_tmp_producer(use_ssa: bool) -> None:
    """A target read must not create a competing producer for a captured TMP."""
    artifact = _function([
        _mov(_tmp(1), _reg("ax")),
        IRInstr("CALL", _tmp(1), (), addr=_ENTRY),
        _mov(_tmp(2), _tmp(1)),
    ], use_ssa)
    definitions = build_scalar_definition_index_8616(artifact)
    source = artifact.blocks[0].instrs[2].args[0]
    assert isinstance(source, IRValue)
    producers = reaching_scalar_definitions_8616(
        definitions, source, block_addr=_ENTRY, before_index=2,
    )
    assert tuple(item.instr_index for item in producers) == (0,)
    assert tuple(item.instruction.op for item in producers) == ("MOV",)


@pytest.mark.parametrize("use_ssa", [False, True])
@pytest.mark.parametrize("target", [_tmp(1), _reg("ax"), _const(0x1234)])
def test_scalar_index_call_only_target_is_not_a_producer(
    use_ssa: bool, target: IRValue,
) -> None:
    """No target storage class can turn an input-only CALL into a definition."""
    artifact = _function([IRInstr("CALL", target, (), addr=_ENTRY)], use_ssa)
    assert build_scalar_definition_index_8616(artifact) == {}


@pytest.mark.parametrize("use_ssa", [False, True])
def test_scalar_index_real_register_output_after_call_still_defines(use_ssa: bool) -> None:
    """An explicit post-call MOV remains the sole defining operation."""
    artifact = _function([
        IRInstr("CALL", _reg("ax"), (), addr=_ENTRY),
        _mov(_reg("ax"), _const(0x55)),
    ], use_ssa)
    indexed = build_scalar_definition_index_8616(artifact)
    definitions = tuple(item for group in indexed.values() for item in group)
    assert tuple(item.instr_index for item in definitions) == (1,)
    assert tuple(item.instruction.op for item in definitions) == ("MOV",)


def test_scalar_definition_contract_refuses_an_input_only_call() -> None:
    """Even a manually supplied CALL record cannot assert a true definition."""
    assert not ScalarDefinition8616(
        _ENTRY, 0, IRInstr("CALL", _reg("ax"), (), addr=_ENTRY),
    ).complete
    assert ScalarDefinition8616(
        _ENTRY, 0, _mov(_reg("ax"), _const(0x55)),
    ).complete
