from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr.sim_variable import SimStackVariable
from inertia.ir.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
)
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.structuring.decompiler_structuring_stage import DECOMPILER_STRUCTURING_PASSES
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from inertia.ir.ssa_function import build_x86_16_function_ssa
from inertia.ir.ssa_memory_contracts import SSAMemoryOverlapRelation8616
from inertia.lowering.stack_memory_ssa import (
    lower_x86_16_stack_memory_ssa_alias_artifact,
)
from inertia.lowering.stack_memory_ssa_contracts import (
    StackMemorySSALoweringRefusalKind8616,
)
from inertia.pipeline.errors import PipelineHardError

from inertia.alias.logical_stack_memory_projection import (
    LogicalStackMemoryAliasFailure8616,
    LogicalStackMemoryAliasRefusal8616,
)
from inertia.alias.stack_memory_ssa import build_x86_16_stack_memory_ssa_alias_artifact
from inertia.alias.stack_memory_ssa_contracts import StackMemoryAliasStats8616
from inertia.widening.stack_memory_objects import (
    apply_x86_16_stack_memory_object_widening_8616,
    build_x86_16_stack_memory_object_widening_artifact,
)
from inertia.widening.stack_memory_objects_contracts import (
    StackMemoryObjectWideningRefusalKind8616,
)


def _bp_slot(offset: int, size: int) -> IRAddress:
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.DEFAULTED,
    )


def _store(address: IRAddress, value: int = 1) -> IRInstr:
    return IRInstr(
        "STORE",
        None,
        (address, IRValue(MemSpace.CONST, const=value, size=address.size)),
        size=address.size,
    )


def _load(address: IRAddress) -> IRInstr:
    return IRInstr(
        "LOAD",
        IRValue(MemSpace.REG, name="ax", size=address.size),
        (address,),
        size=address.size,
    )


def _alias_for_blocks(*blocks: IRBlock):
    function_ssa = build_x86_16_function_ssa(
        IRFunctionArtifact(function_addr=0x1000, blocks=blocks)
    )
    return build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)


def test_stack_memory_object_widening_accepts_unique_containing_word() -> None:
    word = _bp_slot(-4, 2)
    high_byte = _bp_slot(-3, 1)
    source = _alias_for_blocks(
        IRBlock(addr=0x1000, instrs=(_store(word), _load(high_byte)))
    )

    artifact = build_x86_16_stack_memory_object_widening_artifact(source)

    assert artifact.complete is True
    assert artifact.stats.raw_fact_count == artifact.stats.materialized_count == 1
    assert artifact.stats.failure_count == 0
    assert artifact.refusals == ()
    assert len(artifact.candidates) == 1
    candidate = artifact.candidates[0]
    assert (candidate.address.offset, candidate.address.size) == (-4, 2)
    assert [(address.offset, address.size) for address in candidate.covered_addresses] == [
        (-4, 1),
        (-4, 2),
        (-3, 1),
    ]
    assert candidate.versions == (1, 2)
    assert [kind.value for kind in candidate.fact_kinds] == ["load", "store"]


def test_stack_memory_object_widening_refuses_partial_overlap_component() -> None:
    word = _bp_slot(-4, 2)
    shifted_word = _bp_slot(-3, 2)
    source = _alias_for_blocks(
        IRBlock(addr=0x1000, instrs=(_store(word), _load(shifted_word)))
    )

    artifact = build_x86_16_stack_memory_object_widening_artifact(source)

    assert artifact.complete is True
    assert artifact.candidates == ()
    assert artifact.stats.raw_fact_count == artifact.stats.failure_count == 1
    assert artifact.refusals[0].kind is StackMemoryObjectWideningRefusalKind8616.PARTIAL_OVERLAP
    assert {(address.offset, address.size) for address in artifact.refusals[0].addresses} >= {
        (-4, 2),
        (-3, 2),
    }


def test_logical_alias_refusal_survives_widening_and_lowering() -> None:
    source = _alias_for_blocks(IRBlock(addr=0x1000))
    logical_refusal = LogicalStackMemoryAliasRefusal8616(
        LogicalStackMemoryAliasFailure8616.MISSING_EXECUTION_SLICE,
        "logical operand has no exact execution slice",
    )
    source = replace(
        source,
        logical_refusals=(logical_refusal,),
        logical_stats=StackMemoryAliasStats8616(raw_fact_count=1, failure_count=1),
    )

    widening = build_x86_16_stack_memory_object_widening_artifact(source)

    assert widening.complete is True
    assert widening.stats.raw_fact_count == widening.stats.failure_count == 1
    assert widening.refusals[0].kind is StackMemoryObjectWideningRefusalKind8616.SOURCE_LOGICAL_ALIAS_REFUSAL
    assert widening.refusals[0].source_logical_refusal is logical_refusal

    codegen = SimpleNamespace(
        _inertia_stack_memory_ssa_alias_artifact=source,
        _inertia_stack_memory_object_widening_artifact=widening,
    )
    lowered = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)

    assert lowered is not None and lowered.complete is True
    assert lowered.stats.raw_fact_count == lowered.stats.failure_count == 1
    assert lowered.refusals[0].kind is StackMemorySSALoweringRefusalKind8616.SOURCE_WIDENING_REFUSAL


def test_stack_memory_object_widening_accepts_non_laminar_views_with_unique_owner() -> None:
    owner = _bp_slot(-8, 4)
    low_word = _bp_slot(-8, 2)
    shifted_word = _bp_slot(-7, 2)
    source = _alias_for_blocks(
        IRBlock(addr=0x1000, instrs=(_store(owner), _load(low_word), _load(shifted_word)))
    )

    artifact = build_x86_16_stack_memory_object_widening_artifact(source)

    assert any(
        overlap.source.relation is SSAMemoryOverlapRelation8616.PARTIAL
        for overlap in source.overlaps
    )
    assert artifact.complete is True
    assert artifact.refusals == ()
    assert artifact.stats.raw_fact_count == artifact.stats.materialized_count == 1
    assert len(artifact.candidates) == 1
    candidate = artifact.candidates[0]
    assert (candidate.address.offset, candidate.address.size) == (-8, 4)
    assert {(address.offset, address.size) for address in candidate.covered_addresses} >= {
        (-8, 4),
        (-8, 2),
        (-7, 2),
    }


def test_stack_memory_lowering_materializes_non_laminar_unique_owner_atomically() -> None:
    source = _alias_for_blocks(
        IRBlock(
            addr=0x1000,
            instrs=(
                _store(_bp_slot(-8, 4)),
                _load(_bp_slot(-8, 2)),
                _load(_bp_slot(-7, 2)),
            ),
        )
    )
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        cfunc=SimpleNamespace(
            addr=source.function_addr,
            variables_in_use={},
            unified_local_vars={},
            arg_list=(),
            sort_local_vars=lambda: None,
        ),
        _inertia_stack_memory_ssa_alias_artifact=source,
        _inertia_stack_memory_object_widening_artifact=(
            build_x86_16_stack_memory_object_widening_artifact(source)
        ),
        _inertia_vex_ir_frame=FrameAccessArtifact(
            bp_coordinate=BPFrameCoordinateEvidence8616(
                status=FrameCoordinateStatus8616.PROVEN,
                bp_entry_sp_delta=-2,
                detail="test fixture",
                stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
            )
        ),
        next_idx=lambda _name: 1,
        next_ident=lambda name: f"{name}_0",
        next_node_idx=lambda: 1,
    )

    artifact = lower_x86_16_stack_memory_ssa_alias_artifact(codegen)

    assert artifact is not None and artifact.complete is True
    assert artifact.refusals == ()
    assert len(artifact.candidates) == 1
    assert (
        artifact.candidates[0].address.offset,
        artifact.candidates[0].entry_sp_offset,
    ) == (-8, -10)
    stack_variables = [
        variable for variable in codegen.cfunc.variables_in_use if isinstance(variable, SimStackVariable)
    ]
    assert [(variable.offset, variable.size) for variable in stack_variables] == [(-10, 4)]


def test_stack_memory_object_widening_consumes_every_byte_phi() -> None:
    word = _bp_slot(-4, 2)
    high_byte = _bp_slot(-3, 1)
    source = _alias_for_blocks(
        IRBlock(addr=0x1000, successor_addrs=(0x1010, 0x1020)),
        IRBlock(addr=0x1010, successor_addrs=(0x1030,), instrs=(_store(word, 1),)),
        IRBlock(addr=0x1020, successor_addrs=(0x1030,), instrs=(_store(word, 2),)),
        IRBlock(addr=0x1030, instrs=(_load(high_byte),)),
    )

    artifact = build_x86_16_stack_memory_object_widening_artifact(source)

    assert artifact.complete is True
    candidate = artifact.candidates[0]
    assert len(candidate.source_facts) == len(source.facts)
    assert set(candidate.source_facts) == set(source.facts)
    assert "phi" in {kind.value for kind in candidate.fact_kinds}
    assert {fact.address.offset for fact in candidate.source_facts if fact.kind.value == "phi"} == {
        -4,
        -3,
    }


def test_stack_memory_object_widening_attaches_to_codegen_boundary() -> None:
    word = _bp_slot(-4, 2)
    high_byte = _bp_slot(-3, 1)
    source = _alias_for_blocks(
        IRBlock(addr=0x1000, instrs=(_store(word), _load(high_byte)))
    )
    codegen = SimpleNamespace(_inertia_stack_memory_ssa_alias_artifact=source)

    changed = apply_x86_16_stack_memory_object_widening_8616(object(), codegen)

    artifact = codegen._inertia_stack_memory_object_widening_artifact
    assert changed is False
    assert artifact.complete is True
    assert artifact.source_alias is source
    assert apply_x86_16_stack_memory_object_widening_8616(object(), codegen) is False
    assert codegen._inertia_stack_memory_object_widening_artifact is artifact


def test_stack_memory_object_widening_runs_after_alias_on_main_path() -> None:
    names = tuple(spec.name for spec in DECOMPILER_STRUCTURING_PASSES)

    assert names.index("_stack_memory_ssa_alias_artifact_8616") < names.index(
        "_stack_memory_object_widening_artifact"
    )
    assert names.index("_carry_borrow_widening_artifact_8616") < names.index(
        "_stack_memory_object_widening_artifact"
    )


def test_stack_memory_lowering_rejects_widening_from_different_alias_source() -> None:
    source = _alias_for_blocks(
        IRBlock(addr=0x1000, instrs=(_store(_bp_slot(-4, 2)), _load(_bp_slot(-3, 1))))
    )
    stale_source = _alias_for_blocks(
        IRBlock(addr=0x1000, instrs=(_store(_bp_slot(-8, 2)), _load(_bp_slot(-7, 1))))
    )
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        cfunc=SimpleNamespace(
            addr=source.function_addr,
            variables_in_use={},
            unified_local_vars={},
            arg_list=(),
            sort_local_vars=lambda: None,
        ),
        _inertia_stack_memory_ssa_alias_artifact=source,
        _inertia_stack_memory_object_widening_artifact=(
            build_x86_16_stack_memory_object_widening_artifact(stale_source)
        ),
        _inertia_vex_ir_frame=FrameAccessArtifact(
            bp_coordinate=BPFrameCoordinateEvidence8616(
                status=FrameCoordinateStatus8616.PROVEN,
                bp_entry_sp_delta=-2,
                detail="test fixture",
                stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
            )
        ),
    )

    with pytest.raises(PipelineHardError, match="does not consume this exact Alias artifact"):
        lower_x86_16_stack_memory_ssa_alias_artifact(codegen)
