from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.alias.stack_memory_ssa import (
    StackMemoryAliasFactKind8616,
    StackMemoryAliasRefusalKind8616,
    apply_x86_16_stack_memory_ssa_alias_artifact,
    build_x86_16_stack_memory_ssa_alias_artifact,
)
from angr_platforms.X86_16.decompiler_structuring_stage import DECOMPILER_STRUCTURING_PASSES
from angr_platforms.X86_16.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.ir.ssa import SSABlock
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact, build_x86_16_function_ssa
from angr_platforms.X86_16.ir.ssa_memory_contracts import (
    SSAMemoryAccess8616,
    SSAMemoryAccessKind8616,
    SSAMemoryIncomingValue8616,
    SSAMemoryOverlap8616,
    SSAMemoryOverlapRelation8616,
    SSAMemoryPhiNode8616,
    SSAMemoryStats8616,
)
from angr_platforms.X86_16.pipeline.errors import PipelineHardError


def _bp_slot(offset: int, size: int, *, version: int | None = None) -> IRAddress:
    return IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.DEFAULTED,
        version=version,
    )


def _branching_stack_artifact() -> IRFunctionArtifact:
    slot = _bp_slot(-2, 2)
    return IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(addr=0x1000, successor_addrs=(0x1010, 0x1020)),
            IRBlock(
                addr=0x1010,
                successor_addrs=(0x1030,),
                instrs=(IRInstr("STORE", None, (slot, IRValue(MemSpace.CONST, const=1, size=2)), size=2),),
            ),
            IRBlock(
                addr=0x1020,
                successor_addrs=(0x1030,),
                instrs=(IRInstr("STORE", None, (slot, IRValue(MemSpace.CONST, const=2, size=2)), size=2),),
            ),
            IRBlock(
                addr=0x1030,
                instrs=(IRInstr("LOAD", IRValue(MemSpace.REG, name="ax", size=2), (slot,), size=2),),
            ),
        ),
    )


def test_stack_memory_ssa_alias_projects_accesses_and_phi_exactly() -> None:
    function_ssa = build_x86_16_function_ssa(_branching_stack_artifact())

    artifact = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)

    assert artifact.source_ssa is function_ssa
    assert artifact.complete is True
    expected_accesses_and_phi = 4
    assert artifact.stats.raw_fact_count == expected_accesses_and_phi
    assert artifact.stats.materialized_count == expected_accesses_and_phi
    assert artifact.stats.failure_count == 0
    assert [fact.kind for fact in artifact.facts] == [
        StackMemoryAliasFactKind8616.STORE,
        StackMemoryAliasFactKind8616.STORE,
        StackMemoryAliasFactKind8616.LOAD,
        StackMemoryAliasFactKind8616.PHI,
    ]
    assert [fact.address.version for fact in artifact.facts] == [1, 2, 3, 3]
    assert artifact.facts[-1].incoming_versions == (1, 2)
    assert all(fact.storage == artifact.facts[0].storage for fact in artifact.facts)


def test_stack_memory_ssa_alias_projects_partial_overlap_as_composed_views() -> None:
    word = _bp_slot(-4, 2)
    overlap = _bp_slot(-3, 2)
    function_ssa = build_x86_16_function_ssa(
        IRFunctionArtifact(
            function_addr=0x1000,
            blocks=(
                IRBlock(
                    addr=0x1000,
                    instrs=(
                        IRInstr("STORE", None, (word, IRValue(MemSpace.CONST, const=1, size=2)), size=2),
                        IRInstr("LOAD", IRValue(MemSpace.REG, name="ax", size=2), (overlap,), size=2),
                    ),
                ),
            ),
        )
    )

    artifact = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)

    assert artifact.complete is True
    assert artifact.facts == ()
    expected_accesses = 2
    expected_accesses_and_overlap = expected_accesses + 1
    assert len(artifact.accesses) == expected_accesses
    assert artifact.stats.raw_fact_count == expected_accesses_and_overlap
    assert artifact.stats.materialized_count == expected_accesses_and_overlap
    assert artifact.stats.failure_count == 0
    alias_overlap = artifact.overlaps[0]
    assert alias_overlap.source.relation is SSAMemoryOverlapRelation8616.PARTIAL
    assert alias_overlap.left_storage.contains(alias_overlap.intersection_storage)
    assert alias_overlap.right_storage.contains(alias_overlap.intersection_storage)
    assert not alias_overlap.left_storage.contains(alias_overlap.right_storage)
    assert not alias_overlap.right_storage.contains(alias_overlap.left_storage)
    assert artifact.source_refusals == ()
    assert artifact.refusals == ()
    assert [len(access.slices) for access in artifact.accesses] == [2, 2]
    assert artifact.to_dict()["accesses"][0]["source"]["complete"] is True


def test_stack_memory_ssa_alias_preserves_contained_byte_view() -> None:
    word = _bp_slot(-4, 2)
    byte = _bp_slot(-3, 1)
    function_ssa = build_x86_16_function_ssa(
        IRFunctionArtifact(
            function_addr=0x1000,
            blocks=(
                IRBlock(
                    addr=0x1000,
                    instrs=(
                        IRInstr("STORE", None, (word, IRValue(MemSpace.CONST, const=1, size=2)), size=2),
                        IRInstr("LOAD", IRValue(MemSpace.REG, name="al", size=1), (byte,), size=1),
                    ),
                ),
            ),
        )
    )

    artifact = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)

    assert artifact.complete is True
    assert len(artifact.facts) == 1
    assert artifact.facts[0].kind is StackMemoryAliasFactKind8616.LOAD
    expected_written_byte_version = 2
    expected_word_slices = 2
    expected_accesses_and_overlap = 3
    assert artifact.facts[0].address.version == expected_written_byte_version
    assert len(artifact.accesses) == 1
    assert len(artifact.accesses[0].slices) == expected_word_slices
    assert artifact.stats.raw_fact_count == expected_accesses_and_overlap
    assert artifact.stats.materialized_count == expected_accesses_and_overlap
    assert artifact.stats.failure_count == 0
    alias_overlap = artifact.overlaps[0]
    assert alias_overlap.source.relation is SSAMemoryOverlapRelation8616.LEFT_CONTAINS_RIGHT
    assert alias_overlap.left_storage.contains(alias_overlap.right_storage)
    assert alias_overlap.right_storage == alias_overlap.intersection_storage


@pytest.mark.parametrize("unclassifiable_position", (None, 0, 1, 2))
def test_stack_memory_ssa_alias_refuses_inconsistent_overlap_relation(unclassifiable_position) -> None:
    word = _bp_slot(-4, 2)
    byte = _bp_slot(-3, 1)
    addresses = [word, byte, byte]
    if unclassifiable_position is not None:
        addresses[unclassifiable_position] = replace(
            addresses[unclassifiable_position], status=AddressStatus.PROVISIONAL,
        )
    function_ssa = SSAFunctionArtifact(
        function_addr=0x1000,
        blocks=(),
        memory_overlaps=(
            SSAMemoryOverlap8616(
                *addresses,
                SSAMemoryOverlapRelation8616.RIGHT_CONTAINS_LEFT,
            ),
        ),
        memory_stats=SSAMemoryStats8616(1, 1, 1, 1, 0),
    )

    artifact = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)

    assert artifact.complete is True
    assert artifact.overlaps == ()
    assert artifact.stats.raw_fact_count == artifact.stats.failure_count == 1
    if unclassifiable_position is None:
        assert artifact.refusals[0].kind is StackMemoryAliasRefusalKind8616.INCONSISTENT_OVERLAP_STORAGE
    else:
        assert artifact.refusals[0].kind is StackMemoryAliasRefusalKind8616.ALIAS_FAILURE
        assert artifact.refusals[0].address is addresses[unclassifiable_position]


def test_stack_memory_ssa_alias_refuses_incomplete_composed_access() -> None:
    address = _bp_slot(-4, 2)
    function_ssa = SSAFunctionArtifact(
        function_addr=0x1000,
        blocks=(),
        memory_accesses=(
            SSAMemoryAccess8616(
                SSAMemoryAccessKind8616.LOAD,
                0x1000,
                0,
                address,
                (),
            ),
        ),
        memory_stats=SSAMemoryStats8616(1, 1, 1, 1, 0),
    )

    artifact = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)

    assert artifact.complete is True
    assert artifact.accesses == ()
    assert artifact.stats.raw_fact_count == artifact.stats.failure_count == 1
    assert artifact.refusals[0].kind is StackMemoryAliasRefusalKind8616.INCOMPLETE_ACCESS_SLICES


@pytest.mark.parametrize("provisional_position,missing_version", [
    (None, False), (0, False), (1, False), (2, False),
    (0, True), (1, True), (2, True),
])
def test_stack_memory_ssa_alias_refuses_phi_with_mixed_storage_identity(
    provisional_position: int | None, missing_version: bool,
) -> None:
    target = _bp_slot(-2, 2, version=3)
    function_ssa = SSAFunctionArtifact(
        function_addr=0x1000,
        blocks=(),
        memory_phi_nodes=(
            SSAMemoryPhiNode8616(
                block_addr=0x1030,
                key=("ss", ("bp",), -2, 2),
                target=target,
                incoming=(
                    SSAMemoryIncomingValue8616(0x1010, _bp_slot(-2, 2, version=1)),
                    SSAMemoryIncomingValue8616(0x1020, _bp_slot(-4, 2, version=2)),
                ),
            ),
        ),
    )

    if provisional_position is not None:
        phi = function_ssa.memory_phi_nodes[0]
        addresses = [phi.target, *(item.address for item in phi.incoming)]
        address = addresses[provisional_position]
        addresses[provisional_position] = (
            replace(address, version=None) if missing_version
            else replace(address, status=AddressStatus.PROVISIONAL)
        )
        phi = replace(phi, target=addresses[0], incoming=tuple(
            replace(item, address=address) for item, address in zip(phi.incoming, addresses[1:], strict=True)
        ))
        function_ssa = replace(function_ssa, memory_phi_nodes=(phi,))
    artifact = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)

    assert artifact.complete is True
    assert artifact.facts == ()
    assert artifact.stats.raw_fact_count == artifact.stats.failure_count == 1
    expected = (StackMemoryAliasRefusalKind8616.INCONSISTENT_PHI_STORAGE
                if provisional_position is None else StackMemoryAliasRefusalKind8616.ALIAS_FAILURE)
    if missing_version:
        expected = StackMemoryAliasRefusalKind8616.UNVERSIONED_PHI
    assert artifact.refusals[0].kind is expected


def test_stack_memory_ssa_alias_refuses_all_inputs_when_upstream_is_incomplete() -> None:
    slot = _bp_slot(-2, 2, version=1)
    function_ssa = SSAFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            SSABlock(
                addr=0x1000,
                instrs=(IRInstr("LOAD", IRValue(MemSpace.REG, name="ax", size=2), (slot,), size=2),),
                bindings=(),
            ),
        ),
        memory_stats=SSAMemoryStats8616(raw_fact_count=1),
    )

    artifact = build_x86_16_stack_memory_ssa_alias_artifact(function_ssa)

    assert artifact.complete is False
    assert artifact.facts == ()
    assert artifact.stats.raw_fact_count == artifact.stats.failure_count == 1
    assert artifact.refusals[0].kind is StackMemoryAliasRefusalKind8616.UPSTREAM_INCOMPLETE


def test_stack_memory_ssa_alias_apply_attaches_typed_artifact() -> None:
    function_ssa = build_x86_16_function_ssa(_branching_stack_artifact())
    codegen = SimpleNamespace(_inertia_vex_ir_function_ssa=function_ssa)

    assert apply_x86_16_stack_memory_ssa_alias_artifact(SimpleNamespace(), codegen) is False
    assert codegen._inertia_stack_memory_ssa_alias_artifact.complete is True
    assert apply_x86_16_stack_memory_ssa_alias_artifact(SimpleNamespace(), SimpleNamespace()) is False


def test_stack_memory_ssa_alias_apply_rebuilds_for_replaced_ssa_source() -> None:
    first_ssa = build_x86_16_function_ssa(_branching_stack_artifact())
    second_ssa = replace(first_ssa, summary={"generation": 2})
    codegen = SimpleNamespace(_inertia_vex_ir_function_ssa=first_ssa)

    assert apply_x86_16_stack_memory_ssa_alias_artifact(SimpleNamespace(), codegen) is False
    first_alias = codegen._inertia_stack_memory_ssa_alias_artifact
    codegen._inertia_vex_ir_function_ssa = second_ssa

    assert apply_x86_16_stack_memory_ssa_alias_artifact(SimpleNamespace(), codegen) is False
    second_alias = codegen._inertia_stack_memory_ssa_alias_artifact
    assert second_alias is not first_alias
    assert second_alias.source_ssa is second_ssa


def test_stack_memory_ssa_alias_apply_hard_fails_open_upstream_accounting() -> None:
    function_ssa = SSAFunctionArtifact(
        function_addr=0x1000,
        blocks=(),
        memory_stats=SSAMemoryStats8616(raw_fact_count=1),
    )

    with pytest.raises(PipelineHardError, match="incomplete evidence accounting"):
        apply_x86_16_stack_memory_ssa_alias_artifact(
            SimpleNamespace(),
            SimpleNamespace(_inertia_vex_ir_function_ssa=function_ssa),
        )


def test_structuring_stage_runs_stack_memory_alias_immediately_after_vex_ir() -> None:
    names = tuple(spec.name for spec in DECOMPILER_STRUCTURING_PASSES)

    vex_index = names.index("_vex_ir_artifact_8616")
    memory_alias_index = names.index("_stack_memory_ssa_alias_artifact_8616")
    restoration_index = names.index("_segment_stack_restore_artifact_8616")
    assert vex_index < memory_alias_index < restoration_index
