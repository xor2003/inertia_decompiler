from __future__ import annotations

from inertia.ir.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
)
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

from inertia.alias.stack_coordinate_projection import (
    StackCoordinateProjectionStatus8616,
    project_stack_offset_to_machine_bp_8616,
)
from inertia.alias.stack_memory_ssa import (
    build_x86_16_stack_memory_ssa_alias_artifact,
)


def _source(*ranges: tuple[int, int]):
    instructions = tuple(
        IRInstr(
            "LOAD",
            IRValue(MemSpace.REG, name=f"r{index}", size=size),
            (
                IRAddress(
                    MemSpace.SS,
                    base=("bp",),
                    offset=offset,
                    size=size,
                    status=AddressStatus.STABLE,
                    segment_origin=SegmentOrigin.DEFAULTED,
                ),
            ),
            size=size,
        )
        for index, (offset, size) in enumerate(ranges)
    )
    return build_x86_16_stack_memory_ssa_alias_artifact(
        build_x86_16_function_ssa(
            IRFunctionArtifact(
                function_addr=0x1000,
                blocks=(IRBlock(addr=0x1000, instrs=instructions),),
            )
        )
    )


def _frame() -> FrameAccessArtifact:
    return FrameAccessArtifact(
        bp_coordinate=BPFrameCoordinateEvidence8616(
            status=FrameCoordinateStatus8616.PROVEN,
            bp_entry_sp_delta=-2,
            detail="test frame",
            stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
        )
    )


def test_entry_sp_argument_projects_to_alias_machine_bp_range() -> None:
    result = project_stack_offset_to_machine_bp_8616(
        _source((4, 2)),
        _frame(),
        2,
        2,
    )

    assert result.status is StackCoordinateProjectionStatus8616.PROJECTED_ENTRY_SP
    assert result.bp_offset == 4
    assert result.stats.complete is True


def test_raw_machine_bp_range_remains_raw() -> None:
    result = project_stack_offset_to_machine_bp_8616(
        _source((4, 2)),
        _frame(),
        4,
        2,
    )

    assert result.status is StackCoordinateProjectionStatus8616.RAW_MACHINE_BP
    assert result.bp_offset == 4


def test_numeric_coordinate_collision_refuses() -> None:
    result = project_stack_offset_to_machine_bp_8616(
        _source((2, 2), (4, 2)),
        _frame(),
        2,
        2,
    )

    assert result.status is StackCoordinateProjectionStatus8616.AMBIGUOUS
    assert result.bp_offset is None
    assert result.stats.complete is True
