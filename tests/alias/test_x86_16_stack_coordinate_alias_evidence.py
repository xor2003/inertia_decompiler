from types import SimpleNamespace

from angr.sim_variable import SimStackVariable
from inertia.ir.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
    StackFrameSlot,
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
from inertia.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    record_stack_variable_coordinate_projection_8616,
)

from inertia.alias.stack_memory_ssa import (
    build_x86_16_stack_memory_ssa_alias_artifact,
)


def _complete_stack_alias_artifact():
    instructions = tuple(
        IRInstr(
            "LOAD",
            IRValue(MemSpace.REG, name=f"r{index}", size=2),
            (
                IRAddress(
                    MemSpace.SS,
                    base=("bp",),
                    offset=offset,
                    size=2,
                    status=AddressStatus.STABLE,
                    segment_origin=SegmentOrigin.DEFAULTED,
                ),
            ),
            size=2,
            addr=0x1010 + index,
        )
        for index, offset in enumerate((-2, -4, -6))
    )
    return build_x86_16_stack_memory_ssa_alias_artifact(
        build_x86_16_function_ssa(
            IRFunctionArtifact(
                function_addr=0x1000,
                blocks=(IRBlock(addr=0x1000, instrs=instructions),),
            )
        )
    )


def test_complete_alias_evidence_disambiguates_anonymous_entry_sp_clone() -> None:
    codegen = SimpleNamespace(
        _inertia_stack_memory_ssa_alias_artifact=_complete_stack_alias_artifact()
    )
    for bp_offset, entry_sp_offset in ((-2, -4), (-4, -6), (-6, -8)):
        variable = SimStackVariable(entry_sp_offset, 2, base="bp")
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=variable,
            cvar=object(),
            bp_offset=bp_offset,
            entry_sp_offset=entry_sp_offset,
            size=2,
        )

    anonymous_entry_sp_clone = SimStackVariable(-8, 2, base="bp")
    colliding_raw_bp_variable = SimStackVariable(-4, 2, base="bp")

    assert machine_bp_offset_for_stack_variable_8616(
        codegen,
        anonymous_entry_sp_clone,
    ) == -6
    assert machine_bp_offset_for_stack_variable_8616(
        codegen,
        colliding_raw_bp_variable,
    ) is None


def test_typed_frame_evidence_disambiguates_anonymous_entry_sp_clone() -> None:
    codegen = SimpleNamespace(
        _inertia_vex_ir_frame=FrameAccessArtifact(
            slots=tuple(
                StackFrameSlot("bp", offset, "local", 2)
                for offset in (-2, -4, -6)
            ),
            bp_coordinate=BPFrameCoordinateEvidence8616(
                status=FrameCoordinateStatus8616.PROVEN,
                bp_entry_sp_delta=-2,
                stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
            ),
        )
    )
    for bp_offset, entry_sp_offset in ((-2, -4), (-4, -6), (-6, -8)):
        record_stack_variable_coordinate_projection_8616(
            codegen,
            variable=SimStackVariable(entry_sp_offset, 2, base="bp"),
            cvar=object(),
            bp_offset=bp_offset,
            entry_sp_offset=entry_sp_offset,
            size=2,
        )

    assert machine_bp_offset_for_stack_variable_8616(
        codegen,
        SimStackVariable(-8, 2, base="bp"),
    ) == -6
    assert machine_bp_offset_for_stack_variable_8616(
        codegen,
        SimStackVariable(-4, 2, base="bp"),
    ) is None
