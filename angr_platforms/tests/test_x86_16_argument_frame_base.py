from types import SimpleNamespace

from angr_platforms.X86_16.alias.segment_stack_restore import (
    SegmentStackRestoreArtifact8616,
    SegmentStackRestoreFact8616,
    SegmentStackRestoreVerdict8616,
)
from angr_platforms.X86_16.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.argument_frame_base import (
    FAR_FIRST_ARGUMENT_BP_OFFSET_8616,
    NEAR_FIRST_ARGUMENT_BP_OFFSET_8616,
    msc_calling_convention_for_function_8616,
    proven_far_return_frame_8616,
    proven_first_argument_machine_bp_offset_8616,
)
from angr_platforms.X86_16.simos_86_16 import (
    SimCC8616MSClarge,
    SimCC8616MSCsmall,
)


def _codegen(far: bool) -> SimpleNamespace:
    """One codegen boundary with or without a proven far return frame."""
    facts: tuple[SegmentStackRestoreFact8616, ...] = ()
    if far:
        facts = (
            SegmentStackRestoreFact8616(
                block_addr=0x1000,
                restore_instruction_addr=0x1010,
                restore_register="cs",
                saved_instruction_addr=None,
                saved_register=None,
                stack_offsets=(4, 5),
                verdict=SegmentStackRestoreVerdict8616.UNKNOWN_REFUSE,
            ),
        )
    return SimpleNamespace(
        _inertia_vex_ir_frame=FrameAccessArtifact(
            bp_coordinate=BPFrameCoordinateEvidence8616(
                FrameCoordinateStatus8616.PROVEN,
                -2,
                "test",
                FrameCoordinateStats8616(1, 1, 1, 1, 0),
            )
        ),
        _inertia_segment_stack_restore_artifact=SegmentStackRestoreArtifact8616(facts=facts),
        _inertia_vex_ir_artifact=SimpleNamespace(
            blocks=(
                SimpleNamespace(
                    instrs=(SimpleNamespace(op="MOV", addr=0x1000), SimpleNamespace(op="RET", addr=0x1010))
                ),
            )
        ),
    )


def test_near_frame_keeps_near_argument_base() -> None:
    assert proven_far_return_frame_8616(_codegen(far=False)) is False
    assert proven_first_argument_machine_bp_offset_8616(_codegen(far=False)) == NEAR_FIRST_ARGUMENT_BP_OFFSET_8616


def test_far_cs_restore_proves_far_argument_base() -> None:
    assert proven_far_return_frame_8616(_codegen(far=True)) is True
    assert proven_first_argument_machine_bp_offset_8616(_codegen(far=True)) == FAR_FIRST_ARGUMENT_BP_OFFSET_8616


def test_msc_convention_selects_large_only_for_proven_far_function(monkeypatch) -> None:
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    function = SimpleNamespace(addr=0x1000)

    def _far_proof(project_arg: object, addr: int) -> bool:
        assert project_arg is project
        assert addr == 0x1000
        return True

    monkeypatch.setattr(
        "angr_platforms.X86_16.lowering.argument_frame_base.proven_far_return_frame_at_8616",
        _far_proof,
    )

    assert isinstance(
        msc_calling_convention_for_function_8616(project, function),
        SimCC8616MSClarge,
    )

    def _near_proof(project_arg: object, addr: int) -> bool:
        del project_arg, addr
        return False

    monkeypatch.setattr(
        "angr_platforms.X86_16.lowering.argument_frame_base.proven_far_return_frame_at_8616",
        _near_proof,
    )

    assert isinstance(
        msc_calling_convention_for_function_8616(project, function),
        SimCC8616MSCsmall,
    )
