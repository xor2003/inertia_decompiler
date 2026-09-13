"""Typed frame evidence for tests that require a function-wide coordinate shift."""

from angr_platforms.X86_16.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
)


def proven_frame_coordinate(delta: int) -> FrameAccessArtifact:
    """Supply explicit frame proof, independently of local object bindings."""
    return FrameAccessArtifact(
        bp_coordinate=BPFrameCoordinateEvidence8616(
            status=FrameCoordinateStatus8616.PROVEN,
            bp_entry_sp_delta=delta,
            stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
        ),
    )
