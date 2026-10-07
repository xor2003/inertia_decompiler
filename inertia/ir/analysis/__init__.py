"""Analysis-layer package exports.

Layer: Analysis.
Responsibility: owns derived read-only analysis artifacts from typed IR.
Do not own alias state, materialize objects, validate acceptance, rewrite emitted C,
or use rendered text as proof.
"""

from __future__ import annotations

from .alias import MemRange, Storage, may_alias, overlap, storage_of
from .stack_frame_ir import (
    FrameAccessArtifact,
    StackFrameSlot,
    build_x86_16_ir_frame_access_artifact,
)

__all__ = [
    "FrameAccessArtifact",
    "MemRange",
    "StackFrameSlot",
    "Storage",
    "build_x86_16_ir_frame_access_artifact",
    "may_alias",
    "overlap",
    "storage_of",
]
