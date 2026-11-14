# cython: language_level=3, infer_types=True
"""Function-level typed IR artifact contract.

Layer: IR.
Responsibility: retain blocks, refusals, diagnostics, and authoritative logical
memory evidence together while IR artifacts are reconstructed by later stages.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass, field
from typing import TYPE_CHECKING
import dataclasses
FunctionLifecycle8616 = typing.TypeVar("FunctionLifecycle8616")
FunctionLifecycleStage8616 = typing.TypeVar("FunctionLifecycleStage8616")
FunctionSourceRevision8616 = typing.TypeVar("FunctionSourceRevision8616")
IRBlock = typing.TypeVar("IRBlock")
IRFunctionConditionArtifact8616 = typing.TypeVar("IRFunctionConditionArtifact8616")
IRLogicalMemoryArtifact8616 = typing.TypeVar("IRLogicalMemoryArtifact8616")
IRRefusal = typing.TypeVar("IRRefusal")

if TYPE_CHECKING:
    from .core import IRBlock, IRRefusal
    from .function_condition_artifact import IRFunctionConditionArtifact8616
    from .function_lifecycle import FunctionLifecycle8616
    from .function_readiness_contracts import (
        FunctionLifecycleStage8616,
        FunctionSourceRevision8616,
    )
    from .logical_memory_contracts import IRLogicalMemoryArtifact8616


@cython.ccall
def _default_lifecycle_stage_8616() -> FunctionLifecycleStage8616:
    """Resolve the canonical IR stage lazily to avoid import cycles."""
    from .function_readiness_contracts import FunctionLifecycleStage8616

    return FunctionLifecycleStage8616.IR


@cython.ccall
def _default_function_lifecycle_8616() -> FunctionLifecycle8616:
    """Create an unbound projection handle without introducing an import cycle."""
    from .function_lifecycle import FunctionLifecycle8616

    return FunctionLifecycle8616()


@dataclasses.dataclass(frozen=True, )
class IRFunctionArtifact:
    """Typed IR artifact for one recovered function and its logical accesses.

    ``source_revision`` is the builder-attested source generation the artifact
    was lifted from. ``None`` means the producer recorded no attestation; the
    owning registry binds publication-observed revisions for such artifacts.
    ``lifecycle_stage`` describes this immutable projection. ``lifecycle``
    transports the authoritative function-wide producer evidence, last checked
    maturity and typed refusals shared with SSA and later consumers.
    """

    function_addr: cython.longlong
    blocks: tuple[IRBlock, ...] = ()
    refusals: tuple[IRRefusal, ...] = ()
    summary: object = field(default_factory=dict)
    logical_memory: IRLogicalMemoryArtifact8616 | None = None
    condition_evidence: IRFunctionConditionArtifact8616 | None = None
    source_revision: FunctionSourceRevision8616 | None = None
    lifecycle_stage: FunctionLifecycleStage8616 = field(
        default_factory=_default_lifecycle_stage_8616
    )

    lifecycle: FunctionLifecycle8616 = field(
        default_factory=_default_function_lifecycle_8616, compare=False, repr=False,
    )

    def to_dict(self) -> dict[str, object]:
        """Serialize this function-level typed IR artifact."""
        return {
            "function_addr": self.function_addr,
            "blocks": [block.to_dict() for block in iter(self.blocks)],
            **self.non_block_payload_8616(),
        }

    def non_block_payload_8616(self) -> dict[str, object]:
        """Share non-block fields between diagnostics and finite body attestation."""
        return {
            "function_addr": self.function_addr,
            "refusals": [item.to_dict() for item in iter(self.refusals)],
            "summary": dict(self.summary),
            "logical_memory": None if self.logical_memory is None else self.logical_memory.to_dict(),
            "condition_evidence": (
                None
                if self.condition_evidence is None
                else self.condition_evidence.to_dict()
            ),
            "source_revision": (
                None if self.source_revision is None else self.source_revision.to_dict()
            ),
            "lifecycle_stage": self.lifecycle_stage.value,
            "lifecycle": self.lifecycle.to_dict(),
        }


__all__ = ["IRFunctionArtifact"]
