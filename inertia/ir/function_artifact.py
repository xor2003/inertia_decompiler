"""Function-level typed IR artifact contract.

Layer: IR.
Responsibility: retain blocks, refusals, diagnostics, and authoritative logical
memory evidence together while IR artifacts are reconstructed by later stages.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .core import IRBlock, IRRefusal

if TYPE_CHECKING:
    from .function_condition_artifact import IRFunctionConditionArtifact8616
    from .logical_memory_contracts import IRLogicalMemoryArtifact8616


@dataclass(frozen=True, slots=True)
class IRFunctionArtifact:
    """Typed IR artifact for one recovered function and its logical accesses."""

    function_addr: int
    blocks: tuple[IRBlock, ...] = ()
    refusals: tuple[IRRefusal, ...] = ()
    summary: dict[str, object] = field(default_factory=dict)
    logical_memory: IRLogicalMemoryArtifact8616 | None = None
    condition_evidence: IRFunctionConditionArtifact8616 | None = None

    def to_dict(self) -> dict[str, object]:
        """Serialize this function-level typed IR artifact."""
        return {
            "function_addr": self.function_addr,
            "blocks": [block.to_dict() for block in self.blocks],
            "refusals": [item.to_dict() for item in self.refusals],
            "summary": dict(self.summary),
            "logical_memory": None if self.logical_memory is None else self.logical_memory.to_dict(),
            "condition_evidence": (
                None
                if self.condition_evidence is None
                else self.condition_evidence.to_dict()
            ),
        }


__all__ = ["IRFunctionArtifact"]
