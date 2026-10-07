"""Layer: Structuring.

Responsibility: expose IR-readiness hints that explain structuring limits.
Forbidden: semantic recovery, alias recovery, or changing structuring verdicts.

Package ownership contract (canonical inertia/structuring package):
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from inertia.structuring.ir_readiness import IRReadinessSummary, summarize_x86_16_ir_readiness
from inertia.structuring.ir_recovery_summary import IRRecoverySource

__all__ = ["StructuringIRHintArtifact", "build_structuring_ir_hint_artifact"]


def _ir_recovery_source_from_codegen(codegen: object) -> IRRecoverySource:
    summary = vars(codegen).get("_inertia_vex_ir_summary", {})
    if not isinstance(summary, Mapping) or not summary:
        for codegen_type in type(codegen).mro():
            summary = vars(codegen_type).get("_inertia_vex_ir_summary", {})
            if isinstance(summary, Mapping):
                break
    return {"_inertia_vex_ir_summary": summary if isinstance(summary, Mapping) else {}}


@dataclass(frozen=True, slots=True)
class StructuringIRHintArtifact:
    """IR-readiness hints that explain structuring limits without changing verdicts."""

    readiness: IRReadinessSummary
    hints: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible structuring hint payload."""
        return {
            "readiness": self.readiness.to_dict(),
            "hints": list(self.hints),
        }


def build_structuring_ir_hint_artifact(
    codegen: object, *, succeeded: bool, iterations: int
) -> StructuringIRHintArtifact:
    """Build structuring diagnostics from already-collected IR readiness facts."""

    def _impl() -> StructuringIRHintArtifact:
        readiness = summarize_x86_16_ir_readiness(_ir_recovery_source_from_codegen(codegen))
        hints: list[str] = []

        if readiness.level == "missing":
            hints.append("Typed IR unavailable: structuring guidance is limited to CFG-only diagnostics")
        if not succeeded and readiness.condition_count == 0 and iterations >= 50:
            hints.append("Typed conditions missing: branch intent still depends on lifted flag temporaries")
        if not succeeded and readiness.unknown_segment_count > 0:
            hints.append("Segment identity still unknown: memory-space evidence is missing for some typed addresses")
        elif not succeeded and readiness.defaulted_segment_count > 0:
            hints.append("Segment identity is still defaulted: downstream memory reasoning may remain conservative")
        if not succeeded and readiness.provisional_address_count > 0:
            hints.append(
                "Segmented addresses remain provisional: memory-space evidence may still be too weak for later recovery"
            )
        if not succeeded and readiness.phi_node_count == 0 and iterations >= 25:
            hints.append("Cross-block SSA absent: join-sensitive value history still depends on block-local facts")

        return StructuringIRHintArtifact(readiness=readiness, hints=tuple(hints))

    return _impl()
