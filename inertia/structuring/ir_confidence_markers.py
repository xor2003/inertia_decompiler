"""Layer: Recovery/reporting.

Responsibility: attach confidence markers that expose IR assumptions and unknowns.
Forbidden: changing recovered semantics, structuring verdicts, or validation acceptance.

Package ownership contract (canonical inertia/structuring package):
Layer: Structuring.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, cast

from inertia.lowering.codegen_metadata import append_codegen_sequence_attr

from .ir_readiness import IRReadinessSummary, summarize_x86_16_ir_readiness
from .ir_recovery_summary import IRRecoverySource

__all__ = ["IRConfidenceMarkerArtifact", "apply_x86_16_ir_confidence_markers"]


@dataclass(frozen=True, slots=True)
class IRConfidenceMarkerArtifact:
    """Confidence marker payload derived from already-collected typed IR facts."""

    readiness: IRReadinessSummary
    assumptions: tuple[str, ...]
    critical_unknowns: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible confidence marker payload."""
        return {
            "readiness": self.readiness.to_dict(),
            "assumptions": list(self.assumptions),
            "critical_unknowns": list(self.critical_unknowns),
        }


class _CodegenWithConfidenceMarkers(Protocol):
    cfunc: object
    _inertia_ir_confidence_markers: IRConfidenceMarkerArtifact


def _append_unique(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _ir_recovery_source_from_codegen(codegen: object) -> IRRecoverySource:
    summary = vars(codegen).get("_inertia_vex_ir_summary", {})
    if not isinstance(summary, Mapping) or not summary:
        for codegen_type in type(codegen).mro():
            summary = vars(codegen_type).get("_inertia_vex_ir_summary", {})
            if isinstance(summary, Mapping):
                break
    return {"_inertia_vex_ir_summary": summary if isinstance(summary, Mapping) else {}}


def _cfunc_from_codegen(codegen: object) -> object | None:
    if not hasattr(codegen, "cfunc"):
        return None
    return cast(_CodegenWithConfidenceMarkers, codegen).cfunc


def _build_ir_confidence_marker_artifact(codegen: object) -> IRConfidenceMarkerArtifact:
    readiness = summarize_x86_16_ir_readiness(_ir_recovery_source_from_codegen(codegen))
    assumptions: list[str] = []
    critical_unknowns: list[str] = []

    if readiness.level == "missing":
        assumptions.append("typed IR unavailable")
        return IRConfidenceMarkerArtifact(readiness=readiness, assumptions=tuple(assumptions), critical_unknowns=())

    if readiness.defaulted_segment_count > 0 and readiness.proven_segment_count == 0:
        assumptions.append("typed IR segment identity is only defaulted")
    if readiness.condition_count == 0:
        assumptions.append("typed IR conditions are absent")
    if readiness.block_count > 1 and readiness.phi_node_count == 0:
        assumptions.append("typed IR cross-block SSA is absent")
    if readiness.unknown_segment_count > 0:
        critical_unknowns.append("typed IR still has unknown segment identity")

    return IRConfidenceMarkerArtifact(
        readiness=readiness,
        assumptions=tuple(assumptions),
        critical_unknowns=tuple(critical_unknowns),
    )


def apply_x86_16_ir_confidence_markers(codegen: object) -> bool:
    """Attach typed-IR readiness assumptions to codegen side metadata."""
    cfunc = _cfunc_from_codegen(codegen)
    if cfunc is None:
        return False

    artifact = _build_ir_confidence_marker_artifact(codegen)
    cast(_CodegenWithConfidenceMarkers, codegen)._inertia_ir_confidence_markers = artifact
    append_codegen_sequence_attr(codegen, cfunc, "_assumptions", artifact.assumptions)
    append_codegen_sequence_attr(codegen, cfunc, "_critical_unknowns", artifact.critical_unknowns)
    return False
