"""Layer: Recovery/reporting.

Responsibility: summarize typed IR readiness from already-collected IR recovery facts.
Forbidden: manufacturing IR facts, changing structuring verdicts, or hiding unknowns.
"""

from __future__ import annotations

from dataclasses import dataclass

from .ir_recovery_summary import IRRecoverySource, summarize_x86_16_ir_recovery

__all__ = ["IRReadinessSummary", "summarize_x86_16_ir_readiness"]


@dataclass(frozen=True, slots=True)
class IRReadinessSummary:
    """Readiness verdict derived from already-collected typed IR counters."""

    level: str
    block_count: int
    provisional_address_count: int
    defaulted_segment_count: int
    proven_segment_count: int
    unknown_segment_count: int
    condition_count: int
    phi_node_count: int
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible IR readiness payload."""
        return {
            "level": self.level,
            "block_count": self.block_count,
            "provisional_address_count": self.provisional_address_count,
            "defaulted_segment_count": self.defaulted_segment_count,
            "proven_segment_count": self.proven_segment_count,
            "unknown_segment_count": self.unknown_segment_count,
            "condition_count": self.condition_count,
            "phi_node_count": self.phi_node_count,
            "reasons": list(self.reasons),
        }


def _readiness_reasons_8616(
    block_count: int,
    provisional_address_count: int,
    defaulted_segment_count: int,
    unknown_segment_count: int,
    condition_count: int,
    phi_node_count: int,
) -> tuple[str, ...]:
    """List every readiness defect proven by the recovery census."""
    reasons: list[str] = []
    if block_count <= 0:
        reasons.append("no_ir_blocks")
    if provisional_address_count > 0:
        reasons.append("provisional_addresses_present")
    if defaulted_segment_count > 0:
        reasons.append("defaulted_segment_identity_present")
    if unknown_segment_count > 0:
        reasons.append("unknown_segment_identity_present")
    if condition_count <= 0:
        reasons.append("no_typed_conditions")
    if phi_node_count <= 0:
        reasons.append("no_cross_block_ssa")
    return tuple(reasons)


def _readiness_level_8616(
    block_count: int,
    provisional_address_count: int,
    defaulted_segment_count: int,
    proven_segment_count: int,
    condition_count: int,
    phi_node_count: int,
) -> str:
    """Classify readiness from the strongest proven IR evidence downward."""
    if block_count <= 0:
        return "missing"
    typed_segments = proven_segment_count > 0 or defaulted_segment_count > 0
    if condition_count > 0 and typed_segments and phi_node_count > 0:
        return "typed_address_condition_and_ssa"
    if condition_count > 0 and typed_segments:
        return "typed_address_and_condition"
    if condition_count > 0:
        return "typed_condition_only"
    if provisional_address_count > 0 or typed_segments:
        return "typed_address_only"
    return "minimal"


def summarize_x86_16_ir_readiness(source: IRRecoverySource) -> IRReadinessSummary:
    """Summarize whether recovered IR is ready for later decompiler stages."""
    summary = summarize_x86_16_ir_recovery(source)
    provisional_address_count = int(summary.address_status_counts.get("provisional", 0) or 0)
    defaulted_segment_count = int(summary.segment_origin_counts.get("defaulted", 0) or 0)
    proven_segment_count = int(summary.segment_origin_counts.get("proven", 0) or 0)
    unknown_segment_count = int(summary.segment_origin_counts.get("unknown", 0) or 0)
    condition_count = int(sum(summary.condition_counts.values()))
    phi_node_count = int(summary.phi_node_count)
    reasons = _readiness_reasons_8616(
        summary.block_count,
        provisional_address_count,
        defaulted_segment_count,
        unknown_segment_count,
        condition_count,
        phi_node_count,
    )
    level = _readiness_level_8616(
        summary.block_count,
        provisional_address_count,
        defaulted_segment_count,
        proven_segment_count,
        condition_count,
        phi_node_count,
    )

    return IRReadinessSummary(
        level=level,
        block_count=summary.block_count,
        provisional_address_count=provisional_address_count,
        defaulted_segment_count=defaulted_segment_count,
        proven_segment_count=proven_segment_count,
        unknown_segment_count=unknown_segment_count,
        condition_count=condition_count,
        phi_node_count=phi_node_count,
        reasons=tuple(reasons),
    )
