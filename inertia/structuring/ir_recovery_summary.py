"""Layer: Recovery/reporting.

Responsibility: summarize typed IR recovery counters from existing pipeline artifacts.
Forbidden: mutating IR, fabricating facts, or treating missing summaries as success.

Package ownership contract (canonical inertia/structuring package):
Layer: Structuring.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

__all__ = ["IRRecoverySummary", "summarize_x86_16_ir_recovery"]

type IRRecoverySource = Mapping[str, object]


def _value(source: IRRecoverySource, name: str, default: object = None) -> object:
    return source.get(name, default)


def _count(value: object) -> int:
    return value if isinstance(value, int) else 0


def _string_int_counts(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    counts: dict[str, int] = {}
    for key, count in value.items():
        if isinstance(count, int):
            counts[str(key)] = count
    return counts


@dataclass(frozen=True, slots=True)
class IRRecoverySummary:
    """Deterministic summary of already-collected typed IR recovery counters."""

    block_count: int
    instruction_count: int
    refusal_count: int
    aliasable_value_count: int
    ssa_binding_count: int
    phi_node_count: int
    frame_slot_count: int
    frame_refusal_count: int
    space_counts: dict[str, int]
    address_status_counts: dict[str, int]
    segment_origin_counts: dict[str, int]
    condition_counts: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible IR recovery payload."""
        return {
            "block_count": self.block_count,
            "instruction_count": self.instruction_count,
            "refusal_count": self.refusal_count,
            "aliasable_value_count": self.aliasable_value_count,
            "ssa_binding_count": self.ssa_binding_count,
            "phi_node_count": self.phi_node_count,
            "frame_slot_count": self.frame_slot_count,
            "frame_refusal_count": self.frame_refusal_count,
            "space_counts": dict(self.space_counts),
            "address_status_counts": dict(self.address_status_counts),
            "segment_origin_counts": dict(self.segment_origin_counts),
            "condition_counts": dict(self.condition_counts),
        }


def summarize_x86_16_ir_recovery(source: IRRecoverySource) -> IRRecoverySummary:
    """Summarize typed IR recovery counters from an existing mapping row."""

    def _impl() -> IRRecoverySummary:
        summary = (
            _value(source, "x86_16_vex_ir_summary")
            or _value(source, "_inertia_vex_ir_summary")
            or _value(source, "vex_ir_summary")
            or {}
        )
        if not isinstance(summary, Mapping):
            summary = {}
        return IRRecoverySummary(
            block_count=_count(summary.get("block_count", 0)),
            instruction_count=_count(summary.get("instruction_count", 0)),
            refusal_count=_count(summary.get("refusal_count", 0)),
            aliasable_value_count=_count(summary.get("aliasable_value_count", 0)),
            ssa_binding_count=_count(summary.get("ssa_binding_count", 0)),
            phi_node_count=_count(summary.get("phi_node_count", 0)),
            frame_slot_count=_count(summary.get("frame_slot_count", 0)),
            frame_refusal_count=_count(summary.get("frame_refusal_count", 0)),
            space_counts=_string_int_counts(summary.get("space_counts", {})),
            address_status_counts=_string_int_counts(summary.get("address_status_counts", {})),
            segment_origin_counts=_string_int_counts(summary.get("segment_origin_counts", {})),
            condition_counts=_string_int_counts(summary.get("condition_counts", {})),
        )

    return _impl()
