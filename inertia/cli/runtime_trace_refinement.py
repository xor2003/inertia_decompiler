"""Layer: Recovery metadata.

Responsibility: summarize optional runtime trace refinement of already-collected IR readiness.
Forbidden: using runtime traces as sole semantics, validation success, or output repair.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from inertia.structuring.ir_readiness import summarize_x86_16_ir_readiness
from inertia.structuring.ir_recovery_summary import IRRecoverySource

__all__ = [
    "RuntimeTraceRefinementSummary",
    "summarize_x86_16_runtime_trace_refinement",
]

_SEGMENT_REGS = frozenset({"cs", "ds", "es", "ss", "fs", "gs"})


@dataclass(frozen=True, slots=True)
class RuntimeTraceRefinementSummary:
    """Runtime-trace refinement summary for already-collected IR readiness."""

    provenance: str = "none"
    segment_register_values: dict[str, int] | None = None
    refined_unknown_segment_count: int = 0
    remaining_unknown_segment_count: int = 0
    memory_read_count: int = 0
    memory_write_count: int = 0

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible runtime refinement payload."""
        return {
            "provenance": self.provenance,
            "segment_register_values": dict(sorted((self.segment_register_values or {}).items())),
            "refined_unknown_segment_count": self.refined_unknown_segment_count,
            "remaining_unknown_segment_count": self.remaining_unknown_segment_count,
            "memory_read_count": self.memory_read_count,
            "memory_write_count": self.memory_write_count,
        }


def _value(source: IRRecoverySource, name: str, default: object = None) -> object:
    return source.get(name, default)


def summarize_x86_16_runtime_trace_refinement(source: IRRecoverySource) -> RuntimeTraceRefinementSummary:
    """Summarize optional runtime trace refinement without using it as proof."""
    trace = _value(source, "runtime_trace", None)
    if not isinstance(trace, Mapping):
        return RuntimeTraceRefinementSummary()
    segment_registers = trace.get("segment_registers", {})
    segment_values = {
        str(name).lower(): int(value)
        for name, value in (segment_registers.items() if isinstance(segment_registers, Mapping) else ())
        if str(name).lower() in _SEGMENT_REGS and isinstance(value, int)
    }
    memory_reads = tuple(trace.get("memory_reads", ()) or ())
    memory_writes = tuple(trace.get("memory_writes", ()) or ())
    readiness = summarize_x86_16_ir_readiness(source)
    refined = min(readiness.unknown_segment_count, len(segment_values))
    return RuntimeTraceRefinementSummary(
        provenance="runtime_trace",
        segment_register_values=dict(sorted(segment_values.items())),
        refined_unknown_segment_count=refined,
        remaining_unknown_segment_count=max(0, readiness.unknown_segment_count - refined),
        memory_read_count=len(memory_reads),
        memory_write_count=len(memory_writes),
    )
