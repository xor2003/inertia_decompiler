"""Typed stack lowering result objects with hard-fail enforcement.

Layer: Types/Lowering.
Responsibility: owns typed stack materialization result contracts.
Consumes alias, widening, and typed facts by reporting whether proven stack
slots were actually materialized.
Do not recover semantics from COD, source, assembly, or rendered C text.

AGENTS rule: SS:BP+offset → stack slot → variable.
If a proven SS stack slot cannot be materialized as a named variable,
the function is marked invalid rather than silently continuing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

__all__ = [
    "StackLoweringResult",
    "StackLoweringStatus",
    "StackSlotFailure",
    "materialization_diagnostics_8616",
]


class StackLoweringStatus(StrEnum):
    """Typed verdict for stack slot materialization."""

    OK = "ok"
    FAILED = "failed"
    PARTIAL = "partial"


@dataclass(frozen=True, slots=True)
class StackSlotFailure:
    """A proven SS stack slot that could not be materialized as a named variable."""

    offset: int
    size: int
    reason: str
    evidence: tuple[str, ...] = ()


@dataclass(slots=True)
class StackLoweringResult:
    """Outcome of a stack lowering pass with mandatory hard-fail tracking.

    If status != "ok", the pipeline MUST stop before rewrite and emit
    honest partial output with diagnostic information.
    """

    status: StackLoweringStatus = StackLoweringStatus.OK
    failures: list[StackSlotFailure] = field(default_factory=list)
    materialized: list[tuple[int, str]] = field(default_factory=list)
    diagnostics: list[str] = field(default_factory=list)

    @property
    def is_ok(self) -> bool:
        """Return whether all proven stack slots were materialized."""
        return self.status is StackLoweringStatus.OK

    @property
    def is_failed(self) -> bool:
        """Return whether stack lowering found a hard materialization failure."""
        return self.status is StackLoweringStatus.FAILED

    @property
    def failure_count(self) -> int:
        """Return the number of refused stack-slot materializations."""
        return len(self.failures)

    def to_dict(self) -> dict[str, object]:
        """Return a stable diagnostic representation for reporting gates."""
        return {
            "status": self.status.value,
            "failure_count": self.failure_count,
            "materialized_count": len(self.materialized),
            "failures": [
                {
                    "offset": f.offset,
                    "size": f.size,
                    "reason": f.reason,
                }
                for f in self.failures
            ],
            "materialized": [{"offset": offset, "name": name} for offset, name in self.materialized],
            "diagnostics": list(self.diagnostics),
        }


def materialization_diagnostics_8616(result: StackLoweringResult) -> str:
    """Format a readable diagnostic summary for stack lowering failure."""
    lines: list[str] = [f"Stack lowering: {result.status.value}"]
    if result.materialized:
        lines.append(f"  Materialized: {len(result.materialized)} slots")
    if result.failures:
        lines.append(f"  Failures: {len(result.failures)} slots not materialized")
        for f in result.failures:
            lines.append(f"    SS:BP{f.offset:+d} ({f.size} bytes): {f.reason}")
    return "\n".join(lines)
