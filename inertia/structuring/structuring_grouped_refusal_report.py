"""Layer: Structuring.

Responsibility: report explicit grouped-entry refusal reasons to validation consumers.
Forbidden: treating refusals as success, recovery proof, or rewrite-stage repair.

Package ownership contract (canonical inertia/structuring package):
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass

from inertia.structuring.structuring_grouped_units import build_x86_16_cross_entry_grouped_units


@dataclass(frozen=True, slots=True)
class StructuringGroupedRefusalReportRow:
    """Summarize one explicit cross-entry grouping refusal reason."""

    refusal_reason: str
    count: int
    likely_layer: str
    next_root_cause_file: str


@dataclass(frozen=True, slots=True)
class StructuringGroupedRefusalReport:
    """Carry cross-entry grouping refusal rows without treating them as success."""

    rows: tuple[StructuringGroupedRefusalReportRow, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a stable serialization for validation reports."""
        return {
            "rows": [
                {
                    "refusal_reason": row.refusal_reason,
                    "count": row.count,
                    "likely_layer": row.likely_layer,
                    "next_root_cause_file": row.next_root_cause_file,
                }
                for row in self.rows
            ]
        }


def build_x86_16_structuring_grouped_refusal_report(codegen: object) -> StructuringGroupedRefusalReport | None:
    """Build a validation report from already-collected grouped-unit refusals."""
    artifact = build_x86_16_cross_entry_grouped_units(codegen)
    if artifact is None:
        return None
    counts: dict[str, int] = {}
    for refusal in artifact.refusals:
        counts[refusal.refusal_reason] = counts.get(refusal.refusal_reason, 0) + 1
    rows = tuple(
        StructuringGroupedRefusalReportRow(
            refusal_reason=refusal_reason,
            count=counts[refusal_reason],
            likely_layer="cross_entry_grouping",
            next_root_cause_file="inertia/structuring/structuring_grouped_units.py",
        )
        for refusal_reason in sorted(counts)
    )
    return StructuringGroupedRefusalReport(rows=rows)


def describe_x86_16_structuring_grouped_refusal_report_surface() -> dict[str, object]:
    """Return the deterministic grouped-refusal report contract."""
    return {
        "consumer": "structuring_grouped_refusal_report",
        "producer": "build_x86_16_cross_entry_grouped_units",
        "surface": "cross_entry_grouped_unit_refusals",
        "typed_rows": (
            "refusal_reason",
            "count",
            "likely_layer",
            "next_root_cause_file",
        ),
        "purpose": "Expose explicit multi-entry grouping refusal reasons to validation/reporting consumers.",
    }


__all__ = [
    "StructuringGroupedRefusalReport",
    "StructuringGroupedRefusalReportRow",
    "build_x86_16_structuring_grouped_refusal_report",
    "describe_x86_16_structuring_grouped_refusal_report_surface",
]
