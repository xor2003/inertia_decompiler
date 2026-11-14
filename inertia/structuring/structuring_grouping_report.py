# cython: language_level=3, infer_types=True
"""Layer: Structuring.

Responsibility: report CFG grouping kinds to validation and reporting consumers.
Forbidden: creating proof, hiding grouping failures, or rewriting recovered C.

Package ownership contract (canonical inertia/structuring package):
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass

from inertia.structuring.structuring_cfg_grouping import build_cfg_grouping_artifact
import dataclasses
import builtins


@dataclasses.dataclass(frozen=True, )
class StructuringGroupingReportRow:
    """Summarize one CFG grouping kind for validation/report consumers."""

    grouping_kind: object
    count: cython.longlong
    likely_layer: object
    next_root_cause_file: object


@dataclasses.dataclass(frozen=True, )
class StructuringGroupingReport:
    """Carry grouped-entry CFG report rows without changing verdicts."""

    rows: object

    def to_dict(self) -> dict[str, object]:
        """Return a stable serialization for validation reports."""
        return {
            "rows": [
                {
                    "grouping_kind": row.grouping_kind,
                    "count": row.count,
                    "likely_layer": row.likely_layer,
                    "next_root_cause_file": row.next_root_cause_file,
                }
                for row in iter(self.rows)
            ]
        }


def build_x86_16_structuring_grouping_report(codegen: object) -> StructuringGroupingReport | None:
    """Build a validation report from already-collected CFG grouping artifacts."""
    artifact: object
    record: object
    artifact = build_cfg_grouping_artifact(codegen)
    if artifact is None:
        return None
    counts = {
        "primary_entry": 0,
        "entry_fragment": 0,
        "grouped_entry_candidate": 0,
        "single_cfg_owner": 0,
    }
    for record in artifact.records:
        if record.grouping_kind in counts:
            counts[record.grouping_kind] += 1
    rows = tuple(
        StructuringGroupingReportRow(
            grouping_kind=grouping_kind,
            count=count,
            likely_layer="cfg_grouping",
            next_root_cause_file="inertia/structuring/structuring_cfg_grouping.py",
        )
        for grouping_kind, count in builtins.iter(counts.items())
        if count
    )
    return StructuringGroupingReport(rows=rows)


@cython.ccall
def describe_x86_16_structuring_grouping_report_surface() -> dict[str, object]:
    """Return the deterministic structuring-grouping report contract."""
    return {
        "consumer": "structuring_grouping_report",
        "producer": "build_cfg_grouping_artifact",
        "surface": "cfg_grouping",
        "typed_rows": (
            "grouping_kind",
            "count",
            "likely_layer",
            "next_root_cause_file",
        ),
        "purpose": "Expose grouped-entry and entry-fragment CFG evidence to validation/reporting consumers.",
    }


__all__ = [
    "StructuringGroupingReport",
    "StructuringGroupingReportRow",
    "build_x86_16_structuring_grouping_report",
    "describe_x86_16_structuring_grouping_report_surface",
]
