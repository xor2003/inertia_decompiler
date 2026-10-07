"""Layer: Validation.

Responsibility: present typed helper-family validation summaries without changing verdicts.
Forbidden: semantic recovery from source, COD, assembly, or rendered C text.

Package ownership contract (canonical inertia/validation package):
Owns canonical equivalence checking and validation diagnostics.
Do not mutate IR, rewrite emitted C, recover semantics, or accept source/COD-backed proof.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from inertia.validation.recovery_confidence import summarize_recovery_confidence


@dataclass(frozen=True, slots=True)
class ValidationHelperFamilyRow:
    """Describe one helper-family validation signal for report consumers."""

    family: str
    count: int
    likely_layer: str
    next_root_cause_file: str
    signal: str


@dataclass(frozen=True, slots=True)
class ValidationHelperReport:
    """Carry typed helper-family rows without changing validation verdicts."""

    rows: tuple[ValidationHelperFamilyRow, ...]

    def as_rows(self) -> tuple[dict[str, object], ...]:
        """Return serializable helper-family rows for milestone reports."""
        return tuple(
            {
                "family": row.family,
                "count": row.count,
                "likely_layer": row.likely_layer,
                "next_root_cause_file": row.next_root_cause_file,
                "signal": row.signal,
            }
            for row in self.rows
        )


def _row_count(item: Mapping[str, object]) -> int:
    count = item.get("count", 0)
    if isinstance(count, bool):
        return int(count)
    if isinstance(count, int):
        return count
    if isinstance(count, str) and count.isdecimal():
        return int(count)
    return 0


def _helper_family_rows(summary: Mapping[str, object]) -> tuple[Mapping[str, object], ...]:
    rows = summary.get("helper_family_rows", ())
    if not isinstance(rows, list | tuple):
        return ()
    return tuple(item for item in rows if isinstance(item, Mapping))


def build_x86_16_validation_helper_report(results: Sequence[Mapping[str, object]]) -> ValidationHelperReport:
    """Build the typed helper-family validation report from confidence rows."""

    def _impl() -> ValidationHelperReport:
        summary = summarize_recovery_confidence(list(results))
        rows: list[ValidationHelperFamilyRow] = []
        for item in _helper_family_rows(summary):
            family = item.get("family")
            likely_layer = item.get("likely_layer")
            next_root_cause_file = item.get("next_root_cause_file")
            signal = item.get("signal")
            if not isinstance(family, str) or not family:
                continue
            if not isinstance(likely_layer, str) or not likely_layer:
                continue
            if not isinstance(next_root_cause_file, str) or not next_root_cause_file:
                continue
            if not isinstance(signal, str) or not signal:
                continue
            rows.append(
                ValidationHelperFamilyRow(
                    family=family,
                    count=_row_count(item),
                    likely_layer=likely_layer,
                    next_root_cause_file=next_root_cause_file,
                    signal=signal,
                )
            )
        return ValidationHelperReport(rows=tuple(rows))

    return _impl()


def describe_x86_16_validation_helper_report_surface() -> dict[str, object]:
    """Return the deterministic validation-helper report surface contract."""
    return {
        "consumer": "validation_helper_report",
        "producer": "summarize_recovery_confidence",
        "surface": "helper_family_rows",
        "typed_rows": (
            "family",
            "count",
            "likely_layer",
            "next_root_cause_file",
            "signal",
        ),
        "purpose": "Route helper/wrapper family evidence into later validation/report consumers.",
    }


__all__ = [
    "ValidationHelperFamilyRow",
    "ValidationHelperReport",
    "build_x86_16_validation_helper_report",
    "describe_x86_16_validation_helper_report_surface",
]
