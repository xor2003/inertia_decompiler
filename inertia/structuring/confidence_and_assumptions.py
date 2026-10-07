"""Layer: Recovery/reporting.

Responsibility: attach confidence and assumption reporting metadata from already-collected recovery facts.
Forbidden: creating proof, hiding assumptions, or changing recovered semantics.

Confidence assignments:
- HIGH: Strong evidence from multiple sources (e.g., proven types from alias model)
- MEDIUM: Single evidence source or weak evidence (e.g., inferred from pattern)
- LOW: Guessed or assumed (e.g., no evidence, convention-based)

Tracking:
- Unresolved indirect targets
- Guessed helper signatures
- Uncertain segmented pointers
- Weak type inferences
- Conservative fallback choices

Output:
- Function comment headers with confidence breakdown
- Milestone reports with confidence statistics
- Scan summary with confidence distribution

Evidence contract: markers are built only from the typed projection produced
by ``confidence_evidence.load_confidence_evidence``, which validates the
optional producer metadata published by the struct-merging, array-matching and
segmented-memory passes (and validated legacy cfunc attachments). Missing
evidence stays absent, refused facts stay LOW, and malformed payloads are
recorded as report assumptions instead of being replaced by defaults.

Package ownership contract (canonical inertia/structuring package):
Layer: Structuring.
Owns CFG shape, loops, switches, and structured condition lowering from proven IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery, rewrite cleanup,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, cast

from inertia.lowering.codegen_metadata import get_codegen_sequence_attr, get_codegen_side_metadata

from .confidence_evidence import (
    ArrayEvidenceItem,
    EvidenceChannel,
    SegmentEvidenceItem,
    StructEvidenceItem,
    load_confidence_evidence,
)

__all__ = [
    "ConfidenceLevel",
    "ConfidenceMarker",
    "ConfidenceTracker",
    "FunctionConfidenceReport",
    "ScanConfidenceSummary",
    "apply_x86_16_confidence_and_assumptions",
    "build_function_with_confidence_markers",
]


class ConfidenceLevel(Enum):
    """Confidence level for recovery facts."""

    HIGH = "HIGH"  # Strong multiple-source evidence
    MEDIUM = "MEDIUM"  # Single source or weak evidence
    LOW = "LOW"  # Guessed or assumed


@dataclass(frozen=True, slots=True)
class ConfidenceMarker:
    """Confidence marker attached to recovered facts."""

    fact_kind: str  # 'struct', 'array', 'pointer', 'type', 'loop', 'switch'
    fact_detail: str  # Description of what was recovered
    confidence: ConfidenceLevel
    evidence_count: int  # Number of sources supporting this
    reason: str | None = None  # Why we chose this confidence level


@dataclass(slots=True)
class ConfidenceTracker:
    """Aggregates confidence markers from recovery stages."""

    markers: list[ConfidenceMarker] = field(default_factory=list)

    def add_marker(
        self,
        fact_kind: str,
        fact_detail: str,
        confidence: ConfidenceLevel,
        evidence_count: int = 1,
        reason: str | None = None,
    ) -> None:
        """Add a confidence marker."""
        marker = ConfidenceMarker(
            fact_kind=fact_kind,
            fact_detail=fact_detail,
            confidence=confidence,
            evidence_count=evidence_count,
            reason=reason,
        )
        self.markers.append(marker)

    def high_count(self) -> int:
        """Count HIGH confidence markers."""
        return sum(1 for m in self.markers if m.confidence == ConfidenceLevel.HIGH)

    def medium_count(self) -> int:
        """Count MEDIUM confidence markers."""
        return sum(1 for m in self.markers if m.confidence == ConfidenceLevel.MEDIUM)

    def low_count(self) -> int:
        """Count LOW confidence markers."""
        return sum(1 for m in self.markers if m.confidence == ConfidenceLevel.LOW)

    def total_count(self) -> int:
        """Total marker count."""
        return len(self.markers)

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary representation."""
        return {
            "high_count": self.high_count(),
            "medium_count": self.medium_count(),
            "low_count": self.low_count(),
            "total_count": self.total_count(),
            "markers": [
                {
                    "fact_kind": m.fact_kind,
                    "fact_detail": m.fact_detail,
                    "confidence": m.confidence.value,
                    "evidence_count": m.evidence_count,
                    "reason": m.reason,
                }
                for m in self.markers
            ],
        }


@dataclass(slots=True)
class FunctionConfidenceReport:
    """Confidence report for a single function."""

    func_addr: int
    func_name: str
    confidence_tracker: ConfidenceTracker
    assumptions: list[str] = field(default_factory=list)
    critical_unknowns: list[str] = field(default_factory=list)

    def add_assumption(self, assumption: str) -> None:
        """Record an assumption."""
        self.assumptions.append(assumption)

    def add_critical_unknown(self, unknown: str) -> None:
        """Record a critical unknown (may affect correctness)."""
        self.critical_unknowns.append(unknown)

    def overall_confidence(self) -> ConfidenceLevel:
        """Determine overall function confidence."""
        # Critical unknowns always lower confidence to LOW
        if self.critical_unknowns:
            return ConfidenceLevel.LOW

        total = self.confidence_tracker.total_count()
        if total == 0:
            return ConfidenceLevel.MEDIUM

        high = self.confidence_tracker.high_count()
        low = self.confidence_tracker.low_count()

        high_ratio = high / total
        low_ratio = low / total

        if high_ratio >= 0.8 and low_ratio == 0:
            return ConfidenceLevel.HIGH
        elif low_ratio >= 0.3:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.MEDIUM

    def comment_header(self) -> str:
        """Generate function comment header with confidence breakdown."""
        lines = [
            f"// {self.func_name} @ {hex(self.func_addr)}",
            f"// Confidence: {self.overall_confidence().value}",
        ]

        total = self.confidence_tracker.total_count()
        if total > 0:
            high = self.confidence_tracker.high_count()
            medium = self.confidence_tracker.medium_count()
            low = self.confidence_tracker.low_count()
            lines.append(f"// Evidence: {high} HIGH, {medium} MEDIUM, {low} LOW")

        if self.assumptions:
            lines.append(f"// Assumptions: {len(self.assumptions)} recorded")
            for assumption in self.assumptions[:3]:  # Show first 3
                lines.append(f"//   - {assumption}")
            if len(self.assumptions) > 3:
                lines.append(f"//   ... and {len(self.assumptions) - 3} more")

        if self.critical_unknowns:
            lines.append("// ⚠️ CRITICAL UNKNOWNS:")
            for unknown in self.critical_unknowns:
                lines.append(f"//   - {unknown}")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary representation."""
        return {
            "func_addr": hex(self.func_addr),
            "func_name": self.func_name,
            "overall_confidence": self.overall_confidence().value,
            "confidence_breakdown": self.confidence_tracker.to_dict(),
            "assumptions_count": len(self.assumptions),
            "assumptions": self.assumptions,
            "critical_unknowns_count": len(self.critical_unknowns),
            "critical_unknowns": self.critical_unknowns,
        }


@dataclass(slots=True)
class ScanConfidenceSummary:
    """Summary of confidence levels across multiple functions."""

    total_functions: int = 0
    high_confidence_count: int = 0
    medium_confidence_count: int = 0
    low_confidence_count: int = 0
    total_assumptions: int = 0
    total_critical_unknowns: int = 0

    def add_function_report(self, report: FunctionConfidenceReport) -> None:
        """Add a function report to the summary."""
        self.total_functions += 1
        confidence = report.overall_confidence()

        if confidence == ConfidenceLevel.HIGH:
            self.high_confidence_count += 1
        elif confidence == ConfidenceLevel.MEDIUM:
            self.medium_confidence_count += 1
        else:
            self.low_confidence_count += 1

        self.total_assumptions += len(report.assumptions)
        self.total_critical_unknowns += len(report.critical_unknowns)

    def high_confidence_ratio(self) -> float:
        """Percentage of high-confidence functions."""
        if self.total_functions == 0:
            return 0.0
        return self.high_confidence_count / self.total_functions

    def scan_classification(self) -> str:
        """Overall scan classification based on confidence distribution."""
        if self.total_functions == 0:
            return "empty"

        high_ratio = self.high_confidence_ratio()
        low_ratio = self.low_confidence_count / self.total_functions if self.total_functions > 0 else 0

        if high_ratio >= 0.8 and low_ratio == 0 and self.total_critical_unknowns == 0:
            return "strong"
        elif low_ratio >= 0.3 or self.total_critical_unknowns > 0:
            return "weak"
        else:
            return "partial"

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary representation."""
        return {
            "total_functions": self.total_functions,
            "high_confidence_count": self.high_confidence_count,
            "medium_confidence_count": self.medium_confidence_count,
            "low_confidence_count": self.low_confidence_count,
            "high_confidence_ratio": self.high_confidence_ratio(),
            "total_assumptions": self.total_assumptions,
            "total_critical_unknowns": self.total_critical_unknowns,
            "scan_classification": self.scan_classification(),
        }


def build_function_with_confidence_markers(
    cfunc: object | None,
    confidence_report: FunctionConfidenceReport,
    *,
    codegen: object | None = None,
) -> bool:
    """Attach confidence markers across the dynamic third-party decompiler object boundary.

    Args:
        cfunc: Decompiled function (CFunction)
        confidence_report: Confidence report with markers and assumptions
        codegen: Optional code generator that receives side metadata

    Returns:
        True if markers were successfully attached
    """
    if cfunc is None:
        return False

    # Attach confidence data as metadata
    if codegen is not None:
        metadata = get_codegen_side_metadata(codegen)
        metadata["confidence_report"] = confidence_report
    cfunc_dynamic = cast(Any, cfunc)
    cfunc_metadata = getattr(cfunc, "_recovery_metadata", None)
    if not isinstance(cfunc_metadata, dict):
        cfunc_metadata = {}
        try:
            # Dynamic decompiler boundary: recovery metadata is optional on third-party CFunction objects.
            cfunc_dynamic._recovery_metadata = cfunc_metadata
        except (AttributeError, TypeError):
            # A third-party object that refuses attribute writes cannot carry
            # the metadata map; codegen side metadata above still recorded it.
            cfunc_metadata = None
    if cfunc_metadata is not None:
        cfunc_metadata["confidence_report"] = confidence_report

    # Prepend comment header to function
    if hasattr(cfunc_dynamic, "decompile"):
        original_decomp = cfunc_dynamic.decompile()
        header = confidence_report.comment_header()
        if original_decomp:
            # Dynamic decompiler boundary: cached text is an optional CFunction diagnostic surface.
            cfunc_dynamic._cached_decomp = header + "\n\n" + original_decomp

    return True


def apply_x86_16_confidence_and_assumptions(codegen: object) -> bool:
    """Attach confidence metadata without marking structuring as changed."""

    def _impl() -> bool:
        """Attach confidence markers through the dynamic third-party angr codegen boundary.

        This pass:
        1. Collects confidence markers from the typed producer-evidence projection
        2. Aggregates assumptions from structuring/type analysis
        3. Attaches metadata to decompiled functions
        4. Optionally caches confidence comment headers for report consumers

        Args:
            codegen: Decompiler code generator

        Returns:
            False because this reporting-only pass does not mutate recovered semantics

        Raises:
            Any unexpected exception raised by third-party attribute access or
            by the producer-evidence projection propagates unchanged; absent or
            malformed evidence is reported, never fabricated.
        """
        # Dynamic codegen boundary: angr codegen supplies cfunc at runtime.
        codegen_dynamic = cast(Any, codegen)
        cfunc = getattr(codegen_dynamic, "cfunc", None)
        if cfunc is None:
            return False

        # Dynamic codegen boundary: addr/name are third-party CFunction fields.
        func_addr = getattr(cfunc, "addr", 0)
        func_name = getattr(cfunc, "name", f"func_{hex(func_addr)}")

        # Build confidence tracker from the typed producer-evidence projection
        evidence = load_confidence_evidence(codegen, cfunc)
        tracker = ConfidenceTracker()

        _collect_struct_confidence_8616(tracker, evidence.structs)
        _collect_array_confidence_8616(tracker, evidence.arrays)
        _collect_segmented_memory_confidence_8616(tracker, evidence.segments)

        # Build report
        report = FunctionConfidenceReport(func_addr=func_addr, func_name=func_name, confidence_tracker=tracker)

        # Record producer failures and malformed evidence honestly
        _record_channel_diagnostics_8616(report, "struct merging", evidence.structs)
        _record_channel_diagnostics_8616(report, "array matching", evidence.arrays)
        _record_channel_diagnostics_8616(report, "segmented memory", evidence.segments)

        # Add assumptions from analysis
        for assumption in get_codegen_sequence_attr(codegen, cfunc, "_assumptions"):
            report.add_assumption(assumption)

        # Add critical unknowns
        for unknown in get_codegen_sequence_attr(codegen, cfunc, "_critical_unknowns"):
            report.add_critical_unknown(unknown)

        # Attach to function
        build_function_with_confidence_markers(cfunc, report, codegen=codegen)

        return False

    return _impl()


def _record_channel_diagnostics_8616[ItemT](
    report: FunctionConfidenceReport,
    channel_name: str,
    channel: EvidenceChannel[ItemT],
) -> None:
    """Record producer errors and malformed evidence as explicit assumptions."""
    if channel.error is not None:
        report.add_assumption(f"{channel_name} producer reported an error: {channel.error}")
    for malformed in channel.malformed:
        report.add_assumption(f"ignored malformed {channel_name} evidence: {malformed}")


def _collect_struct_confidence_8616(
    tracker: ConfidenceTracker,
    channel: EvidenceChannel[StructEvidenceItem],
) -> None:
    """Record confidence markers for projected struct evidence (Phase 2.3)."""
    for item in channel.items:
        if item.refusal_reason is not None or not item.segmented_allowed:
            confidence = ConfidenceLevel.LOW
            reason = f"segmented memory refused lowering: {item.refusal_reason or 'reason not published'}"
        else:
            confidence = ConfidenceLevel.HIGH if item.evidence_count >= 2 else ConfidenceLevel.MEDIUM
            reason = f"recovered from {item.evidence_count} {item.evidence_basis}(s) [{item.source}]"
        tracker.add_marker(
            fact_kind="struct",
            fact_detail=f"struct {item.identity}",
            confidence=confidence,
            evidence_count=item.evidence_count,
            reason=reason,
        )
    for refusal in channel.refusals:
        tracker.add_marker(
            fact_kind="struct",
            fact_detail=f"refused storage object {refusal.identity}",
            confidence=ConfidenceLevel.LOW,
            evidence_count=0,
            reason=f"refused: {refusal.reason}",
        )


def _collect_array_confidence_8616(
    tracker: ConfidenceTracker,
    channel: EvidenceChannel[ArrayEvidenceItem],
) -> None:
    """Record confidence markers for projected array evidence (Phase 2.2)."""
    for item in channel.items:
        confidence = ConfidenceLevel.HIGH if item.evidence_count >= 3 else ConfidenceLevel.MEDIUM
        tracker.add_marker(
            fact_kind="array",
            fact_detail=f"array {item.identity}",
            confidence=confidence,
            evidence_count=item.evidence_count,
            reason=f"detected from {item.evidence_count} {item.evidence_basis}(s) [{item.source}]",
        )
    for refusal in channel.refusals:
        tracker.add_marker(
            fact_kind="array",
            fact_detail=f"refused array {refusal.identity}",
            confidence=ConfidenceLevel.LOW,
            evidence_count=0,
            reason=f"refused: {refusal.reason}",
        )


def _segment_association_confidence_8616(stability: float) -> ConfidenceLevel:
    """Map segment-association stability to a confidence level."""
    if stability >= 0.8:
        return ConfidenceLevel.HIGH
    if stability >= 0.5:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def _collect_segmented_memory_confidence_8616(
    tracker: ConfidenceTracker,
    channel: EvidenceChannel[SegmentEvidenceItem],
) -> None:
    """Record confidence markers for projected segment associations (Phase 3)."""
    for item in channel.items:
        tracker.add_marker(
            fact_kind="segmented_memory",
            fact_detail=f"segment {item.segment} association",
            confidence=_segment_association_confidence_8616(item.stability),
            evidence_count=item.evidence_count,
            reason=f"{item.detail}; stability={item.stability:.2f}",
        )
