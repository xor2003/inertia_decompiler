"""Structuring diagnostics and failure classification.

Layer: Structuring.
Responsibility: classify structuring failures and attach diagnostic metadata without changing output.

Tracks structuring failures with detailed root-cause classification
and provides recovery hints for debugging.

Failure Reasons:
- MAX_ITERATIONS: Structuring reached 1000-iteration limit (too complex)
- NO_PROGRESS: Regions no longer match any pattern
- TIMEOUT: External timeout/cancellation
- MIXED_ENTRY_EXIT: Regions with mixed entry/exit points
- UNSUPPORTED_PATTERN: Region pattern not yet implemented
- RESOURCE_LIMIT: Memory or other resource exhaustion
- UNKNOWN: Classification uncertain
"""

from __future__ import annotations

import typing
from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable

from .codegen_metadata import get_codegen_side_metadata
from .structuring_cfg_grouping import CFGGroupingArtifact, build_cfg_grouping_artifact
from .structuring_cfg_indirect import CFGIndirectSiteArtifact
from .structuring_cfg_ownership import CFGOwnershipArtifact
from .structuring_cfg_snapshot import CFGSnapshot
from .structuring_ir_hints import StructuringIRHintArtifact, build_structuring_ir_hint_artifact

__all__ = [
    "DiagnosticsCollector",
    "StructuringDiagnostic",
    "StructuringDiagnosticsReport",
    "StructuringFailureReason",
    "apply_x86_16_structuring_diagnostics",
    "build_failure_reason_from_stats",
    "suggest_recovery_hints",
]


class StructuringFailureReason(Enum):
    """Root cause of structuring failure."""

    MAX_ITERATIONS = "max_iterations"
    NO_PROGRESS = "no_progress"
    TIMEOUT = "timeout"
    MIXED_ENTRY_EXIT = "mixed_entry_exit"
    UNSUPPORTED_PATTERN = "unsupported_pattern"
    RESOURCE_LIMIT = "resource_limit"
    UNKNOWN = "unknown"


@runtime_checkable
class _StructuringFailureStatsLike8616(Protocol):
    """Structural view of fields needed to classify structuring failure."""

    iterations: int
    regions_reduced: int
    max_iterations_reached: bool


@runtime_checkable
class _StructuringHintStatsLike8616(_StructuringFailureStatsLike8616, Protocol):
    """Structural view of fields needed to emit structuring recovery hints."""

    cycles_resolved: int
    had_unstructured_gotos: bool


@runtime_checkable
class _CodegenWithCfuncLike8616(Protocol):
    """Structural codegen surface for optional structuring diagnostics."""

    cfunc: object


@dataclass(frozen=True, slots=True)
class StructuringDiagnostic:
    """Single diagnostic entry from structuring analysis."""

    kind: str  # 'failure', 'warning', 'progress'
    message: str
    region_ids: tuple[int, ...] = ()  # Affected region IDs if applicable
    iteration: int = 0  # Iteration when diagnostic occurred
    reason: StructuringFailureReason | None = None


@dataclass(slots=True)
class DiagnosticsCollector:
    """Collects diagnostics during structuring analysis."""

    diagnostics: list[StructuringDiagnostic] = field(default_factory=list)
    current_iteration: int = 0
    max_iterations: int = 1000

    def record_iteration(self, iteration: int) -> None:
        """Update current iteration counter."""
        self.current_iteration = iteration

    def add_diagnostic(
        self,
        kind: str,
        message: str,
        region_ids: tuple[int, ...] = (),
        reason: StructuringFailureReason | None = None,
    ) -> None:
        """Add a diagnostic entry."""
        diag = StructuringDiagnostic(
            kind=kind,
            message=message,
            region_ids=region_ids,
            iteration=self.current_iteration,
            reason=reason,
        )
        self.diagnostics.append(diag)

    def add_progress(self, message: str, region_ids: tuple[int, ...] = ()) -> None:
        """Record successful progress."""
        self.add_diagnostic(kind="progress", message=message, region_ids=region_ids)

    def add_warning(self, message: str, region_ids: tuple[int, ...] = ()) -> None:
        """Record a warning (non-fatal issue)."""
        self.add_diagnostic(kind="warning", message=message, region_ids=region_ids)

    def add_failure(
        self,
        message: str,
        reason: StructuringFailureReason,
        region_ids: tuple[int, ...] = (),
    ) -> None:
        """Record a failure with classified reason."""
        self.add_diagnostic(kind="failure", message=message, region_ids=region_ids, reason=reason)

    def failure_count(self) -> int:
        """Count total failures recorded."""
        return sum(1 for d in self.diagnostics if d.kind == "failure")

    def warning_count(self) -> int:
        """Count total warnings recorded."""
        return sum(1 for d in self.diagnostics if d.kind == "warning")

    def progress_count(self) -> int:
        """Count successful progress entries."""
        return sum(1 for d in self.diagnostics if d.kind == "progress")

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary representation."""
        return {
            "total_diagnostics": len(self.diagnostics),
            "failures": self.failure_count(),
            "warnings": self.warning_count(),
            "progress": self.progress_count(),
            "current_iteration": self.current_iteration,
            "diagnostics": [
                {
                    "kind": d.kind,
                    "message": d.message,
                    "iteration": d.iteration,
                    "reason": d.reason.value if d.reason else None,
                    "region_ids": list(d.region_ids),
                }
                for d in self.diagnostics
            ],
        }


@dataclass(slots=True)
class StructuringDiagnosticsReport:
    """Full report of structuring analysis."""

    func_addr: int
    func_name: str
    succeeded: bool
    final_iteration: int
    max_iterations: int
    diagnostics_collector: DiagnosticsCollector
    failure_reason: StructuringFailureReason | None = None
    recovery_hints: list[str] = field(default_factory=list)
    cfg_snapshot: CFGSnapshot | None = None
    cfg_ownership: CFGOwnershipArtifact | None = None
    cfg_indirect: CFGIndirectSiteArtifact | None = None
    cfg_grouping: CFGGroupingArtifact | None = None
    ir_hints: StructuringIRHintArtifact | None = None

    def add_recovery_hint(self, hint: str) -> None:
        """Add a recovery hint for debugging."""
        self.recovery_hints.append(hint)

    def last_failure_reason(self) -> StructuringFailureReason | None:
        """Get reason of last failure, if any."""
        for diag in reversed(self.diagnostics_collector.diagnostics):
            if diag.kind == "failure" and diag.reason:
                return diag.reason
        return self.failure_reason

    def summary_line(self) -> str:
        """One-line summary for logging."""
        if self.succeeded:
            return f"✓ {self.func_name} @ {hex(self.func_addr)}: structured in {self.final_iteration} iterations"
        else:
            reason = self.last_failure_reason()
            reason_str = reason.value if reason else "unknown"
            return (
                f"✗ {self.func_name} @ {hex(self.func_addr)}: "
                f"failed after {self.final_iteration} iterations ({reason_str})"
            )

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary representation."""
        failure_reason = self.last_failure_reason()
        return {
            "func_addr": hex(self.func_addr),
            "func_name": self.func_name,
            "succeeded": self.succeeded,
            "final_iteration": self.final_iteration,
            "max_iterations": self.max_iterations,
            "failure_reason": failure_reason.value if failure_reason is not None else None,
            "diagnostics": self.diagnostics_collector.to_dict(),
            "recovery_hints": self.recovery_hints,
            "cfg_snapshot": self.cfg_snapshot.to_dict() if self.cfg_snapshot else None,
            "cfg_ownership": self.cfg_ownership.to_dict() if self.cfg_ownership else None,
            "cfg_indirect": self.cfg_indirect.to_dict() if self.cfg_indirect else None,
            "cfg_grouping": self.cfg_grouping.to_dict() if self.cfg_grouping else None,
            "ir_hints": self.ir_hints.to_dict() if self.ir_hints else None,
        }


def build_failure_reason_from_stats(stats: object) -> StructuringFailureReason | None:
    """Classify failure reason from structuring statistics.

    Args:
        stats: StructuringStats object from analysis

    Returns:
        Classified failure reason, or None if no failure
    """
    if not isinstance(stats, _StructuringFailureStatsLike8616):
        return None

    if stats.max_iterations_reached:
        return StructuringFailureReason.MAX_ITERATIONS

    # Check if we made progress
    if stats.iterations > 100 and stats.regions_reduced == 0:
        return StructuringFailureReason.NO_PROGRESS

    return None


def suggest_recovery_hints(stats: object, region_ids: tuple[int, ...] = ()) -> list[str]:
    """Suggest recovery hints based on structuring statistics.

    Args:
        stats: StructuringStats object
        region_ids: Problem region IDs

    Returns:
        List of suggested recovery hints
    """
    hints = []

    if not isinstance(stats, _StructuringHintStatsLike8616):
        return ["Unknown reason for failure: check decompiler logs for details"]

    if stats.max_iterations_reached:
        hints.append(f"Reached iteration limit ({stats.iterations}): CFG is complex or contains unsupported patterns")
        hints.append("Try: checking for indirect jumps, tail calls, or exception handling not yet supported")

    if stats.iterations > 100 and stats.regions_reduced < 5:
        hints.append(f"Very slow progress: only {stats.regions_reduced} regions reduced in {stats.iterations} iterations")
        hints.append("Try: looking for cyclic patterns with mixed entry/exit points")

    if stats.cycles_resolved == 0 and stats.iterations > 50:
        hints.append("No cyclic patterns found despite many iterations: loops may use uncommon patterns")
        hints.append("Try: checking for breaks/continues as separate regions")

    if stats.had_unstructured_gotos:
        hints.append("Result contains unstructured gotos: some regions could not be matched to patterns")
        hints.append("Try: adding support for fallback structuring or emitting diagnostic markers in output")

    if region_ids:
        hints.append(f"Problem regions: {region_ids}")

    if not hints:
        hints.append("Unknown reason for failure: check decompiler logs for details")

    return hints


def apply_x86_16_structuring_diagnostics(codegen: object) -> bool:
    """Attach diagnostics metadata at the angr/codegen dynamic boundary without changing structuring."""

    def _impl() -> bool:
        try:
            # Handle missing or empty cfunc gracefully
            if not isinstance(codegen, _CodegenWithCfuncLike8616) or not codegen.cfunc:
                return False

            cfunc = codegen.cfunc
            # Dynamic codegen boundary: angr cfunc objects expose addresses without an owned protocol.
            func_addr = getattr(cfunc, "addr", 0)
            # Dynamic codegen boundary: angr cfunc objects expose optional display names.
            func_name = getattr(cfunc, "name", f"func_{hex(func_addr)}")

            # Check if structuring info is available
            structuring_stats = _cfunc_structuring_stats_8616(cfunc)
            succeeded = True
            final_iteration = 0
            if structuring_stats is not None:
                final_iteration = structuring_stats.iterations
                succeeded = not structuring_stats.max_iterations_reached

            # Build diagnostics collector
            collector = DiagnosticsCollector(max_iterations=1000)
            collector.current_iteration = final_iteration

            # Determine failure reason
            failure_reason = None
            if structuring_stats:
                failure_reason = build_failure_reason_from_stats(structuring_stats)

            cfg_grouping = build_cfg_grouping_artifact(codegen)
            cfg_indirect = cfg_grouping.indirect if cfg_grouping is not None else None
            cfg_ownership = cfg_indirect.ownership if cfg_indirect is not None else None
            cfg_snapshot = cfg_ownership.snapshot if cfg_ownership is not None else None

            # Build diagnostics report
            report = StructuringDiagnosticsReport(
                func_addr=func_addr,
                func_name=func_name,
                succeeded=succeeded,
                final_iteration=final_iteration,
                max_iterations=1000,
                diagnostics_collector=collector,
                failure_reason=failure_reason,
                cfg_snapshot=cfg_snapshot,
                cfg_ownership=cfg_ownership,
                cfg_indirect=cfg_indirect,
                cfg_grouping=cfg_grouping,
                ir_hints=build_structuring_ir_hint_artifact(codegen, succeeded=succeeded, iterations=final_iteration),
            )

            _collect_diagnostics_progress_8616(
                collector, report, cfg_snapshot, cfg_ownership, cfg_indirect, cfg_grouping
            )
            _attach_report_hints_8616(report, structuring_stats, succeeded)
            _attach_diagnostics_report_8616(codegen, cfunc, report)

            return False

        except Exception:
            pass

        return False

    return _impl()


def _cfunc_structuring_stats_8616(cfunc: object) -> _StructuringFailureStatsLike8616 | None:
    """Read the optional structuring stats attached at the codegen boundary."""
    # Dynamic codegen boundary: angr cfunc metadata may carry this optional compatibility field.
    stats = getattr(cfunc, "_structuring_stats", None)
    if isinstance(stats, _StructuringFailureStatsLike8616):
        return stats
    return None


def _collect_diagnostics_progress_8616(
    collector: DiagnosticsCollector,
    report: StructuringDiagnosticsReport,
    cfg_snapshot: CFGSnapshot | None,
    cfg_ownership: CFGOwnershipArtifact | None,
    cfg_indirect: CFGIndirectSiteArtifact | None,
    cfg_grouping: CFGGroupingArtifact | None,
) -> None:
    """Feed artifact summary lines into the diagnostics collector."""
    for artifact in (cfg_snapshot, cfg_ownership, cfg_indirect, cfg_grouping):
        if artifact is not None:
            collector.add_progress(artifact.summary_line())
    if report.ir_hints is not None:
        readiness = report.ir_hints.readiness
        collector.add_progress(
            "ir_readiness "
            f"level={readiness.level} "
            f"cond={readiness.condition_count} "
            f"phi={readiness.phi_node_count} "
            f"defaulted={readiness.defaulted_segment_count} "
            f"provisional={readiness.provisional_address_count}"
        )


def _attach_report_hints_8616(
    report: StructuringDiagnosticsReport,
    structuring_stats: _StructuringFailureStatsLike8616 | None,
    succeeded: bool,
) -> None:
    """Generate recovery hints and attach them to the diagnostics report."""
    if not succeeded and structuring_stats:
        for hint in suggest_recovery_hints(structuring_stats):
            report.add_recovery_hint(hint)
    if report.ir_hints is not None:
        for hint in report.ir_hints.hints:
            report.add_recovery_hint(hint)


def _attach_diagnostics_report_8616(
    codegen: object, cfunc: object, report: StructuringDiagnosticsReport
) -> None:
    """Attach the diagnostics report to codegen side metadata and the cfunc."""
    metadata = get_codegen_side_metadata(codegen)
    metadata["structuring_diagnostics"] = report
    try:
        # Dynamic codegen boundary: read optional recovery metadata from an angr cfunc object.
        cfunc_metadata = getattr(cfunc, "_recovery_metadata", None)
        if not isinstance(cfunc_metadata, dict):
            cfunc_metadata = {}
            # Dynamic codegen boundary: attach optional recovery metadata to an angr cfunc object.
            typing.cast(typing.Any, cfunc)._recovery_metadata = cfunc_metadata
        cfunc_metadata["structuring_diagnostics"] = report
    except Exception:
        pass
