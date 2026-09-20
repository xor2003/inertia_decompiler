"""Layer: Recovery/reporting.

Responsibility: assemble immutable recovery artifacts from already-produced summaries.
Forbidden: collecting new semantics, mutating output, or hiding failures.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .function_effect_summary import FunctionEffectSummary, summarize_x86_16_function_effects
from .function_state_summary import FunctionStateSummary, summarize_x86_16_function_state
from .helper_effect_summary import HelperEligibilitySummary, summarize_x86_16_helper_eligibility
from .ir_readiness import IRReadinessSummary, summarize_x86_16_ir_readiness
from .ir_recovery_summary import IRRecoverySummary, summarize_x86_16_ir_recovery
from .recovery_confidence import RecoveryConfidenceSummary, classify_x86_16_recovery_confidence
from .runtime_trace_refinement import RuntimeTraceRefinementSummary, summarize_x86_16_runtime_trace_refinement

__all__ = [
    "CorpusRecoveryArtifact",
    "FunctionRecoveryArtifact",
    "build_x86_16_corpus_recovery_artifact",
    "build_x86_16_function_recovery_artifact",
]

type RecoverySource = Mapping[str, object]


def _value(source: RecoverySource, name: str, default: object = None) -> object:
    return source.get(name, default)


@dataclass(frozen=True, slots=True)
class FunctionRecoveryArtifact:
    """Immutable function-level recovery report assembled from existing summaries."""

    cod_file: str
    proc_name: str
    proc_kind: str
    ok: bool
    stage_reached: str
    failure_class: str | None
    fallback_kind: str | None
    semantic_family: str | None
    ir_summary: IRRecoverySummary
    ir_readiness: IRReadinessSummary
    effect_summary: FunctionEffectSummary
    state_summary: FunctionStateSummary
    helper_summary: HelperEligibilitySummary
    trace_refinement: RuntimeTraceRefinementSummary
    confidence: RecoveryConfidenceSummary

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible function artifact."""
        return {
            "cod_file": self.cod_file,
            "proc_name": self.proc_name,
            "proc_kind": self.proc_kind,
            "ok": self.ok,
            "stage_reached": self.stage_reached,
            "failure_class": self.failure_class,
            "fallback_kind": self.fallback_kind,
            "semantic_family": self.semantic_family,
            "ir_summary": self.ir_summary.to_dict(),
            "ir_readiness": self.ir_readiness.to_dict(),
            "effect_summary": self.effect_summary.to_dict(),
            "state_summary": self.state_summary.to_dict(),
            "helper_summary": self.helper_summary.to_dict(),
            "trace_refinement": self.trace_refinement.to_dict(),
            "confidence": self.confidence.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class CorpusRecoveryArtifact:
    """Immutable corpus-level recovery report assembled from function artifacts."""

    function_rows: tuple[FunctionRecoveryArtifact, ...]
    confidence_status_counts: dict[str, int]
    ir_readiness_level_counts: dict[str, int]
    low_memory_read_region_counts: dict[str, int]
    low_memory_write_region_counts: dict[str, int]
    helper_status_counts: dict[str, int]
    helper_candidate_counts: dict[str, int]
    helper_refusal_counts: dict[str, int]
    helper_family_rows: tuple[dict[str, object], ...]

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible corpus artifact."""
        return {
            "function_rows": [row.to_dict() for row in self.function_rows],
            "confidence_status_counts": dict(self.confidence_status_counts),
            "ir_readiness_level_counts": dict(self.ir_readiness_level_counts),
            "low_memory_read_region_counts": dict(self.low_memory_read_region_counts),
            "low_memory_write_region_counts": dict(self.low_memory_write_region_counts),
            "helper_status_counts": dict(self.helper_status_counts),
            "helper_candidate_counts": dict(self.helper_candidate_counts),
            "helper_refusal_counts": dict(self.helper_refusal_counts),
            "helper_family_rows": [dict(row) for row in self.helper_family_rows],
        }


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _string_int_counts(value: object) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    counts: dict[str, int] = {}
    for key, count in value.items():
        if isinstance(count, int):
            counts[str(key)] = count
    return counts


def _mapping_rows(value: object) -> tuple[dict[str, object], ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    rows: list[dict[str, object]] = []
    for item in value:
        if isinstance(item, Mapping):
            rows.append({str(key): row_value for key, row_value in item.items()})
    return tuple(rows)


def build_x86_16_function_recovery_artifact(source: RecoverySource) -> FunctionRecoveryArtifact:
    """Build one function recovery artifact from an already-produced mapping row."""
    return FunctionRecoveryArtifact(
        cod_file=str(_value(source, "cod_file", "")),
        proc_name=str(_value(source, "proc_name", "")),
        proc_kind=str(_value(source, "proc_kind", "")),
        ok=bool(_value(source, "ok", False)),
        stage_reached=str(_value(source, "stage_reached", "unknown")),
        failure_class=_optional_text(_value(source, "failure_class", None)),
        fallback_kind=_optional_text(_value(source, "fallback_kind", None)),
        semantic_family=_optional_text(_value(source, "semantic_family", None)),
        ir_summary=summarize_x86_16_ir_recovery(source),
        ir_readiness=summarize_x86_16_ir_readiness(source),
        effect_summary=summarize_x86_16_function_effects(source),
        state_summary=summarize_x86_16_function_state(source),
        helper_summary=summarize_x86_16_helper_eligibility(source),
        trace_refinement=summarize_x86_16_runtime_trace_refinement(source),
        confidence=classify_x86_16_recovery_confidence(source),
    )


def build_x86_16_corpus_recovery_artifact(results: Sequence[RecoverySource]) -> CorpusRecoveryArtifact:
    """Build a deterministic corpus recovery artifact from existing mapping rows."""
    from .recovery_confidence import summarize_recovery_confidence

    def _sorted_counts(counts: dict[str, int]) -> dict[str, int]:
        return dict(sorted(counts.items()))

    function_rows = tuple(
        sorted(
            (build_x86_16_function_recovery_artifact(result) for result in results),
            key=lambda row: (row.cod_file, row.proc_name, row.proc_kind),
        )
    )
    ir_readiness_level_counts: dict[str, int] = {}
    low_memory_read_region_counts: dict[str, int] = {}
    low_memory_write_region_counts: dict[str, int] = {}
    for row in function_rows:
        ir_readiness_level_counts[row.ir_readiness.level] = ir_readiness_level_counts.get(row.ir_readiness.level, 0) + 1
        for access in row.state_summary.low_memory_reads:
            low_memory_read_region_counts[access.region] = low_memory_read_region_counts.get(access.region, 0) + 1
        for access in row.state_summary.low_memory_writes:
            low_memory_write_region_counts[access.region] = low_memory_write_region_counts.get(access.region, 0) + 1
    confidence_summary = summarize_recovery_confidence(list(results))
    return CorpusRecoveryArtifact(
        function_rows=function_rows,
        confidence_status_counts=_string_int_counts(confidence_summary.get("status_counts", {})),
        ir_readiness_level_counts=_sorted_counts(ir_readiness_level_counts),
        low_memory_read_region_counts=_sorted_counts(low_memory_read_region_counts),
        low_memory_write_region_counts=_sorted_counts(low_memory_write_region_counts),
        helper_status_counts=_string_int_counts(confidence_summary.get("helper_status_counts", {})),
        helper_candidate_counts=_string_int_counts(confidence_summary.get("helper_candidate_counts", {})),
        helper_refusal_counts=_string_int_counts(confidence_summary.get("helper_refusal_counts", {})),
        helper_family_rows=_mapping_rows(confidence_summary.get("helper_family_rows", ())),
    )
