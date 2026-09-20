"""Report generated-C acceptance markers without defining semantic truth.

Layer: CLI/fallback/reporting.
Responsibility: summarize generated-output quality markers without deciding semantic correctness.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass

from inertia_decompiler.work_items import TailValidationDisplayOutcome

__all__ = [
    "AcceptanceScorecard",
    "X86_16QualityMetrics",
    "build_acceptance_scorecard",
    "format_x86_16_quality_report_8616",
    "measure_x86_16_codegen_quality_8616",
    "measure_x86_16_function_quality_8616",
]


class X86_16QualityMetrics:
    """Reporting-only generated-C quality metrics for a single function."""

    __slots__ = (
        "asm_fallback_count",
        "function_addr",
        "function_name",
        "named_local_count",
        "raw_flag_condition_count",
        "raw_ss_linear_expr_count",
        "tmp_condition_count",
        "typed_condition_count",
        "validation_uncollected_count",
    )

    def __init__(
        self,
        *,
        function_name: str = "unknown",
        function_addr: int = 0,
        tmp_condition_count: int = 0,
        raw_flag_condition_count: int = 0,
        raw_ss_linear_expr_count: int = 0,
        asm_fallback_count: int = 0,
        validation_uncollected_count: int = 0,
        typed_condition_count: int = 0,
        named_local_count: int = 0,
    ) -> None:
        """Initialize a deterministic quality metric row for one function."""
        self.function_name = function_name
        self.function_addr = function_addr
        self.tmp_condition_count = tmp_condition_count
        self.raw_flag_condition_count = raw_flag_condition_count
        self.raw_ss_linear_expr_count = raw_ss_linear_expr_count
        self.asm_fallback_count = asm_fallback_count
        self.validation_uncollected_count = validation_uncollected_count
        self.typed_condition_count = typed_condition_count
        self.named_local_count = named_local_count

    def to_dict(self) -> dict[str, object]:
        """Return a deterministic JSON-compatible metric payload."""
        return {
            "function_name": self.function_name,
            "function_addr": self.function_addr,
            "tmp_condition_count": self.tmp_condition_count,
            "raw_flag_condition_count": self.raw_flag_condition_count,
            "raw_ss_linear_expr_count": self.raw_ss_linear_expr_count,
            "asm_fallback_count": self.asm_fallback_count,
            "validation_uncollected_count": self.validation_uncollected_count,
            "typed_condition_count": self.typed_condition_count,
            "named_local_count": self.named_local_count,
        }

    @property
    def total_bad_patterns(self) -> int:
        """Return the total count of emitted-C patterns that lower quality."""
        return (
            self.tmp_condition_count
            + self.raw_flag_condition_count
            + self.raw_ss_linear_expr_count
            + self.asm_fallback_count
        )

    @property
    def quality_score(self) -> float:
        """Return the bounded quality score derived from bad-pattern counters."""
        penalty = self.total_bad_patterns * 0.1 + self.validation_uncollected_count * 0.5
        penalty = min(penalty, 0.95)
        return round(1.0 - penalty, 3)


_TMP_CONDITION_RE = re.compile(r"tmp_\d+", re.IGNORECASE)
_RAW_FLAG_RE = re.compile(r"\b(flags|eflags)\b", re.IGNORECASE)
_RAW_SS_EXPR_RE = re.compile(r"\(\(ss\s*<<\s*4\)\s*\+", re.IGNORECASE)
_CMP_NE_RE = re.compile(r"CmpNE\(", re.IGNORECASE)
_CMP_EQ_RE = re.compile(r"CmpEQ\(", re.IGNORECASE)


def _int_field(aggregate: Mapping[str, object], name: str) -> int:
    """Return one integer aggregate field or a reporting-safe zero."""
    value = aggregate.get(name, 0)
    return value if isinstance(value, int) else 0


def _float_field(aggregate: Mapping[str, object], name: str) -> float:
    """Return one float aggregate field or a reporting-safe zero."""
    value = aggregate.get(name, 0.0)
    return value if isinstance(value, float) else 0.0


def measure_x86_16_codegen_quality_8616(
    c_text: str,
    *,
    function_name: str = "unknown",
    function_addr: int = 0,
    asm_fallback: bool = False,
    validation_uncollected: bool = False,
) -> X86_16QualityMetrics:
    """Measure reporting-only VEX/tmp leakage metrics from generated C text."""
    return X86_16QualityMetrics(
        function_name=function_name,
        function_addr=function_addr,
        tmp_condition_count=len(_TMP_CONDITION_RE.findall(c_text)),
        raw_flag_condition_count=len(_RAW_FLAG_RE.findall(c_text)),
        raw_ss_linear_expr_count=len(_RAW_SS_EXPR_RE.findall(c_text)),
        asm_fallback_count=1 if asm_fallback else 0,
        validation_uncollected_count=1 if validation_uncollected else 0,
        typed_condition_count=len(_CMP_NE_RE.findall(c_text)) + len(_CMP_EQ_RE.findall(c_text)),
        named_local_count=len(re.findall(r"\bvar_[0-9a-f]+\b", c_text, re.IGNORECASE)),
    )


def measure_x86_16_function_quality_8616(
    metrics_list: list[X86_16QualityMetrics],
) -> dict[str, object]:
    """Aggregate reporting-only quality metrics across multiple functions."""
    if not metrics_list:
        return {
            "function_count": 0,
            "total_tmp_conditions": 0,
            "total_raw_flag_conditions": 0,
            "total_raw_ss_linear_exprs": 0,
            "total_asm_fallbacks": 0,
            "total_validation_uncollected": 0,
            "total_typed_conditions": 0,
            "total_named_locals": 0,
            "avg_quality_score": 0.0,
        }
    total = len(metrics_list)
    return {
        "function_count": total,
        "total_tmp_conditions": sum(m.tmp_condition_count for m in metrics_list),
        "total_raw_flag_conditions": sum(m.raw_flag_condition_count for m in metrics_list),
        "total_raw_ss_linear_exprs": sum(m.raw_ss_linear_expr_count for m in metrics_list),
        "total_asm_fallbacks": sum(m.asm_fallback_count for m in metrics_list),
        "total_validation_uncollected": sum(m.validation_uncollected_count for m in metrics_list),
        "total_typed_conditions": sum(m.typed_condition_count for m in metrics_list),
        "total_named_locals": sum(m.named_local_count for m in metrics_list),
        "avg_quality_score": round(sum(m.quality_score for m in metrics_list) / max(total, 1), 3),
    }


def format_x86_16_quality_report_8616(aggregate: Mapping[str, object]) -> str:
    """Format aggregate generated-C quality metrics for diagnostics."""
    total = _int_field(aggregate, "function_count")
    lines: list[str] = [
        f"Quality Report ({total} functions)",
        "=" * 40,
        f"  tmp conditions:          {_int_field(aggregate, 'total_tmp_conditions')}",
        f"  raw flag conditions:     {_int_field(aggregate, 'total_raw_flag_conditions')}",
        f"  raw ss linear exprs:     {_int_field(aggregate, 'total_raw_ss_linear_exprs')}",
        f"  asm fallbacks:           {_int_field(aggregate, 'total_asm_fallbacks')}",
        f"  validation uncollected:  {_int_field(aggregate, 'total_validation_uncollected')}",
        f"  typed conditions:        {_int_field(aggregate, 'total_typed_conditions')}",
        f"  named locals:            {_int_field(aggregate, 'total_named_locals')}",
        f"  avg quality score:       {_float_field(aggregate, 'avg_quality_score')}",
    ]
    return "\n".join(lines)


_FLAGS_RE = re.compile(r"\bflags(?:_[A-Za-z0-9]+)?\b")
_VVAR_RE = re.compile(r"\bvvar_[A-Za-z0-9]+\b")
_SUB_RE = re.compile(r"\bsub_[0-9a-fA-F]+\b")
_TAIL_VALIDATION_METADATA_RE = re.compile(r"@@INERTIA_TAIL_VALIDATION@@\s+(\{.*\})")
_WHOLE_TAIL_REPORT_RE = re.compile(
    r"^\[tail-validation\] whole-tail validation (clean|changed|failed|unknown|uncollected)"
    r"(?: across \d+ functions)?\s*$", re.MULTILINE,
)
_DS_HELPER_LINEAR_RE = re.compile(r"\b(?:SEG_PTR|MK_FP|SEG_U8|SEG_U16|SEG_U32)\s*\(\s*ds\s*,")
_SS_LINEAR_RE = re.compile(r"\bss\s*\*\s*16\b")


@dataclass(frozen=True, slots=True)
class AcceptanceScorecard:
    """Generated-output quality counters for one recovered function."""

    function_name: str
    raw_flags_count: int
    raw_ss_linear_count: int
    raw_ds_linear_count: int
    vvar_count: int
    anonymous_sub_count: int
    recovery_mode: str
    validation_verdict: str
    source_present: bool

    def to_row(self) -> dict[str, object]:
        """Return a stable JSON-serializable scorecard row."""
        return {
            "function_name": self.function_name,
            "raw_flags_count": self.raw_flags_count,
            "raw_ss_linear_count": self.raw_ss_linear_count,
            "raw_ds_linear_count": self.raw_ds_linear_count,
            "vvar_count": self.vvar_count,
            "anonymous_sub_count": self.anonymous_sub_count,
            "recovery_mode": self.recovery_mode,
            "validation_verdict": self.validation_verdict,
            "source_present": self.source_present,
        }


def _recovery_mode_from_output(output: str) -> str:
    lowered = output.lower()
    if "/* == asm fallback == */" in lowered:
        return "asm_fallback"
    if "/* -- c (non-optimized fallback) -- */" in lowered or "/* non-optimized fallback" in lowered:
        return "asm_fallback"
    if "/* == c == */" in lowered or "/* -- c -- */" in lowered:
        return "decompiled"
    return "unknown"


def _metadata_validation_verdict(output: str) -> str | None:
    """Decode the legacy structured report without treating arbitrary JSON as evidence."""
    match = _TAIL_VALIDATION_METADATA_RE.search(output)
    if match is None:
        return None
    try:
        payload = json.loads(match.group(1))
    except json.JSONDecodeError:
        return None
    surface = payload.get("surface") if isinstance(payload, dict) else None
    severity = surface.get("severity") if isinstance(surface, dict) else None
    if not isinstance(severity, str) or not severity:
        return None
    return "failed" if severity == "changed" else severity


def _validation_verdict_from_output(output: str) -> str:
    """Prefer published validation reports over diagnostics of rejected attempts."""
    metadata = _metadata_validation_verdict(output)
    if metadata is not None:
        return metadata
    reports = _WHOLE_TAIL_REPORT_RE.findall(output)
    if reports:
        final = reports[-1]
        status = TailValidationDisplayOutcome.STABLE if final == "clean" else TailValidationDisplayOutcome(final)
        return str(TailValidationDisplayOutcome.FAILED if status is TailValidationDisplayOutcome.CHANGED else status)
    lowered = output.lower()
    for verdict in ("failed", "unknown", "uncollected", "stable", "changed"):
        if f"tail-validation:{verdict}" in lowered or f"validation={verdict}" in lowered:
            return "failed" if verdict == "changed" else verdict
    return "uncollected"


def build_acceptance_scorecard(
    function_name: str,
    recovered_output: str,
    *,
    source_text: str | None = None,
) -> AcceptanceScorecard:
    """Build reporting-only quality counters for one recovered output."""
    recovery_mode = _recovery_mode_from_output(recovered_output)
    validation_verdict = _validation_verdict_from_output(recovered_output)
    if recovery_mode == "asm_fallback" and validation_verdict == "failed":
        # Scorecards track fallback degradation separately from strict CLI
        # validation printing ("failed").
        validation_verdict = "changed"
    return AcceptanceScorecard(
        function_name=function_name,
        raw_flags_count=len(_FLAGS_RE.findall(recovered_output)),
        raw_ss_linear_count=recovered_output.count("ss << 4") + len(_SS_LINEAR_RE.findall(recovered_output)),
        raw_ds_linear_count=recovered_output.count("ds << 4") + len(_DS_HELPER_LINEAR_RE.findall(recovered_output)),
        vvar_count=len(_VVAR_RE.findall(recovered_output)),
        anonymous_sub_count=len(_SUB_RE.findall(recovered_output)),
        recovery_mode=recovery_mode,
        validation_verdict=validation_verdict,
        source_present=bool(source_text),
    )
