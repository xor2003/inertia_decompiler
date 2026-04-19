from __future__ import annotations

from dataclasses import dataclass
import json
import re

__all__ = [
    "AcceptanceScorecard",
    "build_acceptance_scorecard",
]


_FLAGS_RE = re.compile(r"\bflags(?:_[A-Za-z0-9]+)?\b")
_VVAR_RE = re.compile(r"\bvvar_[A-Za-z0-9]+\b")
_SUB_RE = re.compile(r"\bsub_[0-9a-fA-F]+\b")
_TAIL_VALIDATION_METADATA_RE = re.compile(r"@@INERTIA_TAIL_VALIDATION@@\s+(\{.*\})")


@dataclass(frozen=True, slots=True)
class AcceptanceScorecard:
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
        return "c_fallback"
    if "/* == c == */" in lowered or "/* -- c -- */" in lowered:
        return "decompiled"
    return "unknown"


def _validation_verdict_from_output(output: str) -> str:
    lowered = output.lower()
    metadata_match = _TAIL_VALIDATION_METADATA_RE.search(output)
    if metadata_match is not None:
        with_context = metadata_match.group(1)
        try:
            payload = json.loads(with_context)
        except Exception:
            payload = None
        if isinstance(payload, dict):
            surface = payload.get("surface", {})
            severity = surface.get("severity")
            if isinstance(severity, str) and severity:
                return severity
    for verdict in ("changed", "unknown", "uncollected", "stable"):
        if f"tail-validation:{verdict}" in lowered or f"validation={verdict}" in lowered:
            return verdict
    if "[tail-validation] whole-tail validation changed" in lowered:
        return "changed"
    if "[tail-validation] whole-tail validation clean" in lowered:
        return "stable"
    if "[tail-validation] whole-tail validation unknown" in lowered:
        return "unknown"
    if "[tail-validation] whole-tail validation uncollected" in lowered:
        return "uncollected"
    return "disabled"


def build_acceptance_scorecard(
    function_name: str,
    recovered_output: str,
    *,
    source_text: str | None = None,
) -> AcceptanceScorecard:
    return AcceptanceScorecard(
        function_name=function_name,
        raw_flags_count=len(_FLAGS_RE.findall(recovered_output)),
        raw_ss_linear_count=recovered_output.count("ss << 4"),
        raw_ds_linear_count=recovered_output.count("ds << 4"),
        vvar_count=len(_VVAR_RE.findall(recovered_output)),
        anonymous_sub_count=len(_SUB_RE.findall(recovered_output)),
        recovery_mode=_recovery_mode_from_output(recovered_output),
        validation_verdict=_validation_verdict_from_output(recovered_output),
        source_present=bool(source_text),
    )
