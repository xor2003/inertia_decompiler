"""Layer: Recompilable output.

Responsibility: keep storage fallback decisions explicit and currently disabled.
Forbidden: selecting source-evidence fallback C or hiding live decompile failures.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "RecompilableStorageFallbackDecision",
    "decide_recompilable_storage_fallback",
]


@dataclass(frozen=True, slots=True)
class RecompilableStorageFallbackDecision:
    """Explicit result of the currently disabled storage fallback selector."""

    use_fallback: bool
    c_text_source: str | None
    bounded_live_decompile_outcome: str | None
    selected_text: str | None
    live_shape_ok: bool
    fallback_shape_ok: bool
    shape_ok_evidence_present: bool
    fallback_evidence_present: bool
    storage_object_record_count: int
    storage_object_refusal_count: int


def decide_recompilable_storage_fallback(
    *,
    live_shape_ok: bool,
    fallback_shape_ok: bool,
    shape_ok_evidence_text: str | None,
    fallback_evidence_text: str | None,
    storage_object_record_count: int,
    storage_object_refusal_count: int,
) -> RecompilableStorageFallbackDecision:
    """Refuse storage fallback C while preserving live/fallback evidence inputs."""
    return RecompilableStorageFallbackDecision(
        use_fallback=False,
        c_text_source=None,
        bounded_live_decompile_outcome=None,
        selected_text=None,
        live_shape_ok=live_shape_ok,
        fallback_shape_ok=fallback_shape_ok,
        shape_ok_evidence_present=shape_ok_evidence_text is not None,
        fallback_evidence_present=fallback_evidence_text is not None,
        storage_object_record_count=storage_object_record_count,
        storage_object_refusal_count=storage_object_refusal_count,
    )
