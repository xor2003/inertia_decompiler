# cython: language_level=3, infer_types=True
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
import typing
import cython

from dataclasses import dataclass
import dataclasses

__all__ = [
    "RecompilableStorageFallbackDecision",
    "decide_recompilable_storage_fallback",
]


@dataclasses.dataclass(frozen=True, )
class RecompilableStorageFallbackDecision:
    """Explicit result of the currently disabled storage fallback selector."""

    use_fallback: cython.bint
    c_text_source: object
    bounded_live_decompile_outcome: object
    selected_text: object
    live_shape_ok: cython.bint
    fallback_shape_ok: cython.bint
    shape_ok_evidence_present: cython.bint
    fallback_evidence_present: cython.bint
    storage_object_record_count: cython.longlong
    storage_object_refusal_count: cython.longlong


@cython.ccall
def decide_recompilable_storage_fallback(
    *,
    live_shape_ok: cython.bint,
    fallback_shape_ok: cython.bint,
    shape_ok_evidence_text: object,
    fallback_evidence_text: object,
    storage_object_record_count: cython.longlong,
    storage_object_refusal_count: cython.longlong,
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
