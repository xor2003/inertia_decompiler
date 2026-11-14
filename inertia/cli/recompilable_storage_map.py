# cython: language_level=3, infer_types=True
"""Layer: Recompilable output.

Responsibility: materialize proven segmented storage rows for generated-C recompilation.
Forbidden: segment flattening, guessed objects, or text-derived storage identity.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable
from dataclasses import dataclass
import dataclasses

__all__ = [
    "RecompilableStorageMapArtifact",
    "RecompilableStorageMapCandidate",
    "RecompilableStorageMapRefusal",
    "RecompilableStorageMapRow",
    "build_recompilable_storage_map",
]


_SEGMENT_ORDER = {
    "CS": 0,
    "DS": 1,
    "ES": 2,
    "SS": 3,
    "FS": 4,
    "GS": 5,
}


@dataclasses.dataclass(frozen=True, )
class RecompilableStorageMapCandidate:
    """Candidate segmented storage identity for recompilable C output."""

    segment_reg: object
    segment_value: int | None
    offset: cython.longlong
    width: cython.longlong
    identity_kind: object
    association_classification: object
    allow_linear_lowering: cython.bint
    stable_object_kind: object = None
    stable_object_name: object = None


@dataclasses.dataclass(frozen=True, )
class RecompilableStorageMapRow:
    """Accepted segmented storage row with proven linear-lowering support."""

    segment_reg: object
    segment_value: int | None
    offset: cython.longlong
    width: cython.longlong
    identity_kind: object
    stable_object_kind: object
    stable_object_name: object


@dataclasses.dataclass(frozen=True, )
class RecompilableStorageMapRefusal:
    """Rejected segmented storage candidate with an explicit refusal reason."""

    segment_reg: object
    offset: cython.longlong
    width: cython.longlong
    identity_kind: object
    classification: object
    reason: object


@dataclasses.dataclass(frozen=True, )
class RecompilableStorageMapArtifact:
    """Complete accepted/refused segmented storage map for recompilation reports."""

    rows: object
    refusals: object


@cython.ccall
def _segment_sort_key(segment_reg: object) -> tuple[cython.longlong, str]:
    normalized = segment_reg.upper()
    return (_SEGMENT_ORDER.get(normalized, 99), normalized)


@cython.ccall
def _candidate_sort_key(
    candidate: RecompilableStorageMapCandidate,
) -> tuple[tuple[cython.longlong, str], cython.longlong, cython.longlong, str, str, str]:
    return (
        _segment_sort_key(candidate.segment_reg),
        candidate.offset,
        candidate.width,
        candidate.identity_kind,
        candidate.stable_object_kind or "",
        candidate.stable_object_name or "",
    )


@cython.ccall
def _refusal_reason(candidate: RecompilableStorageMapCandidate) -> str:
    if candidate.association_classification == "over_associated":
        return "multiple incompatible segment bases"
    if candidate.association_classification == "unknown":
        return "unknown segment association"
    if candidate.association_classification == "single":
        return "stable segment register but no constant base"
    return "segment lowering not proven"


@cython.ccall
def build_recompilable_storage_map(
    candidates: Iterable[RecompilableStorageMapCandidate],
) -> RecompilableStorageMapArtifact:
    """Build a deterministic storage map from proven segmented candidates."""
    candidate: object
    rows: list[RecompilableStorageMapRow] = []
    refusals: list[RecompilableStorageMapRefusal] = []

    for candidate in sorted(candidates, key=_candidate_sort_key):
        if not candidate.allow_linear_lowering:
            refusals.append(
                RecompilableStorageMapRefusal(
                    segment_reg=candidate.segment_reg.upper(),
                    offset=candidate.offset,
                    width=candidate.width,
                    identity_kind=candidate.identity_kind,
                    classification=candidate.association_classification,
                    reason=_refusal_reason(candidate),
                )
            )
            continue
        rows.append(
            RecompilableStorageMapRow(
                segment_reg=candidate.segment_reg.upper(),
                segment_value=candidate.segment_value,
                offset=candidate.offset,
                width=candidate.width,
                identity_kind=candidate.identity_kind,
                stable_object_kind=candidate.stable_object_kind,
                stable_object_name=candidate.stable_object_name,
            )
        )

    return RecompilableStorageMapArtifact(tuple(rows), tuple(refusals))
