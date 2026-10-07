"""Define sidecar precision policy for CLI discovery decisions.

Layer: CLI/fallback/reporting.
Responsibility: classify optional sidecar precision without owning semantic recovery.
"""

from __future__ import annotations

from typing import Protocol

__all__ = ["metadata_has_precise_code_regions"]


class _MetadataLike(Protocol):
    source_format: str


_PRECISE_SOURCE_MARKERS = (
    "codeview",
    "cod_listing",
    "turbo_debug",
    "td",
    "source_listing",
    "ida_lst",
    "ida_map",
    "mzre_map",
    "debug",
)


def metadata_has_precise_code_regions(metadata: _MetadataLike | None) -> bool:
    """Return whether sidecar metadata includes precise code-region evidence."""
    if metadata is None:
        return False
    source_format = metadata.source_format or ""
    parts = tuple(part.strip().lower() for part in source_format.split("+") if part.strip())
    return any(any(marker in part for marker in _PRECISE_SOURCE_MARKERS) for part in parts)
