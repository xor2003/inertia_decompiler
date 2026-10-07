"""Persist final indexed-global Widening artifacts for clean workers.

Layer: CLI/fallback/reporting.
Responsibility: key, encode, and restore one coherent layout plus bounded-range
bundle without rebuilding or reclassifying IR, Alias, Widening, or Types facts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import angr

from inertia.widening.global_object_layout import (
    GlobalObjectLayoutEvidence8616,
)
from inertia.widening.global_object_layout_codec import (
    global_object_layout_evidence_from_record_8616,
    global_object_layout_evidence_record_8616,
)
from inertia.widening.indexed_global_object_program_range_codec import (
    project_bounded_global_ranges_from_record_8616,
    project_bounded_global_ranges_record_8616,
)
from inertia.widening.indexed_global_object_program_ranges import (
    ProjectBoundedGlobalObjectRangeEvidence8616,
)

from .cache import _load_cache_json, _recovery_cache_key, _store_cache_json
from .cache_source_manifest import RecoveryCacheSourceScope8616
from .cli_function_discovery import _display_catalog_cache_policy_8616

INDEXED_GLOBAL_OBJECT_CACHE_NAMESPACE_8616: str = "indexed_global_object_evidence"
_INDEXED_GLOBAL_OBJECT_CACHE_SCHEMA_8616: int = 1

log: logging.Logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PersistedIndexedGlobalObjectEvidence8616:
    """Closed layout and bounded-range Widening artifacts from one census."""

    layouts: GlobalObjectLayoutEvidence8616
    ranges: ProjectBoundedGlobalObjectRangeEvidence8616

    @property
    def closed(self) -> bool:
        """Return whether both artifacts are closed and share one layout."""
        return bool(
            self.layouts.closed
            and self.ranges.closed
            and self.ranges.layouts == self.layouts
        )


def indexed_global_object_cache_key_8616(
    source_project: object,
    binary_path: Path | None,
) -> dict[str, object] | None:
    """Return semantic identity for one closed indexed-global bundle."""
    policy = _display_catalog_cache_policy_8616(cast(angr.Project, source_project))
    return _recovery_cache_key(
        binary_path=binary_path,
        kind=INDEXED_GLOBAL_OBJECT_CACHE_NAMESPACE_8616,
        source_scope=RecoveryCacheSourceScope8616.INDEXED_ALIAS_PROGRAM,
        extra={
            "artifact_schema": _INDEXED_GLOBAL_OBJECT_CACHE_SCHEMA_8616,
            "ignore_local_sidecar_hints": policy.ignore_local_sidecar_hints,
            "include_library_functions": policy.include_library_functions,
            "function_discovery_backend": policy.function_discovery_backend,
            "pat_backend": policy.pat_backend,
            "auto_rizin_policy": policy.auto_rizin_policy,
            "signature_catalog_path": policy.signature_catalog_path,
            "signature_catalog_size": policy.signature_catalog_size,
            "signature_catalog_mtime_ns": policy.signature_catalog_mtime_ns,
        },
    )


def load_indexed_global_object_cache_8616(
    cache_key: dict[str, object],
) -> PersistedIndexedGlobalObjectEvidence8616 | None:
    """Restore one closed Widening bundle, refusing malformed cache data."""
    record = _load_cache_json(INDEXED_GLOBAL_OBJECT_CACHE_NAMESPACE_8616, cache_key)
    if record is None:
        return None
    try:
        if not isinstance(record, dict) or record.get("schema") != _INDEXED_GLOBAL_OBJECT_CACHE_SCHEMA_8616:
            raise ValueError("indexed-global cache has an unsupported schema")
        result = PersistedIndexedGlobalObjectEvidence8616(
            global_object_layout_evidence_from_record_8616(record.get("layouts")),
            project_bounded_global_ranges_from_record_8616(record.get("ranges")),
        )
        if not result.closed:
            raise ValueError("indexed-global cache artifacts are incoherent")
        return result
    except ValueError as exc:
        log.warning("persisted indexed-global Widening artifact refused: %s", exc)
        return None


def store_indexed_global_object_cache_8616(
    cache_key: dict[str, object],
    evidence: PersistedIndexedGlobalObjectEvidence8616,
) -> None:
    """Persist one already-classified closed Widening bundle."""
    if not evidence.closed:
        raise ValueError("cannot persist incoherent indexed-global evidence")
    _store_cache_json(
        INDEXED_GLOBAL_OBJECT_CACHE_NAMESPACE_8616,
        cache_key,
        {
            "schema": _INDEXED_GLOBAL_OBJECT_CACHE_SCHEMA_8616,
            "layouts": global_object_layout_evidence_record_8616(evidence.layouts),
            "ranges": project_bounded_global_ranges_record_8616(evidence.ranges),
        },
    )


__all__ = [
    "INDEXED_GLOBAL_OBJECT_CACHE_NAMESPACE_8616",
    "PersistedIndexedGlobalObjectEvidence8616",
    "indexed_global_object_cache_key_8616",
    "load_indexed_global_object_cache_8616",
    "store_indexed_global_object_cache_8616",
]
