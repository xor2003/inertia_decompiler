"""Persist closed project-wide direct-global Widening evidence.

Layer: CLI/fallback/reporting.
Responsibility: key, encode, and restore one already-classified direct-global
object-layout census without rebuilding or reclassifying Lowering evidence.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import cast

import angr

from inertia.widening.direct_global_object_layout_codec import (
    direct_global_object_layout_evidence_from_record_8616,
    direct_global_object_layout_evidence_record_8616,
)
from inertia.widening.global_object_layout import (
    DirectGlobalObjectLayoutEvidence8616,
)

from .cache import _load_cache_json, _recovery_cache_key, _store_cache_json
from .cache_source_manifest import RecoveryCacheSourceScope8616
from .cli_function_discovery import _display_catalog_cache_policy_8616

DIRECT_GLOBAL_OBJECT_CACHE_NAMESPACE_8616: str = "direct_global_object_evidence"
_DIRECT_GLOBAL_OBJECT_CACHE_SCHEMA_8616: int = 1

log: logging.Logger = logging.getLogger(__name__)


def direct_global_object_cache_key_8616(
    source_project: object,
    binary_path: Path | None,
) -> dict[str, object] | None:
    """Return semantic identity for one complete direct-global census."""
    policy = _display_catalog_cache_policy_8616(cast(angr.Project, source_project))
    return _recovery_cache_key(
        binary_path=binary_path,
        kind=DIRECT_GLOBAL_OBJECT_CACHE_NAMESPACE_8616,
        source_scope=RecoveryCacheSourceScope8616.DIRECT_GLOBAL_OBJECT,
        extra={
            "artifact_schema": _DIRECT_GLOBAL_OBJECT_CACHE_SCHEMA_8616,
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


def load_direct_global_object_cache_8616(
    cache_key: dict[str, object],
) -> DirectGlobalObjectLayoutEvidence8616 | None:
    """Restore one closed census, refusing malformed cache data."""
    record = _load_cache_json(DIRECT_GLOBAL_OBJECT_CACHE_NAMESPACE_8616, cache_key)
    if record is None:
        return None
    try:
        if (
            not isinstance(record, dict)
            or record.get("schema") != _DIRECT_GLOBAL_OBJECT_CACHE_SCHEMA_8616
        ):
            raise ValueError("direct-global cache has an unsupported schema")
        return direct_global_object_layout_evidence_from_record_8616(
            record.get("evidence")
        )
    except ValueError as exc:
        log.warning("persisted direct-global Widening artifact refused: %s", exc)
        return None


def store_direct_global_object_cache_8616(
    cache_key: dict[str, object],
    evidence: DirectGlobalObjectLayoutEvidence8616,
) -> None:
    """Persist one already-classified closed direct-global census."""
    _store_cache_json(
        DIRECT_GLOBAL_OBJECT_CACHE_NAMESPACE_8616,
        cache_key,
        {
            "schema": _DIRECT_GLOBAL_OBJECT_CACHE_SCHEMA_8616,
            "evidence": direct_global_object_layout_evidence_record_8616(evidence),
        },
    )


__all__ = [
    "DIRECT_GLOBAL_OBJECT_CACHE_NAMESPACE_8616",
    "direct_global_object_cache_key_8616",
    "load_direct_global_object_cache_8616",
    "store_direct_global_object_cache_8616",
]
