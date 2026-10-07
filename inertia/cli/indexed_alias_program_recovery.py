"""Recover a complete function catalog for program-scoped evidence.

Layer: CLI/fallback/reporting orchestration.
Responsibility: recover one complete binary function catalog and publish the
already-owned Types/Lowering callsite evidence for that catalog. This module
does not classify IR, Alias, Widening, call arguments, or rendered C.
"""

from __future__ import annotations

import contextlib
import logging
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import cast

import angr

from inertia.lowering.project_callee_callsite_collection import (
    collect_complete_project_callee_callsites_8616,
)

from .cli_function_discovery import (
    _recover_fast_exe_catalog,
    _source_region_catalog_evidence_8616,
)
from .discovery_evidence_project import isolated_discovery_evidence_project_8616
from .function_ir_ssa_cache import FunctionIRSSACatalogResult8616, hydrate_function_ir_ssa_catalog_8616
from .program_callsite_cache import (
    attach_program_callsite_caller_ranges_8616,
    attach_program_callsite_evidence_8616,
    program_callsite_evidence_from_project_8616,
    store_program_callsite_cache_8616,
)

log: logging.Logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RecoveredIndexedAliasCatalog8616:
    """One isolated evidence project and its complete function boundaries."""

    evidence_project: object
    functions: tuple[object, ...]
    ir_ssa_cache: FunctionIRSSACatalogResult8616


def recover_direct_indexed_alias_catalog_8616(
    source_project: object,
    *,
    timeout: int,
    window: int,
) -> RecoveredIndexedAliasCatalog8616 | None:
    """Recover a complete catalog, refusing incomplete discovery evidence."""
    evidence_project = isolated_discovery_evidence_project_8616(
        cast(angr.Project, source_project)
    )
    with contextlib.redirect_stdout(sys.stderr):
        recovered = _recover_fast_exe_catalog(
            evidence_project,
            timeout=max(1, timeout),
            window=max(1, window),
            low_memory=False,
            limit=None,
            seed_calling_conventions_enabled=False,
        )
    catalog = _source_region_catalog_evidence_8616(evidence_project)
    if catalog is None or not catalog.complete:
        log.warning(
            "indexed Alias program context refused: binary function census incomplete"
        )
        return None
    functions = tuple(function for _cfg, function in recovered)
    hydration = hydrate_function_ir_ssa_catalog_8616(
        evidence_project,
        functions,
    )
    if not hydration.stats.closed:
        raise RuntimeError("function IR/SSA cache hydration accounting is not closed")
    return RecoveredIndexedAliasCatalog8616(
        evidence_project,
        functions,
        hydration,
    )


def publish_recovered_program_callsites_8616(
    catalog: RecoveredIndexedAliasCatalog8616,
    target_project: object,
    source_project: object,
    *,
    cache_key: dict[str, object] | None,
    already_ready: bool,
) -> bool:
    """Publish complete callsites when required and return readiness."""
    if already_ready:
        return True
    caller_ranges_ready = attach_program_callsite_caller_ranges_8616(
        catalog.evidence_project,
        target_project,
        source_project,
    )
    if not caller_ranges_ready:
        log.warning(
            "program callsite cache refused: complete caller ranges unavailable"
        )
        return False
    collect_complete_project_callee_callsites_8616(
        catalog.evidence_project,
        cast(Sequence[object], catalog.functions),
    )
    callsite_evidence = program_callsite_evidence_from_project_8616(
        catalog.evidence_project
    )
    attach_program_callsite_evidence_8616(target_project, callsite_evidence)
    if cache_key is not None:
        store_program_callsite_cache_8616(
            cache_key,
            catalog.evidence_project,
            callsite_evidence,
        )
    return True


__all__ = [
    "RecoveredIndexedAliasCatalog8616",
    "publish_recovered_program_callsites_8616",
    "recover_direct_indexed_alias_catalog_8616",
]
