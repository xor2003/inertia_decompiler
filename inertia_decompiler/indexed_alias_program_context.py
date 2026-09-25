"""Publish discovered function boundaries as Alias and Widening artifacts.

Layer: CLI/fallback/reporting orchestration.
Responsibility: transport a complete binary function catalog into the Alias
program builder once, invoke the Widening owner, then attach immutable results
for sliced workers. No semantic fact is classified in CLI; discovery supplies
boundaries and the owning X86_16 layers classify them.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol, cast

from angr_platforms.X86_16.alias.indexed_address_program import (
    IndexedAliasProgramEvidence8616,
)
from angr_platforms.X86_16.lowering.global_object_program_requirement import (
    GlobalObjectProgramRequirementEvidence8616,
    collect_global_object_program_requirement_8616,
)
from angr_platforms.X86_16.widening.global_object_layout import (
    DirectGlobalObjectLayoutEvidence8616,
    GlobalObjectLayoutEvidence8616,
)
from angr_platforms.X86_16.widening.indexed_global_object_program_ranges import (
    ProjectBoundedGlobalObjectRangeEvidence8616,
)

from .cache import _cache_key_lock
from .direct_global_object_cache import direct_global_object_cache_key_8616
from .direct_global_object_context import (
    attach_available_direct_global_object_evidence_8616,
    publish_recovered_direct_global_object_evidence_8616,
)
from .direct_indexed_alias_local_cache import (
    build_cached_direct_indexed_alias_local_evidence_8616,
)
from .function_ir_ssa_cache import store_function_ir_ssa_catalog_8616
from .indexed_alias_program_publication import publish_discovered_indexed_alias_program_8616
from .indexed_alias_program_recovery import (
    publish_recovered_program_callsites_8616,
    recover_direct_indexed_alias_catalog_8616,
)
from .indexed_global_object_cache import (
    INDEXED_GLOBAL_OBJECT_CACHE_NAMESPACE_8616,
    PersistedIndexedGlobalObjectEvidence8616,
    indexed_global_object_cache_key_8616,
    load_indexed_global_object_cache_8616,
    store_indexed_global_object_cache_8616,
)
from .program_callsite_cache import (
    attach_available_program_callsite_evidence_8616,
    program_callsite_cache_key_8616,
)
from .project_evidence_transport import (
    attach_project_bounded_global_object_ranges_8616,
    attach_project_global_object_layout_evidence_8616,
)


class IndexedAliasProgramContextStatus8616(StrEnum):
    """Typed result of preparing one direct-run Alias program context."""

    NOT_REQUIRED = "not_required"
    PUBLISHED = "published"
    REUSED_WIDENING = "reused_widening"
    REUSED_PERSISTED_WIDENING = "reused_persisted_widening"
    DISCOVERY_INCOMPLETE = "discovery_incomplete"


@dataclass(frozen=True, slots=True)
class IndexedAliasProgramContextResult8616:
    """One direct-run context status and its optional complete program."""

    status: IndexedAliasProgramContextStatus8616
    program: IndexedAliasProgramEvidence8616 | None
    requirement: GlobalObjectProgramRequirementEvidence8616


class _ProjectProgramSurface8616(Protocol):
    """Owned immutable Alias/Widening artifacts attached to a project."""

    _inertia_indexed_alias_program_evidence_8616: IndexedAliasProgramEvidence8616
    _inertia_project_global_object_layout_evidence_8616: GlobalObjectLayoutEvidence8616
    _inertia_project_bounded_global_object_ranges_8616: ProjectBoundedGlobalObjectRangeEvidence8616
    _inertia_project_direct_global_object_layout_evidence_8616: DirectGlobalObjectLayoutEvidence8616
    _inertia_global_object_program_requirement_8616: GlobalObjectProgramRequirementEvidence8616


def _discover_direct_indexed_alias_program_context_8616(
    source_project: object,
    target_project: object,
    requirement: GlobalObjectProgramRequirementEvidence8616,
    *,
    timeout: int,
    window: int,
    cache_key: dict[str, object] | None,
    callsite_cache_key: dict[str, object] | None,
    direct_cache_key: dict[str, object] | None,
    program_callsites_ready: bool = False,
) -> IndexedAliasProgramContextResult8616:
    """Publish a complete census and optionally persist its closed projection."""
    catalog = recover_direct_indexed_alias_catalog_8616(
        source_project,
        timeout=timeout,
        window=window,
    )
    if catalog is None:
        return IndexedAliasProgramContextResult8616(
            IndexedAliasProgramContextStatus8616.DISCOVERY_INCOMPLETE,
            None,
            requirement,
        )
    publish_recovered_direct_global_object_evidence_8616(
        catalog.evidence_project,
        catalog.functions,
        target_project,
        cache_key=direct_cache_key,
    )
    program = publish_discovered_indexed_alias_program_8616(
        catalog.evidence_project,
        catalog.functions,
        target_project=target_project,
    )
    stored_ir_ssa = store_function_ir_ssa_catalog_8616(
        catalog.evidence_project, catalog.functions,
        already_hydrated=catalog.ir_ssa_cache,
    )
    if not stored_ir_ssa.stats.closed:
        raise RuntimeError("function IR/SSA cache store accounting is not closed")
    target_layout = cast(
        _ProjectProgramSurface8616,
        target_project,
    )._inertia_project_global_object_layout_evidence_8616
    target_ranges = cast(
        _ProjectProgramSurface8616,
        target_project,
    )._inertia_project_bounded_global_object_ranges_8616
    publish_recovered_program_callsites_8616(
        catalog,
        target_project,
        source_project,
        cache_key=callsite_cache_key,
        already_ready=program_callsites_ready,
    )
    if cache_key is not None:
        store_indexed_global_object_cache_8616(
            cache_key,
            PersistedIndexedGlobalObjectEvidence8616(target_layout, target_ranges),
        )
    return IndexedAliasProgramContextResult8616(
        IndexedAliasProgramContextStatus8616.PUBLISHED,
        program,
        requirement,
    )


def _transported_widening_bundle_8616(
    target_surface: _ProjectProgramSurface8616,
) -> tuple[GlobalObjectLayoutEvidence8616, ProjectBoundedGlobalObjectRangeEvidence8616] | None:
    """Return a coherent transported Widening bundle, or None when absent."""
    try:
        transported_layout = target_surface._inertia_project_global_object_layout_evidence_8616
    except AttributeError:
        transported_layout = None
    try:
        transported_ranges = target_surface._inertia_project_bounded_global_object_ranges_8616
    except AttributeError:
        transported_ranges = None
    if (transported_layout is None) != (transported_ranges is None):
        raise ValueError("transported indexed-global Widening bundle is incomplete")
    if transported_layout is None or transported_ranges is None:
        return None
    if not isinstance(transported_layout, GlobalObjectLayoutEvidence8616):
        raise TypeError("transported indexed-global Widening artifact has a wrong type")
    if not isinstance(transported_ranges, ProjectBoundedGlobalObjectRangeEvidence8616):
        raise TypeError("transported bounded-global Widening artifact has a wrong type")
    if not transported_layout.closed:
        raise ValueError("transported indexed-global Widening artifact is open")
    if not transported_ranges.closed or transported_ranges.layouts != transported_layout:
        raise ValueError("transported indexed-global Widening bundle is incoherent")
    return transported_layout, transported_ranges


def _reused_persisted_context_8616(
    source_project: object,
    target_project: object,
    requirement: GlobalObjectProgramRequirementEvidence8616,
    *,
    persisted: PersistedIndexedGlobalObjectEvidence8616 | None,
    timeout: int,
    window: int,
    callsite_cache_key: object,
    direct_cache_key: object,
    direct_evidence_ready: bool,
    program_callsites_ready: bool,
) -> IndexedAliasProgramContextResult8616 | None:
    """Reuse a persisted Widening bundle when callsite evidence allows."""
    if persisted is None:
        return None
    if program_callsites_ready and direct_evidence_ready:
        attach_project_global_object_layout_evidence_8616(
            target_project,
            persisted.layouts,
        )
        attach_project_bounded_global_object_ranges_8616(
            target_project,
            persisted.ranges,
        )
        return IndexedAliasProgramContextResult8616(
            IndexedAliasProgramContextStatus8616.REUSED_PERSISTED_WIDENING,
            None,
            requirement,
        )
    catalog = recover_direct_indexed_alias_catalog_8616(
        source_project,
        timeout=timeout,
        window=window,
    )
    if catalog is None:
        if program_callsites_ready:
            attach_project_global_object_layout_evidence_8616(
                target_project,
                persisted.layouts,
            )
            attach_project_bounded_global_object_ranges_8616(
                target_project,
                persisted.ranges,
            )
            return IndexedAliasProgramContextResult8616(
                IndexedAliasProgramContextStatus8616.REUSED_PERSISTED_WIDENING,
                None,
                requirement,
            )
        return IndexedAliasProgramContextResult8616(
            IndexedAliasProgramContextStatus8616.DISCOVERY_INCOMPLETE,
            None,
            requirement,
        )
    if not direct_evidence_ready:
        publish_recovered_direct_global_object_evidence_8616(
            catalog.evidence_project,
            catalog.functions,
            target_project,
            cache_key=direct_cache_key,
        )
    if not program_callsites_ready:
        callsites_published = publish_recovered_program_callsites_8616(
            catalog,
            target_project,
            source_project,
            cache_key=callsite_cache_key,
            already_ready=False,
        )
        if not callsites_published:
            return IndexedAliasProgramContextResult8616(
                IndexedAliasProgramContextStatus8616.DISCOVERY_INCOMPLETE,
                None,
                requirement,
            )
    attach_project_global_object_layout_evidence_8616(
        target_project,
        persisted.layouts,
    )
    attach_project_bounded_global_object_ranges_8616(
        target_project,
        persisted.ranges,
    )
    return IndexedAliasProgramContextResult8616(
        IndexedAliasProgramContextStatus8616.REUSED_PERSISTED_WIDENING,
        None,
        requirement,
    )


def prepare_direct_indexed_alias_program_context_8616(
    source_project: object,
    target_project: object,
    function: object,
    *,
    timeout: int,
    window: int,
    binary_path: Path | None = None,
) -> IndexedAliasProgramContextResult8616:
    """Publish a full catalog only when the direct function needs one."""
    local_program = build_cached_direct_indexed_alias_local_evidence_8616(
        target_project,
        function,
    )
    requirement = collect_global_object_program_requirement_8616(
        source_project,
        function,
        local_program,
    )
    target_surface = cast(_ProjectProgramSurface8616, target_project)
    target_surface._inertia_global_object_program_requirement_8616 = requirement
    direct_cache_key = direct_global_object_cache_key_8616(
        source_project,
        binary_path,
    )
    direct_evidence_ready = attach_available_direct_global_object_evidence_8616(
        target_project,
        direct_cache_key,
    )
    if not requirement.requires_program:
        return IndexedAliasProgramContextResult8616(
            IndexedAliasProgramContextStatus8616.NOT_REQUIRED,
            None,
            requirement,
        )
    program_callsites_required = bool(requirement.callsite_addrs)
    callsite_cache_key = program_callsite_cache_key_8616(
        source_project,
        binary_path,
    )
    transported = _transported_widening_bundle_8616(target_surface)
    if transported is not None and (
        not program_callsites_required
        or attach_available_program_callsite_evidence_8616(
            target_project,
            callsite_cache_key,
        )
    ):
        return IndexedAliasProgramContextResult8616(
            IndexedAliasProgramContextStatus8616.REUSED_WIDENING,
            None,
            requirement,
        )
    cache_key = indexed_global_object_cache_key_8616(source_project, binary_path)
    if cache_key is None:
        return _discover_direct_indexed_alias_program_context_8616(
            source_project,
            target_project,
            requirement,
            timeout=timeout,
            window=window,
            cache_key=None,
            callsite_cache_key=callsite_cache_key,
            direct_cache_key=direct_cache_key,
            program_callsites_ready=not program_callsites_required,
        )
    lock_timeout = max(600.0, float(max(1, timeout)) * 2.0)
    with _cache_key_lock(
        INDEXED_GLOBAL_OBJECT_CACHE_NAMESPACE_8616,
        cache_key,
        timeout_seconds=lock_timeout,
    ):
        program_callsites_ready = (
            not program_callsites_required
            or attach_available_program_callsite_evidence_8616(
                target_project,
                callsite_cache_key,
            )
        )
        persisted = load_indexed_global_object_cache_8616(cache_key)
        reused = _reused_persisted_context_8616(
            source_project,
            target_project,
            requirement,
            persisted=persisted,
            timeout=timeout,
            window=window,
            callsite_cache_key=callsite_cache_key,
            direct_cache_key=direct_cache_key,
            direct_evidence_ready=direct_evidence_ready,
            program_callsites_ready=program_callsites_ready,
        )
        if reused is not None:
            return reused
        return _discover_direct_indexed_alias_program_context_8616(
            source_project,
            target_project,
            requirement,
            timeout=timeout,
            window=window,
            cache_key=cache_key,
            callsite_cache_key=callsite_cache_key,
            direct_cache_key=direct_cache_key,
            program_callsites_ready=program_callsites_ready,
        )


__all__ = [
    "IndexedAliasProgramContextResult8616",
    "IndexedAliasProgramContextStatus8616",
    "prepare_direct_indexed_alias_program_context_8616",
    "publish_discovered_indexed_alias_program_8616",
]
