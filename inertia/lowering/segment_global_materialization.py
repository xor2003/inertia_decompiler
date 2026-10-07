"""Coordinate proven segmented-global materializers after C-AST regeneration.

Layer: Types/Lowering.
Responsibility: replay typed segment/global materialization in one deterministic
order for Structuring, validation priming, and CLI regeneration callers.
Consumes alias, widening, and typed facts; it does not produce semantic evidence.
Do not recover semantics from COD, source, assembly, or rendered C text.
Dynamic boundary: project and codegen are third-party angr plugin objects.
"""

from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass
from typing import Any, cast

from inertia.pipeline.structured_ast_query_index import (
    StructuredAstQuerySession8616,
    StructuredAstQuerySessionStats8616,
)

from inertia.widening.segmented_load_widening import apply_segmented_load_widening_8616

from .cod_global_identity import reconcile_recorded_cod_global_storage_identities_8616
from .direct_global_register_updates import materialize_direct_global_register_updates_8616
from .dos_interrupt_aggregate_globals import materialize_dos_interrupt_aggregate_globals_8616
from .logical_word_memory_copy_materialization import (
    materialize_logical_word_memory_copies_8616,
)
from .segmented_global_loads import (
    materialize_compare_register_global_carriers_8616,
    materialize_direct_global_symbol_stores_8616,
    materialize_indexed_segmented_global_loads_8616,
    materialize_named_segmented_global_loads_8616,
)
from .segmented_memory_lowering import apply_runtime_segment_lowering_8616

type ProjectBoundary8616 = Any
type CodegenBoundary8616 = Any

__all__ = [
    "SegmentGlobalMaterializationResult8616",
    "SegmentGlobalMaterializationTiming8616",
    "cod_metadata_for_codegen_8616",
    "run_segment_global_materialization_8616",
]


@dataclass(frozen=True, slots=True)
class SegmentGlobalMaterializationTiming8616:
    """Inclusive component timings for one Lowering replay request."""

    named_global_seconds: float
    compare_register_seconds: float
    indexed_global_seconds: float
    direct_global_store_seconds: float
    dos_interrupt_aggregate_seconds: float
    segmented_load_widening_seconds: float
    runtime_segment_seconds: float

    @property
    def total_seconds(self) -> float:
        """Return the sum of all component timings."""
        return sum(
            (
                self.named_global_seconds,
                self.compare_register_seconds,
                self.indexed_global_seconds,
                self.direct_global_store_seconds,
                self.dos_interrupt_aggregate_seconds,
                self.segmented_load_widening_seconds,
                self.runtime_segment_seconds,
            )
        )


@dataclass(frozen=True, slots=True)
class SegmentGlobalMaterializationResult8616:
    """Result of one complete segmented-global materialization replay."""

    query_stats: StructuredAstQuerySessionStats8616 | None
    runtime_segment_changed: bool
    segmented_load_widening_changed: bool
    named_global_changed: bool
    compare_register_global_changed: bool
    direct_global_store_changed: bool
    indexed_global_changed: bool
    dos_interrupt_aggregate_changed: bool

    @property
    def changed(self) -> bool:
        """Return True when any owning materializer changed the C AST."""
        return (
            self.runtime_segment_changed
            or self.segmented_load_widening_changed
            or self.named_global_changed
            or self.compare_register_global_changed
            or self.direct_global_store_changed
            or self.indexed_global_changed
            or self.dos_interrupt_aggregate_changed
        )


def cod_metadata_for_codegen_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
) -> object | None:
    """Return optional sidecar metadata for the active dynamic angr codegen."""
    func_addr = getattr(getattr(codegen, "cfunc", None), "addr", None)
    if not isinstance(func_addr, int):
        return None
    projects = (project, getattr(project, "_inertia_original_project", None))
    delta = getattr(project, "_inertia_original_linear_delta", None)
    candidate_addrs = [func_addr]
    if isinstance(delta, int):
        candidate_addrs.extend((func_addr + delta, func_addr - delta))
    for candidate_project in projects:
        metadata_by_addr = getattr(candidate_project, "_inertia_cod_metadata_by_func_addr_8616", None)
        if not isinstance(metadata_by_addr, dict):
            continue
        for candidate_addr in candidate_addrs:
            metadata = metadata_by_addr.get(candidate_addr)
            if metadata is not None:
                return cast(object, metadata)
        unique_metadata = {id(metadata): metadata for metadata in metadata_by_addr.values()}
        if len(unique_metadata) == 1:
            return cast(object, next(iter(unique_metadata.values())))
    return None


def run_segment_global_materialization_8616(
    project: ProjectBoundary8616,
    codegen: CodegenBoundary8616,
    synthetic_globals: object,
    *,
    cod_metadata: object | None = None,
    include_runtime_segment: bool = False,
) -> SegmentGlobalMaterializationResult8616:
    """Run proven segment/global materializers in Types/Lowering-owned order."""
    component_started = time.perf_counter()
    named_global_changed = bool(
        materialize_named_segmented_global_loads_8616(
            project,
            codegen,
            synthetic_globals,
            cod_metadata=cod_metadata,
        )
    )
    cfunc = getattr(codegen, "cfunc", None)
    query_root = getattr(cfunc, "statements", None)
    query_session = (
        StructuredAstQuerySession8616(query_root)
        if query_root is not None
        else None
    )
    logical_copy_result = materialize_logical_word_memory_copies_8616(
        codegen,
        query_session=query_session,
    )
    direct_register_changed = materialize_direct_global_register_updates_8616(
        project,
        codegen,
        synthetic_globals,
        query_session=query_session,
    )
    named_global_changed = bool(
        logical_copy_result.changed
        or direct_register_changed
        or named_global_changed
    )
    named_global_seconds = time.perf_counter() - component_started
    component_started = time.perf_counter()
    compare_register_global_changed = bool(
        materialize_compare_register_global_carriers_8616(
            project,
            codegen,
            synthetic_globals,
            cod_metadata=cod_metadata,
        )
    )
    compare_register_seconds = time.perf_counter() - component_started
    component_started = time.perf_counter()
    indexed_global_changed = bool(
        materialize_indexed_segmented_global_loads_8616(project, codegen, cod_metadata=cod_metadata)
    )
    indexed_global_seconds = time.perf_counter() - component_started
    component_started = time.perf_counter()
    direct_global_store_changed = bool(
        materialize_direct_global_symbol_stores_8616(
            project,
            codegen,
            synthetic_globals,
            cod_metadata=cod_metadata,
        )
    )
    direct_global_store_seconds = time.perf_counter() - component_started
    component_started = time.perf_counter()
    dos_interrupt_aggregate_changed = bool(
        materialize_dos_interrupt_aggregate_globals_8616(codegen)
    )
    dos_interrupt_aggregate_seconds = time.perf_counter() - component_started
    component_started = time.perf_counter()
    segmented_load_widening_changed = bool(apply_segmented_load_widening_8616(codegen))
    segmented_load_widening_seconds = time.perf_counter() - component_started
    target = str(getattr(project, "_inertia_c_target", "portable-flat") or "portable-flat")
    component_started = time.perf_counter()
    runtime_segment_changed = (
        bool(apply_runtime_segment_lowering_8616(codegen, target=target)) if include_runtime_segment else False
    )
    runtime_segment_seconds = time.perf_counter() - component_started
    if runtime_segment_changed:
        component_started = time.perf_counter()
        named_global_changed = bool(
            materialize_named_segmented_global_loads_8616(
                project,
                codegen,
                synthetic_globals,
                cod_metadata=cod_metadata,
            )
            or named_global_changed
        )
        named_global_changed = bool(
            reconcile_recorded_cod_global_storage_identities_8616(codegen)
            or named_global_changed
        )
        named_global_seconds += time.perf_counter() - component_started
    timing = SegmentGlobalMaterializationTiming8616(
        named_global_seconds=named_global_seconds,
        compare_register_seconds=compare_register_seconds,
        indexed_global_seconds=indexed_global_seconds,
        direct_global_store_seconds=direct_global_store_seconds,
        dos_interrupt_aggregate_seconds=dos_interrupt_aggregate_seconds,
        segmented_load_widening_seconds=segmented_load_widening_seconds,
        runtime_segment_seconds=runtime_segment_seconds,
    )
    codegen._inertia_segment_global_materialization_timing_8616 = timing
    timing_enabled = os.environ.get("INERTIA_DEBUG_TIMING", "").strip().lower()
    if timing_enabled not in {"", "0", "false", "no", "off"}:
        print(
            "segment/global components: "
            f"named={timing.named_global_seconds:.3f} "
            f"compare={timing.compare_register_seconds:.3f} "
            f"indexed={timing.indexed_global_seconds:.3f} "
            f"direct={timing.direct_global_store_seconds:.3f} "
            f"aggregate={timing.dos_interrupt_aggregate_seconds:.3f} "
            f"widening={timing.segmented_load_widening_seconds:.3f} "
            f"runtime={timing.runtime_segment_seconds:.3f} "
            f"total={timing.total_seconds:.3f}",
            file=sys.stderr,
            flush=True,
        )
    result = SegmentGlobalMaterializationResult8616(
        query_stats=query_session.stats() if query_session is not None else None,
        runtime_segment_changed=runtime_segment_changed,
        segmented_load_widening_changed=segmented_load_widening_changed,
        named_global_changed=named_global_changed,
        compare_register_global_changed=compare_register_global_changed,
        direct_global_store_changed=direct_global_store_changed,
        indexed_global_changed=indexed_global_changed,
        dos_interrupt_aggregate_changed=dos_interrupt_aggregate_changed,
    )
    if result.changed:
        codegen._inertia_segment_global_materialization_8616 = {
            "runtime_segment_changed": result.runtime_segment_changed,
            "segmented_load_widening_changed": result.segmented_load_widening_changed,
            "named_global_changed": result.named_global_changed,
            "compare_register_global_changed": result.compare_register_global_changed,
            "direct_global_store_changed": result.direct_global_store_changed,
            "indexed_global_changed": result.indexed_global_changed,
            "dos_interrupt_aggregate_changed": result.dos_interrupt_aggregate_changed,
            "changed": result.changed,
            "owner": "lowering.segment_global_materialization",
        }
    return result
